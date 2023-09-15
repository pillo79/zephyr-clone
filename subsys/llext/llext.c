/*
 * Copyright (c) 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/sys/util.h>
#include <zephyr/llext/elf.h>
#include <zephyr/llext/loader.h>
#include <zephyr/llext/llext.h>
#include <zephyr/kernel.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(llext, CONFIG_LLEXT_LOG_LEVEL);

#include <string.h>

static struct llext_symtable SYMTAB;

K_HEAP_DEFINE(llext_heap, CONFIG_LLEXT_HEAP_SIZE * 1024);

static const char ELF_MAGIC[] = {0x7f, 'E', 'L', 'F'};

static inline int llext_read(struct llext_loader *l, void *buf, size_t len)
{
	return l->read(l, buf, len);
}

static inline int llext_seek(struct llext_loader *l, size_t pos)
{
	return l->seek(l, pos);
}

static sys_slist_t _llext_list = SYS_SLIST_STATIC_INIT(&_llext_list);

sys_slist_t *llext_list(void)
{
	return &_llext_list;
}

struct llext *llext_by_name(const char *name)
{
	sys_slist_t *mlist = llext_list();
	sys_snode_t *node = sys_slist_peek_head(mlist);
	struct llext *ext = CONTAINER_OF(node, struct llext, _llext_list);

	while (node != NULL) {
		if (strncmp(ext->name, name, sizeof(ext->name)) == 0) {
			return ext;
		}
		node = sys_slist_peek_next(node);
		ext = CONTAINER_OF(node, struct llext, _llext_list);
	}

	return NULL;
}

void *llext_find_sym(const struct llext_symtable *sym_table, const char *sym_name)
{
	/* find symbols in module */
	for (size_t i = 0; i < sym_table->sym_cnt; i++) {
		if (strcmp(sym_table->syms[i].name, sym_name) == 0) {
			return sym_table->syms[i].addr;
		}
	}

	return NULL;
}

/**
 * @brief load a relocatable object file.
 *
 * An unlinked or partially linked elf will have symbols that have yet to be
 * determined and must be linked in effect. This is similar, but not exactly like,
 * a dynamic elf. Typically the code and addresses *are* position dependent.
 */
static int llext_load_rel(struct llext_loader *ldr, struct llext *ext)
{
	elf_word i, j, sym_cnt, rel_cnt;
	elf_rel_t rel;
	char name[32];

	ext->mem_size = 0;
	ext->sym_tab.sym_cnt = 0;

	elf_shdr_t shdr;
	size_t pos = ldr->hdr.e_shoff;
	unsigned int str_cnt = 0;

	ldr->sect_map = k_heap_alloc(&llext_heap, ldr->hdr.e_shnum * sizeof(uint32_t), K_NO_WAIT);
	if (!ldr->sect_map) {
		return -ENOMEM;
	}
	ldr->sect_cnt = ldr->hdr.e_shnum;

	ldr->sects[LLEXT_SECT_SHSTRTAB] =
		ldr->sects[LLEXT_SECT_STRTAB] =
		ldr->sects[LLEXT_SECT_SYMTAB] = (elf_shdr_t){0};

	/* Find symbol and string tables */
	for (i = 0; i < ldr->hdr.e_shnum && str_cnt < 3; i++) {
		llext_seek(ldr, pos);
		llext_read(ldr, &shdr, sizeof(elf_shdr_t));

		pos += ldr->hdr.e_shentsize;

		LOG_DBG("section %d at %x: name %d, type %d, flags %x, addr %x, size %d",
			i,
			ldr->hdr.e_shoff + i * ldr->hdr.e_shentsize,
			shdr.sh_name,
			shdr.sh_type,
			shdr.sh_flags,
			shdr.sh_addr,
			shdr.sh_size);

		switch (shdr.sh_type) {
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			LOG_DBG("symtab at %d", i);
			ldr->sects[LLEXT_SECT_SYMTAB] = shdr;
			ldr->sect_map[i] = LLEXT_SECT_SYMTAB;
			str_cnt++;
			break;
		case SHT_STRTAB:
			if (ldr->hdr.e_shstrndx == i) {
				LOG_DBG("shstrtab at %d", i);
				ldr->sects[LLEXT_SECT_SHSTRTAB] = shdr;
				ldr->sect_map[i] = LLEXT_SECT_SHSTRTAB;
			} else {
				LOG_DBG("strtab at %d", i);
				ldr->sects[LLEXT_SECT_STRTAB] = shdr;
				ldr->sect_map[i] = LLEXT_SECT_STRTAB;
			}
			str_cnt++;
			break;
		default:
			break;
		}
	}

	if (!ldr->sects[LLEXT_SECT_SHSTRTAB].sh_type ||
	    !ldr->sects[LLEXT_SECT_STRTAB].sh_type ||
	    !ldr->sects[LLEXT_SECT_SYMTAB].sh_type) {
		LOG_ERR("Some sections are missing or present multiple times!");
		return -ENOENT;
	}

	pos = ldr->hdr.e_shoff;

	/* Copy over useful sections */
	for (i = 0; i < ldr->hdr.e_shnum; i++) {
		llext_seek(ldr, pos);
		llext_read(ldr, &shdr, sizeof(elf_shdr_t));

		pos += ldr->hdr.e_shentsize;

		elf32_word str_idx = shdr.sh_name;

		llext_seek(ldr, ldr->sects[LLEXT_SECT_SHSTRTAB].sh_offset + str_idx);
		llext_read(ldr, name, sizeof(name));
		name[sizeof(name) - 1] = '\0';

		LOG_DBG("section %d name %s", i, name);

		enum llext_mem mem_idx;
		enum llext_section sect_idx;

		if (strncmp(name, ".text", sizeof(name)) == 0) {
			mem_idx = LLEXT_MEM_TEXT;
			sect_idx = LLEXT_SECT_TEXT;
		} else if (strncmp(name, ".data", sizeof(name)) == 0) {
			mem_idx = LLEXT_MEM_DATA;
			sect_idx = LLEXT_SECT_DATA;
		} else if (strncmp(name, ".rodata", sizeof(name)) == 0) {
			mem_idx = LLEXT_MEM_RODATA;
			sect_idx = LLEXT_SECT_RODATA;
		} else if (strncmp(name, ".bss", sizeof(name)) == 0) {
			mem_idx = LLEXT_MEM_BSS;
			sect_idx = LLEXT_SECT_BSS;
		} else {
			LOG_DBG("Not copied section %s", name);
			continue;
		}

		ldr->sects[sect_idx] = shdr;
		ldr->sect_map[i] = sect_idx;

		ext->mem[mem_idx] =
			k_heap_alloc(&llext_heap, ldr->sects[sect_idx].sh_size, K_NO_WAIT);
		llext_seek(ldr, ldr->sects[sect_idx].sh_offset);
		llext_read(ldr, ext->mem[mem_idx], ldr->sects[sect_idx].sh_size);

		ext->mem_size += shdr.sh_size;

		LOG_DBG("Copied section %s (idx: %d, size: %d, addr %x) to mem %d, module size %d",
			name, i, shdr.sh_size, shdr.sh_addr,
			mem_idx, ext->mem_size);
	}

	/* Iterate all symbols in symtab and update its st_value,
	 * for sections, using its loading address,
	 * for undef functions or variables, find it's address globally.
	 */
	elf_sym_t sym;
	size_t ent_size = ldr->sects[LLEXT_SECT_SYMTAB].sh_entsize;
	size_t syms_size = ldr->sects[LLEXT_SECT_SYMTAB].sh_size;
	size_t exp_syms_cnt = 0;

	pos = ldr->sects[LLEXT_SECT_SYMTAB].sh_offset;
	sym_cnt = syms_size / sizeof(elf_sym_t);

	LOG_DBG("symbol count %d", sym_cnt);

	for (i = 0; i < sym_cnt; i++) {
		llext_seek(ldr, pos);
		llext_read(ldr, &sym, ent_size);
		pos += ent_size;

		uint32_t stt = ELF_ST_TYPE(sym.st_info);
		uint32_t stb = ELF_ST_BIND(sym.st_info);
		uint32_t sect = sym.st_shndx;

		llext_seek(ldr, ldr->sects[LLEXT_SECT_STRTAB].sh_offset + sym.st_name);
		llext_read(ldr, name, sizeof(name));

		if (stb == STB_GLOBAL) {
			LOG_DBG("exported symbol %d, name %s, type tag %d, bind %d, sect %d",
				i, name, stt, stb, sect);
			exp_syms_cnt++;
		} else {
			LOG_DBG("unhandled symbol %d, name %s, type tag %d, bind %d, sect %d",
				i, name, stt, stb, sect);
		}
	}

	/* Copy over global symbols to symtab */

	ext->sym_tab.syms = k_heap_alloc(&llext_heap, exp_syms_cnt * sizeof(struct llext_symbol),
				       K_NO_WAIT);
	ext->sym_tab.sym_cnt = exp_syms_cnt;
	pos = ldr->sects[LLEXT_SECT_SYMTAB].sh_offset;
	j = 0;
	for (i = 0; i < sym_cnt; i++) {
		llext_seek(ldr, pos);
		llext_read(ldr, &sym, ent_size);
		pos += ent_size;

		uint32_t stt = ELF_ST_TYPE(sym.st_info);
		uint32_t stb = ELF_ST_BIND(sym.st_info);
		uint32_t sect = sym.st_shndx;

		llext_seek(ldr, ldr->sects[LLEXT_SECT_STRTAB].sh_offset + sym.st_name);
		llext_read(ldr, name, sizeof(name));

		if (stb == STB_GLOBAL && sect != SHN_UNDEF) {
			size_t name_sz = sizeof(name);

			ext->sym_tab.syms[j].name = k_heap_alloc(&llext_heap,
							       sizeof(name),
							       K_NO_WAIT);
			strncpy(ext->sym_tab.syms[j].name, name, name_sz);
			ext->sym_tab.syms[j].addr =
				(void *)((uintptr_t)ext->mem[ldr->sect_map[sym.st_shndx]]
					 + sym.st_value);
			LOG_DBG("exported symbol %d name %s addr %p (sect %d + 0x%x)",
				j, name, ext->sym_tab.syms[j].addr, ldr->sect_map[sym.st_shndx], sym.st_value);
			j++;
		}
	}

	/* relocations */
	uintptr_t loc = 0;

	pos = ldr->hdr.e_shoff;

	for (i = 0; i < ldr->hdr.e_shnum - 1; i++) {
		llext_seek(ldr, pos);
		llext_read(ldr, &shdr, sizeof(elf_shdr_t));

		pos += ldr->hdr.e_shentsize;

		/* find relocation sections */
		if (shdr.sh_type != SHT_REL && shdr.sh_type != SHT_RELA) {
			continue;
		}

		rel_cnt = shdr.sh_size / sizeof(elf_rel_t);


		llext_seek(ldr, ldr->sects[LLEXT_SECT_SHSTRTAB].sh_offset + shdr.sh_name);
		llext_read(ldr, name, sizeof(name));

		if (strncmp(name, ".rel.text", sizeof(name)) == 0 ||
		    strncmp(name, ".rela.text", sizeof(name)) == 0) {
			loc = (uintptr_t)ext->mem[LLEXT_MEM_TEXT];
		} else if (strncmp(name, ".rel.bss", sizeof(name)) == 0) {
			loc = (uintptr_t)ext->mem[LLEXT_MEM_BSS];
		} else if (strncmp(name, ".rel.rodata", sizeof(name)) == 0) {
			loc = (uintptr_t)ext->mem[LLEXT_MEM_RODATA];
		} else if (strncmp(name, ".rel.data", sizeof(name)) == 0) {
			loc = (uintptr_t)ext->mem[LLEXT_MEM_DATA];
		}

		LOG_DBG("relocation section %s (%d) linked to section %d has %d relocations",
			name, i, shdr.sh_link, rel_cnt);

		for (j = 0; j < rel_cnt; j++) {
			/* get each relocation entry */
			llext_seek(ldr, shdr.sh_offset + j * sizeof(elf_rel_t));
			llext_read(ldr, &rel, sizeof(elf_rel_t));

			/* get corresponding symbol */
			llext_seek(ldr, ldr->sects[LLEXT_SECT_SYMTAB].sh_offset
				    + ELF_R_SYM(rel.r_info) * sizeof(elf_sym_t));
			llext_read(ldr, &sym, sizeof(elf_sym_t));

			llext_seek(ldr, ldr->sects[LLEXT_SECT_STRTAB].sh_offset +
				    sym.st_name);
			llext_read(ldr, name, sizeof(name));

			LOG_DBG("relocation %d:%d info %x (type %d, sym %d) offset %d sym_name "
				"%s sym_type %d sym_bind %d sym_ndx %d",
				i, j, rel.r_info, ELF_R_TYPE(rel.r_info), ELF_R_SYM(rel.r_info),
				rel.r_offset, name, ELF_ST_TYPE(sym.st_info),
				ELF_ST_BIND(sym.st_info), sym.st_shndx);

			uintptr_t link_addr, op_loc, op_code;

			/* If symbol is undefined, then we need to look it up */
			if (sym.st_shndx == SHN_UNDEF) {
				link_addr = (uintptr_t)llext_find_sym(&SYMTAB, name);

				if (link_addr == 0) {
					LOG_ERR("Undefined symbol with no entry in "
						"symbol table %s, offset %d, link section %d",
						name, rel.r_offset, shdr.sh_link);
					/* TODO cleanup and leave */
					continue;
				} else {
					op_code = (uintptr_t)(loc + rel.r_offset);

					LOG_INF("found symbol %s at 0x%lx, updating op code 0x%lx",
						name, link_addr, op_code);
				}
			} else if (sym.st_shndx == SHN_ABS) {
				link_addr = 0;

				LOG_INF("symbol %s is absolute", name);
			} else {
				link_addr = (uintptr_t)ext->mem[ldr->sect_map[sym.st_shndx]];

				LOG_INF("found symbol %s in section %d base addr 0x%lx", name, ldr->sect_map[sym.st_shndx], link_addr);
			}

			op_loc = loc + rel.r_offset;

			LOG_INF("relocating (linking) symbol %s type %d binding %d ndx %d offset "
				"%d link section %d",
				name, ELF_ST_TYPE(sym.st_info), ELF_ST_BIND(sym.st_info),
				sym.st_shndx, rel.r_offset, shdr.sh_link);

			LOG_INF("writing relocation symbol %s type %d sym %d at addr 0x%lx "
				"addr 0x%lx",
				name, ELF_R_TYPE(rel.r_info), ELF_R_SYM(rel.r_info),
				op_loc, link_addr);

			/* relocation */
			arch_elf_relocate(&rel, op_loc, link_addr);
		}
	}

	LOG_DBG("loaded module, .text at %p, .rodata at %p",
		ext->mem[LLEXT_MEM_TEXT], ext->mem[LLEXT_MEM_RODATA]);
	return 0;
}

STRUCT_SECTION_START_EXTERN(llext_symbol);

int llext_load(struct llext_loader *ldr, const char *name, struct llext **ext)
{
	int ret = 0;
	elf_ehdr_t ehdr;

	if (!SYMTAB.sym_cnt) {
		STRUCT_SECTION_COUNT(llext_symbol, &SYMTAB.sym_cnt);
		SYMTAB.syms = STRUCT_SECTION_START(llext_symbol);
	}

	llext_seek(ldr, 0);
	llext_read(ldr, &ehdr, sizeof(ehdr));

	/* check whether this is an valid elf file */
	if (memcmp(ehdr.e_ident, ELF_MAGIC, sizeof(ELF_MAGIC)) != 0) {
		LOG_HEXDUMP_ERR(ehdr.e_ident, 16, "Invalid ELF, magic does not match");
		return -EINVAL;
	}

	switch (ehdr.e_type) {
	case ET_REL:
	case ET_DYN:
		LOG_DBG("Loading relocatable or shared elf");
		*ext = k_heap_alloc(&llext_heap, sizeof(struct llext), K_NO_WAIT);

		for (int i = 0; i < LLEXT_MEM_COUNT; i++) {
			(*ext)->mem[i] = NULL;
		}

		if (ext == NULL) {
			LOG_ERR("Not enough memory for extension metadata");
			ret = -ENOMEM;
		} else {
			ldr->hdr = ehdr;
			ret = llext_load_rel(ldr, *ext);
		}
		break;
	default:
		LOG_ERR("Unsupported elf file type %x", ehdr.e_type);
		*ext = NULL;
		ret = -EINVAL;
	}

	if (ret != 0) {
		if (*ext != NULL) {
			llext_unload(*ext);
		}
		*ext = NULL;
	} else {
		strncpy((*ext)->name, name, sizeof((*ext)->name));
		sys_slist_append(&_llext_list, &(*ext)->_llext_list);
	}

	return ret;
}

void llext_unload(struct llext *ext)
{
	__ASSERT(ext, "Expected non-null extension");

	sys_slist_find_and_remove(&_llext_list, &ext->_llext_list);

	for (int i = 0; i < LLEXT_MEM_COUNT; i++) {
		if (ext->mem[i] != NULL) {
			LOG_DBG("freeing memory region %d", i);
			k_heap_free(&llext_heap, ext->mem[i]);
			ext->mem[i] = NULL;
		}
	}

	if (ext->sym_tab.syms != NULL) {
		LOG_DBG("freeing symbol table");
		k_heap_free(&llext_heap, ext->sym_tab.syms);
		ext->sym_tab.syms = NULL;
	}

	LOG_DBG("freeing module");
	k_heap_free(&llext_heap, ext);
}

int llext_call_fn(struct llext *ext, const char *sym_name)
{
	void (*fn)(void);

	fn = llext_find_sym(&ext->sym_tab, sym_name);
	if (fn == NULL) {
		return -EINVAL;
	}
	fn();

	return 0;
}
