/*
 * Copyright (c) 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_LLEXT_SYMBOL_H
#define ZEPHYR_LLEXT_SYMBOL_H

#include <zephyr/sys/iterable_sections.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Linkable loadable extension symbol
 * @defgroup llext_symbols LLEXT symbols
 * @ingroup llext
 * @{
 */

/**
 * @brief Symbols are named memory addresses
 *
 * Symbols may be named function or global objects that have been exported
 * for linking.
 */
struct llext_symbol {
	/** Name of symbol */
	char *name;

	/** Address of symbol */
	void *addr;
};

/**
 * @brief A symbol table
 *
 * An array of symbols
 */
struct llext_symtable {
	/** Number of symbols in the table */
	size_t sym_cnt;

	/** Array of symbols */
	struct llext_symbol *syms;
};


/**
 * @brief Export a symbol to a table of symbols
 *
 * Takes a symbol (function or object) by symbolic name and adds the name
 * and address of the symbol to a table of symbols that may be used for linking.
 *
 * @param x Symbol to export
 */
#define EXPORT_SYMBOL(x)					\
	STRUCT_SECTION_ITERABLE(llext_symbol, x ## _sym) = {	\
		.name = STRINGIFY(x), .addr = x,		\
	}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif


#endif /* ZEPHYR_LLEXT_SYMBOL_H */
