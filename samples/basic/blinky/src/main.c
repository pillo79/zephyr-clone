/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>

#include "sysled.h"

/* 1000 msec = 1 sec */
#define SLEEP_TIME_MS   1000

/* The devicetree node identifier for the "led0" alias. */
#define LED0_NODE DT_ALIAS(led0)

/* change this to any other UART peripheral if desired */
#define UART_DEVICE_NODE DT_NODELABEL(uart4)

static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
#include <zephyr/drivers/uart.h>

/*
 * A build error on this line means your board is unsupported.
 * See the sample documentation for information on how to fix this.
 */
//static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);

int main(void)
{
	int ret;

	initLeds();
/*
	if (!gpio_is_ready_dt(&led)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}
*/
	ret = device_init(uart_dev);
	if (ret < 0) {
		printk("UART device init err %i", ret);
		return 0;
	}

	if (!device_is_ready(uart_dev)) {
		printk("UART device not found!");
		return 0;
	}

	const char *msg="0123456789abcdef";
	int i=0;
	ret = SetLed(0, 1);
	while (1) {
		static int st = 1;
		st = !st;
		if (ret < 0) {
			return 0;
		}
		k_msleep(SLEEP_TIME_MS);
		ret = SetLed(0, st);
		uart_poll_out(uart_dev, msg[(i++) & 0xf]);
	}
	return 0;
}
