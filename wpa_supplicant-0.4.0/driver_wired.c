/*
 * WPA Supplicant - wired Ethernet driver interface
 * Copyright (c) 2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "driver.h"
#include "wpa_supplicant.h"


struct wpa_driver_wired_data {
	void *ctx;
};


static int wpa_driver_wired_set_wpa(void *priv, int enabled)
{
	return 0;
}


static int wpa_driver_wired_get_ssid(void *priv, u8 *ssid)
{
	ssid[0] = 0;
	return 0;
}


static int wpa_driver_wired_get_bssid(void *priv, u8 *bssid)
{
	/* Report PAE group address as the "BSSID" for wired connection. */
	bssid[0] = 0x01;
	bssid[1] = 0x80;
	bssid[2] = 0xc2;
	bssid[3] = 0x00;
	bssid[4] = 0x00;
	bssid[5] = 0x03;
	return 0;
}


static void * wpa_driver_wired_init(void *ctx, const char *ifname)
{
	struct wpa_driver_wired_data *drv;

	drv = malloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	memset(drv, 0, sizeof(*drv));
	drv->ctx = ctx;

	return drv;
}


static void wpa_driver_wired_deinit(void *priv)
{
	struct wpa_driver_wired_data *drv = priv;
	free(drv);
}


struct wpa_driver_ops wpa_driver_wired_ops = {
	.name = "wired",
	.desc = "wpa_supplicant wired Ethernet driver",
	.set_wpa = wpa_driver_wired_set_wpa,
	.get_ssid = wpa_driver_wired_get_ssid,
	.get_bssid = wpa_driver_wired_get_bssid,
	.init = wpa_driver_wired_init,
	.deinit = wpa_driver_wired_deinit,
};
