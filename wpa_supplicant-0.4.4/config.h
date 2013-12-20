/*
 * WPA Supplicant / Configuration file structures
 * Copyright (c) 2003-2005, Jouni Malinen <jkmaline@cc.hut.fi>
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

#ifndef CONFIG_H
#define CONFIG_H

#ifdef CONFIG_CTRL_IFACE
#ifndef CONFIG_CTRL_IFACE_UDP
#include <grp.h>
#endif /* CONFIG_CTRL_IFACE_UDP */
#endif /* CONFIG_CTRL_IFACE */

#include "config_ssid.h"

/**
 * struct wpa_config - wpa_supplicant configuration data
 */
struct wpa_config {
	struct wpa_ssid *ssid; /* global network list */
	struct wpa_ssid **pssid; /* per priority network lists (in priority
				  * order) */
	int num_prio; /* number of different priorities */
	int eapol_version;
	int ap_scan;
	char *ctrl_interface; /* directory for UNIX domain sockets */
#ifdef CONFIG_CTRL_IFACE
#ifndef CONFIG_CTRL_IFACE_UDP
	gid_t ctrl_interface_gid;
#endif /* CONFIG_CTRL_IFACE_UDP */
	int ctrl_interface_gid_set;
#endif /* CONFIG_CTRL_IFACE */
	int fast_reauth;
	char *opensc_engine_path;
	char *pkcs11_engine_path;
	char *pkcs11_module_path;
	char *driver_param;

	unsigned int dot11RSNAConfigPMKLifetime;
	unsigned int dot11RSNAConfigPMKReauthThreshold;
	unsigned int dot11RSNAConfigSATimeout;
};


struct wpa_config * wpa_config_read(const char *config_file);
void wpa_config_free(struct wpa_config *ssid);
void wpa_config_free_ssid(struct wpa_ssid *ssid);
struct wpa_ssid * wpa_config_get_network(struct wpa_config *config, int id);
struct wpa_ssid * wpa_config_add_network(struct wpa_config *config);
int wpa_config_remove_network(struct wpa_config *config, int id);
int wpa_config_set(struct wpa_ssid *ssid, const char *var, const char *value,
		   int line);
void wpa_config_update_psk(struct wpa_ssid *ssid);

#endif /* CONFIG_H */
