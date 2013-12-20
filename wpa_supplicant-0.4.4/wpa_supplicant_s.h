/*
 * wpa_supplicant - Semi-internal definitions
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
 *
 * These definitions are currently shared between the core wpa_supplicant code
 * and WPA state machines. These will likely be replaced with something cleaner
 * (e.g., registered callback functions) to get rid of direct function calls
 * from wpa.c/preauth.c to core wpa_supplicant code.
 */

#ifndef WPA_SUPPLICANT_S_H
#define WPA_SUPPLICANT_S_H

typedef enum {
	WPA_DISCONNECTED, WPA_INACTIVE, WPA_SCANNING, WPA_ASSOCIATING,
	WPA_ASSOCIATED, WPA_4WAY_HANDSHAKE, WPA_GROUP_HANDSHAKE,
	WPA_COMPLETED
} wpa_states;

void wpa_supplicant_set_state(struct wpa_supplicant *wpa_s, wpa_states state);
wpa_states wpa_supplicant_get_state(struct wpa_supplicant *wpa_s);


u8 * wpa_alloc_eapol(const struct wpa_supplicant *wpa_s, const u8 *dest,
		     u16 proto, u8 type, const void *data, u16 data_len,
		     size_t *msg_len, void **data_pos);
int wpa_ether_send(struct wpa_supplicant *wpa_s, u8 *buf, size_t len);

int wpa_supplicant_get_beacon_ie(struct wpa_supplicant *wpa_s);

struct wpa_ssid * wpa_supplicant_get_ssid(struct wpa_supplicant *wpa_s);

void wpa_supplicant_cancel_auth_timeout(struct wpa_supplicant *wpa_s);

void wpa_supplicant_deauthenticate(struct wpa_supplicant *wpa_s,
				   int reason_code);
void wpa_supplicant_disassociate(struct wpa_supplicant *wpa_s,
				 int reason_code);

void wpa_supplicant_scan(void *eloop_ctx, void *timeout_ctx);

void wpa_supplicant_req_scan(struct wpa_supplicant *wpa_s, int sec, int usec);

int wpa_supplicant_get_bssid(struct wpa_supplicant *wpa_s, u8 *bssid);
int wpa_supplicant_set_key(struct wpa_supplicant *wpa_s, wpa_alg alg,
			   const u8 *addr, int key_idx, int set_tx,
			   const u8 *seq, size_t seq_len,
			   const u8 *key, size_t key_len);
int wpa_supplicant_add_pmkid(struct wpa_supplicant *wpa_s,
			     const u8 *bssid, const u8 *pmkid);
int wpa_supplicant_remove_pmkid(struct wpa_supplicant *wpa_s,
				const u8 *bssid, const u8 *pmkid);

#endif /* WPA_SUPPLICANT_S_H */
