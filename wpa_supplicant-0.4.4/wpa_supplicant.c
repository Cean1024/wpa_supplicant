/*
 * WPA Supplicant
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#ifndef CONFIG_NATIVE_WINDOWS
#include <netinet/in.h>
#endif /* CONFIG_NATIVE_WINDOWS */
#include <fcntl.h>

#include "common.h"
#include "eapol_sm.h"
#include "eap.h"
#include "wpa.h"
#include "driver.h"
#include "eloop.h"
#include "wpa_supplicant.h"
#include "config.h"
#include "l2_packet.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "pcsc_funcs.h"
#include "version.h"
#include "preauth.h"
#include "wpa_ctrl.h"

static const char *wpa_supplicant_version =
"wpa_supplicant v" VERSION_STR "\n"
"Copyright (c) 2003-2005, Jouni Malinen <jkmaline@cc.hut.fi> and contributors";

static const char *wpa_supplicant_license =
"This program is free software. You can distribute it and/or modify it\n"
"under the terms of the GNU General Public License version 2.\n"
"\n"
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license. See README and COPYING for more details.\n"
#ifdef EAP_TLS_FUNCS
"\nThis product includes software developed by the OpenSSL Project\n"
"for use in the OpenSSL Toolkit (http://www.openssl.org/)\n"
#endif /* EAP_TLS_FUNCS */
;

static const char *wpa_supplicant_full_license =
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License version 2 as\n"
"published by the Free Software Foundation.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License\n"
"along with this program; if not, write to the Free Software\n"
"Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\n"
"\n"
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license.\n"
"\n"
"Redistribution and use in source and binary forms, with or without\n"
"modification, are permitted provided that the following conditions are\n"
"met:\n"
"\n"
"1. Redistributions of source code must retain the above copyright\n"
"   notice, this list of conditions and the following disclaimer.\n"
"\n"
"2. Redistributions in binary form must reproduce the above copyright\n"
"   notice, this list of conditions and the following disclaimer in the\n"
"   documentation and/or other materials provided with the distribution.\n"
"\n"
"3. Neither the name(s) of the above-listed copyright holder(s) nor the\n"
"   names of its contributors may be used to endorse or promote products\n"
"   derived from this software without specific prior written permission.\n"
"\n"
"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
"\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
"LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
"A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
"OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
"SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
"LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
"OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
"\n";

extern struct wpa_driver_ops *wpa_supplicant_drivers[];

extern int wpa_debug_level;
extern int wpa_debug_show_keys;
extern int wpa_debug_timestamp;


void wpa_msg(struct wpa_supplicant *wpa_s, int level, char *fmt, ...)
{
	va_list ap;
	char *buf;
	const int buflen = 2048;
	int len;

	buf = malloc(buflen);
	if (buf == NULL) {
		printf("Failed to allocate message buffer for:\n");
		va_start(ap, fmt);
		vprintf(fmt, ap);
		printf("\n");
		va_end(ap);
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_printf(level, "%s", buf);
	wpa_supplicant_ctrl_iface_send(wpa_s, level, buf, len);
	free(buf);
}


u8 * wpa_alloc_eapol(const struct wpa_supplicant *wpa_s, const u8 *dest,
		     u16 proto, u8 type, const void *data, u16 data_len,
		     size_t *msg_len, void **data_pos)
{
	struct l2_ethhdr *eth;
	struct ieee802_1x_hdr *hdr;

	*msg_len = sizeof(*eth) + sizeof(*hdr) + data_len;
	eth = malloc(*msg_len);
	if (eth == NULL)
		return NULL;

	hdr = l2_packet_set_ethhdr(eth, dest, wpa_s->own_addr, proto);
	hdr->version = wpa_s->conf->eapol_version;
	hdr->type = type;
	hdr->length = htons(data_len);

	if (data)
		memcpy(hdr + 1, data, data_len);
	else
		memset(hdr + 1, 0, data_len);

	if (data_pos)
		*data_pos = hdr + 1;

	return (u8 *) eth;
}


/**
 * wpa_ether_send - Send Ethernet frame
 * @wpa_s: pointer to wpa_supplicant data
 * @buf: Ethernet frame (including header and payload)
 * @len: Ethernet frame length (including header and payload)
 */
int wpa_ether_send(struct wpa_supplicant *wpa_s, u8 *buf, size_t len)
{
	if (wpa_s->l2)
		return l2_packet_send(wpa_s->l2, buf, len);

	return wpa_drv_send_eapol(wpa_s, buf, len);
}


/**
 * wpa_supplicant_eapol_send - Send IEEE 802.1X EAPOL packet to Authenticator
 * @ctx: pointer to wpa_supplicant data
 * @type: IEEE 802.1X packet type (IEEE802_1X_TYPE_*)
 * @buf: EAPOL payload (after IEEE 802.1X header)
 * @len: EAPOL payload length
 *
 * This function adds Ethernet and IEEE 802.1X header and sends the EAPOL frame
 * to the current Authenticator.
 */
static int wpa_supplicant_eapol_send(void *ctx, int type, u8 *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;
	u8 *msg, *dst, bssid[ETH_ALEN];
	size_t msglen;
	int res;

	/* TODO: could add l2_packet_sendmsg that allows fragments to avoid
	 * extra copy here */

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_NONE) {
		/* Current SSID is not using IEEE 802.1X/EAP, so drop possible
		 * EAPOL frames (mainly, EAPOL-Start) from EAPOL state
		 * machines. */
		wpa_printf(MSG_DEBUG, "WPA: drop TX EAPOL in non-IEEE 802.1X "
			   "mode (type=%d len=%lu)", type,
			   (unsigned long) len);
		return -1;
	}

	if (pmksa_cache_get_current(wpa_s->wpa) &&
	    type == IEEE802_1X_TYPE_EAPOL_START) {
		/* Trying to use PMKSA caching - do not send EAPOL-Start frames
		 * since they will trigger full EAPOL authentication. */
		wpa_printf(MSG_DEBUG, "RSN: PMKSA caching - do not send "
			   "EAPOL-Start");
		return -1;
	}

	if (memcmp(wpa_s->bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) == 0) {
		wpa_printf(MSG_DEBUG, "BSSID not set when trying to send an "
			   "EAPOL frame");
		if (wpa_drv_get_bssid(wpa_s, bssid) == 0 &&
		    memcmp(bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) != 0) {
			dst = bssid;
			wpa_printf(MSG_DEBUG, "Using current BSSID " MACSTR
				   " from the driver as the EAPOL destination",
				   MAC2STR(dst));
		} else {
			dst = wpa_s->last_eapol_src;
			wpa_printf(MSG_DEBUG, "Using the source address of the"
				   " last received EAPOL frame " MACSTR " as "
				   "the EAPOL destination",
				   MAC2STR(dst));
		}
	} else {
		/* BSSID was already set (from (Re)Assoc event, so use it as
		 * the EAPOL destination. */
		dst = wpa_s->bssid;
	}

	msg = wpa_alloc_eapol(wpa_s, dst, ETH_P_EAPOL, type, buf, len, &msglen,
			      NULL);
	if (msg == NULL)
		return -1;

	wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", msg, msglen);
	res = wpa_ether_send(wpa_s, msg, msglen);
	free(msg);
	return res;
}


/**
 * wpa_eapol_set_wep_key - set WEP key for the driver
 * @ctx: pointer to wpa_supplicant data
 * @unicast: 1 = individual unicast key, 0 = broadcast key
 * @keyidx: WEP key index (0..3)
 * @key: pointer to key data
 * @keylen: key length in bytes
 *
 * Returns 0 on success or < 0 on error.
 */
static int wpa_eapol_set_wep_key(void *ctx, int unicast, int keyidx,
				 u8 *key, size_t keylen)
{
	struct wpa_supplicant *wpa_s = ctx;
	return wpa_drv_set_key(wpa_s, WPA_ALG_WEP,
			       unicast ? wpa_s->bssid :
			       (u8 *) "\xff\xff\xff\xff\xff\xff",
			       keyidx, unicast, (u8 *) "", 0, key, keylen);
}


/* Configure default/group WEP key for static WEP */
static int wpa_set_wep_key(void *ctx, int set_tx, int keyidx, const u8 *key,
			   size_t keylen)
{
	struct wpa_supplicant *wpa_s = ctx;
	return wpa_drv_set_key(wpa_s, WPA_ALG_WEP,
			       (u8 *) "\xff\xff\xff\xff\xff\xff",
			       keyidx, set_tx, (u8 *) "", 0, key, keylen);
}


static int wpa_supplicant_set_wpa_none_key(struct wpa_supplicant *wpa_s,
					   struct wpa_ssid *ssid)
{
	u8 key[32];
	size_t keylen;
	wpa_alg alg;
	u8 seq[6] = { 0 };

	/* IBSS/WPA-None uses only one key (Group) for both receiving and
	 * sending unicast and multicast packets. */

	if (ssid->mode != IEEE80211_MODE_IBSS) {
		wpa_printf(MSG_INFO, "WPA: Invalid mode %d (not IBSS/ad-hoc) "
			   "for WPA-None", ssid->mode);
		return -1;
	}

	if (!ssid->psk_set) {
		wpa_printf(MSG_INFO, "WPA: No PSK configured for WPA-None");
		return -1;
	}

	switch (wpa_s->group_cipher) {
	case WPA_CIPHER_CCMP:
		memcpy(key, ssid->psk, 16);
		keylen = 16;
		alg = WPA_ALG_CCMP;
		break;
	case WPA_CIPHER_TKIP:
		/* WPA-None uses the same Michael MIC key for both TX and RX */
		memcpy(key, ssid->psk, 16 + 8);
		memcpy(key + 16 + 8, ssid->psk + 16, 8);
		keylen = 32;
		alg = WPA_ALG_TKIP;
		break;
	default:
		wpa_printf(MSG_INFO, "WPA: Invalid group cipher %d for "
			   "WPA-None", wpa_s->group_cipher);
		return -1;
	}

	/* TODO: should actually remember the previously used seq#, both for TX
	 * and RX from each STA.. */

	return wpa_drv_set_key(wpa_s, alg, (u8 *) "\xff\xff\xff\xff\xff\xff",
			       0, 1, seq, 6, key, keylen);
}


static void wpa_supplicant_notify_eapol_done(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;
	wpa_msg(wpa_s, MSG_DEBUG, "WPA: EAPOL processing complete");
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
		wpa_supplicant_set_state(wpa_s, WPA_4WAY_HANDSHAKE);
	} else {
		eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
		wpa_supplicant_cancel_auth_timeout(wpa_s);
		wpa_supplicant_set_state(wpa_s, WPA_COMPLETED);
	}
}


struct wpa_blacklist * wpa_blacklist_get(struct wpa_supplicant *wpa_s,
					 const u8 *bssid)
{
	struct wpa_blacklist *e;

	e = wpa_s->blacklist;
	while (e) {
		if (memcmp(e->bssid, bssid, ETH_ALEN) == 0)
			return e;
		e = e->next;
	}

	return NULL;
}


int wpa_blacklist_add(struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	struct wpa_blacklist *e;

	e = wpa_blacklist_get(wpa_s, bssid);
	if (e) {
		e->count++;
		wpa_printf(MSG_DEBUG, "BSSID " MACSTR " blacklist count "
			   "incremented to %d",
			   MAC2STR(bssid), e->count);
		return 0;
	}

	e = malloc(sizeof(*e));
	if (e == NULL)
		return -1;
	memset(e, 0, sizeof(*e));
	memcpy(e->bssid, bssid, ETH_ALEN);
	e->count = 1;
	e->next = wpa_s->blacklist;
	wpa_s->blacklist = e;
	wpa_printf(MSG_DEBUG, "Added BSSID " MACSTR " into blacklist",
		   MAC2STR(bssid));

	return 0;
}


int wpa_blacklist_del(struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	struct wpa_blacklist *e, *prev = NULL;

	e = wpa_s->blacklist;
	while (e) {
		if (memcmp(e->bssid, bssid, ETH_ALEN) == 0) {
			if (prev == NULL) {
				wpa_s->blacklist = e->next;
			} else {
				prev->next = e->next;
			}
			wpa_printf(MSG_DEBUG, "Removed BSSID " MACSTR " from "
				   "blacklist", MAC2STR(bssid));
			free(e);
			return 0;
		}
		prev = e;
		e = e->next;
	}
	return -1;
}


void wpa_blacklist_clear(struct wpa_supplicant *wpa_s)
{
	struct wpa_blacklist *e, *prev;

	e = wpa_s->blacklist;
	wpa_s->blacklist = NULL;
	while (e) {
		prev = e;
		e = e->next;
		wpa_printf(MSG_DEBUG, "Removed BSSID " MACSTR " from "
			   "blacklist (clear)", MAC2STR(prev->bssid));
		free(prev);
	}
}


const char * wpa_ssid_txt(u8 *ssid, size_t ssid_len)
{
	static char ssid_txt[MAX_SSID_LEN + 1];
	char *pos;

	if (ssid_len > MAX_SSID_LEN)
		ssid_len = MAX_SSID_LEN;
	memcpy(ssid_txt, ssid, ssid_len);
	ssid_txt[ssid_len] = '\0';
	for (pos = ssid_txt; *pos != '\0'; pos++) {
		if ((u8) *pos < 32 || (u8) *pos >= 127)
			*pos = '_';
	}
	return ssid_txt;
}


void wpa_supplicant_req_scan(struct wpa_supplicant *wpa_s, int sec, int usec)
{
	wpa_msg(wpa_s, MSG_DEBUG, "Setting scan request: %d sec %d usec",
		sec, usec);
	eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
	eloop_register_timeout(sec, usec, wpa_supplicant_scan, wpa_s, NULL);
}


void wpa_supplicant_cancel_scan(struct wpa_supplicant *wpa_s)
{
	wpa_msg(wpa_s, MSG_DEBUG, "Cancelling scan request");
	eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
}


static void wpa_supplicant_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	wpa_msg(wpa_s, MSG_INFO, "Authentication with " MACSTR " timed out.",
		MAC2STR(wpa_s->bssid));
	wpa_blacklist_add(wpa_s, wpa_s->bssid);
	wpa_sm_notify_disassoc(wpa_s->wpa);
	wpa_supplicant_disassociate(wpa_s, REASON_DEAUTH_LEAVING);
	wpa_s->reassociate = 1;
	wpa_supplicant_req_scan(wpa_s, 0, 0);
}


void wpa_supplicant_req_auth_timeout(struct wpa_supplicant *wpa_s,
				     int sec, int usec)
{
	if (wpa_s->conf && wpa_s->conf->ap_scan == 0 &&
	    wpa_s->driver && strcmp(wpa_s->driver->name, "wired") == 0)
		return;

	wpa_msg(wpa_s, MSG_DEBUG, "Setting authentication timeout: %d sec "
		"%d usec", sec, usec);
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
	eloop_register_timeout(sec, usec, wpa_supplicant_timeout, wpa_s, NULL);
}


void wpa_supplicant_cancel_auth_timeout(struct wpa_supplicant *wpa_s)
{
	wpa_msg(wpa_s, MSG_DEBUG, "Cancelling authentication timeout");
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
	wpa_blacklist_del(wpa_s, wpa_s->bssid);
}


void wpa_supplicant_initiate_eapol(struct wpa_supplicant *wpa_s)
{
	struct eapol_config eapol_conf;
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK) {
		eapol_sm_notify_eap_success(wpa_s->eapol, FALSE);
		eapol_sm_notify_eap_fail(wpa_s->eapol, FALSE);
	}
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_WPA_NONE)
		eapol_sm_notify_portControl(wpa_s->eapol, ForceAuthorized);
	else
		eapol_sm_notify_portControl(wpa_s->eapol, Auto);

	memset(&eapol_conf, 0, sizeof(eapol_conf));
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		eapol_conf.accept_802_1x_keys = 1;
		eapol_conf.required_keys = 0;
		if (ssid->eapol_flags & EAPOL_FLAG_REQUIRE_KEY_UNICAST) {
			eapol_conf.required_keys |= EAPOL_REQUIRE_KEY_UNICAST;
		}
		if (ssid->eapol_flags & EAPOL_FLAG_REQUIRE_KEY_BROADCAST) {
			eapol_conf.required_keys |=
				EAPOL_REQUIRE_KEY_BROADCAST;
		}
	}
	eapol_conf.fast_reauth = wpa_s->conf->fast_reauth;
	eapol_conf.workaround = ssid->eap_workaround;
	eapol_sm_notify_config(wpa_s->eapol, ssid, &eapol_conf);
}


void wpa_supplicant_set_non_wpa_policy(struct wpa_supplicant *wpa_s,
				       struct wpa_ssid *ssid)
{
	int i;

	if (ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA)
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X_NO_WPA;
	else
		wpa_s->key_mgmt = WPA_KEY_MGMT_NONE;
	wpa_sm_set_ap_wpa_ie(wpa_s->wpa, NULL, 0);
	wpa_sm_set_ap_rsn_ie(wpa_s->wpa, NULL, 0);
	wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);
	wpa_s->pairwise_cipher = WPA_CIPHER_NONE;
	wpa_s->group_cipher = WPA_CIPHER_NONE;

	for (i = 0; i < NUM_WEP_KEYS; i++) {
		if (ssid->wep_key_len[i] > 5) {
			wpa_s->pairwise_cipher = WPA_CIPHER_WEP104;
			wpa_s->group_cipher = WPA_CIPHER_WEP104;
			break;
		} else if (ssid->wep_key_len[i] > 0) {
			wpa_s->pairwise_cipher = WPA_CIPHER_WEP40;
			wpa_s->group_cipher = WPA_CIPHER_WEP40;
			break;
		}
	}

	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_KEY_MGMT, wpa_s->key_mgmt);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_PAIRWISE,
			 wpa_s->pairwise_cipher);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_GROUP, wpa_s->group_cipher);

	pmksa_cache_clear_current(wpa_s->wpa);
}


static void wpa_supplicant_cleanup(struct wpa_supplicant *wpa_s)
{
	scard_deinit(wpa_s->scard);
	wpa_s->scard = NULL;
	wpa_sm_set_scard_ctx(wpa_s->wpa, NULL);
	eapol_sm_register_scard_ctx(wpa_s->eapol, NULL);
	l2_packet_deinit(wpa_s->l2);
	wpa_s->l2 = NULL;

	wpa_supplicant_ctrl_iface_deinit(wpa_s);
	if (wpa_s->conf != NULL) {
		wpa_config_free(wpa_s->conf);
		wpa_s->conf = NULL;
	}

	free(wpa_s->confname);
	wpa_s->confname = NULL;

	wpa_sm_set_eapol(wpa_s->wpa, NULL);
	eapol_sm_deinit(wpa_s->eapol);
	wpa_s->eapol = NULL;

	rsn_preauth_deinit(wpa_s->wpa);

	pmksa_candidate_free(wpa_s->wpa);
	pmksa_cache_free(wpa_s->wpa);
	wpa_sm_deinit(wpa_s->wpa);
	wpa_s->wpa = NULL;
	wpa_blacklist_clear(wpa_s);

	free(wpa_s->scan_results);
	wpa_s->scan_results = NULL;
	wpa_s->num_scan_results = 0;
}


void wpa_clear_keys(struct wpa_supplicant *wpa_s, const u8 *addr)
{
	u8 *bcast = (u8 *) "\xff\xff\xff\xff\xff\xff";

	if (wpa_s->keys_cleared) {
		/* Some drivers (e.g., ndiswrapper & NDIS drivers) seem to have
		 * timing issues with keys being cleared just before new keys
		 * are set or just after association or something similar. This
		 * shows up in group key handshake failing often because of the
		 * client not receiving the first encrypted packets correctly.
		 * Skipping some of the extra key clearing steps seems to help
		 * in completing group key handshake more reliably. */
		wpa_printf(MSG_DEBUG, "No keys have been configured - "
			   "skip key clearing");
		return;
	}

	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, bcast, 0, 0, NULL, 0, NULL, 0);
	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, bcast, 1, 0, NULL, 0, NULL, 0);
	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, bcast, 2, 0, NULL, 0, NULL, 0);
	wpa_drv_set_key(wpa_s, WPA_ALG_NONE, bcast, 3, 0, NULL, 0, NULL, 0);
	if (addr) {
		wpa_drv_set_key(wpa_s, WPA_ALG_NONE, addr, 0, 0, NULL, 0, NULL,
				0);
	}
	wpa_s->keys_cleared = 1;
}


const char * wpa_supplicant_state_txt(int state)
{
	switch (state) {
	case WPA_DISCONNECTED:
		return "DISCONNECTED";
	case WPA_INACTIVE:
		return "INACTIVE";
	case WPA_SCANNING:
		return "SCANNING";
	case WPA_ASSOCIATING:
		return "ASSOCIATING";
	case WPA_ASSOCIATED:
		return "ASSOCIATED";
	case WPA_4WAY_HANDSHAKE:
		return "4WAY_HANDSHAKE";
	case WPA_GROUP_HANDSHAKE:
		return "GROUP_HANDSHAKE";
	case WPA_COMPLETED:
		return "COMPLETED";
	default:
		return "UNKNOWN";
	}
}


void wpa_supplicant_set_state(struct wpa_supplicant *wpa_s, wpa_states state)
{
	wpa_printf(MSG_DEBUG, "State: %s -> %s",
		   wpa_supplicant_state_txt(wpa_s->wpa_state),
		   wpa_supplicant_state_txt(state));
	if (state == WPA_COMPLETED && wpa_s->new_connection) {
		wpa_s->new_connection = 0;
		wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_CONNECTED "- Connection to "
			MACSTR " completed %s",
			MAC2STR(wpa_s->bssid), wpa_s->reassociated_connection ?
			"(reauth)" : "(auth)");
		wpa_s->reassociated_connection = 1;
	} else if (state == WPA_DISCONNECTED || state == WPA_ASSOCIATING ||
		   state == WPA_ASSOCIATED) {
		wpa_s->new_connection = 1;
	}
	wpa_s->wpa_state = state;
}


wpa_states wpa_supplicant_get_state(struct wpa_supplicant *wpa_s)
{
	return wpa_s->wpa_state;
}


static void wpa_supplicant_terminate(int sig, void *eloop_ctx,
				     void *signal_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	for (wpa_s = wpa_s->head; wpa_s; wpa_s = wpa_s->next) {
		wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_TERMINATING "- signal %d "
			"received", sig);
	}
	eloop_terminate();
}


int wpa_supplicant_reload_configuration(struct wpa_supplicant *wpa_s)
{
	struct wpa_config *conf;
	int reconf_ctrl;
	if (wpa_s->confname == NULL)
		return -1;
	conf = wpa_config_read(wpa_s->confname);
	if (conf == NULL) {
		wpa_msg(wpa_s, MSG_ERROR, "Failed to parse the configuration "
			"file '%s' - exiting", wpa_s->confname);
		return -1;
	}

	reconf_ctrl = !!conf->ctrl_interface != !!wpa_s->conf->ctrl_interface
		|| (conf->ctrl_interface && wpa_s->conf->ctrl_interface &&
		    strcmp(conf->ctrl_interface, wpa_s->conf->ctrl_interface)
		    != 0);

	if (reconf_ctrl)
		wpa_supplicant_ctrl_iface_deinit(wpa_s);

	wpa_s->current_ssid = NULL;
	/*
	 * TODO: should notify EAPOL SM about changes in opensc_engine_path,
	 * pkcs11_engine_path, pkcs11_module_path.
	 */ 
	eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
	wpa_sm_set_config(wpa_s->wpa, NULL);
	wpa_sm_set_fast_reauth(wpa_s->wpa, wpa_s->conf->fast_reauth);
	pmksa_cache_notify_reconfig(wpa_s->wpa);
	rsn_preauth_deinit(wpa_s->wpa);
	wpa_config_free(wpa_s->conf);
	wpa_s->conf = conf;
	if (reconf_ctrl)
		wpa_supplicant_ctrl_iface_init(wpa_s);
	wpa_s->reassociate = 1;
	wpa_supplicant_req_scan(wpa_s, 0, 0);
	wpa_msg(wpa_s, MSG_DEBUG, "Reconfiguration completed");
	return 0;
}


#ifndef CONFIG_NATIVE_WINDOWS
static void wpa_supplicant_reconfig(int sig, void *eloop_ctx,
				    void *signal_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	wpa_printf(MSG_DEBUG, "Signal %d received - reconfiguring", sig);
	for (wpa_s = wpa_s->head; wpa_s; wpa_s = wpa_s->next) {
		if (wpa_supplicant_reload_configuration(wpa_s) < 0) {
			eloop_terminate();
		}
	}
}
#endif /* CONFIG_NATIVE_WINDOWS */


static void wpa_supplicant_gen_assoc_event(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *ssid;
	union wpa_event_data data;

	ssid = wpa_supplicant_get_ssid(wpa_s);
	if (ssid == NULL)
		return;

	wpa_printf(MSG_DEBUG, "Already associated with a configured network - "
		   "generating associated event");
	memset(&data, 0, sizeof(data));
	wpa_supplicant_event(wpa_s, EVENT_ASSOC, &data);
}


void wpa_supplicant_scan(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct wpa_ssid *ssid;
	int enabled, scan_req = 0;

	if (wpa_s->disconnected)
		return;

	enabled = 0;
	ssid = wpa_s->conf->ssid;
	while (ssid) {
		if (!ssid->disabled) {
			enabled++;
			break;
		}
		ssid = ssid->next;
	}
	if (!enabled && !wpa_s->scan_req) {
		wpa_printf(MSG_DEBUG, "No enabled networks - do not scan");
		wpa_supplicant_set_state(wpa_s, WPA_INACTIVE);
		return;
	}
	scan_req = wpa_s->scan_req;
	wpa_s->scan_req = 0;

	if (wpa_s->conf->ap_scan == 0) {
		wpa_supplicant_gen_assoc_event(wpa_s);
		return;
	}

	if (wpa_s->wpa_state == WPA_DISCONNECTED ||
	    wpa_s->wpa_state == WPA_INACTIVE)
		wpa_supplicant_set_state(wpa_s, WPA_SCANNING);

	ssid = wpa_s->conf->ssid;
	if (wpa_s->prev_scan_ssid != BROADCAST_SSID_SCAN) {
		while (ssid) {
			if (ssid == wpa_s->prev_scan_ssid) {
				ssid = ssid->next;
				break;
			}
			ssid = ssid->next;
		}
	}
	while (ssid) {
		if (!ssid->disabled &&
		    (ssid->scan_ssid || wpa_s->conf->ap_scan == 2))
			break;
		ssid = ssid->next;
	}

	if (scan_req != 2 && wpa_s->conf->ap_scan == 2) {
		/*
		 * ap_scan=2 mode - try to associate with each SSID instead of
		 * scanning for each scan_ssid=1 network.
		 */
		if (ssid == NULL)
			return;
		if (ssid->next) {
			/* Continue from the next SSID on the next attempt. */
			wpa_s->prev_scan_ssid = ssid;
		} else {
			/* Start from the beginning of the SSID list. */
			wpa_s->prev_scan_ssid = BROADCAST_SSID_SCAN;
		}
		wpa_supplicant_associate(wpa_s, NULL, ssid);
		return;
	}

	wpa_printf(MSG_DEBUG, "Starting AP scan (%s SSID)",
		   ssid ? "specific": "broadcast");
	if (ssid) {
		wpa_hexdump_ascii(MSG_DEBUG, "Scan SSID",
				  ssid->ssid, ssid->ssid_len);
		wpa_s->prev_scan_ssid = ssid;
	} else
		wpa_s->prev_scan_ssid = BROADCAST_SSID_SCAN;

	if (wpa_drv_scan(wpa_s, ssid ? ssid->ssid : NULL,
			 ssid ? ssid->ssid_len : 0)) {
		wpa_printf(MSG_WARNING, "Failed to initiate AP scan.");
		wpa_supplicant_req_scan(wpa_s, 10, 0);
	}
}


static wpa_cipher cipher_suite2driver(int cipher)
{
	switch (cipher) {
	case WPA_CIPHER_NONE:
		return CIPHER_NONE;
	case WPA_CIPHER_WEP40:
		return CIPHER_WEP40;
	case WPA_CIPHER_WEP104:
		return CIPHER_WEP104;
	case WPA_CIPHER_CCMP:
		return CIPHER_CCMP;
	case WPA_CIPHER_TKIP:
	default:
		return CIPHER_TKIP;
	}
}


static wpa_key_mgmt key_mgmt2driver(int key_mgmt)
{
	switch (key_mgmt) {
	case WPA_KEY_MGMT_NONE:
		return KEY_MGMT_NONE;
	case WPA_KEY_MGMT_IEEE8021X_NO_WPA:
		return KEY_MGMT_802_1X_NO_WPA;
	case WPA_KEY_MGMT_IEEE8021X:
		return KEY_MGMT_802_1X;
	case WPA_KEY_MGMT_WPA_NONE:
		return KEY_MGMT_WPA_NONE;
	case WPA_KEY_MGMT_PSK:
	default:
		return KEY_MGMT_PSK;
	}
}


static int wpa_supplicant_suites_from_ai(struct wpa_supplicant *wpa_s,
					 struct wpa_ssid *ssid,
					 struct wpa_ie_data *ie) {
	if (wpa_sm_parse_own_wpa_ie(wpa_s->wpa, ie)) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Failed to parse WPA IE from "
			"association info");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "WPA: Using WPA IE from AssocReq to set cipher "
		   "suites");
	if (!(ie->group_cipher & ssid->group_cipher)) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Driver used disabled group "
			"cipher 0x%x (mask 0x%x) - reject",
			ie->group_cipher, ssid->group_cipher);
		return -1;
	}
	if (!(ie->pairwise_cipher & ssid->pairwise_cipher)) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Driver used disabled pairwise "
			"cipher 0x%x (mask 0x%x) - reject",
			ie->pairwise_cipher, ssid->pairwise_cipher);
		return -1;
	}
	if (!(ie->key_mgmt & ssid->key_mgmt)) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Driver used disabled key "
			"management 0x%x (mask 0x%x) - reject",
			ie->key_mgmt, ssid->key_mgmt);
		return -1;
	}

	return 0;
}


int wpa_supplicant_set_suites(struct wpa_supplicant *wpa_s,
			      struct wpa_scan_result *bss,
			      struct wpa_ssid *ssid,
			      u8 *wpa_ie, size_t *wpa_ie_len)
{
	struct wpa_ie_data ie;
	int sel, proto;
	u8 *ap_ie;
	size_t ap_ie_len;

	if (bss && bss->rsn_ie_len && (ssid->proto & WPA_PROTO_RSN)) {
		wpa_msg(wpa_s, MSG_DEBUG, "RSN: using IEEE 802.11i/D9.0");
		proto = WPA_PROTO_RSN;
		ap_ie = bss->rsn_ie;
		ap_ie_len = bss->rsn_ie_len;
	} else if (bss) {
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using IEEE 802.11i/D3.0");
		proto = WPA_PROTO_WPA;
		ap_ie = bss->wpa_ie;
		ap_ie_len = bss->wpa_ie_len;
	} else {
		if (ssid->proto & WPA_PROTO_RSN)
			proto = WPA_PROTO_RSN;
		else
			proto = WPA_PROTO_WPA;
		ap_ie = NULL;
		ap_ie_len = 0;
		if (wpa_supplicant_suites_from_ai(wpa_s, ssid, &ie) < 0) {
			memset(&ie, 0, sizeof(ie));
			ie.group_cipher = ssid->group_cipher;
			ie.pairwise_cipher = ssid->pairwise_cipher;
			ie.key_mgmt = ssid->key_mgmt;
			wpa_printf(MSG_DEBUG, "WPA: Set cipher suites based "
				   "on configuration");
		}
	}

	if (ap_ie && wpa_parse_wpa_ie(ap_ie, ap_ie_len, &ie)) {
		wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to parse WPA IE for "
			"the selected BSS.");
		return -1;
	}
	wpa_printf(MSG_DEBUG, "WPA: Selected cipher suites: group %d "
		   "pairwise %d key_mgmt %d",
		   ie.group_cipher, ie.pairwise_cipher, ie.key_mgmt);

	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_PROTO, proto);

	if (wpa_sm_set_ap_wpa_ie(wpa_s->wpa, bss ? bss->wpa_ie : NULL,
				 bss ? bss->wpa_ie_len : 0) ||
	    wpa_sm_set_ap_rsn_ie(wpa_s->wpa, bss ? bss->rsn_ie : NULL,
				 bss ? bss->rsn_ie_len : 0))
		return -1;

	sel = ie.group_cipher & ssid->group_cipher;
	if (sel & WPA_CIPHER_CCMP) {
		wpa_s->group_cipher = WPA_CIPHER_CCMP;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using GTK CCMP");
	} else if (sel & WPA_CIPHER_TKIP) {
		wpa_s->group_cipher = WPA_CIPHER_TKIP;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using GTK TKIP");
	} else if (sel & WPA_CIPHER_WEP104) {
		wpa_s->group_cipher = WPA_CIPHER_WEP104;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using GTK WEP104");
	} else if (sel & WPA_CIPHER_WEP40) {
		wpa_s->group_cipher = WPA_CIPHER_WEP40;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using GTK WEP40");
	} else {
		wpa_printf(MSG_WARNING, "WPA: Failed to select group cipher.");
		return -1;
	}

	sel = ie.pairwise_cipher & ssid->pairwise_cipher;
	if (sel & WPA_CIPHER_CCMP) {
		wpa_s->pairwise_cipher = WPA_CIPHER_CCMP;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using PTK CCMP");
	} else if (sel & WPA_CIPHER_TKIP) {
		wpa_s->pairwise_cipher = WPA_CIPHER_TKIP;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using PTK TKIP");
	} else if (sel & WPA_CIPHER_NONE) {
		wpa_s->pairwise_cipher = WPA_CIPHER_NONE;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using PTK NONE");
	} else {
		wpa_printf(MSG_WARNING, "WPA: Failed to select pairwise "
			   "cipher.");
		return -1;
	}

	sel = ie.key_mgmt & ssid->key_mgmt;
	if (sel & WPA_KEY_MGMT_IEEE8021X) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT 802.1X");
	} else if (sel & WPA_KEY_MGMT_PSK) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_PSK;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT WPA-PSK");
	} else if (sel & WPA_KEY_MGMT_WPA_NONE) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_WPA_NONE;
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT WPA-NONE");
	} else {
		wpa_printf(MSG_WARNING, "WPA: Failed to select authenticated "
			   "key management type.");
		return -1;
	}

	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_KEY_MGMT, wpa_s->key_mgmt);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_PAIRWISE,
			 wpa_s->pairwise_cipher);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_GROUP, wpa_s->group_cipher);

	if (wpa_sm_set_assoc_wpa_ie_default(wpa_s->wpa, wpa_ie, wpa_ie_len)) {
		wpa_printf(MSG_WARNING, "WPA: Failed to generate WPA IE.");
		return -1;
	}

	if (ssid->key_mgmt & WPA_KEY_MGMT_PSK)
		wpa_sm_set_pmk(wpa_s->wpa, ssid->psk, PMK_LEN);
	else
		wpa_sm_set_pmk_from_pmksa(wpa_s->wpa);

	return 0;
}


void wpa_supplicant_associate(struct wpa_supplicant *wpa_s,
			      struct wpa_scan_result *bss,
			      struct wpa_ssid *ssid)
{
	u8 wpa_ie[80];
	size_t wpa_ie_len;
	int use_crypt;
	int algs = AUTH_ALG_OPEN_SYSTEM;
	int cipher_pairwise, cipher_group;
	struct wpa_driver_associate_params params;
	int wep_keys_set = 0;
	struct wpa_driver_capa capa;

	wpa_s->reassociate = 0;
	if (bss) {
		wpa_msg(wpa_s, MSG_INFO, "Trying to associate with " MACSTR
			" (SSID='%s' freq=%d MHz)", MAC2STR(bss->bssid),
			wpa_ssid_txt(bss->ssid, bss->ssid_len), bss->freq);
		memset(wpa_s->bssid, 0, ETH_ALEN);
	} else {
		wpa_msg(wpa_s, MSG_INFO, "Trying to associate with SSID '%s'",
			wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
	}
	wpa_supplicant_cancel_scan(wpa_s);

	/* Starting new association, so clear the possibly used WPA IE from the
	 * previous association. */
	wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);

	if (ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if (ssid->leap) {
			if (ssid->non_leap == 0)
				algs = AUTH_ALG_LEAP;
			else
				algs |= AUTH_ALG_LEAP;
		}
	}
	wpa_printf(MSG_DEBUG, "Automatic auth_alg selection: 0x%x", algs);
	if (ssid->auth_alg) {
		algs = 0;
		if (ssid->auth_alg & WPA_AUTH_ALG_OPEN)
			algs |= AUTH_ALG_OPEN_SYSTEM;
		if (ssid->auth_alg & WPA_AUTH_ALG_SHARED)
			algs |= AUTH_ALG_SHARED_KEY;
		if (ssid->auth_alg & WPA_AUTH_ALG_LEAP)
			algs |= AUTH_ALG_LEAP;
		wpa_printf(MSG_DEBUG, "Overriding auth_alg selection: 0x%x",
			   algs);
	}
	wpa_drv_set_auth_alg(wpa_s, algs);

	if (bss && (bss->wpa_ie_len || bss->rsn_ie_len) &&
	    (ssid->key_mgmt & (WPA_KEY_MGMT_IEEE8021X | WPA_KEY_MGMT_PSK))) {
		int try_opportunistic;
		try_opportunistic = ssid->proactive_key_caching &&
			(ssid->proto & WPA_PROTO_RSN);
		if (pmksa_cache_set_current(wpa_s->wpa, NULL, bss->bssid,
					    wpa_s->current_ssid,
					    try_opportunistic) == 0)
			eapol_sm_notify_pmkid_attempt(wpa_s->eapol, 1);
		wpa_ie_len = sizeof(wpa_ie);
		if (wpa_supplicant_set_suites(wpa_s, bss, ssid,
					      wpa_ie, &wpa_ie_len)) {
			wpa_printf(MSG_WARNING, "WPA: Failed to set WPA key "
				   "management and encryption suites");
			return;
		}
	} else if (ssid->key_mgmt &
		   (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_IEEE8021X |
		    WPA_KEY_MGMT_WPA_NONE)) {
		wpa_ie_len = sizeof(wpa_ie);
		if (wpa_supplicant_set_suites(wpa_s, NULL, ssid,
					      wpa_ie, &wpa_ie_len)) {
			wpa_printf(MSG_WARNING, "WPA: Failed to set WPA key "
				   "management and encryption suites (no scan "
				   "results)");
			return;
		}
	} else {
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
		wpa_ie_len = 0;
	}

	wpa_clear_keys(wpa_s, bss ? bss->bssid : NULL);
	use_crypt = 1;
	cipher_pairwise = cipher_suite2driver(wpa_s->pairwise_cipher);
	cipher_group = cipher_suite2driver(wpa_s->group_cipher);
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		int i;
		if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE)
			use_crypt = 0;
		for (i = 0; i < NUM_WEP_KEYS; i++) {
			if (ssid->wep_key_len[i]) {
				use_crypt = 1;
				wep_keys_set = 1;
				wpa_set_wep_key(wpa_s,
						i == ssid->wep_tx_keyidx,
						i, ssid->wep_key[i],
						ssid->wep_key_len[i]);
			}
		}
	}

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if ((ssid->eapol_flags &
		     (EAPOL_FLAG_REQUIRE_KEY_UNICAST |
		      EAPOL_FLAG_REQUIRE_KEY_BROADCAST)) == 0 &&
		    !wep_keys_set) {
			use_crypt = 0;
		} else {
			/* Assume that dynamic WEP-104 keys will be used and
			 * set cipher suites in order for drivers to expect
			 * encryption. */
			cipher_pairwise = cipher_group = CIPHER_WEP104;
		}
	}

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPA_NONE) {
		/* Set the key before (and later after) association */
		wpa_supplicant_set_wpa_none_key(wpa_s, ssid);
	}

	wpa_drv_set_drop_unencrypted(wpa_s, use_crypt);
	wpa_supplicant_set_state(wpa_s, WPA_ASSOCIATING);
	memset(&params, 0, sizeof(params));
	if (bss) {
		params.bssid = bss->bssid;
		params.ssid = bss->ssid;
		params.ssid_len = bss->ssid_len;
		params.freq = bss->freq;
	} else {
		params.ssid = ssid->ssid;
		params.ssid_len = ssid->ssid_len;
	}
	params.wpa_ie = wpa_ie;
	params.wpa_ie_len = wpa_ie_len;
	params.pairwise_suite = cipher_pairwise;
	params.group_suite = cipher_group;
	params.key_mgmt_suite = key_mgmt2driver(wpa_s->key_mgmt);
	params.auth_alg = algs;
	params.mode = ssid->mode;
	if (wpa_drv_associate(wpa_s, &params) < 0) {
		wpa_msg(wpa_s, MSG_INFO, "Association request to the driver "
			"failed");
		/* try to continue anyway; new association will be tried again
		 * after timeout */
	}

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPA_NONE) {
		/* Set the key after the association just in case association
		 * cleared the previously configured key. */
		wpa_supplicant_set_wpa_none_key(wpa_s, ssid);
		/* No need to timeout authentication since there is no key
		 * management. */
		wpa_supplicant_cancel_auth_timeout(wpa_s);
		wpa_supplicant_set_state(wpa_s, WPA_COMPLETED);
	} else {
		/* Timeout for IEEE 802.11 authentication and association */
		wpa_supplicant_req_auth_timeout(wpa_s, 5, 0);
	}

	if (wep_keys_set && wpa_drv_get_capa(wpa_s, &capa) == 0 &&
	    capa.flags & WPA_DRIVER_FLAGS_SET_KEYS_AFTER_ASSOC) {
		/* Set static WEP keys again */
		int i;
		for (i = 0; i < NUM_WEP_KEYS; i++) {
			if (ssid->wep_key_len[i]) {
				wpa_set_wep_key(wpa_s,
						i == ssid->wep_tx_keyidx,
						i, ssid->wep_key[i],
						ssid->wep_key_len[i]);
			}
		}
	}

	wpa_s->current_ssid = ssid;
	wpa_sm_set_config(wpa_s->wpa, wpa_s->current_ssid);
	wpa_supplicant_initiate_eapol(wpa_s);
}


void wpa_supplicant_disassociate(struct wpa_supplicant *wpa_s,
				 int reason_code)
{
	u8 *addr = NULL;
	wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
	if (memcmp(wpa_s->bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) != 0) {
		wpa_drv_disassociate(wpa_s, wpa_s->bssid, reason_code);
		addr = wpa_s->bssid;
	}
	wpa_clear_keys(wpa_s, addr);
	wpa_s->current_ssid = NULL;
	wpa_sm_set_config(wpa_s->wpa, NULL);
	eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
	eapol_sm_notify_portEnabled(wpa_s->eapol, FALSE);
	eapol_sm_notify_portValid(wpa_s->eapol, FALSE);
}


void wpa_supplicant_deauthenticate(struct wpa_supplicant *wpa_s,
				   int reason_code)
{
	u8 *addr = NULL;
	wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
	if (memcmp(wpa_s->bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) != 0) {
		wpa_drv_deauthenticate(wpa_s, wpa_s->bssid, reason_code);
		addr = wpa_s->bssid;
	}
	wpa_clear_keys(wpa_s, addr);
	wpa_s->current_ssid = NULL;
	wpa_sm_set_config(wpa_s->wpa, NULL);
	eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
	eapol_sm_notify_portEnabled(wpa_s->eapol, FALSE);
	eapol_sm_notify_portValid(wpa_s->eapol, FALSE);
}


int wpa_supplicant_get_scan_results(struct wpa_supplicant *wpa_s)
{
#define SCAN_AP_LIMIT 128
	struct wpa_scan_result *results, *tmp;
	int num;

	results = malloc(SCAN_AP_LIMIT * sizeof(struct wpa_scan_result));
	if (results == NULL) {
		wpa_printf(MSG_WARNING, "Failed to allocate memory for scan "
			   "results");
		return -1;
	}

	num = wpa_drv_get_scan_results(wpa_s, results, SCAN_AP_LIMIT);
	wpa_printf(MSG_DEBUG, "Scan results: %d", num);
	if (num < 0) {
		wpa_printf(MSG_DEBUG, "Failed to get scan results");
		free(results);
		return -1;
	}
	if (num > SCAN_AP_LIMIT) {
		wpa_printf(MSG_INFO, "Not enough room for all APs (%d < %d)",
			   num, SCAN_AP_LIMIT);
		num = SCAN_AP_LIMIT;
	}

	/* Free unneeded memory for unused scan result entries */
	tmp = realloc(results, num * sizeof(struct wpa_scan_result));
	if (tmp || num == 0) {
		results = tmp;
	}

	free(wpa_s->scan_results);
	wpa_s->scan_results = results;
	wpa_s->num_scan_results = num;

	return 0;
}


static int wpa_get_beacon_ie(struct wpa_supplicant *wpa_s)
{
	int i, ret = 0;
	struct wpa_scan_result *results, *curr = NULL;

	results = wpa_s->scan_results;
	if (results == NULL) {
		return -1;
	}

	for (i = 0; i < wpa_s->num_scan_results; i++) {
		if (memcmp(results[i].bssid, wpa_s->bssid, ETH_ALEN) == 0) {
			curr = &results[i];
			break;
		}
	}

	if (curr) {
		if (wpa_sm_set_ap_wpa_ie(wpa_s->wpa, curr->wpa_ie,
					 curr->wpa_ie_len) ||
		    wpa_sm_set_ap_rsn_ie(wpa_s->wpa, curr->rsn_ie,
					 curr->rsn_ie_len))
			ret = -1;
	} else {
		ret = -1;
	}

	return ret;
}


int wpa_supplicant_get_beacon_ie(struct wpa_supplicant *wpa_s)
{
	if (wpa_get_beacon_ie(wpa_s) == 0) {
		return 0;
	}

	/* No WPA/RSN IE found in the cached scan results. Try to get updated
	 * scan results from the driver. */
	if (wpa_supplicant_get_scan_results(wpa_s) < 0) {
		return -1;
	}

	return wpa_get_beacon_ie(wpa_s);
}


/**
 * wpa_supplicant_get_ssid - get a pointer to the current network structure
 * @wpa_s: pointer to wpa_supplicant data
 *
 * Returns: a pointer to the current network structure or %NULL on failure
 */
struct wpa_ssid * wpa_supplicant_get_ssid(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *entry;
	u8 ssid[MAX_SSID_LEN];
	int ssid_len;
	u8 bssid[ETH_ALEN];

	ssid_len = wpa_drv_get_ssid(wpa_s, ssid);
	if (ssid_len < 0) {
		wpa_printf(MSG_WARNING, "Could not read SSID from driver.");
		return NULL;
	}

	if (wpa_drv_get_bssid(wpa_s, bssid) < 0) {
		wpa_printf(MSG_WARNING, "Could not read BSSID from driver.");
		return NULL;
	}

	entry = wpa_s->conf->ssid;
	while (entry) {
		if (!entry->disabled &&
		    ssid_len == entry->ssid_len &&
		    memcmp(ssid, entry->ssid, ssid_len) == 0 &&
		    (!entry->bssid_set ||
		     memcmp(bssid, entry->bssid, ETH_ALEN) == 0))
			return entry;
		entry = entry->next;
	}

	return NULL;
}


int wpa_supplicant_get_bssid(struct wpa_supplicant *wpa_s, u8 *bssid)
{
	return wpa_drv_get_bssid(wpa_s, bssid);
}


int wpa_supplicant_set_key(struct wpa_supplicant *wpa_s, wpa_alg alg,
			   const u8 *addr, int key_idx, int set_tx,
			   const u8 *seq, size_t seq_len,
			   const u8 *key, size_t key_len)
{
	return wpa_drv_set_key(wpa_s, alg, addr, key_idx, set_tx, seq, seq_len,
			       key, key_len);
}


int wpa_supplicant_add_pmkid(struct wpa_supplicant *wpa_s,
			     const u8 *bssid, const u8 *pmkid)
{
	return wpa_drv_add_pmkid(wpa_s, bssid, pmkid);
}


int wpa_supplicant_remove_pmkid(struct wpa_supplicant *wpa_s,
				const u8 *bssid, const u8 *pmkid)
{
	return wpa_drv_remove_pmkid(wpa_s, bssid, pmkid);
}


static int wpa_supplicant_set_driver(struct wpa_supplicant *wpa_s,
				     const char *name)
{
	int i;

	if (wpa_s == NULL)
		return -1;

	if (wpa_supplicant_drivers[0] == NULL) {
		wpa_printf(MSG_ERROR, "No driver interfaces build into "
			   "wpa_supplicant.");
		return -1;
	}

	if (name == NULL) {
		/* default to first driver in the list */
		wpa_s->driver = wpa_supplicant_drivers[0];
		return 0;
	}

	for (i = 0; wpa_supplicant_drivers[i]; i++) {
		if (strcmp(name, wpa_supplicant_drivers[i]->name) == 0) {
			wpa_s->driver = wpa_supplicant_drivers[i];
			return 0;
		}
	}

	printf("Unsupported driver '%s'.\n", name);
	return -1;
}


static void wpa_supplicant_fd_workaround(void)
{
	int s, i;
	/* When started from pcmcia-cs scripts, wpa_supplicant might start with
	 * fd 0, 1, and 2 closed. This will cause some issues because many
	 * places in wpa_supplicant are still printing out to stdout. As a
	 * workaround, make sure that fd's 0, 1, and 2 are not used for other
	 * sockets. */
	for (i = 0; i < 3; i++) {
		s = open("/dev/null", O_RDWR);
		if (s > 2) {
			close(s);
			break;
		}
	}
}


void wpa_supplicant_rx_eapol(void *ctx, unsigned char *src_addr,
			     unsigned char *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_printf(MSG_DEBUG, "RX EAPOL from " MACSTR, MAC2STR(src_addr));
	wpa_hexdump(MSG_MSGDUMP, "RX EAPOL", buf, len);

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE) {
		wpa_printf(MSG_DEBUG, "Ignored received EAPOL frame since "
			   "no key management is configured");
		return;
	}

	if (wpa_s->eapol_received == 0) {
		/* Timeout for completing IEEE 802.1X and WPA authentication */
		wpa_supplicant_req_auth_timeout(
			wpa_s,
			(wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X ||
			 wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) ?
			70 : 10, 0);
	}
	wpa_s->eapol_received++;

	if (wpa_s->countermeasures) {
		wpa_printf(MSG_INFO, "WPA: Countermeasures - dropped EAPOL "
			   "packet");
		return;
	}

	/* Source address of the incoming EAPOL frame could be compared to the
	 * current BSSID. However, it is possible that a centralized
	 * Authenticator could be using another MAC address than the BSSID of
	 * an AP, so just allow any address to be used for now. The replies are
	 * still sent to the current BSSID (if available), though. */

	memcpy(wpa_s->last_eapol_src, src_addr, ETH_ALEN);
	if (wpa_s->key_mgmt != WPA_KEY_MGMT_PSK &&
	    eapol_sm_rx_eapol(wpa_s->eapol, src_addr, buf, len) > 0)
		return;
	wpa_drv_poll(wpa_s);
	wpa_sm_rx_eapol(wpa_s->wpa, src_addr, buf, len);
}


int wpa_supplicant_driver_init(struct wpa_supplicant *wpa_s,
			       int wait_for_interface)
{
	static int interface_count = 0;

	for (;;) {
		if (wpa_s->driver->send_eapol) {
			const u8 *addr = wpa_drv_get_mac_addr(wpa_s);
			if (addr)
				memcpy(wpa_s->own_addr, addr, ETH_ALEN);
			break;
		}
		wpa_s->l2 = l2_packet_init(wpa_s->ifname,
					   wpa_drv_get_mac_addr(wpa_s),
					   ETH_P_EAPOL,
					   wpa_supplicant_rx_eapol, wpa_s);
		if (wpa_s->l2)
			break;
		else if (!wait_for_interface)
			return -1;
		printf("Waiting for interface..\n");
		sleep(5);
	}

	if (wpa_s->l2 && l2_packet_get_own_addr(wpa_s->l2, wpa_s->own_addr)) {
		fprintf(stderr, "Failed to get own L2 address\n");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "Own MAC address: " MACSTR,
		   MAC2STR(wpa_s->own_addr));

	/* Backwards compatibility call to set_wpa() handler. This is called
	 * only just after init and just before deinit, so these handler can be
	 * used to implement same functionality. */
	if (wpa_drv_set_wpa(wpa_s, 1) < 0) {
		struct wpa_driver_capa capa;
		if (wpa_drv_get_capa(wpa_s, &capa) < 0 ||
		    !(capa.flags & (WPA_DRIVER_CAPA_KEY_MGMT_WPA |
				    WPA_DRIVER_CAPA_KEY_MGMT_WPA2))) {
			wpa_printf(MSG_DEBUG, "Driver does not support WPA.");
			/* Continue to allow non-WPA modes to be used. */
		} else {
			fprintf(stderr, "Failed to enable WPA in the "
				"driver.\n");
			return -1;
		}
	}

	wpa_clear_keys(wpa_s, NULL);

	/* Make sure that TKIP countermeasures are not left enabled (could
	 * happen if wpa_supplicant is killed during countermeasures. */
	wpa_drv_set_countermeasures(wpa_s, 0);

	wpa_drv_set_drop_unencrypted(wpa_s, 1);

	wpa_s->prev_scan_ssid = BROADCAST_SSID_SCAN;
	wpa_supplicant_req_scan(wpa_s, interface_count, 100000);
	interface_count++;

	return 0;
}


static void usage(void)
{
	int i;
	printf("%s\n\n%s\n"
	       "usage:\n"
	       "  wpa_supplicant [-BddehLqqvwW] -i<ifname> -c<config file> "
	       "[-D<driver>] \\\n"
	       "      [-P<pid file>] "
	       "[-N -i<ifname> -c<conf> [-D<driver>] ...]\n"
	       "\n"
	       "drivers:\n",
	       wpa_supplicant_version, wpa_supplicant_license);

	for (i = 0; wpa_supplicant_drivers[i]; i++) {
		printf("  %s = %s\n",
		       wpa_supplicant_drivers[i]->name,
		       wpa_supplicant_drivers[i]->desc);
	}

	printf("options:\n"
	       "  -B = run daemon in the background\n"
	       "  -d = increase debugging verbosity (-dd even more)\n"
	       "  -K = include keys (passwords, etc.) in debug output\n"
	       "  -t = include timestamp in debug messages\n"
	       "  -h = show this help text\n"
	       "  -L = show license (GPL and BSD)\n"
	       "  -q = decrease debugging verbosity (-qq even less)\n"
	       "  -v = show version\n"
	       "  -w = wait for interface to be added, if needed\n"
	       "  -W = wait for a control interface monitor before starting\n"
	       "  -N = start describing new interface\n");
}


static void license(void)
{
	printf("%s\n\n%s\n",
	       wpa_supplicant_version, wpa_supplicant_full_license);
}


static struct wpa_supplicant * wpa_supplicant_alloc(void)
{
	struct wpa_supplicant *wpa_s;

	wpa_s = malloc(sizeof(*wpa_s));
	if (wpa_s == NULL)
		return NULL;
	memset(wpa_s, 0, sizeof(*wpa_s));
	wpa_s->ctrl_sock = -1;
	wpa_s->scan_req = 1;

	return wpa_s;
}


struct wpa_interface {
	const char *confname, *driver, *ifname;
};


static int wpa_supplicant_init(struct wpa_supplicant *wpa_s,
			       struct wpa_interface *iface)
{
	wpa_printf(MSG_DEBUG, "Initializing interface '%s' conf '%s' driver "
		   "'%s'", iface->ifname, iface->confname,
		   iface->driver ? iface->driver : "default");

	if (wpa_supplicant_set_driver(wpa_s, iface->driver) < 0) {
		return -1;
	}

	if (iface->confname) {
		wpa_s->confname = rel2abs_path(iface->confname);
		if (wpa_s->confname == NULL) {
			wpa_printf(MSG_ERROR, "Failed to get absolute path "
				   "for configuration file '%s'.",
				   iface->confname);
			return -1;
		}
		wpa_printf(MSG_DEBUG, "Configuration file '%s' -> '%s'",
			   iface->confname, wpa_s->confname);
		wpa_s->conf = wpa_config_read(wpa_s->confname);
		if (wpa_s->conf == NULL) {
			printf("Failed to read configuration file '%s'.\n",
			       wpa_s->confname);
			return -1;
		}
	}

	if (wpa_s->conf == NULL) {
		usage();
		printf("\nNo configuration found.\n");
		return -1;
	}

	if (iface->ifname == NULL) {
		usage();
		printf("\nInterface name is required.\n");
		return -1;
	}
	if (strlen(iface->ifname) >= sizeof(wpa_s->ifname)) {
		printf("Too long interface name '%s'.\n", iface->ifname);
		return -1;
	}
	strncpy(wpa_s->ifname, iface->ifname, sizeof(wpa_s->ifname));

	return 0;
}


static int wpa_supplicant_init2(struct wpa_supplicant *wpa_s,
				int wait_for_interface)
{
	const char *ifname;
	struct eapol_ctx *ctx;

	wpa_printf(MSG_DEBUG, "Initializing interface (2) '%s'",
		   wpa_s->ifname);

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		printf("Failed to allocate EAPOL context.\n");
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->ctx = wpa_s;
	ctx->msg_ctx = wpa_s;
	ctx->eapol_send_ctx = wpa_s;
	ctx->preauth = 0;
	ctx->eapol_done_cb = wpa_supplicant_notify_eapol_done;
	ctx->eapol_send = wpa_supplicant_eapol_send;
	ctx->set_wep_key = wpa_eapol_set_wep_key;
	ctx->opensc_engine_path = wpa_s->conf->opensc_engine_path;
	ctx->pkcs11_engine_path = wpa_s->conf->pkcs11_engine_path;
	ctx->pkcs11_module_path = wpa_s->conf->pkcs11_module_path;
	wpa_s->eapol = eapol_sm_init(ctx);
	if (wpa_s->eapol == NULL) {
		free(ctx);
		printf("Failed to initialize EAPOL state machines.\n");
		return -1;
	}

	/* RSNA Supplicant Key Management - INITIALIZE */
	eapol_sm_notify_portEnabled(wpa_s->eapol, FALSE);
	eapol_sm_notify_portValid(wpa_s->eapol, FALSE);

	/* Initialize driver interface and register driver event handler before
	 * L2 receive handler so that association events are processed before
	 * EAPOL-Key packets if both become available for the same select()
	 * call. */
	wpa_s->drv_priv = wpa_drv_init(wpa_s, wpa_s->ifname);
	if (wpa_s->drv_priv == NULL) {
		fprintf(stderr, "Failed to initialize driver interface\n");
		return -1;
	}
	if (wpa_drv_set_param(wpa_s, wpa_s->conf->driver_param) < 0) {
		fprintf(stderr, "Driver interface rejected driver_param "
			"'%s'\n", wpa_s->conf->driver_param);
		return -1;
	}

	ifname = wpa_drv_get_ifname(wpa_s);
	if (ifname && strcmp(ifname, wpa_s->ifname) != 0) {
		wpa_printf(MSG_DEBUG, "Driver interface replaced interface "
			   "name with '%s'", ifname);
		strncpy(wpa_s->ifname, ifname, sizeof(wpa_s->ifname));
	}

	wpa_s->wpa = wpa_sm_init(wpa_s);
	if (wpa_s->wpa == NULL) {
		fprintf(stderr, "Failed to initialize WPA state machine\n");
		return -1;
	}
	wpa_sm_set_ifname(wpa_s->wpa, wpa_s->ifname);
	wpa_sm_set_fast_reauth(wpa_s->wpa, wpa_s->conf->fast_reauth);
	wpa_sm_set_eapol(wpa_s->wpa, wpa_s->eapol);

	if (wpa_s->conf->dot11RSNAConfigPMKLifetime &&
	    wpa_sm_set_param(wpa_s->wpa, RSNA_PMK_LIFETIME,
			     wpa_s->conf->dot11RSNAConfigPMKLifetime)) {
		fprintf(stderr, "Invalid WPA parameter value for "
			"dot11RSNAConfigPMKLifetime\n");
		return -1;
	}

	if (wpa_s->conf->dot11RSNAConfigPMKReauthThreshold &&
	    wpa_sm_set_param(wpa_s->wpa, RSNA_PMK_REAUTH_THRESHOLD,
			     wpa_s->conf->dot11RSNAConfigPMKReauthThreshold)) {
		fprintf(stderr, "Invalid WPA parameter value for "
			"dot11RSNAConfigPMKReauthThreshold\n");
		return -1;
	}

	if (wpa_s->conf->dot11RSNAConfigSATimeout &&
	    wpa_sm_set_param(wpa_s->wpa, RSNA_SA_TIMEOUT,
			     wpa_s->conf->dot11RSNAConfigSATimeout)) {
		fprintf(stderr, "Invalid WPA parameter value for "
			"dot11RSNAConfigSATimeout\n");
		return -1;
	}

	if (wpa_supplicant_driver_init(wpa_s, wait_for_interface) < 0) {
		return -1;
	}
	wpa_sm_set_own_addr(wpa_s->wpa, wpa_s->own_addr);

	if (wpa_supplicant_ctrl_iface_init(wpa_s)) {
		printf("Failed to initialize control interface '%s'.\n"
		       "You may have another wpa_supplicant process already "
		       "running or the file was\n"
		       "left by an unclean termination of wpa_supplicant in "
		       "which case you will need\n"
		       "to manually remove this file before starting "
		       "wpa_supplicant again.\n",
		       wpa_s->conf->ctrl_interface);
		return -1;
	}

	return 0;
}


static void wpa_supplicant_deinit(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->drv_priv) {
		/* Backwards compatibility call to set_wpa() handler. This is
		 * called only just after init and just before deinit, so these
		 * handler can be used to implement same functionality. */
		if (wpa_drv_set_wpa(wpa_s, 0) < 0) {
			fprintf(stderr, "Failed to disable WPA in the "
				"driver.\n");
		}

		wpa_drv_set_drop_unencrypted(wpa_s, 0);
		wpa_drv_set_countermeasures(wpa_s, 0);
		wpa_clear_keys(wpa_s, NULL);

		wpa_drv_deinit(wpa_s);
	}
	wpa_supplicant_cleanup(wpa_s);
}


struct wpa_params {
	int daemonize, wait_for_interface;
	int wait_for_monitor;
	char *pid_file;
};

static int wpa_supplicant_run(struct wpa_params *params,
			      struct wpa_interface *iface, size_t num)
{
	struct wpa_supplicant *head = NULL, *wpa_s = NULL, *new_wpa_s;
	int i, exitcode;

	for (i = 0; i < num; i++) {
		new_wpa_s = wpa_supplicant_alloc();
		if (new_wpa_s == NULL)
			return -1;

		if (head == NULL) {
			head = wpa_s = new_wpa_s;
			eloop_init(head);
		} else {
			wpa_s->next = new_wpa_s;
			wpa_s = new_wpa_s;
			wpa_s->head = head;
		}

		if (wpa_supplicant_init(wpa_s, &iface[i]))
			return -1;
	}

	exitcode = 0;

	if (params->wait_for_interface && params->daemonize) {
		wpa_printf(MSG_DEBUG, "Daemonize..");
		if (daemon(0, 0)) {
			perror("daemon");
			exitcode = -1;
			goto cleanup;
		}
	}

	for (wpa_s = head; wpa_s; wpa_s = wpa_s->next) {
		if (wpa_supplicant_init2(wpa_s, params->wait_for_interface)) {
			exitcode = -1;
			goto cleanup;
		}
	}

	if (!params->wait_for_interface && params->daemonize) {
		wpa_printf(MSG_DEBUG, "Daemonize..");
		if (daemon(0, 0)) {
			perror("daemon");
			exitcode = -1;
			goto cleanup;
		}
	}

	if (params->pid_file) {
		FILE *f = fopen(params->pid_file, "w");
		if (f) {
			fprintf(f, "%u\n", getpid());
			fclose(f);
		}
	}

	if (params->wait_for_monitor) {
		for (wpa_s = head; wpa_s; wpa_s = wpa_s->next) {
			wpa_supplicant_ctrl_iface_wait(wpa_s);
		}
	}

	eloop_register_signal(SIGINT, wpa_supplicant_terminate, NULL);
	eloop_register_signal(SIGTERM, wpa_supplicant_terminate, NULL);
#ifndef CONFIG_NATIVE_WINDOWS
	eloop_register_signal(SIGHUP, wpa_supplicant_reconfig, NULL);
#endif /* CONFIG_NATIVE_WINDOWS */

	eloop_run();

	for (wpa_s = head; wpa_s; wpa_s = wpa_s->next) {
		wpa_supplicant_deauthenticate(wpa_s, REASON_DEAUTH_LEAVING);
	}

cleanup:
	wpa_s = head;
	while (wpa_s) {
		struct wpa_supplicant *prev;
		wpa_supplicant_deinit(wpa_s);
		prev = wpa_s;
		wpa_s = wpa_s->next;
		free(prev);
	}

	eloop_destroy();

	if (params->pid_file)
		unlink(params->pid_file);

	return exitcode;
}


int main(int argc, char *argv[])
{
	int c;
	struct wpa_interface *ifaces, *iface;
	int iface_count, exitcode;
	struct wpa_params params;

#ifdef CONFIG_NATIVE_WINDOWS
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 0), &wsaData)) {
		printf("Could not find a usable WinSock.dll\n");
		return -1;
	}
#endif /* CONFIG_NATIVE_WINDOWS */

	memset(&params, 0, sizeof(params));
	iface = ifaces = malloc(sizeof(struct wpa_interface));
	if (ifaces == NULL)
		return -1;
	memset(iface, 0, sizeof(*iface));
	iface_count = 1;

	wpa_supplicant_fd_workaround();

	for (;;) {
		c = getopt(argc, argv, "Bc:D:dhi:KLNP:qtvwW");
		if (c < 0)
			break;
		switch (c) {
		case 'B':
			params.daemonize++;
			break;
		case 'c':
			iface->confname = optarg;
			break;
		case 'D':
			iface->driver = optarg;
			break;
		case 'd':
			wpa_debug_level--;
			break;
		case 'h':
			usage();
			return -1;
		case 'i':
			iface->ifname = optarg;
			break;
		case 'K':
			wpa_debug_show_keys++;
			break;
		case 'L':
			license();
			return -1;
		case 'P':
			params.pid_file = rel2abs_path(optarg);
			break;
		case 'q':
			wpa_debug_level++;
			break;
		case 't':
			wpa_debug_timestamp++;
			break;
		case 'v':
			printf("%s\n", wpa_supplicant_version);
			return -1;
		case 'w':
			params.wait_for_interface++;
			break;
		case 'W':
			params.wait_for_monitor++;
			break;
		case 'N':
			iface_count++;
			iface = realloc(ifaces, iface_count *
					sizeof(struct wpa_interface));
			if (ifaces == NULL) {
				free(ifaces);
				return -1;
			}
			ifaces = iface;
			iface = &ifaces[iface_count - 1]; 
			memset(iface, 0, sizeof(*iface));
			break;
		default:
			usage();
			return -1;
		}
	}

	exitcode = wpa_supplicant_run(&params, ifaces, iface_count);
	free(ifaces);
	free(params.pid_file);

#ifdef CONFIG_NATIVE_WINDOWS
	WSACleanup();
#endif /* CONFIG_NATIVE_WINDOWS */

	return exitcode;
}
