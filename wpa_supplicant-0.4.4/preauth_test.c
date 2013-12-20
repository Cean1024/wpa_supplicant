/*
 * WPA Supplicant - test code for pre-authentication
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
 * IEEE 802.1X Supplicant test code (to be used in place of wpa_supplicant.c.
 * Not used in production version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <assert.h>
#include <arpa/inet.h>

#include "common.h"
#include "config.h"
#include "eapol_sm.h"
#include "eloop.h"
#include "wpa.h"
#include "eap.h"
#include "wpa_supplicant.h"
#include "wpa_supplicant_i.h"
#include "l2_packet.h"
#include "ctrl_iface.h"
#include "pcsc_funcs.h"
#include "preauth.h"


extern int wpa_debug_level;
extern int wpa_debug_show_keys;


struct preauth_test_data {
	int auth_timed_out;
};


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


const char * wpa_supplicant_state_txt(int state)
{
	switch (state) {
	case WPA_DISCONNECTED:
		return "DISCONNECTED";
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


void wpa_supplicant_req_scan(struct wpa_supplicant *wpa_s, int sec, int usec)
{
}


const char * wpa_ssid_txt(u8 *ssid, size_t ssid_len)
{
	return NULL;
}


int wpa_supplicant_reload_configuration(struct wpa_supplicant *wpa_s)
{
	return -1;
}


void wpa_supplicant_disassociate(struct wpa_supplicant *wpa_s,
				 int reason_code)
{
}


void wpa_supplicant_deauthenticate(struct wpa_supplicant *wpa_s,
				   int reason_code)
{
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


void wpa_supplicant_set_state(struct wpa_supplicant *wpa_s, wpa_states state)
{
	wpa_s->wpa_state = state;
}


wpa_states wpa_supplicant_get_state(struct wpa_supplicant *wpa_s)
{
	return wpa_s->wpa_state;
}


int wpa_ether_send(struct wpa_supplicant *wpa_s, u8 *buf, size_t len)
{
	printf("%s - not implemented\n", __func__);
	return -1;
}


struct wpa_ssid * wpa_supplicant_get_ssid(struct wpa_supplicant *wpa_s)
{
	printf("%s - not implemented\n", __func__);
	return NULL;
}


void wpa_supplicant_cancel_auth_timeout(struct wpa_supplicant *wpa_s)
{
	printf("%s - not implemented\n", __func__);
}


int wpa_supplicant_get_beacon_ie(struct wpa_supplicant *wpa_s)
{
	printf("%s - not implemented\n", __func__);
	return -1;
}


void wpa_supplicant_scan(void *eloop_ctx, void *timeout_ctx)
{
	printf("%s - not implemented\n", __func__);
}


int wpa_supplicant_get_bssid(struct wpa_supplicant *wpa_s, u8 *bssid)
{
	printf("%s - not implemented\n", __func__);
	return -1;
}


int wpa_supplicant_set_key(struct wpa_supplicant *wpa_s, wpa_alg alg,
			   const u8 *addr, int key_idx, int set_tx,
			   const u8 *seq, size_t seq_len,
			   const u8 *key, size_t key_len)
{
	printf("%s - not implemented\n", __func__);
	return -1;
}


int wpa_supplicant_add_pmkid(struct wpa_supplicant *wpa_s,
			     const u8 *bssid, const u8 *pmkid)
{
	printf("%s - not implemented\n", __func__);
	return -1;
}


int wpa_supplicant_remove_pmkid(struct wpa_supplicant *wpa_s,
				const u8 *bssid, const u8 *pmkid)
{
	printf("%s - not implemented\n", __func__);
	return -1;
}


static void test_eapol_clean(struct wpa_supplicant *wpa_s)
{
	rsn_preauth_deinit(wpa_s->wpa);
	wpa_sm_deinit(wpa_s->wpa);
	scard_deinit(wpa_s->scard);
	wpa_supplicant_ctrl_iface_deinit(wpa_s);
	wpa_config_free(wpa_s->conf);
}


static void eapol_test_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct preauth_test_data *p = eloop_ctx;
	printf("EAPOL test timed out\n");
	p->auth_timed_out = 1;
	eloop_terminate();
}


static void eapol_test_poll(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	if (!rsn_preauth_in_progress(wpa_s->wpa))
		eloop_terminate();
	else {
		eloop_register_timeout(0, 100000, eapol_test_poll, eloop_ctx,
				       timeout_ctx);
	}
}


static int wpa_supplicant_scard_init(struct wpa_supplicant *wpa_s,
				     struct wpa_ssid *ssid)
{
	if (ssid->pcsc == NULL || wpa_s->scard != NULL)
		return 0;
	wpa_printf(MSG_DEBUG, "Selected network is configured to use SIM - "
		   "initialize PCSC");
	wpa_s->scard = scard_init(SCARD_TRY_BOTH);
	if (wpa_s->scard == NULL) {
		wpa_printf(MSG_WARNING, "Failed to initialize SIM "
			   "(pcsc-lite)");
		return -1;
	}
	wpa_sm_set_scard_ctx(wpa_s->wpa, wpa_s->scard);

	return 0;
}


static struct wpa_driver_ops dummy_driver;


static void wpa_init_conf(struct wpa_supplicant *wpa_s, const char *ifname)
{
	struct l2_packet_data *l2;

	memset(&dummy_driver, 0, sizeof(dummy_driver));
	wpa_s->driver = &dummy_driver;

	wpa_s->wpa = wpa_sm_init(wpa_s);
	assert(wpa_s->wpa != NULL);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_PROTO, WPA_PROTO_RSN);

	strncpy(wpa_s->ifname, ifname, sizeof(wpa_s->ifname));
	wpa_sm_set_ifname(wpa_s->wpa, wpa_s->ifname);

	l2 = l2_packet_init(wpa_s->ifname, NULL, ETH_P_RSN_PREAUTH, NULL,
			    NULL);
	assert(l2 != NULL);
	if (l2_packet_get_own_addr(l2, wpa_s->own_addr)) {
		wpa_printf(MSG_WARNING, "Failed to get own L2 address\n");
		exit(-1);
	}
	l2_packet_deinit(l2);
	wpa_sm_set_own_addr(wpa_s->wpa, wpa_s->own_addr);
}


static void eapol_test_terminate(int sig, void *eloop_ctx,
				 void *signal_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	wpa_msg(wpa_s, MSG_INFO, "Signal %d received - terminating", sig);
	eloop_terminate();
}


int main(int argc, char *argv[])
{
	struct wpa_supplicant wpa_s;
	int ret = 1;
	u8 bssid[ETH_ALEN];
	struct preauth_test_data preauth_test;

	memset(&preauth_test, 0, sizeof(preauth_test));

	wpa_debug_level = 0;
	wpa_debug_show_keys = 1;

	if (argc != 4) {
		printf("usage: eapol_test <conf> <target MAC address> "
		       "<ifname>\n");
		return -1;
	}

	if (hwaddr_aton(argv[2], bssid)) {
		printf("Failed to parse target address '%s'.\n", argv[2]);
		return -1;
	}

	eloop_init(&wpa_s);

	memset(&wpa_s, 0, sizeof(wpa_s));
	wpa_s.conf = wpa_config_read(argv[1]);
	if (wpa_s.conf == NULL) {
		printf("Failed to parse configuration file '%s'.\n", argv[1]);
		return -1;
	}
	if (wpa_s.conf->ssid == NULL) {
		printf("No networks defined.\n");
		return -1;
	}

	wpa_init_conf(&wpa_s, argv[3]);
	if (wpa_supplicant_ctrl_iface_init(&wpa_s)) {
		printf("Failed to initialize control interface '%s'.\n"
		       "You may have another eapol_test process already "
		       "running or the file was\n"
		       "left by an unclean termination of eapol_test in "
		       "which case you will need\n"
		       "to manually remove this file before starting "
		       "eapol_test again.\n",
		       wpa_s.conf->ctrl_interface);
		return -1;
	}
	if (wpa_supplicant_scard_init(&wpa_s, wpa_s.conf->ssid))
		return -1;

	if (rsn_preauth_init(wpa_s.wpa, bssid, wpa_s.conf->ssid))
		return -1;

	eloop_register_timeout(30, 0, eapol_test_timeout, &preauth_test, NULL);
	eloop_register_timeout(0, 100000, eapol_test_poll, &wpa_s, NULL);
	eloop_register_signal(SIGINT, eapol_test_terminate, NULL);
	eloop_register_signal(SIGTERM, eapol_test_terminate, NULL);
	eloop_register_signal(SIGHUP, eapol_test_terminate, NULL);
	eloop_run();

	if (preauth_test.auth_timed_out)
		ret = -2;
	else {
		ret = pmksa_cache_get(wpa_s.wpa, bssid, NULL) ? 0 : -3;
	}

	test_eapol_clean(&wpa_s);

	eloop_destroy();

	return ret;
}
