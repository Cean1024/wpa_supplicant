/*
 * WPA Supplicant - RSN pre-authentication and PMKSA caching
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
#include <sys/time.h>
#ifndef CONFIG_NATIVE_WINDOWS
#include <netinet/in.h>
#endif /* CONFIG_NATIVE_WINDOWS */
#include <string.h>
#include <time.h>

#include "common.h"
#include "sha1.h"
#include "wpa.h"
#include "driver.h"
#include "eloop.h"
#include "wpa_supplicant.h"
#include "config.h"
#include "l2_packet.h"
#include "eapol_sm.h"
#include "wpa_supplicant_i.h"
#include "preauth.h"


#define PMKID_CANDIDATE_PRIO_SCAN 1000
static const int pmksa_cache_max_entries = 32;
static const int dot11RSNAConfigPMKLifetime = 43200;


/**
 * rsn_pmkid - calculate PMK identifier
 * @pmk: pairwise master key
 * @aa: authenticator address
 * @spa: supplicant address
 *
 * IEEE Std 802.11i-2004 - 8.5.1.2 Pairwise key hierarchy
 * PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AA || SPA)
 */
static void rsn_pmkid(const u8 *pmk, const u8 *aa, const u8 *spa, u8 *pmkid)
{
	char *title = "PMK Name";
	const unsigned char *addr[3];
	const size_t len[3] = { 8, ETH_ALEN, ETH_ALEN };
	unsigned char hash[SHA1_MAC_LEN];

	addr[0] = (unsigned char *) title;
	addr[1] = aa;
	addr[2] = spa;

	hmac_sha1_vector(pmk, PMK_LEN, 3, addr, len, hash);
	memcpy(pmkid, hash, PMKID_LEN);
}


static void pmksa_cache_set_expiration(struct wpa_supplicant *wpa_s);


static void pmksa_cache_free_entry(struct wpa_supplicant *wpa_s,
				   struct rsn_pmksa_cache *entry)
{
	free(entry);
	wpa_s->pmksa_count--;
	if (wpa_s->cur_pmksa == entry) {
		wpa_printf(MSG_DEBUG, "RSN: removed current PMKSA entry");
		/* TODO: should drop PMK and PTK and trigger new key
		 * negotiation */
		wpa_s->cur_pmksa = NULL;
	}
}


static void pmksa_cache_expire(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	time_t now;

	time(&now);
	while (wpa_s->pmksa && wpa_s->pmksa->expiration <= now) {
		struct rsn_pmksa_cache *entry = wpa_s->pmksa;
		wpa_s->pmksa = entry->next;
		wpa_printf(MSG_DEBUG, "RSN: expired PMKSA cache entry for "
			   MACSTR, MAC2STR(entry->aa));
		pmksa_cache_free_entry(wpa_s, entry);
	}

	pmksa_cache_set_expiration(wpa_s);
}


static void pmksa_cache_set_expiration(struct wpa_supplicant *wpa_s)
{
	int sec;
	eloop_cancel_timeout(pmksa_cache_expire, wpa_s, NULL);
	if (wpa_s->pmksa == NULL)
		return;
	sec = wpa_s->pmksa->expiration - time(NULL);
	if (sec < 0)
		sec = 0;
	eloop_register_timeout(sec + 1, 0, pmksa_cache_expire, wpa_s, NULL);
}


struct rsn_pmksa_cache *
pmksa_cache_add(struct wpa_supplicant *wpa_s, const u8 *pmk,
		size_t pmk_len, const u8 *aa, const u8 *spa,
		struct wpa_ssid *ssid)
{
	struct rsn_pmksa_cache *entry, *pos, *prev;

	if (wpa_s->proto != WPA_PROTO_RSN || pmk_len > PMK_LEN)
		return NULL;

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		return NULL;
	memset(entry, 0, sizeof(*entry));
	memcpy(entry->pmk, pmk, pmk_len);
	entry->pmk_len = pmk_len;
	rsn_pmkid(pmk, aa, spa, entry->pmkid);
	entry->expiration = time(NULL) + dot11RSNAConfigPMKLifetime;
	entry->akmp = WPA_KEY_MGMT_IEEE8021X;
	memcpy(entry->aa, aa, ETH_ALEN);
	entry->ssid = ssid;

	/* Replace an old entry for the same Authenticator (if found) with the
	 * new entry */
	pos = wpa_s->pmksa;
	prev = NULL;
	while (pos) {
		if (memcmp(aa, pos->aa, ETH_ALEN) == 0) {
			if (prev == NULL)
				wpa_s->pmksa = pos->next;
			else
				prev->next = pos->next;
			pmksa_cache_free_entry(wpa_s, pos);
			break;
		}
		prev = pos;
		pos = pos->next;
	}

	if (wpa_s->pmksa_count >= pmksa_cache_max_entries && wpa_s->pmksa) {
		/* Remove the oldest entry to make room for the new entry */
		pos = wpa_s->pmksa;
		wpa_s->pmksa = pos->next;
		wpa_printf(MSG_DEBUG, "RSN: removed the oldest PMKSA cache "
			   "entry (for " MACSTR ") to make room for new one",
			   MAC2STR(pos->aa));
		wpa_drv_remove_pmkid(wpa_s, pos->aa, pos->pmkid);
		pmksa_cache_free_entry(wpa_s, pos);
	}

	/* Add the new entry; order by expiration time */
	pos = wpa_s->pmksa;
	prev = NULL;
	while (pos) {
		if (pos->expiration > entry->expiration)
			break;
		prev = pos;
		pos = pos->next;
	}
	if (prev == NULL) {
		entry->next = wpa_s->pmksa;
		wpa_s->pmksa = entry;
	} else {
		entry->next = prev->next;
		prev->next = entry;
	}
	wpa_s->pmksa_count++;
	wpa_printf(MSG_DEBUG, "RSN: added PMKSA cache entry for " MACSTR,
		   MAC2STR(entry->aa));
	wpa_drv_add_pmkid(wpa_s, entry->aa, entry->pmkid);

	return entry;
}


/**
 * pmksa_cache_free - free all entries in PMKSA cache
 * @wpa_s: pointer to wpa_supplicant data
 */
void pmksa_cache_free(struct wpa_supplicant *wpa_s)
{
	struct rsn_pmksa_cache *entry, *prev;

	entry = wpa_s->pmksa;
	wpa_s->pmksa = NULL;
	while (entry) {
		prev = entry;
		entry = entry->next;
		free(prev);
	}
	pmksa_cache_set_expiration(wpa_s);
	wpa_s->cur_pmksa = NULL;
}


/**
 * pmksa_cache_get - fetch a PMKSA cache entry
 * @wpa_s: pointer to wpa_supplicant data
 * @aa: authenticator address or %NULL to match any
 * @pmkid: PMKID or %NULL to match any
 *
 * Returns: pointer to PMKSA cache entry or %NULL if no match was found
 */
struct rsn_pmksa_cache * pmksa_cache_get(struct wpa_supplicant *wpa_s,
					 const u8 *aa, const u8 *pmkid)
{
	struct rsn_pmksa_cache *entry = wpa_s->pmksa;
	while (entry) {
		if ((aa == NULL || memcmp(entry->aa, aa, ETH_ALEN) == 0) &&
		    (pmkid == NULL ||
		     memcmp(entry->pmkid, pmkid, PMKID_LEN) == 0))
			return entry;
		entry = entry->next;
	}
	return NULL;
}


/**
 * pmksa_cache_notify_reconfig - reconfiguration notification for PMKSA cache
 * @wpa_s: pointer to wpa_supplicant data
 *
 * Clear references to old data structures when wpa_supplicant is reconfigured.
 */
void pmksa_cache_notify_reconfig(struct wpa_supplicant *wpa_s)
{
	struct rsn_pmksa_cache *entry = wpa_s->pmksa;
	while (entry) {
		entry->ssid = NULL;
		entry = entry->next;
	}
}


static struct rsn_pmksa_cache *
pmksa_cache_clone_entry(struct wpa_supplicant *wpa_s,
			const struct rsn_pmksa_cache *old_entry, const u8 *aa)
{
	struct rsn_pmksa_cache *new_entry;

	new_entry = pmksa_cache_add(wpa_s, old_entry->pmk, old_entry->pmk_len,
				    aa, wpa_s->own_addr, old_entry->ssid);
	if (new_entry == NULL)
		return NULL;

	/* TODO: reorder entries based on expiration time? */
	new_entry->expiration = old_entry->expiration;
	new_entry->opportunistic = 1;

	return new_entry;
}


/**
 * pmksa_cache_get_opportunistic - try to get an opportunistic PMKSA entry
 * @wpa_s: pointer to wpa_supplicant data
 * @ssid: pointer to the current network configuration
 * @aa: authenticator address for the new AP
 *
 * Try to create a new PMKSA cache entry opportunistically by guessing that the
 * new AP is sharing the same PMK as another AP that has the same SSID and has
 * already an entry in PMKSA cache.
 *
 * Returns: pointer to a new PMKSA cache entry or %NULL if not available
 */
struct rsn_pmksa_cache *
pmksa_cache_get_opportunistic(struct wpa_supplicant *wpa_s,
			      struct wpa_ssid *ssid, const u8 *aa)
{
	struct rsn_pmksa_cache *entry = wpa_s->pmksa;
	if (ssid == NULL)
		return NULL;
	while (entry) {
		if (entry->ssid == ssid) {
			entry = pmksa_cache_clone_entry(wpa_s, entry, aa);
			if (entry) {
				wpa_printf(MSG_DEBUG, "RSN: added "
					   "opportunistic PMKSA cache entry "
					   "for " MACSTR, MAC2STR(aa));
			}
			return entry;
		}
		entry = entry->next;
	}
	return NULL;
}


/**
 * pmksa_cache_list - dump text list of entries in PMKSA cache
 * @wpa_s: pointer to wpa_supplicant data
 * @buf: buffer for the list
 * @len: length of the buffer
 *
 * Returns: number of bytes written to buffer
 */
int pmksa_cache_list(struct wpa_supplicant *wpa_s, char *buf, size_t len)
{
	int i, j;
	char *pos = buf;
	struct rsn_pmksa_cache *entry;
	time_t now;

	time(&now);
	pos += snprintf(pos, buf + len - pos,
			"Index / AA / PMKID / expiration (in seconds) / "
			"opportunistic\n");
	i = 0;
	entry = wpa_s->pmksa;
	while (entry) {
		i++;
		pos += snprintf(pos, buf + len - pos, "%d " MACSTR " ",
				i, MAC2STR(entry->aa));
		for (j = 0; j < PMKID_LEN; j++)
			pos += snprintf(pos, buf + len - pos, "%02x",
					entry->pmkid[j]);
		pos += snprintf(pos, buf + len - pos, " %d %d\n",
				(int) (entry->expiration - now),
				entry->opportunistic);
		entry = entry->next;
	}
	return pos - buf;
}


/**
 * pmksa_candidate_free - free all entries in PMKSA candidate list
 * @wpa_s: pointer to wpa_supplicant data
 */
void pmksa_candidate_free(struct wpa_supplicant *wpa_s)
{
	struct rsn_pmksa_candidate *entry, *prev;

	entry = wpa_s->pmksa_candidates;
	wpa_s->pmksa_candidates = NULL;
	while (entry) {
		prev = entry;
		entry = entry->next;
		free(prev);
	}
}


#ifdef IEEE8021X_EAPOL

static void rsn_preauth_receive(void *ctx, unsigned char *src_addr,
				unsigned char *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_printf(MSG_DEBUG, "RX pre-auth from " MACSTR, MAC2STR(src_addr));
	wpa_hexdump(MSG_MSGDUMP, "RX pre-auth", buf, len);

	if (wpa_s->preauth_eapol == NULL ||
	    memcmp(wpa_s->preauth_bssid, "\x00\x00\x00\x00\x00\x00",
		   ETH_ALEN) == 0 ||
	    memcmp(wpa_s->preauth_bssid, src_addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_WARNING, "RSN pre-auth frame received from "
			   "unexpected source " MACSTR " - dropped",
			   MAC2STR(src_addr));
		return;
	}

	eapol_sm_rx_eapol(wpa_s->preauth_eapol, src_addr, buf, len);
}


static void rsn_preauth_eapol_cb(struct eapol_sm *eapol, int success,
				 void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;
	u8 pmk[PMK_LEN];

	wpa_msg(wpa_s, MSG_INFO, "RSN: pre-authentication with " MACSTR
		" %s", MAC2STR(wpa_s->preauth_bssid),
		success ? "completed successfully" : "failed");

	if (success) {
		int res, pmk_len;
		pmk_len = PMK_LEN;
		res = eapol_sm_get_key(eapol, pmk, PMK_LEN);
#ifdef EAP_LEAP
		if (res) {
			res = eapol_sm_get_key(eapol, pmk, 16);
			pmk_len = 16;
		}
#endif /* EAP_LEAP */
		if (res == 0) {
			wpa_hexdump_key(MSG_DEBUG, "RSN: PMK from pre-auth",
					pmk, pmk_len);
			wpa_s->pmk_len = pmk_len;
			pmksa_cache_add(wpa_s, pmk, pmk_len,
					wpa_s->preauth_bssid, wpa_s->own_addr,
					wpa_s->current_ssid);
		} else {
			wpa_msg(wpa_s, MSG_INFO, "RSN: failed to get master "
				"session key from pre-auth EAPOL state "
				"machines");
		}
	}

	rsn_preauth_deinit(wpa_s);
	rsn_preauth_candidate_process(wpa_s);
}


static void rsn_preauth_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	wpa_msg(wpa_s, MSG_INFO, "RSN: pre-authentication with " MACSTR
		" timed out", MAC2STR(wpa_s->preauth_bssid));
	rsn_preauth_deinit(wpa_s);
	rsn_preauth_candidate_process(wpa_s);
}


int rsn_preauth_init(struct wpa_supplicant *wpa_s, u8 *dst)
{
	struct eapol_config eapol_conf;
	struct eapol_ctx *ctx;

	if (wpa_s->preauth_eapol)
		return -1;

	wpa_msg(wpa_s, MSG_DEBUG, "RSN: starting pre-authentication with "
		MACSTR, MAC2STR(dst));

	wpa_s->l2_preauth = l2_packet_init(wpa_s->ifname,
					   wpa_drv_get_mac_addr(wpa_s),
					   ETH_P_RSN_PREAUTH,
					   rsn_preauth_receive, wpa_s);
	if (wpa_s->l2_preauth == NULL) {
		wpa_printf(MSG_WARNING, "RSN: Failed to initialize L2 packet "
			   "processing for pre-authentication");
		return -2;
	}

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		wpa_printf(MSG_WARNING, "Failed to allocate EAPOL context.");
		return -4;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->ctx = wpa_s;
	ctx->preauth = 1;
	ctx->cb = rsn_preauth_eapol_cb;
	ctx->cb_ctx = wpa_s;
	ctx->scard_ctx = wpa_s->scard;
	ctx->eapol_done_cb = wpa_supplicant_notify_eapol_done;
	ctx->eapol_send = wpa_eapol_send_preauth;

	wpa_s->preauth_eapol = eapol_sm_init(ctx);
	if (wpa_s->preauth_eapol == NULL) {
		free(ctx);
		wpa_printf(MSG_WARNING, "RSN: Failed to initialize EAPOL "
			   "state machines for pre-authentication");
		return -3;
	}
	memset(&eapol_conf, 0, sizeof(eapol_conf));
	eapol_conf.accept_802_1x_keys = 0;
	eapol_conf.required_keys = 0;
	eapol_conf.fast_reauth = wpa_s->conf->fast_reauth;
	if (wpa_s->current_ssid)
		eapol_conf.workaround = wpa_s->current_ssid->eap_workaround;
	eapol_sm_notify_config(wpa_s->preauth_eapol, wpa_s->current_ssid,
			       &eapol_conf);
	memcpy(wpa_s->preauth_bssid, dst, ETH_ALEN);

	eapol_sm_notify_portValid(wpa_s->preauth_eapol, TRUE);
	/* 802.1X::portControl = Auto */
	eapol_sm_notify_portEnabled(wpa_s->preauth_eapol, TRUE);

	eloop_register_timeout(60, 0, rsn_preauth_timeout, wpa_s, NULL);

	return 0;
}


void rsn_preauth_deinit(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s->preauth_eapol)
		return;

	eloop_cancel_timeout(rsn_preauth_timeout, wpa_s, NULL);
	eapol_sm_deinit(wpa_s->preauth_eapol);
	wpa_s->preauth_eapol = NULL;
	memset(wpa_s->preauth_bssid, 0, ETH_ALEN);

	l2_packet_deinit(wpa_s->l2_preauth);
	wpa_s->l2_preauth = NULL;
}


void rsn_preauth_candidate_process(struct wpa_supplicant *wpa_s)
{
	struct rsn_pmksa_candidate *candidate;

	if (wpa_s->pmksa_candidates == NULL)
		return;

	/* TODO: drop priority for old candidate entries */

	wpa_msg(wpa_s, MSG_DEBUG, "RSN: processing PMKSA candidate list");
	if (wpa_s->preauth_eapol ||
	    wpa_s->proto != WPA_PROTO_RSN ||
	    wpa_s->wpa_state != WPA_COMPLETED ||
	    wpa_s->key_mgmt != WPA_KEY_MGMT_IEEE8021X) {
		wpa_msg(wpa_s, MSG_DEBUG, "RSN: not in suitable state for new "
			"pre-authentication");
		return; /* invalid state for new pre-auth */
	}

	while (wpa_s->pmksa_candidates) {
		struct rsn_pmksa_cache *p = NULL;
		candidate = wpa_s->pmksa_candidates;
		p = pmksa_cache_get(wpa_s, candidate->bssid, NULL);
		if (memcmp(wpa_s->bssid, candidate->bssid, ETH_ALEN) != 0 &&
		    (p == NULL || p->opportunistic)) {
			wpa_msg(wpa_s, MSG_DEBUG, "RSN: PMKSA candidate "
				MACSTR " selected for pre-authentication",
				MAC2STR(candidate->bssid));
			wpa_s->pmksa_candidates = candidate->next;
			rsn_preauth_init(wpa_s, candidate->bssid);
			free(candidate);
			return;
		}
		wpa_msg(wpa_s, MSG_DEBUG, "RSN: PMKSA candidate " MACSTR
			" does not need pre-authentication anymore",
			MAC2STR(candidate->bssid));
		/* Some drivers (e.g., NDIS) expect to get notified about the
		 * PMKIDs again, so report the existing data now. */
		if (p)
			wpa_drv_add_pmkid(wpa_s, candidate->bssid, p->pmkid);

		wpa_s->pmksa_candidates = candidate->next;
		free(candidate);
	}
	wpa_msg(wpa_s, MSG_DEBUG, "RSN: no more pending PMKSA candidates");
}


void pmksa_candidate_add(struct wpa_supplicant *wpa_s, const u8 *bssid,
			 int prio, int preauth)
{
	struct rsn_pmksa_candidate *cand, *prev, *pos;

	if (wpa_s->current_ssid && wpa_s->current_ssid->proactive_key_caching)
	{
		pmksa_cache_get_opportunistic(wpa_s, wpa_s->current_ssid,
					      bssid);
	}

	if (!preauth) {
		wpa_printf(MSG_DEBUG, "RSN: Ignored PMKID candidate without "
			   "preauth flag");
		return;
	}

	/* If BSSID already on candidate list, update the priority of the old
	 * entry. Do not override priority based on normal scan results. */
	prev = NULL;
	cand = wpa_s->pmksa_candidates;
	while (cand) {
		if (memcmp(cand->bssid, bssid, ETH_ALEN) == 0) {
			if (prev)
				prev->next = cand->next;
			else
				wpa_s->pmksa_candidates = cand->next;
			break;
		}
		prev = cand;
		cand = cand->next;
	}

	if (cand) {
		if (prio < PMKID_CANDIDATE_PRIO_SCAN)
			cand->priority = prio;
	} else {
		cand = malloc(sizeof(*cand));
		if (cand == NULL)
			return;
		memset(cand, 0, sizeof(*cand));
		memcpy(cand->bssid, bssid, ETH_ALEN);
		cand->priority = prio;
	}

	/* Add candidate to the list; order by increasing priority value. i.e.,
	 * highest priority (smallest value) first. */
	prev = NULL;
	pos = wpa_s->pmksa_candidates;
	while (pos) {
		if (cand->priority <= pos->priority)
			break;
		prev = pos;
		pos = pos->next;
	}
	cand->next = pos;
	if (prev)
		prev->next = cand;
	else
		wpa_s->pmksa_candidates = cand;

	wpa_msg(wpa_s, MSG_DEBUG, "RSN: added PMKSA cache "
		"candidate " MACSTR " prio %d", MAC2STR(bssid), prio);
	rsn_preauth_candidate_process(wpa_s);
}


/* TODO: schedule periodic scans if current AP supports preauth */
void rsn_preauth_scan_results(struct wpa_supplicant *wpa_s,
			      struct wpa_scan_result *results, int count)
{
	struct wpa_scan_result *r;
	struct wpa_ie_data ie;
	int i;
	struct rsn_pmksa_cache *pmksa;

	if (wpa_s->current_ssid == NULL)
		return;

	pmksa_candidate_free(wpa_s);

	for (i = count - 1; i >= 0; i--) {
		r = &results[i];
		if (r->ssid_len != wpa_s->current_ssid->ssid_len ||
		    memcmp(r->ssid, wpa_s->current_ssid->ssid,
			   r->ssid_len) != 0)
			continue;

		if (memcmp(r->bssid, wpa_s->bssid, ETH_ALEN) == 0)
			continue;

		if (r->rsn_ie_len == 0 ||
		    wpa_parse_wpa_ie(wpa_s, r->rsn_ie, r->rsn_ie_len, &ie))
			continue;

		pmksa = pmksa_cache_get(wpa_s, r->bssid, NULL);
		if (pmksa &&
		    (!pmksa->opportunistic ||
		     !(ie.capabilities & WPA_CAPABILITY_PREAUTH)))
			continue;

		/*
		 * Give less priority to candidates found from normal
		 * scan results.
		 */
		pmksa_candidate_add(wpa_s, r->bssid,
				    PMKID_CANDIDATE_PRIO_SCAN,
				    ie.capabilities & WPA_CAPABILITY_PREAUTH);
	}
}

#endif /* IEEE8021X_EAPOL */
