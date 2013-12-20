/*
 * WPA Supplicant - WPA state machine and EAPOL-Key processing
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
#ifndef CONFIG_NATIVE_WINDOWS
#include <netinet/in.h>
#endif /* CONFIG_NATIVE_WINDOWS */
#include <string.h>

#include "common.h"
#include "md5.h"
#include "sha1.h"
#include "rc4.h"
#include "aes_wrap.h"
#include "wpa.h"
#include "driver.h"
#include "eloop.h"
#include "wpa_supplicant.h"
#include "config.h"
#include "l2_packet.h"
#include "eapol_sm.h"
#include "wpa_supplicant_i.h"
#include "preauth.h"


/* TODO: make these configurable */
static const int dot11RSNAConfigPMKLifetime = 43200;
static const int dot11RSNAConfigPMKReauthThreshold = 70;
static const int dot11RSNAConfigSATimeout = 60;

static const int WPA_SELECTOR_LEN = 4;
static const u8 WPA_OUI_TYPE[] = { 0x00, 0x50, 0xf2, 1 };
static const u16 WPA_VERSION = 1;
static const u8 WPA_AUTH_KEY_MGMT_NONE[] = { 0x00, 0x50, 0xf2, 0 };
static const u8 WPA_AUTH_KEY_MGMT_UNSPEC_802_1X[] = { 0x00, 0x50, 0xf2, 1 };
static const u8 WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X[] = { 0x00, 0x50, 0xf2, 2 };
static const u8 WPA_CIPHER_SUITE_NONE[] = { 0x00, 0x50, 0xf2, 0 };
static const u8 WPA_CIPHER_SUITE_WEP40[] = { 0x00, 0x50, 0xf2, 1 };
static const u8 WPA_CIPHER_SUITE_TKIP[] = { 0x00, 0x50, 0xf2, 2 };
static const u8 WPA_CIPHER_SUITE_WRAP[] = { 0x00, 0x50, 0xf2, 3 };
static const u8 WPA_CIPHER_SUITE_CCMP[] = { 0x00, 0x50, 0xf2, 4 };
static const u8 WPA_CIPHER_SUITE_WEP104[] = { 0x00, 0x50, 0xf2, 5 };

/* WPA IE version 1
 * 00-50-f2:1 (OUI:OUI type)
 * 0x01 0x00 (version; little endian)
 * (all following fields are optional:)
 * Group Suite Selector (4 octets) (default: TKIP)
 * Pairwise Suite Count (2 octets, little endian) (default: 1)
 * Pairwise Suite List (4 * n octets) (default: TKIP)
 * Authenticated Key Management Suite Count (2 octets, little endian)
 *    (default: 1)
 * Authenticated Key Management Suite List (4 * n octets)
 *    (default: unspec 802.1x)
 * WPA Capabilities (2 octets, little endian) (default: 0)
 */

struct wpa_ie_hdr {
	u8 elem_id;
	u8 len;
	u8 oui[3];
	u8 oui_type;
	u8 version[2];
} __attribute__ ((packed));


static const int RSN_SELECTOR_LEN = 4;
static const u16 RSN_VERSION = 1;
static const u8 RSN_AUTH_KEY_MGMT_UNSPEC_802_1X[] = { 0x00, 0x0f, 0xac, 1 };
static const u8 RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X[] = { 0x00, 0x0f, 0xac, 2 };
static const u8 RSN_CIPHER_SUITE_NONE[] = { 0x00, 0x0f, 0xac, 0 };
static const u8 RSN_CIPHER_SUITE_WEP40[] = { 0x00, 0x0f, 0xac, 1 };
static const u8 RSN_CIPHER_SUITE_TKIP[] = { 0x00, 0x0f, 0xac, 2 };
static const u8 RSN_CIPHER_SUITE_WRAP[] = { 0x00, 0x0f, 0xac, 3 };
static const u8 RSN_CIPHER_SUITE_CCMP[] = { 0x00, 0x0f, 0xac, 4 };
static const u8 RSN_CIPHER_SUITE_WEP104[] = { 0x00, 0x0f, 0xac, 5 };

/* EAPOL-Key Key Data Encapsulation
 * GroupKey and STAKey require encryption, otherwise, encryption is optional.
 */
static const u8 RSN_KEY_DATA_GROUPKEY[] = { 0x00, 0x0f, 0xac, 1 };
static const u8 RSN_KEY_DATA_STAKEY[] = { 0x00, 0x0f, 0xac, 2 };
static const u8 RSN_KEY_DATA_MAC_ADDR[] = { 0x00, 0x0f, 0xac, 3 };
static const u8 RSN_KEY_DATA_PMKID[] = { 0x00, 0x0f, 0xac, 4 };

/* 1/4: PMKID
 * 2/4: RSN IE
 * 3/4: one or two RSN IEs + GTK IE (encrypted)
 * 4/4: empty
 * 1/2: GTK IE (encrypted)
 * 2/2: empty
 */

/* RSN IE version 1
 * 0x01 0x00 (version; little endian)
 * (all following fields are optional:)
 * Group Suite Selector (4 octets) (default: CCMP)
 * Pairwise Suite Count (2 octets, little endian) (default: 1)
 * Pairwise Suite List (4 * n octets) (default: CCMP)
 * Authenticated Key Management Suite Count (2 octets, little endian)
 *    (default: 1)
 * Authenticated Key Management Suite List (4 * n octets)
 *    (default: unspec 802.1x)
 * RSN Capabilities (2 octets, little endian) (default: 0)
 * PMKID Count (2 octets) (default: 0)
 * PMKID List (16 * n octets)
 */

struct rsn_ie_hdr {
	u8 elem_id; /* WLAN_EID_RSN */
	u8 len;
	u8 version[2];
} __attribute__ ((packed));


static int wpa_selector_to_bitfield(const u8 *s)
{
	if (memcmp(s, WPA_CIPHER_SUITE_NONE, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_NONE;
	if (memcmp(s, WPA_CIPHER_SUITE_WEP40, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_WEP40;
	if (memcmp(s, WPA_CIPHER_SUITE_TKIP, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_TKIP;
	if (memcmp(s, WPA_CIPHER_SUITE_CCMP, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_CCMP;
	if (memcmp(s, WPA_CIPHER_SUITE_WEP104, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_WEP104;
	return 0;
}


static int wpa_key_mgmt_to_bitfield(const u8 *s)
{
	if (memcmp(s, WPA_AUTH_KEY_MGMT_UNSPEC_802_1X, WPA_SELECTOR_LEN) == 0)
		return WPA_KEY_MGMT_IEEE8021X;
	if (memcmp(s, WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X, WPA_SELECTOR_LEN) ==
	    0)
		return WPA_KEY_MGMT_PSK;
	if (memcmp(s, WPA_AUTH_KEY_MGMT_NONE, WPA_SELECTOR_LEN) == 0)
		return WPA_KEY_MGMT_WPA_NONE;
	return 0;
}


static int rsn_selector_to_bitfield(const u8 *s)
{
	if (memcmp(s, RSN_CIPHER_SUITE_NONE, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_NONE;
	if (memcmp(s, RSN_CIPHER_SUITE_WEP40, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_WEP40;
	if (memcmp(s, RSN_CIPHER_SUITE_TKIP, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_TKIP;
	if (memcmp(s, RSN_CIPHER_SUITE_CCMP, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_CCMP;
	if (memcmp(s, RSN_CIPHER_SUITE_WEP104, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_WEP104;
	return 0;
}


static int rsn_key_mgmt_to_bitfield(const u8 *s)
{
	if (memcmp(s, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X, RSN_SELECTOR_LEN) == 0)
		return WPA_KEY_MGMT_IEEE8021X;
	if (memcmp(s, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X, RSN_SELECTOR_LEN) ==
	    0)
		return WPA_KEY_MGMT_PSK;
	return 0;
}


static int wpa_parse_wpa_ie_wpa(struct wpa_supplicant *wpa_s, const u8 *wpa_ie,
				size_t wpa_ie_len, struct wpa_ie_data *data)
{
	const struct wpa_ie_hdr *hdr;
	const u8 *pos;
	int left;
	int i, count;

	data->proto = WPA_PROTO_WPA;
	data->pairwise_cipher = WPA_CIPHER_TKIP;
	data->group_cipher = WPA_CIPHER_TKIP;
	data->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
	data->capabilities = 0;
	data->pmkid = NULL;
	data->num_pmkid = 0;

	if (wpa_ie_len == 0) {
		/* No WPA IE - fail silently */
		return -1;
	}

	if (wpa_ie_len < sizeof(struct wpa_ie_hdr)) {
		wpa_printf(MSG_DEBUG, "%s: ie len too short %lu",
			   __func__, (unsigned long) wpa_ie_len);
		return -1;
	}

	hdr = (const struct wpa_ie_hdr *) wpa_ie;

	if (hdr->elem_id != GENERIC_INFO_ELEM ||
	    hdr->len != wpa_ie_len - 2 ||
	    memcmp(&hdr->oui, WPA_OUI_TYPE, WPA_SELECTOR_LEN) != 0 ||
	    (hdr->version[0] | (hdr->version[1] << 8)) != WPA_VERSION) {
		wpa_printf(MSG_DEBUG, "%s: malformed ie or unknown version",
			   __func__);
		return -1;
	}

	pos = (const u8 *) (hdr + 1);
	left = wpa_ie_len - sizeof(*hdr);

	if (left >= WPA_SELECTOR_LEN) {
		data->group_cipher = wpa_selector_to_bitfield(pos);
		pos += WPA_SELECTOR_LEN;
		left -= WPA_SELECTOR_LEN;
	} else if (left > 0) {
		wpa_printf(MSG_DEBUG, "%s: ie length mismatch, %u too much",
			   __func__, left);
		return -1;
	}

	if (left >= 2) {
		data->pairwise_cipher = 0;
		count = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * WPA_SELECTOR_LEN) {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (pairwise), "
				   "count %u left %u", __func__, count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->pairwise_cipher |= wpa_selector_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} else if (left == 1) {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for key mgmt)",
			   __func__);
		return -1;
	}

	if (left >= 2) {
		data->key_mgmt = 0;
		count = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * WPA_SELECTOR_LEN) {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (key mgmt), "
				   "count %u left %u", __func__, count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->key_mgmt |= wpa_key_mgmt_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} else if (left == 1) {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for capabilities)",
			   __func__);
		return -1;
	}

	if (left >= 2) {
		data->capabilities = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
	}

	if (left > 0) {
		wpa_printf(MSG_DEBUG, "%s: ie has %u trailing bytes",
			   __func__, left);
		return -1;
	}

	return 0;
}


static int wpa_parse_wpa_ie_rsn(struct wpa_supplicant *wpa_s, const u8 *rsn_ie,
				size_t rsn_ie_len, struct wpa_ie_data *data)
{
	const struct rsn_ie_hdr *hdr;
	const u8 *pos;
	int left;
	int i, count;

	data->proto = WPA_PROTO_RSN;
	data->pairwise_cipher = WPA_CIPHER_CCMP;
	data->group_cipher = WPA_CIPHER_CCMP;
	data->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
	data->capabilities = 0;
	data->pmkid = NULL;
	data->num_pmkid = 0;

	if (rsn_ie_len == 0) {
		/* No RSN IE - fail silently */
		return -1;
	}

	if (rsn_ie_len < sizeof(struct rsn_ie_hdr)) {
		wpa_printf(MSG_DEBUG, "%s: ie len too short %lu",
			   __func__, (unsigned long) rsn_ie_len);
		return -1;
	}

	hdr = (const struct rsn_ie_hdr *) rsn_ie;

	if (hdr->elem_id != RSN_INFO_ELEM ||
	    hdr->len != rsn_ie_len - 2 ||
	    (hdr->version[0] | (hdr->version[1] << 8)) != RSN_VERSION) {
		wpa_printf(MSG_DEBUG, "%s: malformed ie or unknown version",
			   __func__);
		return -1;
	}

	pos = (const u8 *) (hdr + 1);
	left = rsn_ie_len - sizeof(*hdr);

	if (left >= RSN_SELECTOR_LEN) {
		data->group_cipher = rsn_selector_to_bitfield(pos);
		pos += RSN_SELECTOR_LEN;
		left -= RSN_SELECTOR_LEN;
	} else if (left > 0) {
		wpa_printf(MSG_DEBUG, "%s: ie length mismatch, %u too much",
			   __func__, left);
		return -1;
	}

	if (left >= 2) {
		data->pairwise_cipher = 0;
		count = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * RSN_SELECTOR_LEN) {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (pairwise), "
				   "count %u left %u", __func__, count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->pairwise_cipher |= rsn_selector_to_bitfield(pos);
			pos += RSN_SELECTOR_LEN;
			left -= RSN_SELECTOR_LEN;
		}
	} else if (left == 1) {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for key mgmt)",
			   __func__);
		return -1;
	}

	if (left >= 2) {
		data->key_mgmt = 0;
		count = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * RSN_SELECTOR_LEN) {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (key mgmt), "
				   "count %u left %u", __func__, count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->key_mgmt |= rsn_key_mgmt_to_bitfield(pos);
			pos += RSN_SELECTOR_LEN;
			left -= RSN_SELECTOR_LEN;
		}
	} else if (left == 1) {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for capabilities)",
			   __func__);
		return -1;
	}

	if (left >= 2) {
		data->capabilities = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
	}

	if (left >= 2) {
		data->num_pmkid = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
		if (left < data->num_pmkid * PMKID_LEN) {
			wpa_printf(MSG_DEBUG, "%s: PMKID underflow "
				   "(num_pmkid=%d left=%d)",
				   __func__, data->num_pmkid, left);
			data->num_pmkid = 0;
		} else {
			data->pmkid = pos;
			pos += data->num_pmkid * PMKID_LEN;
			left -= data->num_pmkid * PMKID_LEN;
		}
	}

	if (left > 0) {
		wpa_printf(MSG_DEBUG, "%s: ie has %u trailing bytes - ignored",
			   __func__, left);
	}

	return 0;
}


/**
 * wpa_parse_wpa_ie - parse WPA/RSN IE
 * @wpa_s: pointer to wpa_supplicant data
 * @wpa_ie: pointer to WPA or RSN IE
 * @wpa_ie_len: length of the WPA/RSN IE
 * @data: pointer to data area for parsing results
 *
 * Returns 0 on success, -1 on failure
 *
 * Parse the contents of WPA or RSN IE and write the parsed data into @data.
 */
int wpa_parse_wpa_ie(struct wpa_supplicant *wpa_s, const u8 *wpa_ie,
		     size_t wpa_ie_len, struct wpa_ie_data *data)
{
	if (wpa_ie_len >= 1 && wpa_ie[0] == RSN_INFO_ELEM)
		return wpa_parse_wpa_ie_rsn(wpa_s, wpa_ie, wpa_ie_len, data);
	else
		return wpa_parse_wpa_ie_wpa(wpa_s, wpa_ie, wpa_ie_len, data);
}


static int wpa_gen_wpa_ie_wpa(struct wpa_supplicant *wpa_s, u8 *wpa_ie,
			      size_t wpa_ie_len)
{
	u8 *pos;
	struct wpa_ie_hdr *hdr;

	if (wpa_ie_len < sizeof(*hdr) + WPA_SELECTOR_LEN +
	    2 + WPA_SELECTOR_LEN + 2 + WPA_SELECTOR_LEN)
		return -1;

	hdr = (struct wpa_ie_hdr *) wpa_ie;
	hdr->elem_id = GENERIC_INFO_ELEM;
	memcpy(&hdr->oui, WPA_OUI_TYPE, WPA_SELECTOR_LEN);
	hdr->version[0] = WPA_VERSION & 0xff;
	hdr->version[1] = WPA_VERSION >> 8;
	pos = (u8 *) (hdr + 1);

	if (wpa_s->group_cipher == WPA_CIPHER_CCMP) {
		memcpy(pos, WPA_CIPHER_SUITE_CCMP, WPA_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_TKIP) {
		memcpy(pos, WPA_CIPHER_SUITE_TKIP, WPA_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_WEP104) {
		memcpy(pos, WPA_CIPHER_SUITE_WEP104, WPA_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_WEP40) {
		memcpy(pos, WPA_CIPHER_SUITE_WEP40, WPA_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid group cipher (%d).",
			   wpa_s->group_cipher);
		return -1;
	}
	pos += WPA_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (wpa_s->pairwise_cipher == WPA_CIPHER_CCMP) {
		memcpy(pos, WPA_CIPHER_SUITE_CCMP, WPA_SELECTOR_LEN);
	} else if (wpa_s->pairwise_cipher == WPA_CIPHER_TKIP) {
		memcpy(pos, WPA_CIPHER_SUITE_TKIP, WPA_SELECTOR_LEN);
	} else if (wpa_s->pairwise_cipher == WPA_CIPHER_NONE) {
		memcpy(pos, WPA_CIPHER_SUITE_NONE, WPA_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid pairwise cipher (%d).",
			   wpa_s->pairwise_cipher);
		return -1;
	}
	pos += WPA_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
		memcpy(pos, WPA_AUTH_KEY_MGMT_UNSPEC_802_1X, WPA_SELECTOR_LEN);
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK) {
		memcpy(pos, WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X,
		       WPA_SELECTOR_LEN);
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPA_NONE) {
		memcpy(pos, WPA_AUTH_KEY_MGMT_NONE, WPA_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid key management type (%d).",
			   wpa_s->key_mgmt);
		return -1;
	}
	pos += WPA_SELECTOR_LEN;

	/* WPA Capabilities; use defaults, so no need to include it */

	hdr->len = (pos - wpa_ie) - 2;

	WPA_ASSERT(pos - wpa_ie <= wpa_ie_len);

	return pos - wpa_ie;
}


static int wpa_gen_wpa_ie_rsn(struct wpa_supplicant *wpa_s, u8 *rsn_ie,
			      size_t rsn_ie_len)
{
	u8 *pos;
	struct rsn_ie_hdr *hdr;

	if (rsn_ie_len < sizeof(*hdr) + RSN_SELECTOR_LEN +
	    2 + RSN_SELECTOR_LEN + 2 + RSN_SELECTOR_LEN + 2 +
	    (wpa_s->cur_pmksa ? 2 + PMKID_LEN : 0))
		return -1;

	hdr = (struct rsn_ie_hdr *) rsn_ie;
	hdr->elem_id = RSN_INFO_ELEM;
	hdr->version[0] = RSN_VERSION & 0xff;
	hdr->version[1] = RSN_VERSION >> 8;
	pos = (u8 *) (hdr + 1);

	if (wpa_s->group_cipher == WPA_CIPHER_CCMP) {
		memcpy(pos, RSN_CIPHER_SUITE_CCMP, RSN_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_TKIP) {
		memcpy(pos, RSN_CIPHER_SUITE_TKIP, RSN_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_WEP104) {
		memcpy(pos, RSN_CIPHER_SUITE_WEP104, RSN_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_WEP40) {
		memcpy(pos, RSN_CIPHER_SUITE_WEP40, RSN_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid group cipher (%d).",
			   wpa_s->group_cipher);
		return -1;
	}
	pos += RSN_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (wpa_s->pairwise_cipher == WPA_CIPHER_CCMP) {
		memcpy(pos, RSN_CIPHER_SUITE_CCMP, RSN_SELECTOR_LEN);
	} else if (wpa_s->pairwise_cipher == WPA_CIPHER_TKIP) {
		memcpy(pos, RSN_CIPHER_SUITE_TKIP, RSN_SELECTOR_LEN);
	} else if (wpa_s->pairwise_cipher == WPA_CIPHER_NONE) {
		memcpy(pos, RSN_CIPHER_SUITE_NONE, RSN_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid pairwise cipher (%d).",
			   wpa_s->pairwise_cipher);
		return -1;
	}
	pos += RSN_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
		memcpy(pos, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X, RSN_SELECTOR_LEN);
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK) {
		memcpy(pos, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X,
		       RSN_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid key management type (%d).",
			   wpa_s->key_mgmt);
		return -1;
	}
	pos += RSN_SELECTOR_LEN;

	/* RSN Capabilities */
	*pos++ = 0;
	*pos++ = 0;

	if (wpa_s->cur_pmksa) {
		/* PMKID Count (2 octets, little endian) */
		*pos++ = 1;
		*pos++ = 0;
		/* PMKID */
		memcpy(pos, wpa_s->cur_pmksa->pmkid, PMKID_LEN);
		pos += PMKID_LEN;
	}

	hdr->len = (pos - rsn_ie) - 2;

	WPA_ASSERT(pos - rsn_ie <= rsn_ie_len);

	return pos - rsn_ie;
}


/**
 * wpa_gen_wpa_ie - generate WPA/RSN IE based on current security policy
 * @wpa_s: pointer to wpa_supplicant data
 * @wpa_ie: pointer to memory area for the generated WPA/RSN IE
 * @wpa_ie_len: maximum length of the generated WPA/RSN IE
 *
 * Returns the length of the generated WPA/RSN IE or -1 on failure
 */
int wpa_gen_wpa_ie(struct wpa_supplicant *wpa_s, u8 *wpa_ie, size_t wpa_ie_len)
{
	if (wpa_s->proto == WPA_PROTO_RSN)
		return wpa_gen_wpa_ie_rsn(wpa_s, wpa_ie, wpa_ie_len);
	else
		return wpa_gen_wpa_ie_wpa(wpa_s, wpa_ie, wpa_ie_len);
}


/**
 * wpa_pmk_to_ptk - calculate PTK from PMK, addresses, and nonces
 * @pmk: pairwise master key
 * @addr1: AA or SA
 * @addr2: SA or AA
 * @nonce1: ANonce or SNonce
 * @nonce2: SNonce or ANonce
 * @ptk: buffer for pairwise transient key
 * @ptk_len: length of PTK
 *
 * IEEE Std 802.11i-2004 - 8.5.1.2 Pairwise key hierarchy
 * PTK = PRF-X(PMK, "Pairwise key expansion",
 *             Min(AA, SA) || Max(AA, SA) ||
 *             Min(ANonce, SNonce) || Max(ANonce, SNonce))
 */
static void wpa_pmk_to_ptk(const u8 *pmk, size_t pmk_len,
			   const u8 *addr1, const u8 *addr2,
			   const u8 *nonce1, const u8 *nonce2,
			   u8 *ptk, size_t ptk_len)
{
	u8 data[2 * ETH_ALEN + 2 * 32];

	if (memcmp(addr1, addr2, ETH_ALEN) < 0) {
		memcpy(data, addr1, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		memcpy(data, addr2, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr1, ETH_ALEN);
	}

	if (memcmp(nonce1, nonce2, 32) < 0) {
		memcpy(data + 2 * ETH_ALEN, nonce1, 32);
		memcpy(data + 2 * ETH_ALEN + 32, nonce2, 32);
	} else {
		memcpy(data + 2 * ETH_ALEN, nonce2, 32);
		memcpy(data + 2 * ETH_ALEN + 32, nonce1, 32);
	}

	sha1_prf(pmk, pmk_len, "Pairwise key expansion", data, sizeof(data),
		 ptk, ptk_len);

	wpa_hexdump_key(MSG_DEBUG, "WPA: PMK", pmk, pmk_len);
	wpa_hexdump_key(MSG_DEBUG, "WPA: PTK", ptk, ptk_len);
}


/**
 * wpa_eapol_key_mic - calculate EAPOL-Key MIC
 * @key: EAPOL-Key Key Confirmation Key (KCK)
 * @ver: key descriptor version (WPA_KEY_INFO_TYPE_*)
 * @buf: pointer to the beginning of the EAPOL header (version field)
 * @len: length of the EAPOL frame (from EAPOL header to the end of the frame)
 * @mic: pointer to the buffer to which the EAPOL-Key MIC is written
 *
 * Calculate EAPOL-Key MIC for an EAPOL-Key packet. The EAPOL-Key MIC field has
 * to be cleared (all zeroes) when calling this function.
 *
 * Note: 'IEEE Std 802.11i-2004 - 8.5.2 EAPOL-Key frames' has an error in the
 * description of the Key MIC calculation. It includes packet data from the
 * beginning of the EAPOL-Key header, not EAPOL header. This incorrect change
 * happened during final editing of the standard and the correct behavior is
 * defined in the last draft (IEEE 802.11i/D10).
 */
static void wpa_eapol_key_mic(const u8 *key, int ver,
			      const u8 *buf, size_t len, u8 *mic)
{
	if (ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
		hmac_md5(key, 16, buf, len, mic);
	} else if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		u8 hash[SHA1_MAC_LEN];
		hmac_sha1(key, 16, buf, len, hash);
		memcpy(mic, hash, MD5_MAC_LEN);
	}
}


static void wpa_eapol_key_send(struct wpa_supplicant *wpa_s, const u8 *kck,
			       int ver, u8 *msg, size_t msg_len, u8 *key_mic)
{
	if (key_mic) {
		wpa_eapol_key_mic(kck, ver, msg + sizeof(struct l2_ethhdr),
				  msg_len - sizeof(struct l2_ethhdr),
				  key_mic);
	}
	wpa_hexdump(MSG_MSGDUMP, "WPA: TX EAPOL-Key", msg, msg_len);
	l2_packet_send(wpa_s->l2, msg, msg_len);
	eapol_sm_notify_tx_eapol_key(wpa_s->eapol);
	free(msg);
}


/**
 * wpa_supplicant_key_request - send EAPOL-Key Request
 * @wpa_s: pointer to wpa_supplicant data
 * @error: indicate whether this is an Michael MIC error report
 * @pairwise: 1 = error report for pairwise packet, 0 = for group packet
 *
 * Returns: a pointer to the current network structure or %NULL on failure
 *
 * Send an EAPOL-Key Request to the current authenticator.
 */
void wpa_supplicant_key_request(struct wpa_supplicant *wpa_s,
				int error, int pairwise)
{
	size_t rlen;
	struct wpa_eapol_key *reply;
	int key_info, ver;
	u8 bssid[ETH_ALEN], *rbuf;

	if (wpa_s->pairwise_cipher == WPA_CIPHER_CCMP)
		ver = WPA_KEY_INFO_TYPE_HMAC_SHA1_AES;
	else
		ver = WPA_KEY_INFO_TYPE_HMAC_MD5_RC4;

	if (wpa_drv_get_bssid(wpa_s, bssid) < 0) {
		wpa_printf(MSG_WARNING, "Failed to read BSSID for EAPOL-Key "
			   "request");
		return;
	}

	rbuf = wpa_alloc_eapol(wpa_s, bssid, ETH_P_EAPOL,
			       IEEE802_1X_TYPE_EAPOL_KEY, NULL, sizeof(*reply),
			       &rlen, (void *) &reply);
	if (rbuf == NULL)
		return;

	reply->type = wpa_s->proto == WPA_PROTO_RSN ?
		EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
	key_info = WPA_KEY_INFO_REQUEST | ver;
	if (wpa_s->ptk_set)
		key_info |= WPA_KEY_INFO_MIC;
	if (error)
		key_info |= WPA_KEY_INFO_ERROR;
	if (pairwise)
		key_info |= WPA_KEY_INFO_KEY_TYPE;
	reply->key_info = host_to_be16(key_info);
	reply->key_length = 0;
	memcpy(reply->replay_counter, wpa_s->request_counter,
	       WPA_REPLAY_COUNTER_LEN);
	inc_byte_array(wpa_s->request_counter, WPA_REPLAY_COUNTER_LEN);

	reply->key_data_length = host_to_be16(0);

	wpa_printf(MSG_INFO, "WPA: Sending EAPOL-Key Request (error=%d "
		   "pairwise=%d ptk_set=%d len=%lu)",
		   error, pairwise, wpa_s->ptk_set, (unsigned long) rlen);
	wpa_eapol_key_send(wpa_s, wpa_s->ptk.kck, ver, rbuf, rlen,
			   key_info & WPA_KEY_INFO_MIC ?
			   reply->key_mic : NULL);
}


struct wpa_eapol_ie_parse {
	const u8 *wpa_ie;
	size_t wpa_ie_len;
	const u8 *rsn_ie;
	size_t rsn_ie_len;
	const u8 *pmkid;
	const u8 *gtk;
	size_t gtk_len;
};


/**
 * wpa_supplicant_parse_generic - parse EAPOL-Key Key Data Generic IEs
 * @pos: pointer to the IE header
 * @end: pointer to the end of the Key Data buffer
 * @ie: pointer to parsed IE data
 *
 * Returns: 0 on success, 1 if end mark is found, -1 on failure
 */
static int wpa_supplicant_parse_generic(const u8 *pos, const u8 *end,
					struct wpa_eapol_ie_parse *ie)
{
	if (pos[1] == 0)
		return 1;

	if (pos[1] >= 6 &&
	    memcmp(pos + 2, WPA_OUI_TYPE, WPA_SELECTOR_LEN) == 0 &&
	    pos[2 + WPA_SELECTOR_LEN] == 1 &&
	    pos[2 + WPA_SELECTOR_LEN + 1] == 0) {
		ie->wpa_ie = pos;
		ie->wpa_ie_len = pos[1] + 2;
		return 0;
	}

	if (pos + 1 + RSN_SELECTOR_LEN < end &&
	    pos[1] >= RSN_SELECTOR_LEN + PMKID_LEN &&
	    memcmp(pos + 2, RSN_KEY_DATA_PMKID, RSN_SELECTOR_LEN) == 0) {
		ie->pmkid = pos + 2 + RSN_SELECTOR_LEN;
		return 0;
	}

	if (pos[1] > RSN_SELECTOR_LEN + 2 &&
	    memcmp(pos + 2, RSN_KEY_DATA_GROUPKEY, RSN_SELECTOR_LEN) == 0) {
		ie->gtk = pos + 2 + RSN_SELECTOR_LEN;
		ie->gtk_len = pos[1] - RSN_SELECTOR_LEN;
	}

	return 0;
}


/**
 * wpa_supplicant_parse_ies - parse EAPOL-Key Key Data IEs
 * @buf: pointer to the Key Data buffer
 * @len: Key Data Length
 * @ie: pointer to parsed IE data
 *
 * Returns: 0 on success, -1 on failure
 */
static int wpa_supplicant_parse_ies(const u8 *buf, size_t len,
				    struct wpa_eapol_ie_parse *ie)
{
	const u8 *pos, *end;
	int ret = 0;

	memset(ie, 0, sizeof(*ie));
	pos = buf;
	end = pos + len;

	for (pos = buf, end = pos + len; pos + 1 < end; pos += 2 + pos[1]) {
		if (pos + 2 + pos[1] > end) {
			wpa_printf(MSG_DEBUG, "WPA: EAPOL-Key Key Data "
				   "underflow (ie=%d len=%d)", pos[0], pos[1]);
			ret = -1;
			break;
		}
		if (*pos == RSN_INFO_ELEM) {
			ie->rsn_ie = pos;
			ie->rsn_ie_len = pos[1] + 2;
		} else if (*pos == GENERIC_INFO_ELEM) {
			ret = wpa_supplicant_parse_generic(pos, end, ie);
			if (ret < 0)
				break;
			if (ret > 0) {
				ret = 0;
				break;
			}
		} else {
			wpa_hexdump(MSG_DEBUG, "WPA: Unrecognized EAPOL-Key "
				    "Key Data IE", pos, 2 + pos[1]);
		}
	}

	return ret;
}


static int wpa_supplicant_get_pmk(struct wpa_supplicant *wpa_s,
				  const unsigned char *src_addr,
				  const u8 *pmkid)
{
	int abort_cached = 0;

	if (pmkid && !wpa_s->cur_pmksa) {
		/* When using drivers that generate RSN IE, wpa_supplicant may
		 * not have enough time to get the association information
		 * event before receiving this 1/4 message, so try to find a
		 * matching PMKSA cache entry here. */
		wpa_s->cur_pmksa = pmksa_cache_get(wpa_s, src_addr, pmkid);
		if (wpa_s->cur_pmksa) {
			wpa_printf(MSG_DEBUG, "RSN: found matching PMKID from "
				   "PMKSA cache");
		} else {
			wpa_printf(MSG_DEBUG, "RSN: no matching PMKID found");
			abort_cached = 1;
		}
	}

	if (pmkid && wpa_s->cur_pmksa &&
	    memcmp(pmkid, wpa_s->cur_pmksa->pmkid, PMKID_LEN) == 0) {
		wpa_hexdump(MSG_DEBUG, "RSN: matched PMKID", pmkid, PMKID_LEN);
		memcpy(wpa_s->pmk, wpa_s->cur_pmksa->pmk, PMK_LEN);
		wpa_hexdump_key(MSG_DEBUG, "RSN: PMK from PMKSA cache",
				wpa_s->pmk, PMK_LEN);
		eapol_sm_notify_cached(wpa_s->eapol);
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X && wpa_s->eapol) {
		int res, pmk_len;
		pmk_len = PMK_LEN;
		res = eapol_sm_get_key(wpa_s->eapol, wpa_s->pmk, PMK_LEN);
#ifdef EAP_LEAP
		if (res) {
			res = eapol_sm_get_key(wpa_s->eapol, wpa_s->pmk, 16);
			pmk_len = 16;
		}
#endif /* EAP_LEAP */
		if (res == 0) {
			wpa_hexdump_key(MSG_DEBUG, "WPA: PMK from EAPOL state "
					"machines", wpa_s->pmk, pmk_len);
			wpa_s->pmk_len = pmk_len;
			pmksa_cache_add(wpa_s, wpa_s->pmk, pmk_len, src_addr,
					wpa_s->own_addr, wpa_s->current_ssid);
			if (!wpa_s->cur_pmksa && pmkid &&
			    pmksa_cache_get(wpa_s, src_addr, pmkid)) {
				wpa_printf(MSG_DEBUG, "RSN: the new PMK "
					   "matches with the PMKID");
				abort_cached = 0;
			}
		} else {
			wpa_msg(wpa_s, MSG_WARNING,
				"WPA: Failed to get master session key from "
				"EAPOL state machines");
			wpa_msg(wpa_s, MSG_WARNING,
				"WPA: Key handshake aborted");
			if (wpa_s->cur_pmksa) {
				wpa_printf(MSG_DEBUG, "RSN: Cancelled PMKSA "
					   "caching attempt");
				wpa_s->cur_pmksa = NULL;
				abort_cached = 1;
			} else {
				return -1;
			}
		}
#ifdef CONFIG_XSUPPLICANT_IFACE
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X &&
		   !wpa_s->ext_pmk_received) {
		wpa_printf(MSG_INFO, "WPA: Master session has not yet "
			   "been received from the external IEEE "
			   "802.1X Supplicant - ignoring WPA "
			   "EAPOL-Key frame");
		return -1;
#endif /* CONFIG_XSUPPLICANT_IFACE */
	}

	if (abort_cached && wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
		/* Send EAPOL-Start to trigger full EAP authentication. */
		wpa_printf(MSG_DEBUG, "RSN: no PMKSA entry found - trigger "
			   "full EAP authenication");
		wpa_eapol_send(wpa_s, IEEE802_1X_TYPE_EAPOL_START,
			       (u8 *) "", 0);
		return -1;
	}

	return 0;
}


static int wpa_supplicant_send_2_of_4(struct wpa_supplicant *wpa_s,
				      const unsigned char *src_addr,
				      const struct wpa_eapol_key *key,
				      int ver)
{
	size_t rlen;
	struct wpa_eapol_key *reply;
	struct wpa_ptk *ptk;
	u8 buf[8], *rbuf, wpa_ie_buf[80], *wpa_ie;
	int wpa_ie_len;

	if (wpa_s->assoc_wpa_ie) {
		/* The driver reported a WPA IE that may be different from the
		 * one that the Supplicant would use. Message 2/4 has to use
		 * the exact copy of the WPA IE from the Association Request,
		 * so use the value reported by the driver. */
		wpa_ie = wpa_s->assoc_wpa_ie;
		wpa_ie_len = wpa_s->assoc_wpa_ie_len;
	} else {
		wpa_ie = wpa_ie_buf;
		wpa_ie_len = wpa_gen_wpa_ie(wpa_s, wpa_ie, sizeof(wpa_ie_buf));
		if (wpa_ie_len < 0) {
			wpa_printf(MSG_WARNING, "WPA: Failed to generate "
				   "WPA IE (for msg 2 of 4).");
			return -1;
		}
		wpa_hexdump(MSG_DEBUG, "WPA: WPA IE for msg 2/4",
			    wpa_ie, wpa_ie_len);
	}

	rbuf = wpa_alloc_eapol(wpa_s, src_addr, ETH_P_EAPOL,
			       IEEE802_1X_TYPE_EAPOL_KEY, NULL,
			       sizeof(*reply) + wpa_ie_len,
			       &rlen, (void *) &reply);
	if (rbuf == NULL)
		return -1;

	reply->type = wpa_s->proto == WPA_PROTO_RSN ?
		EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
	reply->key_info = host_to_be16(ver | WPA_KEY_INFO_KEY_TYPE |
				       WPA_KEY_INFO_MIC);
	reply->key_length = wpa_s->proto == WPA_PROTO_RSN ?
		0 : key->key_length;
	memcpy(reply->replay_counter, key->replay_counter,
	       WPA_REPLAY_COUNTER_LEN);

	reply->key_data_length = host_to_be16(wpa_ie_len);
	memcpy(reply + 1, wpa_ie, wpa_ie_len);

	if (wpa_s->renew_snonce) {
		if (hostapd_get_rand(wpa_s->snonce, WPA_NONCE_LEN)) {
			wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to get "
				"random data for SNonce");
			free(rbuf);
			return -1;
		}
		wpa_s->renew_snonce = 0;
		wpa_hexdump(MSG_DEBUG, "WPA: Renewed SNonce",
			    wpa_s->snonce, WPA_NONCE_LEN);
	}
	memcpy(reply->key_nonce, wpa_s->snonce, WPA_NONCE_LEN);

	/* Calculate PTK which will be stored as a temporary PTK until it has
	 * been verified when processing message 3/4. */
	ptk = &wpa_s->tptk;
	wpa_pmk_to_ptk(wpa_s->pmk, wpa_s->pmk_len, wpa_s->own_addr, src_addr,
		       wpa_s->snonce, key->key_nonce,
		       (u8 *) ptk, sizeof(*ptk));
	/* Supplicant: swap tx/rx Mic keys */
	memcpy(buf, ptk->u.auth.tx_mic_key, 8);
	memcpy(ptk->u.auth.tx_mic_key, ptk->u.auth.rx_mic_key, 8);
	memcpy(ptk->u.auth.rx_mic_key, buf, 8);
	wpa_s->tptk_set = 1;

	wpa_printf(MSG_DEBUG, "WPA: Sending EAPOL-Key 2/4");
	wpa_eapol_key_send(wpa_s, ptk->kck, ver, rbuf, rlen, reply->key_mic);

	return 0;
}


static void wpa_supplicant_process_1_of_4(struct wpa_supplicant *wpa_s,
					  const unsigned char *src_addr,
					  const struct wpa_eapol_key *key,
					  int ver)
{
	struct wpa_eapol_ie_parse ie;

	wpa_supplicant_set_state(wpa_s, WPA_4WAY_HANDSHAKE);
	wpa_printf(MSG_DEBUG, "WPA: RX message 1 of 4-Way Handshake from "
		   MACSTR " (ver=%d)", MAC2STR(src_addr), ver);

	if (wpa_supplicant_get_ssid(wpa_s) == NULL) {
		wpa_printf(MSG_WARNING, "WPA: No SSID info found (msg 1 of "
			   "4).");
		return;
	}

	memset(&ie, 0, sizeof(ie));

	if (wpa_s->proto == WPA_PROTO_RSN) {
		/* RSN: msg 1/4 should contain PMKID for the selected PMK */
		const u8 *buf = (const u8 *) (key + 1);
		size_t len = be_to_host16(key->key_data_length);
		wpa_hexdump(MSG_DEBUG, "RSN: msg 1/4 key data", buf, len);
		wpa_supplicant_parse_ies(buf, len, &ie);
		if (ie.pmkid) {
			wpa_hexdump(MSG_DEBUG, "RSN: PMKID from "
				    "Authenticator", ie.pmkid, PMKID_LEN);
		}
	}

	if (wpa_supplicant_get_pmk(wpa_s, src_addr, ie.pmkid))
		return;

	if (wpa_supplicant_send_2_of_4(wpa_s, src_addr, key, ver))
		return;

	memcpy(wpa_s->anonce, key->key_nonce, WPA_NONCE_LEN);
}


static void wpa_supplicant_key_neg_complete(struct wpa_supplicant *wpa_s,
					    const u8 *addr, int secure)
{
	wpa_msg(wpa_s, MSG_INFO, "WPA: Key negotiation completed with "
		MACSTR " [PTK=%s GTK=%s]", MAC2STR(addr),
		wpa_cipher_txt(wpa_s->pairwise_cipher),
		wpa_cipher_txt(wpa_s->group_cipher));
	eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
	wpa_supplicant_cancel_auth_timeout(wpa_s);
	wpa_supplicant_set_state(wpa_s, WPA_COMPLETED);

	if (secure) {
		/* MLME.SETPROTECTION.request(TA, Tx_Rx) */
		eapol_sm_notify_portValid(wpa_s->eapol, TRUE);
		if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK)
			eapol_sm_notify_eap_success(wpa_s->eapol, TRUE);
		rsn_preauth_candidate_process(wpa_s);
	}

	if (wpa_s->cur_pmksa && wpa_s->cur_pmksa->opportunistic) {
		wpa_printf(MSG_DEBUG, "RSN: Authenticator accepted "
			   "opportunistic PMKSA entry - marking it valid");
		wpa_s->cur_pmksa->opportunistic = 0;
	}
}


static int wpa_supplicant_install_ptk(struct wpa_supplicant *wpa_s,
				      const unsigned char *src_addr,
				      const struct wpa_eapol_key *key)
{
	int alg, keylen, rsclen;
	const u8 *key_rsc;
	u8 null_rsc[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	wpa_printf(MSG_DEBUG, "WPA: Installing PTK to the driver.");

	switch (wpa_s->pairwise_cipher) {
	case WPA_CIPHER_CCMP:
		alg = WPA_ALG_CCMP;
		keylen = 16;
		rsclen = 6;
		break;
	case WPA_CIPHER_TKIP:
		alg = WPA_ALG_TKIP;
		keylen = 32;
		rsclen = 6;
		break;
	case WPA_CIPHER_NONE:
		wpa_printf(MSG_DEBUG, "WPA: Pairwise Cipher Suite: "
			   "NONE - do not use pairwise keys");
		return 0;
	default:
		wpa_printf(MSG_WARNING, "WPA: Unsupported pairwise cipher %d",
			   wpa_s->pairwise_cipher);
		return -1;
	}

	if (wpa_s->proto == WPA_PROTO_RSN) {
		key_rsc = null_rsc;
	} else {
		key_rsc = key->key_rsc;
		wpa_hexdump(MSG_DEBUG, "WPA: RSC", key_rsc, rsclen);
	}

	wpa_s->keys_cleared = 0;
	if (wpa_drv_set_key(wpa_s, alg, src_addr, 0, 1, key_rsc, rsclen,
			    (u8 *) &wpa_s->ptk.tk1, keylen) < 0) {
		wpa_printf(MSG_WARNING, "WPA: Failed to set PTK to the "
			   "driver.");
		return -1;
	}
	return 0;
}


static int wpa_supplicant_check_group_cipher(struct wpa_supplicant *wpa_s,
					     int keylen, int maxkeylen,
					     int *key_rsc_len, int *alg)
{
	int ret = 0;

	switch (wpa_s->group_cipher) {
	case WPA_CIPHER_CCMP:
		if (keylen != 16 || maxkeylen < 16) {
			ret = -1;
			break;
		}
		*key_rsc_len = 6;
		*alg = WPA_ALG_CCMP;
		break;
	case WPA_CIPHER_TKIP:
		if (keylen != 32 || maxkeylen < 32) {
			ret = -1;
			break;
		}
		*key_rsc_len = 6;
		*alg = WPA_ALG_TKIP;
		break;
	case WPA_CIPHER_WEP104:
		if (keylen != 13 || maxkeylen < 13) {
			ret = -1;
			break;
		}
		*key_rsc_len = 0;
		*alg = WPA_ALG_WEP;
		break;
	case WPA_CIPHER_WEP40:
		if (keylen != 5 || maxkeylen < 5) {
			ret = -1;
			break;
		}
		*key_rsc_len = 0;
		*alg = WPA_ALG_WEP;
		break;
	default:
		wpa_printf(MSG_WARNING, "WPA: Unsupported Group Cipher %d",
			   wpa_s->group_cipher);
		return -1;
	}

	if (ret < 0 ) {
		wpa_printf(MSG_WARNING, "WPA: Unsupported %s Group Cipher key "
			   "length %d (%d).",
			   wpa_cipher_txt(wpa_s->group_cipher),
			   keylen, maxkeylen);
	}

	return ret;
}


struct wpa_gtk_data {
	int alg, tx, key_rsc_len, keyidx;
	u8 gtk[32];
	int gtk_len;
};


static int wpa_supplicant_install_gtk(struct wpa_supplicant *wpa_s,
				      const struct wpa_gtk_data *gd,
				      const u8 *key_rsc)
{
	const u8 *_gtk = gd->gtk;
	u8 gtk_buf[32];

	wpa_hexdump_key(MSG_DEBUG, "WPA: Group Key", gd->gtk, gd->gtk_len);
	wpa_printf(MSG_DEBUG, "WPA: Installing GTK to the driver "
		   "(keyidx=%d tx=%d).", gd->keyidx, gd->tx);
	wpa_hexdump(MSG_DEBUG, "WPA: RSC", key_rsc, gd->key_rsc_len);
	if (wpa_s->group_cipher == WPA_CIPHER_TKIP) {
		/* Swap Tx/Rx keys for Michael MIC */
		memcpy(gtk_buf, gd->gtk, 16);
		memcpy(gtk_buf + 16, gd->gtk + 24, 8);
		memcpy(gtk_buf + 24, gd->gtk + 16, 8);
		_gtk = gtk_buf;
	}
	wpa_s->keys_cleared = 0;
	if (wpa_s->pairwise_cipher == WPA_CIPHER_NONE) {
		if (wpa_drv_set_key(wpa_s, gd->alg,
				    (u8 *) "\xff\xff\xff\xff\xff\xff",
				    gd->keyidx, 1, key_rsc, gd->key_rsc_len,
				    _gtk, gd->gtk_len) < 0) {
			wpa_printf(MSG_WARNING, "WPA: Failed to set "
				   "GTK to the driver (Group only).");
			return -1;
		}
	} else if (wpa_drv_set_key(wpa_s, gd->alg,
				   (u8 *) "\xff\xff\xff\xff\xff\xff",
				   gd->keyidx, gd->tx, key_rsc,
				   gd->key_rsc_len, _gtk, gd->gtk_len) < 0) {
		wpa_printf(MSG_WARNING, "WPA: Failed to set GTK to "
			   "the driver.");
		return -1;
	}

	return 0;
}


static int wpa_supplicant_gtk_tx_bit_workaround(
	const struct wpa_supplicant *wpa_s, int tx)
{
	if (tx && wpa_s->pairwise_cipher != WPA_CIPHER_NONE) {
		/* Ignore Tx bit for GTK if a pairwise key is used. One AP
		 * seemed to set this bit (incorrectly, since Tx is only when
		 * doing Group Key only APs) and without this workaround, the
		 * data connection does not work because wpa_supplicant
		 * configured non-zero keyidx to be used for unicast. */
		wpa_printf(MSG_INFO, "WPA: Tx bit set for GTK, but pairwise "
			   "keys are used - ignore Tx bit");
		return 0;
	}
	return tx;
}


static int wpa_supplicant_pairwise_gtk(struct wpa_supplicant *wpa_s,
				       const unsigned char *src_addr,
				       const struct wpa_eapol_key *key,
				       const u8 *gtk, int gtk_len,
				       int key_info)
{
	struct wpa_gtk_data gd;

	/*
	 * IEEE Std 802.11i-2004 - 8.5.2 EAPOL-Key frames - Figure 43x
	 * GTK KDE format:
	 * KeyID[bits 0-1], Tx [bit 2], Reserved [bits 3-7]
	 * Reserved [bits 0-7]
	 * GTK
	 */

	memset(&gd, 0, sizeof(gd));
	wpa_hexdump_key(MSG_DEBUG, "RSN: received GTK in pairwise handshake",
			gtk, gtk_len);

	if (gtk_len < 2 || gtk_len - 2 > sizeof(gd.gtk))
		return -1;

	gd.keyidx = gtk[0] & 0x3;
	gd.tx = wpa_supplicant_gtk_tx_bit_workaround(wpa_s,
						     !!(gtk[0] & BIT(2)));
	gtk += 2;
	gtk_len -= 2;

	memcpy(gd.gtk, gtk, gtk_len);
	gd.gtk_len = gtk_len;

	if (wpa_supplicant_check_group_cipher(wpa_s, gtk_len, gtk_len,
					      &gd.key_rsc_len, &gd.alg) ||
	    wpa_supplicant_install_gtk(wpa_s, &gd, key->key_rsc)) {
		wpa_printf(MSG_DEBUG, "RSN: Failed to install GTK");
		return -1;
	}

	wpa_supplicant_key_neg_complete(wpa_s, src_addr,
					key_info & WPA_KEY_INFO_SECURE);
	return 0;
}


static void wpa_report_ie_mismatch(struct wpa_supplicant *wpa_s,
				   const char *reason, const u8 *src_addr,
				   const u8 *wpa_ie, size_t wpa_ie_len,
				   const u8 *rsn_ie, size_t rsn_ie_len)
{
	wpa_msg(wpa_s, MSG_WARNING, "WPA: %s (src=" MACSTR ")",
		reason, MAC2STR(src_addr));

	if (wpa_s->ap_wpa_ie) {
		wpa_hexdump(MSG_INFO, "WPA: WPA IE in Beacon/ProbeResp",
			    wpa_s->ap_wpa_ie, wpa_s->ap_wpa_ie_len);
	}
	if (wpa_ie) {
		if (!wpa_s->ap_wpa_ie) {
			wpa_printf(MSG_INFO, "WPA: No WPA IE in "
				   "Beacon/ProbeResp");
		}
		wpa_hexdump(MSG_INFO, "WPA: WPA IE in 3/4 msg",
			    wpa_ie, wpa_ie_len);
	}

	if (wpa_s->ap_rsn_ie) {
		wpa_hexdump(MSG_INFO, "WPA: RSN IE in Beacon/ProbeResp",
			    wpa_s->ap_rsn_ie, wpa_s->ap_rsn_ie_len);
	}
	if (rsn_ie) {
		if (!wpa_s->ap_rsn_ie) {
			wpa_printf(MSG_INFO, "WPA: No RSN IE in "
				   "Beacon/ProbeResp");
		}
		wpa_hexdump(MSG_INFO, "WPA: RSN IE in 3/4 msg",
			    rsn_ie, rsn_ie_len);
	}

	wpa_supplicant_disassociate(wpa_s, REASON_IE_IN_4WAY_DIFFERS);
	wpa_supplicant_req_scan(wpa_s, 0, 0);
}


static int wpa_supplicant_validate_ie(struct wpa_supplicant *wpa_s,
				      const unsigned char *src_addr,
				      struct wpa_eapol_ie_parse *ie)
{
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	if (wpa_s->ap_wpa_ie == NULL && wpa_s->ap_rsn_ie == NULL) {
		wpa_printf(MSG_DEBUG, "WPA: No WPA/RSN IE for this AP known. "
			   "Trying to get from scan results");
		if (wpa_supplicant_get_beacon_ie(wpa_s) < 0) {
			wpa_printf(MSG_WARNING, "WPA: Could not find AP from "
				   "the scan results");
		} else {
			wpa_printf(MSG_DEBUG, "WPA: Found the current AP from "
				   "updated scan results");
		}
	}

	if ((ie->wpa_ie && wpa_s->ap_wpa_ie &&
	     (ie->wpa_ie_len != wpa_s->ap_wpa_ie_len ||
	      memcmp(ie->wpa_ie, wpa_s->ap_wpa_ie, ie->wpa_ie_len) != 0)) ||
	    (ie->rsn_ie && wpa_s->ap_rsn_ie &&
	     (ie->rsn_ie_len != wpa_s->ap_rsn_ie_len ||
	      memcmp(ie->rsn_ie, wpa_s->ap_rsn_ie, ie->rsn_ie_len) != 0))) {
		wpa_report_ie_mismatch(wpa_s, "IE in 3/4 msg does not match "
				       "with IE in Beacon/ProbeResp",
				       src_addr, ie->wpa_ie, ie->wpa_ie_len,
				       ie->rsn_ie, ie->rsn_ie_len);
		return -1;
	}

	if (wpa_s->proto == WPA_PROTO_WPA &&
	    ie->rsn_ie && wpa_s->ap_rsn_ie == NULL &&
	    ssid && (ssid->proto & WPA_PROTO_RSN)) {
		wpa_report_ie_mismatch(wpa_s, "Possible downgrade attack "
				       "detected - RSN was enabled and RSN IE "
				       "was in msg 3/4, but not in "
				       "Beacon/ProbeResp",
				       src_addr, ie->wpa_ie, ie->wpa_ie_len,
				       ie->rsn_ie, ie->rsn_ie_len);
		return -1;
	}

	return 0;
}


static int wpa_supplicant_send_4_of_4(struct wpa_supplicant *wpa_s,
				      const unsigned char *src_addr,
				      const struct wpa_eapol_key *key,
				      int ver, int key_info)
{
	size_t rlen;
	struct wpa_eapol_key *reply;
	u8 *rbuf;

	rbuf = wpa_alloc_eapol(wpa_s, src_addr, ETH_P_EAPOL,
			       IEEE802_1X_TYPE_EAPOL_KEY, NULL,
			       sizeof(*reply), &rlen, (void *) &reply);
	if (rbuf == NULL)
		return -1;

	reply->type = wpa_s->proto == WPA_PROTO_RSN ?
		EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
	reply->key_info = host_to_be16(ver | WPA_KEY_INFO_KEY_TYPE |
				       WPA_KEY_INFO_MIC |
				       (key_info & WPA_KEY_INFO_SECURE));
	reply->key_length = wpa_s->proto == WPA_PROTO_RSN ?
		0 : key->key_length;
	memcpy(reply->replay_counter, key->replay_counter,
	       WPA_REPLAY_COUNTER_LEN);

	reply->key_data_length = host_to_be16(0);

	wpa_printf(MSG_DEBUG, "WPA: Sending EAPOL-Key 4/4");
	wpa_eapol_key_send(wpa_s, wpa_s->ptk.kck, ver, rbuf, rlen,
			   reply->key_mic);

	return 0;
}


static void wpa_supplicant_process_3_of_4(struct wpa_supplicant *wpa_s,
					  const unsigned char *src_addr,
					  const struct wpa_eapol_key *key,
					  int extra_len, int ver)
{
	int key_info, keylen;
	const u8 *pos;
	u16 len;
	struct wpa_eapol_ie_parse ie;

	wpa_supplicant_set_state(wpa_s, WPA_4WAY_HANDSHAKE);
	wpa_printf(MSG_DEBUG, "WPA: RX message 3 of 4-Way Handshake from "
		   MACSTR " (ver=%d)", MAC2STR(src_addr), ver);

	key_info = be_to_host16(key->key_info);

	pos = (const u8 *) (key + 1);
	len = be_to_host16(key->key_data_length);
	wpa_hexdump(MSG_DEBUG, "WPA: IE KeyData", pos, len);
	wpa_supplicant_parse_ies(pos, len, &ie);
	if (ie.gtk && !(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		wpa_printf(MSG_WARNING, "WPA: GTK IE in unencrypted key data");
		return;
	}

	if (wpa_supplicant_validate_ie(wpa_s, src_addr, &ie) < 0)
		return;

	if (memcmp(wpa_s->anonce, key->key_nonce, WPA_NONCE_LEN) != 0) {
		wpa_printf(MSG_WARNING, "WPA: ANonce from message 1 of 4-Way "
			   "Handshake differs from 3 of 4-Way Handshake - drop"
			   " packet (src=" MACSTR ")", MAC2STR(src_addr));
		return;
	}

	keylen = be_to_host16(key->key_length);
	switch (wpa_s->pairwise_cipher) {
	case WPA_CIPHER_CCMP:
		if (keylen != 16) {
			wpa_printf(MSG_WARNING, "WPA: Invalid CCMP key length "
				   "%d (src=" MACSTR ")",
				   keylen, MAC2STR(src_addr));
			return;
		}
		break;
	case WPA_CIPHER_TKIP:
		if (keylen != 32) {
			wpa_printf(MSG_WARNING, "WPA: Invalid TKIP key length "
				   "%d (src=" MACSTR ")",
				   keylen, MAC2STR(src_addr));
			return;
		}
		break;
	}

	if (wpa_supplicant_send_4_of_4(wpa_s, src_addr, key, ver, key_info))
		return;

	/* SNonce was successfully used in msg 3/4, so mark it to be renewed
	 * for the next 4-Way Handshake. If msg 3 is received again, the old
	 * SNonce will still be used to avoid changing PTK. */
	wpa_s->renew_snonce = 1;

	if (key_info & WPA_KEY_INFO_INSTALL) {
		wpa_supplicant_install_ptk(wpa_s, src_addr, key);
	}

	if (key_info & WPA_KEY_INFO_SECURE) {
		/* MLME.SETPROTECTION.request(TA, Tx_Rx) */
		eapol_sm_notify_portValid(wpa_s->eapol, TRUE);
	}
	wpa_supplicant_set_state(wpa_s, WPA_GROUP_HANDSHAKE);

	if (ie.gtk &&
	    wpa_supplicant_pairwise_gtk(wpa_s, src_addr, key,
					ie.gtk, ie.gtk_len, key_info) < 0) {
		wpa_printf(MSG_INFO, "RSN: Failed to configure GTK");
	}
}


static int wpa_supplicant_process_1_of_2_rsn(struct wpa_supplicant *wpa_s,
					     const u8 *keydata,
					     size_t keydatalen,
					     int key_info,
					     struct wpa_gtk_data *gd)
{
	int maxkeylen;
	struct wpa_eapol_ie_parse ie;

	wpa_hexdump(MSG_DEBUG, "RSN: msg 1/2 key data", keydata, keydatalen);
	wpa_supplicant_parse_ies(keydata, keydatalen, &ie);
	if (ie.gtk && !(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		wpa_printf(MSG_WARNING, "WPA: GTK IE in unencrypted key data");
		return -1;
	}
	if (ie.gtk == NULL) {
		wpa_printf(MSG_INFO, "WPA: No GTK IE in Group Key msg 1/2");
		return -1;
	}
	maxkeylen = gd->gtk_len = ie.gtk_len - 2;

	if (wpa_supplicant_check_group_cipher(wpa_s, gd->gtk_len, maxkeylen,
					      &gd->key_rsc_len, &gd->alg))
		return -1;

	wpa_hexdump(MSG_DEBUG, "RSN: received GTK in group key handshake",
		    ie.gtk, ie.gtk_len);
	gd->keyidx = ie.gtk[0] & 0x3;
	gd->tx = wpa_supplicant_gtk_tx_bit_workaround(wpa_s,
						      !!(ie.gtk[0] & BIT(2)));
	if (ie.gtk_len - 2 > sizeof(gd->gtk)) {
		wpa_printf(MSG_INFO, "RSN: Too long GTK in GTK IE "
			   "(len=%lu)", (unsigned long) ie.gtk_len - 2);
		return -1;
	}
	memcpy(gd->gtk, ie.gtk + 2, ie.gtk_len - 2);

	return 0;
}


static int wpa_supplicant_process_1_of_2_wpa(struct wpa_supplicant *wpa_s,
					     const struct wpa_eapol_key *key,
					     size_t keydatalen, int key_info,
					     int extra_len, int ver,
					     struct wpa_gtk_data *gd)
{
	int maxkeylen;
	u8 ek[32];

	gd->gtk_len = be_to_host16(key->key_length);
	maxkeylen = keydatalen;
	if (keydatalen > extra_len) {
		wpa_printf(MSG_INFO, "WPA: Truncated EAPOL-Key packet:"
			   " key_data_length=%lu > extra_len=%d",
			   (unsigned long) keydatalen, extra_len);
		return -1;
	}
	if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES)
		maxkeylen -= 8;

	if (wpa_supplicant_check_group_cipher(wpa_s, gd->gtk_len, maxkeylen,
					      &gd->key_rsc_len, &gd->alg))
		return -1;

	gd->keyidx = (key_info & WPA_KEY_INFO_KEY_INDEX_MASK) >>
		WPA_KEY_INFO_KEY_INDEX_SHIFT;
	if (ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
		memcpy(ek, key->key_iv, 16);
		memcpy(ek + 16, wpa_s->ptk.kek, 16);
		if (keydatalen > sizeof(gd->gtk)) {
			wpa_printf(MSG_WARNING, "WPA: RC4 key data "
				   "too long (%lu)",
				   (unsigned long) keydatalen);
			return -1;
		}
		memcpy(gd->gtk, key + 1, keydatalen);
		rc4_skip(ek, 32, 256, gd->gtk, keydatalen);
	} else if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		if (keydatalen % 8) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported AES-WRAP "
				   "len %lu", (unsigned long) keydatalen);
			return -1;
		}
		if (aes_unwrap(wpa_s->ptk.kek, maxkeylen / 8,
			       (const u8 *) (key + 1), gd->gtk)) {
			wpa_printf(MSG_WARNING, "WPA: AES unwrap "
				   "failed - could not decrypt GTK");
			return -1;
		}
	}
	gd->tx = wpa_supplicant_gtk_tx_bit_workaround(
		wpa_s, !!(key_info & WPA_KEY_INFO_TXRX));
	return 0;
}


static int wpa_supplicant_send_2_of_2(struct wpa_supplicant *wpa_s,
				      const unsigned char *src_addr,
				      const struct wpa_eapol_key *key,
				      int ver, int key_info)
{
	size_t rlen;
	struct wpa_eapol_key *reply;
	u8 *rbuf;

	rbuf = wpa_alloc_eapol(wpa_s, src_addr, ETH_P_EAPOL,
			       IEEE802_1X_TYPE_EAPOL_KEY, NULL,
			       sizeof(*reply), &rlen, (void *) &reply);
	if (rbuf == NULL)
		return -1;

	reply->type = wpa_s->proto == WPA_PROTO_RSN ?
		EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
	reply->key_info =
		host_to_be16(ver | WPA_KEY_INFO_MIC | WPA_KEY_INFO_SECURE |
			     (key_info & WPA_KEY_INFO_KEY_INDEX_MASK));
	reply->key_length = wpa_s->proto == WPA_PROTO_RSN ?
		0 : key->key_length;
	memcpy(reply->replay_counter, key->replay_counter,
	       WPA_REPLAY_COUNTER_LEN);

	reply->key_data_length = host_to_be16(0);

	wpa_printf(MSG_DEBUG, "WPA: Sending EAPOL-Key 2/2");
	wpa_eapol_key_send(wpa_s, wpa_s->ptk.kck, ver, rbuf, rlen,
			   reply->key_mic);

	return 0;
}


static void wpa_supplicant_process_1_of_2(struct wpa_supplicant *wpa_s,
					  const unsigned char *src_addr,
					  const struct wpa_eapol_key *key,
					  int extra_len, int ver)
{
	int key_info, keydatalen;
	int rekey;
	struct wpa_gtk_data gd;

	memset(&gd, 0, sizeof(gd));

	rekey = wpa_s->wpa_state == WPA_COMPLETED;
	wpa_supplicant_set_state(wpa_s, WPA_GROUP_HANDSHAKE);
	wpa_printf(MSG_DEBUG, "WPA: RX message 1 of Group Key Handshake from "
		   MACSTR " (ver=%d)", MAC2STR(src_addr), ver);

	key_info = be_to_host16(key->key_info);
	keydatalen = be_to_host16(key->key_data_length);

	if (wpa_s->proto == WPA_PROTO_RSN) {
		if (wpa_supplicant_process_1_of_2_rsn(wpa_s,
						      (const u8 *) (key + 1),
						      keydatalen, key_info,
						      &gd))
			return;
	} else {
		if (wpa_supplicant_process_1_of_2_wpa(wpa_s, key, keydatalen,
						      key_info, extra_len,
						      ver, &gd))
			return;
	}

	if (wpa_supplicant_install_gtk(wpa_s, &gd, key->key_rsc) ||
	    wpa_supplicant_send_2_of_2(wpa_s, src_addr, key, ver, key_info))
		return;

	if (rekey) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Group rekeying completed with "
			MACSTR " [GTK=%s]", MAC2STR(src_addr),
			wpa_cipher_txt(wpa_s->group_cipher));
		wpa_supplicant_set_state(wpa_s, WPA_COMPLETED);
	} else {
		wpa_supplicant_key_neg_complete(wpa_s, src_addr,
						key_info &
						WPA_KEY_INFO_SECURE);
	}
}


static int wpa_supplicant_verify_eapol_key_mic(struct wpa_supplicant *wpa_s,
					       struct wpa_eapol_key *key,
					       int ver,
					       const u8 *buf, size_t len)
{
	u8 mic[16];
	int ok = 0;

	memcpy(mic, key->key_mic, 16);
	if (wpa_s->tptk_set) {
		memset(key->key_mic, 0, 16);
		wpa_eapol_key_mic(wpa_s->tptk.kck, ver, buf, len,
				  key->key_mic);
		if (memcmp(mic, key->key_mic, 16) != 0) {
			wpa_printf(MSG_WARNING, "WPA: Invalid EAPOL-Key MIC "
				   "when using TPTK - ignoring TPTK");
		} else {
			ok = 1;
			wpa_s->tptk_set = 0;
			wpa_s->ptk_set = 1;
			memcpy(&wpa_s->ptk, &wpa_s->tptk, sizeof(wpa_s->ptk));
		}
	}

	if (!ok && wpa_s->ptk_set) {
		memset(key->key_mic, 0, 16);
		wpa_eapol_key_mic(wpa_s->ptk.kck, ver, buf, len,
				  key->key_mic);
		if (memcmp(mic, key->key_mic, 16) != 0) {
			wpa_printf(MSG_WARNING, "WPA: Invalid EAPOL-Key MIC "
				   "- dropping packet");
			return -1;
		}
		ok = 1;
	}

	if (!ok) {
		wpa_printf(MSG_WARNING, "WPA: Could not verify EAPOL-Key MIC "
			   "- dropping packet");
		return -1;
	}

	memcpy(wpa_s->rx_replay_counter, key->replay_counter,
	       WPA_REPLAY_COUNTER_LEN);
	wpa_s->rx_replay_counter_set = 1;
	return 0;
}


/* Decrypt RSN EAPOL-Key key data (RC4 or AES-WRAP) */
static int wpa_supplicant_decrypt_key_data(struct wpa_supplicant *wpa_s,
					   struct wpa_eapol_key *key, int ver)
{
	int keydatalen = be_to_host16(key->key_data_length);

	wpa_hexdump(MSG_DEBUG, "RSN: encrypted key data",
		    (u8 *) (key + 1), keydatalen);
	if (!wpa_s->ptk_set) {
		wpa_printf(MSG_WARNING, "WPA: PTK not available, "
			   "cannot decrypt EAPOL-Key key data.");
		return -1;
	}

	/* Decrypt key data here so that this operation does not need
	 * to be implemented separately for each message type. */
	if (ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
		u8 ek[32];
		memcpy(ek, key->key_iv, 16);
		memcpy(ek + 16, wpa_s->ptk.kek, 16);
		rc4_skip(ek, 32, 256, (u8 *) (key + 1), keydatalen);
	} else if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		u8 *buf;
		if (keydatalen % 8) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported "
				   "AES-WRAP len %d", keydatalen);
			return -1;
		}
		keydatalen -= 8; /* AES-WRAP adds 8 bytes */
		buf = malloc(keydatalen);
		if (buf == NULL) {
			wpa_printf(MSG_WARNING, "WPA: No memory for "
				   "AES-UNWRAP buffer");
			return -1;
		}
		if (aes_unwrap(wpa_s->ptk.kek, keydatalen / 8,
			       (u8 *) (key + 1), buf)) {
			free(buf);
			wpa_printf(MSG_WARNING, "WPA: AES unwrap failed - "
				   "could not decrypt EAPOL-Key key data");
			return -1;
		}
		memcpy(key + 1, buf, keydatalen);
		free(buf);
		key->key_data_length = host_to_be16(keydatalen);
	}
	wpa_hexdump_key(MSG_DEBUG, "WPA: decrypted EAPOL-Key key data",
			(u8 *) (key + 1), keydatalen);
	return 0;
}


/**
 * wpa_sm_rx_eapol - process received WPA EAPOL frames
 * @wpa_s: pointer to wpa_supplicant data
 * @src_addr: source MAC address of the EAPOL packet
 * @buf: pointer to the beginning of the EAPOL data (EAPOL header)
 * @len: length of the EAPOL frame
 *
 * Returns: 1 = WPA EAPOL-Key processed, 0 = not a WPA EAPOL-Key, -1 failure
 */
int wpa_sm_rx_eapol(struct wpa_supplicant *wpa_s, unsigned char *src_addr,
		    unsigned char *buf, size_t len)
{
	size_t plen, data_len, extra_len;
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *key;
	int key_info, ver;

	hdr = (struct ieee802_1x_hdr *) buf;
	key = (struct wpa_eapol_key *) (hdr + 1);
	if (len < sizeof(*hdr) + sizeof(*key)) {
		wpa_printf(MSG_DEBUG, "WPA: EAPOL frame too short to be a WPA "
			   "EAPOL-Key (len %lu, expecting at least %lu)",
			   (unsigned long) len,
			   (unsigned long) sizeof(*hdr) + sizeof(*key));
		return 0;
	}
	plen = ntohs(hdr->length);
	data_len = plen + sizeof(*hdr);
	wpa_printf(MSG_DEBUG, "IEEE 802.1X RX: version=%d type=%d length=%lu",
		   hdr->version, hdr->type, (unsigned long) plen);

	wpa_drv_poll(wpa_s);

	if (hdr->version < EAPOL_VERSION) {
		/* TODO: backwards compatibility */
	}
	if (hdr->type != IEEE802_1X_TYPE_EAPOL_KEY) {
		wpa_printf(MSG_DEBUG, "WPA: EAPOL frame (type %u) discarded, "
			"not a Key frame", hdr->type);
		if (wpa_s->cur_pmksa) {
			wpa_printf(MSG_DEBUG, "WPA: Cancelling PMKSA caching "
				   "attempt - attempt full EAP "
				   "authentication");
			eapol_sm_notify_pmkid_attempt(wpa_s->eapol, 0);
		}
		return 0;
	}
	if (plen > len - sizeof(*hdr) || plen < sizeof(*key)) {
		wpa_printf(MSG_DEBUG, "WPA: EAPOL frame payload size %lu "
			   "invalid (frame size %lu)",
			   (unsigned long) plen, (unsigned long) len);
		return 0;
	}

	wpa_printf(MSG_DEBUG, "  EAPOL-Key type=%d", key->type);
	if (key->type != EAPOL_KEY_TYPE_WPA && key->type != EAPOL_KEY_TYPE_RSN)
	{
		wpa_printf(MSG_DEBUG, "WPA: EAPOL-Key type (%d) unknown, "
			   "discarded", key->type);
		return 0;
	}

	wpa_hexdump(MSG_MSGDUMP, "WPA: RX EAPOL-Key", buf, len);
	if (data_len < len) {
		wpa_printf(MSG_DEBUG, "WPA: ignoring %lu bytes after the IEEE "
			   "802.1X data", (unsigned long) len - data_len);
	}
	key_info = be_to_host16(key->key_info);
	ver = key_info & WPA_KEY_INFO_TYPE_MASK;
	if (ver != WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 &&
	    ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		wpa_printf(MSG_INFO, "WPA: Unsupported EAPOL-Key descriptor "
			   "version %d.", ver);
		return -1;
	}

	if (wpa_s->pairwise_cipher == WPA_CIPHER_CCMP &&
	    ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		wpa_printf(MSG_INFO, "WPA: CCMP is used, but EAPOL-Key "
			   "descriptor version (%d) is not 2.", ver);
		if (wpa_s->group_cipher != WPA_CIPHER_CCMP &&
		    !(key_info & WPA_KEY_INFO_KEY_TYPE)) {
			/* Earlier versions of IEEE 802.11i did not explicitly
			 * require version 2 descriptor for all EAPOL-Key
			 * packets, so allow group keys to use version 1 if
			 * CCMP is not used for them. */
			wpa_printf(MSG_INFO, "WPA: Backwards compatibility: "
				   "allow invalid version for non-CCMP group "
				   "keys");
		} else
			return -1;
	}

	if (wpa_s->rx_replay_counter_set &&
	    memcmp(key->replay_counter, wpa_s->rx_replay_counter,
		   WPA_REPLAY_COUNTER_LEN) <= 0) {
		wpa_printf(MSG_WARNING, "WPA: EAPOL-Key Replay Counter did not"
			   " increase - dropping packet");
		return -1;
	}

	if (!(key_info & WPA_KEY_INFO_ACK)) {
		wpa_printf(MSG_INFO, "WPA: No Ack bit in key_info");
		return -1;
	}

	if (key_info & WPA_KEY_INFO_REQUEST) {
		wpa_printf(MSG_INFO, "WPA: EAPOL-Key with Request bit - "
			   "dropped");
		return -1;
	}

	if ((key_info & WPA_KEY_INFO_MIC) &&
	    wpa_supplicant_verify_eapol_key_mic(wpa_s, key, ver, buf,
						data_len))
		return -1;

	extra_len = data_len - sizeof(*hdr) - sizeof(*key);

	if (be_to_host16(key->key_data_length) > extra_len) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Invalid EAPOL-Key frame - "
			"key_data overflow (%d > %lu)",
			be_to_host16(key->key_data_length),
			(unsigned long) extra_len);
		return -1;
	}

	if (wpa_s->proto == WPA_PROTO_RSN &&
	    (key_info & WPA_KEY_INFO_ENCR_KEY_DATA) &&
	    wpa_supplicant_decrypt_key_data(wpa_s, key, ver))
		return -1;

	if (key_info & WPA_KEY_INFO_KEY_TYPE) {
		if (key_info & WPA_KEY_INFO_KEY_INDEX_MASK) {
			wpa_printf(MSG_WARNING, "WPA: Ignored EAPOL-Key "
				   "(Pairwise) with non-zero key index");
			return -1;
		}
		if (key_info & WPA_KEY_INFO_MIC) {
			/* 3/4 4-Way Handshake */
			wpa_supplicant_process_3_of_4(wpa_s, src_addr, key,
						      extra_len, ver);
		} else {
			/* 1/4 4-Way Handshake */
			wpa_supplicant_process_1_of_4(wpa_s, src_addr, key,
						      ver);
		}
	} else {
		if (key_info & WPA_KEY_INFO_MIC) {
			/* 1/2 Group Key Handshake */
			wpa_supplicant_process_1_of_2(wpa_s, src_addr, key,
						      extra_len, ver);
		} else {
			wpa_printf(MSG_WARNING, "WPA: EAPOL-Key (Group) "
				   "without Mic bit - dropped");
		}
	}

	return 1;
}


static int wpa_cipher_bits(int cipher)
{
	switch (cipher) {
	case WPA_CIPHER_CCMP:
		return 128;
	case WPA_CIPHER_TKIP:
		return 256;
	case WPA_CIPHER_WEP104:
		return 104;
	case WPA_CIPHER_WEP40:
		return 40;
	default:
		return 0;
	}
}


static const u8 * wpa_key_mgmt_suite(struct wpa_supplicant *wpa_s)
{
	static const u8 *dummy = (u8 *) "\x00\x00\x00\x00";
	switch (wpa_s->key_mgmt) {
	case WPA_KEY_MGMT_IEEE8021X:
		return (wpa_s->proto == WPA_PROTO_RSN ?
			RSN_AUTH_KEY_MGMT_UNSPEC_802_1X :
			WPA_AUTH_KEY_MGMT_UNSPEC_802_1X);
	case WPA_KEY_MGMT_PSK:
		return (wpa_s->proto == WPA_PROTO_RSN ?
			RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X :
			WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X);
	case WPA_KEY_MGMT_WPA_NONE:
		return WPA_AUTH_KEY_MGMT_NONE;
	default:
		return dummy;
	}
}


static const u8 * wpa_cipher_suite(struct wpa_supplicant *wpa_s, int cipher)
{
	static const u8 *dummy = (u8 *) "\x00\x00\x00\x00";
	switch (cipher) {
	case WPA_CIPHER_CCMP:
		return (wpa_s->proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_CCMP : WPA_CIPHER_SUITE_CCMP);
	case WPA_CIPHER_TKIP:
		return (wpa_s->proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_TKIP : WPA_CIPHER_SUITE_TKIP);
	case WPA_CIPHER_WEP104:
		return (wpa_s->proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_WEP104 : WPA_CIPHER_SUITE_WEP104);
	case WPA_CIPHER_WEP40:
		return (wpa_s->proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_WEP40 : WPA_CIPHER_SUITE_WEP40);
	case WPA_CIPHER_NONE:
		return (wpa_s->proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_NONE : WPA_CIPHER_SUITE_NONE);
	default:
		return dummy;
	}
}


#define RSN_SUITE "%02x-%02x-%02x-%d"
#define RSN_SUITE_ARG(s) (s)[0], (s)[1], (s)[2], (s)[3]

/**
 * wpa_get_mib - dump text list of MIB entries
 * @wpa_s: pointer to wpa_supplicant data
 * @buf: buffer for the list
 * @buflen: length of the buffer
 *
 * Returns: number of bytes written to buffer
 */
int wpa_get_mib(struct wpa_supplicant *wpa_s, char *buf, size_t buflen)
{
	int len, i;
	char pmkid_txt[PMKID_LEN * 2 + 1];

	if (wpa_s->cur_pmksa) {
		char *pos = pmkid_txt;
		for (i = 0; i < PMKID_LEN; i++) {
			pos += sprintf(pos, "%02x",
				       wpa_s->cur_pmksa->pmkid[i]);
		}
	} else
		pmkid_txt[0] = '\0';

	len = snprintf(buf, buflen,
		       "dot11RSNAConfigVersion=%d\n"
		       "dot11RSNAConfigPairwiseKeysSupported=5\n"
		       "dot11RSNAConfigGroupCipherSize=%d\n"
		       "dot11RSNAConfigPMKLifetime=%d\n"
		       "dot11RSNAConfigPMKReauthThreshold=%d\n"
		       "dot11RSNAConfigNumberOfPTKSAReplayCounters=1\n"
		       "dot11RSNAConfigSATimeout=%d\n"
		       "dot11RSNAAuthenticationSuiteSelected=" RSN_SUITE "\n"
		       "dot11RSNAPairwiseCipherSelected=" RSN_SUITE "\n"
		       "dot11RSNAGroupCipherSelected=" RSN_SUITE "\n"
		       "dot11RSNAPMKIDUsed=%s\n"
		       "dot11RSNAAuthenticationSuiteRequested=" RSN_SUITE "\n"
		       "dot11RSNAPairwiseCipherRequested=" RSN_SUITE "\n"
		       "dot11RSNAGroupCipherRequested=" RSN_SUITE "\n"
		       "dot11RSNAConfigNumberOfGTKSAReplayCounters=0\n",
		       RSN_VERSION,
		       wpa_cipher_bits(wpa_s->group_cipher),
		       dot11RSNAConfigPMKLifetime,
		       dot11RSNAConfigPMKReauthThreshold,
		       dot11RSNAConfigSATimeout,
		       RSN_SUITE_ARG(wpa_key_mgmt_suite(wpa_s)),
		       RSN_SUITE_ARG(wpa_cipher_suite(wpa_s,
						      wpa_s->pairwise_cipher)),
		       RSN_SUITE_ARG(wpa_cipher_suite(wpa_s,
						      wpa_s->group_cipher)),
		       pmkid_txt,
		       RSN_SUITE_ARG(wpa_key_mgmt_suite(wpa_s)),
		       RSN_SUITE_ARG(wpa_cipher_suite(wpa_s,
						      wpa_s->pairwise_cipher)),
		       RSN_SUITE_ARG(wpa_cipher_suite(wpa_s,
						      wpa_s->group_cipher)));
	return len;
}
