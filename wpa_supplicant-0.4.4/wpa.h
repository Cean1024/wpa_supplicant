/*
 * wpa_supplicant - WPA definitions
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

#ifndef WPA_H
#define WPA_H

#define BIT(n) (1 << (n))

struct ieee802_1x_hdr {
	u8 version;
	u8 type;
	u16 length;
	/* followed by length octets of data */
} __attribute__ ((packed));

#define EAPOL_VERSION 2

enum { IEEE802_1X_TYPE_EAP_PACKET = 0,
       IEEE802_1X_TYPE_EAPOL_START = 1,
       IEEE802_1X_TYPE_EAPOL_LOGOFF = 2,
       IEEE802_1X_TYPE_EAPOL_KEY = 3,
       IEEE802_1X_TYPE_EAPOL_ENCAPSULATED_ASF_ALERT = 4
};

enum { EAPOL_KEY_TYPE_RC4 = 1, EAPOL_KEY_TYPE_RSN = 2,
       EAPOL_KEY_TYPE_WPA = 254 };


#define IEEE8021X_REPLAY_COUNTER_LEN 8
#define IEEE8021X_KEY_SIGN_LEN 16
#define IEEE8021X_KEY_IV_LEN 16

#define IEEE8021X_KEY_INDEX_FLAG 0x80
#define IEEE8021X_KEY_INDEX_MASK 0x03

struct ieee802_1x_eapol_key {
	u8 type;
	/* Note: key_length is unaligned */
	u8 key_length[2];
	/* does not repeat within the life of the keying material used to
	 * encrypt the Key field; 64-bit NTP timestamp MAY be used here */
	u8 replay_counter[IEEE8021X_REPLAY_COUNTER_LEN];
	u8 key_iv[IEEE8021X_KEY_IV_LEN]; /* cryptographically random number */
	u8 key_index; /* key flag in the most significant bit:
		       * 0 = broadcast (default key),
		       * 1 = unicast (key mapping key); key index is in the
		       * 7 least significant bits */
	/* HMAC-MD5 message integrity check computed with MS-MPPE-Send-Key as
	 * the key */
	u8 key_signature[IEEE8021X_KEY_SIGN_LEN];

	/* followed by key: if packet body length = 44 + key length, then the
	 * key field (of key_length bytes) contains the key in encrypted form;
	 * if packet body length = 44, key field is absent and key_length
	 * represents the number of least significant octets from
	 * MS-MPPE-Send-Key attribute to be used as the keying material;
	 * RC4 key used in encryption = Key-IV + MS-MPPE-Recv-Key */
} __attribute__ ((packed));


#define WPA_NONCE_LEN 32
#define WPA_REPLAY_COUNTER_LEN 8

struct wpa_eapol_key {
	u8 type;
	/* Note: key_info, key_length, and key_data_length are unaligned */
	u8 key_info[2];
	u8 key_length[2];
	u8 replay_counter[WPA_REPLAY_COUNTER_LEN];
	u8 key_nonce[WPA_NONCE_LEN];
	u8 key_iv[16];
	u8 key_rsc[8];
	u8 key_id[8]; /* Reserved in IEEE 802.11i/RSN */
	u8 key_mic[16];
	u8 key_data_length[2];
	/* followed by key_data_length bytes of key_data */
} __attribute__ ((packed));

#define WPA_KEY_INFO_TYPE_MASK (BIT(0) | BIT(1) | BIT(2))
#define WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 BIT(0)
#define WPA_KEY_INFO_TYPE_HMAC_SHA1_AES BIT(1)
#define WPA_KEY_INFO_KEY_TYPE BIT(3) /* 1 = Pairwise, 0 = Group key */
/* bit4..5 is used in WPA, but is reserved in IEEE 802.11i/RSN */
#define WPA_KEY_INFO_KEY_INDEX_MASK (BIT(4) | BIT(5))
#define WPA_KEY_INFO_KEY_INDEX_SHIFT 4
#define WPA_KEY_INFO_INSTALL BIT(6) /* pairwise */
#define WPA_KEY_INFO_TXRX BIT(6) /* group */
#define WPA_KEY_INFO_ACK BIT(7)
#define WPA_KEY_INFO_MIC BIT(8)
#define WPA_KEY_INFO_SECURE BIT(9)
#define WPA_KEY_INFO_ERROR BIT(10)
#define WPA_KEY_INFO_REQUEST BIT(11)
#define WPA_KEY_INFO_ENCR_KEY_DATA BIT(12) /* IEEE 802.11i/RSN only */

#define WPA_CAPABILITY_PREAUTH BIT(0)

#define GENERIC_INFO_ELEM 0xdd
#define RSN_INFO_ELEM 0x30

enum {
	REASON_UNSPECIFIED = 1,
	REASON_DEAUTH_LEAVING = 3,
	REASON_INVALID_IE = 13,
	REASON_MICHAEL_MIC_FAILURE = 14,
	REASON_4WAY_HANDSHAKE_TIMEOUT = 15,
	REASON_GROUP_KEY_UPDATE_TIMEOUT = 16,
	REASON_IE_IN_4WAY_DIFFERS = 17,
	REASON_GROUP_CIPHER_NOT_VALID = 18,
	REASON_PAIRWISE_CIPHER_NOT_VALID = 19,
	REASON_AKMP_NOT_VALID = 20,
	REASON_UNSUPPORTED_RSN_IE_VERSION = 21,
	REASON_INVALID_RSN_IE_CAPAB = 22,
	REASON_IEEE_802_1X_AUTH_FAILED = 23,
	REASON_CIPHER_SUITE_REJECTED = 24
};

#define PMKID_LEN 16


struct wpa_sm;
struct wpa_ssid;
struct eapol_sm;

struct wpa_sm * wpa_sm_init(void *ctx);
void wpa_sm_deinit(struct wpa_sm *sm);
void wpa_sm_notify_assoc(struct wpa_sm *sm, const u8 *bssid);
void wpa_sm_notify_disassoc(struct wpa_sm *sm);
void wpa_sm_set_pmk(struct wpa_sm *sm, const u8 *pmk, size_t pmk_len);
void wpa_sm_set_pmk_from_pmksa(struct wpa_sm *sm);
void wpa_sm_set_fast_reauth(struct wpa_sm *sm, int fast_reauth);
void wpa_sm_set_scard_ctx(struct wpa_sm *sm, void *scard_ctx);
void wpa_sm_set_config(struct wpa_sm *sm, struct wpa_ssid *config);
void wpa_sm_set_own_addr(struct wpa_sm *sm, const u8 *addr);
void wpa_sm_set_ifname(struct wpa_sm *sm, const char *ifname);
void wpa_sm_set_eapol(struct wpa_sm *sm, struct eapol_sm *eapol);
int wpa_sm_set_assoc_wpa_ie(struct wpa_sm *sm, const u8 *ie, size_t len);
int wpa_sm_set_assoc_wpa_ie_default(struct wpa_sm *sm, u8 *wpa_ie,
				    size_t *wpa_ie_len);
int wpa_sm_set_ap_wpa_ie(struct wpa_sm *sm, const u8 *ie, size_t len);
int wpa_sm_set_ap_rsn_ie(struct wpa_sm *sm, const u8 *ie, size_t len);
int wpa_sm_get_mib(struct wpa_sm *sm, char *buf, size_t buflen);

enum wpa_sm_conf_params {
	RSNA_PMK_LIFETIME /* dot11RSNAConfigPMKLifetime */,
	RSNA_PMK_REAUTH_THRESHOLD /* dot11RSNAConfigPMKReauthThreshold */,
	RSNA_SA_TIMEOUT /* dot11RSNAConfigSATimeout */,
	WPA_PARAM_PROTO,
	WPA_PARAM_PAIRWISE,
	WPA_PARAM_GROUP,
	WPA_PARAM_KEY_MGMT
};

int wpa_sm_set_param(struct wpa_sm *sm, enum wpa_sm_conf_params param,
		     unsigned int value);
unsigned int wpa_sm_get_param(struct wpa_sm *sm,
			      enum wpa_sm_conf_params param);

int wpa_sm_get_status(struct wpa_sm *sm, char *buf, size_t buflen,
		      int verbose);

void wpa_sm_key_request(struct wpa_sm *sm, int error, int pairwise);


struct wpa_ie_data {
	int proto;
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int capabilities;
	int num_pmkid;
	const u8 *pmkid;
};

int wpa_parse_wpa_ie(const u8 *wpa_ie, size_t wpa_ie_len,
		     struct wpa_ie_data *data);

int wpa_sm_rx_eapol(struct wpa_sm *sm, const unsigned char *src_addr,
		    unsigned char *buf, size_t len);
int wpa_sm_parse_own_wpa_ie(struct wpa_sm *sm, struct wpa_ie_data *data);

#endif /* WPA_H */
