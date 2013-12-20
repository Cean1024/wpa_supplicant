/*
 * WPA Supplicant / Network configuration structures
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

#ifndef CONFIG_SSID_H
#define CONFIG_SSID_H

#define WPA_CIPHER_NONE BIT(0)
#define WPA_CIPHER_WEP40 BIT(1)
#define WPA_CIPHER_WEP104 BIT(2)
#define WPA_CIPHER_TKIP BIT(3)
#define WPA_CIPHER_CCMP BIT(4)

#define WPA_KEY_MGMT_IEEE8021X BIT(0)
#define WPA_KEY_MGMT_PSK BIT(1)
#define WPA_KEY_MGMT_NONE BIT(2)
#define WPA_KEY_MGMT_IEEE8021X_NO_WPA BIT(3)
#define WPA_KEY_MGMT_WPA_NONE BIT(4)

#define WPA_PROTO_WPA BIT(0)
#define WPA_PROTO_RSN BIT(1)

#define WPA_AUTH_ALG_OPEN BIT(0)
#define WPA_AUTH_ALG_SHARED BIT(1)
#define WPA_AUTH_ALG_LEAP BIT(2)

#define MAX_SSID_LEN 32
#define PMK_LEN 32
#define EAP_PSK_LEN 16

/**
 * struct wpa_ssid - Network configuration data
 *
 * This structure includes all the configuration variables for a network. The
 * data is read from configuration file and each network block is mapped to a
 * struct wpa_ssid instance.
 */
struct wpa_ssid {
	/**
	 * next - Next network in global list
	 *
	 * This pointer can be used to iterate over all networks. The head of
	 * this list is stored in the ssid field of struct wpa_config.
	 */
	struct wpa_ssid *next;

	/**
	 * pnext - Next network in per-priority list
	 *
	 * This pointer can be used to iterate over all networks in the same
	 * priority class. The heads of these list are stored in the pssid
	 * fields of struct wpa_config.
	 */
	struct wpa_ssid *pnext;

	/**
	 * id - Unique id for the network
	 *
	 * This identifier is used as a unique identifier for each network
	 * block when using the control interface. Each network is allocated an
	 * id when it is being created, either when reading the configuration
	 * file or when a new network is added through the control interface.
	 */
	int id;

	int priority;
	u8 *ssid;
	size_t ssid_len;
	u8 bssid[ETH_ALEN];
	int bssid_set;
	u8 psk[PMK_LEN];
	int psk_set;
	char *passphrase;
	/* Bitfields of allowed Pairwise/Group Ciphers, WPA_CIPHER_* */
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int proto; /* Bitfield of allowed protocols (WPA_PROTO_*) */
	int auth_alg; /* Bitfield of allow authentication algorithms
		       * (WPA_AUTH_ALG_*) */
	int scan_ssid; /* scan this SSID with Probe Requests */
	u8 *identity; /* EAP Identity */
	size_t identity_len;
	u8 *anonymous_identity; /* Anonymous EAP Identity (for unencrypted use
				 * with EAP types that support different
				 * tunnelled identity, e.g., EAP-TTLS) */
	size_t anonymous_identity_len;
	u8 *eappsk;
	size_t eappsk_len;
	u8 *nai;
	size_t nai_len;
	u8 *server_nai;
	size_t server_nai_len;
	u8 *password;
	size_t password_len;
	u8 *ca_cert;
	u8 *client_cert;
	u8 *private_key;
	u8 *private_key_passwd;
	u8 *dh_file;
	u8 *subject_match;
	u8 *altsubject_match;
	u8 *ca_cert2;
	u8 *client_cert2;
	u8 *private_key2;
	u8 *private_key2_passwd;
	u8 *dh_file2;
	u8 *subject_match2;
	u8 *altsubject_match2;
	u8 *eap_methods; /* zero (EAP_TYPE_NONE) terminated list of allowed
			  * EAP methods or NULL = any */
	char *phase1;
	char *phase2;
	char *pcsc;
	char *pin;

	int engine;
	char *engine_id;
	char *key_id;

#define EAPOL_FLAG_REQUIRE_KEY_UNICAST BIT(0)
#define EAPOL_FLAG_REQUIRE_KEY_BROADCAST BIT(1)
	int eapol_flags; /* bit field of IEEE 802.1X/EAPOL options */

#define NUM_WEP_KEYS 4
#define MAX_WEP_KEY_LEN 16
	u8 wep_key[NUM_WEP_KEYS][MAX_WEP_KEY_LEN];
	size_t wep_key_len[NUM_WEP_KEYS];
	int wep_tx_keyidx;

	int proactive_key_caching;

	/* Per SSID variables that are not read from the configuration file */
	u8 *otp;
	size_t otp_len;
	int pending_req_identity, pending_req_password, pending_req_pin;
	int pending_req_new_password, pending_req_passphrase;
	char *pending_req_otp;
	size_t pending_req_otp_len;
	int leap, non_leap;

	unsigned int eap_workaround;

	char *pac_file;

	int mode;

	int mschapv2_retry;
	u8 *new_password;
	size_t new_password_len;

	int disabled;
};

int wpa_config_allowed_eap_method(struct wpa_ssid *ssid, int method);

#endif /* CONFIG_SSID_H */
