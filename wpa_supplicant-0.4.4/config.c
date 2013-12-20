/*
 * WPA Supplicant / Configuration file parser
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
#include <string.h>

#include "common.h"
#include "wpa.h"
#include "config.h"
#include "sha1.h"
#include "wpa_supplicant.h"
#include "eapol_sm.h"
#include "eap.h"
#include "config.h"


struct parse_data {
	char *name;
	int (*parser)(struct parse_data *data, int line, const char *value);
	void *param1, *param2, *param3, *param4;
	struct wpa_ssid *ssid;
	int key_data;
};


static char * wpa_config_get_line(char *s, int size, FILE *stream, int *line)
{
	char *pos, *end, *sstart;

	while (fgets(s, size, stream)) {
		(*line)++;
		s[size - 1] = '\0';
		pos = s;

		while (*pos == ' ' || *pos == '\t' || *pos == '\r')
			pos++;
		if (*pos == '#' || *pos == '\n' || *pos == '\0' ||
		    *pos == '\r')
			continue;

		/* Remove # comments unless they are within a double quoted
		 * string. Remove trailing white space. */
		sstart = strchr(pos, '"');
		if (sstart)
			sstart = strrchr(sstart + 1, '"');
		if (!sstart)
			sstart = pos;
		end = strchr(sstart, '#');
		if (end)
			*end-- = '\0';
		else
			end = pos + strlen(pos) - 1;
		while (end > pos &&
		       (*end == '\n' || *end == ' ' || *end == '\t' ||
			*end == '\r')) {
			*end-- = '\0';
		}
		if (*pos == '\0')
			continue;

		return pos;
	}

	return NULL;
}


static char * wpa_config_parse_string(const char *value, size_t *len)
{
	if (*value == '"') {
		char *pos;
		value++;
		pos = strchr(value, '"');
		if (pos == NULL || pos[1] != '\0')
			return NULL;
		*pos = '\0';
		*len = strlen(value);
		return strdup(value);
	} else {
		u8 *str;
		size_t hlen = strlen(value);
		if (hlen % 1)
			return NULL;
		*len = hlen / 2;
		str = malloc(*len);
		if (str == NULL)
			return NULL;
		if (hexstr2bin(value, str, *len)) {
			free(str);
			return NULL;
		}
		return (char *) str;
	}
}


static int wpa_config_parse_str(struct parse_data *data,
				int line, const char *value)
{
	size_t res_len, *dst_len;
	char **dst;

	dst = (char **) (((u8 *) data->ssid) + (long) data->param1);
	dst_len = (size_t *) (((u8 *) data->ssid) + (long) data->param2);

	free(*dst);
	*dst = wpa_config_parse_string(value, &res_len);
	if (*dst == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse %s '%s'.",
			   line, data->name, value);
		return -1;
	}
	if (data->param2)
		*dst_len = res_len;

	if (data->key_data) {
		wpa_hexdump_ascii_key(MSG_MSGDUMP, data->name,
				      (u8 *) *dst, res_len);
	} else {
		wpa_hexdump_ascii(MSG_MSGDUMP, data->name,
				  (u8 *) *dst, res_len);
	}

	if (data->param3 && res_len < (size_t) data->param3) {
		wpa_printf(MSG_ERROR, "Line %d: too short %s (len=%lu "
			   "min_len=%ld)", line, data->name,
			   (unsigned long) res_len, (long) data->param3);
		free(*dst);
		*dst = NULL;
		return -1;
	}

	if (data->param4 && res_len > (size_t) data->param4) {
		wpa_printf(MSG_ERROR, "Line %d: too long %s (len=%lu "
			   "max_len=%ld)", line, data->name,
			   (unsigned long) res_len, (long) data->param4);
		free(*dst);
		*dst = NULL;
		return -1;
	}

	return 0;
}


static int wpa_config_parse_int(struct parse_data *data,
				int line, const char *value)
{
	int *dst;

	dst = (int *) (((u8 *) data->ssid) + (long) data->param1);
	*dst = atoi(value);
	wpa_printf(MSG_MSGDUMP, "%s=%d (0x%x)", data->name, *dst, *dst);

	if (data->param3 && *dst < (long) data->param3) {
		wpa_printf(MSG_ERROR, "Line %d: too small %s (value=%d "
			   "min_value=%ld)", line, data->name, *dst,
			   (long) data->param3);
		*dst = (long) data->param3;
		return -1;
	}

	if (data->param4 && *dst > (long) data->param4) {
		wpa_printf(MSG_ERROR, "Line %d: too large %s (value=%d "
			   "max_value=%ld)", line, data->name, *dst,
			   (long) data->param4);
		*dst = (long) data->param4;
		return -1;
	}

	return 0;
}


static int wpa_config_parse_bssid(struct parse_data *data, int line,
				  const char *value)
{
	if (hwaddr_aton(value, data->ssid->bssid)) {
		wpa_printf(MSG_ERROR, "Line %d: Invalid BSSID '%s'.",
			   line, value);
		return -1;
	}
	data->ssid->bssid_set = 1;
	wpa_hexdump(MSG_MSGDUMP, "BSSID", data->ssid->bssid, ETH_ALEN);
	return 0;
}


static int wpa_config_parse_psk(struct parse_data *data, int line,
				const char *value)
{
	if (*value == '"') {
		char *pos;
		size_t len;

		value++;
		pos = strrchr(value, '"');
		if (pos)
			*pos = '\0';
		len = strlen(value);
		if (len < 8 || len > 63) {
			wpa_printf(MSG_ERROR, "Line %d: Invalid passphrase "
				   "length %lu (expected: 8..63) '%s'.",
				   line, (unsigned long) len, value);
			return -1;
		}
		wpa_hexdump_ascii_key(MSG_MSGDUMP, "PSK (ASCII passphrase)",
				      (u8 *) value, len);
		data->ssid->passphrase = strdup(value);
		return data->ssid->passphrase == NULL ? -1 : 0;
	}

	if (hexstr2bin(value, data->ssid->psk, PMK_LEN) ||
	    value[PMK_LEN * 2] != '\0') {
		wpa_printf(MSG_ERROR, "Line %d: Invalid PSK '%s'.",
			   line, value);
		return -1;
	}
	data->ssid->psk_set = 1;
	wpa_hexdump_key(MSG_MSGDUMP, "PSK", data->ssid->psk, PMK_LEN);
	return 0;
}


static int wpa_config_parse_proto(struct parse_data *data, int line,
				  const char *value)
{
	int val = 0, last, errors = 0;
	char *start, *end, *buf;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (strcmp(start, "WPA") == 0)
			val |= WPA_PROTO_WPA;
		else if (strcmp(start, "RSN") == 0 ||
			 strcmp(start, "WPA2") == 0)
			val |= WPA_PROTO_RSN;
		else {
			wpa_printf(MSG_ERROR, "Line %d: invalid proto '%s'",
				   line, start);
			errors++;
		}

		if (last)
			break;
		start = end + 1;
	}
	free(buf);

	if (val == 0) {
		wpa_printf(MSG_ERROR,
			   "Line %d: no proto values configured.", line);
		errors++;
	}

	wpa_printf(MSG_MSGDUMP, "proto: 0x%x", val);
	data->ssid->proto = val;
	return errors ? -1 : 0;
}


static int wpa_config_parse_key_mgmt(struct parse_data *data, int line,
				     const char *value)
{
	int val = 0, last, errors = 0;
	char *start, *end, *buf;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (strcmp(start, "WPA-PSK") == 0)
			val |= WPA_KEY_MGMT_PSK;
		else if (strcmp(start, "WPA-EAP") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X;
		else if (strcmp(start, "IEEE8021X") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X_NO_WPA;
		else if (strcmp(start, "NONE") == 0)
			val |= WPA_KEY_MGMT_NONE;
		else if (strcmp(start, "WPA-NONE") == 0)
			val |= WPA_KEY_MGMT_WPA_NONE;
		else {
			wpa_printf(MSG_ERROR, "Line %d: invalid key_mgmt '%s'",
				   line, start);
			errors++;
		}

		if (last)
			break;
		start = end + 1;
	}
	free(buf);

	if (val == 0) {
		wpa_printf(MSG_ERROR,
			   "Line %d: no key_mgmt values configured.", line);
		errors++;
	}

	wpa_printf(MSG_MSGDUMP, "key_mgmt: 0x%x", val);
	data->ssid->key_mgmt = val;
	return errors ? -1 : 0;
}


static int wpa_config_parse_cipher(int line, const char *value)
{
	int val = 0, last;
	char *start, *end, *buf;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (strcmp(start, "CCMP") == 0)
			val |= WPA_CIPHER_CCMP;
		else if (strcmp(start, "TKIP") == 0)
			val |= WPA_CIPHER_TKIP;
		else if (strcmp(start, "WEP104") == 0)
			val |= WPA_CIPHER_WEP104;
		else if (strcmp(start, "WEP40") == 0)
			val |= WPA_CIPHER_WEP40;
		else if (strcmp(start, "NONE") == 0)
			val |= WPA_CIPHER_NONE;
		else {
			wpa_printf(MSG_ERROR, "Line %d: invalid cipher '%s'.",
				   line, start);
			free(buf);
			return -1;
		}

		if (last)
			break;
		start = end + 1;
	}
	free(buf);

	if (val == 0) {
		wpa_printf(MSG_ERROR, "Line %d: no cipher values configured.",
			   line);
		return -1;
	}
	return val;
}


static int wpa_config_parse_pairwise(struct parse_data *data, int line,
				     const char *value)
{
	int val;
	val = wpa_config_parse_cipher(line, value);
	if (val == -1)
		return -1;
	if (val & ~(WPA_CIPHER_CCMP | WPA_CIPHER_TKIP | WPA_CIPHER_NONE)) {
		wpa_printf(MSG_ERROR, "Line %d: not allowed pairwise cipher "
			   "(0x%x).", line, val);
		return -1;
	}

	wpa_printf(MSG_MSGDUMP, "pairwise: 0x%x", val);
	data->ssid->pairwise_cipher = val;
	return 0;
}


static int wpa_config_parse_group(struct parse_data *data, int line,
				  const char *value)
{
	int val;
	val = wpa_config_parse_cipher(line, value);
	if (val == -1)
		return -1;
	if (val & ~(WPA_CIPHER_CCMP | WPA_CIPHER_TKIP | WPA_CIPHER_WEP104 |
		    WPA_CIPHER_WEP40)) {
		wpa_printf(MSG_ERROR, "Line %d: not allowed group cipher "
			   "(0x%x).", line, val);
		return -1;
	}

	wpa_printf(MSG_MSGDUMP, "group: 0x%x", val);
	data->ssid->group_cipher = val;
	return 0;
}


static int wpa_config_parse_auth_alg(struct parse_data *data, int line,
				     const char *value)
{
	int val = 0, last, errors = 0;
	char *start, *end, *buf;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (strcmp(start, "OPEN") == 0)
			val |= WPA_AUTH_ALG_OPEN;
		else if (strcmp(start, "SHARED") == 0)
			val |= WPA_AUTH_ALG_SHARED;
		else if (strcmp(start, "LEAP") == 0)
			val |= WPA_AUTH_ALG_LEAP;
		else {
			wpa_printf(MSG_ERROR, "Line %d: invalid auth_alg '%s'",
				   line, start);
			errors++;
		}

		if (last)
			break;
		start = end + 1;
	}
	free(buf);

	if (val == 0) {
		wpa_printf(MSG_ERROR,
			   "Line %d: no auth_alg values configured.", line);
		errors++;
	}

	wpa_printf(MSG_MSGDUMP, "auth_alg: 0x%x", val);
	data->ssid->auth_alg = val;
	return errors ? -1 : 0;
}


static int wpa_config_parse_eap(struct parse_data *data, int line,
				const char *value)
{
	int last, errors = 0;
	char *start, *end, *buf;
	u8 *methods = NULL, *tmp;
	size_t num_methods = 0;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		tmp = methods;
		methods = realloc(methods, num_methods + 1);
		if (methods == NULL) {
			free(tmp);
			return -1;
		}
		methods[num_methods] = eap_get_type(start);
		if (methods[num_methods] == EAP_TYPE_NONE) {
			wpa_printf(MSG_ERROR, "Line %d: unknown EAP method "
				   "'%s'", line, start);
			wpa_printf(MSG_ERROR, "You may need to add support for"
				   " this EAP method during wpa_supplicant\n"
				   "build time configuration.\n"
				   "See README for more information.");
			errors++;
		} else if (methods[num_methods] == EAP_TYPE_LEAP)
			data->ssid->leap++;
		else
			data->ssid->non_leap++;
		num_methods++;
		if (last)
			break;
		start = end + 1;
	}
	free(buf);

	tmp = methods;
	methods = realloc(methods, num_methods + 1);
	if (methods == NULL) {
		free(tmp);
		return -1;
	}
	methods[num_methods] = EAP_TYPE_NONE;
	num_methods++;

	wpa_hexdump(MSG_MSGDUMP, "eap methods", methods, num_methods);
	data->ssid->eap_methods = methods;
	return errors ? -1 : 0;
}


static int wpa_config_parse_wep_key(u8 *key, size_t *len, int line,
				    const char *value, int idx)
{
	char *buf, title[20];

	buf = wpa_config_parse_string(value, len);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: Invalid WEP key %d '%s'.",
			   line, idx, value);
		return -1;
	}
	if (*len > MAX_WEP_KEY_LEN) {
		wpa_printf(MSG_ERROR, "Line %d: Too long WEP key %d '%s'.",
			   line, idx, value);
		free(buf);
		return -1;
	}
	memcpy(key, buf, *len);
	free(buf);
	snprintf(title, sizeof(title), "wep_key%d", idx);
	wpa_hexdump_key(MSG_MSGDUMP, title, key, *len);
	return 0;
}


static int wpa_config_parse_wep_key0(struct parse_data *data, int line,
				     const char *value)
{
	return wpa_config_parse_wep_key(data->ssid->wep_key[0],
					&data->ssid->wep_key_len[0], line,
					value, 0);
}


static int wpa_config_parse_wep_key1(struct parse_data *data, int line,
				     const char *value)
{
	return wpa_config_parse_wep_key(data->ssid->wep_key[1],
					&data->ssid->wep_key_len[1], line,
					value, 1);
}


static int wpa_config_parse_wep_key2(struct parse_data *data, int line,
				     const char *value)
{
	return wpa_config_parse_wep_key(data->ssid->wep_key[2],
					&data->ssid->wep_key_len[2], line,
					value, 2);
}


static int wpa_config_parse_wep_key3(struct parse_data *data, int line,
				     const char *value)
{
	return wpa_config_parse_wep_key(data->ssid->wep_key[3],
					&data->ssid->wep_key_len[3], line,
					value, 3);
}


#define OFFSET(v) ((void *) &((struct wpa_ssid *) 0)->v)
#define STR(f) .name = #f, .parser = wpa_config_parse_str, .param1 = OFFSET(f)
#define STR_LEN(f) STR(f), .param2 = OFFSET(f ## _len)
#define STR_RANGE(f, min, max) STR_LEN(f), .param3 = (void *) (min), \
	.param4 = (void *) (max)
#define INT(f) .name = #f, .parser = wpa_config_parse_int, \
	.param1 = OFFSET(f), .param2 = (void *) 0
#define INT_RANGE(f, min, max) INT(f), .param3 = (void *) (min), \
	.param4 = (void *) (max)
#define FUNC(f) .name = #f, .parser = wpa_config_parse_ ## f

static struct parse_data ssid_fields[] = {
	{ STR_RANGE(ssid, 0, MAX_SSID_LEN) },
	{ INT_RANGE(scan_ssid, 0, 1) },
	{ FUNC(bssid) },
	{ FUNC(psk), .key_data = 1 },
	{ FUNC(proto) },
	{ FUNC(key_mgmt) },
	{ FUNC(pairwise) },
	{ FUNC(group) },
	{ FUNC(auth_alg) },
	{ FUNC(eap) },
	{ STR_LEN(identity) },
	{ STR_LEN(anonymous_identity) },
	{ STR_RANGE(eappsk, EAP_PSK_LEN, EAP_PSK_LEN), .key_data = 1 },
	{ STR_LEN(nai) },
	{ STR_LEN(server_nai) },
	{ STR_LEN(password), .key_data = 1 },
	{ STR(ca_cert) },
	{ STR(client_cert) },
	{ STR(private_key) },
	{ STR(private_key_passwd), .key_data = 1 },
	{ STR(dh_file) },
	{ STR(subject_match) },
	{ STR(altsubject_match) },
	{ STR(ca_cert2) },
	{ STR(client_cert2) },
	{ STR(private_key2) },
	{ STR(private_key2_passwd), .key_data = 1 },
	{ STR(dh_file2) },
	{ STR(subject_match2) },
	{ STR(altsubject_match2) },
	{ STR(phase1) },
	{ STR(phase2) },
	{ STR(pcsc) },
	{ STR(pin), .key_data = 1 },
	{ STR(engine_id) },
	{ STR(key_id) },
	{ INT(engine) },
	{ INT(eapol_flags) },
	{ FUNC(wep_key0), .key_data = 1 },
	{ FUNC(wep_key1), .key_data = 1 },
	{ FUNC(wep_key2), .key_data = 1 },
	{ FUNC(wep_key3), .key_data = 1 },
	{ INT(wep_tx_keyidx) },
	{ INT(priority) },
	{ INT(eap_workaround) },
	{ STR(pac_file) },
	{ INT_RANGE(mode, 0, 1) },
	{ INT_RANGE(proactive_key_caching, 0, 1) },
	{ INT(disabled) },
};

#undef OFFSET
#undef STR
#undef STR_LEN
#undef STR_RANGE
#undef INT
#undef INT_RANGE
#undef FUNC
#define NUM_SSID_FIELDS (sizeof(ssid_fields) / sizeof(ssid_fields[0]))


static struct wpa_ssid * wpa_config_read_network(FILE *f, int *line, int id)
{
	struct wpa_ssid *ssid;
	int errors = 0, end = 0;
	char buf[256], *pos, *pos2;

	wpa_printf(MSG_MSGDUMP, "Line: %d - start of a new network block",
		   *line);
	ssid = (struct wpa_ssid *) malloc(sizeof(*ssid));
	if (ssid == NULL)
		return NULL;
	memset(ssid, 0, sizeof(*ssid));
	ssid->id = id;

	ssid->proto = WPA_PROTO_WPA | WPA_PROTO_RSN;
	ssid->pairwise_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
	ssid->group_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP |
		WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40;
	ssid->key_mgmt = WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_IEEE8021X;
	ssid->eapol_flags = EAPOL_FLAG_REQUIRE_KEY_UNICAST |
		EAPOL_FLAG_REQUIRE_KEY_BROADCAST;
	ssid->eap_workaround = (unsigned int) -1;

	while ((pos = wpa_config_get_line(buf, sizeof(buf), f, line))) {
		if (strcmp(pos, "}") == 0) {
			end = 1;
			break;
		}

		pos2 = strchr(pos, '=');
		if (pos2 == NULL) {
			wpa_printf(MSG_ERROR, "Line %d: Invalid SSID line "
				   "'%s'.", *line, pos);
			errors++;
			continue;
		}

		*pos2++ = '\0';
		if (*pos2 == '"') {
			if (strchr(pos2 + 1, '"') == NULL) {
				wpa_printf(MSG_ERROR, "Line %d: invalid "
					   "quotation '%s'.", *line, pos2);
				errors++;
				continue;
			}
		}

		if (wpa_config_set(ssid, pos, pos2, *line) < 0)
			errors++;
	}

	if (!end) {
		wpa_printf(MSG_ERROR, "Line %d: network block was not "
			   "terminated properly.", *line);
		errors++;
	}

	if (ssid->passphrase) {
		if (ssid->psk_set) {
			wpa_printf(MSG_ERROR, "Line %d: both PSK and "
				   "passphrase configured.", *line);
			errors++;
		}
		wpa_config_update_psk(ssid);
	}

	if ((ssid->key_mgmt & WPA_KEY_MGMT_PSK) && !ssid->psk_set) {
		wpa_printf(MSG_ERROR, "Line %d: WPA-PSK accepted for key "
			   "management, but no PSK configured.", *line);
		errors++;
	}

	if ((ssid->group_cipher & WPA_CIPHER_CCMP) &&
	    !(ssid->pairwise_cipher & WPA_CIPHER_CCMP)) {
		/* Group cipher cannot be stronger than the pairwise cipher. */
		wpa_printf(MSG_DEBUG, "Line %d: removed CCMP from group cipher"
			   " list since it was not allowed for pairwise "
			   "cipher", *line);
		ssid->group_cipher &= ~WPA_CIPHER_CCMP;
	}

	if (errors) {
		free(ssid);
		ssid = NULL;
	}

	return ssid;
}


static int wpa_config_add_prio_network(struct wpa_config *config,
				       struct wpa_ssid *ssid)
{
	int prio;
	struct wpa_ssid *prev, **nlist;

	for (prio = 0; prio < config->num_prio; prio++) {
		prev = config->pssid[prio];
		if (prev->priority == ssid->priority) {
			while (prev->pnext)
				prev = prev->pnext;
			prev->pnext = ssid;
			return 0;
		}
	}

	/* First network for this priority - add new priority list */
	nlist = realloc(config->pssid,
			(config->num_prio + 1) * sizeof(struct wpa_ssid *));
	if (nlist == NULL)
		return -1;

	for (prio = 0; prio < config->num_prio; prio++) {
		if (nlist[prio]->priority < ssid->priority)
			break;
	}

	memmove(&nlist[prio + 1], &nlist[prio],
		(config->num_prio - prio) * sizeof(struct wpa_ssid *));

	nlist[prio] = ssid;
	config->num_prio++;
	config->pssid = nlist;

	return 0;
}


/**
 * wpa_config_update_prio_list - Update network priority list
 * @config: Configuration data from wpa_config_read()
 * Returns: 0 on success, -1 on failure
 *
 * This function is called to update the priority list of networks in the
 * configuration when a network is being added or removed. This is also called
 * if a priority for a network is changed.
 */
static int wpa_config_update_prio_list(struct wpa_config *config)
{
	struct wpa_ssid *ssid;
	int ret = 0;

	free(config->pssid);
	config->pssid = NULL;
	config->num_prio = 0;

	ssid = config->ssid;
	while (ssid) {
		ssid->pnext = NULL;
		if (wpa_config_add_prio_network(config, ssid) < 0)
			ret = -1;
		ssid = ssid->next;
	}

	return ret;
}


/**
 * wpa_config_read - Read and parse a configuration file
 * @config_file: Path and file name for the configuration file
 * Returns: Pointer to allocated configuration data or %NULL on failure
 *
 * This function reads a configuration file, parses its contents, and allocates
 * data structures needed for storing configuration information. The allocated
 * data can be freed with wpa_config_free().
 */
struct wpa_config * wpa_config_read(const char *config_file)
{
	FILE *f;
	char buf[256], *pos;
	int errors = 0, line = 0;
	struct wpa_ssid *ssid, *tail = NULL, *head = NULL;
	struct wpa_config *config;
	int id = 0, prio;

	config = malloc(sizeof(*config));
	if (config == NULL)
		return NULL;
	memset(config, 0, sizeof(*config));
	config->eapol_version = 1;
	config->ap_scan = 1;
	config->fast_reauth = 1;
	wpa_printf(MSG_DEBUG, "Reading configuration file '%s'",
		   config_file);
	f = fopen(config_file, "r");
	if (f == NULL) {
		free(config);
		return NULL;
	}

	while ((pos = wpa_config_get_line(buf, sizeof(buf), f, &line))) {
		if (strcmp(pos, "network={") == 0) {
			ssid = wpa_config_read_network(f, &line, id++);
			if (ssid == NULL) {
				wpa_printf(MSG_ERROR, "Line %d: failed to "
					   "parse network block.", line);
				errors++;
				continue;
			}
			if (head == NULL) {
				head = tail = ssid;
			} else {
				tail->next = ssid;
				tail = ssid;
			}
			if (wpa_config_add_prio_network(config, ssid)) {
				wpa_printf(MSG_ERROR, "Line %d: failed to add "
					   "network block to priority list.",
					   line);
				errors++;
				continue;
			}
#ifdef CONFIG_CTRL_IFACE
		} else if (strncmp(pos, "ctrl_interface=", 15) == 0) {
			free(config->ctrl_interface);
			config->ctrl_interface = strdup(pos + 15);
			wpa_printf(MSG_DEBUG, "ctrl_interface='%s'",
				   config->ctrl_interface);
#ifndef CONFIG_CTRL_IFACE_UDP
		} else if (strncmp(pos, "ctrl_interface_group=", 21) == 0) {
			struct group *grp;
			char *endp;
			const char *group = pos + 21;

			grp = getgrnam(group);
			if (grp) {
				config->ctrl_interface_gid = grp->gr_gid;
				config->ctrl_interface_gid_set = 1;
				wpa_printf(MSG_DEBUG, "ctrl_interface_group=%d"
					   " (from group name '%s')",
					   (int) config->ctrl_interface_gid, 
					   group);
				continue;
			}

			/* Group name not found - try to parse this as gid */
			config->ctrl_interface_gid = strtol(group, &endp, 10);
			if (*group == '\0' || *endp != '\0') {
				wpa_printf(MSG_DEBUG, "Line %d: Invalid group "
					   "'%s'", line, group);
				errors++;
				continue;
			}
			config->ctrl_interface_gid_set = 1;
			wpa_printf(MSG_DEBUG, "ctrl_interface_group=%d",
				   (int) config->ctrl_interface_gid);
#endif /* CONFIG_CTRL_IFACE_UDP */
#endif /* CONFIG_CTRL_IFACE */
		} else if (strncmp(pos, "eapol_version=", 14) == 0) {
			config->eapol_version = atoi(pos + 14);
			if (config->eapol_version < 1 ||
			    config->eapol_version > 2) {
				wpa_printf(MSG_ERROR, "Line %d: Invalid EAPOL "
					   "version (%d): '%s'.",
					   line, config->eapol_version, pos);
				errors++;
				continue;
			}
			wpa_printf(MSG_DEBUG, "eapol_version=%d",
				   config->eapol_version);
		} else if (strncmp(pos, "ap_scan=", 8) == 0) {
			config->ap_scan = atoi(pos + 8);
			wpa_printf(MSG_DEBUG, "ap_scan=%d", config->ap_scan);
		} else if (strncmp(pos, "fast_reauth=", 12) == 0) {
			config->fast_reauth = atoi(pos + 12);
			wpa_printf(MSG_DEBUG, "fast_reauth=%d",
				   config->fast_reauth);
		} else if (strncmp(pos, "opensc_engine_path=", 19) == 0) {
			free(config->opensc_engine_path);
			config->opensc_engine_path = strdup(pos + 19);
			wpa_printf(MSG_DEBUG, "opensc_engine_path='%s'",
				   config->opensc_engine_path);
		} else if (strncmp(pos, "pkcs11_engine_path=", 19) == 0) {
			free(config->pkcs11_engine_path);
			config->pkcs11_engine_path = strdup(pos + 19);
			wpa_printf(MSG_DEBUG, "pkcs11_engine_path='%s'",
				   config->pkcs11_engine_path);
		} else if (strncmp(pos, "pkcs11_module_path=", 19) == 0) {
			free(config->pkcs11_module_path);
			config->pkcs11_module_path = strdup(pos + 19);
			wpa_printf(MSG_DEBUG, "pkcs11_module_path='%s'",
				   config->pkcs11_module_path);
		} else if (strncmp(pos, "driver_param=", 13) == 0) {
			free(config->driver_param);
			config->driver_param = strdup(pos + 13);
			wpa_printf(MSG_DEBUG, "driver_param='%s'",
				   config->driver_param);
		} else if (strncmp(pos, "dot11RSNAConfigPMKLifetime=", 27) ==
			   0) {
			config->dot11RSNAConfigPMKLifetime = atoi(pos + 27);
			wpa_printf(MSG_DEBUG, "dot11RSNAConfigPMKLifetime=%d",
				   config->dot11RSNAConfigPMKLifetime);
		} else if (strncmp(pos, "dot11RSNAConfigPMKReauthThreshold=",
				   34) ==
			   0) {
			config->dot11RSNAConfigPMKReauthThreshold =
				atoi(pos + 34);
			wpa_printf(MSG_DEBUG,
				   "dot11RSNAConfigPMKReauthThreshold=%d",
				   config->dot11RSNAConfigPMKReauthThreshold);
		} else if (strncmp(pos, "dot11RSNAConfigSATimeout=", 25) ==
			   0) {
			config->dot11RSNAConfigSATimeout = atoi(pos + 25);
			wpa_printf(MSG_DEBUG, "dot11RSNAConfigSATimeout=%d",
				   config->dot11RSNAConfigSATimeout);
		} else {
			wpa_printf(MSG_ERROR, "Line %d: Invalid configuration "
				   "line '%s'.", line, pos);
			errors++;
			continue;
		}
	}

	fclose(f);

	config->ssid = head;
	for (prio = 0; prio < config->num_prio; prio++) {
		ssid = config->pssid[prio];
		wpa_printf(MSG_DEBUG, "Priority group %d",
			   ssid->priority);
		while (ssid) {
			wpa_printf(MSG_DEBUG, "   id=%d ssid='%s'",
				   ssid->id,
				   wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
			ssid = ssid->pnext;
		}
	}
	if (errors) {
		wpa_config_free(config);
		config = NULL;
		head = NULL;
	}

	return config;
}


/**
 * wpa_config_free_ssid - Free network/ssid configuration data
 * @ssid: Configuration data for the network
 *
 * This function frees all resources allocated for the netowkr configuration
 * data.
 */
void wpa_config_free_ssid(struct wpa_ssid *ssid)
{
	free(ssid->ssid);
	free(ssid->passphrase);
	free(ssid->eap_methods);
	free(ssid->identity);
	free(ssid->anonymous_identity);
	free(ssid->eappsk);
	free(ssid->nai);
	free(ssid->server_nai);
	free(ssid->password);
	free(ssid->ca_cert);
	free(ssid->client_cert);
	free(ssid->private_key);
	free(ssid->private_key_passwd);
	free(ssid->dh_file);
	free(ssid->subject_match);
	free(ssid->altsubject_match);
	free(ssid->ca_cert2);
	free(ssid->client_cert2);
	free(ssid->private_key2);
	free(ssid->private_key2_passwd);
	free(ssid->dh_file2);
	free(ssid->subject_match2);
	free(ssid->altsubject_match2);
	free(ssid->phase1);
	free(ssid->phase2);
	free(ssid->pcsc);
	free(ssid->pin);
	free(ssid->otp);
	free(ssid->pending_req_otp);
	free(ssid->pac_file);
	free(ssid->new_password);
	free(ssid);
}


/**
 * wpa_config_free - Free configuration data
 * @config: Configuration data from wpa_config_read()
 *
 * This function frees all resources allocated for the configuration data by
 * wpa_config_read().
 */
void wpa_config_free(struct wpa_config *config)
{
	struct wpa_ssid *ssid, *prev = NULL;
	ssid = config->ssid;
	while (ssid) {
		prev = ssid;
		ssid = ssid->next;
		wpa_config_free_ssid(prev);
	}
	free(config->ctrl_interface);
	free(config->opensc_engine_path);
	free(config->pkcs11_engine_path);
	free(config->pkcs11_module_path);
	free(config->driver_param);
	free(config->pssid);
	free(config);
}


/**
 * wpa_config_allowed_eap_method - Check whether EAP method is allowed
 * @ssid: Pointer to a configuration data
 * @method: EAP type
 * Returns: 1 = allowed EAP method, 0 = not allowed
 */
int wpa_config_allowed_eap_method(struct wpa_ssid *ssid, int method)
{
	u8 *pos;

	if (ssid == NULL || ssid->eap_methods == NULL)
		return 1;

	pos = ssid->eap_methods;
	while (*pos != EAP_TYPE_NONE) {
		if (*pos == method)
			return 1;
		pos++;
	}
	return 0;
}


/**
 * wpa_config_get_network - Get configured network based on id
 * @config: Configuration data from wpa_config_read()
 * @id: Unique network id to search for
 * Returns: Network configuration or %NULL if not found
 */
struct wpa_ssid * wpa_config_get_network(struct wpa_config *config, int id)
{
	struct wpa_ssid *ssid;

	ssid = config->ssid;
	while (ssid) {
		if (id == ssid->id)
			break;
		ssid = ssid->next;
	}

	return ssid;
}


/**
 * wpa_config_add_network - Add a new network with empty configuration
 * @config: Configuration data from wpa_config_read()
 * Returns: The new network configuration or %NULL if operation failed
 */
struct wpa_ssid * wpa_config_add_network(struct wpa_config *config)
{
	int id;
	struct wpa_ssid *ssid, *last = NULL;

	id = -1;
	ssid = config->ssid;
	while (ssid) {
		if (ssid->id > id)
			id = ssid->id;
		last = ssid;
		ssid = ssid->next;
	}
	id++;

	ssid = malloc(sizeof(*ssid));
	if (ssid == NULL)
		return NULL;
	memset(ssid, 0, sizeof(*ssid));
	ssid->id = id;
	if (last)
		last->next = ssid;
	else
		config->ssid = ssid;

	wpa_config_update_prio_list(config);

	return ssid;
}


/**
 * wpa_config_remove_network - Remove a configured network based on id
 * @config: Configuration data from wpa_config_read()
 * @id: Unique network id to search for
 * Returns: 0 on success, or -1 if the network was not found
 */
int wpa_config_remove_network(struct wpa_config *config, int id)
{
	struct wpa_ssid *ssid, *prev = NULL;

	ssid = config->ssid;
	while (ssid) {
		if (id == ssid->id)
			break;
		prev = ssid;
		ssid = ssid->next;
	}

	if (ssid == NULL)
		return -1;

	if (prev)
		prev->next = ssid->next;
	else
		config->ssid = ssid->next;

	wpa_config_update_prio_list(config);
	wpa_config_free_ssid(ssid);
	return 0;
}


/**
 * wpa_config_set - Set a variable in network configuration
 * @ssid: Pointer to a network configuration data
 * @var: Variable name, e.g., "ssid"
 * @value: Variable value
 * @line: Line number in configuration file or 0 if not used
 * Returns: 0 on success, -1 on failure
 *
 * This function can be used to set network configuration variables based on
 * both the configuration file and management interface input. The value
 * parameter must be in the same format as the text-based configuration file is
 * using. For example, strings are using double quotation marks.
 */
int wpa_config_set(struct wpa_ssid *ssid, const char *var, const char *value,
		   int line)
{
	int i, ret = 0;

	if (ssid == NULL || var == NULL || value == NULL)
		return -1;

	for (i = 0; i < NUM_SSID_FIELDS; i++) {
		struct parse_data *field = &ssid_fields[i];
		if (strcmp(var, field->name) != 0)
			continue;

		field->ssid = ssid;
		if (field->parser(field, line, value)) {
			if (line) {
				wpa_printf(MSG_ERROR, "Line %d: failed to "
					   "parse %s '%s'.", line, var, value);
			}
			ret = -1;
		}
		break;
	}
	if (i == NUM_SSID_FIELDS) {
		if (line) {
			wpa_printf(MSG_ERROR, "Line %d: unknown network field "
				   "'%s'.", line, var);
		}
		ret = -1;
	}

	return ret;
}


/**
 * wpa_config_update_psk - Update WPA PSK based on passphrase and SSID
 * @ssid: Pointer to a network configuration data
 *
 * This function must be called to update WPA PSK when either SSID or the
 * passphrase has changed for the network configuration.
 */
void wpa_config_update_psk(struct wpa_ssid *ssid)
{
	pbkdf2_sha1(ssid->passphrase,
		    (char *) ssid->ssid, ssid->ssid_len, 4096,
		    ssid->psk, PMK_LEN);
	wpa_hexdump_key(MSG_MSGDUMP, "PSK (from passphrase)",
			ssid->psk, PMK_LEN);
	ssid->psk_set = 1;
}
