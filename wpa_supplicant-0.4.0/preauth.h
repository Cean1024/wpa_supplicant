#ifndef PREAUTH_H
#define PREAUTH_H

struct wpa_scan_result;

void pmksa_cache_free(struct wpa_supplicant *wpa_s);
struct rsn_pmksa_cache * pmksa_cache_get(struct wpa_supplicant *wpa_s,
					 const u8 *aa, const u8 *pmkid);
int pmksa_cache_list(struct wpa_supplicant *wpa_s, char *buf, size_t len);
void pmksa_candidate_free(struct wpa_supplicant *wpa_s);
struct rsn_pmksa_cache *
pmksa_cache_add(struct wpa_supplicant *wpa_s, const u8 *pmk,
		size_t pmk_len, const u8 *aa, const u8 *spa,
		struct wpa_ssid *ssid);
void pmksa_cache_notify_reconfig(struct wpa_supplicant *wpa_s);
struct rsn_pmksa_cache *
pmksa_cache_get_opportunistic(struct wpa_supplicant *wpa_s,
			      struct wpa_ssid *ssid, const u8 *aa);

#ifdef IEEE8021X_EAPOL

int rsn_preauth_init(struct wpa_supplicant *wpa_s, u8 *dst);
void rsn_preauth_deinit(struct wpa_supplicant *wpa_s);
void rsn_preauth_scan_results(struct wpa_supplicant *wpa_s,
			      struct wpa_scan_result *results, int count);
void pmksa_candidate_add(struct wpa_supplicant *wpa_s, const u8 *bssid,
			 int prio, int preauth);
void rsn_preauth_candidate_process(struct wpa_supplicant *wpa_s);

#else /* IEEE8021X_EAPOL */

#define rsn_preauth_candidate_process(w) do { } while (0)

static inline int rsn_preauth_init(struct wpa_supplicant *wpa_s, u8 *dst)
{
	return -1;
}

static inline void rsn_preauth_deinit(struct wpa_supplicant *wpa_s)
{
}
static inline void rsn_preauth_scan_results(struct wpa_supplicant *wpa_s,
					    struct wpa_scan_result *results,
					    int count)
{
}

static inline void pmksa_candidate_add(struct wpa_supplicant *wpa_s,
				       const u8 *bssid,
				       int prio, int preauth)
{
}

#endif /* IEEE8021X_EAPOL */

#endif /* PREAUTH_H */
