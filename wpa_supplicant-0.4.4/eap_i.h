/*
 * WPA Supplicant / EAP state machines internal structures
 * Copyright (c) 2004-2005, Jouni Malinen <jkmaline@cc.hut.fi>
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

#ifndef EAP_I_H
#define EAP_I_H

#include "eap.h"

/* draft-ietf-eap-statemachine-05.pdf - Peer state machine */

typedef enum {
	DECISION_FAIL, DECISION_COND_SUCC, DECISION_UNCOND_SUCC
} EapDecision;

typedef enum {
	METHOD_NONE, METHOD_INIT, METHOD_CONT, METHOD_MAY_CONT, METHOD_DONE
} EapMethodState;

struct eap_method_ret {
	Boolean ignore;
	EapMethodState methodState;
	EapDecision decision;
	Boolean allowNotifications;
};


/**
 * struct eap_method - EAP method interface
 * This structure defines the EAP method interface. Each method will need to
 * register its own EAP type, EAP name, and set of function pointers for method
 * specific operations. This interface is based on section 4.4 of
 * draft-ietf-eap-statemachine-06.txt.
 */
struct eap_method {
	EapType method;
	const char *name;

	void * (*init)(struct eap_sm *sm);
	void (*deinit)(struct eap_sm *sm, void *priv);

	/**
	 * process - Process an EAP request
	 * @sm: Pointer to EAP state machine allocated with eap_sm_init()
	 * @priv: Pointer to private EAP method data from init()
	 * @ret: Return values from EAP request validation and processing
	 * @reqData: EAP request to be processed
	 * @reqDataLen: Length of the EAP request
	 * @respDataLen: Length of the returned EAP response
	 * Returns: Pointer to allocate EAP response packet
	 *
	 * This function is a combination of m.check(), m.process(), and
	 * m.buildResp() procedures defined in section 4.4 of
	 * draft-ietf-eap-statemachine-06.txt. In other words, this function
	 * validates the incoming request, processes it, and build a response
	 * packet. m.check() and m.process() return values are returned
	 * through struct eap_method_ret *ret variable. Caller is responsible
	 * for freeing the returned EAP response packet.
	 */
	u8 * (*process)(struct eap_sm *sm, void *priv,
			struct eap_method_ret *ret,
			u8 *reqData, size_t reqDataLen,
			size_t *respDataLen);
	Boolean (*isKeyAvailable)(struct eap_sm *sm, void *priv);
	u8 * (*getKey)(struct eap_sm *sm, void *priv, size_t *len);
	int (*get_status)(struct eap_sm *sm, void *priv, char *buf,
			  size_t buflen, int verbose);

	/**
	 * has_reauth_data - Whether method is ready for fast reauthentication
	 * @sm: Pointer to EAP state machine allocated with eap_sm_init()
	 * @priv: Pointer to private EAP method data from init()
	 * Returns: %TRUE or %FALSE based on whether fast reauthentication is
	 * possible
	 *
	 * This function is an optional handler that only EAP methods
	 * supporting fast re-authentication need to implement.
	 */
	Boolean (*has_reauth_data)(struct eap_sm *sm, void *priv);

	/**
	 * deinit_for_reauth - Release data that is not needed for fast re-auth
	 * @sm: Pointer to EAP state machine allocated with eap_sm_init()
	 * @priv: Pointer to private EAP method data from init()
	 *
	 * This function is an optional handler that only EAP methods
	 * supporting fast re-authentication need to implement. This is called
	 * when authentication has been completed and EAP state machine is
	 * requesting that enough state information is maintained for fast
	 * re-authentication
	 */
	void (*deinit_for_reauth)(struct eap_sm *sm, void *priv);

	/**
	 * init_for_reauth - Prepare for start of fast re-authentication
	 * @sm: Pointer to EAP state machine allocated with eap_sm_init()
	 * @priv: Pointer to private EAP method data from init()
	 *
	 * This function is an optional handler that only EAP methods
	 * supporting fast re-authentication need to implement. This is called
	 * when EAP authentication is started and EAP state machine is
	 * requesting fast re-authentication to be used.
	 */
	void * (*init_for_reauth)(struct eap_sm *sm, void *priv);

	/**
	 * get_identity - Get method specific identity for re-authentication
	 * @sm: Pointer to EAP state machine allocated with eap_sm_init()
	 * @priv: Pointer to private EAP method data from init()
	 * @len: Length of the returned identity
	 * Returns: Pointer to the method specific identity or %NULL if default
	 * identity is to be used
	 *
	 * This function is an optional handler that only EAP methods
	 * that use method specific identity need to implement.
	 */
	const u8 * (*get_identity)(struct eap_sm *sm, void *priv, size_t *len);
};


/**
 * struct eap_sm - EAP state machine data
 */
struct eap_sm {
	enum {
		EAP_INITIALIZE, EAP_DISABLED, EAP_IDLE, EAP_RECEIVED,
		EAP_GET_METHOD, EAP_METHOD, EAP_SEND_RESPONSE, EAP_DISCARD,
		EAP_IDENTITY, EAP_NOTIFICATION, EAP_RETRANSMIT, EAP_SUCCESS,
		EAP_FAILURE
	} EAP_state;
	/* Long-term local variables */
	EapType selectedMethod;
	EapMethodState methodState;
	int lastId;
	u8 *lastRespData;
	size_t lastRespDataLen;
	EapDecision decision;
	/* Short-term local variables */
	Boolean rxReq;
	Boolean rxSuccess;
	Boolean rxFailure;
	int reqId;
	EapType reqMethod;
	Boolean ignore;
	/* Constants */
	int ClientTimeout;

	/* Miscellaneous variables */
	Boolean allowNotifications; /* peer state machine <-> methods */
	u8 *eapRespData; /* peer to lower layer */
	size_t eapRespDataLen; /* peer to lower layer */
	Boolean eapKeyAvailable; /* peer to lower layer */
	u8 *eapKeyData; /* peer to lower layer */
	size_t eapKeyDataLen; /* peer to lower layer */
	const struct eap_method *m; /* selected EAP method */
	/* not defined in draft-ietf-eap-statemachine-02 */
	Boolean changed;
	void *eapol_ctx;
	struct eapol_callbacks *eapol_cb;
	void *eap_method_priv;
	int init_phase2;
	int fast_reauth;

	Boolean rxResp /* LEAP only */;
	Boolean leap_done;
	Boolean peap_done;
	u8 req_md5[16]; /* MD5() of the current EAP packet */
	u8 last_md5[16]; /* MD5() of the previously received EAP packet; used
			  * in duplicate request detection. */

	void *msg_ctx;
	void *scard_ctx;
	void *ssl_ctx;

	unsigned int workaround;

	/* Optional challenges generated in Phase 1 (EAP-FAST) */
	u8 *peer_challenge, *auth_challenge;

	int num_rounds;
};

#endif /* EAP_I_H */
