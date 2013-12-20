/*
 * WPA Supplicant - Layer2 packet interface definition
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
 * This file defines an interface for layer 2 (link layer) packet sending and
 * receiving. l2_packet_linux.c is one implementation for such a layer 2
 * implementation using Linux packet sockets and l2_packet_pcap.c another one
 * using libpcap and libdnet. When porting %wpa_supplicant to other operating
 * systems, a new l2_packet implementation may need to be added.
 */

#ifndef L2_PACKET_H
#define L2_PACKET_H

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#ifndef ETH_P_EAPOL
#define ETH_P_EAPOL 0x888e
#endif

#ifndef ETH_P_RSN_PREAUTH
#define ETH_P_RSN_PREAUTH 0x88c7
#endif

/**
 * struct l2_packet_data - Internal l2_packet data structure
 *
 * This structure is used by the l2_packet implementation to store its private
 * data. Other files use a pointer to this data when calling the l2_packet
 * functions, but the contents of this structure should not be used directly
 * outside l2_packet implementation.
 */
struct l2_packet_data;

struct l2_ethhdr {
	u8 h_dest[ETH_ALEN];
	u8 h_source[ETH_ALEN];
	u16 h_proto;
} __attribute__ ((packed));

/**
 * l2_packet_init - Initialize l2_packet interface
 * @ifname: Interface name
 * @own_addr: Optional own MAC address if available from driver interface or
 *	%NULL if not available
 * @protocol: Ethernet protocol number in host byte order
 * @rx_callback: Callback function that will be called for each received packet
 * @rx_callback_ctx: Callback data (ctx) for calls to rx_callback()
 * Returns: Pointer to internal data or %NULL on failure
 *
 * rx_callback function will be called with src_addr pointing to the source
 * address (MAC address) of the the packet. By default, buf points to len bytes
 * of the payload after the layer 2 header. This behavior can be changed with
 * l2_packet_set_rx_l2_hdr() to include the layer 2 header in the data buffer.
 */
struct l2_packet_data * l2_packet_init(
	const char *ifname, const u8 *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, unsigned char *src_addr,
			    unsigned char *buf, size_t len),
	void *rx_callback_ctx);

/**
 * l2_packet_deinit - Deinitialize l2_packet interface
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 */
void l2_packet_deinit(struct l2_packet_data *l2);

/**
 * l2_packet_get_own_addr - Get own layer 2 address
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @addr: Buffer for the own address (6 bytes)
 * Returns: 0 on success, -1 on failure
 */
int l2_packet_get_own_addr(struct l2_packet_data *l2, u8 *addr);

/**
 * l2_packet_send - Send a packet
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @buf: Packet contents to be sent; including layer 2 header
 * Returns: >=0 on success, <0 on failure
 */
int l2_packet_send(struct l2_packet_data *l2, u8 *buf, size_t len);

/**
 * l2_packet_set_rx_l2_hdr - Set whether layer 2 packet is included in receive
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @rx_l2_hdr: 1 = include layer 2 header, 0 = do not include header
 *
 * This function changes the behavior of the rx_callback calls. If rx_l2_hdr is
 * set, the buffer will include the layer 2 header.
 */
void l2_packet_set_rx_l2_hdr(struct l2_packet_data *l2, int rx_l2_hdr);

/**
 * l2_packet_set_ethhdr - Helper function for writing a layer 2 header
 * @ethhdr: Pointer to buffer for the header
 * @dest: Destination address
 * @source: Source address
 * @proto: Ethertype for the protocol in host byte order
 * Returns: Pointer to the beginning of the payload
 *
 * This function can be used to write layer 2 headers without having to
 * explicitly know the header structure.
 */
void * l2_packet_set_ethhdr(struct l2_ethhdr *ethhdr, const u8 *dest,
			    const u8 *source, u16 proto);

/**
 * l2_packet_get_ip_addr - Get the current IP address from the interface
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @buf: Buffer for the IP address in text format
 * @len: Maximum buffer length
 * Returns: 0 on success, -1 on failure
 *
 * This function can be used to get the current IP address from the interface
 * bound to the l2_packet. This is mainly for status information and the IP
 * address will be stored as an ASCII string. This function is not essential
 * for %wpa_supplicant operation, so full implementation is not required.
 * l2_packet implementation will need to define the function, but it can return
 * -1 if the IP address information is not available.
 */
int l2_packet_get_ip_addr(struct l2_packet_data *l2, char *buf, size_t len);

#endif /* L2_PACKET_H */
