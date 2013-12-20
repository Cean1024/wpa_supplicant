/*
 * WPA Supplicant - Layer2 packet handling with libpcap/libdnet and WinPcap
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
#ifndef CONFIG_NATIVE_WINDOWS
#include <sys/ioctl.h>
#endif /* CONFIG_NATIVE_WINDOWS */
#include <errno.h>
#include <pcap.h>
#ifndef CONFIG_WINPCAP
#include <dnet.h>
#endif /* CONFIG_WINPCAP */
#ifdef __linux__
#include <arpa/inet.h>
#endif /* __linux__ */

#include "common.h"
#include "eloop.h"
#include "l2_packet.h"


struct l2_packet_data {
	pcap_t *pcap;
#ifndef CONFIG_WINPCAP
	eth_t *eth;
#endif /* CONFIG_WINPCAP */
	char ifname[100];
	u8 own_addr[ETH_ALEN];
	void (*rx_callback)(void *ctx, unsigned char *src_addr,
			    unsigned char *buf, size_t len);
	void *rx_callback_ctx;
	int rx_l2_hdr; /* whether to include layer 2 (Ethernet) header in calls
			* to rx_callback */
};


int l2_packet_get_own_addr(struct l2_packet_data *l2, u8 *addr)
{
	memcpy(addr, l2->own_addr, ETH_ALEN);
	return 0;
}


void l2_packet_set_rx_l2_hdr(struct l2_packet_data *l2, int rx_l2_hdr)
{
	l2->rx_l2_hdr = rx_l2_hdr;
}


#ifndef CONFIG_WINPCAP
static int l2_packet_init_libdnet(struct l2_packet_data *l2)
{
	eth_addr_t own_addr;

	l2->eth = eth_open(l2->ifname);
	if (!l2->eth) {
		printf("Failed to open interface '%s'.\n", l2->ifname);
		perror("eth_open");
		return -1;
	}

	if (eth_get(l2->eth, &own_addr) < 0) {
		printf("Failed to get own hw address from interface '%s'.\n",
		       l2->ifname);
		perror("eth_get");
		eth_close(l2->eth);
		l2->eth = NULL;
		return -1;
	}
	memcpy(l2->own_addr, own_addr.data, ETH_ALEN);

	return 0;
}
#endif /* CONFIG_WINPCAP */


#ifdef CONFIG_WINPCAP
int pcap_sendpacket(pcap_t *p, u_char *buf, int size);
#endif /* CONFIG_WINPCAP */

int l2_packet_send(struct l2_packet_data *l2, u8 *buf, size_t len)
{
	if (l2 == NULL)
		return -1;
#ifdef CONFIG_WINPCAP
	return pcap_sendpacket(l2->pcap, buf, len);
#else /* CONFIG_WINPCAP */
	return eth_send(l2->eth, buf, len);
#endif /* CONFIG_WINPCAP */
}


static void l2_packet_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct l2_packet_data *l2 = eloop_ctx;
	pcap_t *pcap = sock_ctx;
	struct pcap_pkthdr hdr;
	const u_char *packet;
	struct l2_ethhdr *ethhdr;
	unsigned char *buf;
	size_t len;

	packet = pcap_next(pcap, &hdr);

	if (packet == NULL || hdr.caplen < sizeof(*ethhdr))
		return;

	ethhdr = (struct l2_ethhdr *) packet;
	if (l2->rx_l2_hdr) {
		buf = (unsigned char *) ethhdr;
		len = hdr.caplen;
	} else {
		buf = (unsigned char *) (ethhdr + 1);
		len = hdr.caplen - sizeof(*ethhdr);
	}
	l2->rx_callback(l2->rx_callback_ctx, ethhdr->h_source, buf, len);
}


#ifdef CONFIG_WINPCAP
static void l2_packet_receive_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct l2_packet_data *l2 = eloop_ctx;
	pcap_t *pcap = timeout_ctx;
	/* Register new timeout before calling l2_packet_receive() since
	 * receive handler may free this l2_packet instance (which will
	 * cancel this timeout). */
	eloop_register_timeout(0, 100000, l2_packet_receive_timeout,
			       l2, pcap);
	l2_packet_receive(-1, eloop_ctx, timeout_ctx);
}
#endif /* CONFIG_WINPCAP */


static int l2_packet_init_libpcap(struct l2_packet_data *l2,
				  unsigned short protocol)
{
	bpf_u_int32 pcap_maskp, pcap_netp;
	char pcap_filter[100], pcap_err[PCAP_ERRBUF_SIZE];
	struct bpf_program pcap_fp;

	pcap_lookupnet(l2->ifname, &pcap_netp, &pcap_maskp, pcap_err);
	l2->pcap = pcap_open_live(l2->ifname, 2500, 0, 10, pcap_err);
	if (l2->pcap == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", pcap_err);
		fprintf(stderr, "ifname='%s'\n", l2->ifname);
		return -1;
	}
#ifndef CONFIG_WINPCAP
	if (pcap_datalink(l2->pcap) != DLT_EN10MB &&
	    pcap_set_datalink(l2->pcap, DLT_EN10MB) < 0) {
		fprintf(stderr, "pcap_set_datalinke(DLT_EN10MB): %s\n",
			pcap_geterr(l2->pcap));
		return -1;
	}
#endif /* CONFIG_WINPCAP */
	snprintf(pcap_filter, sizeof(pcap_filter),
		 "ether dst " MACSTR " and ether proto 0x%x",
		 MAC2STR(l2->own_addr), protocol);
	if (pcap_compile(l2->pcap, &pcap_fp, pcap_filter, 1, pcap_netp) < 0) {
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(l2->pcap));
		return -1;
	}

	if (pcap_setfilter(l2->pcap, &pcap_fp) < 0) {
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(l2->pcap));
		return -1;
	}

	pcap_freecode(&pcap_fp);
#ifdef BIOCIMMEDIATE
	/*
	 * When libpcap uses BPF we must enable "immediate mode" to
	 * receive frames right away; otherwise the system may
	 * buffer them for us.
	 */
	{
		unsigned int on = 1;
		if (ioctl(pcap_fileno(l2->pcap), BIOCIMMEDIATE, &on) < 0) {
			fprintf(stderr, "%s: cannot enable immediate mode on "
				"interface %s: %s\n",
				__func__, l2->ifname, strerror(errno));
			/* XXX should we fail? */
		}
	}
#endif /* BIOCIMMEDIATE */

#ifdef CONFIG_WINPCAP
	eloop_register_timeout(0, 100000, l2_packet_receive_timeout,
			       l2, l2->pcap);
#else /* CONFIG_WINPCAP */
	eloop_register_read_sock(pcap_get_selectable_fd(l2->pcap),
				 l2_packet_receive, l2, l2->pcap);
#endif /* CONFIG_WINPCAP */

	return 0;
}


struct l2_packet_data * l2_packet_init(
	const char *ifname, const u8 *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, unsigned char *src_addr,
			    unsigned char *buf, size_t len),
	void *rx_callback_ctx)
{
	struct l2_packet_data *l2;

	l2 = malloc(sizeof(struct l2_packet_data));
	if (l2 == NULL)
		return NULL;
	memset(l2, 0, sizeof(*l2));
	strncpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;

#ifdef CONFIG_WINPCAP
	if (own_addr)
		memcpy(l2->own_addr, own_addr, ETH_ALEN);
#else /* CONFIG_WINPCAP */
	if (l2_packet_init_libdnet(l2))
		return NULL;
#endif /* CONFIG_WINPCAP */

	if (l2_packet_init_libpcap(l2, protocol)) {
#ifndef CONFIG_WINPCAP
		eth_close(l2->eth);
#endif /* CONFIG_WINPCAP */
		free(l2);
		return NULL;
	}

	return l2;
}


void l2_packet_deinit(struct l2_packet_data *l2)
{
	if (l2 == NULL)
		return;

#ifdef CONFIG_WINPCAP
	eloop_cancel_timeout(l2_packet_receive_timeout, l2, l2->pcap);
#else /* CONFIG_WINPCAP */
	if (l2->eth)
		eth_close(l2->eth);
#endif /* CONFIG_WINPCAP */
	if (l2->pcap)
		pcap_close(l2->pcap);
	free(l2);
}


void * l2_packet_set_ethhdr(struct l2_ethhdr *ethhdr, const u8 *dest,
			    const u8 *source, u16 proto)
{
	memcpy(ethhdr->h_dest, dest, ETH_ALEN);
	memcpy(ethhdr->h_source, source, ETH_ALEN);
	ethhdr->h_proto = htons(proto);
	return (void *) (ethhdr + 1);
}


int l2_packet_get_ip_addr(struct l2_packet_data *l2, char *buf, size_t len)
{
	pcap_if_t *devs, *dev;
	struct pcap_addr *addr;
	struct sockaddr_in *saddr;
	int found = 0;
	char err[PCAP_ERRBUF_SIZE + 1];

	if (pcap_findalldevs(&devs, err) < 0) {
		wpa_printf(MSG_DEBUG, "pcap_findalldevs: %s\n", err);
		return -1;
	}

	for (dev = devs; dev && !found; dev = dev->next) {
		if (strcmp(dev->name, l2->ifname) != 0)
			continue;

		addr = dev->addresses;
		while (addr) {
			saddr = (struct sockaddr_in *) addr->addr;
			if (saddr && saddr->sin_family == AF_INET) {
				snprintf(buf, len, "%s",
					 inet_ntoa(saddr->sin_addr));
				found = 1;
				break;
			}
			addr = addr->next;
		}
	}

	pcap_freealldevs(devs);

	return found ? 0 : -1;
}
