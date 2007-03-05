/*
 * receive code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998-2003   Richard Guy Briggs.
 * Copyright (C) 2004-2007   Michael Richardson <mcr@xelerance.com>
 *
 * OCF/receive state machine written by
 * David McCullough <dmccullough@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 *
 * Many enhancements by Bart Trojanowski.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

char ipsec_rcv_c_version[] = "RCSID $Id: ipsec_rcv.c,v 1.178 2005/10/21 02:19:34 mcr Exp $";

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

#include "openswan/ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>	/* struct device, and other headers */
#include <linux/etherdevice.h>	/* eth_type_trans */
#include <linux/ip.h>		/* struct iphdr */

#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>
#include <openswan.h>
#ifdef SPINLOCK
# ifdef SPINLOCK_23
#  include <linux/spinlock.h> /* *lock* */
# else /* SPINLOCK_23 */
#  include <asm/spinlock.h> /* *lock* */
# endif /* SPINLOCK_23 */
#endif /* SPINLOCK */

#include <net/ip.h>

#include <linux/moduleparam.h>

#include "openswan/ipsec_kern24.h"
#include "openswan/radij.h"
#include "openswan/ipsec_encap.h"
#include "openswan/ipsec_sa.h"

#include "openswan/ipsec_radij.h"
#include "openswan/ipsec_xform.h"
#include "openswan/ipsec_tunnel.h"
#include "openswan/ipsec_rcv.h"

#include "openswan/ipsec_auth.h"

#include "openswan/ipsec_esp.h"

#ifdef CONFIG_KLIPS_AH
#include "openswan/ipsec_ah.h"
#endif /* CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_IPCOMP
#include "openswan/ipsec_ipcomp.h"
#endif /* CONFIG_KLIPS_COMP */

#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include "openswan/ipsec_debug.h"
#include "openswan/ipsec_proto.h"
#include "openswan/ipsec_alg.h"
#include "openswan/ipsec_kern24.h"

#ifdef CONFIG_KLIPS_OCF
#include "ipsec_ocf.h"
#endif

/* parameters */
extern int sysctl_ipsec_inbound_policy_check;
module_param_named(ipsec_inbound_policy_check,
		   sysctl_ipsec_inbound_policy_check, uint, 0644);
MODULE_PARM_DESC(ipsec_inbound_policy_check,
		 "whether or not to check inner packet against policy");

static int ipsec_irs_max = 1000;
module_param(ipsec_irs_max,int,0644);
MODULE_PARM_DESC(ipsec_irs_max, "Maximum outstanding receive packets");

/* statistics */
static unsigned ipsec_rcv_packets=0;
static unsigned ipsec_netif_called=0;
static unsigned irs_requested=0;
static unsigned irs_declined=0;
static unsigned irs_declined_while_ret_wait=0;
static unsigned irs_declined_while_proc_blocked=0;
static unsigned irs_declined_while_retproc_blocked=0;
static unsigned irs_declined_in_a_row=0;
static unsigned irs_declined_max_in_a_row=0;
static unsigned irs_cache_allocated_count = 0;
static unsigned irs_alloc_failed=0;
static int irs_in_a_row=0;
static uint rsm_calls=0;
static uint rsm_exit1=0;
static uint rsm_exit2=0;
static uint rsm_exit3=0;
static uint rsm_exit4=0;
static uint rcv_exitbad=0;
static uint debug_rcv_once=0;

module_param(irs_requested,               uint, 0444);
module_param(irs_declined,                uint, 0444);
module_param(irs_declined_while_ret_wait, uint, 0444);
module_param(irs_declined_while_proc_blocked, uint, 0444);
module_param(irs_declined_while_retproc_blocked, uint, 0444);
module_param(irs_declined_in_a_row,       uint, 0444);
module_param(irs_declined_max_in_a_row,   uint, 0444);
module_param(irs_cache_allocated_count,   uint, 0444);
module_param(irs_alloc_failed,            uint, 0444);
module_param(ipsec_rcv_packets,           uint, 0444);
module_param(ipsec_netif_called,          uint, 0444);
module_param(rsm_calls, uint, 0444);
module_param(rsm_exit1, uint, 0444);
module_param(rsm_exit2, uint, 0444);
module_param(rsm_exit3, uint, 0444);
module_param(rsm_exit4, uint, 0444);
module_param(rcv_exitbad, uint, 0444);
module_param(debug_rcv_once, uint, 0644);





#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
#include <linux/udp.h>
#endif

/* This is a private use protocol, and AT&T should be ashamed. They should have
 * used protocol # 59, which is "no next header" instead of 0xFE.
 */
#ifndef IPPROTO_ATT_HEARTBEAT
#define IPPROTO_ATT_HEARTBEAT 0xFE
#endif

/*
 * specialize it to receive debugging only
 */
#ifdef ipsec_sa_get
#undef ipsec_sa_get
#define ipsec_sa_get(ips) __ipsec_sa_get(ips, __FUNCTION__, __LINE__,0x40)

#undef ipsec_sa_getbyid
#define ipsec_sa_getbyid(said) __ipsec_sa_getbyid(said,__FUNCTION__,__LINE__,0x40)
#endif


/*
 * Check-replay-window routine, adapted from the original
 * by J. Hughes, from draft-ietf-ipsec-esp-des-md5-03.txt
 *
 *  This is a routine that implements a 64 packet window. This is intend-
 *  ed on being an implementation sample.
 */

DEBUG_NO_STATIC int
ipsec_checkreplaywindow(struct ipsec_sa*ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq) {
		return 1;		/* larger is good */
	}
	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin) {
		return 0;
	}
	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;
	return 1;			/* out of order but good */
}

DEBUG_NO_STATIC int
ipsec_updatereplaywindow(struct ipsec_sa*ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq) {
		diff = seq - ipsp->ips_replaywin_lastseq;

		/* In win, set bit for this pkt */
		if (diff < ipsp->ips_replaywin)
			ipsp->ips_replaywin_bitmap =
				(ipsp->ips_replaywin_bitmap << diff) | 1;
		else
			/* This packet has way larger seq num */
			ipsp->ips_replaywin_bitmap = 1;

		if(seq - ipsp->ips_replaywin_lastseq - 1 > ipsp->ips_replaywin_maxdiff) {
			ipsp->ips_replaywin_maxdiff = seq - ipsp->ips_replaywin_lastseq - 1;
		}
		ipsp->ips_replaywin_lastseq = seq;
		return 1;		/* larger is good */
	}
	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin) {
/*
		if(seq < 0.25*max && ipsp->ips_replaywin_lastseq > 0.75*max) {
			ipsec_sa_delchain(ipsp);
		}
*/
		return 0;
	}
	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;
	ipsp->ips_replaywin_bitmap |= (1 << diff);	/* mark as seen */
	return 1;			/* out of order but good */
}

#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
struct auth_alg ipsec_rcv_md5[]={
	{osMD5Init, osMD5Update, osMD5Final, AHMD596_ALEN}
};

#endif /* CONFIG_KLIPS_AUTH_HMAC_MD5 */

#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
struct auth_alg ipsec_rcv_sha1[]={
	{SHA1Init, SHA1Update, SHA1Final, AHSHA196_ALEN}
};
#endif /* CONFIG_KLIPS_AUTH_HMAC_MD5 */


/*
 * here is a state machine to handle receiving ipsec packets.
 * basically we keep getting re-entered until processing is
 * complete.  For the simple case we step down the states and finish.
 * each state is ideally some logical part of the process.  If a state
 * can pend (ie., require async processing to complete),  then this
 * should be the part of last action before it returns IPSEC_RCV_PENDING
 *
 * Any particular action may alter the next_state in irs to move us to
 * a state other than the preferred "next_state",  but this is the
 * exception and is highlighted when it is done.
 *
 * prototypes for state action
 */

static enum ipsec_rcv_value ipsec_rcv_init(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_decap_init(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_decap_chk(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_auth_init(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_auth_calc(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_auth_chk(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_decrypt(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_decap_cont(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_cleanup(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_ipcomp(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_complete(struct ipsec_rcv_state *irs);

/*
 * the state table and each action
 */

struct {
	enum ipsec_rcv_value (*action)(struct ipsec_rcv_state *irs);
	int next_state;
} rcv_state_table[] = {
	[IPSEC_RSM_INIT]       = {ipsec_rcv_init,       IPSEC_RSM_DECAP_INIT },
	[IPSEC_RSM_DECAP_INIT] = {ipsec_rcv_decap_init, IPSEC_RSM_DECAP_CHK },
	[IPSEC_RSM_DECAP_CHK]  = {ipsec_rcv_decap_chk,  IPSEC_RSM_AUTH_INIT },
	[IPSEC_RSM_AUTH_INIT]  = {ipsec_rcv_auth_init,  IPSEC_RSM_AUTH_CALC },
	[IPSEC_RSM_AUTH_CALC]  = {ipsec_rcv_auth_calc,  IPSEC_RSM_AUTH_CHK },
	[IPSEC_RSM_AUTH_CHK]   = {ipsec_rcv_auth_chk,  IPSEC_RSM_DECRYPT },
	[IPSEC_RSM_DECRYPT]    = {ipsec_rcv_decrypt,    IPSEC_RSM_DECAP_CONT },
	[IPSEC_RSM_DECAP_CONT] = {ipsec_rcv_decap_cont, IPSEC_RSM_CLEANUP },
	[IPSEC_RSM_CLEANUP]    = {ipsec_rcv_cleanup,    IPSEC_RSM_IPCOMP },
	[IPSEC_RSM_IPCOMP]     = {ipsec_rcv_ipcomp,     IPSEC_RSM_COMPLETE },
	[IPSEC_RSM_COMPLETE]   = {ipsec_rcv_complete,   IPSEC_RSM_DONE },

	[IPSEC_RSM_DONE]       = {NULL,                 IPSEC_RSM_DONE},
};



struct sk_buff *ipsec_rcv_unclone(struct sk_buff *skb,
				  struct ipsec_rcv_state *irs)
{
	/* if skb was cloned (most likely due to a packet sniffer such as
	   tcpdump being momentarily attached to the interface), make
	   a copy of our own to modify */
	if(skb_cloned(skb)) {
		/* include any mac header while copying.. */
		if(skb_headroom(skb) < irs->hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv: "
			       "tried to skb_push hhlen=%d, %d available.  This should never happen, please report.\n",
			       irs->hard_header_len,
			       skb_headroom(skb));
			goto rcvleave;
		}
		skb_push(skb, irs->hard_header_len);
		if
#ifdef SKB_COW_NEW
		  (skb_cow(skb, skb_headroom(skb)) != 0)
#else /* SKB_COW_NEW */
		  ((skb = skb_cow(skb, skb_headroom(skb))) == NULL)
#endif /* SKB_COW_NEW */
		{
			goto rcvleave;
		}
		if(skb->len < irs->hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv: "
			       "tried to skb_pull hhlen=%d, %d available.  This should never happen, please report.\n",
			       irs->hard_header_len,
			       skb->len);
			goto rcvleave;
		}
		skb_pull(skb, irs->hard_header_len);
	}
	return skb;

rcvleave:
	ipsec_kfree_skb(skb);
	return NULL;
}




#if !defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
/*
 * decapsulate a UDP encapsulated ESP packet
 */
struct sk_buff *ipsec_rcv_natt_decap(struct sk_buff *skb
				     , struct ipsec_rcv_state *irs
				     , int *udp_decap_ret_p)
{
	*udp_decap_ret_p = 0;
	if (skb->sk && skb->nh.iph && skb->nh.iph->protocol==IPPROTO_UDP) {
		/**
		 * Packet comes from udp_queue_rcv_skb so it is already defrag,
		 * checksum verified, ... (ie safe to use)
		 *
		 * If the packet is not for us, return -1 and udp_queue_rcv_skb
		 * will continue to handle it (do not kfree skb !!).
		 */

#ifndef UDP_OPT_IN_SOCK
		struct udp_opt {
			__u32 esp_in_udp;
		};
		struct udp_opt *tp =  (struct udp_opt *)&(skb->sk->tp_pinfo.af_tcp);
#else
		struct udp_opt *tp =  &(skb->sk->tp_pinfo.af_udp);
#endif

		struct iphdr *ip = (struct iphdr *)skb->nh.iph;
		struct udphdr *udp = (struct udphdr *)((__u32 *)ip+ip->ihl);
		__u8 *udpdata = (__u8 *)udp + sizeof(struct udphdr);
		__u32 *udpdata32 = (__u32 *)udpdata;
		
		irs->natt_sport = ntohs(udp->source);
		irs->natt_dport = ntohs(udp->dest);
	  
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "suspected ESPinUDP packet (NAT-Traversal) [%d].\n",
			    tp->esp_in_udp);
		KLIPS_IP_PRINT(debug_rcv, ip);
	  
		if (udpdata < skb->tail) {
			unsigned int len = skb->tail - udpdata;
			if ((len==1) && (udpdata[0]==0xff)) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    /* not IPv6 compliant message */
					    "NAT-keepalive from %d.%d.%d.%d.\n", NIPQUAD(ip->saddr));
				*udp_decap_ret_p = 0;
				return NULL;
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_IKE) &&
				  (len > (2*sizeof(__u32) + sizeof(struct esphdr))) &&
				  (udpdata32[0]==0) && (udpdata32[1]==0) ) {
				/* ESP Packet with Non-IKE header */
				KLIPS_PRINT(debug_rcv, 
					    "klips_debug:ipsec_rcv: "
					    "ESPinUDP pkt with Non-IKE - spi=0x%x\n",
					    ntohl(udpdata32[2]));
				irs->natt_type = ESPINUDP_WITH_NON_IKE;
				irs->natt_len = sizeof(struct udphdr)+(2*sizeof(__u32));
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_ESP) &&
				  (len > sizeof(struct esphdr)) &&
				  (udpdata32[0]!=0) ) {
				/* ESP Packet without Non-ESP header */
				irs->natt_type = ESPINUDP_WITH_NON_ESP;
				irs->natt_len = sizeof(struct udphdr);
				KLIPS_PRINT(debug_rcv, 
					    "klips_debug:ipsec_rcv: "
					    "ESPinUDP pkt without Non-ESP - spi=0x%x\n",
					    ntohl(udpdata32[0]));
			}
			else {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "IKE packet - not handled here\n");
				*udp_decap_ret_p = -1;
				return NULL;
			}
		}
		else {
			return NULL;
		}
  	}
	return skb;
}
#endif

/*
 * get all the initial checking and setup done.  Not of this can be off
 * loaded by any currently support hardware
 *
 * the following things should be setup when we exit this function.
 *
 * irs->stats  == stats structure (or NULL)
 * irs->ipp    = IP header.
 * irs->len    = total length of packet
 * skb->nh.iph = ipp;
 * skb->h.raw  = start of payload
 * irs->ipsp   = NULL.
 * irs->iphlen = N/A = is recalculated.
 * irs->ilen   = 0;
 * irs->authlen = 0;
 * irs->authfuncs = NULL;
 * irs->skb    = the skb;
 *
 * proto_funcs should be from ipsec_esp.c, ipsec_ah.c or ipsec_ipcomp.c.
 *
 */

static enum ipsec_rcv_value
ipsec_rcv_init(struct ipsec_rcv_state *irs)
{
#ifdef CONFIG_KLIPS_DEBUG
	struct net_device *dev;
#endif /* CONFIG_KLIPS_DEBUG */
	unsigned char protoc;
	struct iphdr *ipp;
	struct net_device_stats *stats = NULL;		/* This device's statistics */
	struct net_device *ipsecdev = NULL, *prvdev;
	struct ipsecpriv *prv;
	char name[9];
	int i;
	struct sk_buff *skb;

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

	if (irs == NULL) {
		KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_rcv_init: NULL irs.");
		return IPSEC_RCV_REALLYBAD;
	}

	skb = irs->skb;
	if (!skb) {
		KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_rcv_init: NULL skb.");
		return IPSEC_RCV_REALLYBAD;
	}
	dev = skb->dev;

	if (skb->data == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		return IPSEC_RCV_REALLYBAD;
	}

	/* dev->hard_header_len is unreliable and should not be used */
	/* klips26_rcv_encap will have already set hard_header_len for us */
	if (irs->hard_header_len == 0) {
		irs->hard_header_len = skb->mac.raw ? (skb->nh.raw - skb->mac.raw) : 0;
		if((irs->hard_header_len < 0) || (irs->hard_header_len > skb_headroom(skb)))
			irs->hard_header_len = 0;
	}

	skb = ipsec_rcv_unclone(skb, irs);
	if(skb == NULL) {
		return IPSEC_RCV_REALLYBAD;
	}

#if IP_FRAGMENT_LINEARIZE
	/* In Linux 2.4.4, we may have to reassemble fragments. They are
	   not assembled automatically to save TCP from having to copy
	   twice.
	*/
        if (skb_is_nonlinear(skb)) {
#ifdef HAVE_NEW_SKB_LINEARIZE
                if (skb_linearize_cow(skb) != 0) 
#else
                if (skb_linearize(skb, GFP_ATOMIC) != 0) 
#endif
                        return IPSEC_RCV_REALLYBAD;
        }
#endif /* IP_FRAGMENT_LINEARIZE */

	ipp = skb->nh.iph;

#if defined(CONFIG_IPSEC_NAT_TRAVERSAL) && !defined(NET_26)
	if (irs->natt_len) {
		/**
		 * Now, we are sure packet is ESPinUDP, and we have a private
		 * copy that has been linearized, remove natt_len bytes
		 * from packet and modify protocol to ESP.
		 */
		if (((unsigned char *)skb->data > (unsigned char *)skb->nh.iph)
		    && ((unsigned char *)skb->nh.iph > (unsigned char *)skb->head))
		{
			unsigned int _len = (unsigned char *)skb->data -
				(unsigned char *)skb->nh.iph;
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: adjusting skb: skb_push(%u)\n",
				_len);
			skb_push(skb, _len);
		}
		KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
			"removing %d bytes from ESPinUDP packet\n", irs->natt_len);
		ipp = (struct iphdr *)skb->data;
		irs->iphlen = ipp->ihl << 2;
		ipp->tot_len = htons(ntohs(ipp->tot_len) - irs->natt_len);
		if (skb->len < irs->iphlen + irs->natt_len) {
			printk(KERN_WARNING
		       "klips_error:ipsec_rcv: "
		       "ESPinUDP packet is too small (%d < %d+%d). "
			   "This should never happen, please report.\n",
		       (int)(skb->len), irs->iphlen, irs->natt_len);
			return IPSEC_RCV_REALLYBAD;
		}

		/* advance payload pointer to point past the UDP header */
		skb->h.raw = skb->h.raw + irs->natt_len;

		/* modify protocol */
		ipp->protocol = IPPROTO_ESP;

		skb->sk = NULL;

		KLIPS_IP_PRINT(debug_rcv, skb->nh.iph);
	}
#endif

	if (debug_rcv)
	{
	  	struct in_addr ipsaddr;
		struct in_addr ipdaddr;

		ipsaddr.s_addr = ipp->saddr;
		addrtoa(ipsaddr, 0, irs->ipsaddr_txt
			, sizeof(irs->ipsaddr_txt));
		ipdaddr.s_addr = ipp->daddr;
		addrtoa(ipdaddr, 0, irs->ipdaddr_txt
			, sizeof(irs->ipdaddr_txt));
	}

	irs->iphlen = ipp->ihl << 2;

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "<<< Info -- ");
	KLIPS_PRINTMORE(debug_rcv && skb->dev, "skb->dev=%s ",
			skb->dev->name ? skb->dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv && dev, "dev=%s ",
			dev->name ? dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv, "\n");

	KLIPS_PRINT(debug_rcv && !(skb->dev && dev && (skb->dev == dev)),
		    "klips_debug:ipsec_rcv: "
		    "Informational -- **if this happens, find out why** skb->dev:%s is not equal to dev:%s\n",
		    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL",
		    dev ? (dev->name ? dev->name : "NULL") : "NULL");

	protoc = ipp->protocol;
#ifndef NET_21
	if((!protocol) || (protocol->protocol != protoc)) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPSA,
			    "klips_debug:ipsec_rcv: "
			    "protocol arg is NULL or unequal to the packet contents, this is odd, using value in packet.\n");
	}
#endif /* !NET_21 */

	if( (protoc != IPPROTO_AH) &&
#ifdef CONFIG_KLIPS_IPCOMP_disabled_until_we_register_IPCOMP_HANDLER
	    (protoc != IPPROTO_COMP) &&
#endif /* CONFIG_KLIPS_IPCOMP */
	    (protoc != IPPROTO_ESP) ) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPSA,
			    "klips_debug:ipsec_rcv: Why the hell is someone "
			    "passing me a non-ipsec protocol = %d packet? -- dropped.\n",
			    protoc);
		return IPSEC_RCV_REALLYBAD;
	}

	if(skb->dev) {
		for(i = 0; i < IPSEC_NUM_IF; i++) {
			sprintf(name, IPSEC_DEV_FORMAT, i);
			if(!strcmp(name, skb->dev->name)) {
				prv = (struct ipsecpriv *)(skb->dev->priv);
				if(prv) {
					stats = (struct net_device_stats *) &(prv->mystats);
				}
				ipsecdev = skb->dev;
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "Info -- pkt already proc'ed a group of ipsec headers, processing next group of ipsec headers.\n");
				break;
			}
			if((ipsecdev = __ipsec_dev_get(name)) == NULL) {
				KLIPS_PRINT(debug_rcv,
					    "klips_error:ipsec_rcv: "
					    "device %s does not exist\n",
					    name);
			}
			prv = ipsecdev ? (struct ipsecpriv *)(ipsecdev->priv) : NULL;
			prvdev = prv ? (struct net_device *)(prv->dev) : NULL;

#if 0
			KLIPS_PRINT(debug_rcv && prvdev,
				    "klips_debug:ipsec_rcv: "
				    "physical device for device %s is %s\n",
				    name,
				    prvdev->name);
#endif
			if(prvdev && skb->dev &&
			   !strcmp(prvdev->name, skb->dev->name)) {
				stats = prv ? ((struct net_device_stats *) &(prv->mystats)) : NULL;
				skb->dev = ipsecdev;
				KLIPS_PRINT(debug_rcv && prvdev,
					    "klips_debug:ipsec_rcv: "
					    "assigning packet ownership to virtual device %s from physical device %s.\n",
					    name, prvdev->name);
				if(stats) {
					stats->rx_packets++;
				}
				break;
			}
		}
	} else {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "device supplied with skb is NULL\n");
	}

	if(stats == NULL) {
		KLIPS_PRINT((debug_rcv),
			    "klips_error:ipsec_rcv: "
			    "packet received from physical I/F (%s) not connected to ipsec I/F.  Cannot record stats.  May not have SA for decoding.  Is IPSEC traffic expected on this I/F?  Check routing.\n",
			    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL");
	}
		
	KLIPS_IP_PRINT(debug_rcv, ipp);

	/* set up for decap */
	irs->stats= stats;
	irs->ipp  = ipp;
	irs->ipsp = NULL;
	irs->ilen = 0;
	irs->authlen=0;
	irs->authfuncs=NULL;
	irs->skb = skb;
	return IPSEC_RCV_OK;
}


static enum ipsec_rcv_value
ipsec_rcv_decap_init(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

	switch (irs->ipp->protocol) {
	case IPPROTO_ESP:
		irs->proto_funcs = esp_xform_funcs;
		break;

#ifdef CONFIG_KLIPS_AH
	case IPPROTO_AH:
		irs->proto_funcs = ah_xform_funcs;
		break;
#endif /* !CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_IPCOMP
	case IPPROTO_COMP:
		irs->proto_funcs = ipcomp_xform_funcs;
		break;
#endif /* !CONFIG_KLIPS_IPCOMP */

	default:
		if (irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADPROTO;
	}
	return IPSEC_RCV_OK;
}


static enum ipsec_rcv_value
ipsec_rcv_decap_chk(struct ipsec_rcv_state *irs)
{
	struct in_addr ipsaddr;
	struct in_addr ipdaddr;
	struct iphdr *ipp;
	struct sk_buff *skb;

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

	irs->replay = 0;
	irs->ixt_a = NULL;

	skb = irs->skb;
	irs->len = skb->len;
	ipp = irs->ipp;
	irs->proto = ipp->protocol;
	if (debug_rcv) {
	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));
	}

	irs->iphlen = ipp->ihl << 2;

	ipp->check = 0;			/* we know the sum is good */
	
	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv_decap_once: "
		    "decap (%d) from %s -> %s\n",
		    irs->proto, irs->ipsaddr_txt, irs->ipdaddr_txt);

	/*
	 * Find tunnel control block and (indirectly) call the
	 * appropriate tranform routine. The resulting sk_buf
	 * is a valid IP packet ready to go through input processing.
	 */

	irs->said.dst.u.v4.sin_addr.s_addr = ipp->daddr;
	irs->said.dst.u.v4.sin_family = AF_INET;

	/* note: rcv_checks set up the said.spi value, if appropriate */
	if (irs->proto_funcs->rcv_checks)
		return (*irs->proto_funcs->rcv_checks)(irs, irs->skb);

	return IPSEC_RCV_OK;
}


static enum ipsec_rcv_value
ipsec_rcv_auth_init(struct ipsec_rcv_state *irs)
{
	struct ipsec_sa *newipsp;

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

	irs->said.proto = irs->proto;
	if (debug_rcv) {
	irs->sa_len = satot(&irs->said, 0, irs->sa, sizeof(irs->sa));
	if(irs->sa_len == 0) {
		strcpy(irs->sa, "(error)");
	}
	} else
		irs->sa_len = 0;

	newipsp = ipsec_sa_getbyid(&irs->said);
	if (newipsp == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "no ipsec_sa for SA:%s: incoming packet with no SA dropped\n",
			    irs->sa_len ? irs->sa : " (error)");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	/* If it is in larval state, drop the packet, we cannot process yet. */
	if(newipsp->ips_state == K_SADB_SASTATE_LARVAL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "ipsec_sa in larval state, cannot be used yet, dropping packet.\n");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		ipsec_sa_put(newipsp);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if(newipsp->ips_state == K_SADB_SASTATE_DEAD) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "ipsec_sa in dead state, cannot be used any more, dropping packet.\n");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		ipsec_sa_put(newipsp);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if(sysctl_ipsec_inbound_policy_check) {
		if(irs->ipp->saddr != ((struct sockaddr_in*)(newipsp->ips_addr_s))->sin_addr.s_addr) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
				    irs->sa_len ? irs->sa : " (error)",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			ipsec_sa_put(newipsp);
			return IPSEC_RCV_FAILEDINBOUND;
		}

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "SA:%s, src=%s of pkt agrees with expected SA source address policy.\n",
			    irs->sa_len ? irs->sa : " (error)",
			    irs->ipsaddr_txt);

		/*
		 * at this point, we have looked up a new SA, and we want to make sure that if this
		 * isn't the first SA in the list, that the previous SA actually points at this one.
		 */
		if(irs->ipsp) {
			if(irs->ipsp->ips_inext != newipsp) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "unexpected SA:%s: does not agree with ips->inext policy, dropped\n",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				ipsec_sa_put(newipsp);
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s grouping from previous SA is OK.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s First SA in group.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
                if (irs->proto == IPPROTO_ESP) {
                        KLIPS_PRINT(debug_rcv,
                                "klips_debug:ipsec_rcv: "
                                "natt_type=%u tdbp->ips_natt_type=%u : %s\n",
                                irs->natt_type, newipsp->ips_natt_type,
                                (irs->natt_type==newipsp->ips_natt_type)?"ok":"bad");
                        if (irs->natt_type != newipsp->ips_natt_type) {
                                KLIPS_PRINT(debug_rcv,
                                            "klips_debug:ipsec_rcv: "
                                            "SA:%s does not agree with expected NAT-T policy.\n",
                                            irs->sa_len ? irs->sa : " (error)");
                                if(irs->stats) {
                                        irs->stats->rx_dropped++;
                                }
                                ipsec_sa_put(newipsp);
                                return IPSEC_RCV_FAILEDINBOUND;
                        }
                }
#endif		 
	}

	/* okay, SA checks out, so free any previous SA, and record a new one*/

	if(irs->ipsp) {
		ipsec_sa_put(irs->ipsp);
	}
	irs->ipsp=newipsp;

	/* note that the outer code will free the irs->ipsp
	   if there is an error */


	/* now check the lifetimes */
	if(ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_bytes,   "bytes",
				irs->sa, ipsec_life_countbased, ipsec_incoming,
				irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "addtime",
				irs->sa, ipsec_life_timebased,  ipsec_incoming,
				irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "usetime",
				irs->sa, ipsec_life_timebased,  ipsec_incoming,
				irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_packets, "packets",
				irs->sa, ipsec_life_countbased, ipsec_incoming,
				irs->ipsp) == ipsec_life_harddied) {

		/*
		 * disconnect SA from the hash table, so it can not be
		 * found again.
		 */
		ipsec_sa_rm(irs->ipsp);
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_decap_once: "
			    "decap (%d) failed lifetime check\n",
			    irs->proto);

		return IPSEC_RCV_LIFETIMEFAILED;
	}

#if 0
	/*
	 * This is removed for some reasons:
	 *   1) it needs to happen *after* authentication.
	 *   2) do we really care, if it authenticates, if it came
	 *      from the wrong location?
         *   3) the NAT_KA messages in IKE will also get to pluto
	 *      and it will figure out that stuff has moved.
	 *   4) the 2.6 udp-esp encap function does not pass us
	 *      the originating port number, and I can't tell
	 *      if skb->sk is guaranteed to be valid here.
	 *  2005-04-16: mcr@xelerance.com
	 */
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	/*
	 *
	 * XXX we should ONLY update pluto if the SA passes all checks,
	 *     which we clearly do not now.
	 */
	if ((irs->natt_type) &&
		( (irs->ipp->saddr != (((struct sockaddr_in*)(newipsp->ips_addr_s))->sin_addr.s_addr)) ||
		  (irs->natt_sport != newipsp->ips_natt_sport)
		)) {
		struct sockaddr sipaddr;
		struct sockaddr_in *psin = (struct sockaddr_in*)(newipsp->ips_addr_s);

		/** Advertise NAT-T addr change to pluto **/
		sipaddr.sa_family = AF_INET;
		((struct sockaddr_in*)&sipaddr)->sin_addr.s_addr = irs->ipp->saddr;
		((struct sockaddr_in*)&sipaddr)->sin_port = htons(irs->natt_sport);
		pfkey_nat_t_new_mapping(newipsp, &sipaddr, irs->natt_sport);

		/**
		 * Then allow or block packet depending on
		 * sysctl_ipsec_inbound_policy_check.
		 *
		 * In all cases, pluto will update SA if new mapping is
		 * accepted.
		 */
		if (sysctl_ipsec_inbound_policy_check) {
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"SA:%s, src=%s:%u of pkt does not agree with expected "
				"SA source address [%08x:%u] (notifying pluto of change).\n",
				irs->sa_len ? irs->sa : " (error)",
				    irs->ipsaddr_txt, irs->natt_sport,
				    psin->sin_addr.s_addr,
				    newipsp->ips_natt_sport);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			ipsec_sa_put(newipsp);
			return IPSEC_RCV_FAILEDINBOUND;
		}
	}
#endif
#endif

	irs->authfuncs=NULL;

	/* authenticate, if required */
#ifdef CONFIG_KLIPS_OCF
	if (irs->ipsp->ocf_in_use) {
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;
	} else
#endif /* CONFIG_KLIPS_OCF */
	if ((irs->ixt_a=irs->ipsp->ips_alg_auth)) {
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;
		KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"authalg=%d authlen=%d\n",
				irs->ipsp->ips_authalg, 
				irs->authlen);
	} else
	switch(irs->ipsp->ips_authalg) {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
	case AH_MD5:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_md5;
		irs->ictx = (void *)&((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)&((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len = sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len = sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
	case AH_SHA:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_sha1;
		irs->ictx = (void *)&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len = sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len = sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	case AH_NONE:
		irs->authlen = 0;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;
		break;
	default:
		irs->ipsp->ips_errs.ips_alg_errs += 1;
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADAUTH;
	}

	/* ilen counts number of bytes in ESP portion */
	irs->ilen = ((irs->skb->data + irs->skb->len) - irs->skb->h.raw) - irs->authlen;
	if(irs->ilen <= 0) {
	  KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "runt %s packet with no data, dropping.\n",
		      (irs->proto == IPPROTO_ESP ? "esp" : "ah"));
	  if(irs->stats) {
	    irs->stats->rx_dropped++;
	  }
	  return IPSEC_RCV_BADLEN;
	}

	if(irs->authfuncs ||
#ifdef CONFIG_KLIPS_OCF
			irs->ipsp->ocf_in_use ||
#endif
			irs->ixt_a) {
	  if(irs->proto_funcs->rcv_setup_auth)
	    return (*irs->proto_funcs->rcv_setup_auth)(irs, irs->skb,
				&irs->replay, &irs->authenticator);
	}
	return IPSEC_RCV_OK;
}


static enum ipsec_rcv_value
ipsec_rcv_auth_calc(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

	if(irs->authfuncs ||
#ifdef CONFIG_KLIPS_OCF
			(irs->ipsp->ocf_in_use && irs->ipsp->ips_authalg) ||
#endif
			irs->ixt_a) {
		if(!irs->authenticator) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_BADAUTH;
		}

		if(!ipsec_checkreplaywindow(irs->ipsp, irs->replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYFAILED;
		}

		/*
		 * verify authenticator
		 */

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "encalg = %d, authalg = %d.\n",
			    irs->ipsp->ips_encalg,
			    irs->ipsp->ips_authalg);

		/* calculate authenticator */
		if(irs->proto_funcs->rcv_calc_auth == NULL) {
			return IPSEC_RCV_BADAUTH;
		}
		/* such as ipsec_rcv_esp_authcalc */
		return (*irs->proto_funcs->rcv_calc_auth)(irs, irs->skb);
	}
	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value
ipsec_rcv_auth_chk(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

	if(irs->authfuncs ||
#ifdef CONFIG_KLIPS_OCF
			(irs->ipsp->ocf_in_use && irs->ipsp->ips_authalg) ||
#endif
			irs->ixt_a) {
		if (memcmp(irs->hash, irs->authenticator, irs->authlen)) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			KLIPS_ERROR(debug_rcv & DB_RX_INAU,
				    "klips_debug:ipsec_rcv: "
				    "auth failed on incoming packet from %s: calculated=%08x%08x%08x packetauth=%08x%08x%08x, dropped\n",
				    irs->ipsaddr_txt,
				    ntohl(*(__u32*)&irs->hash[0]),
				    ntohl(*(__u32*)&irs->hash[4]),
				    ntohl(*(__u32*)&irs->hash[8]),
				    ntohl(*(__u32*)irs->authenticator),
				    ntohl(*((__u32*)irs->authenticator + 1)),
				    ntohl(*((__u32*)irs->authenticator + 2)));
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_AUTHFAILED;
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "authentication successful.\n");
		}

		/* Crypto hygiene: clear memory used to calculate autheticator.
		 * The length varies with the algorithm.
		 */
		memset(irs->hash, 0, irs->authlen);

		/* If the sequence number == 0, expire SA, it had rolled */
		if(irs->ipsp->ips_replaywin && !irs->replay /* !irs->ipsp->ips_replaywin_lastseq */) {

		        /* we need to remove it from the sadb hash, so that it can't be found again */
			ipsec_sa_rm(irs->ipsp);

			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "replay window counter rolled, expiring SA.\n");
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYROLLED;
		}

		/* now update the replay counter */
		if (!ipsec_updatereplaywindow(irs->ipsp, irs->replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYROLLED;
		}
	}
	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value
ipsec_rcv_decrypt(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

	if (irs->proto_funcs->rcv_decrypt) {
		return (*irs->proto_funcs->rcv_decrypt)(irs);
	}
	return IPSEC_RCV_OK;
}

/*
 * here we decide if there is more decapsulating required and
 * change the next state appropriately
 */
static enum ipsec_rcv_value
ipsec_rcv_decap_cont(struct ipsec_rcv_state *irs)
{
	struct sk_buff *skb;
	struct iphdr *ipp;
	struct in_addr ipsaddr;
	struct in_addr ipdaddr;
	struct ipsec_sa *ipsnext = NULL; /* next SA towards inside of packet */

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

	/*
	 *	Adjust pointers after decrypt
	 */
	skb = irs->skb;
	irs->len = skb->len;
	ipp = irs->ipp = skb->nh.iph;
	irs->iphlen = ipp->ihl<<2;
	skb->h.raw = skb->nh.raw + irs->iphlen;

	/* zero any options that there might be */
	memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));

	if (debug_rcv) {
		ipsaddr.s_addr = ipp->saddr;
		addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
		ipdaddr.s_addr = ipp->daddr;
		addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));
	}

	/*
	 *	Discard the original ESP/AH header
	 */
	ipp->protocol = irs->next_header;

	ipp->check = 0;	/* NOTE: this will be included in checksum */
	ipp->check = ip_fast_csum((unsigned char *)skb->nh.iph, irs->iphlen >> 2);

	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "after <%s%s%s>, SA:%s:\n",
		    IPS_XFORM_NAME(irs->ipsp),
		    irs->sa_len ? irs->sa : " (error)");
	KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = 0;

	ipsnext = irs->ipsp->ips_inext;
	if(sysctl_ipsec_inbound_policy_check) {
		if(ipsnext) {
			if(
				ipp->protocol != IPPROTO_AH
				&& ipp->protocol != IPPROTO_ESP
#ifdef CONFIG_KLIPS_IPCOMP
				&& ipp->protocol != IPPROTO_COMP
				&& (ipsnext->ips_said.proto != IPPROTO_COMP
				    || ipsnext->ips_inext)
#endif /* CONFIG_KLIPS_IPCOMP */
				&& ipp->protocol != IPPROTO_IPIP
				&& ipp->protocol != IPPROTO_ATT_HEARTBEAT  /* heartbeats to AT&T SIG/GIG */
				) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "packet with incomplete policy dropped, last successful SA:%s.\n",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, Another IPSEC header to process.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "No ips_inext from this SA:%s.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}
	}

#ifdef CONFIG_KLIPS_IPCOMP
	/* update ipcomp ratio counters, even if no ipcomp packet is present */
	if (ipsnext
	    && ipsnext->ips_said.proto == IPPROTO_COMP
	    && ipp->protocol != IPPROTO_COMP) {
		ipsnext->ips_comp_ratio_cbytes += ntohs(ipp->tot_len);
		ipsnext->ips_comp_ratio_dbytes += ntohs(ipp->tot_len);
	}
#endif /* CONFIG_KLIPS_IPCOMP */

	irs->ipsp->ips_life.ipl_bytes.ipl_count += irs->len;
	irs->ipsp->ips_life.ipl_bytes.ipl_last   = irs->len;

	if(!irs->ipsp->ips_life.ipl_usetime.ipl_count) {
		irs->ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
	}
	irs->ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
	irs->ipsp->ips_life.ipl_packets.ipl_count += 1;

#ifdef CONFIG_NETFILTER
	if(irs->proto == IPPROTO_ESP || irs->proto == IPPROTO_AH) {
		skb->nfmark = (skb->nfmark & (~(IPsecSAref2NFmark(IPSEC_SA_REF_MASK))))
			| IPsecSAref2NFmark(IPsecSA2SAref(irs->ipsp));
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "%s SA sets skb->nfmark=0x%x.\n",
			    irs->proto == IPPROTO_ESP ? "ESP" : "AH",
			    (unsigned)skb->nfmark);
	}
#endif /* CONFIG_NETFILTER */

	/*
	 * do we need to do more decapsulation
	 */

	if (irs->ipp->protocol == IPPROTO_ESP ||
			irs->ipp->protocol == IPPROTO_AH ||
#ifdef CONFIG_KLIPS_IPCOMP
			irs->ipp->protocol == IPPROTO_COMP ||
#endif /* CONFIG_KLIPS_IPCOMP */
			0) {
		irs->next_state = IPSEC_RSM_DECAP_INIT;
	}
	return IPSEC_RCV_OK;
}


static enum ipsec_rcv_value
ipsec_rcv_cleanup(struct ipsec_rcv_state *irs)
{
	struct sk_buff *skb;
	struct iphdr *ipp;
	struct in_addr ipsaddr;
	struct in_addr ipdaddr;
	struct ipsec_sa *ipsnext = NULL; /* next SA towards inside of packet */
	struct ipsec_sa *ipsp = NULL;

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);


	/* set up for decap loop */
	ipp  = irs->ipp;
	ipsp = irs->ipsp;
	ipsnext = ipsp->ips_inext;
	skb = irs->skb;

	/* if there is an IPCOMP, but we don't have an IPPROTO_COMP,
	 * then we can just skip it
	 */
#ifdef CONFIG_KLIPS_IPCOMP
	if(ipsnext && ipsnext->ips_said.proto == IPPROTO_COMP) {
		ipsp = ipsnext;
		ipsnext = ipsp->ips_inext;
	}
#endif /* CONFIG_KLIPS_IPCOMP */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if ((irs->natt_type) && (ipp->protocol != IPPROTO_IPIP)) {
	  /**
	   * NAT-Traversal and Transport Mode:
	   *   we need to correct TCP/UDP checksum
	   *
	   * If we've got NAT-OA, we can fix checksum without recalculation.
	   */
	  __u32 natt_oa = ipsp->ips_natt_oa ?
	    ((struct sockaddr_in*)(ipsp->ips_natt_oa))->sin_addr.s_addr : 0;
	  __u16 pkt_len = skb->tail - (unsigned char *)ipp;
	  __u16 data_len = pkt_len - (ipp->ihl << 2);
  	  
	  switch (ipp->protocol) {
	  case IPPROTO_TCP:
	    if (data_len >= sizeof(struct tcphdr)) {
	      struct tcphdr *tcp = skb->h.th;
	      if (natt_oa) {
		__u32 buff[2] = { ~natt_oa, ipp->saddr };
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: "
			    "fix TCP checksum using NAT-OA\n");
		tcp->check = csum_fold(
				       csum_partial((unsigned char *)buff, sizeof(buff),
						    tcp->check^0xffff));
	      }
	      else {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: recalc TCP checksum\n");
		if (pkt_len > (ntohs(ipp->tot_len)))
		  data_len -= (pkt_len - ntohs(ipp->tot_len));
		tcp->check = 0;
		tcp->check = csum_tcpudp_magic(ipp->saddr, ipp->daddr,
					       data_len, IPPROTO_TCP,
					       csum_partial((unsigned char *)tcp, data_len, 0));
	      }
  	    }
  	    else {
  	      KLIPS_PRINT(debug_rcv,
  			  "klips_debug:ipsec_rcv: "
			  "NAT-T & TRANSPORT: can't fix TCP checksum\n");
  	    }
	    break;
	  case IPPROTO_UDP:
	    if (data_len >= sizeof(struct udphdr)) {
	      struct udphdr *udp = skb->h.uh;
	      if (udp->check == 0) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: UDP checksum already 0\n");
	      }
	      else if (natt_oa) {
		__u32 buff[2] = { ~natt_oa, ipp->saddr };
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: "
			    "fix UDP checksum using NAT-OA\n");
		udp->check = csum_fold(
				       csum_partial((unsigned char *)buff, sizeof(buff),
						    udp->check^0xffff));
	      }
	      else {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: zero UDP checksum\n");
		udp->check = 0;
	      }
  	    }
  	    else {
  	      KLIPS_PRINT(debug_rcv,
  			  "klips_debug:ipsec_rcv: "
			  "NAT-T & TRANSPORT: can't fix UDP checksum\n");
  	    }
	    break;
	  default:
	    KLIPS_PRINT(debug_rcv,
			"klips_debug:ipsec_rcv: "
			"NAT-T & TRANSPORT: non TCP/UDP packet -- do nothing\n");
	    break;
  	  }
  	}
#endif
  
	KLIPS_PRINT(debug_rcv, "before ipip skb->len: %u tot_len: %u\n", skb->len, ntohs(irs->ipp->tot_len));

	/*
	 * XXX this needs to be locked from when it was first looked
	 * up in the decapsulation loop.  Perhaps it is better to put
	 * the IPIP decap inside the loop.
	 */
	if(ipsnext) {
		ipsp = ipsnext;
		irs->sa_len = KLIPS_SATOT(debug_rcv, &irs->said, 0, irs->sa, sizeof(irs->sa));
		if((ipp->protocol != IPPROTO_IPIP) && 
                   (ipp->protocol != IPPROTO_ATT_HEARTBEAT)) {  /* AT&T heartbeats to SIG/GIG */
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, Hey!  How did this get through?  Dropped.\n",
				    irs->sa_len ? irs->sa : " (error)");
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REALLYBAD;
		}
		if(sysctl_ipsec_inbound_policy_check) {
			struct sockaddr_in *psin = (struct sockaddr_in*)(ipsp->ips_addr_s);
			if((ipsnext = ipsp->ips_inext)) {
				char sa2[SATOT_BUF];
				size_t sa_len2;
				sa_len2 = KLIPS_SATOT(debug_rcv, &ipsnext->ips_said, 0, sa2, sizeof(sa2));
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "unexpected SA:%s after IPIP SA:%s\n",
					    sa_len2 ? sa2 : " (error)",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				return IPSEC_RCV_FAILEDINBOUND;
			}
			if(ipp->saddr != psin->sin_addr.s_addr) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "SA:%s, src=%s(%08x) does not match expected 0x%08x.\n",
					    irs->sa_len ? irs->sa : " (error)",
					    irs->ipsaddr_txt, 
					    ipp->saddr, psin->sin_addr.s_addr);
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				return IPSEC_RCV_FAILEDINBOUND;
			}
		}

		if(ipp->protocol == IPPROTO_IPIP)  /* added to support AT&T heartbeats to SIG/GIG */
		{  
			/*
			 * XXX this needs to be locked from when it was first looked
			 * up in the decapsulation loop.  Perhaps it is better to put
			 * the IPIP decap inside the loop.
			 */
			ipsp->ips_life.ipl_bytes.ipl_count += skb->len;
			ipsp->ips_life.ipl_bytes.ipl_last   = skb->len;
			
			if(!ipsp->ips_life.ipl_usetime.ipl_count) {
				ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
			}
			ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
			ipsp->ips_life.ipl_packets.ipl_count += 1;
			
			if(skb->len < irs->iphlen) {
				printk(KERN_WARNING "klips_debug:ipsec_rcv: "
				       "tried to skb_pull iphlen=%d, %d available.  This should never happen, please report.\n",
				       irs->iphlen,
				       (int)(skb->len));
				
				return IPSEC_RCV_REALLYBAD;
			}
			
			/*
			 * we need to pull up by size of IP header,
			 * options, but also by any UDP/ESP encap there might
			 * have been, and this deals with all cases.
			 */
			skb_pull(skb, (skb->h.raw - skb->nh.raw));
			
			/* new L3 header is where L4 payload was */
			skb->nh.raw = skb->h.raw;
			
			/* now setup new L4 payload location */
			ipp = (struct iphdr *)skb->nh.raw;
			skb->h.raw = skb->nh.raw + (ipp->ihl << 2);
			
			
			/* remove any saved options that we might have,
			 * since we have a new IP header.
			 */
			memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
			
#if 0
			KLIPS_PRINT(debug_rcv, "csum: %d\n", ip_fast_csum((u8 *)ipp, ipp->ihl));
#endif
			
			/* re-do any strings for debugging */
			ipsaddr.s_addr = ipp->saddr;
			if (debug_rcv)
				addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
			ipdaddr.s_addr = ipp->daddr;
			if (debug_rcv)
				addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));
			
			skb->protocol = htons(ETH_P_IP);
			skb->ip_summed = 0;
			KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
				    "klips_debug:ipsec_rcv: "
				    "IPIP tunnel stripped.\n");
			KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);
		}

		if(sysctl_ipsec_inbound_policy_check
		   /*
		      Note: "xor" (^) logically replaces "not equal"
		      (!=) and "bitwise or" (|) logically replaces
		      "boolean or" (||).  This is done to speed up
		      execution by doing only bitwise operations and
		      no branch operations
		   */
		   && (((ipp->saddr & ipsp->ips_mask_s.u.v4.sin_addr.s_addr)
				    ^ ipsp->ips_flow_s.u.v4.sin_addr.s_addr)
		       | ((ipp->daddr & ipsp->ips_mask_d.u.v4.sin_addr.s_addr)
				      ^ ipsp->ips_flow_d.u.v4.sin_addr.s_addr)) )
		{
			char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];

			subnettoa(ipsp->ips_flow_s.u.v4.sin_addr,
				ipsp->ips_mask_s.u.v4.sin_addr,
				0, sflow_txt, sizeof(sflow_txt));
			subnettoa(ipsp->ips_flow_d.u.v4.sin_addr,
				ipsp->ips_mask_d.u.v4.sin_addr,
				0, dflow_txt, sizeof(dflow_txt));
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, inner tunnel policy [%s -> %s] does not agree with pkt contents [%s -> %s].\n",
				    irs->sa_len ? irs->sa : " (error)",
				    sflow_txt,
				    dflow_txt,
				    irs->ipsaddr_txt,
				    irs->ipdaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REALLYBAD;
		}
#ifdef CONFIG_NETFILTER
		skb->nfmark = (skb->nfmark & (~(IPsecSAref2NFmark(IPSEC_SA_REF_TABLE_MASK))))
			| IPsecSAref2NFmark(IPsecSA2SAref(ipsp));
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "IPIP SA sets skb->nfmark=0x%x.\n",
			    (unsigned)skb->nfmark);
#endif /* CONFIG_NETFILTER */
	}

	if(irs->stats) {
		irs->stats->rx_bytes += skb->len;
	}
	if(skb->dst) {
		dst_release(skb->dst);
		skb->dst = NULL;
	}
	KLIPS_PRINT(debug_rcv, "skb->len: %u tot_len: %u\n", skb->len, ntohs(irs->ipp->tot_len));
	//skb->len = ntohs(irs->ipp->tot_len);

	skb->pkt_type = PACKET_HOST;
	if(irs->hard_header_len &&
	   (skb->mac.raw != (skb->nh.raw - irs->hard_header_len)) &&
	   (irs->hard_header_len <= skb_headroom(skb))) {
		/* copy back original MAC header */
		memmove(skb->nh.raw - irs->hard_header_len,
			skb->mac.raw, irs->hard_header_len);
		skb->mac.raw = skb->nh.raw - irs->hard_header_len;
	}
	return IPSEC_RCV_OK;
}


static enum ipsec_rcv_value
ipsec_rcv_ipcomp(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

#ifdef CONFIG_KLIPS_IPCOMP
	if(irs->ipp->protocol == IPPROTO_COMP) {
		unsigned int flags = 0;

		if(sysctl_ipsec_inbound_policy_check) {
			KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
				"klips_debug:ipsec_rcv: "
				"inbound policy checking enabled, IPCOMP follows IPIP, dropped.\n");
			if (irs->stats) {
				irs->stats->rx_errors++;
			}
			return IPSEC_RCV_IPCOMPFAILED;
		}
		/*
		  XXX need a ipsec_sa for updating ratio counters but it is not
		  following policy anyways so it is not a priority
		*/
		irs->skb = skb_decompress(irs->skb, NULL, &flags);
		if (!irs->skb || flags) {
			KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
				"klips_debug:ipsec_rcv: "
				"skb_decompress() returned error flags: %d, dropped.\n",
				flags);
			if (irs->stats) {
				irs->stats->rx_errors++;
			}
			return IPSEC_RCV_IPCOMPFAILED;
		}
	}
#endif /* CONFIG_KLIPS_IPCOMP */
	return IPSEC_RCV_OK;
}


static enum ipsec_rcv_value
ipsec_rcv_complete(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
			irs->state, irs->next_state);

	/*
	 * make sure that data now starts at IP header, since we are going
	 * to pass this back to ip_input (aka netif_rx). Rules for what the
	 * pointers wind up a different for 2.6 vs 2.4, so we just fudge it here.
	 */
#ifdef NET_26
	irs->skb->data = skb_push(irs->skb, irs->skb->h.raw - irs->skb->nh.raw);
#else
	irs->skb->data = irs->skb->nh.raw;
	{
	  struct iphdr *iph = irs->skb->nh.iph;
	  int len = ntohs(iph->tot_len);
	  irs->skb->len  = len;
	}
#endif

#ifdef SKB_RESET_NFCT
	nf_conntrack_put(irs->skb->nfct);
	irs->skb->nfct = NULL;
#if defined(CONFIG_NETFILTER_DEBUG) && defined(HAVE_SKB_NF_DEBUG)
	irs->skb->nf_debug = 0;
#endif /* CONFIG_NETFILTER_DEBUG */
#endif /* SKB_RESET_NFCT */
	if(irs->ipsp) ipsec_sa_put(irs->ipsp);
	irs->ipsp=NULL;

	ipsec_netif_called++;
	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "netif_rx() called.\n");
	netif_rx(irs->skb);
	irs->skb=NULL;

	return IPSEC_RCV_OK;
}

/* management of buffers */
static struct ipsec_rcv_state * ipsec_rcv_state_new (void);
static void ipsec_rcv_state_delete (struct ipsec_rcv_state *irs);

/*
 * ipsec_rsm is responsible for walking us through the state machine
 * it is the only entry point into the receive processing and does
 * appropriate checks and state changes for us.
 */

void
ipsec_rsm(struct ipsec_rcv_state *irs)
{
	rsm_calls++;
	if (irs == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rsm: "
			    "irs == NULL.\n");
		rsm_exit1++;
		return;
	}

	/*
	 * make sure nothing is removed from underneath us
	 */
	spin_lock_bh(&tdb_lock);

	KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_rsm(%p)\n",irs);

#if 0
	{
	/*
	 * XXX - but sa's are refcounted. (MCR)
	 *
	 * if we have a valid said,  then we must check it here to ensure it
	 * hasn't gone away while we were waiting for a task to complete
	 */
	struct ipsec_sa *ips;

	ips = ipsec_sa_getbyid(&irs->said);
	if (irs->said.proto && ips == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "no ipsec_sa for SA:%s: incoming packet with no SA dropped\n",
			    irs->sa_len ? irs->sa : " (error)");
		if (irs->stats)
			irs->stats->rx_dropped++;

		/* drop through and cleanup */
		irs->state = IPSEC_RSM_DONE;
	}
	if(ips) ipsec_sa_put(ips);
	ips=NULL;
	}
#endif

	while (irs->state != IPSEC_RSM_DONE) {
		int rc;

		irs->next_state = rcv_state_table[irs->state].next_state;

		rc = rcv_state_table[irs->state].action(irs);

		if (rc == IPSEC_RCV_OK) {
			/* some functions change the next state, see the state table */
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rsm: (%p) changing state from %u to %u\n", irs, irs->state, irs->next_state);

			irs->state = irs->next_state;
		} else if (rc == IPSEC_RCV_PENDING) {
			/*
			 * things are on hold until we return here in the next/new state
			 * we check our SA is valid when we return
			 */
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rsm: (%p) processing suspended at state=%u\n", irs, irs->state);

			spin_unlock_bh(&tdb_lock);

			rsm_exit2++;
			return;
		} else {
			/* bad result, force state change to done */
			KLIPS_PRINT(debug_rcv,
					"klips_debug:ipsec_rsm: processing irs->state=%d "
                                        "completed due to error %d.\n", irs->state, rc);
			irs->state = IPSEC_RSM_DONE;
		}
	}

	/*
	 * all done with anything needing locks
	 */
	spin_unlock_bh(&tdb_lock);

	if (irs->skb) {
		ipsec_kfree_skb(irs->skb);
		irs->skb = NULL;
	}
        ipsec_rcv_state_delete (irs);

	rsm_exit4++;
	KLIPS_DEC_USE; /* once less packet using the driver */
}

int
ipsec_rcv(struct sk_buff *skb
#ifndef PROTO_HANDLER_SINGLE_PARM
	  unsigned short xlen
#endif /* PROTO_HANDLER_SINGLE_PARM */
	  )
{
	struct ipsec_rcv_state *irs = NULL;

	/* Don't unlink in the middle of a turnaround */
	KLIPS_INC_USE;

#ifdef CONFIG_KLIPS_DEBUG
	if(debug_rcv_once) {
		debug_rcv=0;
		debug_ocf=0;
		debug_xform=0;
		debug_eroute=0;
		debug_spi=0;
		debug_netlink=0;
		debug_radij=0;
		debug_esp=0;
		debug_tunnel=0;
		if(debug_rcv_once==1) {
			debug_rcv=0xffffffff;
			debug_ocf=0xffffffff;
			debug_xform=0xffffffff;
			debug_eroute=0xffffffff;
			debug_spi=0xffffffff;
			debug_netlink=0xffffffff;
			debug_radij=0xffffffff;
			debug_esp=0xffffffff;
			debug_tunnel=0xffffffff;
			debug_rcv_once=2;
		}
	}
#endif

	ipsec_rcv_packets++;

	if (skb == NULL) {
		KLIPS_RATEDEBUG(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb passed in.\n");
		goto error_no_skb;
	}

	if (skb->data == NULL) {
		KLIPS_RATEDEBUG(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		goto error_bad_skb;
	}

        irs = ipsec_rcv_state_new ();
        if (unlikely (! irs)) {
		KLIPS_RATEDEBUG(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "failed to allocate a rcv state object (skb->users=%u)\n",
			    atomic_read(&skb->users));
                goto error_alloc;
        }

#if defined(CONFIG_IPSEC_NAT_TRAVERSAL) && !defined(NET_26)
	{
  		/* NET_26 NAT-T is handled by seperate function */
  		struct sk_buff *nskb;
		int udp_decap_ret = 0;

		nskb = ipsec_rcv_natt_decap(skb, irs, &udp_decap_ret);
  		if(nskb == NULL) {
			/* return with non-zero, because UDP.c code
			 * need to send it upstream.
			 */
			if(skb && udp_decap_ret == 0) {
				ipsec_kfree_skb(skb);
			}
			if (irs) {
                                ipsec_rcv_state_delete (irs);
			}
			KLIPS_DEC_USE;
			return(udp_decap_ret);
  		}
  		skb = nskb;
	}
#endif /* NAT_T */


  	irs->skb = skb;
  
	/*
	 * we hand off real early to the state machine because we just cannot
	 * know how much processing it is off-loading
	 */
	ipsec_rsm(irs);

  	return(0);

error_alloc:
error_bad_skb:
        ipsec_kfree_skb(skb);

error_no_skb:

	KLIPS_DEC_USE;
	rcv_exitbad++;
	return(0);

}

#ifdef NET_26
/*
 * this entry point is not a protocol entry point, so the entry
 * is a bit different.
 *
 * skb->iph->tot_len has been byte-swapped, and reduced by the size of
 *              the IP header (and options).
 * 
 * skb->h.raw has been pulled up the ESP header.
 *
 * skb->iph->protocol = 50 IPPROTO_ESP;
 *
 */
int klips26_rcv_encap(struct sk_buff *skb, __u16 encap_type)
{
	struct ipsec_rcv_state *irs = NULL;

	/* Don't unlink in the middle of a turnaround */
	KLIPS_INC_USE;

        irs = ipsec_rcv_state_new ();
        if (unlikely (! irs)) {
		KLIPS_ERROR(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "failed to allocate a rcv state object\n");
                goto error_alloc;
        }

	/* XXX fudge it so that all nat-t stuff comes from ipsec0    */
	/*     eventually, the SA itself will determine which device
	 *     it comes from
	 */ 
	{
	  skb->dev = ipsec_get_device(0);
	}
	irs->hard_header_len = skb->dev->hard_header_len;

	skb = ipsec_rcv_unclone(skb, irs);

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	switch(encap_type) {
	case UDP_ENCAP_ESPINUDP:
	  irs->natt_type = ESPINUDP_WITH_NON_ESP;
	  break;
	  
	case UDP_ENCAP_ESPINUDP_NON_IKE:
	  irs->natt_type = ESPINUDP_WITH_NON_IKE;
	  break;
	  
	default:
	  if(printk_ratelimit()) {
	    printk(KERN_INFO "KLIPS received unknown UDP-ESP encap type %u\n",
		   encap_type);
	  }
	  goto rcvleave;
	}

#endif
	irs->skb = skb;

	/*
	 * we hand off real early to the state machine because we just cannot
	 * know how much processing it is off-loading
	 */
	ipsec_rsm(irs);

	/* empty any saved SKBs */
	ipsec_skb_gc_flush();

	return(0);

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
rcvleave:
	if(skb) {
		ipsec_kfree_skb(skb);
	}
        ipsec_rcv_state_delete (irs);
#endif
error_alloc:
	/* empty any saved SKBs */
	ipsec_skb_gc_flush();

	KLIPS_DEC_USE;
	return 0;
}
#endif

// ------------------------------------------------------------------------
// this handles creating and managing state for recv path

static spinlock_t irs_cache_lock = SPIN_LOCK_UNLOCKED;
static kmem_cache_t *irs_cache_allocator = NULL;

int
ipsec_rcv_state_cache_init (void)
{
        if (irs_cache_allocator)
                return -EBUSY;

        spin_lock_init(&irs_cache_lock);

        irs_cache_allocator = kmem_cache_create ("ipsec_irs",
                sizeof (struct ipsec_rcv_state), 0,
                0, NULL, NULL);
        if (! irs_cache_allocator)
                return -ENOMEM;

        return 0;
}

void
ipsec_rcv_state_cache_cleanup (void)
{
        if (unlikely (irs_cache_allocated_count))
                printk ("ipsec: deleting ipsec_irs kmem_cache while in use\n");

        if (irs_cache_allocator) {
                kmem_cache_destroy (irs_cache_allocator);
                irs_cache_allocator = NULL;
        }
        irs_cache_allocated_count = 0;
}

static struct ipsec_rcv_state *
ipsec_rcv_state_new (void)
{
	struct ipsec_rcv_state *irs = NULL;
	static int irs_last_declined=-1;

        spin_lock_bh (&irs_cache_lock);

	irs_requested++;
        if (likely (irs_cache_allocated_count >= ipsec_irs_max)) {
		KLIPS_RATEDEBUG(debug_rcv,
			    "klips_debug:ipsec_rcv_state_new: "
			    "exceeded outstanding RX packet cnt %d\n", ipsec_irs_max);
		/* if we declined in a row! */
		if(irs_last_declined == (irs_requested-1)) {
			irs_declined_in_a_row++;
			irs_in_a_row++;
			if(irs_in_a_row > irs_declined_max_in_a_row)
				irs_declined_max_in_a_row=irs_in_a_row;
		} else {
			irs_in_a_row=0;
		}
			
		irs_declined++;
		irs_last_declined=irs_requested;

		{
			extern int cryptoproc_generation;
			static int last_generation=-1;

			if(last_generation == cryptoproc_generation) {
				irs_declined_while_proc_blocked++;
			} else {
				KLIPS_RATEDEBUG(debug_rcv, "proc generation: %u -> %u\n",
					    last_generation, cryptoproc_generation);
			}

			last_generation = cryptoproc_generation;
		}

	} else {
                irs = kmem_cache_alloc (irs_cache_allocator, GFP_ATOMIC);
                if (likely (irs != NULL)) irs_cache_allocated_count++;
		else irs_alloc_failed++;
        }		


        spin_unlock_bh (&irs_cache_lock);

        if (unlikely (NULL == irs))
                goto bail;

        // initialize the object
#if 0 /* optimised to only clear the essentials */
        memset((caddr_t)irs, 0, sizeof(*irs));
#else
	irs->ipsp = NULL;
	irs->state = 0;
	irs->next_state = 0;
	irs->stats = NULL;
	irs->authenticator = NULL;
	irs->said.proto = 0;
	irs->hard_header_len = 0;
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	irs->natt_type = 0;
	irs->natt_len = 0;
#endif
#endif

bail:
        return irs;
}

static void
ipsec_rcv_state_delete (struct ipsec_rcv_state *irs)
{
        if (unlikely (! irs))
                return;

	if(irs->ipsp) 
		ipsec_sa_put(irs->ipsp);

	irs->ipsp=NULL;
		
        spin_lock_bh (&irs_cache_lock);

        irs_cache_allocated_count--;
        kmem_cache_free (irs_cache_allocator, irs);

        spin_unlock_bh (&irs_cache_lock);
}

/*
 * Local Variables:
 * c-set-style: linux
 * End:
 *
 */
