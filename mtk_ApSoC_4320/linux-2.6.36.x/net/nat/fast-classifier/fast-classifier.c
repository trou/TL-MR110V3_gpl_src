/*
 * fast-classifier.c
 *	Shortcut forwarding engine connection manager.
 *	fast-classifier style
 *
 * Copyright (c) 2013-2016 The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/dsfield.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv6.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/netfilter/xt_dscp.h>
#include <net/genetlink.h>
#include <linux/spinlock.h>
#include <linux/if_bridge.h>

#include <sfe_backport.h>
#include <sfe.h>
#include <sfe_cm.h>
#include "fast-classifier.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0))
#include <hashtable.h>
#else
#include "hashtable.h"
#endif

#ifdef PRINT_CYCLES
#include "../core/cycles.h"
static struct cycles_counter fast_classifier_recv_cycles = {.total = 0, .cnt = 0, .average = 0, .lock = __SPIN_LOCK_UNLOCKED(fast_classifier_recv_cycles.lock)};
#endif

/*
 * Per-module structure.
 */
struct fast_classifier {
	spinlock_t lock;		/* Lock for SMP correctness */

	/*
	 * Control state.
	 */
	struct kobject *sys_fast_classifier;	/* sysfs linkage */

	/*
	 * Callback notifiers.
	 */
	struct notifier_block dev_notifier;
					/* Device notifier */
	struct notifier_block inet_notifier;
					/* IPv4 notifier */
	struct notifier_block inet6_notifier;
					/* IPv6 notifier */
};

struct fast_classifier __sc;

static struct nla_policy fast_classifier_genl_policy[FAST_CLASSIFIER_A_MAX + 1] = {
	[FAST_CLASSIFIER_A_TUPLE] = { .type = NLA_UNSPEC,
				      .len = sizeof(struct fast_classifier_tuple)
				    },
};

static struct genl_multicast_group fast_classifier_genl_mcgrp[] = {
	{
		.name = FAST_CLASSIFIER_GENL_MCGRP,
	},
};

static struct genl_family fast_classifier_gnl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = FAST_CLASSIFIER_GENL_HDRSIZE,
	.name = FAST_CLASSIFIER_GENL_NAME,
	.version = FAST_CLASSIFIER_GENL_VERSION,
	.maxattr = FAST_CLASSIFIER_A_MAX,
};

static int fast_classifier_offload_genl_msg(struct sk_buff *skb, struct genl_info *info);
static int fast_classifier_nl_genl_msg_DUMP(struct sk_buff *skb, struct netlink_callback *cb);

static struct genl_ops fast_classifier_gnl_ops[] = {
	{
		.cmd = FAST_CLASSIFIER_C_OFFLOAD,
		.flags = 0,
		.policy = fast_classifier_genl_policy,
		.doit = fast_classifier_offload_genl_msg,
		.dumpit = NULL,
	},
	{
		.cmd = FAST_CLASSIFIER_C_OFFLOADED,
		.flags = 0,
		.policy = fast_classifier_genl_policy,
		.doit = NULL,
		.dumpit = fast_classifier_nl_genl_msg_DUMP,
	},
	{
		.cmd = FAST_CLASSIFIER_C_DONE,
		.flags = 0,
		.policy = fast_classifier_genl_policy,
		.doit = NULL,
		.dumpit = fast_classifier_nl_genl_msg_DUMP,
	},
};

atomic_t offload_msgs = ATOMIC_INIT(0);
atomic_t offload_no_match_msgs = ATOMIC_INIT(0);
atomic_t offloaded_msgs = ATOMIC_INIT(0);
atomic_t done_msgs = ATOMIC_INIT(0);

atomic_t offloaded_fail_msgs = ATOMIC_INIT(0);
atomic_t done_fail_msgs = ATOMIC_INIT(0);

/*
 * Expose the hook for the receive processing.
 */
extern int (*athrs_fast_nat_recv)(struct sk_buff *skb);

/*
 * Expose what should be a static flag in the TCP connection tracker.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
extern int nf_ct_tcp_no_window_check;
#else
int nf_ct_tcp_no_window_check = 0;
#endif

#if (SFE_HOOK_ABOVE_BRIDGE)
/*
 * Accelerate incoming packets destined for bridge device
 * 	If a incoming packet is ultimatly destined for
 * 	a bridge device we will first see the packet coming
 * 	from the phyiscal device, we can skip straight to
 * 	processing the packet like it came from the bridge
 * 	for some more performance gains
 *
 * 	This only works when the hook is above the bridge. We
 * 	only implement ingress for now, because for egress we
 * 	want to have the bridge devices qdiscs be used.
 */
static bool skip_to_bridge_ingress;
#endif

/*
 * fast_classifier_recv()
 *	Handle packet receives.
 *
 * Returns 1 if the packet is forwarded or 0 if it isn't.
 */
int fast_classifier_recv(struct sk_buff *skb)
{
	struct net_device *dev;
#if (SFE_HOOK_ABOVE_BRIDGE)
	struct net_device *master_dev = NULL;
#endif
	int ret = 0;

#ifdef PRINT_CYCLES
	unsigned long long cycles_start, cycles_end;
	cycles_start = get_cyclescount();
#endif

	/*
	 * We know that for the vast majority of packets we need the transport
	 * layer header so we may as well start to fetch it now!
	 */
	prefetch(skb->data + 32);
	barrier();

	dev = skb->dev;

#if (SFE_HOOK_ABOVE_BRIDGE)
	/*
	 * Process packet like it arrived on the bridge device
	 */
	if (skip_to_bridge_ingress &&
	   (dev->priv_flags & IFF_BRIDGE_PORT)) {
		master_dev = sfe_dev_get_master(dev);
		if (master_dev) {
			dev = master_dev;
		}
	}
#endif

	/*
	 * We're only interested in IPv4 and IPv6 packets.
	 */
	if (likely(htons(ETH_P_IP) == skb->protocol)) {
#if (SFE_HOOK_ABOVE_BRIDGE)
		struct in_device *in_dev;

		/*
		 * Does our input device support IP processing?
		 */
		in_dev = (struct in_device *)dev->ip_ptr;
		if (unlikely(!in_dev)) {
			DEBUG_TRACE("no IP processing for device: %s\n", dev->name);
			goto rx_exit;
		}

		/*
		 * Does it have an IP address?  If it doesn't then we can't do anything
		 * interesting here!
		 */
		if (unlikely(!in_dev->ifa_list)) {
			DEBUG_TRACE("no IP address for device: %s\n", dev->name);
			goto rx_exit;
		}
#endif

#ifdef PRINT_CYCLES
		cycles_end = get_cyclescount();
		if (cycles_end > cycles_start) {
			cycles_update_bh(&fast_classifier_recv_cycles, cycles_end - cycles_start);
		}
#endif
		ret = sfe_ipv4_recv(dev, skb);

	} else if (likely(htons(ETH_P_IPV6) == skb->protocol)) {
#if (SFE_HOOK_ABOVE_BRIDGE)
		struct inet6_dev *in_dev;

		/*
		 * Does our input device support IPv6 processing?
		 */
		in_dev = (struct inet6_dev *)dev->ip6_ptr;
		if (unlikely(!in_dev)) {
			DEBUG_TRACE("no IPv6 processing for device: %s\n", dev->name);
			goto rx_exit;
		}

		/*
		 * Does it have an IPv6 address?  If it doesn't then we can't do anything
		 * interesting here!
		 */
		if (unlikely(list_empty(&in_dev->addr_list))) {
			DEBUG_TRACE("no IPv6 address for device: %s\n", dev->name);
			goto rx_exit;
		}
#endif

#ifdef PRINT_CYCLES
		cycles_end = get_cyclescount();
		if (cycles_end > cycles_start) {
			cycles_update_bh(&fast_classifier_recv_cycles, cycles_end - cycles_start);
		}
#endif
		ret = sfe_ipv6_recv(dev, skb);

	} else {
		DEBUG_TRACE("not IP packet\n");
	}

rx_exit:
#if (SFE_HOOK_ABOVE_BRIDGE)
	if (master_dev) {
		dev_put(master_dev);
	}
#endif
	return ret;
}

/*
 * fast_classifier_find_dev_and_mac_addr()
 *	Find the device and MAC address for a given IPv4 address.
 *
 * Returns true if we find the device and MAC address, otherwise false.
 *
 * We look up the rtable entry for the address and, from its neighbour
 * structure, obtain the hardware address.  This means this function also
 * works if the neighbours are routers too.
 */
static bool fast_classifier_find_dev_and_mac_addr(sfe_ip_addr_t *addr, struct net_device **dev, uint8_t *mac_addr, bool is_v4)
{
	struct neighbour *neigh;
	struct rtable *rt;
	struct rt6_info *rt6;
	struct dst_entry *dst;
	struct net_device *mac_dev;

	/*
	 * Look up the rtable entry for the IP address then get the hardware
	 * address from its neighbour structure.  This means this work when the
	 * neighbours are routers too.
	 */
	if (likely(is_v4)) {
		rt = sfe_ip_route_output(&init_net, addr->ip, 0, 0, 0);
		if (unlikely(IS_ERR(rt))) {
			goto ret_fail;
		}

		dst = (struct dst_entry *)rt;
	} else {
		rt6 = rt6_lookup(&init_net, (struct in6_addr *)addr->ip6, 0, 0, 0);
		if (!rt6) {
			goto ret_fail;
		}

		dst = (struct dst_entry *)rt6;
	}

	rcu_read_lock();
	neigh = sfe_dst_neigh_lookup(dst, addr);
	if (unlikely(!neigh)) {
		rcu_read_unlock();
		dst_release(dst);
		goto ret_fail;
	}

	if (unlikely(!(neigh->nud_state & NUD_VALID))) {
		rcu_read_unlock();
		neigh_release(neigh);
		dst_release(dst);
		goto ret_fail;
	}

	mac_dev = neigh->dev;
	if (!mac_dev) {
		rcu_read_unlock();
		neigh_release(neigh);
		dst_release(dst);
		goto ret_fail;
	}

	memcpy(mac_addr, neigh->ha, (size_t)mac_dev->addr_len);

	dev_hold(mac_dev);
	*dev = mac_dev;
	rcu_read_unlock();
	neigh_release(neigh);
	dst_release(dst);

	return true;

ret_fail:
	if (is_v4) {
		DEBUG_TRACE("failed to find MAC address for IP: %pI4\n", addr);

	} else {
		DEBUG_TRACE("failed to find MAC address for IP: %pI6\n", addr);
	}

	return false;
}

static DEFINE_SPINLOCK(sfe_connections_lock);

struct sfe_connection {
	struct hlist_node hl;
	struct sfe_connection_create *sic;
	struct nf_conn *ct;
	int hits;
	int offloaded;
	bool is_v4;
	unsigned char smac[ETH_ALEN];
	unsigned char dmac[ETH_ALEN];
};
static int sfe_connections_size;

#define FC_CONN_HASH_ORDER 13
static DEFINE_HASHTABLE(fc_conn_ht, FC_CONN_HASH_ORDER);

static u32 fc_conn_hash(sfe_ip_addr_t *saddr, sfe_ip_addr_t *daddr,
			unsigned short sport, unsigned short dport, bool is_v4)
{
	uint32_t idx, cnt = (is_v4 ? sizeof(saddr->ip) : sizeof(saddr->ip6))/sizeof(uint32_t);
	uint32_t hash = 0;

	for (idx = 0; idx < cnt; idx++) {
		hash ^= ((uint32_t *)saddr)[idx] ^ ((uint32_t *)daddr)[idx];
	}

	return hash ^ (sport | (dport << 16));
}

/*
 * fast_classifier_update_protocol()
 * 	Update sfe_ipv4_create struct with new protocol information before we offload
 */
static int fast_classifier_update_protocol(struct sfe_connection_create *p_sic, struct nf_conn *ct)
{
	switch (p_sic->protocol) {
	case IPPROTO_TCP:
		p_sic->src_td_window_scale = ct->proto.tcp.seen[0].td_scale;
		p_sic->src_td_max_window = ct->proto.tcp.seen[0].td_maxwin;
		p_sic->src_td_end = ct->proto.tcp.seen[0].td_end;
		p_sic->src_td_max_end = ct->proto.tcp.seen[0].td_maxend;
		p_sic->dest_td_window_scale = ct->proto.tcp.seen[1].td_scale;
		p_sic->dest_td_max_window = ct->proto.tcp.seen[1].td_maxwin;
		p_sic->dest_td_end = ct->proto.tcp.seen[1].td_end;
		p_sic->dest_td_max_end = ct->proto.tcp.seen[1].td_maxend;
		if (nf_ct_tcp_no_window_check
		    || (ct->proto.tcp.seen[0].flags & IP_CT_TCP_FLAG_BE_LIBERAL)
		    || (ct->proto.tcp.seen[1].flags & IP_CT_TCP_FLAG_BE_LIBERAL)) {
			p_sic->flags |= SFE_CREATE_FLAG_NO_SEQ_CHECK;
		}

		/*
		 * If the connection is shutting down do not manage it.
		 * state can not be SYN_SENT, SYN_RECV because connection is assured
		 * Not managed states: FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSE.
		 */
		spin_lock(&ct->lock);
		if (ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) {
			spin_unlock(&ct->lock);
			DEBUG_TRACE("connection in termination state: %#x, s: %pI4:%u, d: %pI4:%u\n",
				    ct->proto.tcp.state, &p_sic->src_ip, ntohs(p_sic->src_port),
				    &p_sic->dest_ip, ntohs(p_sic->dest_port));
			return 0;
		}
		spin_unlock(&ct->lock);
		break;

	case IPPROTO_UDP:
		break;

	default:
		DEBUG_TRACE("unhandled protocol %d\n", p_sic->protocol);
		return 0;
	}

	return 1;
}

/* fast_classifier_send_genl_msg()
 * 	Function to send a generic netlink message
 */
static void fast_classifier_send_genl_msg(int msg, struct fast_classifier_tuple *fc_msg)
{
	struct sk_buff *skb;
	int rc;
	void *msg_head;

	skb = genlmsg_new(sizeof(*fc_msg) + fast_classifier_gnl_family.hdrsize,
			  GFP_ATOMIC);
	if (skb == NULL)
		return;

	msg_head = genlmsg_put(skb, 0, 0, &fast_classifier_gnl_family, 0, msg);
	if (msg_head == NULL) {
		nlmsg_free(skb);
		return;
	}

	rc = nla_put(skb, FAST_CLASSIFIER_A_TUPLE, sizeof(struct fast_classifier_tuple), fc_msg);
	if (rc != 0) {
		genlmsg_cancel(skb, msg_head);
		nlmsg_free(skb);
		return;
	}

	rc = genlmsg_end(skb, msg_head);
	if (rc < 0) {
		genlmsg_cancel(skb, msg_head);
		nlmsg_free(skb);
		return;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0))
	rc = genlmsg_multicast(&fast_classifier_gnl_family, skb, 0, 0, GFP_ATOMIC);
#else
	rc = genlmsg_multicast(skb, 0, fast_classifier_genl_mcgrp[0].id, GFP_ATOMIC);
#endif
	switch (msg) {
	case FAST_CLASSIFIER_C_OFFLOADED:
		if (rc == 0) {
			atomic_inc(&offloaded_msgs);
		} else {
			atomic_inc(&offloaded_fail_msgs);
		}
		break;
	case FAST_CLASSIFIER_C_DONE:
		if (rc == 0) {
			atomic_inc(&done_msgs);
		} else {
			atomic_inc(&done_fail_msgs);
		}
		break;
	default:
		DEBUG_ERROR("fast-classifer: Unknown message type sent!\n");
		break;
	}

	DEBUG_TRACE("Notify NL message %d ", msg);
	if (fc_msg->ethertype == AF_INET) {
		DEBUG_TRACE("sip=%pI4 dip=%pI4 ", &(fc_msg->src_saddr), &(fc_msg->dst_saddr));
	} else {
		DEBUG_TRACE("sip=%pI6 dip=%pI6 ", &(fc_msg->src_saddr), &(fc_msg->dst_saddr));
	}
	DEBUG_TRACE("protocol=%d sport=%d dport=%d smac=%pM dmac=%pM\n",
		    fc_msg->proto, fc_msg->sport, fc_msg->dport, fc_msg->smac, fc_msg->dmac);
}

/*
 * fast_classifier_find_conn()
 * 	find a connection object in the hash table
 *      @pre the sfe_connection_lock must be held before calling this function
 */
static struct sfe_connection *
fast_classifier_find_conn(sfe_ip_addr_t *saddr, sfe_ip_addr_t *daddr,
			  unsigned short sport, unsigned short dport,
			  unsigned char proto, bool is_v4)
{
	struct sfe_connection_create *p_sic;
	struct sfe_connection *conn;
	uint32_t key;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
	struct hlist_node *node;
#endif

	key = fc_conn_hash(saddr, daddr, sport, dport, is_v4);

	sfe_hash_for_each_possible(fc_conn_ht, conn, node, hl, key) {
		if (conn->is_v4 != is_v4) {
			continue;
		}

		p_sic = conn->sic;
		
		if (p_sic->protocol == proto &&
		    p_sic->src_port == sport &&
		    p_sic->dest_port == dport &&
		    sfe_addr_equal(&p_sic->src_ip, saddr, is_v4) &&
		    sfe_addr_equal(&p_sic->dest_ip, daddr, is_v4)) {
			return conn;
		}
	}

	DEBUG_TRACE("connection not found\n");
	return NULL;
}

/*
 * fast_classifier_destroy_all_conns()
 * 	Destroy connections in fc_conn_ht that match a particular device.
 *  If we pass dev as NULL then this destroys all connections.
 */
static void fast_classifier_destroy_all_conns(struct net_device *dev)
{
	u32 bkt;
	struct sfe_connection *conn;
	struct hlist_node *tmp;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
	struct hlist_node *node;
#endif

	spin_lock_bh(&sfe_connections_lock);
	sfe_hash_for_each_safe(fc_conn_ht, bkt, node, tmp, conn, hl) {
		if (!dev
		    || (dev == conn->sic->src_dev)
		    || (dev == conn->sic->dest_dev)) {
			kfree(conn->sic);
			hash_del(&conn->hl);
			sfe_connections_size--;
			kfree(conn);
		}	
	}
	spin_unlock_bh(&sfe_connections_lock);
}

/*
 * fast_classifier_offload_genl_msg()
 * 	Called from user space to offload a connection
 */
static int
fast_classifier_offload_genl_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret;
	struct nlattr *na;
	struct fast_classifier_tuple *fc_msg;
	struct sfe_connection *conn;

	na = info->attrs[FAST_CLASSIFIER_A_TUPLE];
	fc_msg = nla_data(na);

	DEBUG_TRACE((fc_msg->ethertype == AF_INET ?
		"want to offload: %d-%d, %pI4, %pI4, %d, %d SMAC=%pM DMAC=%pM\n" :
		"want to offload: %d-%d, %pI6, %pI6, %d, %d SMAC=%pM DMAC=%pM\n"),
		    fc_msg->ethertype,
		    fc_msg->proto,
		    &(fc_msg->src_saddr),
		    &(fc_msg->dst_saddr),
		    fc_msg->sport,
		    fc_msg->dport,
		    fc_msg->smac,
		    fc_msg->dmac);

	spin_lock_bh(&sfe_connections_lock);
	conn = fast_classifier_find_conn((sfe_ip_addr_t *)&fc_msg->src_saddr,
					 (sfe_ip_addr_t *)&fc_msg->dst_saddr,
					 fc_msg->sport,
					 fc_msg->dport,
					 fc_msg->proto,
					 (fc_msg->ethertype == AF_INET));
	if (conn == NULL) {
		/* reverse the tuple and try again */
		conn = fast_classifier_find_conn((sfe_ip_addr_t *)&fc_msg->dst_saddr,
						 (sfe_ip_addr_t *)&fc_msg->src_saddr,
						 fc_msg->dport,
						 fc_msg->sport,
						 fc_msg->proto,
						 (fc_msg->ethertype == AF_INET));
		if (conn == NULL) {
			spin_unlock_bh(&sfe_connections_lock);
			DEBUG_TRACE("REQUEST OFFLOAD NO MATCH\n");
			atomic_inc(&offload_no_match_msgs);
			return 0;
		}
	}

	if (conn->offloaded != 0) {
		spin_unlock_bh(&sfe_connections_lock);
		DEBUG_TRACE("GOT REQUEST TO OFFLOAD ALREADY OFFLOADED CONN FROM USERSPACE\n");
		return 0;
	}

	DEBUG_TRACE("USERSPACE OFFLOAD REQUEST, MATCH FOUND, WILL OFFLOAD\n");
	if (fast_classifier_update_protocol(conn->sic, conn->ct) == 0) {
		spin_unlock_bh(&sfe_connections_lock);
		DEBUG_TRACE("UNKNOWN PROTOCOL OR CONNECTION CLOSING, SKIPPING\n");
		return 0;
	}

	DEBUG_TRACE("INFO: calling sfe rule creation!\n");
	spin_unlock_bh(&sfe_connections_lock);
	ret = conn->is_v4 ? sfe_ipv4_create_rule(conn->sic) : sfe_ipv6_create_rule(conn->sic);
	if ((ret == 0) || (ret == -EADDRINUSE)) {
		conn->offloaded = 1;
		fast_classifier_send_genl_msg(FAST_CLASSIFIER_C_OFFLOADED,
					      fc_msg);
	}

	atomic_inc(&offload_msgs);
	return 0;
}

/*
 * fast_classifier_nl_genl_msg_DUMP()
 *	ignore fast_classifier_messages OFFLOADED and DONE
 */
static int fast_classifier_nl_genl_msg_DUMP(struct sk_buff *skb,
					    struct netlink_callback *cb)
{
	return 0;
}

/* auto offload connection once we have this many packets*/
static int offload_at_pkts = 128;

/*
 * fast_classifier_post_routing()
 *	Called for packets about to leave the box - either locally generated or forwarded from another interface
 */
static unsigned int fast_classifier_post_routing(struct sk_buff *skb, bool is_v4)
{
	int ret;
	struct sfe_connection_create sic;
	struct sfe_connection_create *p_sic;
	struct net_device *in;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct net_device *dev;
	struct net_device *src_dev;
	struct net_device *dest_dev;
	struct net_device *src_br_dev = NULL;
	struct net_device *dest_br_dev = NULL;
	struct nf_conntrack_tuple orig_tuple;
	struct nf_conntrack_tuple reply_tuple;
	struct sfe_connection *conn;
	u32 key;
	SFE_NF_CONN_ACCT(acct);

	/*
	 * Don't process broadcast or multicast packets.
	 */
	if (unlikely(skb->pkt_type == PACKET_BROADCAST)) {
		DEBUG_TRACE("broadcast, ignoring\n");
		return NF_ACCEPT;
	}
	if (unlikely(skb->pkt_type == PACKET_MULTICAST)) {
		DEBUG_TRACE("multicast, ignoring\n");
		return NF_ACCEPT;
	}

#ifdef CONFIG_XFRM
	/*
	 * Packet to xfrm for encapsulation, we can't process it
	 */
	if (unlikely(skb_dst(skb)->xfrm)) {
		DEBUG_TRACE("packet to xfrm, ignoring\n");
		return NF_ACCEPT;
	}
#endif

	/*
	 * Don't process locally generated packets.
	 */
	if (skb->sk) {
		DEBUG_TRACE("skip local out packet\n");
		return NF_ACCEPT;
	}

	/*
	 * Don't process packets that are not being forwarded.
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (!in) {
		DEBUG_TRACE("packet not forwarding\n");
		return NF_ACCEPT;
	}

	dev_put(in);

	/*
	 * Don't process packets that aren't being tracked by conntrack.
	 */
	ct = nf_ct_get(skb, &ctinfo);
	if (unlikely(!ct)) {
		DEBUG_TRACE("no conntrack connection, ignoring\n");
		return NF_ACCEPT;
	}

	/*
	 * Don't process untracked connections.
	 */
	if (unlikely(nf_ct_is_untracked(ct))) {
		DEBUG_TRACE("untracked connection\n");
		return NF_ACCEPT;
	}

	/*
	 * Unconfirmed connection may be dropped by Linux at the final step,
	 * So we don't process unconfirmed connections.
	 */
	if (!nf_ct_is_confirmed(ct)) {
		DEBUG_TRACE("unconfirmed connection\n");
		return NF_ACCEPT;
	}

	/*
	 * Don't process connections that require support from a 'helper' (typically a NAT ALG).
	 */
	if (unlikely(nfct_help(ct))) {
		DEBUG_TRACE("connection has helper\n");
		return NF_ACCEPT;
	}

	/*
	 * Check if the acceleration of a flow could be rejected quickly.
	 */
	acct = nf_conn_acct_find(ct);
	if (acct) {
		long long packets = atomic64_read(&SFE_ACCT_COUNTER(acct)[CTINFO2DIR(ctinfo)].packets);
		if ((packets > 0xff) && (packets & 0xff)) {
			/*
			 * Connection hits slow path at least 256 times, so it must be not able to accelerate.
			 * But we also give it a chance to walk through ECM every 256 packets
			 */
			return NF_ACCEPT;
		}
	}

	memset(&sic, 0, sizeof(sic));

	/*
	 * Look up the details of our connection in conntrack.
	 *
	 * Note that the data we get from conntrack is for the "ORIGINAL" direction
	 * but our packet may actually be in the "REPLY" direction.
	 */
	orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	reply_tuple = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	sic.protocol = (int32_t)orig_tuple.dst.protonum;

	sic.flags = 0;

	/*
	 * Get addressing information, non-NAT first
	 */
	if (likely(is_v4)) {
		uint32_t dscp;

		sic.src_ip.ip = (__be32)orig_tuple.src.u3.ip;
		sic.dest_ip.ip = (__be32)orig_tuple.dst.u3.ip;

		if (ipv4_is_multicast(sic.src_ip.ip) || ipv4_is_multicast(sic.dest_ip.ip)) {
			DEBUG_TRACE("multicast address\n");
			return NF_ACCEPT;
		}

		/*
		 * NAT'ed addresses - note these are as seen from the 'reply' direction
		 * When NAT does not apply to this connection these will be identical to the above.
		 */
		sic.src_ip_xlate.ip = (__be32)reply_tuple.dst.u3.ip;
		sic.dest_ip_xlate.ip = (__be32)reply_tuple.src.u3.ip;

		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> XT_DSCP_SHIFT;
		if (dscp) {
			sic.src_dscp = sic.dest_dscp = dscp;
			sic.flags |= SFE_CREATE_FLAG_REMARK_DSCP;
		}
	} else {
		uint32_t dscp;

		sic.src_ip.ip6[0] = *((struct sfe_ipv6_addr *)&orig_tuple.src.u3.in6);
		sic.dest_ip.ip6[0] = *((struct sfe_ipv6_addr *)&orig_tuple.dst.u3.in6);

		if (ipv6_addr_is_multicast((struct in6_addr *)sic.src_ip.ip6) ||
		    ipv6_addr_is_multicast((struct in6_addr *)sic.dest_ip.ip6)) {
			DEBUG_TRACE("multicast address\n");
			return NF_ACCEPT;
		}

		/*
		 * NAT'ed addresses - note these are as seen from the 'reply' direction
		 * When NAT does not apply to this connection these will be identical to the above.
		 */
		sic.src_ip_xlate.ip6[0] = *((struct sfe_ipv6_addr *)&reply_tuple.dst.u3.in6);
		sic.dest_ip_xlate.ip6[0] = *((struct sfe_ipv6_addr *)&reply_tuple.src.u3.in6);

		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> XT_DSCP_SHIFT;
		if (dscp) {
			sic.src_dscp = sic.dest_dscp = dscp;
			sic.flags |= SFE_CREATE_FLAG_REMARK_DSCP;
		}
	}

	switch (sic.protocol) {
	case IPPROTO_TCP:
		sic.src_port = orig_tuple.src.u.tcp.port;
		sic.dest_port = orig_tuple.dst.u.tcp.port;
		sic.src_port_xlate = reply_tuple.dst.u.tcp.port;
		sic.dest_port_xlate = reply_tuple.src.u.tcp.port;

		/*
		 * Don't try to manage a non-established connection.
		 */
		if (!test_bit(IPS_ASSURED_BIT, &ct->status)) {
			DEBUG_TRACE("non-established connection\n");
			return NF_ACCEPT;
		}

		break;

	case IPPROTO_UDP:
		sic.src_port = orig_tuple.src.u.udp.port;
		sic.dest_port = orig_tuple.dst.u.udp.port;
		sic.src_port_xlate = reply_tuple.dst.u.udp.port;
		sic.dest_port_xlate = reply_tuple.src.u.udp.port;
		break;

	default:
		DEBUG_TRACE("unhandled protocol %d\n", sic.protocol);
		return NF_ACCEPT;
	}

#ifdef CONFIG_XFRM
	sic.original_accel = 1;
	sic.reply_accel = 1;

	/*
	 * For packets de-capsulated from xfrm, we still can accelerate it
	 * on the direction we just received the packet.
	 */
	if (unlikely(skb->sp)) {
		if (sic.protocol == IPPROTO_TCP &&
			!(sic.flags & SFE_CREATE_FLAG_NO_SEQ_CHECK)) {
			return NF_ACCEPT;
		}

		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
			sic.reply_accel = 0;
		} else {
			sic.original_accel = 0;
		}
	}
#endif

	/*
	 * Get QoS information
	 */
	if (skb->priority) {
		sic.src_priority = sic.dest_priority = skb->priority;
		sic.flags |= SFE_CREATE_FLAG_REMARK_PRIORITY;
	}

	if (is_v4) {
		DEBUG_TRACE("POST_ROUTE: checking new connection: %d src_ip: %pI4(%pI4), dst_ip: %pI4(%pI4), src_port: %u(%u), dst_port: %u(%u)\n",
				sic.protocol, &(sic.src_ip), &(sic.src_ip_xlate), &(sic.dest_ip), &(sic.dest_ip_xlate), 
				ntohs(sic.src_port), ntohs(sic.src_port_xlate), ntohs(sic.dest_port), ntohs(sic.dest_port_xlate));
	} else {
		DEBUG_TRACE("POST_ROUTE: checking new connection: %d src_ip: %pI6 dst_ip: %pI6, src_port: %d, dst_port: %d\n",
				sic.protocol, &(sic.src_ip), &(sic.dest_ip), sic.src_port, sic.dest_port);
	}

	/*
	 * If we already have this connection in our list, skip it
	 * XXX: this may need to be optimized
	 */
	spin_lock_bh(&sfe_connections_lock);

	conn = fast_classifier_find_conn(&sic.src_ip, &sic.dest_ip, sic.src_port, sic.dest_port, sic.protocol, is_v4);
	if (conn) {
		conn->hits++;

		if (!conn->offloaded) {
			if (conn->hits >= offload_at_pkts) {
				DEBUG_TRACE("OFFLOADING CONNECTION, TOO MANY HITS\n");

				if (fast_classifier_update_protocol(conn->sic, conn->ct) == 0) {
					spin_unlock_bh(&sfe_connections_lock);
					DEBUG_TRACE("UNKNOWN PROTOCOL OR CONNECTION CLOSING, SKIPPING\n");
					return NF_ACCEPT;
				}

				DEBUG_TRACE("INFO: calling sfe rule creation!\n");
				spin_unlock_bh(&sfe_connections_lock);

				ret = is_v4 ? sfe_ipv4_create_rule(conn->sic) : sfe_ipv6_create_rule(conn->sic);
				if ((ret == 0) || (ret == -EADDRINUSE)) {
					struct fast_classifier_tuple fc_msg;

					if (is_v4) {
						fc_msg.ethertype = AF_INET;
						fc_msg.src_saddr.in = *((struct in_addr *)&sic.src_ip);
						fc_msg.dst_saddr.in = *((struct in_addr *)&sic.dest_ip_xlate);
					} else {
						fc_msg.ethertype = AF_INET6;
						fc_msg.src_saddr.in6 = *((struct in6_addr *)&sic.src_ip);
						fc_msg.dst_saddr.in6 = *((struct in6_addr *)&sic.dest_ip_xlate);
					}

					fc_msg.proto = sic.protocol;
					fc_msg.sport = sic.src_port;
					fc_msg.dport = sic.dest_port_xlate;
					memcpy(fc_msg.smac, conn->smac, ETH_ALEN);
					memcpy(fc_msg.dmac, conn->dmac, ETH_ALEN);
					fast_classifier_send_genl_msg(FAST_CLASSIFIER_C_OFFLOADED, &fc_msg);
					conn->offloaded = 1;
				}

				return NF_ACCEPT;
			}
		}

		spin_unlock_bh(&sfe_connections_lock);
		if (conn->offloaded) {
			ret = is_v4 ? sfe_ipv4_update_rule(conn->sic) : sfe_ipv6_update_rule(conn->sic);
			if (ret) {
				DEBUG_TRACE("Free connection (rule not found)\n");
				kfree(conn->sic);
				hash_del(&conn->hl);
				sfe_connections_size--;
				kfree(conn);
			}
		}

		DEBUG_TRACE("FOUND, SKIPPING\n");
		return NF_ACCEPT;
	}

	spin_unlock_bh(&sfe_connections_lock);

	/*
	 * Get the net device and MAC addresses that correspond to the various source and
	 * destination host addresses.
	 */
	if (!fast_classifier_find_dev_and_mac_addr(&sic.src_ip, &src_dev, sic.src_mac, is_v4)) {
		return NF_ACCEPT;
	}

	if (!fast_classifier_find_dev_and_mac_addr(&sic.src_ip_xlate, &dev, sic.src_mac_xlate, is_v4)) {
		goto done1;
	}

	dev_put(dev);

	if (!fast_classifier_find_dev_and_mac_addr(&sic.dest_ip, &dev, sic.dest_mac, is_v4)) {
		goto done1;
	}

	dev_put(dev);

	if (!fast_classifier_find_dev_and_mac_addr(&sic.dest_ip_xlate, &dest_dev, sic.dest_mac_xlate, is_v4)) {
		goto done1;
	}

#if (!SFE_HOOK_ABOVE_BRIDGE)
	/*
	 * Now our devices may actually be a bridge interface.  If that's
	 * the case then we need to hunt down the underlying interface.
	 */
	if (src_dev->priv_flags & IFF_EBRIDGE) {
		src_br_dev = sfe_br_port_dev_get(src_dev, sic.src_mac);
		if (!src_br_dev) {
			DEBUG_TRACE("no port found on bridge\n");
			goto done2;
		}

		src_dev = src_br_dev;
	}

	if (dest_dev->priv_flags & IFF_EBRIDGE) {
		dest_br_dev = sfe_br_port_dev_get(dest_dev, sic.dest_mac_xlate);
		if (!dest_br_dev) {
			DEBUG_TRACE("no port found on bridge\n");
			goto done3;
		}

		dest_dev = dest_br_dev;
	}
#else
	/*
	 * Our devices may actually be part of a bridge interface.  If that's
	 * the case then find the bridge interface instead.
	 */
	if (src_dev->priv_flags & IFF_BRIDGE_PORT) {
		src_br_dev = sfe_dev_get_master(src_dev);
		if (!src_br_dev) {
			DEBUG_TRACE("no bridge found for: %s\n", src_dev->name);
			goto done2;
		}

		src_dev = src_br_dev;
	}

	if (dest_dev->priv_flags & IFF_BRIDGE_PORT) {
		dest_br_dev = sfe_dev_get_master(dest_dev);
		if (!dest_br_dev) {
			DEBUG_TRACE("no bridge found for: %s\n", dest_dev->name);
			goto done3;
		}

		dest_dev = dest_br_dev;
	}
#endif

	sic.src_dev = src_dev;
	sic.dest_dev = dest_dev;

	sic.src_mtu = src_dev->mtu;
	sic.dest_mtu = dest_dev->mtu;

	sic.mark = ct->mark;

	conn = kmalloc(sizeof(struct sfe_connection), GFP_ATOMIC);
	if (conn == NULL) {
		printk(KERN_CRIT "ERROR: no memory for sfe\n");
		goto done3;
	}
	conn->hits = 0;
	conn->offloaded = 0;
	conn->is_v4 = is_v4;
	DEBUG_TRACE("Source MAC=%pM\n", sic.src_mac);
	memcpy(conn->smac, sic.src_mac, ETH_ALEN);
	memcpy(conn->dmac, sic.dest_mac_xlate, ETH_ALEN);

	p_sic = kmalloc(sizeof(struct sfe_connection_create), GFP_ATOMIC);
	if (p_sic == NULL) {
		printk(KERN_CRIT "ERROR: no memory for sfe\n");
		kfree(conn);
		goto done3;
	}

	memcpy(p_sic, &sic, sizeof(sic));
	conn->sic = p_sic;
	conn->ct = ct;
	sfe_connections_size++;
	DEBUG_TRACE(" -> adding item to sfe_connections, new size: %d\n", sfe_connections_size);
	spin_lock_bh(&sfe_connections_lock);
	key = fc_conn_hash(&conn->sic->src_ip,
			   &conn->sic->dest_ip,
			   conn->sic->src_port,
			   conn->sic->dest_port,
			   is_v4);
	hash_add(fc_conn_ht, &conn->hl, key);
	spin_unlock_bh(&sfe_connections_lock);

	if (is_v4) {
		DEBUG_TRACE("new offloadable: key: %u proto: %d src_ip: %pI4 dst_ip: %pI4, src_port: %d, dst_port: %d\n",
				key, p_sic->protocol, &(p_sic->src_ip), &(p_sic->dest_ip), p_sic->src_port, p_sic->dest_port);
	} else {
		DEBUG_TRACE("new offloadable: key: %u proto: %d src_ip: %pI6 dst_ip: %pI6, src_port: %d, dst_port: %d\n",
				key, p_sic->protocol, &(p_sic->src_ip), &(p_sic->dest_ip), p_sic->src_port, p_sic->dest_port);
	}

	/*
	 * If we had bridge ports then release them too.
	 */
	if (dest_br_dev) {
		dev_put(dest_br_dev);
	}

done3:
	if (src_br_dev) {
		dev_put(src_br_dev);
	}

done2:
	dev_put(dest_dev);

done1:
	dev_put(src_dev);

	return NF_ACCEPT;
}

/*
 * fast_classifier_ipv4_post_routing_hook()
 *	Called for packets about to leave the box - either locally generated or forwarded from another interface
 */
fast_classifier_ipv4_post_routing_hook(hooknum, ops, skb, in_unused, out, okfn)
{
	return fast_classifier_post_routing(skb, true);
}

/*
 * fast_classifier_ipv6_post_routing_hook()
 *	Called for packets about to leave the box - either locally generated or forwarded from another interface
 */
fast_classifier_ipv6_post_routing_hook(hooknum, ops, skb, in_unused, out, okfn)
{
	return fast_classifier_post_routing(skb, false);
}

/*
 * fast_classifier_update_mark()
 *	updates the mark for a fast-classifier connection
 */
static void fast_classifier_update_mark(struct sfe_connection_mark *mark, bool is_v4)
{
	struct sfe_connection *conn;

	spin_lock_bh(&sfe_connections_lock);

	conn = fast_classifier_find_conn(&mark->src_ip, &mark->dest_ip,
					 mark->src_port, mark->dest_port,
					 mark->protocol, is_v4);
	if (conn) {
		DEBUG_TRACE("Update mark: %u -> %u\n", conn->sic->mark, mark->mark);
		conn->sic->mark = mark->mark;
	}

	spin_unlock_bh(&sfe_connections_lock);
}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
/*
 * fast_classifier_conntrack_event()
 *	Callback event invoked when a conntrack connection's state changes.
 */
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static int fast_classifier_conntrack_event(struct notifier_block *this,
				unsigned long events, void *ptr)
#else
static int fast_classifier_conntrack_event(unsigned int events, struct nf_ct_event *item)
#endif
{
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
	struct nf_ct_event *item = ptr;
#endif
	struct sfe_connection_destroy sid;
	struct nf_conn *ct = item->ct;
	struct nf_conntrack_tuple orig_tuple;
	struct sfe_connection *conn;
	struct fast_classifier_tuple fc_msg;
	int offloaded = 0;
	bool is_v4;

	/*
	 * If we don't have a conntrack entry then we're done.
	 */
	if (unlikely(!ct)) {
		DEBUG_WARN("no ct in conntrack event callback\n");
		return NOTIFY_DONE;
	}

	/*
	 * If this is an untracked connection then we can't have any state either.
	 */
	if (unlikely(nf_ct_is_untracked(ct))) {
		DEBUG_TRACE("ignoring untracked conn\n");
		return NOTIFY_DONE;
	}

	orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	sid.protocol = (int32_t)orig_tuple.dst.protonum;

	/*
	 * Extract information from the conntrack connection.  We're only interested
	 * in nominal connection information (i.e. we're ignoring any NAT information).
	 */
	if (likely(nf_ct_l3num(ct) == AF_INET)) {
		sid.src_ip.ip = (__be32)orig_tuple.src.u3.ip;
		sid.dest_ip.ip = (__be32)orig_tuple.dst.u3.ip;
		is_v4 = true;
	} else if (likely(nf_ct_l3num(ct) == AF_INET6)) {
		sid.src_ip.ip6[0] = *((struct sfe_ipv6_addr *)&orig_tuple.src.u3.in6);
		sid.dest_ip.ip6[0] = *((struct sfe_ipv6_addr *)&orig_tuple.dst.u3.in6);
		is_v4 = false;
	} else {
		DEBUG_TRACE("ignoring non-IPv4 and non-IPv6 connection\n");
		return NOTIFY_DONE;
	}

	switch (sid.protocol) {
	case IPPROTO_TCP:
		sid.src_port = orig_tuple.src.u.tcp.port;
		sid.dest_port = orig_tuple.dst.u.tcp.port;
		break;

	case IPPROTO_UDP:
		sid.src_port = orig_tuple.src.u.udp.port;
		sid.dest_port = orig_tuple.dst.u.udp.port;
		break;

	default:
		DEBUG_TRACE("unhandled protocol: %d\n", sid.protocol);
		return NOTIFY_DONE;
	}

	/*
	 * Check for an updated mark
	 */
	if ((events & (1 << IPCT_MARK)) && (ct->mark != 0)) {
		struct sfe_connection_mark mark;

		mark.protocol = sid.protocol;
		mark.src_ip = sid.src_ip;
		mark.dest_ip = sid.dest_ip;
		mark.src_port = sid.src_port;
		mark.dest_port = sid.dest_port;
		mark.mark = ct->mark;

		is_v4 ? sfe_ipv4_mark_rule(&mark) : sfe_ipv6_mark_rule(&mark);
		fast_classifier_update_mark(&mark, is_v4);
	}

	/*
	 * We're only interested in destroy events at this point
	 */
	if (unlikely(!(events & (1 << IPCT_DESTROY)))) {
		DEBUG_TRACE("ignoring non-destroy event\n");
		return NOTIFY_DONE;
	}

	if (is_v4) {
		DEBUG_TRACE("Try to clean up: proto: %d src_ip: %pI4 dst_ip: %pI4, src_port: %d, dst_port: %d\n",
			sid.protocol, &sid.src_ip, &sid.dest_ip, ntohs(sid.src_port), ntohs(sid.dest_port));
	} else {
		DEBUG_TRACE("Try to clean up: proto: %d src_ip: %pI6 dst_ip: %pI6, src_port: %d, dst_port: %d\n",
			sid.protocol, &sid.src_ip, &sid.dest_ip, ntohs(sid.src_port), ntohs(sid.dest_port));
	}

	spin_lock_bh(&sfe_connections_lock);

	conn = fast_classifier_find_conn(&sid.src_ip, &sid.dest_ip, sid.src_port, sid.dest_port, sid.protocol, is_v4);
	if (conn && conn->offloaded) {
		if (is_v4) {
			fc_msg.ethertype = AF_INET;
			fc_msg.src_saddr.in = *((struct in_addr *)&conn->sic->src_ip);
			fc_msg.dst_saddr.in = *((struct in_addr *)&conn->sic->dest_ip_xlate);
		} else {
			fc_msg.ethertype = AF_INET6;
			fc_msg.src_saddr.in6 = *((struct in6_addr *)&conn->sic->src_ip);
			fc_msg.dst_saddr.in6 = *((struct in6_addr *)&conn->sic->dest_ip_xlate);
		}

		fc_msg.proto = conn->sic->protocol;
		fc_msg.sport = conn->sic->src_port;
		fc_msg.dport = conn->sic->dest_port_xlate;
		memcpy(fc_msg.smac, conn->smac, ETH_ALEN);
		memcpy(fc_msg.dmac, conn->dmac, ETH_ALEN);
		offloaded = 1;
	}

	if (conn) {
		DEBUG_TRACE("Free connection: proto: %d src_ip: %pI4 dst_ip: %pI4, src_port: %u, dst_port: %u\n",
			sid.protocol, &sid.src_ip, &sid.dest_ip, ntohs(sid.src_port), ntohs(sid.dest_port));
		kfree(conn->sic);
		hash_del(&conn->hl);
		sfe_connections_size--;
		kfree(conn);
	}

	spin_unlock_bh(&sfe_connections_lock);

	is_v4 ? sfe_ipv4_destroy_rule(&sid) : sfe_ipv6_destroy_rule(&sid);

	if (offloaded) {
		fast_classifier_send_genl_msg(FAST_CLASSIFIER_C_DONE, &fc_msg);
	}

	return NOTIFY_DONE;
}

/*
 * Netfilter conntrack event system to monitor connection tracking changes
 */
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static struct notifier_block fast_classifier_conntrack_notifier = {
	.notifier_call = fast_classifier_conntrack_event,
};
#else
static struct nf_ct_event_notifier fast_classifier_conntrack_notifier = {
	.fcn = fast_classifier_conntrack_event,
};
#endif
#endif

/*
 * Structure to establish a hook into the post routing netfilter point - this
 * will pick up local outbound and packets going from one interface to another.
 *
 * Note: see include/linux/netfilter_ipv4.h for info related to priority levels.
 * We want to examine packets after NAT translation and any ALG processing.
 */
static struct nf_hook_ops fast_classifier_ops_post_routing[] __read_mostly = {
	SFE_IPV4_NF_POST_ROUTING_HOOK(__fast_classifier_ipv4_post_routing_hook),
	SFE_IPV6_NF_POST_ROUTING_HOOK(__fast_classifier_ipv6_post_routing_hook),
};

/*
 * fast_classifier_sync_rule()
 *	Synchronize a connection's state.
 */
static void fast_classifier_sync_rule(struct sfe_connection_sync *sis)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct;
	SFE_NF_CONN_ACCT(acct);

	/*
	 * Create a tuple so as to be able to look up a connection
	 */
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u.all = (__be16)sis->src_port;
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	tuple.dst.protonum = (uint8_t)sis->protocol;
	tuple.dst.u.all = (__be16)sis->dest_port;

	if (sis->is_v6) {
		tuple.src.u3.in6 = *((struct in6_addr *)sis->src_ip.ip6);
		tuple.dst.u3.in6 = *((struct in6_addr *)sis->dest_ip.ip6);
		tuple.src.l3num = AF_INET6;

		DEBUG_TRACE("update connection - p: %d, s: %pI6:%u, d: %pI6:%u\n",
			    (int)tuple.dst.protonum,
			    &tuple.src.u3.in6, (unsigned int)ntohs(tuple.src.u.all),
			    &tuple.dst.u3.in6, (unsigned int)ntohs(tuple.dst.u.all));
	} else {
		tuple.src.u3.ip = sis->src_ip.ip;
		tuple.dst.u3.ip = sis->dest_ip.ip;
		tuple.src.l3num = AF_INET;

		DEBUG_TRACE("update connection - p: %d, s: %pI4:%u, d: %pI4:%u\n",
			    (int)tuple.dst.protonum,
			    &tuple.src.u3.ip, (unsigned int)ntohs(tuple.src.u.all),
			    &tuple.dst.u3.ip, (unsigned int)ntohs(tuple.dst.u.all));
	}

#if (SFE_HOOK_ABOVE_BRIDGE)
	/*
	 * Update packet count for ingress on bridge device
	 */
	if (skip_to_bridge_ingress) {
		struct rtnl_link_stats64 nlstats;
		nlstats.tx_packets = 0;
		nlstats.tx_bytes = 0;

		if (sis->src_dev && (sis->src_dev->priv_flags & IFF_EBRIDGE) &&
			(sis->src_new_packet_count || sis->src_new_byte_count)) {
			nlstats.rx_packets = sis->src_new_packet_count;
			nlstats.rx_bytes = sis->src_new_byte_count;
			spin_lock_bh(&sfe_connections_lock);
			sfe_br_dev_update_stats(sis->src_dev, &nlstats);
			spin_unlock_bh(&sfe_connections_lock);
		}
		if (sis->dest_dev && (sis->dest_dev->priv_flags & IFF_EBRIDGE) &&
			(sis->dest_new_packet_count || sis->dest_new_byte_count)) {
			nlstats.rx_packets = sis->dest_new_packet_count;
			nlstats.rx_bytes = sis->dest_new_byte_count;
			spin_lock_bh(&sfe_connections_lock);
			sfe_br_dev_update_stats(sis->dest_dev, &nlstats);
			spin_unlock_bh(&sfe_connections_lock);
		}
	}
#endif

	/*
	 * Look up conntrack connection
	 */
	h = nf_conntrack_find_get(&init_net, SFE_NF_CT_DEFAULT_ZONE, &tuple);
	if (unlikely(!h)) {
		DEBUG_TRACE("no connection found\n");
		return;
	}

	ct = nf_ct_tuplehash_to_ctrack(h);
	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);

	/*
	 * Only update if this is not a fixed timeout
	 */
	if (!test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status)) {
		spin_lock_bh(&ct->lock);
		ct->timeout.expires += sis->delta_jiffies;
		spin_unlock_bh(&ct->lock);
	}

	acct = nf_conn_acct_find(ct);
	if (acct) {
		spin_lock_bh(&ct->lock);
		atomic64_set(&SFE_ACCT_COUNTER(acct)[IP_CT_DIR_ORIGINAL].packets, sis->src_packet_count);
		atomic64_set(&SFE_ACCT_COUNTER(acct)[IP_CT_DIR_ORIGINAL].bytes, sis->src_byte_count);
		atomic64_set(&SFE_ACCT_COUNTER(acct)[IP_CT_DIR_REPLY].packets, sis->dest_packet_count);
		atomic64_set(&SFE_ACCT_COUNTER(acct)[IP_CT_DIR_REPLY].bytes, sis->dest_byte_count);
		spin_unlock_bh(&ct->lock);
	}

	switch (sis->protocol) {
	case IPPROTO_TCP:
		spin_lock_bh(&ct->lock);
		if (ct->proto.tcp.seen[0].td_maxwin < sis->src_td_max_window) {
			ct->proto.tcp.seen[0].td_maxwin = sis->src_td_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[0].td_end - sis->src_td_end) < 0) {
			ct->proto.tcp.seen[0].td_end = sis->src_td_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[0].td_maxend - sis->src_td_max_end) < 0) {
			ct->proto.tcp.seen[0].td_maxend = sis->src_td_max_end;
		}
		if (ct->proto.tcp.seen[1].td_maxwin < sis->dest_td_max_window) {
			ct->proto.tcp.seen[1].td_maxwin = sis->dest_td_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[1].td_end - sis->dest_td_end) < 0) {
			ct->proto.tcp.seen[1].td_end = sis->dest_td_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[1].td_maxend - sis->dest_td_max_end) < 0) {
			ct->proto.tcp.seen[1].td_maxend = sis->dest_td_max_end;
		}
		spin_unlock_bh(&ct->lock);

		break;
	}

	/*
	 * Release connection
	 */
	nf_ct_put(ct);
}

/*
 * fast_classifier_device_event()
 */
static int fast_classifier_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = SFE_DEV_EVENT_PTR(ptr);

	switch (event) {
	case NETDEV_DOWN:
		if (dev) {
			sfe_ipv4_destroy_all_rules_for_dev(dev);
			sfe_ipv6_destroy_all_rules_for_dev(dev);
			fast_classifier_destroy_all_conns(dev);
		}
		break;
	}

	return NOTIFY_DONE;
}

/*
 * fast_classifier_inet_event()
 */
static int fast_classifier_inet_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ((struct in_ifaddr *)ptr)->ifa_dev->dev;
	return sfe_propagate_dev_event(fast_classifier_device_event, this, event, dev);
}

/*
 * fast_classifier_inet6_event()
 */
static int fast_classifier_inet6_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ((struct inet6_ifaddr *)ptr)->idev->dev;
	return sfe_propagate_dev_event(fast_classifier_device_event, this, event, dev);
}

/*
 * fast_classifier_get_offload_at_pkts()
 */
static ssize_t fast_classifier_get_offload_at_pkts(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	return snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", offload_at_pkts);
}

/*
 * fast_classifier_set_offload_at_pkts()
 */
static ssize_t fast_classifier_set_offload_at_pkts(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	long new;
	int ret;

	ret = strict_strtol(buf, 0, &new);
	if (ret == -EINVAL || ((int)new != new))
		return -EINVAL;

	offload_at_pkts = new;

	return size;
}

/*
 * fast_classifier_get_debug_info()
 */
static ssize_t fast_classifier_get_debug_info(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	size_t len = 0;
	struct sfe_connection *conn;
	u32 i;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
	struct hlist_node *node;
#endif

	spin_lock_bh(&sfe_connections_lock);
	len += scnprintf(buf, PAGE_SIZE - len, "size=%d offload=%d offload_no_match=%d"
			" offloaded=%d done=%d offloaded_fail=%d done_fail=%d\n",
			sfe_connections_size,
			atomic_read(&offload_msgs),
			atomic_read(&offload_no_match_msgs),
			atomic_read(&offloaded_msgs),
			atomic_read(&done_msgs),
			atomic_read(&offloaded_fail_msgs),
			atomic_read(&done_fail_msgs));
	sfe_hash_for_each(fc_conn_ht, i, node, conn, hl) {
		len += scnprintf(buf + len , PAGE_SIZE - len,
				(conn->is_v4 ? "o=%d, p=%d [%pM]:%pI4:%u %pI4:%u:[%pM] m=%08x h=%d\n" : "o=%d, p=%d [%pM]:%pI6:%u %pI6:%u:[%pM] m=%08x h=%d\n"),
				conn->offloaded,
				conn->sic->protocol,
				conn->sic->src_mac,
				&(conn->sic->src_ip),
				ntohs(conn->sic->src_port),
				&(conn->sic->dest_ip),
				ntohs(conn->sic->dest_port),
				conn->sic->dest_mac_xlate,
				conn->sic->mark,
				conn->hits);
	}
	spin_unlock_bh(&sfe_connections_lock);

	return len;
}

/*
 * fast_classifier_get_skip_bridge_ingress()
 */
static ssize_t fast_classifier_get_skip_bridge_ingress(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
#if (SFE_HOOK_ABOVE_BRIDGE)
	return snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", skip_to_bridge_ingress);
#else
	return snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", 0);
#endif
}

/*
 * fast_classifier_set_skip_bridge_ingress()
 */
static ssize_t fast_classifier_set_skip_bridge_ingress(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
#if (SFE_HOOK_ABOVE_BRIDGE)
	long new;
	int ret;

	ret = strict_strtol(buf, 0, &new);
	if (ret == -EINVAL || ((int)new != new))
		return -EINVAL;

	skip_to_bridge_ingress = new ? 1 : 0;

	return size;
#else
	return size;
#endif
}

/*
 * fast_classifier_get_no_window_check()
 */
static ssize_t fast_classifier_get_no_window_check(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	return snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", nf_ct_tcp_no_window_check);
}

/*
 * fast_classifier_set_no_window_check()
 */
static ssize_t fast_classifier_set_no_window_check(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	long new;
	int ret;

	ret = strict_strtol(buf, 0, &new);
	if (ret == -EINVAL || ((int)new != new))
		return -EINVAL;

	nf_ct_tcp_no_window_check = new ? 1 : 0;

	return size;
}

/*
 * sysfs attributes.
 */
static const struct device_attribute fast_classifier_offload_at_pkts_attr =
	__ATTR(offload_at_pkts, S_IWUSR | S_IRUGO, fast_classifier_get_offload_at_pkts, fast_classifier_set_offload_at_pkts);
static const struct device_attribute fast_classifier_debug_info_attr =
	__ATTR(debug_info, S_IRUGO, fast_classifier_get_debug_info, NULL);
static const struct device_attribute fast_classifier_skip_bridge_ingress =
	__ATTR(skip_to_bridge_ingress, S_IWUSR | S_IRUGO, fast_classifier_get_skip_bridge_ingress, fast_classifier_set_skip_bridge_ingress);
static const struct device_attribute fast_classifier_no_window_check =
	__ATTR(no_window_check, S_IWUSR | S_IRUGO, fast_classifier_get_no_window_check, fast_classifier_set_no_window_check);

/*
 * fast_classifier_init()
 */
static int __init fast_classifier_init(void)
{
	struct fast_classifier *sc = &__sc;
	int result = -1;

	printk(KERN_ALERT "fast-classifier: starting up\n");
	DEBUG_INFO("SFE CM init\n");

	hash_init(fc_conn_ht);

	/*
	 * Create sys/fast_classifier
	 */
	sc->sys_fast_classifier = kobject_create_and_add("fast_classifier", NULL);
	if (!sc->sys_fast_classifier) {
		DEBUG_ERROR("failed to register fast_classifier\n");
		goto exit1;
	}

	result = sysfs_create_file(sc->sys_fast_classifier, &fast_classifier_offload_at_pkts_attr.attr);
	if (result) {
		DEBUG_ERROR("failed to register offload at pkgs: %d\n", result);
		goto exit2;
	}

	result = sysfs_create_file(sc->sys_fast_classifier, &fast_classifier_debug_info_attr.attr);
	if (result) {
		DEBUG_ERROR("failed to register debug dev: %d\n", result);
		sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_offload_at_pkts_attr.attr);
		goto exit2;
	}

	result = sysfs_create_file(sc->sys_fast_classifier, &fast_classifier_skip_bridge_ingress.attr);
	if (result) {
		DEBUG_ERROR("failed to register skip bridge on ingress: %d\n", result);
		sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_offload_at_pkts_attr.attr);
		sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_debug_info_attr.attr);
		goto exit2;
	}

	result = sysfs_create_file(sc->sys_fast_classifier, &fast_classifier_no_window_check.attr);
	if (result) {
		DEBUG_ERROR("failed to register no window check: %d\n", result);
		sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_offload_at_pkts_attr.attr);
		sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_debug_info_attr.attr);
		sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_skip_bridge_ingress.attr);
		goto exit2;
	}

	sc->dev_notifier.notifier_call = fast_classifier_device_event;
	sc->dev_notifier.priority = 1;
	register_netdevice_notifier(&sc->dev_notifier);

	sc->inet_notifier.notifier_call = fast_classifier_inet_event;
	sc->inet_notifier.priority = 1;
	register_inetaddr_notifier(&sc->inet_notifier);

	sc->inet6_notifier.notifier_call = fast_classifier_inet6_event;
	sc->inet6_notifier.priority = 1;
	register_inet6addr_notifier(&sc->inet6_notifier);

	/*
	 * Register our netfilter hooks.
	 */
	result = nf_register_hooks(fast_classifier_ops_post_routing, ARRAY_SIZE(fast_classifier_ops_post_routing));
	if (result < 0) {
		DEBUG_ERROR("can't register nf post routing hook: %d\n", result);
		goto exit3;
	}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	/*
	 * Register a notifier hook to get fast notifications of expired connections.
	 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0))
	result = nf_conntrack_register_notifier(&init_net, &fast_classifier_conntrack_notifier);
#else
	result = nf_conntrack_register_notifier(&fast_classifier_conntrack_notifier);
#endif
	if (result < 0) {
		DEBUG_ERROR("can't register nf notifier hook: %d\n", result);
		goto exit4;
	}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0))
	result = genl_register_family_with_ops_groups(&fast_classifier_gnl_family,
						      fast_classifier_gnl_ops,
						      fast_classifier_genl_mcgrp);
	if (result) {
		DEBUG_ERROR("failed to register genl ops: %d\n", result);
		goto exit5;
	}
#else
	result = genl_register_family(&fast_classifier_gnl_family);
	if (result) {
		printk(KERN_CRIT "unable to register genl family\n");
		goto exit5;
	}

	result = genl_register_ops(&fast_classifier_gnl_family, fast_classifier_gnl_ops);
	if (result) {
		printk(KERN_CRIT "unable to register ops\n");
		goto exit6;
	}

	result = genl_register_mc_group(&fast_classifier_gnl_family,
					fast_classifier_genl_mcgrp);
	if (result) {
		printk(KERN_CRIT "unable to register multicast group\n");
		goto exit6;
	}
#endif

	printk(KERN_ALERT "fast-classifier: registered\n");

	spin_lock_init(&sc->lock);

	/*
	 * Hook the receive path in the network stack.
	 */
	BUG_ON(athrs_fast_nat_recv != NULL);
	RCU_INIT_POINTER(athrs_fast_nat_recv, fast_classifier_recv);

	/*
	 * Hook the shortcut sync callback.
	 */
	sfe_ipv4_register_sync_rule_callback(fast_classifier_sync_rule);
	sfe_ipv6_register_sync_rule_callback(fast_classifier_sync_rule);

	return 0;

exit6:
	genl_unregister_family(&fast_classifier_gnl_family);

exit5:
#ifdef CONFIG_NF_CONNTRACK_EVENTS
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0))
	nf_conntrack_unregister_notifier(&init_net, &fast_classifier_conntrack_notifier);
#else
	nf_conntrack_unregister_notifier(&fast_classifier_conntrack_notifier);
#endif

exit4:
#endif
	nf_unregister_hooks(fast_classifier_ops_post_routing, ARRAY_SIZE(fast_classifier_ops_post_routing));

exit3:
	unregister_inetaddr_notifier(&sc->inet_notifier);
	unregister_inet6addr_notifier(&sc->inet6_notifier);
	unregister_netdevice_notifier(&sc->dev_notifier);
	sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_offload_at_pkts_attr.attr);
	sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_debug_info_attr.attr);
	sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_skip_bridge_ingress.attr);
	sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_no_window_check.attr);

exit2:
	kobject_put(sc->sys_fast_classifier);

exit1:
	return result;
}

/*
 * fast_classifier_exit()
 */
static void __exit fast_classifier_exit(void)
{
	struct fast_classifier *sc = &__sc;
	int result = -1;

	DEBUG_INFO("SFE CM exit\n");
	printk(KERN_ALERT "fast-classifier: shutting down\n");

	/*
	 * Unregister our sync callback.
	 */
	sfe_ipv4_register_sync_rule_callback(NULL);
	sfe_ipv6_register_sync_rule_callback(NULL);

	/*
	 * Unregister our receive callback.
	 */
	RCU_INIT_POINTER(athrs_fast_nat_recv, NULL);

	/*
	 * Wait for all callbacks to complete.
	 */
	rcu_barrier();

	/*
	 * Destroy all connections.
	 */
	sfe_ipv4_destroy_all_rules_for_dev(NULL);
	sfe_ipv6_destroy_all_rules_for_dev(NULL);
	fast_classifier_destroy_all_conns(NULL);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0))
	result = genl_unregister_ops(&fast_classifier_gnl_family, fast_classifier_gnl_ops);
	if (result != 0) {
		printk(KERN_CRIT "Unable to unreigster genl_ops\n");
	}
#endif

	result = genl_unregister_family(&fast_classifier_gnl_family);
	if (result != 0) {
		printk(KERN_CRIT "Unable to unreigster genl_family\n");
	}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0))
	nf_conntrack_unregister_notifier(&init_net, &fast_classifier_conntrack_notifier);
#else
	nf_conntrack_unregister_notifier(&fast_classifier_conntrack_notifier);
#endif

#endif
	nf_unregister_hooks(fast_classifier_ops_post_routing, ARRAY_SIZE(fast_classifier_ops_post_routing));

	unregister_inet6addr_notifier(&sc->inet6_notifier);
	unregister_inetaddr_notifier(&sc->inet_notifier);
	unregister_netdevice_notifier(&sc->dev_notifier);

	sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_offload_at_pkts_attr.attr);
	sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_debug_info_attr.attr);
	sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_skip_bridge_ingress.attr);
	sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_no_window_check.attr);

	kobject_put(sc->sys_fast_classifier);
}

module_init(fast_classifier_init)
module_exit(fast_classifier_exit)

MODULE_AUTHOR("Qualcomm Atheros Inc.");
MODULE_DESCRIPTION("Shortcut Forwarding Engine - Connection Manager");
MODULE_LICENSE("Dual BSD/GPL");

