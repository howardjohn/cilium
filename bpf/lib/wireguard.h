/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifdef ENABLE_WIREGUARD

#ifndef __WIREGUARD_H_
#define __WIREGUARD_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "tailcall.h"
#include "common.h"
#include "overloadable.h"

/*

// Some verifier BS blocks this but this is more or less what we need to get TCP working I imagine...
static __always_inline int
ctx_redirect_hbone(struct __ctx_buff *ctx)
{
    union macaddr host_mac = HOST_IFINDEX_MAC;
    union macaddr router_mac = NODE_MAC;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *ip4;
	__u16 proto;
	int ret = 0;

    printk("redirect start");
	if (!validate_ethertype(ctx, &proto)) {
		return DROP_UNSUPPORTED_L2;
	}
    printk("redirect star2");
	if (proto != bpf_htons(ETH_P_IP)) {
		return DROP_UNSUPPORTED_L2;
	}
//	ctx->mark = MARK_MAGIC_HBONE;
//    ctx_change_type(ctx, PACKET_HOST);
    printk("redirect set mark and change packet type");
     //	bpf_barrier();

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
        printk("drop 1");
		return DROP_INVALID;
    }

    printk("router mac %x, host mac %x", router_mac.addr[0], host_mac.addr[0]);
//    printk("ttl %d", ip4->ttl);
//    memcpy(&host_mac.addr, HOST_IFINDEX_MAC, 6);
//    memcpy(&router_mac.addr, NODE_MAC, 6);
//    smac = (__u8 *)&router_mac;
    if (eth_store_saddr(ctx, (__u8 *)&router_mac.addr, 0) < 0) {
        return DROP_INVALID;
    }

//	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
//        printk("drop 1");
//		return DROP_INVALID;
//    }
//    smac = (__u8 *)&host_mac;
//    if (smac && eth_store_daddr(ctx, smac, 0) < 0) {
//        return DROP_INVALID;
//    }
//
//	data_end = (void *)(long)ctx->data_end;
//	data = (void *)(long)ctx->data;
//
//    printk("redirect check2");
//	if (!validate_ethertype(ctx, &proto)) {
//		return DROP_UNSUPPORTED_L2;
//	}
//	if (proto != bpf_htons(ETH_P_IP)) {
//		return DROP_UNSUPPORTED_L2;
//	}
//	return ret; // THIS IS TO FIX THE VERIFIER!
//	if (ip4) {
//        printk("ip4");
//        ret = ipv4_l3_nottl(ctx, (__u8 *)&router_mac, (__u8 *)&host_mac);
//    } else {
//        printk("!ip4");
//    }
//	if (IS_ERR(ret)) {
//        printk("drop 2");
//		return ret;
//    }
//	return 0;

//	cilium_dbg(ctx, DBG_CAPTURE_PROXY_PRE, 15008, 0);

	ret = ctx_redirect(ctx, HOST_IFINDEX, BPF_F_INGRESS);

    printk("redirect to %d: %d", HOST_IFINDEX, ret);
	return ret;
}
*/
static __always_inline int
wg_maybe_redirect_to_encrypt(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info *dst;
	struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data, *data_end;
	__u16 proto = 0;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
#ifdef ENABLE_NODE_ENCRYPTION
		/* Previously, ICMPv6 NA (reply to NS) was sent over cilium_wg0,
		 * which resulted in neigh entry not being created due to
		 * IFF_POINTOPOINT | IFF_NOARP set on cilium_wg0. Therefore,
		 * NA should not be sent over WG.
		 */
		if (ip6->nexthdr == IPPROTO_ICMPV6) {
			__u8 icmp_type;

			if (data + sizeof(*ip6) + ETH_HLEN +
			    sizeof(struct icmp6hdr) > data_end)
				return DROP_INVALID;

			if (icmp6_load_type(ctx, ETH_HLEN + sizeof(struct ipv6hdr),
					    &icmp_type) < 0)
				return DROP_INVALID;

			if (icmp_type == ICMP6_NA_MSG_TYPE)
				goto out;
		}
#endif
		dst = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		src = lookup_ip6_remote_endpoint((union v6addr *)&ip6->saddr, 0);
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		dst = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		src = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		break;
#endif
	default:
		goto out;
	}

	/* Redirect to the WireGuard tunnel device if the encryption is
	 * required.
	 *
	 * After the packet has been encrypted, the WG tunnel device
	 * will set the MARK_MAGIC_WG_ENCRYPTED skb mark. So, to avoid
	 * looping forever (e.g., bpf_host@eth0 => cilium_wg0 =>
	 * bpf_host@eth0 => ...; this happens when eth0 is used to send
	 * encrypted WireGuard UDP packets), we check whether the mark
	 * is set before the redirect.
	 */
	if ((ctx->mark & MARK_MAGIC_WG_ENCRYPTED) == MARK_MAGIC_WG_ENCRYPTED)
		goto out;

	/* Unless node encryption is enabled, we don't want to encrypt
	 * traffic from the hostns.
	 *
	 * NB: if iptables has SNAT-ed the packet, its sec id is HOST_ID.
	 * This means that the packet won't be encrypted. This is fine,
	 * as with --encrypt-node=false we encrypt only pod-to-pod packets.
	 */
#ifndef ENABLE_NODE_ENCRYPTION
	if (!src || src->sec_identity == HOST_ID)
		goto out;
#endif /* ENABLE_NODE_ENCRYPTION */

	/* We don't want to encrypt any traffic that originates from outside
	 * the cluster.
	 * Without this check, that may happen for the egress gateway, when
	 * reply traffic arrives from the cluster-external server and goes to
	 * the client pod.
	 */
	if (!src || !identity_is_cluster(src->sec_identity))
		goto out;

	/* Redirect to the WireGuard tunnel device if the encryption is
	 * required.
	 */
	if (dst && dst->key) {
	    printk("real REDIRECT to %d", HBONE_IFINDEX);
//		return ctx_redirect_hbone(ctx);
//		return ctx_redirect(ctx, WG_IFINDEX, 0);
		return ctx_redirect(ctx, HBONE_IFINDEX, 0);
    }

out:
	return CTX_ACT_OK;
}

#ifdef ENCRYPTION_STRICT_MODE

/* strict_allow checks whether the packet is allowed to pass through the strict mode. */
static __always_inline bool
strict_allow(struct __ctx_buff *ctx) {
	struct remote_endpoint_info __maybe_unused *dest_info, __maybe_unused *src_info;
	bool __maybe_unused in_strict_cidr = false;
	void *data, *data_end;
#ifdef ENABLE_IPV4
	struct iphdr *ip4;
#endif
	__u16 proto = 0;

	if (!validate_ethertype(ctx, &proto))
		return true;

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return true;

		/* Allow traffic that is sent from the node:
		 * (1) When encapsulation is used and the destination is a remote pod.
		 * (2) When the destination is a remote-node.
		 */
		if (ip4->saddr == IPV4_GATEWAY || ip4->saddr == IPV4_ENCRYPT_IFACE)
			return true;

		in_strict_cidr = ipv4_is_in_subnet(ip4->daddr,
						   STRICT_IPV4_NET,
						   STRICT_IPV4_NET_SIZE);
		in_strict_cidr &= ipv4_is_in_subnet(ip4->saddr,
						    STRICT_IPV4_NET,
						    STRICT_IPV4_NET_SIZE);

#if defined(TUNNEL_MODE) || defined(STRICT_IPV4_OVERLAPPING_CIDR)
		/* Allow pod to remote-node communication */
		dest_info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (dest_info && dest_info->sec_identity &&
		    identity_is_node(dest_info->sec_identity))
			return true;
#endif /* TUNNEL_MODE || STRICT_IPV4_OVERLAPPING_CIDR */
		return !in_strict_cidr;
#endif /* ENABLE_IPV4 */
	default:
		return true;
	}
}

#endif /* ENCRYPTION_STRICT_MODE */

#endif /* __WIREGUARD_H_ */

#endif /* ENABLE_WIREGUARD */
