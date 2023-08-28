/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifdef ENABLE_WIREGUARD

#ifndef __WIREGUARD_H_
#define __WIREGUARD_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "tailcall.h"
#include "common.h"
#include "lib/proxy.h"
#include "lib/proxy_hairpin.h"
#include "overloadable.h"

static __always_inline int
wg_maybe_redirect_to_encrypt(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info *dst;
	struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data, *data_end;
	__u16 proto = 0;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	__u8 __maybe_unused icmp_type = 0;

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
			if (data + sizeof(*ip6) + ETH_HLEN +
			    sizeof(struct icmp6hdr) > data_end)
				return DROP_INVALID;
			icmp_type = icmp6_load_type(ctx, ETH_HLEN);
			if (icmp_type == ICMP6_NA_MSG_TYPE)
				goto out;
		}
#endif
		dst = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
#ifndef ENABLE_NODE_ENCRYPTION
		src = lookup_ip6_remote_endpoint((union v6addr *)&ip6->saddr, 0);
#endif /* ENABLE_NODE_ENCRYPTION */
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		dst = lookup_ip4_remote_endpoint(ip4->daddr, 0);
#ifndef ENABLE_NODE_ENCRYPTION
		src = lookup_ip4_remote_endpoint(ip4->saddr, 0);
#endif /* ENABLE_NODE_ENCRYPTION */
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
	if (!src || src->sec_label == HOST_ID)
		goto out;
#endif /* ENABLE_NODE_ENCRYPTION */

	/* Redirect to the WireGuard tunnel device if the encryption is
	 * required.
	 */
//#ifdef ENABLE_IPV4
//	if (dst && dst->key) {
//	    printk("wireguard hit %d", HBONE_IFINDEX);
//		printk("dst %pI4, src %pI4", &ip4->daddr, &ip4->saddr);
//		ret = ctx_redirect(ctx, HBONE_IFINDEX, 0);
//	    printk("wireguard ret %d", ret);
//		return ret;
//        ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
//        return ctx_redirect_to_proxy_hairpin_ipv4(ctx, 15008);
//        return ctx_redirect_to_proxy_first(ctx, 15008);
//#endif
//    }

out:
	return CTX_ACT_OK;
}

#endif /* __WIREGUARD_H_ */

#endif /* ENABLE_WIREGUARD */
