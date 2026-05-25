// SPDX-License-Identifier: GPL-2.0-or-later
/* linux/net/ipv4/arp.c
 *
 * Copyright (C) 1994 by Florian  La Roche
 *
 * This module implements the Address Resolution Protocol ARP (RFC 826),
 * which is used to convert IP addresses (or in the future maybe other
 * high-level addresses) into a low-level hardware address (like an Ethernet
 * address).
 *
 * Fixes:
 *		Alan Cox	:	Removed the Ethernet assumptions in
 *					Florian's code
 *		Alan Cox	:	Fixed some small errors in the ARP
 *					logic
 *		Alan Cox	:	Allow >4K in /proc
 *		Alan Cox	:	Make ARP add its own protocol entry
 *		Ross Martin     :       Rewrote arp_rcv() and arp_get_info()
 *		Stephen Henson	:	Add AX25 support to arp_get_info()
 *		Alan Cox	:	Drop data when a device is downed.
 *		Alan Cox	:	Use init_timer().
 *		Alan Cox	:	Double lock fixes.
 *		Martin Seine	:	Move the arphdr structure
 *					to if_arp.h for compatibility.
 *					with BSD based programs.
 *		Andrew Tridgell :       Added ARP netmask code and
 *					re-arranged proxy handling.
 *		Alan Cox	:	Changed to use notifiers.
 *		Niibe Yutaka	:	Reply for this device or proxies only.
 *		Alan Cox	:	Don't proxy across hardware types!
 *		Jonathan Naylor :	Added support for NET/ROM.
 *		Mike Shaver     :       RFC1122 checks.
 *		Jonathan Naylor :	Only lookup the hardware address for
 *					the correct hardware type.
 *		Germano Caronni	:	Assorted subtle races.
 *		Craig Schlenter :	Don't modify permanent entry
 *					during arp_rcv.
 *		Russ Nelson	:	Tidied up a few bits.
 *		Alexey Kuznetsov:	Major changes to caching and behaviour,
 *					eg intelligent arp probing and
 *					generation
 *					of host down events.
 *		Alan Cox	:	Missing unlock in device events.
 *		Eckes		:	ARP ioctl control errors.
 *		Alexey Kuznetsov:	Arp free fix.
 *		Manuel Rodriguez:	Gratuitous ARP.
 *              Jonathan Layes  :       Added arpd support through kerneld
 *                                      message queue (960314)
 *		Mike Shaver	:	/proc/sys/net/ipv4/arp_* support
 *		Mike McLagan    :	Routing by source
 *		Stuart Cheshire	:	Metricom and grat arp fixes
 *					*** FOR 2.1 clean this up ***
 *		Lawrence V. Stefani: (08/12/96) Added FDDI support.
 *		Alan Cox	:	Took the AP1000 nasty FDDI hack and
 *					folded into the mainstream FDDI code.
 *					Ack spit, Linus how did you allow that
 *					one in...
 *		Jes Sorensen	:	Make FDDI work again in 2.1.x and
 *					clean up the APFDDI & gen. FDDI bits.
 *		Alexey Kuznetsov:	new arp state machine;
 *					now it is in net/core/neighbour.c.
 *		Krzysztof Halasa:	Added Frame Relay ARP support.
 *		Arnaldo C. Melo :	convert /proc/net/arp to seq_file
 *		Shmulik Hen:		Split arp_send to arp_create and
 *					arp_xmit so intermediate drivers like
 *					bonding can change the skb before
 *					sending (e.g. insert 8021q tag).
 *		Harald Welte	:	convert to make use of jenkins hash
 *		Jesper D. Brouer:       Proxy ARP PVLAN RFC 3069 support.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/fddidevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/ax25.h>
#include <net/netrom.h>
#include <net/dst_metadata.h>
#include <net/ip_tunnels.h>

#include <linux/uaccess.h>

#include <linux/netfilter_arp.h>

/*
 *	Interface to generic neighbour cache.
 */
static u32 arp_hash(const void *pkey, const struct net_device *dev, __u32 *hash_rnd);
static bool arp_key_eq(const struct neighbour *n, const void *pkey);
static int arp_constructor(struct neighbour *neigh);
static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb);
static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb);
static void parp_redo(struct sk_buff *skb);
static int arp_is_multicast(const void *pkey);

static const struct neigh_ops arp_generic_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_connected_output,
};

static const struct neigh_ops arp_hh_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,  		//arp请求 annouce 申请数据包
	.error_report =		arp_error_report, //当邻居解析失败
	.output =		neigh_resolve_output,
	.connected_output =	neigh_resolve_output,
};

static const struct neigh_ops arp_direct_ops = {
	.family =		AF_INET,
	.output =		neigh_direct_output,
	.connected_output =	neigh_direct_output,
};

struct neigh_table arp_tbl = {
	.family		= AF_INET,
	.key_len	= 4,					 //目的ip是4字节
	.protocol	= cpu_to_be16(ETH_P_IP), //
	.hash		= arp_hash,				 //查hash表时候的hash函数 ipv4+netdev+随机值
	.key_eq		= arp_key_eq,			 //比较key是否相同
	.constructor	= arp_constructor,   //初始化
	.proxy_redo	= parp_redo,			 //代理arp
	.is_multicast	= arp_is_multicast,  //判断ip 地址是否是多播地址
	.id		= "arp_cache",
	.parms		= {						 //默认邻居表项的时间 	
		.tbl			= &arp_tbl,
		.reachable_time		= 30 * HZ,
		.data	= {
			[NEIGH_VAR_MCAST_PROBES] = 3,    	//广播的次数，，默认是3次
			[NEIGH_VAR_UCAST_PROBES] = 3,	 	//单播的次数 默认是3 表示已经知道对端的mac了
			[NEIGH_VAR_RETRANS_TIME] = 1 * HZ,  //探测重传的间隔
			[NEIGH_VAR_BASE_REACHABLE_TIME] = 30 * HZ,	 //可达时间，认为30秒有效
			////REACHABLE 老化成 STALE 后，如果又有数据要发给它，内核不会马上探测，
			// 而是先进入因为这 5 秒内如果收到了对方的正常流量，就可以顺便证明它还活着，不需要额外发 ARP 探测。
			[NEIGH_VAR_DELAY_PROBE_TIME] = 5 * HZ,		
			[NEIGH_VAR_INTERVAL_PROBE_TIME_MS] = 5 * HZ, //更细粒度的探测间隔
			[NEIGH_VAR_GC_STALETIME] = 60 * HZ,          //ARP 表项变旧之后，GC 多久可以考虑回收它
			[NEIGH_VAR_QUEUE_LEN_BYTES] = SK_WMEM_MAX,   //存包的上限
			[NEIGH_VAR_PROXY_QLEN] = 64,  				 //arp代理请求的最大数量
			[NEIGH_VAR_ANYCAST_DELAY] = 1 * HZ,
			[NEIGH_VAR_PROXY_DELAY]	= (8 * HZ) / 10,     //代理arp 回复前的延迟
			[NEIGH_VAR_LOCKTIME] = 1 * HZ,				 //在1s内不希望被覆盖
		},
	},
	.gc_interval	= 30 * HZ,        //GC 的扫描间隔
	.gc_thresh1	= 128,				  //低水位阈值，小于这个不需要清理
	.gc_thresh2	= 512,				  //中水位 清理没用的邻居表
	.gc_thresh3	= 1024,				 //压力很大，强制回收
};
EXPORT_SYMBOL(arp_tbl);

int arp_mc_map(__be32 addr, u8 *haddr, struct net_device *dev, int dir)
{
	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		ip_eth_mc_map(addr, haddr);
		return 0;
	case ARPHRD_INFINIBAND:
		ip_ib_mc_map(addr, dev->broadcast, haddr);
		return 0;
	case ARPHRD_IPGRE:
		ip_ipgre_mc_map(addr, dev->broadcast, haddr);
		return 0;
	default:
		if (dir) {
			memcpy(haddr, dev->broadcast, dev->addr_len);
			return 0;
		}
	}
	return -EINVAL;
}


static u32 arp_hash(const void *pkey,
		    const struct net_device *dev,
		    __u32 *hash_rnd)
{
	return arp_hashfn(pkey, dev, hash_rnd);
}

static bool arp_key_eq(const struct neighbour *neigh, const void *pkey)
{
	return neigh_key_eq32(neigh, pkey);
}
//create neighbor 之后会调用这个初始化函数
//初始化状态，设置回调函数
static int arp_constructor(struct neighbour *neigh)
{
	__be32 addr;
	struct net_device *dev = neigh->dev;
	struct in_device *in_dev;
	struct neigh_parms *parms;
	u32 inaddr_any = INADDR_ANY;
	//loop back 设备处理
	if (dev->flags & (IFF_LOOPBACK | IFF_POINTOPOINT))
		memcpy(neigh->primary_key, &inaddr_any, arp_tbl.key_len);
	//提取key 在createneigh的时候设置的
	addr = *(__be32 *)neigh->primary_key;
	rcu_read_lock();
	//拿到indev
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev) {
		rcu_read_unlock();
		return -EINVAL;
		}
	//返回一个地址类型，例如 rtn_unicast
	//这个值会决定后面是需要arp 二层地址类型，以及nud_state设置成什么
	neigh->type = inet_addr_type_dev_table(dev_net(dev), dev, addr);

	parms = in_dev->arp_parms;
	__neigh_parms_put(neigh->parms);
	neigh->parms = neigh_parms_clone(parms);
	rcu_read_unlock();
	//是否有headrops 在注册设备的时候通过ether_setup设置
	if (!dev->header_ops) {
		neigh->nud_state = NUD_NOARP;
		neigh->ops = &arp_direct_ops; //这个回调就是直接调用dev_queue_xmit
		neigh->output = neigh_direct_output; //同上
	} else { //以太网设备通常肯定走这里！！！！
		/* Good devices (checked by reading texts, but only Ethernet is
		   tested)

		   ARPHRD_ETHER: (ethernet, apfddi)
		   ARPHRD_FDDI: (fddi)
		   ARPHRD_IEEE802: (tr)
		   ARPHRD_METRICOM: (strip)
		   ARPHRD_ARCNET:
		   etc. etc. etc.

		   ARPHRD_IPDDP will also work, if author repairs it.
		   I did not it, because this driver does not work even
		   in old paradigm.
		 */
		//如果目的地址是多播地址，那就是不需要arp
		//直接算一个二层地址就ok了
		if (neigh->type == RTN_MULTICAST) {
			neigh->nud_state = NUD_NOARP;
			arp_mc_map(addr, neigh->ha, dev, 1);
		//回环设备的处理
		} else if (dev->flags & (IFF_NOARP | IFF_LOOPBACK)) {
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->dev_addr, dev->addr_len);
		//如果是一个广播地址或者点对点设备
		} else if (neigh->type == RTN_BROADCAST ||
			   (dev->flags & IFF_POINTOPOINT)) {
			neigh->nud_state = NUD_NOARP;
			//copy 全f
			memcpy(neigh->ha, dev->broadcast, dev->addr_len);
		}
		//设置neghbor的回调
		if (dev->header_ops->cache)
			neigh->ops = &arp_hh_ops;////正常以太网设备都这里
		else
			neigh->ops = &arp_generic_ops;//没有二层头的？  很简单，直接发

		if (neigh->nud_state & NUD_VALID)
			neigh->output = neigh->ops->connected_output;
		else
			neigh->output = neigh->ops->output;//正常的普通单播邻居表走这里，因为还没有设置状态  neigh_resolve_output
	}
	return 0;
}

static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb)
{
	dst_link_failure(skb);
	kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_FAILED);
}

/* Create and send an arp packet. */
static void arp_send_dst(int type, int ptype, __be32 dest_ip,
			 struct net_device *dev, __be32 src_ip,
			 const unsigned char *dest_hw,
			 const unsigned char *src_hw,
			 const unsigned char *target_hw,
			 struct dst_entry *dst)
{
	struct sk_buff *skb;

	/* arp on this interface. */
	if (dev->flags & IFF_NOARP)
		return;
	//构造arp报文
	skb = arp_create(type, ptype, dest_ip, dev, src_ip,
			 dest_hw, src_hw, target_hw);
	if (!skb)
		return;
	//这里通常应该是NULL
	skb_dst_set(skb, dst_clone(dst));
	//封装一个netfilter钩子，然后调用dev_queue_xmit
	arp_xmit(skb);
}

void arp_send(int type, int ptype, __be32 dest_ip,
	      struct net_device *dev, __be32 src_ip,
	      const unsigned char *dest_hw, const unsigned char *src_hw,
	      const unsigned char *target_hw)
{
	arp_send_dst(type, ptype, dest_ip, dev, src_ip, dest_hw, src_hw,
		     target_hw, NULL);
}
EXPORT_SYMBOL(arp_send);

static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb)
{
	__be32 saddr = 0;
	u8 dst_ha[MAX_ADDR_LEN], *dst_hw = NULL;
	struct net_device *dev = neigh->dev;
	__be32 target = *(__be32 *)neigh->primary_key;
	int probes = atomic_read(&neigh->probes);//探测一次后会增加
	struct in_device *in_dev;
	struct dst_entry *dst = NULL;

	rcu_read_lock();
	//获取设备的indev
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev) {
		rcu_read_unlock();
		return;
	}
	//根据announce 选择源ip地址，这里默认是0
	switch (IN_DEV_ARP_ANNOUNCE(in_dev)) {
	default:
	case 0:		/* By default announce any local IP */
		//如果数据包的源ip地址是本机的那就用这个！
		if (skb && inet_addr_type_dev_table(dev_net(dev), dev,
					  ip_hdr(skb)->saddr) == RTN_LOCAL)
			saddr = ip_hdr(skb)->saddr;
		break;
	case 1:		/* Restrict announcements of saddr in same subnet */
		if (!skb)
			break;
		
		saddr = ip_hdr(skb)->saddr;
		if (inet_addr_type_dev_table(dev_net(dev), dev,
					     saddr) == RTN_LOCAL) {
			/* saddr should be known to target */
			//目的ip和源ip必须在同一个子网中！
			if (inet_addr_onlink(in_dev, target, saddr))
				break;
		}
		saddr = 0;
		break;
	case 2:		/* Avoid secondary IPs, get a primary/preferred one */
		//不使用数据包中的ip地址，从网口中获取一个ip地址
		break;
	}
	rcu_read_unlock();
	//如果前面没选出addr这里从设备中选出一个arp用到的源地址
	if (!saddr)
		saddr = inet_select_addr(dev, target, RT_SCOPE_LINK);

	//计算探测次数是否用尽了 小于0 没用尽，貌似通常是走这个分支？ 
	//这里注意第一次探测应该走下面的分支，因为这个参数已经提前被加过了！
	probes -= NEIGH_VAR(neigh->parms, UCAST_PROBES);
	if (probes < 0) {
		if (!(READ_ONCE(neigh->nud_state) & NUD_VALID))
			pr_debug("trying to ucast probe in NUD_INVALID\n");
		neigh_ha_snapshot(dst_ha, neigh, dev);//就是从neigh中memcpy 地址到dst_ha中
		dst_hw = dst_ha;
	} else {
		//这里正常就是0
		probes -= NEIGH_VAR(neigh->parms, APP_PROBES);
		if (probes < 0) {
			neigh_app_ns(neigh);
			return;
		}
	}

	if (skb && !(dev->priv_flags & IFF_XMIT_DST_RELEASE))
		dst = skb_dst(skb);
	//构造arp报文
	arp_send_dst(ARPOP_REQUEST, ETH_P_ARP, target, dev, saddr,
		     dst_hw, dev->dev_addr, NULL, dst);
}

static int arp_ignore(struct in_device *in_dev, __be32 sip, __be32 tip)
{
	struct net *net = dev_net(in_dev->dev);
	int scope;

	switch (IN_DEV_ARP_IGNORE(in_dev)) {
	//最宽松的情况
	case 0:	/* Reply, the tip is already validated */
		return 0;
	//目的ip在这个设备上
	case 1:	/* Reply only if tip is configured on the incoming interface */
		sip = 0;
		scope = RT_SCOPE_HOST;
		break;
	//同网段限制
	case 2:	/*
		 * Reply only if tip is configured on the incoming interface
		 * and is in same subnet as sip
		 */
		scope = RT_SCOPE_HOST;
		break;
	case 3:	/* Do not reply for scope host addresses */
		sip = 0;
		scope = RT_SCOPE_LINK;
		in_dev = NULL;
		break;
	//保留
	case 4:	/* Reserved */
	case 5:
	case 6:
	case 7:
		return 0;
	//不回复
	case 8:	/* Do not reply */
		return 1;
	default:
		return 0;
	}
	return !inet_confirm_addr(net, in_dev, sip, tip, scope);
}

static int arp_accept(struct in_device *in_dev, __be32 sip)
{
	struct net *net = dev_net(in_dev->dev);
	int scope = RT_SCOPE_LINK;

	switch (IN_DEV_ARP_ACCEPT(in_dev)) {
	case 0: /* Don't create new entries from garp *///不接受任何
		return 0;
	case 1: /* Create new entries from garp */ //完全接受
		return 1;
	case 2: /* Create a neighbor in the arp table only if sip
		 * is in the same subnet as an address configured
		 * on the interface that received the garp message
		 */
		//同一子网可以接受
		return !!inet_confirm_addr(net, in_dev, sip, 0, scope);
	default:
		return 0;
	}
}

static int arp_filter(__be32 sip, __be32 tip, struct net_device *dev)
{
	struct rtable *rt;
	int flag = 0;
	/*unsigned long now; */
	struct net *net = dev_net(dev);

	rt = ip_route_output(net, sip, tip, 0, l3mdev_master_ifindex_rcu(dev));
	if (IS_ERR(rt))
		return 1;
	if (rt->dst.dev != dev) {
		__NET_INC_STATS(net, LINUX_MIB_ARPFILTER);
		flag = 1;
	}
	ip_rt_put(rt);
	return flag;
}

/*
 * Check if we can use proxy ARP for this path
 */
static inline int arp_fwd_proxy(struct in_device *in_dev,
				struct net_device *dev,	struct rtable *rt)
{
	struct in_device *out_dev;
	int imi, omi = -1;
	//一个设备，不用管了
	if (rt->dst.dev == dev)
		return 0;
	//没开启
	if (!IN_DEV_PROXY_ARP(in_dev))
		return 0;
	imi = IN_DEV_MEDIUM_ID(in_dev);
	if (imi == 0)
		return 1;
	if (imi == -1)
		return 0;

	/* place to check for proxy_arp for routes */

	out_dev = __in_dev_get_rcu(rt->dst.dev);
	if (out_dev)
		omi = IN_DEV_MEDIUM_ID(out_dev);

	return omi != imi && omi != -1;
}

/*
 * Check for RFC3069 proxy arp private VLAN (allow to send back to same dev)
 *
 * RFC3069 supports proxy arp replies back to the same interface.  This
 * is done to support (ethernet) switch features, like RFC 3069, where
 * the individual ports are not allowed to communicate with each
 * other, BUT they are allowed to talk to the upstream router.  As
 * described in RFC 3069, it is possible to allow these hosts to
 * communicate through the upstream router, by proxy_arp'ing.
 *
 * RFC 3069: "VLAN Aggregation for Efficient IP Address Allocation"
 *
 *  This technology is known by different names:
 *    In RFC 3069 it is called VLAN Aggregation.
 *    Cisco and Allied Telesyn call it Private VLAN.
 *    Hewlett-Packard call it Source-Port filtering or port-isolation.
 *    Ericsson call it MAC-Forced Forwarding (RFC Draft).
 *
 */
static inline int arp_fwd_pvlan(struct in_device *in_dev,
				struct net_device *dev,	struct rtable *rt,
				__be32 sip, __be32 tip)
{
	/* Private VLAN is only concerned about the same ethernet segment */
	if (rt->dst.dev != dev)
		return 0;

	/* Don't reply on self probes (often done by windowz boxes)*/
	if (sip == tip)
		return 0;

	if (IN_DEV_PROXY_ARP_PVLAN(in_dev))
		return 1;
	else
		return 0;
}

/*
 *	Interface to link layer: send routine and receive handler.
 */

/*
 *	Create an arp packet. If dest_hw is not set, we create a broadcast
 *	message.
 */
struct sk_buff *arp_create(int type, int ptype, __be32 dest_ip,
			   struct net_device *dev, __be32 src_ip,
			   const unsigned char *dest_hw,
			   const unsigned char *src_hw,
			   const unsigned char *target_hw)
{
	struct sk_buff *skb;
	struct arphdr *arp;
	unsigned char *arp_ptr;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;

	/*
	 *	Allocate a buffer
	 */
	//申请skb 链路层头部长度 arp报文需要的长度 还有尾部预留的，通常是0把
	skb = alloc_skb(arp_hdr_len(dev) + hlen + tlen, GFP_ATOMIC);
	if (!skb)
		return NULL;
	//移动data 和tail指针
	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	//put 尾部
	arp = skb_put(skb, arp_hdr_len(dev));
	//关联dev
	skb->dev = dev;
	skb->protocol = htons(ETH_P_ARP);
	if (!src_hw)
		src_hw = dev->dev_addr;
	//这里填充全F
	if (!dest_hw)
		dest_hw = dev->broadcast;

	/*
	 *	Fill the device header for the ARP frame
	 */
	 //填充二层头里面调用eth_header pushskb后直接memcpy 
	 // 这里传入的len是给ieee802.3用的
	if (dev_hard_header(skb, dev, ptype, dest_hw, src_hw, skb->len) < 0)
		goto out;

	/*
	 * Fill out the arp protocol part.
	 *
	 * The arp hardware type should match the device type, except for FDDI,
	 * which (according to RFC 1390) should always equal 1 (Ethernet).
	 */
	/*
	 *	Exceptions everywhere. AX.25 uses the AX.25 PID value not the
	 *	DIX code for the protocol. Make these device structure fields.
	 */
	//填 ARP 头
	switch (dev->type) {
	default:
		arp->ar_hrd = htons(dev->type);
		arp->ar_pro = htons(ETH_P_IP);
		break;

#if IS_ENABLED(CONFIG_AX25)
	case ARPHRD_AX25:
		arp->ar_hrd = htons(ARPHRD_AX25);
		arp->ar_pro = htons(AX25_P_IP);
		break;

#if IS_ENABLED(CONFIG_NETROM)
	case ARPHRD_NETROM:
		arp->ar_hrd = htons(ARPHRD_NETROM);
		arp->ar_pro = htons(AX25_P_IP);
		break;
#endif
#endif

#if IS_ENABLED(CONFIG_FDDI)
	case ARPHRD_FDDI:
		arp->ar_hrd = htons(ARPHRD_ETHER);
		arp->ar_pro = htons(ETH_P_IP);
		break;
#endif
	}
	
	arp->ar_hln = dev->addr_len;
	arp->ar_pln = 4;
	arp->ar_op = htons(type);
	//填 ARP 正文
	arp_ptr = (unsigned char *)(arp + 1);

	memcpy(arp_ptr, src_hw, dev->addr_len);
	arp_ptr += dev->addr_len;
	memcpy(arp_ptr, &src_ip, 4);
	arp_ptr += 4;

	switch (dev->type) {
#if IS_ENABLED(CONFIG_FIREWIRE_NET)
	case ARPHRD_IEEE1394:
		break;
#endif
	default:
		if (target_hw)
			memcpy(arp_ptr, target_hw, dev->addr_len);
		else
			memset(arp_ptr, 0, dev->addr_len);
		arp_ptr += dev->addr_len;
	}
	memcpy(arp_ptr, &dest_ip, 4);

	return skb;

out:
	kfree_skb(skb);
	return NULL;
}
EXPORT_SYMBOL(arp_create);

static int arp_xmit_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	return dev_queue_xmit(skb);
}

/*
 *	Send an arp packet.
 */
void arp_xmit(struct sk_buff *skb)
{
	/* Send it off, maybe filter it using firewalling first.  */
	NF_HOOK(NFPROTO_ARP, NF_ARP_OUT,
		dev_net(skb->dev), NULL, skb, NULL, skb->dev,
		arp_xmit_finish);
}
EXPORT_SYMBOL(arp_xmit);

static bool arp_is_garp(struct net *net, struct net_device *dev,
			int *addr_type, __be16 ar_op,
			__be32 sip, __be32 tip,
			unsigned char *sha, unsigned char *tha)
{
	//ip地址必须相同
	bool is_garp = tip == sip;

	/* Gratuitous ARP _replies_ also require target hwaddr to be
	 * the same as source.
	 */
	if (is_garp && ar_op == htons(ARPOP_REPLY))//是否是应答包
		is_garp =
			/* IPv4 over IEEE 1394 doesn't provide target
			 * hardware address field in its ARP payload.
			 */
			tha &&
			!memcmp(tha, sha, dev->addr_len); //标 MAC 地址 tha 必须等于源 MAC 地址 sha。

	//源ip地址必须是单播地址
	if (is_garp) {
		*addr_type = inet_addr_type_dev_table(net, dev, sip);
		if (*addr_type != RTN_UNICAST)
			is_garp = false;
	}
	return is_garp;
}

/*
 *	Process an arp request.
 */

static int arp_process(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct in_device *in_dev = __in_dev_get_rcu(dev);
	struct arphdr *arp;
	unsigned char *arp_ptr;
	struct rtable *rt;
	unsigned char *sha;
	unsigned char *tha = NULL;
	__be32 sip, tip;
	u16 dev_type = dev->type;
	int addr_type;
	struct neighbour *n;
	struct dst_entry *reply_dst = NULL;
	bool is_garp = false;

	/* arp_rcv below verifies the ARP header and verifies the device
	 * is ARP'able.
	 */

	if (!in_dev)
		goto out_free_skb;
	//拿到arp头
	arp = arp_hdr(skb);
	//验证arp报文的合法性
	switch (dev_type) {
	default:
		if (arp->ar_pro != htons(ETH_P_IP) ||
		    htons(dev_type) != arp->ar_hrd)
			goto out_free_skb;
		break;
	case ARPHRD_ETHER:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		/*
		 * ETHERNET, and Fibre Channel (which are IEEE 802
		 * devices, according to RFC 2625) devices will accept ARP
		 * hardware types of either 1 (Ethernet) or 6 (IEEE 802.2).
		 * This is the case also of FDDI, where the RFC 1390 says that
		 * FDDI devices should accept ARP hardware of (1) Ethernet,
		 * however, to be more robust, we'll accept both 1 (Ethernet)
		 * or 6 (IEEE 802.2)
		 */
		if ((arp->ar_hrd != htons(ARPHRD_ETHER) &&
		     arp->ar_hrd != htons(ARPHRD_IEEE802)) ||
		    arp->ar_pro != htons(ETH_P_IP))
			goto out_free_skb;
		break;
	case ARPHRD_AX25:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_AX25))
			goto out_free_skb;
		break;
	case ARPHRD_NETROM:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_NETROM))
			goto out_free_skb;
		break;
	}

	/* Understand only these message types */

	if (arp->ar_op != htons(ARPOP_REPLY) &&
	    arp->ar_op != htons(ARPOP_REQUEST))
		goto out_free_skb;

/*
 *	Extract fields
 */	//偏移到arp的负载 sha表示源mac地址 sip为源ip地址
	arp_ptr = (unsigned char *)(arp + 1);
	sha	= arp_ptr;
	arp_ptr += dev->addr_len;
	memcpy(&sip, arp_ptr, 4);
	arp_ptr += 4;
	switch (dev_type) {
#if IS_ENABLED(CONFIG_FIREWIRE_NET)
	case ARPHRD_IEEE1394:
		break;
#endif
	default:
		tha = arp_ptr; //处理目的mac地址
		arp_ptr += dev->addr_len;
	}
	//提取目的ip地址
	memcpy(&tip, arp_ptr, 4);
/*
 *	Check for bad requests for 127.x.x.x and requests for multicast
 *	addresses.  If this is one such, delete it.
 */
	//多播地址不处理
	if (ipv4_is_multicast(tip) ||
	    (!IN_DEV_ROUTE_LOCALNET(in_dev) && ipv4_is_loopback(tip)))
		goto out_free_skb;

 /*
  *	For some 802.11 wireless deployments (and possibly other networks),
  *	there will be an ARP proxy and gratuitous ARP frames are attacks
  *	and thus should not be accepted.
  */
	//源地址和目地地址相同 免费arp，不处理
	if (sip == tip && IN_DEV_ORCONF(in_dev, DROP_GRATUITOUS_ARP))
		goto out_free_skb;

/*
 *     Special case: We must set Frame Relay source Q.922 address
 *///帧中继
	if (dev_type == ARPHRD_DLCI)
		sha = dev->broadcast;

/*
 *  Process entry.  The idea here is we want to send a reply if it is a
 *  request for us or if it is a request for someone else that we hold
 *  a proxy for.  We want to add an entry to our cache if it is a reply
 *  to us or if it is a request for our address.
 *  (The assumption for this last is that if someone is requesting our
 *  address, they are probably intending to talk to us, so it saves time
 *  if we cache their address.  Their address is also probably not in
 *  our cache, since ours is not in their cache.)
 *
 *  Putting this another way, we only care about replies if they are to
 *  us, in which case we add them to the cache.  For requests, we care
 *  about those for us and those for our proxies.  We reply to both,
 *  and in the case of requests for us we add the requester to the arp
 *  cache.
 */
	//隧道报文的处理
	if (arp->ar_op == htons(ARPOP_REQUEST) && skb_metadata_dst(skb))
		reply_dst = (struct dst_entry *)
			    iptunnel_metadata_reply(skb_metadata_dst(skb),
						    GFP_ATOMIC);

	/* Special case: IPv4 duplicate address detection packet (RFC2131) */
	//源ip地址为0的情况，可以用于是否检测存在ip冲突
	if (sip == 0) {
		if (arp->ar_op == htons(ARPOP_REQUEST) &&
		    inet_addr_type_dev_table(net, dev, tip) == RTN_LOCAL && //tip是本机IP
		    !arp_ignore(in_dev, sip, tip)) //是否允许回复
			//构造arp报文并回复
			arp_send_dst(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip,
				     sha, dev->dev_addr, sha, reply_dst);
		goto out_consume_skb;
	}
	//arp请求 && 根据目的ip进行路由查找
	if (arp->ar_op == htons(ARPOP_REQUEST) &&
	    ip_route_input_noref(skb, tip, sip, 0, dev) == 0) {

		rt = skb_rtable(skb);
		addr_type = rt->rt_type;
		//是发给本地的
		if (addr_type == RTN_LOCAL) {
			int dont_send;
			//目标IP是本机地址 (RTN_LOCAL)
			dont_send = arp_ignore(in_dev, sip, tip);
			//dont_send == 0 表示允许发送，如果配置了arpfilter在进行反向路径过滤检查
			if (!dont_send && IN_DEV_ARPFILTER(in_dev))
				dont_send = arp_filter(sip, tip, dev);
			//可以发送
			if (!dont_send) {
				//这里可能创建邻居表象
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);
				if (n) {
					arp_send_dst(ARPOP_REPLY, ETH_P_ARP,
						     sip, dev, tip, sha,
						     dev->dev_addr, sha,
						     reply_dst);
					neigh_release(n);
				}
			}
			goto out_consume_skb;
		} else if (IN_DEV_FORWARD(in_dev)) { //设备开启了转发
			if (addr_type == RTN_UNICAST  && //路由结果是单播
			    (arp_fwd_proxy(in_dev, dev, rt) || 	//系统层面允许arp代理
			     arp_fwd_pvlan(in_dev, dev, rt, sip, tip) ||
			     (rt->dst.dev != dev &&
			      pneigh_lookup(&arp_tbl, net, &tip, dev, 0)))) {//查找是否这个ip配置了需要代理回答，注意这里没有创建条目
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);//这里创建可能会创建一个条目
				if (n)
					neigh_release(n);

				if (NEIGH_CB(skb)->flags & LOCALLY_ENQUEUED ||	//以前已经排队过了
				    skb->pkt_type == PACKET_HOST ||				//数据包的目的mac就是本机的
				    NEIGH_VAR(in_dev->arp_parms, PROXY_DELAY) == 0) { //管理员把代理延迟设成了 0
					arp_send_dst(ARPOP_REPLY, ETH_P_ARP,
						     sip, dev, tip, sha,
						     dev->dev_addr, sha,
						     reply_dst);
				} else {
					//数据包入队计算响应时间，启动定时器
					pneigh_enqueue(&arp_tbl,
						       in_dev->arp_parms, skb);
					goto out_free_dst;
				}
				goto out_consume_skb;
			}
		}
	}

	/* Update our ARP tables */
	//查找邻居表项，注意这里不创建
	n = __neigh_lookup(&arp_tbl, &sip, dev, 0);

	addr_type = -1;
	if (n || arp_accept(in_dev, sip)) {//邻居表项已经存在，或者可以接受一个不请自来的arp（通常是0）
		is_garp = arp_is_garp(net, dev, &addr_type, arp->ar_op,//是否是免费arp
				      sip, tip, sha, tha);
	}
	//这里默认是0
	if (arp_accept(in_dev, sip)) {
		/* Unsolicited ARP is not accepted by default.
		   It is possible, that this option should be enabled for some
		   devices (strip is candidate)
		 */
		//if (邻居条目不存在 && (是免费ARP || (是ARP应答 && 源IP是单播地址)))
		if (!n &&
		    (is_garp ||
		     (arp->ar_op == htons(ARPOP_REPLY) &&
		      (addr_type == RTN_UNICAST ||
		       (addr_type < 0 &&
			/* postpone calculation to as late as possible */
			inet_addr_type_dev_table(net, dev, sip) ==
				RTN_UNICAST)))))
			//不存在就创建
			n = __neigh_lookup(&arp_tbl, &sip, dev, 1);
	}

	if (n) {
		int state = NUD_REACHABLE;//可达状态
		int override;

		/* If several different ARP replies follows back-to-back,
		   use the FIRST one. It is possible, if several proxy
		   agents are active. Taking the first reply prevents
		   arp trashing and chooses the fastest router.
		 */
		override = time_after(jiffies,
				      n->updated +
				      NEIGH_VAR(n->parms, LOCKTIME)) || //距离上次更新超过 锁定期（LOCKTIME，默认约1秒）
			   is_garp; //免费arp

		/* Broadcast replies and request packets
		   do not assert neighbour reachability.
		 */
		if (arp->ar_op != htons(ARPOP_REPLY) ||
		    skb->pkt_type != PACKET_HOST) //mac地址不是本机，那就是stale
			state = NUD_STALE;
		//执行更新
		neigh_update(n, sha, state,
			     override ? NEIGH_UPDATE_F_OVERRIDE : 0, 0);
		//减少引用计数
		neigh_release(n);
	}

out_consume_skb:
	consume_skb(skb);

out_free_dst:
	dst_release(reply_dst);
	return NET_RX_SUCCESS;

out_free_skb:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static void parp_redo(struct sk_buff *skb)
{
	arp_process(dev_net(skb->dev), NULL, skb);
}

static int arp_is_multicast(const void *pkey)
{
	return ipv4_is_multicast(*((__be32 *)pkey));
}

/*
 *	Receive an arp request from the device layer.
 */

static int arp_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
{
	const struct arphdr *arp;

	/* do not tweak dropwatch on an ARP we will ignore */
	if (dev->flags & IFF_NOARP ||
	    skb->pkt_type == PACKET_OTHERHOST ||
	    skb->pkt_type == PACKET_LOOPBACK)
		goto consumeskb;
	//检查skb的usr引用计数
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto out_of_mem;

	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  */
	//拉一下arp头
	if (!pskb_may_pull(skb, arp_hdr_len(dev)))
		goto freeskb;
	//非法检查
	arp = arp_hdr(skb);
	if (arp->ar_hln != dev->addr_len || arp->ar_pln != 4)
		goto freeskb;

	memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));
	//经过netfilter后给arp_process
	return NF_HOOK(NFPROTO_ARP, NF_ARP_IN,
		       dev_net(dev), NULL, skb, dev, NULL,
		       arp_process);

consumeskb:
	consume_skb(skb);
	return NET_RX_SUCCESS;
freeskb:
	kfree_skb(skb);
out_of_mem:
	return NET_RX_DROP;
}

/*
 *	User level interface (ioctl)
 */

/*
 *	Set (create) an ARP cache entry.
 */

static int arp_req_set_proxy(struct net *net, struct net_device *dev, int on)
{
	if (!dev) {
		IPV4_DEVCONF_ALL(net, PROXY_ARP) = on;
		return 0;
	}
	if (__in_dev_get_rtnl(dev)) {
		IN_DEV_CONF_SET(__in_dev_get_rtnl(dev), PROXY_ARP, on);
		return 0;
	}
	return -ENXIO;
}

static int arp_req_set_public(struct net *net, struct arpreq *r,
		struct net_device *dev)
{
	__be32 ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	__be32 mask = ((struct sockaddr_in *)&r->arp_netmask)->sin_addr.s_addr;

	if (mask && mask != htonl(0xFFFFFFFF))
		return -EINVAL;
	if (!dev && (r->arp_flags & ATF_COM)) {
		dev = dev_getbyhwaddr_rcu(net, r->arp_ha.sa_family,
				      r->arp_ha.sa_data);
		if (!dev)
			return -ENODEV;
	}
	if (mask) {
		if (!pneigh_lookup(&arp_tbl, net, &ip, dev, 1))
			return -ENOBUFS;
		return 0;
	}

	return arp_req_set_proxy(net, dev, 1);
}

static int arp_req_set(struct net *net, struct arpreq *r,
		       struct net_device *dev)
{
	__be32 ip;
	struct neighbour *neigh;
	int err;

	if (r->arp_flags & ATF_PUBL)
		return arp_req_set_public(net, r, dev);

	ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	if (r->arp_flags & ATF_PERM)
		r->arp_flags |= ATF_COM;
	if (!dev) {
		struct rtable *rt = ip_route_output(net, ip, 0, RTO_ONLINK, 0);

		if (IS_ERR(rt))
			return PTR_ERR(rt);
		dev = rt->dst.dev;
		ip_rt_put(rt);
		if (!dev)
			return -EINVAL;
	}
	switch (dev->type) {
#if IS_ENABLED(CONFIG_FDDI)
	case ARPHRD_FDDI:
		/*
		 * According to RFC 1390, FDDI devices should accept ARP
		 * hardware types of 1 (Ethernet).  However, to be more
		 * robust, we'll accept hardware types of either 1 (Ethernet)
		 * or 6 (IEEE 802.2).
		 */
		if (r->arp_ha.sa_family != ARPHRD_FDDI &&
		    r->arp_ha.sa_family != ARPHRD_ETHER &&
		    r->arp_ha.sa_family != ARPHRD_IEEE802)
			return -EINVAL;
		break;
#endif
	default:
		if (r->arp_ha.sa_family != dev->type)
			return -EINVAL;
		break;
	}

	neigh = __neigh_lookup_errno(&arp_tbl, &ip, dev);
	err = PTR_ERR(neigh);
	if (!IS_ERR(neigh)) {
		unsigned int state = NUD_STALE;
		if (r->arp_flags & ATF_PERM)
			state = NUD_PERMANENT;
		err = neigh_update(neigh, (r->arp_flags & ATF_COM) ?
				   r->arp_ha.sa_data : NULL, state,
				   NEIGH_UPDATE_F_OVERRIDE |
				   NEIGH_UPDATE_F_ADMIN, 0);
		neigh_release(neigh);
	}
	return err;
}

static unsigned int arp_state_to_flags(struct neighbour *neigh)
{
	if (neigh->nud_state&NUD_PERMANENT)
		return ATF_PERM | ATF_COM;
	else if (neigh->nud_state&NUD_VALID)
		return ATF_COM;
	else
		return 0;
}

/*
 *	Get an ARP cache entry.
 */

static int arp_req_get(struct arpreq *r, struct net_device *dev)
{
	__be32 ip = ((struct sockaddr_in *) &r->arp_pa)->sin_addr.s_addr;
	struct neighbour *neigh;
	int err = -ENXIO;

	neigh = neigh_lookup(&arp_tbl, &ip, dev);
	if (neigh) {
		if (!(READ_ONCE(neigh->nud_state) & NUD_NOARP)) {
			read_lock_bh(&neigh->lock);
			memcpy(r->arp_ha.sa_data, neigh->ha, dev->addr_len);
			r->arp_flags = arp_state_to_flags(neigh);
			read_unlock_bh(&neigh->lock);
			r->arp_ha.sa_family = dev->type;
			strscpy(r->arp_dev, dev->name, sizeof(r->arp_dev));
			err = 0;
		}
		neigh_release(neigh);
	}
	return err;
}

int arp_invalidate(struct net_device *dev, __be32 ip, bool force)
{
	struct neighbour *neigh = neigh_lookup(&arp_tbl, &ip, dev);
	int err = -ENXIO;
	struct neigh_table *tbl = &arp_tbl;

	if (neigh) {
		if ((READ_ONCE(neigh->nud_state) & NUD_VALID) && !force) {
			neigh_release(neigh);
			return 0;
		}

		if (READ_ONCE(neigh->nud_state) & ~NUD_NOARP)
			err = neigh_update(neigh, NULL, NUD_FAILED,
					   NEIGH_UPDATE_F_OVERRIDE|
					   NEIGH_UPDATE_F_ADMIN, 0);
		write_lock_bh(&tbl->lock);
		neigh_release(neigh);
		neigh_remove_one(neigh, tbl);
		write_unlock_bh(&tbl->lock);
	}

	return err;
}

static int arp_req_delete_public(struct net *net, struct arpreq *r,
		struct net_device *dev)
{
	__be32 ip = ((struct sockaddr_in *) &r->arp_pa)->sin_addr.s_addr;
	__be32 mask = ((struct sockaddr_in *)&r->arp_netmask)->sin_addr.s_addr;

	if (mask == htonl(0xFFFFFFFF))
		return pneigh_delete(&arp_tbl, net, &ip, dev);

	if (mask)
		return -EINVAL;

	return arp_req_set_proxy(net, dev, 0);
}

static int arp_req_delete(struct net *net, struct arpreq *r,
			  struct net_device *dev)
{
	__be32 ip;

	if (r->arp_flags & ATF_PUBL)
		return arp_req_delete_public(net, r, dev);

	ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	if (!dev) {
		struct rtable *rt = ip_route_output(net, ip, 0, RTO_ONLINK, 0);
		if (IS_ERR(rt))
			return PTR_ERR(rt);
		dev = rt->dst.dev;
		ip_rt_put(rt);
		if (!dev)
			return -EINVAL;
	}
	return arp_invalidate(dev, ip, true);
}

/*
 *	Handle an ARP layer I/O control request.
 */

int arp_ioctl(struct net *net, unsigned int cmd, void __user *arg)
{
	int err;
	struct arpreq r;
	struct net_device *dev = NULL;

	switch (cmd) {
	case SIOCDARP:
	case SIOCSARP:
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			return -EPERM;
		fallthrough;
	case SIOCGARP:
		err = copy_from_user(&r, arg, sizeof(struct arpreq));
		if (err)
			return -EFAULT;
		break;
	default:
		return -EINVAL;
	}

	if (r.arp_pa.sa_family != AF_INET)
		return -EPFNOSUPPORT;

	if (!(r.arp_flags & ATF_PUBL) &&
	    (r.arp_flags & (ATF_NETMASK | ATF_DONTPUB)))
		return -EINVAL;
	if (!(r.arp_flags & ATF_NETMASK))
		((struct sockaddr_in *)&r.arp_netmask)->sin_addr.s_addr =
							   htonl(0xFFFFFFFFUL);
	rtnl_lock();
	if (r.arp_dev[0]) {
		err = -ENODEV;
		dev = __dev_get_by_name(net, r.arp_dev);
		if (!dev)
			goto out;

		/* Mmmm... It is wrong... ARPHRD_NETROM==0 */
		if (!r.arp_ha.sa_family)
			r.arp_ha.sa_family = dev->type;
		err = -EINVAL;
		if ((r.arp_flags & ATF_COM) && r.arp_ha.sa_family != dev->type)
			goto out;
	} else if (cmd == SIOCGARP) {
		err = -ENODEV;
		goto out;
	}

	switch (cmd) {
	case SIOCDARP:
		err = arp_req_delete(net, &r, dev);
		break;
	case SIOCSARP:
		err = arp_req_set(net, &r, dev);
		break;
	case SIOCGARP:
		err = arp_req_get(&r, dev);
		break;
	}
out:
	rtnl_unlock();
	if (cmd == SIOCGARP && !err && copy_to_user(arg, &r, sizeof(r)))
		err = -EFAULT;
	return err;
}

static int arp_netdev_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_notifier_change_info *change_info;
	struct in_device *in_dev;
	bool evict_nocarrier;

	switch (event) {
	//网卡mac地址发生变化
	case NETDEV_CHANGEADDR:
	//会遍历 ARP 邻居表，把和这个网卡相关的邻居项重新处理
		neigh_changeaddr(&arp_tbl, dev);
		//刷新路由缓存
		rt_cache_flush(dev_net(dev));
		break;
	//link up /down
	case NETDEV_CHANGE:
		change_info = ptr;
		//IFF_NOARP 这个bit这次有没有变化
		if (change_info->flags_changed & IFF_NOARP)
			neigh_changeaddr(&arp_tbl, dev);

		in_dev = __in_dev_get_rtnl(dev);
		if (!in_dev)
			evict_nocarrier = true;
		else
		//通常走这个，是否主动清理arp表项
			evict_nocarrier = IN_DEV_ARP_EVICT_NOCARRIER(in_dev);
		//link已经donw了，清理的更彻底
		if (evict_nocarrier && !netif_carrier_ok(dev))
			neigh_carrier_down(&arp_tbl, dev);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block arp_netdev_notifier = {
	.notifier_call = arp_netdev_event,
};

/* Note, that it is not on notifier chain.
   It is necessary, that this routine was called after route cache will be
   flushed.
 */
void arp_ifdown(struct net_device *dev)
{
	neigh_ifdown(&arp_tbl, dev);
}


/*
 *	Called once on startup.
 */

static struct packet_type arp_packet_type __read_mostly = {
	.type =	cpu_to_be16(ETH_P_ARP),
	.func =	arp_rcv,
};

#ifdef CONFIG_PROC_FS
#if IS_ENABLED(CONFIG_AX25)

/*
 *	ax25 -> ASCII conversion
 */
static void ax2asc2(ax25_address *a, char *buf)
{
	char c, *s;
	int n;

	for (n = 0, s = buf; n < 6; n++) {
		c = (a->ax25_call[n] >> 1) & 0x7F;

		if (c != ' ')
			*s++ = c;
	}

	*s++ = '-';
	n = (a->ax25_call[6] >> 1) & 0x0F;
	if (n > 9) {
		*s++ = '1';
		n -= 10;
	}

	*s++ = n + '0';
	*s++ = '\0';

	if (*buf == '\0' || *buf == '-') {
		buf[0] = '*';
		buf[1] = '\0';
	}
}
#endif /* CONFIG_AX25 */

#define HBUFFERLEN 30

static void arp_format_neigh_entry(struct seq_file *seq,
				   struct neighbour *n)
{
	char hbuffer[HBUFFERLEN];
	int k, j;
	char tbuf[16];
	struct net_device *dev = n->dev;
	int hatype = dev->type;

	read_lock(&n->lock);
	/* Convert hardware address to XX:XX:XX:XX ... form. */
#if IS_ENABLED(CONFIG_AX25)
	if (hatype == ARPHRD_AX25 || hatype == ARPHRD_NETROM)
		ax2asc2((ax25_address *)n->ha, hbuffer);
	else {
#endif
	for (k = 0, j = 0; k < HBUFFERLEN - 3 && j < dev->addr_len; j++) {
		hbuffer[k++] = hex_asc_hi(n->ha[j]);
		hbuffer[k++] = hex_asc_lo(n->ha[j]);
		hbuffer[k++] = ':';
	}
	if (k != 0)
		--k;
	hbuffer[k] = 0;
#if IS_ENABLED(CONFIG_AX25)
	}
#endif
	sprintf(tbuf, "%pI4", n->primary_key);
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%-17s     *        %s\n",
		   tbuf, hatype, arp_state_to_flags(n), hbuffer, dev->name);
	read_unlock(&n->lock);
}

static void arp_format_pneigh_entry(struct seq_file *seq,
				    struct pneigh_entry *n)
{
	struct net_device *dev = n->dev;
	int hatype = dev ? dev->type : 0;
	char tbuf[16];

	sprintf(tbuf, "%pI4", n->key);
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
		   tbuf, hatype, ATF_PUBL | ATF_PERM, "00:00:00:00:00:00",
		   dev ? dev->name : "*");
}

static int arp_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "IP address       HW type     Flags       "
			      "HW address            Mask     Device\n");
	} else {
		struct neigh_seq_state *state = seq->private;

		if (state->flags & NEIGH_SEQ_IS_PNEIGH)
			arp_format_pneigh_entry(seq, v);
		else
			arp_format_neigh_entry(seq, v);
	}

	return 0;
}

static void *arp_seq_start(struct seq_file *seq, loff_t *pos)
{
	/* Don't want to confuse "arp -a" w/ magic entries,
	 * so we tell the generic iterator to skip NUD_NOARP.
	 */
	return neigh_seq_start(seq, pos, &arp_tbl, NEIGH_SEQ_SKIP_NOARP);
}

static const struct seq_operations arp_seq_ops = {
	.start	= arp_seq_start,
	.next	= neigh_seq_next,
	.stop	= neigh_seq_stop,
	.show	= arp_seq_show,
};
#endif /* CONFIG_PROC_FS */

static int __net_init arp_net_init(struct net *net)
{
	if (!proc_create_net("arp", 0444, net->proc_net, &arp_seq_ops,
			sizeof(struct neigh_seq_state)))
		return -ENOMEM;
	return 0;
}

static void __net_exit arp_net_exit(struct net *net)
{
	remove_proc_entry("arp", net->proc_net);
}

static struct pernet_operations arp_net_ops = {
	.init = arp_net_init,
	.exit = arp_net_exit,
};

void __init arp_init(void)
{
	//把arp_tbl注册到邻居子系统
	neigh_table_init(NEIGH_ARP_TABLE, &arp_tbl);
	//注册arp rcv
	dev_add_pack(&arp_packet_type);
	//每个命令空间一个导出文件
	register_pernet_subsys(&arp_net_ops);
#ifdef CONFIG_SYSCTL
	//sysctl 导出文件
	neigh_sysctl_register(NULL, &arp_tbl.parms, NULL);
#endif
	//注册通知链
	register_netdevice_notifier(&arp_netdev_notifier);
}
