// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: FIB frontend.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>

#include <net/inet_dscp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/ip_fib.h>
#include <net/nexthop.h>
#include <net/rtnetlink.h>
#include <net/xfrm.h>
#include <net/l3mdev.h>
#include <net/lwtunnel.h>
#include <trace/events/fib.h>

#ifndef CONFIG_IP_MULTIPLE_TABLES

static int __net_init fib4_rules_init(struct net *net)
{
	struct fib_table *local_table, *main_table;

	main_table  = fib_trie_table(RT_TABLE_MAIN, NULL);
	if (!main_table)
		return -ENOMEM;

	local_table = fib_trie_table(RT_TABLE_LOCAL, main_table);
	if (!local_table)
		goto fail;

	hlist_add_head_rcu(&local_table->tb_hlist,
				&net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX]);
	hlist_add_head_rcu(&main_table->tb_hlist,
				&net->ipv4.fib_table_hash[TABLE_MAIN_INDEX]);
	return 0;

fail:
	fib_free_table(main_table);
	return -ENOMEM;
}
#else
//根据ID找到一个table 没有就创建一个
struct fib_table *fib_new_table(struct net *net, u32 id)
{
	struct fib_table *tb, *alias = NULL;
	unsigned int h;
	//默认是main表
	if (id == 0)
		id = RT_TABLE_MAIN;
	tb = fib_get_table(net, id);
	if (tb)
		return tb;
	//这里需要注意这里是递归调用，只有传入 参数是local才有可能进入
	//其实这个是给设备配置id 通知链调用的时候这里就是local了 这里会创建一个main表
	if (id == RT_TABLE_LOCAL && !net->ipv4.fib_has_custom_rules)
		alias = fib_new_table(net, RT_TABLE_MAIN);
	//这里是真正的malloc一个路由表
	tb = fib_trie_table(id, alias);
	if (!tb)
		return NULL;

	switch (id) {
	case RT_TABLE_MAIN:
		//关联上面申请的路由表
		rcu_assign_pointer(net->ipv4.fib_main, tb);
		break;
	case RT_TABLE_DEFAULT:
		rcu_assign_pointer(net->ipv4.fib_default, tb);
		break;
	default:
		break;
	}
	//fib_table_hash 哈希表
	h = id & (FIB_TABLE_HASHSZ - 1);
	hlist_add_head_rcu(&tb->tb_hlist, &net->ipv4.fib_table_hash[h]);
	return tb;
}
EXPORT_SYMBOL_GPL(fib_new_table);

/* caller must hold either rtnl or rcu read lock */
struct fib_table *fib_get_table(struct net *net, u32 id)
{
	struct fib_table *tb;
	struct hlist_head *head;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	h = id & (FIB_TABLE_HASHSZ - 1);

	head = &net->ipv4.fib_table_hash[h];
	hlist_for_each_entry_rcu(tb, head, tb_hlist,
				 lockdep_rtnl_is_held()) {
		if (tb->tb_id == id)
			return tb;
	}
	return NULL;
}
#endif /* CONFIG_IP_MULTIPLE_TABLES */

static void fib_replace_table(struct net *net, struct fib_table *old,
			      struct fib_table *new)
{
#ifdef CONFIG_IP_MULTIPLE_TABLES
	switch (new->tb_id) {
	case RT_TABLE_MAIN:
		rcu_assign_pointer(net->ipv4.fib_main, new);
		break;
	case RT_TABLE_DEFAULT:
		rcu_assign_pointer(net->ipv4.fib_default, new);
		break;
	default:
		break;
	}

#endif
	/* replace the old table in the hlist */
	hlist_replace_rcu(&old->tb_hlist, &new->tb_hlist);
}

int fib_unmerge(struct net *net)
{
	struct fib_table *old, *new, *main_table;

	/* attempt to fetch local table if it has been allocated */
	old = fib_get_table(net, RT_TABLE_LOCAL);
	if (!old)
		return 0;

	new = fib_trie_unmerge(old);
	if (!new)
		return -ENOMEM;

	/* table is already unmerged */
	if (new == old)
		return 0;

	/* replace merged table with clean table */
	fib_replace_table(net, old, new);
	fib_free_table(old);

	/* attempt to fetch main table if it has been allocated */
	main_table = fib_get_table(net, RT_TABLE_MAIN);
	if (!main_table)
		return 0;

	/* flush local entries from main table */
	fib_table_flush_external(main_table);

	return 0;
}

void fib_flush(struct net *net)
{
	int flushed = 0;
	unsigned int h;

	for (h = 0; h < FIB_TABLE_HASHSZ; h++) {
		struct hlist_head *head = &net->ipv4.fib_table_hash[h];
		struct hlist_node *tmp;
		struct fib_table *tb;

		hlist_for_each_entry_safe(tb, tmp, head, tb_hlist)
			flushed += fib_table_flush(net, tb, false);
	}

	if (flushed)
		rt_cache_flush(net);
}

/*
 * Find address type as if only "dev" was present in the system. If
 * on_dev is NULL then all interfaces are taken into consideration.
 */
//套接字层的bind会调用，返回一个地址类型
static inline unsigned int __inet_dev_addr_type(struct net *net,
						const struct net_device *dev,
						__be32 addr, u32 tb_id)
{
	struct flowi4		fl4 = { .daddr = addr };
	struct fib_result	res;
	unsigned int ret = RTN_BROADCAST;
	struct fib_table *table;
	//快速判断是否是全0或者全255（有限广播地址）
	if (ipv4_is_zeronet(addr) || ipv4_is_lbcast(addr))
		return RTN_BROADCAST;
	//判断是否是多播
	if (ipv4_is_multicast(addr))
		return RTN_MULTICAST;

	rcu_read_lock();
	//根据id拿到路由表
	table = fib_get_table(net, tb_id);
	if (table) {
		//默认先设置为单播地址
		ret = RTN_UNICAST;
		//这里直接调用查路路由的接口，fl4只有一个目的ip
		if (!fib_table_lookup(table, &fl4, &res, FIB_LOOKUP_NOREF)) {
			struct fib_nh_common *nhc = fib_info_nhc(res.fi, 0);

			if (!dev || dev == nhc->nhc_dev)
				ret = res.type;//重新设置结果
		}
	}

	rcu_read_unlock();
	return ret;
}

unsigned int inet_addr_type_table(struct net *net, __be32 addr, u32 tb_id)
{
	return __inet_dev_addr_type(net, NULL, addr, tb_id);
}
EXPORT_SYMBOL(inet_addr_type_table);

unsigned int inet_addr_type(struct net *net, __be32 addr)
{
	return __inet_dev_addr_type(net, NULL, addr, RT_TABLE_LOCAL);
}
EXPORT_SYMBOL(inet_addr_type);

unsigned int inet_dev_addr_type(struct net *net, const struct net_device *dev,
				__be32 addr)
{
	u32 rt_table = l3mdev_fib_table(dev) ? : RT_TABLE_LOCAL;

	return __inet_dev_addr_type(net, dev, addr, rt_table);
}
EXPORT_SYMBOL(inet_dev_addr_type);

/* inet_addr_type with dev == NULL but using the table from a dev
 * if one is associated
 */
unsigned int inet_addr_type_dev_table(struct net *net,
				      const struct net_device *dev,
				      __be32 addr)
{
	u32 rt_table = l3mdev_fib_table(dev) ? : RT_TABLE_LOCAL;

	return __inet_dev_addr_type(net, NULL, addr, rt_table);
}
EXPORT_SYMBOL(inet_addr_type_dev_table);

__be32 fib_compute_spec_dst(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct in_device *in_dev;
	struct fib_result res;
	struct rtable *rt;
	struct net *net;
	int scope;

	rt = skb_rtable(skb);
	if ((rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST | RTCF_LOCAL)) ==
	    RTCF_LOCAL)
		return ip_hdr(skb)->daddr;

	in_dev = __in_dev_get_rcu(dev);

	net = dev_net(dev);

	scope = RT_SCOPE_UNIVERSE;
	if (!ipv4_is_zeronet(ip_hdr(skb)->saddr)) {
		bool vmark = in_dev && IN_DEV_SRC_VMARK(in_dev);
		struct flowi4 fl4 = {
			.flowi4_iif = LOOPBACK_IFINDEX,
			.flowi4_l3mdev = l3mdev_master_ifindex_rcu(dev),
			.daddr = ip_hdr(skb)->saddr,
			.flowi4_tos = ip_hdr(skb)->tos & IPTOS_RT_MASK,
			.flowi4_scope = scope,
			.flowi4_mark = vmark ? skb->mark : 0,
		};
		if (!fib_lookup(net, &fl4, &res, 0))
			return fib_result_prefsrc(net, &res);
	} else {
		scope = RT_SCOPE_LINK;
	}

	return inet_select_addr(dev, ip_hdr(skb)->saddr, scope);
}

bool fib_info_nh_uses_dev(struct fib_info *fi, const struct net_device *dev)
{
	bool dev_match = false;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (unlikely(fi->nh)) {
		dev_match = nexthop_uses_dev(fi->nh, dev);
	} else {
		int ret;

		for (ret = 0; ret < fib_info_num_path(fi); ret++) {
			const struct fib_nh_common *nhc = fib_info_nhc(fi, ret);

			if (nhc_l3mdev_matches_dev(nhc, dev)) {
				dev_match = true;
				break;
			}
		}
	}
#else
	if (fib_info_nhc(fi, 0)->nhc_dev == dev)
		dev_match = true;
#endif

	return dev_match;
}
EXPORT_SYMBOL_GPL(fib_info_nh_uses_dev);

/* Given (packet source, input interface) and optional (dst, oif, tos):
 * - (main) check, that source is valid i.e. not broadcast or our local
 *   address.
 * - figure out what "logical" interface this packet arrived
 *   and calculate "specific destination" address.
 * - check, that packet arrived from expected physical interface.
 * called with rcu_read_lock()
 */
static int __fib_validate_source(struct sk_buff *skb, __be32 src, __be32 dst,
				 u8 tos, int oif, struct net_device *dev,
				 int rpf, struct in_device *idev, u32 *itag)
{
	struct net *net = dev_net(dev);
	struct flow_keys flkeys;
	int ret, no_addr;
	struct fib_result res;
	struct flowi4 fl4;
	bool dev_match;

	fl4.flowi4_oif = 0; //不指定出接口
	fl4.flowi4_l3mdev = l3mdev_master_ifindex_rcu(dev);
	fl4.flowi4_iif = oif ? : LOOPBACK_IFINDEX;
	fl4.daddr = src; //注意这里倒转了ip地址
	fl4.saddr = dst;
	fl4.flowi4_tos = tos;
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
	fl4.flowi4_tun_key.tun_id = 0;
	fl4.flowi4_flags = 0;
	fl4.flowi4_uid = sock_net_uid(net, NULL);
	fl4.flowi4_multipath_hash = 0;

	no_addr = idev->ifa_list == NULL;

	fl4.flowi4_mark = IN_DEV_SRC_VMARK(idev) ? skb->mark : 0;
	//看看能不能拿port 策略路由有用到
	if (!fib4_rules_early_flow_dissect(net, skb, &fl4, &flkeys)) {
		fl4.flowi4_proto = 0;
		fl4.fl4_sport = 0;
		fl4.fl4_dport = 0;
	} else {
		swap(fl4.fl4_sport, fl4.fl4_dport);
	}
	//查路由
	if (fib_lookup(net, &fl4, &res, 0))
		goto last_resort;
	//路由是否合法
	if (res.type != RTN_UNICAST &&
	    (res.type != RTN_LOCAL || !IN_DEV_ACCEPT_LOCAL(idev)))
		goto e_inval;
	fib_combine_itag(itag, &res);
	//看查出来的路由是不是用当前入接口！！！
	dev_match = fib_info_nh_uses_dev(res.fi, dev);
	/* This is not common, loopback packets retain skb_dst so normally they
	 * would not even hit this slow path.
	 */
	//loopback的特殊处理
	dev_match = dev_match || (res.type == RTN_LOCAL &&
				  dev == net->loopback_dev);
	//通过
	if (dev_match) {
		ret = FIB_RES_NHC(res)->nhc_scope >= RT_SCOPE_HOST;
		return ret;
	}
	//根本没有ip地址的情况，看是否是严格源路由过滤还是。。。
	if (no_addr)
		goto last_resort;
	//严格模式，直接失败
	if (rpf == 1)
		goto e_rpf;
	fl4.flowi4_oif = dev->ifindex;
	//指定出接口再试一次，如果指定出接口都发不出去，拿干脆就认为是非法的
	ret = 0;
	if (fib_lookup(net, &fl4, &res, FIB_LOOKUP_IGNORE_LINKSTATE) == 0) {
		if (res.type == RTN_UNICAST)
			ret = FIB_RES_NHC(res)->nhc_scope >= RT_SCOPE_HOST;
	}
	return ret;

last_resort:
	if (rpf)
		goto e_rpf;
	*itag = 0;
	return 0;

e_inval:
	return -EINVAL;
e_rpf:
	return -EXDEV;
}

/* Ignore rp_filter for packets protected by IPsec. */
int fib_validate_source(struct sk_buff *skb, __be32 src, __be32 dst,
			u8 tos, int oif, struct net_device *dev,
			struct in_device *idev, u32 *itag)
{
	int r = secpath_exists(skb) ? 0 : IN_DEV_RPFILTER(idev);
	struct net *net = dev_net(dev);
	//是否启用 ，开了反向路径过滤就不走这里了
	if (!r && !fib_num_tclassid_users(net) &&
	    (dev->ifindex != oif || !IN_DEV_TX_REDIRECTS(idev))) {
		if (IN_DEV_ACCEPT_LOCAL(idev)) //那么即使源地址看起来像本地地址也放行
			goto ok;
		/* with custom local routes in place, checking local addresses
		 * only will be too optimistic, with custom rules, checking
		 * local addresses only can be too strict, e.g. due to vrf
		 */
		if (net->ipv4.fib_has_custom_local_routes || //有自定义策略路由
		    fib4_has_custom_rules(net))
			goto full_check;
		/* Within the same container, it is regarded as a martian source,
		 * and the same host but different containers are not.
		 */
		//查一下 src 是不是本机持有的 IPv4 地址
		if (inet_lookup_ifaddr_rcu(net, src))
			return -EINVAL;

ok:
		*itag = 0;
		return 0;
	}

full_check:
	return __fib_validate_source(skb, src, dst, tos, oif, dev, r, idev, itag);
}

static inline __be32 sk_extract_addr(struct sockaddr *addr)
{
	return ((struct sockaddr_in *) addr)->sin_addr.s_addr;
}

static int put_rtax(struct nlattr *mx, int len, int type, u32 value)
{
	struct nlattr *nla;

	nla = (struct nlattr *) ((char *) mx + len);
	nla->nla_type = type;
	nla->nla_len = nla_attr_size(4);
	*(u32 *) nla_data(nla) = value;

	return len + nla_total_size(4);
}

static int rtentry_to_fib_config(struct net *net, int cmd, struct rtentry *rt,
				 struct fib_config *cfg)
{
	__be32 addr;
	int plen;

	memset(cfg, 0, sizeof(*cfg));
	cfg->fc_nlinfo.nl_net = net;

	if (rt->rt_dst.sa_family != AF_INET)
		return -EAFNOSUPPORT;

	/*
	 * Check mask for validity:
	 * a) it must be contiguous.
	 * b) destination must have all host bits clear.
	 * c) if application forgot to set correct family (AF_INET),
	 *    reject request unless it is absolutely clear i.e.
	 *    both family and mask are zero.
	 */
	plen = 32;
	addr = sk_extract_addr(&rt->rt_dst);
	if (!(rt->rt_flags & RTF_HOST)) {
		__be32 mask = sk_extract_addr(&rt->rt_genmask);

		if (rt->rt_genmask.sa_family != AF_INET) {
			if (mask || rt->rt_genmask.sa_family)
				return -EAFNOSUPPORT;
		}

		if (bad_mask(mask, addr))
			return -EINVAL;

		plen = inet_mask_len(mask);
	}

	cfg->fc_dst_len = plen;
	cfg->fc_dst = addr;

	if (cmd != SIOCDELRT) {
		cfg->fc_nlflags = NLM_F_CREATE;
		cfg->fc_protocol = RTPROT_BOOT;
	}

	if (rt->rt_metric)
		cfg->fc_priority = rt->rt_metric - 1;

	if (rt->rt_flags & RTF_REJECT) {
		cfg->fc_scope = RT_SCOPE_HOST;
		cfg->fc_type = RTN_UNREACHABLE;
		return 0;
	}

	cfg->fc_scope = RT_SCOPE_NOWHERE;
	cfg->fc_type = RTN_UNICAST;

	if (rt->rt_dev) {
		char *colon;
		struct net_device *dev;
		char devname[IFNAMSIZ];

		if (copy_from_user(devname, rt->rt_dev, IFNAMSIZ-1))
			return -EFAULT;

		devname[IFNAMSIZ-1] = 0;
		colon = strchr(devname, ':');
		if (colon)
			*colon = 0;
		dev = __dev_get_by_name(net, devname);
		if (!dev)
			return -ENODEV;
		cfg->fc_oif = dev->ifindex;
		cfg->fc_table = l3mdev_fib_table(dev);
		if (colon) {
			const struct in_ifaddr *ifa;
			struct in_device *in_dev;

			in_dev = __in_dev_get_rtnl(dev);
			if (!in_dev)
				return -ENODEV;

			*colon = ':';

			rcu_read_lock();
			in_dev_for_each_ifa_rcu(ifa, in_dev) {
				if (strcmp(ifa->ifa_label, devname) == 0)
					break;
			}
			rcu_read_unlock();

			if (!ifa)
				return -ENODEV;
			cfg->fc_prefsrc = ifa->ifa_local;
		}
	}

	addr = sk_extract_addr(&rt->rt_gateway);
	if (rt->rt_gateway.sa_family == AF_INET && addr) {
		unsigned int addr_type;

		cfg->fc_gw4 = addr;
		cfg->fc_gw_family = AF_INET;
		addr_type = inet_addr_type_table(net, addr, cfg->fc_table);
		if (rt->rt_flags & RTF_GATEWAY &&
		    addr_type == RTN_UNICAST)
			cfg->fc_scope = RT_SCOPE_UNIVERSE;
	}

	if (!cfg->fc_table)
		cfg->fc_table = RT_TABLE_MAIN;

	if (cmd == SIOCDELRT)
		return 0;

	if (rt->rt_flags & RTF_GATEWAY && !cfg->fc_gw_family)
		return -EINVAL;

	if (cfg->fc_scope == RT_SCOPE_NOWHERE)
		cfg->fc_scope = RT_SCOPE_LINK;

	if (rt->rt_flags & (RTF_MTU | RTF_WINDOW | RTF_IRTT)) {
		struct nlattr *mx;
		int len = 0;

		mx = kcalloc(3, nla_total_size(4), GFP_KERNEL);
		if (!mx)
			return -ENOMEM;

		if (rt->rt_flags & RTF_MTU)
			len = put_rtax(mx, len, RTAX_ADVMSS, rt->rt_mtu - 40);

		if (rt->rt_flags & RTF_WINDOW)
			len = put_rtax(mx, len, RTAX_WINDOW, rt->rt_window);

		if (rt->rt_flags & RTF_IRTT)
			len = put_rtax(mx, len, RTAX_RTT, rt->rt_irtt << 3);

		cfg->fc_mx = mx;
		cfg->fc_mx_len = len;
	}

	return 0;
}

/*
 * Handle IP routing ioctl calls.
 * These are used to manipulate the routing tables
 */
int ip_rt_ioctl(struct net *net, unsigned int cmd, struct rtentry *rt)
{
	struct fib_config cfg;
	int err;

	switch (cmd) {
	case SIOCADDRT:		/* Add a route */
	case SIOCDELRT:		/* Delete a route */
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			return -EPERM;

		rtnl_lock();
		err = rtentry_to_fib_config(net, cmd, rt, &cfg);
		if (err == 0) {
			struct fib_table *tb;

			if (cmd == SIOCDELRT) {
				tb = fib_get_table(net, cfg.fc_table);
				if (tb)
					err = fib_table_delete(net, tb, &cfg,
							       NULL);
				else
					err = -ESRCH;
			} else {
				tb = fib_new_table(net, cfg.fc_table);
				if (tb)
					err = fib_table_insert(net, tb,
							       &cfg, NULL);
				else
					err = -ENOBUFS;
			}

			/* allocated by rtentry_to_fib_config() */
			kfree(cfg.fc_mx);
		}
		rtnl_unlock();
		return err;
	}
	return -EINVAL;
}

const struct nla_policy rtm_ipv4_policy[RTA_MAX + 1] = {
	[RTA_UNSPEC]		= { .strict_start_type = RTA_DPORT + 1 },
	[RTA_DST]		= { .type = NLA_U32 },
	[RTA_SRC]		= { .type = NLA_U32 },
	[RTA_IIF]		= { .type = NLA_U32 },
	[RTA_OIF]		= { .type = NLA_U32 },
	[RTA_GATEWAY]		= { .type = NLA_U32 },
	[RTA_PRIORITY]		= { .type = NLA_U32 },
	[RTA_PREFSRC]		= { .type = NLA_U32 },
	[RTA_METRICS]		= { .type = NLA_NESTED },
	[RTA_MULTIPATH]		= { .len = sizeof(struct rtnexthop) },
	[RTA_FLOW]		= { .type = NLA_U32 },
	[RTA_ENCAP_TYPE]	= { .type = NLA_U16 },
	[RTA_ENCAP]		= { .type = NLA_NESTED },
	[RTA_UID]		= { .type = NLA_U32 },
	[RTA_MARK]		= { .type = NLA_U32 },
	[RTA_TABLE]		= { .type = NLA_U32 },
	[RTA_IP_PROTO]		= { .type = NLA_U8 },
	[RTA_SPORT]		= { .type = NLA_U16 },
	[RTA_DPORT]		= { .type = NLA_U16 },
	[RTA_NH_ID]		= { .type = NLA_U32 },
};

int fib_gw_from_via(struct fib_config *cfg, struct nlattr *nla,
		    struct netlink_ext_ack *extack)
{
	struct rtvia *via;
	int alen;

	if (nla_len(nla) < offsetof(struct rtvia, rtvia_addr)) {
		NL_SET_ERR_MSG(extack, "Invalid attribute length for RTA_VIA");
		return -EINVAL;
	}

	via = nla_data(nla);
	alen = nla_len(nla) - offsetof(struct rtvia, rtvia_addr);

	switch (via->rtvia_family) {
	case AF_INET:
		if (alen != sizeof(__be32)) {
			NL_SET_ERR_MSG(extack, "Invalid IPv4 address in RTA_VIA");
			return -EINVAL;
		}
		cfg->fc_gw_family = AF_INET;
		cfg->fc_gw4 = *((__be32 *)via->rtvia_addr);
		break;
	case AF_INET6:
#if IS_ENABLED(CONFIG_IPV6)
		if (alen != sizeof(struct in6_addr)) {
			NL_SET_ERR_MSG(extack, "Invalid IPv6 address in RTA_VIA");
			return -EINVAL;
		}
		cfg->fc_gw_family = AF_INET6;
		cfg->fc_gw6 = *((struct in6_addr *)via->rtvia_addr);
#else
		NL_SET_ERR_MSG(extack, "IPv6 support not enabled in kernel");
		return -EINVAL;
#endif
		break;
	default:
		NL_SET_ERR_MSG(extack, "Unsupported address family in RTA_VIA");
		return -EINVAL;
	}

	return 0;
}

static int rtm_to_fib_config(struct net *net, struct sk_buff *skb,
			     struct nlmsghdr *nlh, struct fib_config *cfg,
			     struct netlink_ext_ack *extack)
{
	bool has_gw = false, has_via = false;
	struct nlattr *attr;
	int err, remaining;
	struct rtmsg *rtm;
	//校验消息格式
	err = nlmsg_validate_deprecated(nlh, sizeof(*rtm), RTA_MAX,
					rtm_ipv4_policy, extack);
	if (err < 0)
		goto errout;
	//清空 cfg
	memset(cfg, 0, sizeof(*cfg));
	//取出 rtmsg 头
	rtm = nlmsg_data(nlh);

	if (!inet_validate_dscp(rtm->rtm_tos)) {
		NL_SET_ERR_MSG(extack,
			       "Invalid dsfield (tos): ECN bits must be 0");
		err = -EINVAL;
		goto errout;
	}
	cfg->fc_dscp = inet_dsfield_to_dscp(rtm->rtm_tos);
	//从 rtmsg 头里拷贝基础字段
	cfg->fc_dst_len = rtm->rtm_dst_len; //目的前缀长度
	cfg->fc_table = rtm->rtm_table;		//插入哪张表
	cfg->fc_protocol = rtm->rtm_protocol; //这条路由是谁加的，比如 boot
	cfg->fc_scope = rtm->rtm_scope;		//路由作用范围
	cfg->fc_type = rtm->rtm_type;		//路由类型，比如 unicast/local
	cfg->fc_flags = rtm->rtm_flags;
	cfg->fc_nlflags = nlh->nlmsg_flags;	//fc_nlflags：netlink 层面的标志
	//保存 netlink 来源信息
	cfg->fc_nlinfo.portid = NETLINK_CB(skb).portid;
	cfg->fc_nlinfo.nlh = nlh;
	cfg->fc_nlinfo.nl_net = net;
	//检查 route type 合法性
	if (cfg->fc_type > RTN_MAX) {
		NL_SET_ERR_MSG(extack, "Invalid route type");
		err = -EINVAL;
		goto errout;
	}
	//解析netlink消息 ，这里相当于是可选的
	nlmsg_for_each_attr(attr, nlh, sizeof(struct rtmsg), remaining) {
		switch (nla_type(attr)) {
		case RTA_DST: //目标网络地址
			cfg->fc_dst = nla_get_be32(attr);
			break;
		case RTA_OIF: //输出接口 index。
			cfg->fc_oif = nla_get_u32(attr);
			break;
		case RTA_GATEWAY: //via 1.1.1.1
			has_gw = true;
			cfg->fc_gw4 = nla_get_be32(attr);
			if (cfg->fc_gw4)
				cfg->fc_gw_family = AF_INET;
			break;
		case RTA_VIA:
			has_via = true;
			err = fib_gw_from_via(cfg, attr, extack);
			if (err)
				goto errout;
			break;
		case RTA_PRIORITY: //metri
			cfg->fc_priority = nla_get_u32(attr);
			break;
		case RTA_PREFSRC: //建议源地址
			cfg->fc_prefsrc = nla_get_be32(attr);
			break;
		case RTA_METRICS: //mtu rtt等
			cfg->fc_mx = nla_data(attr);
			cfg->fc_mx_len = nla_len(attr);
			break;
		case RTA_MULTIPATH: //路径路由
			err = lwtunnel_valid_encap_type_attr(nla_data(attr),
							     nla_len(attr),
							     extack);
			if (err < 0)
				goto errout;
			cfg->fc_mp = nla_data(attr);
			cfg->fc_mp_len = nla_len(attr);
			break;
		case RTA_FLOW: //策略路由
			cfg->fc_flow = nla_get_u32(attr);
			break;
		case RTA_TABLE: //哪张表
			cfg->fc_table = nla_get_u32(attr);
			break;
		case RTA_ENCAP: //隧道相关
			cfg->fc_encap = attr;
			break;
		case RTA_ENCAP_TYPE://隧道类型
			cfg->fc_encap_type = nla_get_u16(attr);
			err = lwtunnel_valid_encap_type(cfg->fc_encap_type,
							extack);
			if (err < 0)
				goto errout;
			break;
		case RTA_NH_ID:
			cfg->fc_nh_id = nla_get_u32(attr);
			break;
		}
	}
	//合法性检查
	if (cfg->fc_nh_id) {
		if (cfg->fc_oif || cfg->fc_gw_family ||
		    cfg->fc_encap || cfg->fc_mp) {
			NL_SET_ERR_MSG(extack,
				       "Nexthop specification and nexthop id are mutually exclusive");
			return -EINVAL;
		}
	}

	if (has_gw && has_via) {
		NL_SET_ERR_MSG(extack,
			       "Nexthop configuration can not contain both GATEWAY and VIA");
		return -EINVAL;
	}
	//默认是main表
	if (!cfg->fc_table)
		cfg->fc_table = RT_TABLE_MAIN;

	return 0;
errout:
	return err;
}

static int inet_rtm_delroute(struct sk_buff *skb, struct nlmsghdr *nlh,
			     struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct fib_config cfg;
	struct fib_table *tb;
	int err;
	//把用户命令构造成 fib_config
	err = rtm_to_fib_config(net, skb, nlh, &cfg, extack);
	if (err < 0)
		goto errout;

	if (cfg.fc_nh_id && !nexthop_find_by_id(net, cfg.fc_nh_id)) {
		NL_SET_ERR_MSG(extack, "Nexthop id does not exist");
		err = -EINVAL;
		goto errout;
	}
	//找到对应的路由表
	tb = fib_get_table(net, cfg.fc_table);
	if (!tb) {
		NL_SET_ERR_MSG(extack, "FIB table does not exist");
		err = -ESRCH;
		goto errout;
	}

	err = fib_table_delete(net, tb, &cfg, extack);
errout:
	return err;
}
//执行ip route add 的入口函数
static int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr *nlh,
			     struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct fib_config cfg;
	struct fib_table *tb;
	int err;
	//把netlink消息封装到 cfg中
	err = rtm_to_fib_config(net, skb, nlh, &cfg, extack);
	if (err < 0)
		goto errout;
	//拿到路由表，没有就创建一个
	tb = fib_new_table(net, cfg.fc_table);
	if (!tb) {
		err = -ENOBUFS;
		goto errout;
	}
	//插入这条路由
	err = fib_table_insert(net, tb, &cfg, extack);
	if (!err && cfg.fc_type == RTN_LOCAL)
		net->ipv4.fib_has_custom_local_routes = true;
errout:
	return err;
}

int ip_valid_fib_dump_req(struct net *net, const struct nlmsghdr *nlh,
			  struct fib_dump_filter *filter,
			  struct netlink_callback *cb)
{
	struct netlink_ext_ack *extack = cb->extack;
	struct nlattr *tb[RTA_MAX + 1];
	struct rtmsg *rtm;
	int err, i;

	ASSERT_RTNL();

	if (nlh->nlmsg_len < nlmsg_msg_size(sizeof(*rtm))) {
		NL_SET_ERR_MSG(extack, "Invalid header for FIB dump request");
		return -EINVAL;
	}

	rtm = nlmsg_data(nlh);
	if (rtm->rtm_dst_len || rtm->rtm_src_len  || rtm->rtm_tos   ||
	    rtm->rtm_scope) {
		NL_SET_ERR_MSG(extack, "Invalid values in header for FIB dump request");
		return -EINVAL;
	}

	if (rtm->rtm_flags & ~(RTM_F_CLONED | RTM_F_PREFIX)) {
		NL_SET_ERR_MSG(extack, "Invalid flags for FIB dump request");
		return -EINVAL;
	}
	if (rtm->rtm_flags & RTM_F_CLONED)
		filter->dump_routes = false;
	else
		filter->dump_exceptions = false;

	filter->flags    = rtm->rtm_flags;
	filter->protocol = rtm->rtm_protocol;
	filter->rt_type  = rtm->rtm_type;
	filter->table_id = rtm->rtm_table;

	err = nlmsg_parse_deprecated_strict(nlh, sizeof(*rtm), tb, RTA_MAX,
					    rtm_ipv4_policy, extack);
	if (err < 0)
		return err;

	for (i = 0; i <= RTA_MAX; ++i) {
		int ifindex;

		if (!tb[i])
			continue;

		switch (i) {
		case RTA_TABLE:
			filter->table_id = nla_get_u32(tb[i]);
			break;
		case RTA_OIF:
			ifindex = nla_get_u32(tb[i]);
			filter->dev = __dev_get_by_index(net, ifindex);
			if (!filter->dev)
				return -ENODEV;
			break;
		default:
			NL_SET_ERR_MSG(extack, "Unsupported attribute in dump request");
			return -EINVAL;
		}
	}

	if (filter->flags || filter->protocol || filter->rt_type ||
	    filter->table_id || filter->dev) {
		filter->filter_set = 1;
		cb->answer_flags = NLM_F_DUMP_FILTERED;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ip_valid_fib_dump_req);

static int inet_dump_fib(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct fib_dump_filter filter = { .dump_routes = true,
					  .dump_exceptions = true };
	const struct nlmsghdr *nlh = cb->nlh;
	struct net *net = sock_net(skb->sk);
	unsigned int h, s_h;
	unsigned int e = 0, s_e;
	struct fib_table *tb;
	struct hlist_head *head;
	int dumped = 0, err;

	if (cb->strict_check) {
		err = ip_valid_fib_dump_req(net, nlh, &filter, cb);
		if (err < 0)
			return err;
	} else if (nlmsg_len(nlh) >= sizeof(struct rtmsg)) {
		struct rtmsg *rtm = nlmsg_data(nlh);

		filter.flags = rtm->rtm_flags & (RTM_F_PREFIX | RTM_F_CLONED);
	}

	/* ipv4 does not use prefix flag */
	if (filter.flags & RTM_F_PREFIX)
		return skb->len;

	if (filter.table_id) {
		tb = fib_get_table(net, filter.table_id);
		if (!tb) {
			if (rtnl_msg_family(cb->nlh) != PF_INET)
				return skb->len;

			NL_SET_ERR_MSG(cb->extack, "ipv4: FIB table does not exist");
			return -ENOENT;
		}

		rcu_read_lock();
		err = fib_table_dump(tb, skb, cb, &filter);
		rcu_read_unlock();
		return skb->len ? : err;
	}

	s_h = cb->args[0];
	s_e = cb->args[1];

	rcu_read_lock();

	for (h = s_h; h < FIB_TABLE_HASHSZ; h++, s_e = 0) {
		e = 0;
		head = &net->ipv4.fib_table_hash[h];
		hlist_for_each_entry_rcu(tb, head, tb_hlist) {
			if (e < s_e)
				goto next;
			if (dumped)
				memset(&cb->args[2], 0, sizeof(cb->args) -
						 2 * sizeof(cb->args[0]));
			err = fib_table_dump(tb, skb, cb, &filter);
			if (err < 0) {
				if (likely(skb->len))
					goto out;

				goto out_err;
			}
			dumped = 1;
next:
			e++;
		}
	}
out:
	err = skb->len;
out_err:
	rcu_read_unlock();

	cb->args[1] = e;
	cb->args[0] = h;

	return err;
}

/* Prepare and feed intra-kernel routing request.
 * Really, it should be netlink message, but :-( netlink
 * can be not configured, so that we feed it directly
 * to fib engine. It is legal, because all events occur
 * only when netlink is already locked.
 */
static void fib_magic(int cmd, int type, __be32 dst, int dst_len,
		      struct in_ifaddr *ifa, u32 rt_priority)
{
	struct net *net = dev_net(ifa->ifa_dev->dev);
	u32 tb_id = l3mdev_fib_table(ifa->ifa_dev->dev);
	struct fib_table *tb;
	//构造config 和通过netlink配置ip地址一样
	struct fib_config cfg = {
		.fc_protocol = RTPROT_KERNEL,
		.fc_type = type,  //这个type貌似就是查路由的res保存的type
		.fc_dst = dst,
		.fc_dst_len = dst_len,
		.fc_priority = rt_priority,
		.fc_prefsrc = ifa->ifa_local,
		.fc_oif = ifa->ifa_dev->dev->ifindex,
		.fc_nlflags = NLM_F_CREATE | NLM_F_APPEND,
		.fc_nlinfo = {
			.nl_net = net,
		},
	};

	if (!tb_id)
		tb_id = (type == RTN_UNICAST) ? RT_TABLE_MAIN : RT_TABLE_LOCAL;
	//如果是第一次的话，其实main表和local表都是在这里创建的
	//而且他们共享了 trie
	tb = fib_new_table(net, tb_id);
	if (!tb)
		return;

	cfg.fc_table = tb->tb_id;
	//设置路由的作用范围
	if (type != RTN_LOCAL)
		cfg.fc_scope = RT_SCOPE_LINK;
	else
		cfg.fc_scope = RT_SCOPE_HOST;
	//插入到路由表中
	if (cmd == RTM_NEWROUTE)
		fib_table_insert(net, tb, &cfg, NULL);
	else
	//从路由表中删除
		fib_table_delete(net, tb, &cfg, NULL);
}

void fib_add_ifaddr(struct in_ifaddr *ifa)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	struct in_ifaddr *prim = ifa;
	__be32 mask = ifa->ifa_mask;
	__be32 addr = ifa->ifa_local;
	__be32 prefix = ifa->ifa_address & mask;
	//处理从ip地址的情况 192.168.1.10/24  192.168.1.20/24 
	if (ifa->ifa_flags & IFA_F_SECONDARY) {
		//这里是在找主ip地址
		prim = inet_ifa_byprefix(in_dev, prefix, mask);
		if (!prim) {
			pr_warn("%s: bug: prim == NULL\n", __func__);
			return;
		}
	}
	//先加一条 local 路由 让发往这个IP的包就应该被认为是本地接收！
	fib_magic(RTM_NEWROUTE, RTN_LOCAL, addr, 32, prim, 0);

	if (!(dev->flags & IFF_UP))//网口是否被打开，注意区别linkup
		return;

	/* Add broadcast address, if it is explicitly assigned. */
	//如果配置了广播地址，就给这个广播地址加一个路由，不能是有限广播地址
	if (ifa->ifa_broadcast && ifa->ifa_broadcast != htonl(0xFFFFFFFF)) {
		fib_magic(RTM_NEWROUTE, RTN_BROADCAST, ifa->ifa_broadcast, 32,
			  prim, 0);
		//看看是不是需要更新一下邻居表项(比如失效了)
		arp_invalidate(dev, ifa->ifa_broadcast, false);
	}
	//最常见的情况，如果这个地址是一个正常网段的地址，那就配置一个直连路由
	if (!ipv4_is_zeronet(prefix) && !(ifa->ifa_flags & IFA_F_SECONDARY) &&
	    (prefix != addr || ifa->ifa_prefixlen < 32)) {////如果是192.168.21.10/32这种的那就没必要
		if (!(ifa->ifa_flags & IFA_F_NOPREFIXROUTE))
			fib_magic(RTM_NEWROUTE,
				  dev->flags & IFF_LOOPBACK ? RTN_LOCAL : RTN_UNICAST,
				  prefix, ifa->ifa_prefixlen, prim,
				  ifa->ifa_rt_priority);

		/* Add the network broadcast address, when it makes sense */
		//这里不是和上面的重复了吗？ 注意上面是显示配置的
		if (ifa->ifa_prefixlen < 31) {//网络广播地址才有意义，加一个广播路由
			fib_magic(RTM_NEWROUTE, RTN_BROADCAST, prefix | ~mask,//算广播地址
				  32, prim, 0);
			arp_invalidate(dev, prefix | ~mask, false);
		}
	}
}

void fib_modify_prefix_metric(struct in_ifaddr *ifa, u32 new_metric)
{
	__be32 prefix = ifa->ifa_address & ifa->ifa_mask;
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;

	if (!(dev->flags & IFF_UP) ||
	    ifa->ifa_flags & (IFA_F_SECONDARY | IFA_F_NOPREFIXROUTE) ||
	    ipv4_is_zeronet(prefix) ||
	    (prefix == ifa->ifa_local && ifa->ifa_prefixlen == 32))
		return;

	/* add the new */
	fib_magic(RTM_NEWROUTE,
		  dev->flags & IFF_LOOPBACK ? RTN_LOCAL : RTN_UNICAST,
		  prefix, ifa->ifa_prefixlen, ifa, new_metric);

	/* delete the old */
	fib_magic(RTM_DELROUTE,
		  dev->flags & IFF_LOOPBACK ? RTN_LOCAL : RTN_UNICAST,
		  prefix, ifa->ifa_prefixlen, ifa, ifa->ifa_rt_priority);
}

/* Delete primary or secondary address.
 * Optionally, on secondary address promotion consider the addresses
 * from subnet iprim as deleted, even if they are in device list.
 * In this case the secondary ifa can be in device list.
 */
void fib_del_ifaddr(struct in_ifaddr *ifa, struct in_ifaddr *iprim)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	struct in_ifaddr *ifa1;
	struct in_ifaddr *prim = ifa, *prim1 = NULL;
	__be32 brd = ifa->ifa_address | ~ifa->ifa_mask;
	__be32 any = ifa->ifa_address & ifa->ifa_mask;
#define LOCAL_OK	1
#define BRD_OK		2
#define BRD0_OK		4
#define BRD1_OK		8
	unsigned int ok = 0;
	int subnet = 0;		/* Primary network */
	int gone = 1;		/* Address is missing */
	int same_prefsrc = 0;	/* Another primary with same IP */
	//如果删除的是从ip地址
	if (ifa->ifa_flags & IFA_F_SECONDARY) {
		prim = inet_ifa_byprefix(in_dev, any, ifa->ifa_mask);
		if (!prim) {
			/* if the device has been deleted, we don't perform
			 * address promotion
			 */
			if (!in_dev->dead)
				pr_warn("%s: bug: prim == NULL\n", __func__);
			return;
		}
		if (iprim && iprim != prim) {
			pr_warn("%s: bug: iprim != prim\n", __func__);
			return;
		}
	//如果是主ip地址，且前缀正常
	} else if (!ipv4_is_zeronet(any) &&
		   (any != ifa->ifa_local || ifa->ifa_prefixlen < 32)) { //不是纯 /32 单主机地址
		if (!(ifa->ifa_flags & IFA_F_NOPREFIXROUTE))
			fib_magic(RTM_DELROUTE,//删除路由
				  dev->flags & IFF_LOOPBACK ? RTN_LOCAL : RTN_UNICAST,
				  any, ifa->ifa_prefixlen, prim, 0);
		subnet = 1;
	}
	//设备已经dead了
	if (in_dev->dead)
		goto no_promotions;

	/* Deletion is more complicated than add.
	 * We should take care of not to delete too much :-)
	 *
	 * Scan address list to be sure that addresses are really gone.
	 */
	//扫描接口上的其他地址，判断还能不能删
	rcu_read_lock();
	in_dev_for_each_ifa_rcu(ifa1, in_dev) {
		if (ifa1 == ifa) { //这种概率很小吧？ 删了还存在配置了两个相同的ip？
			/* promotion, keep the IP */
			gone = 0;
			continue;
		}
		/* Ignore IFAs from our subnet */
		//通知连传进来这里为空
		if (iprim && ifa1->ifa_mask == iprim->ifa_mask &&
		    inet_ifa_match(ifa1->ifa_address, iprim))
			continue;

		/* Ignore ifa1 if it uses different primary IP (prefsrc) */
		if (ifa1->ifa_flags & IFA_F_SECONDARY) {//是从ip地址
			/* Another address from our subnet? */
			//掩码一样，前缀也一样
			if (ifa1->ifa_mask == prim->ifa_mask &&
			    inet_ifa_match(ifa1->ifa_address, prim))
				prim1 = prim; //ifa1 这个地址，被认定为属于 prim 这个子网组
			else {//不属于同一个子网？不是同一个子网为什么还要继续查？？？，貌似是判断背后的
				/* We reached the secondaries, so
				 * same_prefsrc should be determined.
				 */
				if (!same_prefsrc) //既然前面所有 primary 都已经检查过了
					continue;
				/* Search new prim1 if ifa1 is not
				 * using the current prim1
				 */
				//给当前这个 secondary ifa1 找它的 primary
				if (!prim1 ||
				    ifa1->ifa_mask != prim1->ifa_mask ||
				    !inet_ifa_match(ifa1->ifa_address, prim1))
					prim1 = inet_ifa_byprefix(in_dev,
							ifa1->ifa_address,
							ifa1->ifa_mask);
				if (!prim1)
					continue;
				if (prim1->ifa_local != prim->ifa_local)
					continue;
			}
		} else {// 主地址的情况
			if (prim->ifa_local != ifa1->ifa_local)//ip地址不一样跳过
				continue;
			prim1 = ifa1; //如果本地地址一样，那说明这个ifa1的主ip地址和当前 prim 有关系。
			if (prim != prim1)
				same_prefsrc = 1; //设置标记
		}
		//local/broadcast 路由 能不能删除
		if (ifa->ifa_local == ifa1->ifa_local)
			ok |= LOCAL_OK;
		if (ifa->ifa_broadcast == ifa1->ifa_broadcast)
			ok |= BRD_OK;
		if (brd == ifa1->ifa_broadcast)
			ok |= BRD1_OK;
		if (any == ifa1->ifa_broadcast)
			ok |= BRD0_OK;
		/* primary has network specific broadcasts */
		if (prim1 == ifa1 && ifa1->ifa_prefixlen < 31) {
			__be32 brd1 = ifa1->ifa_address | ~ifa1->ifa_mask;
			__be32 any1 = ifa1->ifa_address & ifa1->ifa_mask;

			if (!ipv4_is_zeronet(any1)) {
				if (ifa->ifa_broadcast == brd1 ||
				    ifa->ifa_broadcast == any1)
					ok |= BRD_OK;
				if (brd == brd1 || brd == any1)
					ok |= BRD1_OK;
				if (any == brd1 || any == any1)
					ok |= BRD0_OK;
			}
		}
	}
	rcu_read_unlock();

no_promotions:
	//删除对应的广播路由
	if (!(ok & BRD_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, ifa->ifa_broadcast, 32,
			  prim, 0);
	if (subnet && ifa->ifa_prefixlen < 31) {
		if (!(ok & BRD1_OK))
			fib_magic(RTM_DELROUTE, RTN_BROADCAST, brd, 32,
				  prim, 0);
		if (!(ok & BRD0_OK))
			fib_magic(RTM_DELROUTE, RTN_BROADCAST, any, 32,
				  prim, 0);
	}
	//删除对应的本地路由
	if (!(ok & LOCAL_OK)) {
		unsigned int addr_type;

		fib_magic(RTM_DELROUTE, RTN_LOCAL, ifa->ifa_local, 32, prim, 0);

		/* Check, that this local address finally disappeared. */
		addr_type = inet_addr_type_dev_table(dev_net(dev), dev,
						     ifa->ifa_local);
		if (gone && addr_type != RTN_LOCAL) {
			/* And the last, but not the least thing.
			 * We must flush stray FIB entries.
			 *
			 * First of all, we scan fib_info list searching
			 * for stray nexthop entries, then ignite fib_flush.
			 */
			if (fib_sync_down_addr(dev, ifa->ifa_local))
				fib_flush(dev_net(dev));
		}
	}
#undef LOCAL_OK
#undef BRD_OK
#undef BRD0_OK
#undef BRD1_OK
}

static void nl_fib_lookup(struct net *net, struct fib_result_nl *frn)
{

	struct fib_result       res;
	struct flowi4           fl4 = {
		.flowi4_mark = frn->fl_mark,
		.daddr = frn->fl_addr,
		.flowi4_tos = frn->fl_tos,
		.flowi4_scope = frn->fl_scope,
	};
	struct fib_table *tb;

	rcu_read_lock();

	tb = fib_get_table(net, frn->tb_id_in);

	frn->err = -ENOENT;
	if (tb) {
		local_bh_disable();

		frn->tb_id = tb->tb_id;
		frn->err = fib_table_lookup(tb, &fl4, &res, FIB_LOOKUP_NOREF);

		if (!frn->err) {
			frn->prefixlen = res.prefixlen;
			frn->nh_sel = res.nh_sel;
			frn->type = res.type;
			frn->scope = res.scope;
		}
		local_bh_enable();
	}

	rcu_read_unlock();
}

static void nl_fib_input(struct sk_buff *skb)
{
	struct net *net;
	struct fib_result_nl *frn;
	struct nlmsghdr *nlh;
	u32 portid;

	net = sock_net(skb->sk);
	nlh = nlmsg_hdr(skb);
	if (skb->len < nlmsg_total_size(sizeof(*frn)) ||
	    skb->len < nlh->nlmsg_len ||
	    nlmsg_len(nlh) < sizeof(*frn))
		return;

	skb = netlink_skb_clone(skb, GFP_KERNEL);
	if (!skb)
		return;
	nlh = nlmsg_hdr(skb);

	frn = nlmsg_data(nlh);
	nl_fib_lookup(net, frn);

	portid = NETLINK_CB(skb).portid;      /* netlink portid */
	NETLINK_CB(skb).portid = 0;        /* from kernel */
	NETLINK_CB(skb).dst_group = 0;  /* unicast */
	nlmsg_unicast(net->ipv4.fibnl, skb, portid);
}

static int __net_init nl_fib_lookup_init(struct net *net)
{
	struct sock *sk;
	struct netlink_kernel_cfg cfg = {
		.input	= nl_fib_input,
	};

	sk = netlink_kernel_create(net, NETLINK_FIB_LOOKUP, &cfg);
	if (!sk)
		return -EAFNOSUPPORT;
	net->ipv4.fibnl = sk;
	return 0;
}

static void nl_fib_lookup_exit(struct net *net)
{
	netlink_kernel_release(net->ipv4.fibnl);
	net->ipv4.fibnl = NULL;
}

static void fib_disable_ip(struct net_device *dev, unsigned long event,
			   bool force)
{
	//把依赖这个dev做为下一跳的nh标记为不可用
	if (fib_sync_down_dev(dev, event, force))
		fib_flush(dev_net(dev)); //如果前面 fib_table_flush() 动了 FIB 里的状态，那么原先基于旧状态生成的那些 rtable 结果，就可能已经过期了。
	else
		rt_cache_flush(dev_net(dev));
	arp_ifdown(dev);
}

static int fib_inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = ptr;
	struct net_device *dev = ifa->ifa_dev->dev;
	struct net *net = dev_net(dev);

	switch (event) {
	case NETDEV_UP:
		//根据ip地址添加路由
		fib_add_ifaddr(ifa);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		fib_sync_up(dev, RTNH_F_DEAD);
#endif
		atomic_inc(&net->ipv4.dev_addr_genid);
		rt_cache_flush(dev_net(dev));
		break;
	case NETDEV_DOWN:
		//根据ip地址删除路由
		fib_del_ifaddr(ifa, NULL);
		atomic_inc(&net->ipv4.dev_addr_genid);
		//是否一个地址都没有了
		if (!ifa->ifa_dev->ifa_list) {
			/* Last address was deleted from this interface.
			 * Disable IP.
			 */
			//把这个设别的ipv4地址都禁用掉
			fib_disable_ip(dev, event, true);
		} else {
			rt_cache_flush(dev_net(dev));
		}
		break;
	}
	return NOTIFY_DONE;
}

static int fib_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_notifier_changeupper_info *upper_info = ptr;
	struct netdev_notifier_info_ext *info_ext = ptr;
	struct in_device *in_dev;
	struct net *net = dev_net(dev);
	struct in_ifaddr *ifa;
	unsigned int flags;
	//net_dev 注销了
	if (event == NETDEV_UNREGISTER) {
		//把下一跳标记为不可用
		fib_disable_ip(dev, event, true);
		//这里是处理，per-CPU uncached_list
		rt_flush_dev(dev);
		return NOTIFY_DONE;
	}
	//获取管理ip的结构
	in_dev = __in_dev_get_rtnl(dev);
	if (!in_dev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
	//向路由表里面加路由
		in_dev_for_each_ifa_rtnl(ifa, in_dev) {
			fib_add_ifaddr(ifa);
		}
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		fib_sync_up(dev, RTNH_F_DEAD);
#endif
		atomic_inc(&net->ipv4.dev_addr_genid);
		rt_cache_flush(net);
		break;
	case NETDEV_DOWN:
		//表示把和这个设备相关的路由禁用
		fib_disable_ip(dev, event, false);
		break;
	case NETDEV_CHANGE:
		flags = dev_get_flags(dev);
		if (flags & (IFF_RUNNING | IFF_LOWER_UP))//这里应该相当于 linkup
			fib_sync_up(dev, RTNH_F_LINKDOWN); //唤醒之前被标记为dead 的下一跳
		else //链路不通
			fib_sync_down_dev(dev, event, false);//标记下一跳为不可用
		rt_cache_flush(net);
		break;
	case NETDEV_CHANGEMTU: //mtu变化
		fib_sync_mtu(dev, info_ext->ext.mtu);
		rt_cache_flush(net);
		break;
	case NETDEV_CHANGEUPPER:
		upper_info = ptr;
		/* flush all routes if dev is linked to or unlinked from
		 * an L3 master device (e.g., VRF)
		 */
		if (upper_info->upper_dev &&
		    netif_is_l3_master(upper_info->upper_dev))
			fib_disable_ip(dev, NETDEV_DOWN, true);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block fib_inetaddr_notifier = {
	.notifier_call = fib_inetaddr_event,
};

static struct notifier_block fib_netdev_notifier = {
	.notifier_call = fib_netdev_event,
};

static int __net_init ip_fib_net_init(struct net *net)
{
	int err;
	size_t size = sizeof(struct hlist_head) * FIB_TABLE_HASHSZ;
	//注册一组ops，ops的功能是dump数据
	err = fib4_notifier_init(net);
	if (err)
		return err;

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/* Default to 3-tuple */
	net->ipv4.sysctl_fib_multipath_hash_fields =
		FIB_MULTIPATH_HASH_FIELD_DEFAULT_MASK;
#endif

	/* Avoid false sharing : Use at least a full cache line */
	//解决伪共享的问题
	size = max_t(size_t, size, L1_CACHE_BYTES);
	//申请路由表的hash桶
	net->ipv4.fib_table_hash = kzalloc(size, GFP_KERNEL);
	if (!net->ipv4.fib_table_hash) {
		err = -ENOMEM;
		goto err_table_hash_alloc;
	}
	//初始化查路由的顺序规则
	err = fib4_rules_init(net);
	if (err < 0)
		goto err_rules_init;
	return 0;

err_rules_init:
	kfree(net->ipv4.fib_table_hash);
err_table_hash_alloc:
	fib4_notifier_exit(net);
	return err;
}

static void ip_fib_net_exit(struct net *net)
{
	int i;

	ASSERT_RTNL();
#ifdef CONFIG_IP_MULTIPLE_TABLES
	RCU_INIT_POINTER(net->ipv4.fib_main, NULL);
	RCU_INIT_POINTER(net->ipv4.fib_default, NULL);
#endif
	/* Destroy the tables in reverse order to guarantee that the
	 * local table, ID 255, is destroyed before the main table, ID
	 * 254. This is necessary as the local table may contain
	 * references to data contained in the main table.
	 */
	for (i = FIB_TABLE_HASHSZ - 1; i >= 0; i--) {
		struct hlist_head *head = &net->ipv4.fib_table_hash[i];
		struct hlist_node *tmp;
		struct fib_table *tb;

		hlist_for_each_entry_safe(tb, tmp, head, tb_hlist) {
			hlist_del(&tb->tb_hlist);
			fib_table_flush(net, tb, true);
			fib_free_table(tb);
		}
	}

#ifdef CONFIG_IP_MULTIPLE_TABLES
	fib4_rules_exit(net);
#endif

	kfree(net->ipv4.fib_table_hash);
	fib4_notifier_exit(net);
}

static int __net_init fib_net_init(struct net *net)
{
	int error;

#ifdef CONFIG_IP_ROUTE_CLASSID
	atomic_set(&net->ipv4.fib_num_tclassid_users, 0);
#endif
	//初始化查表的顺序
	error = ip_fib_net_init(net);
	if (error < 0)
		goto out;
	error = nl_fib_lookup_init(net);
	if (error < 0)
		goto out_nlfl;
	//创建proc
	error = fib_proc_init(net);
	if (error < 0)
		goto out_proc;
out:
	return error;

out_proc:
	nl_fib_lookup_exit(net);
out_nlfl:
	rtnl_lock();
	ip_fib_net_exit(net);
	rtnl_unlock();
	goto out;
}

static void __net_exit fib_net_exit(struct net *net)
{
	fib_proc_exit(net);
	nl_fib_lookup_exit(net);
}

static void __net_exit fib_net_exit_batch(struct list_head *net_list)
{
	struct net *net;

	rtnl_lock();
	list_for_each_entry(net, net_list, exit_list)
		ip_fib_net_exit(net);

	rtnl_unlock();
}

static struct pernet_operations fib_net_ops = {
	.init = fib_net_init,
	.exit = fib_net_exit,
	.exit_batch = fib_net_exit_batch,
};

void __init ip_fib_init(void)
{

	//创建slab
	fib_trie_init();
	//为每个命名空间初始化一个路由表
	register_pernet_subsys(&fib_net_ops);
	//网卡up/down 变化的通知链子
	register_netdevice_notifier(&fib_netdev_notifier);
	//向 IPv4 地址变化的通知链（inetaddr notifier chain）注册一个回调函数，当系统中的 IPv4 地址发生变化时通知路由子系统。
	register_inetaddr_notifier(&fib_inetaddr_notifier);
	//注册ip route add
	rtnl_register(PF_INET, RTM_NEWROUTE, inet_rtm_newroute, NULL, 0);
	//删除路由
	rtnl_register(PF_INET, RTM_DELROUTE, inet_rtm_delroute, NULL, 0);
	//查询路由
	rtnl_register(PF_INET, RTM_GETROUTE, NULL, inet_dump_fib, 0);
}
