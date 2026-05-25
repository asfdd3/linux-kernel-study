/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <net/fib_notifier.h>
#include <net/fib_rules.h>
#include <net/inet_dscp.h>
#include <net/inetpeer.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/refcount.h>

struct fib_config {
	u8  fc_dst_len;        // 目的前缀长度（CIDR），例如 24 表示 /24

	dscp_t fc_dscp;        // DSCP（服务类型/TOS），用于策略路由匹配

	u8  fc_protocol;       // 路由来源（RTPROT_*），如 kernel / static / boot

	u8  fc_scope;          // 路由作用域（RT_SCOPE_*），如 link / host / universe

	u8  fc_type;           // 路由类型（RTN_*），如 unicast / local / broadcast / blackhole

	u8  fc_gw_family;      // 网关地址族（AF_INET / AF_INET6）

	/* 2 bytes unused */

	u32 fc_table;          // 路由表 ID（如 main=254 / local=255）

	__be32 fc_dst;         // 目的地址（网络序），例如 192.168.1.0

	union {
		__be32 fc_gw4;     // IPv4 网关地址（next hop）
		struct in6_addr fc_gw6; // IPv6 网关地址
	};

	int fc_oif;            // 输出接口 index（ifindex），指定走哪个网卡

	u32 fc_flags;          // 路由标志（RTNH_F_* / RTM_F_* 等），如 onlink / notify

	u32 fc_priority;       // 路由优先级（metric），值越小优先级越高

	__be32 fc_prefsrc;     // 首选源地址（preferred source），用于选源 IP

	u32 fc_nh_id;          // nexthop ID（用于 nexthop 对象模型，支持共享/ECMP）

	struct nlattr *fc_mx;  // metrics 属性（RTAX_*），如 MTU / RTT / window

	struct rtnexthop *fc_mp; // 多路径（multipath）下一跳数组（ECMP）

	int fc_mx_len;         // metrics 属性长度

	int fc_mp_len;         // multipath 数据长度

	u32 fc_flow;           // flow 标识（较少用，和策略路由相关）

	u32 fc_nlflags;        // netlink 标志（NLM_F_*），如 replace / create / excl

	struct nl_info fc_nlinfo; // netlink 消息上下文（发送者信息）

	struct nlattr *fc_encap; // 封装信息（如 LWTunnel，VXLAN/GRE 等）

	u16 fc_encap_type;     // 封装类型（LWTUNNEL_ENCAP_*）
};

struct fib_info;
struct rtable;

struct fib_nh_exception {
	struct fib_nh_exception __rcu	*fnhe_next;
	int				fnhe_genid;
	__be32				fnhe_daddr;
	u32				fnhe_pmtu;
	bool				fnhe_mtu_locked;
	__be32				fnhe_gw;
	unsigned long			fnhe_expires;
	struct rtable __rcu		*fnhe_rth_input;
	struct rtable __rcu		*fnhe_rth_output;
	unsigned long			fnhe_stamp;
	struct rcu_head			rcu;
};

struct fnhe_hash_bucket {
	struct fib_nh_exception __rcu	*chain;
};

#define FNHE_HASH_SHIFT		11
#define FNHE_HASH_SIZE		(1 << FNHE_HASH_SHIFT)
#define FNHE_RECLAIM_DEPTH	5

struct fib_nh_common {
	struct net_device	*nhc_dev;
	netdevice_tracker	nhc_dev_tracker;
	int			nhc_oif;
	unsigned char		nhc_scope;
	u8			nhc_family;
	u8			nhc_gw_family;
	unsigned char		nhc_flags;
	struct lwtunnel_state	*nhc_lwtstate;

	union {
		__be32          ipv4;
		struct in6_addr ipv6;
	} nhc_gw;

	int			nhc_weight;
	atomic_t		nhc_upper_bound;

	/* v4 specific, but allows fib6_nh with v4 routes */
	struct rtable __rcu * __percpu *nhc_pcpu_rth_output;
	struct rtable __rcu     *nhc_rth_input;
	struct fnhe_hash_bucket	__rcu *nhc_exceptions;
};

struct fib_nh {
	struct fib_nh_common	nh_common;
	struct hlist_node	nh_hash;	//插入全局hash表，好像没什么用
	struct fib_info		*nh_parent;   //关联的fib_info
#ifdef CONFIG_IP_ROUTE_CLASSID
	__u32			nh_tclassid;
#endif
	__be32			nh_saddr;		//源地址，应该就是在设备上找一个合适的ip
	int			nh_saddr_genid;
#define fib_nh_family		nh_common.nhc_family	////AF_INET
#define fib_nh_dev		nh_common.nhc_dev		 //输出的设备
#define fib_nh_dev_tracker	nh_common.nhc_dev_tracker
#define fib_nh_oif		nh_common.nhc_oif		  //路由表项输出的设备索引
#define fib_nh_flags		nh_common.nhc_flags		//下一跳状态
#define fib_nh_lws		nh_common.nhc_lwtstate		
#define fib_nh_scope		nh_common.nhc_scope   //路由的范围
#define fib_nh_gw_family	nh_common.nhc_gw_family //AF_INET
#define fib_nh_gw4		nh_common.nhc_gw.ipv4		//网关ip
#define fib_nh_gw6		nh_common.nhc_gw.ipv6
#define fib_nh_weight		nh_common.nhc_weight	//多路径路由用到
#define fib_nh_upper_bound	nh_common.nhc_upper_bound //同上
};

/*
 * This structure contains data shared by many of routes.
 */

struct nexthop;
//多个alis可以共享一个， 但是前缀可能不同！！
struct fib_info {
	struct hlist_node	fib_hash;  //挂在hash表上，这hash表是全局的，用什么做的key？
	struct hlist_node	fib_lhash;	//有首选源地址的时候才插入
	struct list_head	nh_list;	//next
	struct net		*fib_net;      //所属网络命名空间
	refcount_t		fib_treeref; 	//引用计数 创建的时候增加被alias++
	refcount_t		fib_clntref;	//外部引用，比如socket，查找路由的时候会加
	unsigned int		fib_flags;  //flag 比如是否link down等
	unsigned char		fib_dead;	//是否逻辑上已经无了
	unsigned char		fib_protocol; //路由的来源
	unsigned char		fib_scope;   //路由的作用域
	unsigned char		fib_type;    //路由的类型 RTN_UNICAST
	__be32			fib_prefsrc;     //优先的源地址，用户配置的
	u32			fib_tb_id;			//属于哪个路由表
	u32			fib_priority;		//metric 
	struct dst_metrics	*fib_metrics; //tcp用的好像很多用户配置的？
#define fib_mtu fib_metrics->metrics[RTAX_MTU-1]     
#define fib_window fib_metrics->metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics->metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics->metrics[RTAX_ADVMSS-1]
	int			fib_nhs;			//nexthop数量，通常应该是1 //多路径路由的时候才会有多个
	bool			fib_nh_is_v6;
	bool			nh_updated;		//是否更新
	bool			pfsrc_removed;
	struct nexthop		*nh;
	struct rcu_head		rcu;
	struct fib_nh		fib_nh[];	//nexthop
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_table;
struct fib_result {
	__be32			prefix;  		//前缀
	unsigned char		prefixlen;  //前缀长度 0表示默认路由
	unsigned char		nh_sel;     //哪个nh hop
	unsigned char		type;		//RTN_LOCAL  RTN_UNICAST，决定上送还是转发
	unsigned char		scope;		//路由的作用范围
	u32			tclassid;
	struct fib_nh_common	*nhc;    //下一跳 里面有netdev
	struct fib_info		*fi;		 //完整的路由信息
	struct fib_table	*table;		 //对应的路由表
	struct hlist_head	*fa_head;	 //指向的是fib_alis 一条完整的路由
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;
};

#ifdef CONFIG_IP_MULTIPLE_TABLES
#define FIB_TABLE_HASHSZ 256
#else
#define FIB_TABLE_HASHSZ 2
#endif

__be32 fib_info_update_nhc_saddr(struct net *net, struct fib_nh_common *nhc,
				 unsigned char scope);
__be32 fib_result_prefsrc(struct net *net, struct fib_result *res);

#define FIB_RES_NHC(res)		((res).nhc)
#define FIB_RES_DEV(res)	(FIB_RES_NHC(res)->nhc_dev)
#define FIB_RES_OIF(res)	(FIB_RES_NHC(res)->nhc_oif)

struct fib_rt_info {
	struct fib_info		*fi;
	u32			tb_id;
	__be32			dst;
	int			dst_len;
	dscp_t			dscp;
	u8			type;
	u8			offload:1,
				trap:1,
				offload_failed:1,
				unused:5;
};

struct fib_entry_notifier_info {
	struct fib_notifier_info info; /* must be first */
	u32 dst;
	int dst_len;
	struct fib_info *fi;
	dscp_t dscp;
	u8 type;
	u32 tb_id;
};

struct fib_nh_notifier_info {
	struct fib_notifier_info info; /* must be first */
	struct fib_nh *fib_nh;
};

int call_fib4_notifier(struct notifier_block *nb,
		       enum fib_event_type event_type,
		       struct fib_notifier_info *info);
int call_fib4_notifiers(struct net *net, enum fib_event_type event_type,
			struct fib_notifier_info *info);

int __net_init fib4_notifier_init(struct net *net);
void __net_exit fib4_notifier_exit(struct net *net);

void fib_info_notify_update(struct net *net, struct nl_info *info);
int fib_notify(struct net *net, struct notifier_block *nb,
	       struct netlink_ext_ack *extack);

struct fib_table {
	struct hlist_node	tb_hlist;   //挂到全局hash表中，初始化时创建的全局hash表
	u32			tb_id;				//标识是哪一个路由表
	int			tb_num_default;		//如果是插入了一个默认路由就++
	struct rcu_head		rcu;
	unsigned long 		*tb_data;	//指向真正的路由
	unsigned long		__data[];	//柔性数组
};

struct fib_dump_filter {
	u32			table_id;
	/* filter_set is an optimization that an entry is set */
	bool			filter_set;
	bool			dump_routes;
	bool			dump_exceptions;
	unsigned char		protocol;
	unsigned char		rt_type;
	unsigned int		flags;
	struct net_device	*dev;
};

int fib_table_lookup(struct fib_table *tb, const struct flowi4 *flp,
		     struct fib_result *res, int fib_flags);
int fib_table_insert(struct net *, struct fib_table *, struct fib_config *,
		     struct netlink_ext_ack *extack);
int fib_table_delete(struct net *, struct fib_table *, struct fib_config *,
		     struct netlink_ext_ack *extack);
int fib_table_dump(struct fib_table *table, struct sk_buff *skb,
		   struct netlink_callback *cb, struct fib_dump_filter *filter);
int fib_table_flush(struct net *net, struct fib_table *table, bool flush_all);
struct fib_table *fib_trie_unmerge(struct fib_table *main_tb);
void fib_table_flush_external(struct fib_table *table);
void fib_free_table(struct fib_table *tb);

#ifndef CONFIG_IP_MULTIPLE_TABLES

#define TABLE_LOCAL_INDEX	(RT_TABLE_LOCAL & (FIB_TABLE_HASHSZ - 1))
#define TABLE_MAIN_INDEX	(RT_TABLE_MAIN  & (FIB_TABLE_HASHSZ - 1))

static inline struct fib_table *fib_get_table(struct net *net, u32 id)
{
	struct hlist_node *tb_hlist;
	struct hlist_head *ptr;

	ptr = id == RT_TABLE_LOCAL ?
		&net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX] :
		&net->ipv4.fib_table_hash[TABLE_MAIN_INDEX];

	tb_hlist = rcu_dereference_rtnl(hlist_first_rcu(ptr));

	return hlist_entry(tb_hlist, struct fib_table, tb_hlist);
}

static inline struct fib_table *fib_new_table(struct net *net, u32 id)
{
	return fib_get_table(net, id);
}

static inline int fib_lookup(struct net *net, const struct flowi4 *flp,
			     struct fib_result *res, unsigned int flags)
{
	struct fib_table *tb;
	int err = -ENETUNREACH;

	rcu_read_lock();

	tb = fib_get_table(net, RT_TABLE_MAIN);
	if (tb)
		err = fib_table_lookup(tb, flp, res, flags | FIB_LOOKUP_NOREF);

	if (err == -EAGAIN)
		err = -ENETUNREACH;

	rcu_read_unlock();

	return err;
}

static inline bool fib4_has_custom_rules(const struct net *net)
{
	return false;
}

static inline bool fib4_rule_default(const struct fib_rule *rule)
{
	return true;
}

static inline int fib4_rules_dump(struct net *net, struct notifier_block *nb,
				  struct netlink_ext_ack *extack)
{
	return 0;
}

static inline unsigned int fib4_rules_seq_read(struct net *net)
{
	return 0;
}

static inline bool fib4_rules_early_flow_dissect(struct net *net,
						 struct sk_buff *skb,
						 struct flowi4 *fl4,
						 struct flow_keys *flkeys)
{
	return false;
}
#else /* CONFIG_IP_MULTIPLE_TABLES */
int __net_init fib4_rules_init(struct net *net);
void __net_exit fib4_rules_exit(struct net *net);

struct fib_table *fib_new_table(struct net *net, u32 id);
struct fib_table *fib_get_table(struct net *net, u32 id);

int __fib_lookup(struct net *net, struct flowi4 *flp,
		 struct fib_result *res, unsigned int flags);

static inline int fib_lookup(struct net *net, struct flowi4 *flp,
			     struct fib_result *res, unsigned int flags)
{
	struct fib_table *tb;
	int err = -ENETUNREACH;

	flags |= FIB_LOOKUP_NOREF;
	//如果配置了策略路由，通常不走这里
	if (net->ipv4.fib_has_custom_rules)
		return __fib_lookup(net, flp, res, flags);

	rcu_read_lock();

	res->tclassid = 0;
	//没有配置策略路由的情况
	tb = rcu_dereference_rtnl(net->ipv4.fib_main);
	if (tb)//main
		err = fib_table_lookup(tb, flp, res, flags);

	if (!err)
		goto out;

	tb = rcu_dereference_rtnl(net->ipv4.fib_default);
	if (tb)//default
		err = fib_table_lookup(tb, flp, res, flags);

out:
	if (err == -EAGAIN)
		err = -ENETUNREACH;

	rcu_read_unlock();

	return err;
}

static inline bool fib4_has_custom_rules(const struct net *net)
{
	return net->ipv4.fib_has_custom_rules;
}

bool fib4_rule_default(const struct fib_rule *rule);
int fib4_rules_dump(struct net *net, struct notifier_block *nb,
		    struct netlink_ext_ack *extack);
unsigned int fib4_rules_seq_read(struct net *net);

static inline bool fib4_rules_early_flow_dissect(struct net *net,
						 struct sk_buff *skb,
						 struct flowi4 *fl4,
						 struct flow_keys *flkeys)
{
	unsigned int flag = FLOW_DISSECTOR_F_STOP_AT_ENCAP;

	if (!net->ipv4.fib_rules_require_fldissect)
		return false;

	memset(flkeys, 0, sizeof(*flkeys));
	__skb_flow_dissect(net, skb, &flow_keys_dissector,
			   flkeys, NULL, 0, 0, 0, flag);

	fl4->fl4_sport = flkeys->ports.src;
	fl4->fl4_dport = flkeys->ports.dst;
	fl4->flowi4_proto = flkeys->basic.ip_proto;

	return true;
}

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern const struct nla_policy rtm_ipv4_policy[];
void ip_fib_init(void);
int fib_gw_from_via(struct fib_config *cfg, struct nlattr *nla,
		    struct netlink_ext_ack *extack);
__be32 fib_compute_spec_dst(struct sk_buff *skb);
bool fib_info_nh_uses_dev(struct fib_info *fi, const struct net_device *dev);
int fib_validate_source(struct sk_buff *skb, __be32 src, __be32 dst,
			u8 tos, int oif, struct net_device *dev,
			struct in_device *idev, u32 *itag);
#ifdef CONFIG_IP_ROUTE_CLASSID
static inline int fib_num_tclassid_users(struct net *net)
{
	return atomic_read(&net->ipv4.fib_num_tclassid_users);
}
#else
static inline int fib_num_tclassid_users(struct net *net)
{
	return 0;
}
#endif
int fib_unmerge(struct net *net);

static inline bool nhc_l3mdev_matches_dev(const struct fib_nh_common *nhc,
const struct net_device *dev)
{
	if (nhc->nhc_dev == dev ||
	    l3mdev_master_ifindex_rcu(nhc->nhc_dev) == dev->ifindex)
		return true;

	return false;
}

/* Exported by fib_semantics.c */
int ip_fib_check_default(__be32 gw, struct net_device *dev);
int fib_sync_down_dev(struct net_device *dev, unsigned long event, bool force);
int fib_sync_down_addr(struct net_device *dev, __be32 local);
int fib_sync_up(struct net_device *dev, unsigned char nh_flags);
void fib_sync_mtu(struct net_device *dev, u32 orig_mtu);
void fib_nhc_update_mtu(struct fib_nh_common *nhc, u32 new, u32 orig);

/* Fields used for sysctl_fib_multipath_hash_fields.
 * Common to IPv4 and IPv6.
 *
 * Add new fields at the end. This is user API.
 */
#define FIB_MULTIPATH_HASH_FIELD_SRC_IP			BIT(0)
#define FIB_MULTIPATH_HASH_FIELD_DST_IP			BIT(1)
#define FIB_MULTIPATH_HASH_FIELD_IP_PROTO		BIT(2)
#define FIB_MULTIPATH_HASH_FIELD_FLOWLABEL		BIT(3)
#define FIB_MULTIPATH_HASH_FIELD_SRC_PORT		BIT(4)
#define FIB_MULTIPATH_HASH_FIELD_DST_PORT		BIT(5)
#define FIB_MULTIPATH_HASH_FIELD_INNER_SRC_IP		BIT(6)
#define FIB_MULTIPATH_HASH_FIELD_INNER_DST_IP		BIT(7)
#define FIB_MULTIPATH_HASH_FIELD_INNER_IP_PROTO		BIT(8)
#define FIB_MULTIPATH_HASH_FIELD_INNER_FLOWLABEL	BIT(9)
#define FIB_MULTIPATH_HASH_FIELD_INNER_SRC_PORT		BIT(10)
#define FIB_MULTIPATH_HASH_FIELD_INNER_DST_PORT		BIT(11)

#define FIB_MULTIPATH_HASH_FIELD_OUTER_MASK		\
	(FIB_MULTIPATH_HASH_FIELD_SRC_IP |		\
	 FIB_MULTIPATH_HASH_FIELD_DST_IP |		\
	 FIB_MULTIPATH_HASH_FIELD_IP_PROTO |		\
	 FIB_MULTIPATH_HASH_FIELD_FLOWLABEL |		\
	 FIB_MULTIPATH_HASH_FIELD_SRC_PORT |		\
	 FIB_MULTIPATH_HASH_FIELD_DST_PORT)

#define FIB_MULTIPATH_HASH_FIELD_INNER_MASK		\
	(FIB_MULTIPATH_HASH_FIELD_INNER_SRC_IP |	\
	 FIB_MULTIPATH_HASH_FIELD_INNER_DST_IP |	\
	 FIB_MULTIPATH_HASH_FIELD_INNER_IP_PROTO |	\
	 FIB_MULTIPATH_HASH_FIELD_INNER_FLOWLABEL |	\
	 FIB_MULTIPATH_HASH_FIELD_INNER_SRC_PORT |	\
	 FIB_MULTIPATH_HASH_FIELD_INNER_DST_PORT)

#define FIB_MULTIPATH_HASH_FIELD_ALL_MASK		\
	(FIB_MULTIPATH_HASH_FIELD_OUTER_MASK |		\
	 FIB_MULTIPATH_HASH_FIELD_INNER_MASK)

#define FIB_MULTIPATH_HASH_FIELD_DEFAULT_MASK		\
	(FIB_MULTIPATH_HASH_FIELD_SRC_IP |		\
	 FIB_MULTIPATH_HASH_FIELD_DST_IP |		\
	 FIB_MULTIPATH_HASH_FIELD_IP_PROTO)

#ifdef CONFIG_IP_ROUTE_MULTIPATH
int fib_multipath_hash(const struct net *net, const struct flowi4 *fl4,
		       const struct sk_buff *skb, struct flow_keys *flkeys);
#endif
int fib_check_nh(struct net *net, struct fib_nh *nh, u32 table, u8 scope,
		 struct netlink_ext_ack *extack);
void fib_select_multipath(struct fib_result *res, int hash);
void fib_select_path(struct net *net, struct fib_result *res,
		     struct flowi4 *fl4, const struct sk_buff *skb);

int fib_nh_init(struct net *net, struct fib_nh *fib_nh,
		struct fib_config *cfg, int nh_weight,
		struct netlink_ext_ack *extack);
void fib_nh_release(struct net *net, struct fib_nh *fib_nh);
int fib_nh_common_init(struct net *net, struct fib_nh_common *nhc,
		       struct nlattr *fc_encap, u16 fc_encap_type,
		       void *cfg, gfp_t gfp_flags,
		       struct netlink_ext_ack *extack);
void fib_nh_common_release(struct fib_nh_common *nhc);

/* Exported by fib_trie.c */
void fib_alias_hw_flags_set(struct net *net, const struct fib_rt_info *fri);
void fib_trie_init(void);
struct fib_table *fib_trie_table(u32 id, struct fib_table *alias);
bool fib_lookup_good_nhc(const struct fib_nh_common *nhc, int fib_flags,
			 const struct flowi4 *flp);

static inline void fib_combine_itag(u32 *itag, const struct fib_result *res)
{
#ifdef CONFIG_IP_ROUTE_CLASSID
	struct fib_nh_common *nhc = res->nhc;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	if (nhc->nhc_family == AF_INET) {
		struct fib_nh *nh;

		nh = container_of(nhc, struct fib_nh, nh_common);
		*itag = nh->nh_tclassid << 16;
	} else {
		*itag = 0;
	}

#ifdef CONFIG_IP_MULTIPLE_TABLES
	rtag = res->tclassid;
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

void fib_flush(struct net *net);
void free_fib_info(struct fib_info *fi);

static inline void fib_info_hold(struct fib_info *fi)
{
	refcount_inc(&fi->fib_clntref);
}

static inline void fib_info_put(struct fib_info *fi)
{
	if (refcount_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

#ifdef CONFIG_PROC_FS
int __net_init fib_proc_init(struct net *net);
void __net_exit fib_proc_exit(struct net *net);
#else
static inline int fib_proc_init(struct net *net)
{
	return 0;
}
static inline void fib_proc_exit(struct net *net)
{
}
#endif

u32 ip_mtu_from_fib_result(struct fib_result *res, __be32 daddr);

int ip_valid_fib_dump_req(struct net *net, const struct nlmsghdr *nlh,
			  struct fib_dump_filter *filter,
			  struct netlink_callback *cb);

int fib_nexthop_info(struct sk_buff *skb, const struct fib_nh_common *nh,
		     u8 rt_family, unsigned char *flags, bool skip_oif);
int fib_add_nexthop(struct sk_buff *skb, const struct fib_nh_common *nh,
		    int nh_weight, u8 rt_family, u32 nh_tclassid);
#endif  /* _NET_FIB_H */
