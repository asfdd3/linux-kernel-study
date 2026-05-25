// SPDX-License-Identifier: GPL-2.0
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The options processing module for ip.c
 *
 * Authors:	A.N.Kuznetsov
 *
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm/unaligned.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/cipso_ipv4.h>
#include <net/ip_fib.h>

/*
 * Write options to IP header, record destination address to
 * source route option, address of outgoing interface
 * (we should already know it, so that this  function is allowed be
 * called only after routing decision) and timestamp,
 * if we originate this datagram.
 *
 * daddr is real destination address, next hop is recorded in IP header.
 * saddr is address of outgoing interface.
 */

void ip_options_build(struct sk_buff *skb, struct ip_options *opt,
		      __be32 daddr, struct rtable *rt)
{
	unsigned char *iph = skb_network_header(skb);
	//拷贝选项信息到数据包的控制块中
	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	//实际把选项写到ip头
	memcpy(iph + sizeof(struct iphdr), opt->__data, opt->optlen);
	opt = &(IPCB(skb)->opt);
	//源路由
	if (opt->srr)
		memcpy(iph + opt->srr + iph[opt->srr + 1] - 4, &daddr, 4);
	//记录路由
	if (opt->rr_needaddr)
		ip_rt_get_source(iph + opt->rr + iph[opt->rr + 2] - 5, skb, rt);
	if (opt->ts_needaddr)
	//时间戳
		ip_rt_get_source(iph + opt->ts + iph[opt->ts + 2] - 9, skb, rt);
	if (opt->ts_needtime) {
		__be32 midtime;

		midtime = inet_current_timestamp();
		memcpy(iph + opt->ts + iph[opt->ts + 2] - 5, &midtime, 4);
	}
}

/*
 * Provided (sopt, skb) points to received options,
 * build in dopt compiled option set appropriate for answering.
 * i.e. invert SRR option, copy anothers,
 * and grab room in RR/TS options.
 *
 * NOTE: dopt cannot point to skb.
 */

int __ip_options_echo(struct net *net, struct ip_options *dopt,
		      struct sk_buff *skb, const struct ip_options *sopt)
{
	unsigned char *sptr, *dptr;
	int soffset, doffset;
	int	optlen;

	memset(dopt, 0, sizeof(struct ip_options));

	if (sopt->optlen == 0)
		return 0;

	sptr = skb_network_header(skb);
	dptr = dopt->__data;

	if (sopt->rr) {
		optlen  = sptr[sopt->rr+1];
		soffset = sptr[sopt->rr+2];
		dopt->rr = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->rr, optlen);
		if (sopt->rr_needaddr && soffset <= optlen) {
			if (soffset + 3 > optlen)
				return -EINVAL;
			dptr[2] = soffset + 4;
			dopt->rr_needaddr = 1;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->ts) {
		optlen = sptr[sopt->ts+1];
		soffset = sptr[sopt->ts+2];
		dopt->ts = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->ts, optlen);
		if (soffset <= optlen) {
			if (sopt->ts_needaddr) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				dopt->ts_needaddr = 1;
				soffset += 4;
			}
			if (sopt->ts_needtime) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				if ((dptr[3]&0xF) != IPOPT_TS_PRESPEC) {
					dopt->ts_needtime = 1;
					soffset += 4;
				} else {
					dopt->ts_needtime = 0;

					if (soffset + 7 <= optlen) {
						__be32 addr;

						memcpy(&addr, dptr+soffset-1, 4);
						if (inet_addr_type(net, addr) != RTN_UNICAST) {
							dopt->ts_needtime = 1;
							soffset += 8;
						}
					}
				}
			}
			dptr[2] = soffset;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->srr) {
		unsigned char *start = sptr+sopt->srr;
		__be32 faddr;

		optlen  = start[1];
		soffset = start[2];
		doffset = 0;
		if (soffset > optlen)
			soffset = optlen + 1;
		soffset -= 4;
		if (soffset > 3) {
			memcpy(&faddr, &start[soffset-1], 4);
			for (soffset -= 4, doffset = 4; soffset > 3; soffset -= 4, doffset += 4)
				memcpy(&dptr[doffset-1], &start[soffset-1], 4);
			/*
			 * RFC1812 requires to fix illegal source routes.
			 */
			if (memcmp(&ip_hdr(skb)->saddr,
				   &start[soffset + 3], 4) == 0)
				doffset -= 4;
		}
		if (doffset > 3) {
			dopt->faddr = faddr;
			dptr[0] = start[0];
			dptr[1] = doffset+3;
			dptr[2] = 4;
			dptr += doffset+3;
			dopt->srr = dopt->optlen + sizeof(struct iphdr);
			dopt->optlen += doffset+3;
			dopt->is_strictroute = sopt->is_strictroute;
		}
	}
	if (sopt->cipso) {
		optlen  = sptr[sopt->cipso+1];
		dopt->cipso = dopt->optlen+sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->cipso, optlen);
		dptr += optlen;
		dopt->optlen += optlen;
	}
	while (dopt->optlen & 3) {
		*dptr++ = IPOPT_END;
		dopt->optlen++;
	}
	return 0;
}

/*
 *	Options "fragmenting", just fill options not
 *	allowed in fragments with NOOPs.
 *	Simple and stupid 8), but the most efficient way.
 */

void ip_options_fragment(struct sk_buff *skb)
{
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	struct ip_options *opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen < 2 || optlen > l)
		  return;
		if (!IPOPT_COPIED(*optptr))
			memset(optptr, IPOPT_NOOP, optlen);
		l -= optlen;
		optptr += optlen;
	}
	opt->ts = 0;
	opt->rr = 0;
	opt->rr_needaddr = 0;
	opt->ts_needaddr = 0;
	opt->ts_needtime = 0;
}

/* helper used by ip_options_compile() to call fib_compute_spec_dst()
 * at most one time.
 */
static void spec_dst_fill(__be32 *spec_dst, struct sk_buff *skb)
{
	if (*spec_dst == htonl(INADDR_ANY))
		*spec_dst = fib_compute_spec_dst(skb);
}

/*
 * Verify options and fill pointers in struct options.
 * Caller should clear *opt, and set opt->data.
 * If opt == NULL, then skb->data should point to IP header.
 */
//校验合法性（长度、pointer、是否重复、权限等）
//记录各选项在 IP 头中的偏移位置
//设置后续 build 阶段需要的标志位（needaddr/needtime）
int __ip_options_compile(struct net *net,
			 struct ip_options *opt, struct sk_buff *skb,
			 __be32 *info)
{
	__be32 spec_dst = htonl(INADDR_ANY);
	unsigned char *pp_ptr = NULL;
	struct rtable *rt = NULL;
	unsigned char *optptr;
	unsigned char *iph;
	int optlen, l;
	//接收路径调用，skb不为空，主要目的是解析位置，判断是否需要后续修改
	if (skb) {
		rt = skb_rtable(skb);
		optptr = (unsigned char *)&(ip_hdr(skb)[1]);
	} else
		optptr = opt->__data;
	iph = optptr - sizeof(struct iphdr);

	for (l = opt->optlen; l > 0; ) {
		switch (*optptr) {
		case IPOPT_END:
			for (optptr++, l--; l > 0; optptr++, l--) {
				if (*optptr != IPOPT_END) {
					*optptr = IPOPT_END;
					opt->is_changed = 1;
				}
			}
			goto eol;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		//检查长度
		if (unlikely(l < 2)) {
			pp_ptr = optptr;
			goto error;
		}
		//长度非法
		optlen = optptr[1];
		if (optlen < 2 || optlen > l) {
			pp_ptr = optptr;
			goto error;
		}
		switch (*optptr) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if (optlen < 3) {//长度不够
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 4) {//Pointer 不能小于 4 因为type len pointer已经是3了
				pp_ptr = optptr + 2;
				goto error;
			}
			/* NB: cf RFC-1812 5.2.4.1 */
			if (opt->srr) {//只能由一个源路由选项
				pp_ptr = optptr;
				goto error;
			}
			if (!skb) {//发送路径，pointer必须是4 optlen至少是7地址列表必须4字节对齐否则报错
				if (optptr[2] != 4 || optlen < 7 || ((optlen-3) & 3)) {
					pp_ptr = optptr + 1;
					goto error;
				}
				//放到opt中
				memcpy(&opt->faddr, &optptr[3], 4);
				if (optlen > 7)
					memmove(&optptr[3], &optptr[7], optlen-7);
			}
			//标识是否为严格源路由
			opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
			opt->srr = optptr - iph; //源路由 option 在 IP 头中的偏移位置。后续buid_options会用到
			break;
		case IPOPT_RR:
			if (opt->rr) {
				pp_ptr = optptr;
				goto error;
			}
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			if (optptr[2] <= optlen) {
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				if (rt) {
					spec_dst_fill(&spec_dst, skb);
					memcpy(&optptr[optptr[2]-1], &spec_dst, 4);
					opt->is_changed = 1;
				}
				optptr[2] += 4;
				opt->rr_needaddr = 1;
			}
			opt->rr = optptr - iph;
			break;
		case IPOPT_TIMESTAMP:
			if (opt->ts) {
				pp_ptr = optptr;
				goto error;
			}
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 5) {
				pp_ptr = optptr + 2;
				goto error;
			}
			if (optptr[2] <= optlen) {
				unsigned char *timeptr = NULL;
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				switch (optptr[3]&0xF) {
				case IPOPT_TS_TSONLY:
					if (skb)
						timeptr = &optptr[optptr[2]-1];
					opt->ts_needtime = 1;
					optptr[2] += 4;
					break;
				case IPOPT_TS_TSANDADDR:
					if (optptr[2]+7 > optlen) {
						pp_ptr = optptr + 2;
						goto error;
					}
					if (rt)  {
						spec_dst_fill(&spec_dst, skb);
						memcpy(&optptr[optptr[2]-1], &spec_dst, 4);
						timeptr = &optptr[optptr[2]+3];
					}
					opt->ts_needaddr = 1;
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				case IPOPT_TS_PRESPEC:
					if (optptr[2]+7 > optlen) {
						pp_ptr = optptr + 2;
						goto error;
					}
					{
						__be32 addr;
						memcpy(&addr, &optptr[optptr[2]-1], 4);
						if (inet_addr_type(net, addr) == RTN_UNICAST)
							break;
						if (skb)
							timeptr = &optptr[optptr[2]+3];
					}
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				default:
					if (!skb && !ns_capable(net->user_ns, CAP_NET_RAW)) {
						pp_ptr = optptr + 3;
						goto error;
					}
					break;
				}
				if (timeptr) {
					__be32 midtime;

					midtime = inet_current_timestamp();
					memcpy(timeptr, &midtime, 4);
					opt->is_changed = 1;
				}
			} else if ((optptr[3]&0xF) != IPOPT_TS_PRESPEC) {
				unsigned int overflow = optptr[3]>>4;
				if (overflow == 15) {
					pp_ptr = optptr + 3;
					goto error;
				}
				if (skb) {
					optptr[3] = (optptr[3]&0xF)|((overflow+1)<<4);
					opt->is_changed = 1;
				}
			}
			opt->ts = optptr - iph;
			break;
		case IPOPT_RA:
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] == 0 && optptr[3] == 0)
				opt->router_alert = optptr - iph;
			break;
		case IPOPT_CIPSO:
			if ((!skb && !ns_capable(net->user_ns, CAP_NET_RAW)) || opt->cipso) {
				pp_ptr = optptr;
				goto error;
			}
			opt->cipso = optptr - iph;
			if (cipso_v4_validate(skb, &optptr)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		case IPOPT_SEC:
		case IPOPT_SID:
		default:
			if (!skb && !ns_capable(net->user_ns, CAP_NET_RAW)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		}
		l -= optlen;
		optptr += optlen;//下一个选项
	}

eol:
	if (!pp_ptr)
		return 0;

error:
	if (info)
		*info = htonl((pp_ptr-iph)<<24);
	return -EINVAL;
}
EXPORT_SYMBOL(__ip_options_compile);

int ip_options_compile(struct net *net,
		       struct ip_options *opt, struct sk_buff *skb)
{
	int ret;
	__be32 info;

	ret = __ip_options_compile(net, opt, skb, &info);
	if (ret != 0 && skb)
		icmp_send(skb, ICMP_PARAMETERPROB, 0, info);
	return ret;
}
EXPORT_SYMBOL(ip_options_compile);

/*
 *	Undo all the changes done by ip_options_compile().
 */
//撤销修改的ip选项。比如getsockopt调用需要还原回去。
void ip_options_undo(struct ip_options *opt)
{
	//把被取走的下一跳地址塞回去
	if (opt->srr) {
		unsigned char *optptr = opt->__data + opt->srr - sizeof(struct iphdr);

		memmove(optptr + 7, optptr + 3, optptr[1] - 7);
		memcpy(optptr + 3, &opt->faddr, 4);
	}
	//撤销本机写入的路由槽位
	if (opt->rr_needaddr) {
		unsigned char *optptr = opt->__data + opt->rr - sizeof(struct iphdr);

		optptr[2] -= 4;
		memset(&optptr[optptr[2] - 1], 0, 4);
	}
	//撤销时间戳
	if (opt->ts) {
		unsigned char *optptr = opt->__data + opt->ts - sizeof(struct iphdr);

		if (opt->ts_needtime) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2] - 1], 0, 4);
			if ((optptr[3] & 0xF) == IPOPT_TS_PRESPEC)
				optptr[2] -= 4;
		}
		if (opt->ts_needaddr) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2] - 1], 0, 4);
		}
	}
}
//设置ip选项调用
int ip_options_get(struct net *net, struct ip_options_rcu **optp,
		   sockptr_t data, int optlen)
{
	struct ip_options_rcu *opt;

	opt = kzalloc(sizeof(struct ip_options_rcu) + ((optlen + 3) & ~3),
		       GFP_KERNEL);
	if (!opt)
		return -ENOMEM;
	if (optlen && copy_from_sockptr(opt->opt.__data, data, optlen)) {
		kfree(opt);
		return -EFAULT;
	}

	while (optlen & 3)
		opt->opt.__data[optlen++] = IPOPT_END;
	opt->opt.optlen = optlen;
	if (optlen && ip_options_compile(net, &opt->opt, NULL)) {
		kfree(opt);
		return -EINVAL;
	}
	kfree(*optp);
	*optp = opt;
	return 0;
}

void ip_forward_options(struct sk_buff *skb)
{
	struct   ip_options *opt	= &(IPCB(skb)->opt);
	unsigned char *optptr;
	struct rtable *rt = skb_rtable(skb);
	unsigned char *raw = skb_network_header(skb);
	//需要记录路由
	if (opt->rr_needaddr) {
		optptr = (unsigned char *)raw + opt->rr;
		//ip地址写入选项
		ip_rt_get_source(&optptr[optptr[2]-5], skb, rt);
		opt->is_changed = 1;
	}
	if (opt->srr_is_hit) {
		int srrptr, srrspace;

		optptr = raw + opt->srr; //定位源路由 option

		for ( srrptr = optptr[2], srrspace = optptr[1]; 
		     srrptr <= srrspace;
		     srrptr += 4
		     ) {
			if (srrptr + 3 > srrspace)
				break;
			////地址是否匹配？这里第一参数是查路由时候设置的
			if (memcmp(&opt->nexthop, &optptr[srrptr-1], 4) == 0)
				break;
		}
		//找到了
		if (srrptr + 3 <= srrspace) {
			opt->is_changed = 1;
			ip_hdr(skb)->daddr = opt->nexthop;//这里修改报文的目的地址
			ip_rt_get_source(&optptr[srrptr-1], skb, rt);
			optptr[2] = srrptr+4;
		} else {
			net_crit_ratelimited("%s(): Argh! Destination lost!\n",
					     __func__);
		}
		if (opt->ts_needaddr) {
			optptr = raw + opt->ts;
			ip_rt_get_source(&optptr[optptr[2]-9], skb, rt);
			opt->is_changed = 1;
		}
	}
	//重新计算校验和
	if (opt->is_changed) {
		opt->is_changed = 0;
		ip_send_check(ip_hdr(skb));
	}
}
//核心思想貌似就是遍历选项的ip地址 设置成数据包的目的ip然后查找路由，如果是给本机的则继续遍历选项，否则直接走转发
int ip_options_rcv_srr(struct sk_buff *skb, struct net_device *dev)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	int srrspace, srrptr;
	__be32 nexthop;
	struct iphdr *iph = ip_hdr(skb);
	unsigned char *optptr = skb_network_header(skb) + opt->srr;
	struct rtable *rt = skb_rtable(skb);
	struct rtable *rt2;
	unsigned long orefdst;
	int err;

	if (!rt)
		return 0;
	//必须是发给本机的包
	if (skb->pkt_type != PACKET_HOST)
		return -EINVAL;
	//注意这里其实是要转发！！！
	if (rt->rt_type == RTN_UNICAST) {
		if (!opt->is_strictroute)
			return 0;
		//回复控制消息
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl(16<<24));
		return -EINVAL;
	}
	//不是 LOCAL 也不是上面情况
	if (rt->rt_type != RTN_LOCAL)
		return -EINVAL;

	for (srrptr = optptr[2], srrspace = optptr[1]; srrptr <= srrspace; srrptr += 4) {
		if (srrptr + 3 > srrspace) {
			icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((opt->srr+2)<<24));
			return -EINVAL;
		}
		memcpy(&nexthop, &optptr[srrptr-1], 4);

		orefdst = skb->_skb_refdst;
		skb_dst_set(skb, NULL);
		//用 nexthop 重新查路由验证是否可达
		err = ip_route_input(skb, nexthop, iph->saddr, iph->tos, dev);
		rt2 = skb_rtable(skb);//新的查找结果
		//既不是 UNICAST（能转发出去）也不是 LOCAL（本机地址）
		if (err || (rt2->rt_type != RTN_UNICAST && rt2->rt_type != RTN_LOCAL)) {
			skb_dst_drop(skb);
			skb->_skb_refdst = orefdst;
			return -EINVAL;
		}
		refdst_drop(orefdst);
		//需要转发，如果查路由的结果是发给本机的则继续遍历
		if (rt2->rt_type != RTN_LOCAL)
			break;
		/* Superfast 8) loopback forward */
		//重新修改数据包的ip地址
		iph->daddr = nexthop;
		opt->is_changed = 1;
	}
	if (srrptr <= srrspace) {
		opt->srr_is_hit = 1;
		opt->nexthop = nexthop;
		opt->is_changed = 1;
	}
	return 0;
}
EXPORT_SYMBOL(ip_options_rcv_srr);
