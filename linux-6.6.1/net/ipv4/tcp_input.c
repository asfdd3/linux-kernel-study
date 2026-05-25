// SPDX-License-Identifier: GPL-2.0
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

/*
 * Changes:
 *		Pedro Roque	:	Fast Retransmit/Recovery.
 *					Two receive queues.
 *					Retransmit queue handled by TCP.
 *					Better retransmit timer handling.
 *					New congestion avoidance.
 *					Header prediction.
 *					Variable renaming.
 *
 *		Eric		:	Fast Retransmit.
 *		Randy Scott	:	MSS option defines.
 *		Eric Schenk	:	Fixes to slow start algorithm.
 *		Eric Schenk	:	Yet another double ACK bug.
 *		Eric Schenk	:	Delayed ACK bug fixes.
 *		Eric Schenk	:	Floyd style fast retrans war avoidance.
 *		David S. Miller	:	Don't allow zero congestion window.
 *		Eric Schenk	:	Fix retransmitter so that it sends
 *					next packet on ack of previous packet.
 *		Andi Kleen	:	Moved open_request checking here
 *					and process RSTs for open_requests.
 *		Andi Kleen	:	Better prune_queue, and other fixes.
 *		Andrey Savochkin:	Fix RTT measurements in the presence of
 *					timestamps.
 *		Andrey Savochkin:	Check sequence numbers correctly when
 *					removing SACKs due to in sequence incoming
 *					data segments.
 *		Andi Kleen:		Make sure we never ack data there is not
 *					enough room for. Also make this condition
 *					a fatal error if it might still happen.
 *		Andi Kleen:		Add tcp_measure_rcv_mss to make
 *					connections with MSS<min(MTU,ann. MSS)
 *					work without delayed acks.
 *		Andi Kleen:		Process packets with PSH set in the
 *					fast path.
 *		J Hadi Salim:		ECN support
 *	 	Andrei Gurtov,
 *		Pasi Sarolahti,
 *		Panu Kuhlberg:		Experimental audit of TCP (re)transmission
 *					engine. Lots of bugs are found.
 *		Pasi Sarolahti:		F-RTO for dealing with spurious RTOs
 */

#define pr_fmt(fmt) "TCP: " fmt

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/kernel.h>
#include <linux/prefetch.h>
#include <net/dst.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/ipsec.h>
#include <asm/unaligned.h>
#include <linux/errqueue.h>
#include <trace/events/tcp.h>
#include <linux/jump_label_ratelimit.h>
#include <net/busy_poll.h>
#include <net/mptcp.h>

int sysctl_tcp_max_orphans __read_mostly = NR_FILE;

#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/ //ack数据包有数据
#define FLAG_WIN_UPDATE		0x02 /* Incoming ACK was a window update.	*/ //ack数据包更新了snd_wnd
#define FLAG_DATA_ACKED		0x04 /* This ACK acknowledged new data.		*/
#define FLAG_RETRANS_DATA_ACKED	0x08 /* "" "" some of which was retransmitted.	*/
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
#define FLAG_ECE		0x40 /* ECE in this ACK				*/
#define FLAG_LOST_RETRANS	0x80 /* This ACK marks some retransmission lost */ //表示有重传包丢失
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/
#define FLAG_ORIG_SACK_ACKED	0x200 /* Never retransmitted data are (s)acked	*/ //没有重传过数据被确认
#define FLAG_SND_UNA_ADVANCED	0x400 /* Snd_una was changed (!= FLAG_DATA_ACKED) */  //确认了新数据
#define FLAG_DSACKING_ACK	0x800 /* SACK blocks contained D-SACK info */
#define FLAG_SET_XMIT_TIMER	0x1000 /* Set TLP or RTO timer */
#define FLAG_SACK_RENEGING	0x2000 /* snd_una advanced to a sacked seq */   //sack返回
#define FLAG_UPDATE_TS_RECENT	0x4000 /* tcp_replace_ts_recent() */
#define FLAG_NO_CHALLENGE_ACK	0x8000 /* do not call tcp_send_challenge_ack()	*/
#define FLAG_ACK_MAYBE_DELAYED	0x10000 /* Likely a delayed ACK */
#define FLAG_DSACK_TLP		0x20000 /* DSACK for tail loss probe */ //TLP导致的dsack重传

#define FLAG_ACKED		(FLAG_DATA_ACKED|FLAG_SYN_ACKED)
#define FLAG_NOT_DUP		(FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
#define FLAG_CA_ALERT		(FLAG_DATA_SACKED|FLAG_ECE|FLAG_DSACKING_ACK)
#define FLAG_FORWARD_PROGRESS	(FLAG_ACKED|FLAG_DATA_SACKED)

#define TCP_REMNANT (TCP_FLAG_FIN|TCP_FLAG_URG|TCP_FLAG_SYN|TCP_FLAG_PSH)
#define TCP_HP_BITS (~(TCP_RESERVED_BITS|TCP_FLAG_PSH))

#define REXMIT_NONE	0 /* no loss recovery to do */
#define REXMIT_LOST	1 /* retransmit packets marked lost */
#define REXMIT_NEW	2 /* FRTO-style transmit of unsent/new packets */

#if IS_ENABLED(CONFIG_TLS_DEVICE)
static DEFINE_STATIC_KEY_DEFERRED_FALSE(clean_acked_data_enabled, HZ);

void clean_acked_data_enable(struct inet_connection_sock *icsk,
			     void (*cad)(struct sock *sk, u32 ack_seq))
{
	icsk->icsk_clean_acked = cad;
	static_branch_deferred_inc(&clean_acked_data_enabled);
}
EXPORT_SYMBOL_GPL(clean_acked_data_enable);

void clean_acked_data_disable(struct inet_connection_sock *icsk)
{
	static_branch_slow_dec_deferred(&clean_acked_data_enabled);
	icsk->icsk_clean_acked = NULL;
}
EXPORT_SYMBOL_GPL(clean_acked_data_disable);

void clean_acked_data_flush(void)
{
	static_key_deferred_flush(&clean_acked_data_enabled);
}
EXPORT_SYMBOL_GPL(clean_acked_data_flush);
#endif

#ifdef CONFIG_CGROUP_BPF
static void bpf_skops_parse_hdr(struct sock *sk, struct sk_buff *skb)
{
	bool unknown_opt = tcp_sk(sk)->rx_opt.saw_unknown &&
		BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk),
				       BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
	bool parse_all_opt = BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk),
						    BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG);
	struct bpf_sock_ops_kern sock_ops;

	if (likely(!unknown_opt && !parse_all_opt))
		return;

	/* The skb will be handled in the
	 * bpf_skops_established() or
	 * bpf_skops_write_hdr_opt().
	 */
	switch (sk->sk_state) {
	case TCP_SYN_RECV:
	case TCP_SYN_SENT:
	case TCP_LISTEN:
		return;
	}

	sock_owned_by_me(sk);

	memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
	sock_ops.op = BPF_SOCK_OPS_PARSE_HDR_OPT_CB;
	sock_ops.is_fullsock = 1;
	sock_ops.sk = sk;
	bpf_skops_init_skb(&sock_ops, skb, tcp_hdrlen(skb));

	BPF_CGROUP_RUN_PROG_SOCK_OPS(&sock_ops);
}

static void bpf_skops_established(struct sock *sk, int bpf_op,
				  struct sk_buff *skb)
{
	struct bpf_sock_ops_kern sock_ops;

	sock_owned_by_me(sk);

	memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
	sock_ops.op = bpf_op;
	sock_ops.is_fullsock = 1;
	sock_ops.sk = sk;
	/* sk with TCP_REPAIR_ON does not have skb in tcp_finish_connect */
	if (skb)
		bpf_skops_init_skb(&sock_ops, skb, tcp_hdrlen(skb));

	BPF_CGROUP_RUN_PROG_SOCK_OPS(&sock_ops);
}
#else
static void bpf_skops_parse_hdr(struct sock *sk, struct sk_buff *skb)
{
}

static void bpf_skops_established(struct sock *sk, int bpf_op,
				  struct sk_buff *skb)
{
}
#endif

static void tcp_gro_dev_warn(struct sock *sk, const struct sk_buff *skb,
			     unsigned int len)
{
	static bool __once __read_mostly;

	if (!__once) {
		struct net_device *dev;

		__once = true;

		rcu_read_lock();
		dev = dev_get_by_index_rcu(sock_net(sk), skb->skb_iif);
		if (!dev || len >= dev->mtu)
			pr_warn("%s: Driver has suspect GRO implementation, TCP performance may be compromised.\n",
				dev ? dev->name : "Unknown driver");
		rcu_read_unlock();
	}
}

/* Adapt the MSS value used to make delayed ack decision to the
 * real world.
 */
static void tcp_measure_rcv_mss(struct sock *sk, const struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const unsigned int lss = icsk->icsk_ack.last_seg_size;//上1轮的估计mss
	unsigned int len;

	icsk->icsk_ack.last_seg_size = 0;

	/* skb->len may jitter because of SACKs, even if peer
	 * sends good full-sized frames.
	 */
	//大包就是gsosize的大小
	len = skb_shinfo(skb)->gso_size ? : skb->len;
	if (len >= icsk->icsk_ack.rcv_mss) {
		/* Note: divides are still a bit expensive.
		 * For the moment, only adjust scaling_ratio
		 * when we update icsk_ack.rcv_mss.
		 */
		//len发生了变化？更新scaling_ratio，这个就是实际能用多少空间的比例把
		if (unlikely(len != icsk->icsk_ack.rcv_mss)) {
			u64 val = (u64)skb->len << TCP_RMEM_TO_WIN_SCALE;

			do_div(val, skb->truesize);
			tcp_sk(sk)->scaling_ratio = val ? val : 1;
		}
		//更新rcv_mss，被通告mss钳制
		icsk->icsk_ack.rcv_mss = min_t(unsigned int, len,
					       tcp_sk(sk)->advmss);
		/* Account for possibly-removed options */
		//len太大的情况
		if (unlikely(len > icsk->icsk_ack.rcv_mss +
				   MAX_TCP_OPTION_SPACE))
			tcp_gro_dev_warn(sk, skb, len);
		/* If the skb has a len of exactly 1*MSS and has the PSH bit
		 * set then it is likely the end of an application write. So
		 * more data may not be arriving soon, and yet the data sender
		 * may be waiting for an ACK if cwnd-bound or using TX zero
		 * copy. So we set ICSK_ACK_PUSHED here so that
		 * tcp_cleanup_rbuf() will send an ACK immediately if the app
		 * reads all of the data and is not ping-pong. If len > MSS
		 * then this logic does not matter (and does not hurt) because
		 * tcp_cleanup_rbuf() will always ACK immediately if the app
		 * reads data and there is more than an MSS of unACKed data.
		 */
		//如果有psh 则尽快ack
		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_PSH)
			icsk->icsk_ack.pending |= ICSK_ACK_PUSHED;
	} else {
		//这里应该是小包的i情况
		/* Otherwise, we make more careful check taking into account,
		 * that SACKs block is variable.
		 *
		 * "len" is invariant segment length, including TCP header.
		 */
		//加上一个tcp的头部长度
		len += skb->data - skb_transport_header(skb);
		//是否基本大于536？
		if (len >= TCP_MSS_DEFAULT + sizeof(struct tcphdr) ||
		    /* If PSH is not set, packet should be
		     * full sized, provided peer TCP is not badly broken.
		     * This observation (if it is correct 8)) allows
		     * to handle super-low mtu links fairly.
		     */
		    (len >= TCP_MIN_MSS + sizeof(struct tcphdr) &&
		     !(tcp_flag_word(tcp_hdr(skb)) & TCP_REMNANT))) {
			/* Subtract also invariant (if peer is RFC compliant),
			 * tcp header plus fixed timestamp option length.
			 * Resulting "len" is MSS free of SACK jitter.
			 */
			len -= tcp_sk(sk)->tcp_header_len;
			icsk->icsk_ack.last_seg_size = len;
			//注意：上次和这次长度一致 更新mss
			if (len == lss) {
				icsk->icsk_ack.rcv_mss = len;
				return;
			}
		}
		if (icsk->icsk_ack.pending & ICSK_ACK_PUSHED)
			icsk->icsk_ack.pending |= ICSK_ACK_PUSHED2;
		icsk->icsk_ack.pending |= ICSK_ACK_PUSHED;
	}
}

static void tcp_incr_quickack(struct sock *sk, unsigned int max_quickacks)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	//需要多少个ack可以把接收窗口填满
	unsigned int quickacks = tcp_sk(sk)->rcv_wnd / (2 * icsk->icsk_ack.rcv_mss);
	//最小是2个
	if (quickacks == 0)
		quickacks = 2;
	//钳制一下
	quickacks = min(quickacks, max_quickacks);
	//更新，这里是只增不减
	if (quickacks > icsk->icsk_ack.quick)
		icsk->icsk_ack.quick = quickacks;
}

static void tcp_enter_quickack_mode(struct sock *sk, unsigned int max_quickacks)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	tcp_incr_quickack(sk, max_quickacks);
	inet_csk_exit_pingpong_mode(sk);
	icsk->icsk_ack.ato = TCP_ATO_MIN;
}

/* Send ACKs quickly, if "quick" count is not exhausted
 * and the session is not interactive.
 */

static bool tcp_in_quickack_mode(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);

	return (dst && dst_metric(dst, RTAX_QUICKACK)) ||
		(icsk->icsk_ack.quick && !inet_csk_in_pingpong_mode(sk));
}

static void tcp_ecn_queue_cwr(struct tcp_sock *tp)
{
	if (tp->ecn_flags & TCP_ECN_OK)
		tp->ecn_flags |= TCP_ECN_QUEUE_CWR;
}

static void tcp_ecn_accept_cwr(struct sock *sk, const struct sk_buff *skb)
{
	if (tcp_hdr(skb)->cwr) {
		tcp_sk(sk)->ecn_flags &= ~TCP_ECN_DEMAND_CWR;

		/* If the sender is telling us it has entered CWR, then its
		 * cwnd may be very low (even just 1 packet), so we should ACK
		 * immediately.
		 */
		if (TCP_SKB_CB(skb)->seq != TCP_SKB_CB(skb)->end_seq)
			inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
	}
}

static void tcp_ecn_withdraw_cwr(struct tcp_sock *tp)
{
	tp->ecn_flags &= ~TCP_ECN_QUEUE_CWR;
}

static void __tcp_ecn_check_ce(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	switch (TCP_SKB_CB(skb)->ip_dsfield & INET_ECN_MASK) {
	case INET_ECN_NOT_ECT:
		/* Funny extension: if ECT is not set on a segment,
		 * and we already seen ECT on a previous segment,
		 * it is probably a retransmit.
		 */
		if (tp->ecn_flags & TCP_ECN_SEEN)
			tcp_enter_quickack_mode(sk, 2);
		break;
	case INET_ECN_CE:
		if (tcp_ca_needs_ecn(sk))
			tcp_ca_event(sk, CA_EVENT_ECN_IS_CE);

		if (!(tp->ecn_flags & TCP_ECN_DEMAND_CWR)) {
			/* Better not delay acks, sender can have a very low cwnd */
			tcp_enter_quickack_mode(sk, 2);
			tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		}
		tp->ecn_flags |= TCP_ECN_SEEN;
		break;
	default:
		if (tcp_ca_needs_ecn(sk))
			tcp_ca_event(sk, CA_EVENT_ECN_NO_CE);
		tp->ecn_flags |= TCP_ECN_SEEN;
		break;
	}
}

static void tcp_ecn_check_ce(struct sock *sk, const struct sk_buff *skb)
{
	if (tcp_sk(sk)->ecn_flags & TCP_ECN_OK)
		__tcp_ecn_check_ce(sk, skb);
}

static void tcp_ecn_rcv_synack(struct tcp_sock *tp, const struct tcphdr *th)
{
	if ((tp->ecn_flags & TCP_ECN_OK) && (!th->ece || th->cwr))
		tp->ecn_flags &= ~TCP_ECN_OK;
}

static void tcp_ecn_rcv_syn(struct tcp_sock *tp, const struct tcphdr *th)
{
	if ((tp->ecn_flags & TCP_ECN_OK) && (!th->ece || !th->cwr))
		tp->ecn_flags &= ~TCP_ECN_OK;
}

static bool tcp_ecn_rcv_ecn_echo(const struct tcp_sock *tp, const struct tcphdr *th)
{
	if (th->ece && !th->syn && (tp->ecn_flags & TCP_ECN_OK))
		return true;
	return false;
}

/* Buffer size and advertised window tuning.
 *
 * 1. Tuning sk->sk_sndbuf, when connection enters established state.
 */

static void tcp_sndbuf_expand(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct tcp_congestion_ops *ca_ops = inet_csk(sk)->icsk_ca_ops;
	int sndmem, per_mss;
	u32 nr_segs;
	//最坏的情况 不用gso 每个mss对应一个skb 且head用2的幂kmalloc
	/* Worst case is non GSO/TSO : each frame consumes one skb
	 * and skb->head is kmalloced using power of two area of memory
	 */
	per_mss = max_t(u32, tp->rx_opt.mss_clamp, tp->mss_cache) +
		  MAX_TCP_HEADER +
		  SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	per_mss = roundup_pow_of_two(per_mss) +
		  SKB_DATA_ALIGN(sizeof(struct sk_buff));
	//考虑冷启动情况
	nr_segs = max_t(u32, TCP_INIT_CWND, tcp_snd_cwnd(tp));
	//乱序
	nr_segs = max_t(u32, nr_segs, tp->reordering + 1);

	/* Fast Recovery (RFC 5681 3.2) :
	 * Cubic needs 1.7 factor, rounded to 2 to include
	 * extra cushion (application might react slowly to EPOLLOUT)
	 */
	//是否用塞算法的钩子扩大sndbuf
	sndmem = ca_ops->sndbuf_expand ? ca_ops->sndbuf_expand(sk) : 2;
	//计算一下扩容后的内存
	sndmem *= nr_segs * per_mss;
	//是否能扩容，如果能，不要超过第二个大小！！！
	if (sk->sk_sndbuf < sndmem)
		WRITE_ONCE(sk->sk_sndbuf,
			   min(sndmem, READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_wmem[2])));
}

/* 2. Tuning advertised window (window_clamp, rcv_ssthresh)
 *
 * All tcp_full_space() is split to two parts: "network" buffer, allocated
 * forward and advertised in receiver window (tp->rcv_wnd) and
 * "application buffer", required to isolate scheduling/application
 * latencies from network.
 * window_clamp is maximal advertised window. It can be less than
 * tcp_full_space(), in this case tcp_full_space() - window_clamp
 * is reserved for "application" buffer. The less window_clamp is
 * the smoother our behaviour from viewpoint of network, but the lower
 * throughput and the higher sensitivity of the connection to losses. 8)
 *
 * rcv_ssthresh is more strict window_clamp used at "slow start"
 * phase to predict further behaviour of this connection.
 * It is used for two goals:
 * - to enforce header prediction at sender, even when application
 *   requires some significant "application buffer". It is check #1.
 * - to prevent pruning of receive queue because of misprediction
 *   of receiver window. Check #2.
 *
 * The scheme does not work when sender sends good segments opening
 * window and then starts to feed us spaghetti. But it should work
 * in common situations. Otherwise, we have to rely on queue collapsing.
 */

/* Slow part of check#2. */
//用“折半试探”的方式判断：在当前窗口水平下，这种 skb 的内存成本是否足够划算；
// 如果划算就让 rcv_ssthresh 增长一个小步（2*MSS），否则随着窗口越大越保守，最终停止增长。
static int __tcp_grow_window(const struct sock *sk, const struct sk_buff *skb,
			     unsigned int skbtruesize)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	/* Optimize this! */
	int truesize = tcp_win_from_space(sk, skbtruesize) >> 1;

	int window = tcp_win_from_space(sk, READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_rmem[2])) >> 1;

	while (tp->rcv_ssthresh <= window) {
		//这个目的是什么呢???
		if (truesize <= skb->len)
			return 2 * inet_csk(sk)->icsk_ack.rcv_mss;

		truesize >>= 1;
		window >>= 1;
	}
	return 0;
}

/* Even if skb appears to have a bad len/truesize ratio, TCP coalescing
 * can play nice with us, as sk_buff and skb->head might be either
 * freed or shared with up to MAX_SKB_FRAGS segments.
 * Only give a boost to drivers using page frag(s) to hold the frame(s),
 * and if no payload was pulled in skb->head before reaching us.
 */
//把负载给去除了！！！ 前提是么有线性部分
static u32 truesize_adjust(bool adjust, const struct sk_buff *skb)
{
	u32 truesize = skb->truesize;

	if (adjust && !skb_headlen(skb)) {
		truesize -= SKB_TRUESIZE(skb_end_offset(skb));
		/* paranoid check, some drivers might be buggy */
		if (unlikely((int)truesize < (int)skb->len))
			truesize = skb->truesize;
	}
	return truesize;
}
//rcv_ssthresh
static void tcp_grow_window(struct sock *sk, const struct sk_buff *skb,
			    bool adjust)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int room;
	//计算还有多少的剩余空间
	room = min_t(int, tp->window_clamp, tcp_space(sk)) - tp->rcv_ssthresh;

	if (room <= 0)
		return;

	/* Check #1 */
	//是否在内存压力之下
	if (!tcp_under_memory_pressure(sk)) {
		//把负载去除了
		unsigned int truesize = truesize_adjust(adjust, skb);
		int incr;

		/* Check #2. Increase window, if skb with such overhead
		 * will fit to rcvbuf in future.
		 */
		//skb的开销是否太大，如果太大按 2 个 MSS 的量往上加
		if (tcp_win_from_space(sk, truesize) <= skb->len)
			incr = 2 * tp->advmss;
		else
		//折半的方法增长窗口
			incr = __tcp_grow_window(sk, skb, truesize);
		//这个单位是字节
		if (incr) {
			incr = max_t(int, incr, 2 * skb->len);
			//这里更新了接收窗口的慢启动阈值
			tp->rcv_ssthresh += min(room, incr);
			//应该是接收窗口变大了 所以要把快速ack通知给对端？
			inet_csk(sk)->icsk_ack.quick |= 1;
		}
	} else {
		/* Under pressure:
		 * Adjust rcv_ssthresh according to reserved mem
		 */
		//正常计算rcv_ssthresh
		tcp_adjust_rcv_ssthresh(sk);
	}
}

/* 3. Try to fixup all. It is made immediately after connection enters
 *    established state.
 */
static void tcp_init_buffer_space(struct sock *sk)
{
	int tcp_app_win = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_app_win); //默认是31
	struct tcp_sock *tp = tcp_sk(sk);
	int maxwin;
	//用户是否setsockopt显示设置缓冲大小，默认是没有的
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK))
	//这里会扩大snd_buf
		tcp_sndbuf_expand(sk);

	tcp_mstamp_refresh(tp);
	tp->rcvq_space.time = tp->tcp_mstamp;
	tp->rcvq_space.seq = tp->copied_seq;
	 //这个在三次握手的中间也调用过，用于告诉对端本端窗口的大小，是根据rcv_buf计算出来的
	maxwin = tcp_full_space(sk);

	if (tp->window_clamp >= maxwin) {
		tp->window_clamp = maxwin; //限制到最大缓存 这个可以理解为真实的缓存
		//最终大概率window_clamp = maxwin
		if (tcp_app_win && maxwin > 4 * tp->advmss)
			tp->window_clamp = max(maxwin -
					       (maxwin >> tcp_app_win),
					       4 * tp->advmss);
	}

	/* Force reservation of one segment. */
	//接收窗口要让出一个mss
	if (tcp_app_win &&
	    tp->window_clamp > 2 * tp->advmss &&
	    tp->window_clamp + tp->advmss > maxwin)
		tp->window_clamp = max(2 * tp->advmss, maxwin - tp->advmss);
	//tp->rcv_ssthresh  这个值是发送synack的时候计算出来的(根据rcv_buf)
	///这个叫什么接收慢启动阈值？，就应该叫接受窗口阈值吧
	tp->rcv_ssthresh = min(tp->rcv_ssthresh, tp->window_clamp);
	tp->snd_cwnd_stamp = tcp_jiffies32;
	tp->rcvq_space.space = min3(tp->rcv_ssthresh, tp->rcv_wnd,   //预测未来的接收缓冲区状态？？
				    (u32)TCP_INIT_CWND * tp->advmss);
}

/* 4. Recalculate window clamp after socket hit its memory bounds. */
static void tcp_clamp_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct net *net = sock_net(sk);
	int rmem2;
	//退出快速ack 目的是让对端发慢点！！！
	icsk->icsk_ack.quick = 0;
	//套接字的最大接收缓存大小
	rmem2 = READ_ONCE(net->ipv4.sysctl_tcp_rmem[2]);
	//没到最大上限没改过缓冲区大小，不在内存压力之下，不超过系统全局内存
	if (sk->sk_rcvbuf < rmem2 &&
	    !(sk->sk_userlocks & SOCK_RCVBUF_LOCK) &&
	    !tcp_under_memory_pressure(sk) &&
	    sk_memory_allocated(sk) < sk_prot_mem_limits(sk, 0)) {
		//增加接收缓冲区大小
		WRITE_ONCE(sk->sk_rcvbuf,
			   min(atomic_read(&sk->sk_rmem_alloc), rmem2));
	}
	//重新设置接收端慢启动阈值
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf)
		tp->rcv_ssthresh = min(tp->window_clamp, 2U * tp->advmss);
}

/* Initialize RCV_MSS value.
 * RCV_MSS is an our guess about MSS used by the peer.
 * We haven't any direct information about the MSS.
 * It's better to underestimate the RCV_MSS rather than overestimate.
 * Overestimations make us ACKing less frequently than needed.
 * Underestimations are more easy to detect and fix by tcp_measure_rcv_mss().
 */
void tcp_initialize_rcv_mss(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int hint = min_t(unsigned int, tp->advmss, tp->mss_cache);

	hint = min(hint, tp->rcv_wnd / 2);
	hint = min(hint, TCP_MSS_DEFAULT);
	hint = max(hint, TCP_MIN_MSS);

	inet_csk(sk)->icsk_ack.rcv_mss = hint;
}
EXPORT_SYMBOL(tcp_initialize_rcv_mss);

/* Receiver "autotuning" code.
 *
 * The algorithm for RTT estimation w/o timestamps is based on
 * Dynamic Right-Sizing (DRS) by Wu Feng and Mike Fisk of LANL.
 * <https://public.lanl.gov/radiant/pubs.html#DRS>
 *
 * More detail on this code can be found at
 * <http://staff.psc.edu/jheffner/>,
 * though this reference is out of date.  A new paper
 * is pending.
 */
static void tcp_rcv_rtt_update(struct tcp_sock *tp, u32 sample, int win_dep)
{
	u32 new_sample = tp->rcv_rtt_est.rtt_us;
	long m = sample;
	//是否是第一次采样，通过肯定不是
	if (new_sample != 0) {
		/* If we sample in larger samples in the non-timestamp
		 * case, we could grossly overestimate the RTT especially
		 * with chatty applications or bulk transfer apps which
		 * are stalled on filesystem I/O.
		 *
		 * Also, since we are only going for a minimum in the
		 * non-timestamp case, we do not smooth things out
		 * else with timestamps disabled convergence takes too
		 * long.
		 */
		//这个表示有时间戳选项，因为第三个参数是0 ，新的 RTT = 87.5% 旧值 + 12.5% 新样本
		if (!win_dep) {
			m -= (new_sample >> 3);
			new_sample += m;
		} else {
		//没有时间戳选项，新的 RTT = min(旧 RTT, 新样本)
			m <<= 3;
			if (m < new_sample)
				new_sample = m;
		}
	} else {
		/* No previous measure. */
		//第一次采样，直接把传输的参数作为rtt
		new_sample = m << 3;
	}

	tp->rcv_rtt_est.rtt_us = new_sample;
}
//这里计算的rtt好像不是传统意义上的rtt，这个叫接收rtt？这里的rtt是用来我多久回应ack的？？
static inline void tcp_rcv_rtt_measure(struct tcp_sock *tp)
{
	u32 delta_us;
	//第一次计算
	if (tp->rcv_rtt_est.time == 0)
		goto new_measure;
	if (before(tp->rcv_nxt, tp->rcv_rtt_est.seq))
		return;
	//计算rtt
	delta_us = tcp_stamp_us_delta(tp->tcp_mstamp, tp->rcv_rtt_est.time);
	if (!delta_us)
		delta_us = 1;
	//这里表示不用时间戳来计算rtt
	tcp_rcv_rtt_update(tp, delta_us, 1);

new_measure:
	tp->rcv_rtt_est.seq = tp->rcv_nxt + tp->rcv_wnd;
	tp->rcv_rtt_est.time = tp->tcp_mstamp;
}

static inline void tcp_rcv_rtt_measure_ts(struct sock *sk,
					  const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//同一个样本直接返回
	if (tp->rx_opt.rcv_tsecr == tp->rcv_rtt_last_tsecr)
		return;
	tp->rcv_rtt_last_tsecr = tp->rx_opt.rcv_tsecr;
	//前提条件是两个数据包之间要差一个mss，过滤噪声？？？
	if (TCP_SKB_CB(skb)->end_seq -
	    TCP_SKB_CB(skb)->seq >= inet_csk(sk)->icsk_ack.rcv_mss) {
		//这个就是rtt
		u32 delta = tcp_time_stamp(tp) - tp->rx_opt.rcv_tsecr;
		u32 delta_us;
		//这个值是否合法
		if (likely(delta < INT_MAX / (USEC_PER_SEC / TCP_TS_HZ))) {
			if (!delta)
				delta = 1;
			delta_us = delta * (USEC_PER_SEC / TCP_TS_HZ);
			//这里第二参数是0貌似就是表示是基于时间戳计算出来的rtt
			tcp_rcv_rtt_update(tp, delta_us, 0);
		}
	}
}

/*
 * This function should be called every time data is copied to user space.
 * It calculates the appropriate TCP receive buffer space.
 */
void tcp_rcv_space_adjust(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 copied;
	int time;

	trace_tcp_rcv_space_adjust(sk);
	//刷新时间戳
	tcp_mstamp_refresh(tp);
	//间隔
	time = tcp_stamp_us_delta(tp->tcp_mstamp, tp->rcvq_space.time);
	//小于一个rtt 直接返回
	if (time < (tp->rcv_rtt_est.rtt_us >> 3) || tp->rcv_rtt_est.rtt_us == 0)
		return;

	/* Number of bytes copied to user in last RTT */
	//计算上一个rtt 读走了多少数据
	copied = tp->copied_seq - tp->rcvq_space.seq;
	//当前这个周期没有比上次读的更快，不需要变化
	if (copied <= tp->rcvq_space.space)
		goto new_measure;

	/* A bit of theory :
	 * copied = bytes received in previous RTT, our base window
	 * To cope with packet losses, we need a 2x factor
	 * To cope with slow start, and sender growing its cwin by 100 %
	 * every RTT, we need a 4x factor, because the ACK we are sending
	 * now is for the next RTT, not the current one :
	 * <prev RTT . ><current RTT .. ><next RTT .... >
	 */
	//系统参数容许调整缓冲区大小，用户没有显示修改过缓冲区大小
	if (READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_moderate_rcvbuf) &&
	    !(sk->sk_userlocks & SOCK_RCVBUF_LOCK)) {
		u64 rcvwin, grow;
		int rcvbuf;

		/* minimal window to cope with packet losses, assuming
		 * steady state. Add some cushion because of small variations.
		 */
		//先算一个比较靠谱的窗口大小
		rcvwin = ((u64)copied << 1) + 16 * tp->advmss;

		/* Accommodate for sender rate increase (eg. slow start) */
		//计算应用读取的速率是不是在上升
		grow = rcvwin * (copied - tp->rcvq_space.space);
		do_div(grow, tp->rcvq_space.space);
		rcvwin += (grow << 1);
		//换算成需要的缓存区大小，但是钳制一下
		rcvbuf = min_t(u64, tcp_space_from_win(sk, rcvwin),
			       READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_rmem[2]));
		if (rcvbuf > sk->sk_rcvbuf) {
			WRITE_ONCE(sk->sk_rcvbuf, rcvbuf);

			/* Make the window clamp follow along.  */
			//更新最大窗口的上限
			tp->window_clamp = tcp_win_from_space(sk, rcvbuf);
		}
	}
	tp->rcvq_space.space = copied;

new_measure:
	//更新下一次计算需要使用到的字段
	tp->rcvq_space.seq = tp->copied_seq;
	tp->rcvq_space.time = tp->tcp_mstamp;
}

/* There is something which you must keep in mind when you analyze the
 * behavior of the tp->ato delayed ack timeout interval.  When a
 * connection starts up, we want to ack as quickly as possible.  The
 * problem is that "good" TCP's do slow start at the beginning of data
 * transmission.  The means that until we send the first few ACK's the
 * sender will sit on his end and only queue most of his data, because
 * he can only send snd_cwnd unacked packets at any given time.  For
 * each ACK we send, he increments snd_cwnd and transmits more of his
 * queue.  -DaveM
 */
static void tcp_event_data_recv(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 now;
	//设置需要回ack标志位
	inet_csk_schedule_ack(sk);
	//接收端估计对端的mss
	tcp_measure_rcv_mss(sk, skb);
	//计算接收rtt
	tcp_rcv_rtt_measure(tp);

	now = tcp_jiffies32;
	//还没有初始化延迟ack
	if (!icsk->icsk_ack.ato) {
		/* The _first_ data packet received, initialize
		 * delayed ACK engine.
		 */
		tcp_incr_quickack(sk, TCP_MAX_QUICKACKS);
		icsk->icsk_ack.ato = TCP_ATO_MIN; //40ms
	} else {
		//当前时间减去最后一个包收上来的时间
		int m = now - icsk->icsk_ack.lrcvtime;
		//间隔很快
		if (m <= TCP_ATO_MIN / 2) {
			/* The fastest case is the first. */
			//ato变小
			icsk->icsk_ack.ato = (icsk->icsk_ack.ato >> 1) + TCP_ATO_MIN / 2;
		} else if (m < icsk->icsk_ack.ato) { //比ato还小，表示ack还是慢了
			//继续缩小
			icsk->icsk_ack.ato = (icsk->icsk_ack.ato >> 1) + m;
			//不能比rto大
			if (icsk->icsk_ack.ato > icsk->icsk_rto)
				icsk->icsk_ack.ato = icsk->icsk_rto;
		} else if (m > icsk->icsk_rto) { //太久没收到包了，重置
			/* Too long gap. Apparently sender failed to
			 * restart window, so that we send ACKs quickly.
			 */
			tcp_incr_quickack(sk, TCP_MAX_QUICKACKS);
		}
	}
	icsk->icsk_ack.lrcvtime = now;
	//ecn处理
	tcp_ecn_check_ce(sk, skb);
	//触发窗口的自动增长
	if (skb->len >= 128)
		tcp_grow_window(sk, skb, true);
}

/* Called to compute a smoothed rtt estimate. The data fed to this
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge
 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
 * piece by Van Jacobson.
 * NOTE: the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break
 * it up into three procedures. -- erics
 */
static void tcp_rtt_estimator(struct sock *sk, long mrtt_us)
{
	struct tcp_sock *tp = tcp_sk(sk);
	long m = mrtt_us; /* RTT */ //当前计算的rtt
	u32 srtt = tp->srtt_us; //平滑rtt

	/*	The following amusing code comes from Jacobson's
	 *	article in SIGCOMM '88.  Note that rtt and mdev
	 *	are scaled versions of rtt and mean deviation.
	 *	This is designed to be as fast as possible
	 *	m stands for "measurement".
	 *
	 *	On a 1990 paper the rto value is changed to:
	 *	RTO = rtt + 4 * mdev
	 *
	 * Funny. This algorithm seems to be very broken.
	 * These formulae increase RTO, when it should be decreased, increase
	 * too slowly, when it should be increased quickly, decrease too quickly
	 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
	 * does not matter how to _calculate_ it. Seems, it was trap
	 * that VJ failed to avoid. 8)
	 */
	//不是第一次测量，这里注意srtt右移3位是真正的srtt
	if (srtt != 0) {
		m -= (srtt >> 3);	/* m is now error in rtt est */
		srtt += m;		/* rtt = 7/8 rtt + 1/8 new *///这里计算了加权的值新值的权重是1/8
		//下面叫做
		if (m < 0) { //这里m经过上面计算后表示的是误差，如果小于0 表示rtt当前rtt减小了
			m = -m;		/* m is now abs(error) *///取一个绝对值
			m -= (tp->mdev_us >> 2);   /* similar update on mdev */ //误差- mdev/4 //避免rtt减少过快？会影响rto?
			/* This is similar to one of Eifel findings.
			 * Eifel blocks mdev updates when rtt decreases.
			 * This solution is a bit different: we use finer gain
			 * for mdev in this case (alpha*beta).
			 * Like Eifel it also prevents growth of rto,
			 * but also it limits too fast rto decreases,
			 * happening in pure Eifel.
			 */
			if (m > 0)//表示偏差不是太多，这里在×8
				m >>= 3;
		} else {
			m -= (tp->mdev_us >> 2);   /* similar update on mdev */
		}
		tp->mdev_us += m;		/* mdev = 3/4 mdev + 1/4 new */ //更新rtt的偏差
		if (tp->mdev_us > tp->mdev_max_us) { //如果当前波动大于历史最大的波动，则更新
			tp->mdev_max_us = tp->mdev_us;
			////只有当mdev_max_us大于rttvar_us的时候才更新，可目的是更新的更保守？
			if (tp->mdev_max_us > tp->rttvar_us) 
				tp->rttvar_us = tp->mdev_max_us;
		}
		if (after(tp->snd_una, tp->rtt_seq)) {//这里其实是una和sndnxt在比较，可以理解为是否有数据包在传输吧
			if (tp->mdev_max_us < tp->rttvar_us) //如果最大波动小于这个值的话保守的减少rtt
				tp->rttvar_us -= (tp->rttvar_us - tp->mdev_max_us) >> 2;
			tp->rtt_seq = tp->snd_nxt; //更新rtt_seq 为 snd_nxt
			tp->mdev_max_us = tcp_rto_min_us(sk);  //设置最大波动值为最小rto的时间

			tcp_bpf_rtt(sk);
		}
	} else {
		//第一次测量
		/* no previous measure. */
		srtt = m << 3;		/* take the measured time to be rtt *///左移三位为初始的srtt
		tp->mdev_us = m << 1;	/* make sure rto = 3*rtt */ //平均偏差设置为 RTT 样本的 2 倍
		tp->rttvar_us = max(tp->mdev_us, tcp_rto_min_us(sk)); //用于计算rttvar_us，计算rto会用到，确保大于最小的rto
		tp->mdev_max_us = tp->rttvar_us; //设置记录最大波动的值
		tp->rtt_seq = tp->snd_nxt; //更新rtt_seq

		tcp_bpf_rtt(sk);
	}
	//更新平滑rtt
	tp->srtt_us = max(1U, srtt);
}
//三次握手收到ack完成后会调用，tcpack中也会调用
static void tcp_update_pacing_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u64 rate;

	/* set sk_pacing_rate to 200 % of current rate (mss * cwnd / srtt) */
	rate = (u64)tp->mss_cache * ((USEC_PER_SEC / 100) << 3);

	/* current rate is (cwnd * mss) / srtt
	 * In Slow Start [1], set sk_pacing_rate to 200 % the current rate.
	 * In Congestion Avoidance phase, set it to 120 % the current rate.
	 *
	 * [1] : Normal Slow Start condition is (tp->snd_cwnd < tp->snd_ssthresh)
	 *	 If snd_cwnd >= (tp->snd_ssthresh / 2), we are approaching
	 *	 end of slow start and should slow down.
	 */
	//慢启动和拥塞避免 
	if (tcp_snd_cwnd(tp) < tp->snd_ssthresh / 2)
		rate *= READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_pacing_ss_ratio);
	else
		rate *= READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_pacing_ca_ratio);

	rate *= max(tcp_snd_cwnd(tp), tp->packets_out);
	//核心公式
	if (likely(tp->srtt_us))
		do_div(rate, tp->srtt_us);

	/* WRITE_ONCE() is needed because sch_fq fetches sk_pacing_rate
	 * without any lock. We want to make sure compiler wont store
	 * intermediate values in this location.
	 */
	 //这里可能是全F 其实就是不开启
	WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, rate,
					     sk->sk_max_pacing_rate));
}

/* Calculate rto without backoff.  This is the second half of Van Jacobson's
 * routine referred to above.
 */
static void tcp_set_rto(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	/* Old crap is replaced with new one. 8)
	 *
	 * More seriously:
	 * 1. If rtt variance happened to be less 50msec, it is hallucination.
	 *    It cannot be less due to utterly erratic ACK generation made
	 *    at least by solaris and freebsd. "Erratic ACKs" has _nothing_
	 *    to do with delayed acks, because at cwnd>2 true delack timeout
	 *    is invisible. Actually, Linux-2.4 also generates erratic
	 *    ACKs in some circumstances.
	 */
	inet_csk(sk)->icsk_rto = __tcp_set_rto(tp);

	/* 2. Fixups made earlier cannot be right.
	 *    If we do not estimate RTO correctly without them,
	 *    all the algo is pure shit and should be replaced
	 *    with correct one. It is exactly, which we pretend to do.
	 */

	/* NOTE: clamping at TCP_RTO_MIN is not required, current algo
	 * guarantees that rto is higher.
	 */
	tcp_bound_rto(sk);
}

__u32 tcp_init_cwnd(const struct tcp_sock *tp, const struct dst_entry *dst)
{
	__u32 cwnd = (dst ? dst_metric(dst, RTAX_INITCWND) : 0);

	if (!cwnd)
		cwnd = TCP_INIT_CWND;
	return min_t(__u32, cwnd, tp->snd_cwnd_clamp);
}

struct tcp_sacktag_state {
	/* Timestamps for earliest and latest never-retransmitted segment
	 * that was SACKed. RTO needs the earliest RTT to stay conservative,
	 * but congestion control should still get an accurate delay signal.
	 */
	u64	first_sackt;
	u64	last_sackt;
	u32	reord;
	u32	sack_delivered;			//sack确认的段数？
	int	flag;
	unsigned int mss_now;
	struct rate_sample *rate;
};

/* Take a notice that peer is sending D-SACKs. Skip update of data delivery
 * and spurious retransmission information if this DSACK is unlikely caused by
 * sender's action:
 * - DSACKed sequence range is larger than maximum receiver's window.
 * - Total no. of DSACKed segments exceed the total no. of retransmitted segs.
 */
static u32 tcp_dsack_seen(struct tcp_sock *tp, u32 start_seq,
			  u32 end_seq, struct tcp_sacktag_state *state)
{
	u32 seq_len, dup_segs = 1;
	//合法性检查
	if (!before(start_seq, end_seq))
		return 0;
	//计算长度
	seq_len = end_seq - start_seq;
	/* Dubious DSACK: DSACKed range greater than maximum advertised rwnd */
	//合法性检查
	if (seq_len > tp->max_window)
		return 0;
	if (seq_len > tp->mss_cache)
		dup_segs = DIV_ROUND_UP(seq_len, tp->mss_cache);
	//区分是TLP引起的重复还是真正的虚假重传
	else if (tp->tlp_high_seq && tp->tlp_high_seq == end_seq)
		state->flag |= FLAG_DSACK_TLP;
	//记录重复的段数
	tp->dsack_dups += dup_segs;
	/* Skip the DSACK if dup segs weren't retransmitted by sender */
	//合法性检查吧
	if (tp->dsack_dups > tp->total_retrans)
		return 0;
	//收到dsack
	tp->rx_opt.sack_ok |= TCP_DSACK_SEEN;
	/* We increase the RACK ordering window in rounds where we receive
	 * DSACKs that may have been due to reordering causing RACK to trigger
	 * a spurious fast recovery. Thus RACK ignores DSACKs that happen
	 * without having seen reordering, or that match TLP probes (TLP
	 * is timer-driven, not triggered by RACK).
	 */
	//如果不是tlp导致的重传，就告诉rack，这里会影响undoloss
	if (tp->reord_seen && !(state->flag & FLAG_DSACK_TLP))
		tp->rack.dsack_seen = 1;
	//标识sack块中欧给你包含dsack
	state->flag |= FLAG_DSACKING_ACK;
	/* A spurious retransmission is delivered */
	//记录重复的段数
	state->sack_delivered += dup_segs;

	return dup_segs;
}

/* It's reordering when higher sequence was delivered (i.e. sacked) before
 * some lower never-retransmitted sequence ("low_seq"). The maximum reordering
 * distance is approximated in full-mss packet distance ("reordering").
 */
//更新和检测网络包乱续 拥塞算法，sack处理，ack处理中会调用这个函数 撤销部分也会调用
//主要目的是更新reord_seen 和 reordering？
//low_seq 为待检查的最低序列号
/*`tcp_check_sack_reordering`中主要的工作就是更新乱序容忍阈值，`fack` 是当前**SACK 选择确认覆盖到的最高序号**，
通过和`low_seq`计算右侧确认点到低序号之间的距离也就是`metric`，进一步计算乱了多少个`mss`的段，如果若 `metric` **超过** 
目前的容忍阈值`tp->reordering * mss`，说明**真实乱序比我们以前估的更严重**，会提升乱序容忍阈值但不超过系统参数*/
static void tcp_check_sack_reordering(struct sock *sk, const u32 low_seq,
				      const int ts)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const u32 mss = tp->mss_cache;
	u32 fack, metric;
	//fack 为当前选择确认中最大的序列号
	fack = tcp_highest_sack_seq(tp);
	//如果待检查的序列号已经在选择确认最高的后面，则直接返回
	if (!before(low_seq, fack))
		return;
	//可能丢包的范围？
	metric = fack - low_seq;
	if ((metric > tp->reordering * mss) && mss) {
#if FASTRETRANS_DEBUG > 1
		pr_debug("Disorder%d %d %u f%u s%u rr%d\n",
			 tp->rx_opt.sack_ok, inet_csk(sk)->icsk_ca
			 _state,
			 tp->reordering,
			 0,
			 tp->sacked_out,
			 tp->undo_marker ? tp->undo_retrans : 0);
#endif
		//算一下有几个mss和默认值300取一个最小值，reordering的单位为最大乱续包的数量，会决定收到几个ack快速重传吗？
		tp->reordering = min_t(u32, (metric + mss - 1) / mss,
				       READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_max_reordering));
	}

	/* This exciting event is worth to be remembered. 8) */
	//乱续事件计数
	tp->reord_seen++;
	NET_INC_STATS(sock_net(sk),
		      ts ? LINUX_MIB_TCPTSREORDER : LINUX_MIB_TCPSACKREORDER);
}

 /* This must be called before lost_out or retrans_out are updated
  * on a new loss, because we want to know if all skbs previously
  * known to be lost have already been retransmitted, indicating
  * that this newly lost skb is our next skb to retransmit.
  */
static void tcp_verify_retransmit_hint(struct tcp_sock *tp, struct sk_buff *skb)
{
	//重传数据包的指针为空同时重传的数据包数量大于丢包数量（表示所有数据包都重传过） 或者 
	//重传数据包的指针不为空且当前数据包的序号更小
	//更新重传数据包的指针
	if ((!tp->retransmit_skb_hint && tp->retrans_out >= tp->lost_out) || 
	    (tp->retransmit_skb_hint &&
	     before(TCP_SKB_CB(skb)->seq,
		    TCP_SKB_CB(tp->retransmit_skb_hint)->seq)))
		tp->retransmit_skb_hint = skb;
}

/* Sum the number of packets on the wire we have marked as lost, and
 * notify the congestion control module that the given skb was marked lost.
 */
static void tcp_notify_skb_loss_event(struct tcp_sock *tp, const struct sk_buff *skb)
{
	tp->lost += tcp_skb_pcount(skb);
}
//标记skb为丢失，并且更新相关字段 enterloss中会调用，tcp超时重传中会调用，rack中会调用
void tcp_mark_skb_lost(struct sock *sk, struct sk_buff *skb)
{
	//拿到sack的标志位
	__u8 sacked = TCP_SKB_CB(skb)->sacked;
	struct tcp_sock *tp = tcp_sk(sk);
	//如果数据包已经被确认了，直接返回不用标记丢失
	if (sacked & TCPCB_SACKED_ACKED)
		return;

	tcp_verify_retransmit_hint(tp, skb);
	//这个包已经丢过一次了
	if (sacked & TCPCB_LOST) {
		//是否重传过一次了
		if (sacked & TCPCB_SACKED_RETRANS) {
			/* Account for retransmits that are lost again */
			//需要重新重传了，清除掉重传标志
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
			//减少重重的统计激素
			tp->retrans_out -= tcp_skb_pcount(skb);
			//增加统计计数 这个表示重传后又丢包的数量
			NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPLOSTRETRANSMIT,
				      tcp_skb_pcount(skb));
			//更新历史丢包总数
			tcp_notify_skb_loss_event(tp, skb);
		}
	} else {
		//增加 当前待重传的丢包数
		tp->lost_out += tcp_skb_pcount(skb);
		//设置丢包标志
		TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
		//更新历史丢包总数
		tcp_notify_skb_loss_event(tp, skb);
	}
}

/* Updates the delivered and delivered_ce counts */
static void tcp_count_delivered(struct tcp_sock *tp, u32 delivered,
				bool ece_ack)
{
	tp->delivered += delivered;
	if (ece_ack)
		tp->delivered_ce += delivered;
}

/* This procedure tags the retransmission queue when SACKs arrive.
 *
 * We have three tag bits: SACKED(S), RETRANS(R) and LOST(L).
 * Packets in queue with these bits set are counted in variables
 * sacked_out, retrans_out and lost_out, correspondingly.
 *
 * Valid combinations are:
 * Tag  InFlight	Description
 * 0	1		- orig segment is in flight.
 * S	0		- nothing flies, orig reached receiver.
 * L	0		- nothing flies, orig lost by net.
 * R	2		- both orig and retransmit are in flight.
 * L|R	1		- orig is lost, retransmit is in flight.
 * S|R  1		- orig reached receiver, retrans is still in flight.
 * (L|S|R is logically valid, it could occur when L|R is sacked,
 *  but it is equivalent to plain S and code short-curcuits it to S.
 *  L|S is logically invalid, it would mean -1 packet in flight 8))
 *
 * These 6 states form finite state machine, controlled by the following events:
 * 1. New ACK (+SACK) arrives. (tcp_sacktag_write_queue())
 * 2. Retransmission. (tcp_retransmit_skb(), tcp_xmit_retransmit_queue())
 * 3. Loss detection event of two flavors:
 *	A. Scoreboard estimator decided the packet is lost.
 *	   A'. Reno "three dupacks" marks head of queue lost.
 *	B. SACK arrives sacking SND.NXT at the moment, when the
 *	   segment was retransmitted.
 * 4. D-SACK added new rule: D-SACK changes any tag to S.
 *
 * It is pleasant to note, that state diagram turns out to be commutative,
 * so that we are allowed not to be bothered by order of our actions,
 * when multiple events arrive simultaneously. (see the function below).
 *
 * Reordering detection.
 * --------------------
 * Reordering metric is maximal distance, which a packet can be displaced
 * in packet stream. With SACKs we can estimate it:
 *
 * 1. SACK fills old hole and the corresponding segment was not
 *    ever retransmitted -> reordering. Alas, we cannot use it
 *    when segment was retransmitted.
 * 2. The last flaw is solved with D-SACK. D-SACK arrives
 *    for retransmitted and already SACKed segment -> reordering..
 * Both of these heuristics are not used in Loss state, when we cannot
 * account for retransmits accurately.
 *
 * SACK block validation.
 * ----------------------
 *
 * SACK block range validation checks that the received SACK block fits to
 * the expected sequence limits, i.e., it is between SND.UNA and SND.NXT.
 * Note that SND.UNA is not included to the range though being valid because
 * it means that the receiver is rather inconsistent with itself reporting
 * SACK reneging when it should advance SND.UNA. Such SACK block this is
 * perfectly valid, however, in light of RFC2018 which explicitly states
 * that "SACK block MUST reflect the newest segment.  Even if the newest
 * segment is going to be discarded ...", not that it looks very clever
 * in case of head skb. Due to potentional receiver driven attacks, we
 * choose to avoid immediate execution of a walk in write queue due to
 * reneging and defer head skb's loss recovery to standard loss recovery
 * procedure that will eventually trigger (nothing forbids us doing this).
 *
 * Implements also blockage to start_seq wrap-around. Problem lies in the
 * fact that though start_seq (s) is before end_seq (i.e., not reversed),
 * there's no guarantee that it will be before snd_nxt (n). The problem
 * happens when start_seq resides between end_seq wrap (e_w) and snd_nxt
 * wrap (s_w):
 *
 *         <- outs wnd ->                          <- wrapzone ->
 *         u     e      n                         u_w   e_w  s n_w
 *         |     |      |                          |     |   |  |
 * |<------------+------+----- TCP seqno space --------------+---------->|
 * ...-- <2^31 ->|                                           |<--------...
 * ...---- >2^31 ------>|                                    |<--------...
 *
 * Current code wouldn't be vulnerable but it's better still to discard such
 * crazy SACK blocks. Doing this check for start_seq alone closes somewhat
 * similar case (end_seq after snd_nxt wrap) as earlier reversed check in
 * snd_nxt wrap -> snd_una region will then become "well defined", i.e.,
 * equal to the ideal case (infinite seqno space without wrap caused issues).
 *
 * With D-SACK the lower bound is extended to cover sequence space below
 * SND.UNA down to undo_marker, which is the last point of interest. Yet
 * again, D-SACK block must not to go across snd_una (for the same reason as
 * for the normal SACK blocks, explained above). But there all simplicity
 * ends, TCP might receive valid D-SACKs below that. As long as they reside
 * fully below undo_marker they do not affect behavior in anyway and can
 * therefore be safely ignored. In rare cases (which are more or less
 * theoretical ones), the D-SACK will nicely cross that boundary due to skb
 * fragmentation and packet reordering past skb's retransmission. To consider
 * them correctly, the acceptable range must be extended even more though
 * the exact amount is rather hard to quantify. However, tp->max_window can
 * be used as an exaggerated estimate.
 */
//返回 true/false：这个 SACK block 对当前连接来说是不是“合理的、值得处理的”
static bool tcp_is_sackblock_valid(struct tcp_sock *tp, bool is_dsack,
				   u32 start_seq, u32 end_seq)
{
	/* Too far in future, or reversed (interpretation is ambiguous) */
	//明显非法
	if (after(end_seq, tp->snd_nxt) || !before(start_seq, end_seq))
		return false;

	/* Nasty start_seq wrap-around check (see comments above) */
	//明显非法
	if (!before(start_seq, tp->snd_nxt))
		return false;

	/* In outstanding window? ...This is valid exit for D-SACKs too.
	 * start_seq == snd_una is non-sensical (see comments above)
	 */
	//正常 SACK 的合法范围
	if (after(start_seq, tp->snd_una))
		return true;
	//这种情况就应直接判非法，但是dsack需要进一步考虑
	if (!is_dsack || !tp->undo_marker)
		return false;

	/* ...Then it's D-SACK, and must reside below snd_una completely */
	//endseq不合法
	if (after(end_seq, tp->snd_una))
		return false;
	//这个块在undo_marker右边 反悔true
	if (!before(start_seq, tp->undo_marker))
		return true;

	/* Too old */
	//太老
	if (!after(end_seq, tp->undo_marker))
		return false;

	/* Undo_marker boundary crossing (overestimates a lot). Known already:
	 *   start_seq < undo_marker and end_seq >= undo_marker.
	 */
	//start和end跨度不是太大
	return !before(start_seq, end_seq - tp->max_window);
}
//检查dsack 好像rfc的规范是dsack的信息就在前两个块中
static bool tcp_check_dsack(struct sock *sk, const struct sk_buff *ack_skb,
			    struct tcp_sack_block_wire *sp, int num_sacks,
			    u32 prior_snd_una, struct tcp_sacktag_state *state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 start_seq_0 = get_unaligned_be32(&sp[0].start_seq);//起始序列号
	u32 end_seq_0 = get_unaligned_be32(&sp[0].end_seq);    //结束序列号
	u32 dup_segs;
	//第一个SACK块在ACK序号之前，标准的dsack
	if (before(start_seq_0, TCP_SKB_CB(ack_skb)->ack_seq)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPDSACKRECV);
	} else if (num_sacks > 1) {
	//是否存在重叠
		u32 end_seq_1 = get_unaligned_be32(&sp[1].end_seq);
		u32 start_seq_1 = get_unaligned_be32(&sp[1].start_seq);

		if (after(end_seq_0, end_seq_1) || before(start_seq_0, start_seq_1))
			return false;
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPDSACKOFORECV);
	} else {
		return false;
	}
	//走到这里表示一定发生了重复sack，基于mss计算重复的段数
	dup_segs = tcp_dsack_seen(tp, start_seq_0, end_seq_0, state);
	if (!dup_segs) {	/* Skip dubious DSACK */
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPDSACKIGNOREDDUBIOUS);
		return false;
	}

	NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPDSACKRECVSEGS, dup_segs);

	/* D-SACK for already forgotten data... Do dumb counting. */
	if (tp->undo_marker && tp->undo_retrans > 0 &&						//需要undo，且重传过了
	    !after(end_seq_0, prior_snd_una) &&					//dsack的数据是 una之前的数据 
	    after(end_seq_0, tp->undo_marker))					//dsack的数据是 una之前的数据 
		tp->undo_retrans = max_t(int, 0, tp->undo_retrans - dup_segs);	//修正计数

	return true;
}

/* Check if skb is fully within the SACK block. In presence of GSO skbs,
 * the incoming SACK may not exactly match but we can find smaller MSS
 * aligned portion of it that matches. Therefore we might need to fragment
 * which may fail and creates some hassle (caller must handle error case
 * returns).
 *
 * FIXME: this could be merged to shift decision code
 */
//不带 GSO：只做范围比较 → 返回 0/1。
// 带 GSO：如果不刚好对齐 尝试 tcp_fragment
static int tcp_match_skb_to_sack(struct sock *sk, struct sk_buff *skb,
				  u32 start_seq, u32 end_seq)
{
	int err;
	bool in_sack;
	unsigned int pkt_len;
	unsigned int mss;
	//skb 完全被 SACK 覆盖
	in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq) &&
		  !before(end_seq, TCP_SKB_CB(skb)->end_seq);
	// GSO && 部分的情况
	if (tcp_skb_pcount(skb) > 1 && !in_sack &&
	////部分重叠数据包的结束序列号小于块的起始序列号
	    after(TCP_SKB_CB(skb)->end_seq, start_seq)) { 
		mss = tcp_skb_mss(skb);
		in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq); 
		//SACK start在 skb 里面
		if (!in_sack) {
			pkt_len = start_seq - TCP_SKB_CB(skb)->seq;
			if (pkt_len < mss)
				pkt_len = mss;//对齐mss
		//SACK start <= skb 起点
		} else {
			pkt_len = end_seq - TCP_SKB_CB(skb)->seq;
			if (pkt_len < mss)
				return -EINVAL;
		}

		/* Round if necessary so that SACKs cover only full MSSes
		 * and/or the remaining small portion (if present)
		 */
		if (pkt_len > mss) {
			unsigned int new_len = (pkt_len / mss) * mss;
			if (!in_sack && new_len < pkt_len)
				new_len += mss;
			pkt_len = new_len; //对齐成 N * MSS
		}

		if (pkt_len >= skb->len && !in_sack)
			return 0;
		//切分数据包，这里很关键这次返回0 下次应该就不会了
		err = tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb,
				   pkt_len, mss, GFP_ATOMIC);
		if (err < 0)
			return err;
	}

	return in_sack;
}

/* Mark the given newly-SACKed range as such, adjusting counters and hints. */
static u8 tcp_sacktag_one(struct sock *sk,
			  struct tcp_sacktag_state *state, u8 sacked,
			  u32 start_seq, u32 end_seq,
			  int dup_sack, int pcount,
			  u64 xmit_time)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Account D-SACK for retransmitted packet. */
	//如果是dsack且是重传包
	if (dup_sack && (sacked & TCPCB_RETRANS)) {
		if (tp->undo_marker && tp->undo_retrans > 0 && 					//存在重传
		    after(end_seq, tp->undo_marker))
			tp->undo_retrans = max_t(int, 0, tp->undo_retrans - pcount);//更新未确认重传包的数量
		if ((sacked & TCPCB_SACKED_ACKED) && 
		    before(start_seq, state->reord))
				state->reord = start_seq; //跟踪最早的重排序边界
	}

	/* Nothing to do; acked frame is about to be dropped (was ACKed). */
	//如果要标记范围已经被确认了
	if (!after(end_seq, tp->snd_una))
		return sacked;
	//这个数据包没有被sack过的情况，如果是tcp_shifted_skb调进来，大概率进入这个分支吧，注意这个sacked是移动之前的skb所以大概率进入？
	if (!(sacked & TCPCB_SACKED_ACKED)) { //
		//这里很关键，应该叫真正启动rack吧
		tcp_rack_advance(tp, sacked, end_seq, xmit_time);
		//这段数据曾经被重传过
		if (sacked & TCPCB_SACKED_RETRANS) {//
			/* If the segment is not tagged as lost,
			 * we do not clear RETRANS, believing
			 * that retransmission is still in flight.
			 */
			//同时还有LOST标记
			if (sacked & TCPCB_LOST) {
				sacked &= ~(TCPCB_LOST|TCPCB_SACKED_RETRANS);//清掉标志位
				tp->lost_out -= pcount; 
				tp->retrans_out -= pcount;
			}
		} else {//之前没有重传过新的sack，这是最常见的场景吧？
			if (!(sacked & TCPCB_RETRANS)) {
				/* New sack for not retransmitted frame,
				 * which was in hole. It is reordering.
				 */
				//这种情况就表示乱序
				if (before(start_seq,
					   tcp_highest_sack_seq(tp)) &&
				    before(start_seq, state->reord))
					state->reord = start_seq; //更新乱序边界
				//SACK 的 end_seq 不超过 high_seq，是原始发送窗口里的数据
				if (!after(end_seq, tp->high_seq))
					state->flag |= FLAG_ORIG_SACK_ACKED;
				if (state->first_sackt == 0)
					state->first_sackt = xmit_time;
				state->last_sackt = xmit_time;
			}
			//如果之前带 LOST 撤销 LOSS
			if (sacked & TCPCB_LOST) {
				sacked &= ~TCPCB_LOST;
				tp->lost_out -= pcount;
			}
		}
		//真正标记为 SACKED_ACKED
		sacked |= TCPCB_SACKED_ACKED;
		state->flag |= FLAG_DATA_SACKED;
		tp->sacked_out += pcount;
		/* Out-of-order packets delivered */
		state->sack_delivered += pcount;
		//修正 lost_skb_hint 对应的 hint 计数
		/* Lost marker hint past SACKed? Tweak RFC3517 cnt */
		if (tp->lost_skb_hint &&
		    before(start_seq, TCP_SKB_CB(tp->lost_skb_hint)->seq))
			tp->lost_cnt_hint += pcount;
	}

	/* D-SACK. We can detect redundant retransmission in S|R and plain R
	 * frames and clear it. undo_retrans is decreased above, L|R frames
	 * are accounted above as well.
	 */
	if (dup_sack && (sacked & TCPCB_SACKED_RETRANS)) {
		sacked &= ~TCPCB_SACKED_RETRANS;
		tp->retrans_out -= pcount;
	}

	return sacked;
}

/* Shift newly-SACKed bytes from this skb to the immediately previous
 * already-SACKed sk_buff. Mark the newly-SACKed bytes as such.
 */
static bool tcp_shifted_skb(struct sock *sk, struct sk_buff *prev,
			    struct sk_buff *skb,
			    struct tcp_sacktag_state *state,
			    unsigned int pcount, int shifted, int mss,
			    bool dup_sack)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//这里计算的start和end是前面移动的范围
	u32 start_seq = TCP_SKB_CB(skb)->seq;	/* start of newly-SACKed */
	u32 end_seq = start_seq + shifted;	/* end of newly-SACKed */

	BUG_ON(!pcount);

	/* Adjust counters and hints for the newly sacked sequence
	 * range but discard the return value since prev is already
	 * marked. We must tag the range first because the seq
	 * advancement below implicitly advances
	 * tcp_highest_sack_seq() when skb is highest_sack.
	 */
	//注意这里丢弃了返回值，调用这个函数的地方是skb的数据一部分已经移动到prev了 切记！
	//感觉这丢弃返回值原因是就想修正一下计数
	tcp_sacktag_one(sk, state, TCP_SKB_CB(skb)->sacked,
			start_seq, end_seq, dup_sack, pcount,
			tcp_skb_timestamp_us(skb));
	//更新采样字段，拥塞算法可能会用到
	tcp_rate_skb_delivered(sk, skb, state->rate);
	//入如果是丢失的第一个包 修正lost_cnt_hint
	if (skb == tp->lost_skb_hint)
		tp->lost_cnt_hint += pcount;
	//注意这里修改了 挪到prev后的序列号
	TCP_SKB_CB(prev)->end_seq += shifted;
	TCP_SKB_CB(skb)->seq += shifted;
	//更新段数
	tcp_skb_pcount_add(prev, pcount);
	WARN_ON_ONCE(tcp_skb_pcount(skb) < pcount);
	tcp_skb_pcount_add(skb, -pcount);

	/* When we're adding to gso_segs == 1, gso_size will be zero,
	 * in theory this shouldn't be necessary but as long as DSACK
	 * code can come after this skb later on it's better to keep
	 * setting gso_size to something.
	 */
	if (!TCP_SKB_CB(prev)->tcp_gso_size)
		TCP_SKB_CB(prev)->tcp_gso_size = mss;

	/* CHECKME: To clear or not to clear? Mimics normal skb currently */
	if (tcp_skb_pcount(skb) <= 1)
		TCP_SKB_CB(skb)->tcp_gso_size = 0;

	/* Difference in this won't matter, both ACKed by the same cumul. ACK */
	TCP_SKB_CB(prev)->sacked |= (TCP_SKB_CB(skb)->sacked & TCPCB_EVER_RETRANS);
	//这里很关键，决定了外面 tcp_shift_skb_data 是否能继续合并！！！
	if (skb->len > 0) {
		BUG_ON(!tcp_skb_pcount(skb));
		NET_INC_STATS(sock_net(sk), LINUX_MIB_SACKSHIFTED);
		return false;
	}

	/* Whole SKB was eaten :-) */
	//这里当前的数据包都被eaten了  继续修正重传用到的字段
	if (skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = prev;
	if (skb == tp->lost_skb_hint) {
		tp->lost_skb_hint = prev;
		tp->lost_cnt_hint -= tcp_skb_pcount(prev);
	}
	//合并标志位
	TCP_SKB_CB(prev)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(prev)->eor = TCP_SKB_CB(skb)->eor;
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		TCP_SKB_CB(prev)->end_seq++;
	//更新最高 SACK 指针
	if (skb == tcp_highest_sack(sk))
		tcp_advance_highest_sack(sk, skb);
	//处理时间戳
	tcp_skb_collapse_tstamp(prev, skb);
	if (unlikely(TCP_SKB_CB(prev)->tx.delivered_mstamp))
		TCP_SKB_CB(prev)->tx.delivered_mstamp = 0;
	//从重传队列删除并释放这个 skb
	tcp_rtx_queue_unlink_and_free(skb, sk);

	NET_INC_STATS(sock_net(sk), LINUX_MIB_SACKMERGED);

	return true;
}

/* I wish gso_size would have a bit more sane initialization than
 * something-or-zero which complicates things
 */
static int tcp_skb_seglen(const struct sk_buff *skb)
{
	return tcp_skb_pcount(skb) == 1 ? skb->len : tcp_skb_mss(skb);
}

/* Shifting pages past head area doesn't work */
//只有分页数据，没有线性头部数据
static int skb_can_shift(const struct sk_buff *skb)
{
	return !skb_headlen(skb) && skb_is_nonlinear(skb);
}
//SKB是否可合并
int tcp_skb_shift(struct sk_buff *to, struct sk_buff *from,
		  int pcount, int shiftlen)
{
	/* TCP min gso_size is 8 bytes (TCP_MIN_GSO_SIZE)
	 * Since TCP_SKB_CB(skb)->tcp_gso_segs is 16 bits, we need
	 * to make sure not storing more than 65535 * 8 bytes per skb,
	 * even if current MSS is bigger.
	 */
	if (unlikely(to->len + shiftlen >= 65535 * TCP_MIN_GSO_SIZE))
		return 0;
	if (unlikely(tcp_skb_pcount(to) + pcount > 65535))
		return 0;
	return skb_shift(to, from, shiftlen);
}

/* Try collapsing SACK blocks spanning across multiple skbs to a single
 * skb.
 */
//核心就是把skb往前一个挪动 前提是前一个skb必须是sack的,这不是必须的 这是优化策略
// 前
// prev: [#### SACK ####]
// skb : [++++++SACK++++][----未SACK----]
// next: [#### SACK ####]
// 后
// prev: [#### SACK ####][++++++SACK++++]
// skb : [----未SACK----]
// next: [#### SACK ####]

//另外就是努力去填hole吧
static struct sk_buff *tcp_shift_skb_data(struct sock *sk, struct sk_buff *skb,
					  struct tcp_sacktag_state *state,
					  u32 start_seq, u32 end_seq,
					  bool dup_sack)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *prev;
	int mss;
	int pcount = 0;
	int len;
	int in_sack;

	/* Normally R but no L won't result in plain S */
	//如果数据包仅被标记为重传或者丢失则不处理只有 重传标记而没有丢失标记时，不太可能转成普通 SACK状态
	if (!dup_sack &&
	    (TCP_SKB_CB(skb)->sacked & (TCPCB_LOST|TCPCB_SACKED_RETRANS)) == TCPCB_SACKED_RETRANS)
		goto fallback;
	//SKB是否可合并
	if (!skb_can_shift(skb))
		goto fallback;
	/* This frame is about to be dropped (was ACKed). */
	//已经确认过不处理
	if (!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
		goto fallback;

	/* Can only happen with delayed DSACK + discard craziness */
	//获取前一个skb
	prev = skb_rb_prev(skb);
	if (!prev)
		goto fallback;
	//!!!!!!!!!!!!!前一个SKB必须且只能被标记为SACKED_ACKED!!!!!
	if ((TCP_SKB_CB(prev)->sacked & TCPCB_TAGBITS) != TCPCB_SACKED_ACKED)
		goto fallback;
	//大概率通过
	if (!tcp_skb_can_collapse(prev, skb))
		goto fallback;
	//当前skb是否完全被sack块cover住了
	in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq) &&
		  !before(end_seq, TCP_SKB_CB(skb)->end_seq);
	//完全cover住的情况
	if (in_sack) {
		len = skb->len; 				//记录数据包长度
		pcount = tcp_skb_pcount(skb);   //计算段数
		mss = tcp_skb_seglen(skb);		//计算mss

		/* TODO: Fix DSACKs to not fragment already SACKed and we can
		 * drop this restriction as unnecessary
		 */
		if (mss != tcp_skb_seglen(prev)) //两个mss不同，不处理
			goto fallback;
	} else { //检查SKB是否完全在SACK之前
		if (!after(TCP_SKB_CB(skb)->end_seq, start_seq))
			goto noop;
		/* CHECKME: This is non-MSS split case only?, this will
		 * cause skipped skbs due to advancing loop btw, original
		 * has that feature too
		 */
		//是否可以分割
		if (tcp_skb_pcount(skb) <= 1)
			goto noop;
		//SACK 的 start 在 skb 起始序号的左边或相等
		in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq);
		if (!in_sack) {
			/* TODO: head merge to next could be attempted here
			 * if (!after(TCP_SKB_CB(skb)->end_seq, end_seq)),
			 * though it might not be worth of the additional hassle
			 *
			 * ...we can probably just fallback to what was done
			 * previously. We could try merging non-SACKed ones
			 * as well but it probably isn't going to buy off
			 * because later SACKs might again split them, and
			 * it would make skb timestamp tracking considerably
			 * harder problem.
			 */
			goto fallback;
		}
		//左侧或者完全cover住的情况 重叠长度 = SACK结束序列号 - SKB起始序列号
		len = end_seq - TCP_SKB_CB(skb)->seq;
		BUG_ON(len < 0);
		BUG_ON(len > skb->len);

		/* MSS boundaries should be honoured or else pcount will
		 * severely break even though it makes things bit trickier.
		 * Optimize common case to avoid most of the divides
		 */
		//计算mss
		mss = tcp_skb_mss(skb);

		/* TODO: Fix DSACKs to not fragment already SACKed and we can
		 * drop this restriction as unnecessary
		 */
		//MSS对齐 前面几个段必须mss
		if (mss != tcp_skb_seglen(prev))
			goto fallback;

		if (len == mss) {
			pcount = 1;
		} else if (len < mss) {
			goto noop;
		} else {
			pcount = len / mss;
			len = pcount * mss;
		}
	}

	/* tcp_sacktag_one() won't SACK-tag ranges below snd_una */
	// 检查合并部分是否已完全确认
	if (!after(TCP_SKB_CB(skb)->seq + len, tp->snd_una))
		goto fallback;
	//将数据从skb移动到prev
	if (!tcp_skb_shift(prev, skb, pcount, len))
		goto fallback;
	//如果上面合并成功了，这更新数据包的字段，返回false表示数据包合并了一部分！ 就不会走下面的逻辑了
	if (!tcp_shifted_skb(sk, prev, skb, state, pcount, len, mss, dup_sack))
		goto out;

	/* Hole filled allows collapsing with the next as well, this is very
	 * useful when hole on every nth skb pattern happens
	 */
	//看看后面的skb是否可以合并
	skb = skb_rb_next(prev);
	if (!skb)
		goto out;

	if (!skb_can_shift(skb) ||												//缓冲区不符合要求
	    ((TCP_SKB_CB(skb)->sacked & TCPCB_TAGBITS) != TCPCB_SACKED_ACKED) || //不是纯 SACKED_ACKED！！ 其实是把hole给填上
	    (mss != tcp_skb_seglen(skb)))										//mss不一致
		goto out;

	if (!tcp_skb_can_collapse(prev, skb))
		goto out;
	len = skb->len;
	pcount = tcp_skb_pcount(skb);
	//和上面一样
	if (tcp_skb_shift(prev, skb, pcount, len))
		tcp_shifted_skb(sk, prev, skb, state, pcount,
				len, mss, 0);

out:
	return prev;

noop:
	return skb;

fallback:
	NET_INC_STATS(sock_net(sk), LINUX_MIB_SACKSHIFTFALLBACK);
	return NULL;
}
//从给定的 skb 开始，沿着 TCP 发送队列（有序 rb-tree）遍历序列号在 [start_seq, end_seq) 的所有 skb
//这个函数本质上才是sack的核心逻辑
static struct sk_buff *tcp_sacktag_walk(struct sk_buff *skb, struct sock *sk,
					struct tcp_sack_block *next_dup,
					struct tcp_sacktag_state *state,
					u32 start_seq, u32 end_seq,
					bool dup_sack_in)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *tmp;
	//遍历重传队列
	skb_rbtree_walk_from(skb) {
		int in_sack = 0; 			 //标识skb是否被某个sack覆盖
		bool dup_sack = dup_sack_in; //这个块是否dsack语义

		/* queue is in-order => we can short-circuit the walk early */
		//这里开始后面的 skb 都不在 [start_seq, end_seq) 内  可以直接break
		if (!before(TCP_SKB_CB(skb)->seq, end_seq))
			break;
		//第一个条件是 考虑dsack的情况（两块组合编码） && 当前 skb 起始序列号 < DSACK块末尾序号 注意这里传入的的start和end是可能是dup的
		if (next_dup  &&
		    before(TCP_SKB_CB(skb)->seq, next_dup->end_seq)) { 
			//判断当前 skb 是否被 DSACK block 完整或部分覆盖,这里注意，里面会拆分数据包，如果dsack start在skb序号的右侧这里返回的是0
			in_sack = tcp_match_skb_to_sack(sk, skb,
							next_dup->start_seq,
							next_dup->end_seq);
			if (in_sack > 0)
				dup_sack = true;
		}

		/* skb reference here is a bit tricky to get right, since
		 * shifting can eat and free both this skb and the next,
		 * so not even _safe variant of the loop is enough.
		 */
		//不是dsack 或者上面dsack start在skb序号的右侧？
		if (in_sack <= 0) {
			//优化队列结构，本质思想是合成一个大块，返回空表示无法合并
			tmp = tcp_shift_skb_data(sk, skb, state,
						 start_seq, end_seq, dup_sack);
			if (tmp) {
				if (tmp != skb) {
					skb = tmp;
					continue;
				}

				in_sack = 0;
			} else {
				//上面没有合并成功的情况，这里面是拆分数据包，如果这里返回0 表示没有命中sack这也是有可能的因为
				in_sack = tcp_match_skb_to_sack(sk, skb,
								start_seq,
								end_seq);
			}
		}

		if (unlikely(in_sack < 0))
			break;
		//真正的标记数据包，肯定是in_sack才能标记，注意这里接收了返回值
		if (in_sack) {
			TCP_SKB_CB(skb)->sacked =
				tcp_sacktag_one(sk,
						state,
						TCP_SKB_CB(skb)->sacked,
						TCP_SKB_CB(skb)->seq,
						TCP_SKB_CB(skb)->end_seq,
						dup_sack,
						tcp_skb_pcount(skb),
						tcp_skb_timestamp_us(skb));
			//更新拥塞算法用到的字段
			tcp_rate_skb_delivered(sk, skb, state->rate);
			if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
				list_del_init(&skb->tcp_tsorted_anchor);

			if (!before(TCP_SKB_CB(skb)->seq,
				    tcp_highest_sack_seq(tp)))
				//如果需要，更新最高的sack对应的数据包
				tcp_advance_highest_sack(sk, skb);
		}
	}
	//这个数据包貌似已经是不再 sack范围的数据包了
	return skb;
}

static struct sk_buff *tcp_sacktag_bsearch(struct sock *sk, u32 seq)
{
	struct rb_node *parent, **p = &sk->tcp_rtx_queue.rb_node;
	struct sk_buff *skb;

	while (*p) {
		parent = *p;
		skb = rb_to_skb(parent);
		if (before(seq, TCP_SKB_CB(skb)->seq)) {
			p = &parent->rb_left;
			continue;
		}
		if (!before(seq, TCP_SKB_CB(skb)->end_seq)) {
			p = &parent->rb_right;
			continue;
		}
		return skb;
	}
	return NULL;
}

static struct sk_buff *tcp_sacktag_skip(struct sk_buff *skb, struct sock *sk,
					u32 skip_to_seq)
{
	if (skb && after(TCP_SKB_CB(skb)->seq, skip_to_seq))
		return skb;

	return tcp_sacktag_bsearch(sk, skip_to_seq);
}

static struct sk_buff *tcp_maybe_skipping_dsack(struct sk_buff *skb,
						struct sock *sk,
						struct tcp_sack_block *next_dup,
						struct tcp_sacktag_state *state,
						u32 skip_to_seq)
{
	if (!next_dup)
		return skb;

	if (before(next_dup->start_seq, skip_to_seq)) {
		skb = tcp_sacktag_skip(skb, sk, next_dup->start_seq);
		skb = tcp_sacktag_walk(skb, sk, NULL, state,
				       next_dup->start_seq, next_dup->end_seq,
				       1);
	}

	return skb;
}

static int tcp_sack_cache_ok(const struct tcp_sock *tp, const struct tcp_sack_block *cache)
{
	return cache < tp->recv_sack_cache + ARRAY_SIZE(tp->recv_sack_cache);
}

static int
tcp_sacktag_write_queue(struct sock *sk, const struct sk_buff *ack_skb,
			u32 prior_snd_una, struct tcp_sacktag_state *state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//从TCP选项头中提取SACK信息
	const unsigned char *ptr = (skb_transport_header(ack_skb) +
				    TCP_SKB_CB(ack_skb)->sacked);
	//跳过SACK选项类型和长度字段
	struct tcp_sack_block_wire *sp_wire = (struct tcp_sack_block_wire *)(ptr+2);
	struct tcp_sack_block sp[TCP_NUM_SACKS];
	struct tcp_sack_block *cache;
	struct sk_buff *skb;
	//计算SACK块数量
	int num_sacks = min(TCP_NUM_SACKS, (ptr[1] - TCPOLEN_SACK_BASE) >> 3);
	int used_sacks;
	bool found_dup_sack = false;
	int i, j;
	int first_sack_index;

	state->flag = 0;
	state->reord = tp->snd_nxt; //置重排序检测的基准为下一个发送序号

	if (!tp->sacked_out)
		tcp_highest_sack_reset(sk);
	//检查是否有重复的SACK
	found_dup_sack = tcp_check_dsack(sk, ack_skb, sp_wire,
					 num_sacks, prior_snd_una, state);

	/* Eliminate too old ACKs, but take into
	 * account more or less fresh ones, they can
	 * contain valid SACK info.
	 */
	//丢弃太旧的ACK
	if (before(TCP_SKB_CB(ack_skb)->ack_seq, prior_snd_una - tp->max_window))
		return 0;
	//数据都被确认了
	if (!tp->packets_out)
		goto out;

	used_sacks = 0;
	first_sack_index = 0;
	//从 ACK 中提取所有 SACK block，对每一块做合法性验证、排除无效块、排除过旧块
	//最后得到一个干净、有意义的 sp[] SACK 列表，用于后续真正标记发送队列
	for (i = 0; i < num_sacks; i++) {
		bool dup_sack = !i && found_dup_sack;   //如果 i == 0 并且这次 ACK 确实检测出 DSACK，那么第 0 个块就是 DSACK 块
		//转换网络序到本地序
		sp[used_sacks].start_seq = get_unaligned_be32(&sp_wire[i].start_seq);
		sp[used_sacks].end_seq = get_unaligned_be32(&sp_wire[i].end_seq);
		//合法性检查，不合法进入这个分支，表示不值得处理
		if (!tcp_is_sackblock_valid(tp, dup_sack,
					    sp[used_sacks].start_seq,
					    sp[used_sacks].end_seq)) {
			int mib_idx;

			if (dup_sack) { //DSACK 块
				if (!tp->undo_marker)  //D-SACK 太乱太旧
					mib_idx = LINUX_MIB_TCPDSACKIGNOREDNOUNDO;
				else
					mib_idx = LINUX_MIB_TCPDSACKIGNOREDOLD; //不在关心的 undo 区间
			} else { //普通sack块
				/* Don't count olds caused by ACK reordering */
				if ((TCP_SKB_CB(ack_skb)->ack_seq != tp->snd_una) &&
				    !after(sp[used_sacks].end_seq, tp->snd_una))
					continue;
				mib_idx = LINUX_MIB_TCPSACKDISCARD;
			}

			NET_INC_STATS(sock_net(sk), mib_idx);
			if (i == 0)
				first_sack_index = -1;
			continue;
		}

		/* Ignore very old stuff early */
		if (!after(sp[used_sacks].end_seq, prior_snd_una)) {
			if (i == 0)
				first_sack_index = -1;
			continue;
		}

		used_sacks++; //tcp_is_sackblock_valid 判定为合法
	}

	/* order SACK blocks to allow in order walk of the retrans queue */
	//把合法的sack块 按序号从小排序
	for (i = used_sacks - 1; i > 0; i--) {
		for (j = 0; j < i; j++) {
			if (after(sp[j].start_seq, sp[j + 1].start_seq)) {
				swap(sp[j], sp[j + 1]);

				/* Track where the first SACK block goes to */
				if (j == first_sack_index) //first_sack_index 排序后它可能不再是第 0 个了
					first_sack_index = j + 1; 
			}
		}
	}

	state->mss_now = tcp_current_mss(sk);
	skb = NULL;
	i = 0;
	//当前发送队列sack 标记的个数
	if (!tp->sacked_out) {
		/* It's already past, so skip checking against it */
		cache = tp->recv_sack_cache + ARRAY_SIZE(tp->recv_sack_cache); //指向数组末尾之后的位置，表示禁用cache
	} else { //那证明上一次SACK处理中 打过一些标签 并且这些数据还没完全ack 那就找到这个cache
		cache = tp->recv_sack_cache;
		/* Skip empty blocks in at head of the cache */
		while (tcp_sack_cache_ok(tp, cache) && !cache->start_seq &&
		       !cache->end_seq)
			cache++;
	}

	while (i < used_sacks) {
		u32 start_seq = sp[i].start_seq;
		u32 end_seq = sp[i].end_seq;
		bool dup_sack = (found_dup_sack && (i == first_sack_index));
		struct tcp_sack_block *next_dup = NULL;

		if (found_dup_sack && ((i + 1) == first_sack_index)) //DSACK 有两种编码方式，单块模式和双块模式 双块模式就是 SACK block#1: [1000,1200)  SACK block#2: [1000,1500)    
			next_dup = &sp[i + 1];

		/* Skip too early cached blocks */
		//如果本次收到的 SACK block 落在以前缓存的区间之后，那么把 cache 向前推进
		while (tcp_sack_cache_ok(tp, cache) &&
		       !before(start_seq, cache->end_seq))
			cache++;

		/* Can skip some work by looking recv_sack_cache? */
		//有cache可以用！！！！，不是dsack块，右边界在cache start的右边(有重叠)
		if (tcp_sack_cache_ok(tp, cache) && !dup_sack &&
		    after(end_seq, cache->start_seq)) {

			/* Head todo? */
			//头部没有被缓存覆盖
			if (before(start_seq, cache->start_seq)) {
				//二分找到发送队列中第一个 skb，用于作为后续 sacktag_walk 扫描的起点
				skb = tcp_sacktag_skip(skb, sk, start_seq); 
				//对 [start_seq, cache->start_seq) 这段序列范围的数据进行 SACK 标记处理？
				skb = tcp_sacktag_walk(skb, sk, next_dup,
						       state,
						       start_seq,
						       cache->start_seq,
						       dup_sack);
			}

			/* Rest of the block already fully processed? */
			//尾部在缓存内的情况，表示已经可以cover住了，这里直接goto出去
			if (!after(end_seq, cache->end_seq))
				goto advance_sp;
			//对dsack块的特殊处理
			skb = tcp_maybe_skipping_dsack(skb, sk, next_dup,
						       state,
						       cache->end_seq);

			/* ...tail remains todo... */
			//尾部超出了缓存
			if (tcp_highest_sack_seq(tp) == cache->end_seq) {
				/* ...but better entrypoint exists! */
				skb = tcp_highest_sack(sk);
				if (!skb)
					break;
				cache++;
				goto walk;
			}
			//二分查找下一个skb
			skb = tcp_sacktag_skip(skb, sk, cache->end_seq);
			/* Check overlap against next cached too (past this one already) */
			cache++;
			continue;
		}
		//cache不可用的情况 找到一个skb 这个skb是下面二分查找的起点
		if (!before(start_seq, tcp_highest_sack_seq(tp))) {
			skb = tcp_highest_sack(sk);
			if (!skb)
				break;
		}
		//二分查找找到skb
		skb = tcp_sacktag_skip(skb, sk, start_seq);

walk:
		skb = tcp_sacktag_walk(skb, sk, next_dup, state,
				       start_seq, end_seq, dup_sack);

advance_sp:
		i++;
	}

	/* Clear the head of the cache sack blocks so we can skip it next time */
	for (i = 0; i < ARRAY_SIZE(tp->recv_sack_cache) - used_sacks; i++) {
		tp->recv_sack_cache[i].start_seq = 0;
		tp->recv_sack_cache[i].end_seq = 0;
	}
	for (j = 0; j < used_sacks; j++)
		tp->recv_sack_cache[i++] = sp[j];

	if (inet_csk(sk)->icsk_ca_state != TCP_CA_Loss || tp->undo_marker)
		tcp_check_sack_reordering(sk, state->reord, 0);

	tcp_verify_left_out(tp);
out:

#if FASTRETRANS_DEBUG > 0
	WARN_ON((int)tp->sacked_out < 0);
	WARN_ON((int)tp->lost_out < 0);
	WARN_ON((int)tp->retrans_out < 0);
	WARN_ON((int)tcp_packets_in_flight(tp) < 0);
#endif
	return state->flag;
}

/* Limits sacked_out so that sum with lost_out isn't ever larger than
 * packets_out. Returns false if sacked_out adjustement wasn't necessary.
 */
static bool tcp_limit_reno_sacked(struct tcp_sock *tp)
{
	u32 holes;

	holes = max(tp->lost_out, 1U);
	holes = min(holes, tp->packets_out);

	if ((tp->sacked_out + holes) > tp->packets_out) {
		tp->sacked_out = tp->packets_out - holes;
		return true;
	}
	return false;
}

/* If we receive more dupacks than we expected counting segments
 * in assumption of absent reordering, interpret this as reordering.
 * The only another reason could be bug in receiver TCP.
 */
static void tcp_check_reno_reordering(struct sock *sk, const int addend)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_limit_reno_sacked(tp))
		return;

	tp->reordering = min_t(u32, tp->packets_out + addend,
			       READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_max_reordering));
	tp->reord_seen++;
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRENOREORDER);
}

/* Emulate SACKs for SACKless connection: account for a new dupack. */

static void tcp_add_reno_sack(struct sock *sk, int num_dupack, bool ece_ack)
{
	if (num_dupack) {
		struct tcp_sock *tp = tcp_sk(sk);
		u32 prior_sacked = tp->sacked_out;
		s32 delivered;

		tp->sacked_out += num_dupack;
		tcp_check_reno_reordering(sk, 0);
		delivered = tp->sacked_out - prior_sacked;
		if (delivered > 0)
			tcp_count_delivered(tp, delivered, ece_ack);
		tcp_verify_left_out(tp);
	}
}

/* Account for ACK, ACKing some data in Reno Recovery phase. */

static void tcp_remove_reno_sacks(struct sock *sk, int acked, bool ece_ack)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (acked > 0) {
		/* One ACK acked hole. The rest eat duplicate ACKs. */
		tcp_count_delivered(tp, max_t(int, acked - tp->sacked_out, 1),
				    ece_ack);
		if (acked - 1 >= tp->sacked_out)
			tp->sacked_out = 0;
		else
			tp->sacked_out -= acked - 1;
	}
	tcp_check_reno_reordering(sk, acked);
	tcp_verify_left_out(tp);
}

static inline void tcp_reset_reno_sack(struct tcp_sock *tp)
{
	tp->sacked_out = 0;
}

void tcp_clear_retrans(struct tcp_sock *tp)
{
	tp->retrans_out = 0;
	tp->lost_out = 0;
	tp->undo_marker = 0;
	tp->undo_retrans = -1;
	tp->sacked_out = 0;
}
//记录撤销时候用到信息
static inline void tcp_init_undo(struct tcp_sock *tp)
{	//记录当前第一个未被确认的序列号
	tp->undo_marker = tp->snd_una;
	/* Retransmission still in flight may cause DSACKs later. */
	//记录恢复开始时有多少重传包
	tp->undo_retrans = tp->retrans_out ? : -1;
}

static bool tcp_is_rack(const struct sock *sk)
{
	return READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_recovery) &
		TCP_RACK_LOSS_DETECTION;
}
// 先判断是否发生了 SACK reneging（接收端撤销/丢失了先前汇报的 SACK 记忆）；
// 按不同情况（reneging / Reno / RACK）决定如何处理记分板并选择哪些报文标记为丢失；
// 最后校验计数一致性并清理重传加速用的 hint
/* If we detect SACK reneging, forget all SACK information
 * and reset tags completely, otherwise preserve SACKs. If receiver
 * dropped its ofo queue, we will know this due to reneging detection.
 */
static void tcp_timeout_mark_lost(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb, *head;
	bool is_reneg;			/* is receiver reneging on SACKs? */
	//重传队列最老的数据包
	head = tcp_rtx_queue_head(sk);
	//被sack过，但是还在重传队列中，认为是反悔的
	is_reneg = head && (TCP_SKB_CB(head)->sacked & TCPCB_SACKED_ACKED);
	if (is_reneg) { //处理 SACK 反悔情况
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSACKRENEGING);
		tp->sacked_out = 0;
		/* Mark SACK reneging until we recover from this loss event. */
		//置位 is_sack_reneg
		tp->is_sack_reneg = 1;  
	} else if (tcp_is_reno(tp)) {
		tcp_reset_reno_sack(tp);
	}

	skb = head;
	//遍历重传队列
	skb_rbtree_walk_from(skb) {
		if (is_reneg)//处理 SACK 反悔情况
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_ACKED; //反悔了，清掉
		else if (tcp_is_rack(sk) && skb != head &&  //否则如果启用了 RACK（基于时间的丢包检测
			 tcp_rack_skb_timeout(tp, skb, 0) > 0)  //这个数据包的时间戳是否已经超过了一个平均rtt时间
			continue; /* Don't mark recently sent ones lost yet */
		tcp_mark_skb_lost(sk, skb); //标记丢失
	}
	//重置 TCP 的重传辅助指针
	tcp_verify_left_out(tp);
	tcp_clear_all_retrans_hints(tp);
}
/* Enter Loss state. */
//只有定时器到期会调用
///
void tcp_enter_loss(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	bool new_recovery = icsk->icsk_ca_state < TCP_CA_Recovery; //是否在recovery状态之前
	u8 reordering;
	//基于rack 批量标记丢失数据包
	tcp_timeout_mark_lost(sk);

	/* Reduce ssthresh if it has not yet been made inside this window. */
	//保存撤销用到的值
	if (icsk->icsk_ca_state <= TCP_CA_Disorder ||  //如果是乱序或者open
	    !after(tp->high_seq, tp->snd_una) ||  //上一次拥塞恢复范围（high_seq）已经被完全 ACK ， 下面会重新设置
	    (icsk->icsk_ca_state == TCP_CA_Loss && !icsk->icsk_retransmits)) {
		tp->prior_ssthresh = tcp_current_ssthresh(sk);  //慢启动阈值
		tp->prior_cwnd = tcp_snd_cwnd(tp);    //enterloss前保存拥塞窗口
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
		tcp_ca_event(sk, CA_EVENT_LOSS); //调用拥塞算法的钩子
		tcp_init_undo(tp); //初始化撤销用到的信息
	}
	tcp_snd_cwnd_set(tp, tcp_packets_in_flight(tp) + 1); //设置拥塞窗口，飞包数+1
	tp->snd_cwnd_cnt   = 0; //清零 cwnd 计数器
	tp->snd_cwnd_stamp = tcp_jiffies32;  //记录时间戳

	/* Timeout in disordered state after receiving substantial DUPACKs
	 * suggests that the degree of reordering is over-estimated.
	 */
	reordering = READ_ONCE(net->ipv4.sysctl_tcp_reordering); //乱序容忍阈值
	if (icsk->icsk_ca_state <= TCP_CA_Disorder &&
	    tp->sacked_out >= reordering)    		//
		tp->reordering = min_t(unsigned int, tp->reordering,  //缩小乱序容忍阈值,相当于容忍度太宽了，都丢包了，所以要缩小
				       reordering);

	tcp_set_ca_state(sk, TCP_CA_Loss); //设置为loss
	tp->high_seq = tp->snd_nxt;  //进入拥塞控制状态后下一个待发送的序列号
	tcp_ecn_queue_cwr(tp); //设置cwr标志位

	/* F-RTO RFC5682 sec 3.1 step 1: retransmit SND.UNA if no previous
	 * loss recovery is underway except recurring timeout(s) on
	 * the same SND.UNA (sec 3.2). Disable F-RTO on path MTU probing
	 */
	//F-RTO 在 RTO 之后先只重传 SND.UNA 再观察后续 ACK 的模式来判定是否真丢包
	tp->frto = READ_ONCE(net->ipv4.sysctl_tcp_frto) &&  //是否开启frto //这里的`frto`会影响`loss`的撤销
		   (new_recovery || icsk->icsk_retransmits) &&
		   !inet_csk(sk)->icsk_mtup.probe_size;
}

/* If ACK arrived pointing to a remembered SACK, it means that our
 * remembered SACKs do not reflect real state of receiver i.e.
 * receiver _host_ is heavily congested (or buggy).
 *
 * To avoid big spurious retransmission bursts due to transient SACK
 * scoreboard oddities that look like reneging, we give the receiver a
 * little time (max(RTT/2, 10ms)) to send us some more ACKs that will
 * restore sanity to the SACK scoreboard. If the apparent reneging
 * persists until this RTO then we'll clear the SACK scoreboard.
 */
//处理sack撤销的情况，重新设置重传定时器的超时时间 为(max(RTT/2, 10ms) 目的是给一点机会？不立即重传？
static bool tcp_check_sack_reneging(struct sock *sk, int *ack_flag)
{
	//存在sack撤销，且发送窗口前进了
	if (*ack_flag & FLAG_SACK_RENEGING &&
	    *ack_flag & FLAG_SND_UNA_ADVANCED) {
		struct tcp_sock *tp = tcp_sk(sk);
		unsigned long delay = max(usecs_to_jiffies(tp->srtt_us >> 4),
					  msecs_to_jiffies(10));
		//重新设置重传定时器
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  delay, TCP_RTO_MAX);
		*ack_flag &= ~FLAG_SET_XMIT_TIMER;
		return true;
	}
	return false;
}

/* Heurestics to calculate number of duplicate ACKs. There's no dupACKs
 * counter when SACK is enabled (without SACK, sacked_out is used for
 * that purpose).
 *
 * With reordering, holes may still be in flight, so RFC3517 recovery
 * uses pure sacked_out (total number of SACKed segments) even though
 * it violates the RFC that uses duplicate ACKs, often these are equal
 * but when e.g. out-of-window ACKs or packet duplication occurs,
 * they differ. Since neither occurs due to loss, TCP should really
 * ignore them.
 */
static inline int tcp_dupack_heuristics(const struct tcp_sock *tp)
{
	return tp->sacked_out + 1;
}

/* Linux NewReno/SACK/ECN state machine.
 * --------------------------------------
 *
 * "Open"	Normal state, no dubious events, fast path.
 * "Disorder"   In all the respects it is "Open",
 *		but requires a bit more attention. It is entered when
 *		we see some SACKs or dupacks. It is split of "Open"
 *		mainly to move some processing from fast path to slow one.
 * "CWR"	CWND was reduced due to some Congestion Notification event.
 *		It can be ECN, ICMP source quench, local device congestion.
 * "Recovery"	CWND was reduced, we are fast-retransmitting.
 * "Loss"	CWND was reduced due to RTO timeout or SACK reneging.
 *
 * tcp_fastretrans_alert() is entered:
 * - each incoming ACK, if state is not "Open"
 * - when arrived ACK is unusual, namely:
 *	* SACK
 *	* Duplicate ACK.
 *	* ECN ECE.
 *
 * Counting packets in flight is pretty simple.
 *
 *	in_flight = packets_out - left_out + retrans_out
 *
 *	packets_out is SND.NXT-SND.UNA counted in packets.
 *
 *	retrans_out is number of retransmitted segments.
 *
 *	left_out is number of segments left network, but not ACKed yet.
 *
 *		left_out = sacked_out + lost_out
 *
 *     sacked_out: Packets, which arrived to receiver out of order
 *		   and hence not ACKed. With SACKs this number is simply
 *		   amount of SACKed data. Even without SACKs
 *		   it is easy to give pretty reliable estimate of this number,
 *		   counting duplicate ACKs.
 *
 *       lost_out: Packets lost by network. TCP has no explicit
 *		   "loss notification" feedback from network (for now).
 *		   It means that this number can be only _guessed_.
 *		   Actually, it is the heuristics to predict lossage that
 *		   distinguishes different algorithms.
 *
 *	F.e. after RTO, when all the queue is considered as lost,
 *	lost_out = packets_out and in_flight = retrans_out.
 *
 *		Essentially, we have now a few algorithms detecting
 *		lost packets.
 *
 *		If the receiver supports SACK:
 *
 *		RFC6675/3517: It is the conventional algorithm. A packet is
 *		considered lost if the number of higher sequence packets
 *		SACKed is greater than or equal the DUPACK thoreshold
 *		(reordering). This is implemented in tcp_mark_head_lost and
 *		tcp_update_scoreboard.
 *
 *		RACK (draft-ietf-tcpm-rack-01): it is a newer algorithm
 *		(2017-) that checks timing instead of counting DUPACKs.
 *		Essentially a packet is considered lost if it's not S/ACKed
 *		after RTT + reordering_window, where both metrics are
 *		dynamically measured and adjusted. This is implemented in
 *		tcp_rack_mark_lost.
 *
 *		If the receiver does not support SACK:
 *
 *		NewReno (RFC6582): in Recovery we assume that one segment
 *		is lost (classic Reno). While we are in Recovery and
 *		a partial ACK arrives, we assume that one more packet
 *		is lost (NewReno). This heuristics are the same in NewReno
 *		and SACK.
 *
 * Really tricky (and requiring careful tuning) part of algorithm
 * is hidden in functions tcp_time_to_recover() and tcp_xmit_retransmit_queue().
 * The first determines the moment _when_ we should reduce CWND and,
 * hence, slow down forward transmission. In fact, it determines the moment
 * when we decide that hole is caused by loss, rather than by a reorder.
 *
 * tcp_xmit_retransmit_queue() decides, _what_ we should retransmit to fill
 * holes, caused by lost packets.
 *
 * And the most logically complicated part of algorithm is undo
 * heuristics. We detect false retransmits due to both too early
 * fast retransmit (reordering) and underestimated RTO, analyzing
 * timestamps and D-SACKs. When we detect that some segments were
 * retransmitted by mistake and CWND reduction was wrong, we undo
 * window reduction and abort recovery phase. This logic is hidden
 * inside several functions named tcp_try_undo_<something>.
 */

/* This function decides, when we should leave Disordered state
 * and enter Recovery phase, reducing congestion window.
 *
 * Main question: may we further continue forward transmission
 * with the same cwnd?
 */
static bool tcp_time_to_recover(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Trick#1: The loss is proven. */
	//当前待重传的丢包的数量 
	if (tp->lost_out)
		return true;

	/* Not-A-Trick#2 : Classic rule... */
	if (!tcp_is_rack(sk) && tcp_dupack_heuristics(tp) > tp->reordering)
		return true;

	return false;
}

/* Detect loss in event "A" above by marking head of queue up as lost.
 * For RFC3517 SACK, a segment is considered lost if it
 * has at least tp->reordering SACKed seqments above it; "packets" refers to
 * the maximum SACKed segments to pass before reaching this limit.
 */
static void tcp_mark_head_lost(struct sock *sk, int packets, int mark_head)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int cnt;
	/* Use SACK to deduce losses of new sequences sent during recovery */
	const u32 loss_high = tp->snd_nxt;

	WARN_ON(packets > tp->packets_out);
	skb = tp->lost_skb_hint;
	if (skb) {
		/* Head already handled? */
		if (mark_head && after(TCP_SKB_CB(skb)->seq, tp->snd_una))
			return;
		cnt = tp->lost_cnt_hint;
	} else {
		skb = tcp_rtx_queue_head(sk);
		cnt = 0;
	}

	skb_rbtree_walk_from(skb) {
		/* TODO: do this better */
		/* this is not the most efficient way to do this... */
		tp->lost_skb_hint = skb;
		tp->lost_cnt_hint = cnt;

		if (after(TCP_SKB_CB(skb)->end_seq, loss_high))
			break;

		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
			cnt += tcp_skb_pcount(skb);

		if (cnt > packets)
			break;

		if (!(TCP_SKB_CB(skb)->sacked & TCPCB_LOST))
			tcp_mark_skb_lost(sk, skb);

		if (mark_head)
			break;
	}
	tcp_verify_left_out(tp);
}

/* Account newly detected lost packet(s) */

static void tcp_update_scoreboard(struct sock *sk, int fast_rexmit)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_is_sack(tp)) {
		int sacked_upto = tp->sacked_out - tp->reordering;
		if (sacked_upto >= 0)
			tcp_mark_head_lost(sk, sacked_upto, 0);
		else if (fast_rexmit)
			tcp_mark_head_lost(sk, 1, 1);
	}
}
//有时间戳选项，且时间戳选项早于when
static bool tcp_tsopt_ecr_before(const struct tcp_sock *tp, u32 when)
{
	return tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
	       before(tp->rx_opt.rcv_tsecr, when);
}

/* skb is spurious retransmitted if the returned timestamp echo
 * reply is prior to the skb transmission time
 */
static bool tcp_skb_spurious_retrans(const struct tcp_sock *tp,
				     const struct sk_buff *skb)
{
	return (TCP_SKB_CB(skb)->sacked & TCPCB_RETRANS) &&
	       tcp_tsopt_ecr_before(tp, tcp_skb_timestamp(skb));
}

/* Nothing was retransmitted or returned timestamp is less
 * than timestamp of the first retransmission.
 */
static inline bool tcp_packet_delayed(const struct tcp_sock *tp)
{
	return tp->retrans_stamp && //首次重传的时间戳	
	       tcp_tsopt_ecr_before(tp, tp->retrans_stamp);
}

/* Undo procedures. */

/* We can clear retrans_stamp when there are no retransmissions in the
 * window. It would seem that it is trivially available for us in
 * tp->retrans_out, however, that kind of assumptions doesn't consider
 * what will happen if errors occur when sending retransmission for the
 * second time. ...It could the that such segment has only
 * TCPCB_EVER_RETRANS set at the present time. It seems that checking
 * the head skb is enough except for some reneging corner cases that
 * are not worth the effort.
 *
 * Main reason for all this complexity is the fact that connection dying
 * time now depends on the validity of the retrans_stamp, in particular,
 * that successive retransmissions of a segment must not advance
 * retrans_stamp under any conditions.
 */
static bool tcp_any_retrans_done(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	
	if (tp->retrans_out)
		return true;
		//存在重传的数据包，不能撤销
	skb = tcp_rtx_queue_head(sk);
	if (unlikely(skb && TCP_SKB_CB(skb)->sacked & TCPCB_EVER_RETRANS))
		return true;

	return false;
}

static void DBGUNDO(struct sock *sk, const char *msg)
{
#if FASTRETRANS_DEBUG > 1
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);

	if (sk->sk_family == AF_INET) {
		pr_debug("Undo %s %pI4/%u c%u l%u ss%u/%u p%u\n",
			 msg,
			 &inet->inet_daddr, ntohs(inet->inet_dport),
			 tcp_snd_cwnd(tp), tcp_left_out(tp),
			 tp->snd_ssthresh, tp->prior_ssthresh,
			 tp->packets_out);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (sk->sk_family == AF_INET6) {
		pr_debug("Undo %s %pI6/%u c%u l%u ss%u/%u p%u\n",
			 msg,
			 &sk->sk_v6_daddr, ntohs(inet->inet_dport),
			 tcp_snd_cwnd(tp), tcp_left_out(tp),
			 tp->snd_ssthresh, tp->prior_ssthresh,
			 tp->packets_out);
	}
#endif
#endif
} 
//撤销loss中第二个参数是true 撤销recovery也会调用，主要工作就是，清楚重传队列中的丢包标志，以及重新计算慢启动阈值
static void tcp_undo_cwnd_reduction(struct sock *sk, bool unmark_loss)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (unmark_loss) {
		struct sk_buff *skb;
		//遍历重传队列清除重传标志
		skb_rbtree_walk(skb, &sk->tcp_rtx_queue) {
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_LOST;
		}
		tp->lost_out = 0;
		//清空辅助数据
		tcp_clear_all_retrans_hints(tp);
	}
	//之前保存过慢启动阈值
	if (tp->prior_ssthresh) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		//调用拥塞算法的钩子重新设置窗口大小
		tcp_snd_cwnd_set(tp, icsk->icsk_ca_ops->undo_cwnd(sk));
		//更新慢启动阈值
		if (tp->prior_ssthresh > tp->snd_ssthresh) {
			tp->snd_ssthresh = tp->prior_ssthresh;
			//清楚拥塞标记
			tcp_ecn_withdraw_cwr(tp);
		}
	}
	tp->snd_cwnd_stamp = tcp_jiffies32; //记录时间戳
	tp->undo_marker = 0; //重置undo
	//rack 相关字段需要更新？？
	tp->rack.advanced = 1; /* Force RACK to re-exam losses */
}
//有可能需要撤销的标记，且当前确认的数据包的时间戳比重传的数据包要早
static inline bool tcp_may_undo(const struct tcp_sock *tp)
{
	return tp->undo_marker && (!tp->undo_retrans || tcp_packet_delayed(tp));
}

static bool tcp_is_non_sack_preventing_reopen(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->snd_una == tp->high_seq && tcp_is_reno(tp)) {
		/* Hold old state until something *above* high_seq
		 * is ACKed. For Reno it is MUST to prevent false
		 * fast retransmits (RFC2582). SACK TCP is safe. */
		if (!tcp_any_retrans_done(sk))
			tp->retrans_stamp = 0;
		return true;
	}
	return false;
}

/* People celebrate: "We love our President!" */
//loss状态可能调用这个函数 recovery状态下可能也会调用
static bool tcp_try_undo_recovery(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//有撤销的标记，且当前确认的数据包的时间戳比重传的数据包要早
	if (tcp_may_undo(tp)) {
		int mib_idx;

		/* Happy end! We did not retransmit anything
		 * or our original transmission succeeded.
		 */
		DBGUNDO(sk, inet_csk(sk)->icsk_ca_state == TCP_CA_Loss ? "loss" : "retrans");
		//清除重传队列中的标志，更新慢启动阈值
		tcp_undo_cwnd_reduction(sk, false);
		if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss)
			mib_idx = LINUX_MIB_TCPLOSSUNDO;
		else
			mib_idx = LINUX_MIB_TCPFULLUNDO;

		NET_INC_STATS(sock_net(sk), mib_idx);
	} else if (tp->rack.reo_wnd_persist) { //如果真是丢包，就要减少这个值，这个是误判丢包的？
		tp->rack.reo_wnd_persist--;
	}
	//reno算法的处理
	if (tcp_is_non_sack_preventing_reopen(sk))
		return true;
	//即使上面返回false 也会撤销？？
	tcp_set_ca_state(sk, TCP_CA_Open); //从recovery 到 open
	tp->is_sack_reneg = 0;
	return false;
}

/* Try to undo cwnd reduction, because D-SACKs acked all retransmitted data */
//这里没有更新状态，只是更新慢启动阈值和拥塞窗口大小
//recover 状态下会调用这个函数 为什么叫撤销dsack呢，因为最最外层处理过？
static bool tcp_try_undo_dsack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->undo_marker && !tp->undo_retrans) {
		tp->rack.reo_wnd_persist = min(TCP_RACK_RECOVERY_THRESH,
					       tp->rack.reo_wnd_persist + 1);
		DBGUNDO(sk, "D-SACK");
		//清除重传队列中的丢包标志，以及重新计算慢启动阈值,以及拥塞窗口的大小
		tcp_undo_cwnd_reduction(sk, false);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPDSACKUNDO);
		return true;
	}
	return false;
}

/* Undo during loss recovery after partial ACK or using F-RTO. */
//撤销loss fastalert 中  process_loss中调用
static bool tcp_try_undo_loss(struct sock *sk, bool frto_undo)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//frto明确指出要撤销 或者有可能需要撤销的标记，且当前确认的数据包的时间戳比重传的数据包要早，并且没有重传数据包
	if (frto_undo || tcp_may_undo(tp)) {
		tcp_undo_cwnd_reduction(sk, true);

		DBGUNDO(sk, "partial loss");
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPLOSSUNDO);
		if (frto_undo)
			NET_INC_STATS(sock_net(sk),
					LINUX_MIB_TCPSPURIOUSRTOS);
		inet_csk(sk)->icsk_retransmits = 0;
		//要是支持sack 这里直接false
		if (tcp_is_non_sack_preventing_reopen(sk))
			return true;
		//设置状态为open
		if (frto_undo || tcp_is_sack(tp)) {
			tcp_set_ca_state(sk, TCP_CA_Open); //从loss 变成 open
			tp->is_sack_reneg = 0;
		}
		return true;
	}
	return false;
}

/* The cwnd reduction in CWR and Recovery uses the PRR algorithm in RFC 6937.
 * It computes the number of packets to send (sndcnt) based on packets newly
 * delivered:
 *   1) If the packets in flight is larger than ssthresh, PRR spreads the
 *	cwnd reductions across a full RTT.
 *   2) Otherwise PRR uses packet conservation to send as much as delivered.
 *      But when SND_UNA is acked without further losses,
 *      slow starts cwnd up to ssthresh to speed up the recovery.
 */
static void tcp_init_cwnd_reduction(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->high_seq = tp->snd_nxt; //标记恢复开始的位置
	tp->tlp_high_seq = 0; //TLP（尾部丢包探测）相关参数清零
	tp->snd_cwnd_cnt = 0; //这个有什么用？？累加之后影响拥塞窗口？
	tp->prior_cwnd = tcp_snd_cwnd(tp); //保存拥塞窗口
	tp->prr_delivered = 0;
	tp->prr_out = 0;
	////拥塞算法钩子重新计算慢启动阈值
	tp->snd_ssthresh = inet_csk(sk)->icsk_ca_ops->ssthresh(sk); 
	tcp_ecn_queue_cwr(tp);
}

void tcp_cwnd_reduction(struct sock *sk, int newly_acked_sacked, int newly_lost, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int sndcnt = 0;
	int delta = tp->snd_ssthresh - tcp_packets_in_flight(tp);
	//没有新确认的数据包
	if (newly_acked_sacked <= 0 || WARN_ON_ONCE(!tp->prior_cwnd))
		return;
	//快速恢复期间累计确认的数据包数
	tp->prr_delivered += newly_acked_sacked;
	//计算允许发送的新数据包数
	if (delta < 0) {
	//如果确认了N个包，最多允许发送N/2个新包。
		u64 dividend = (u64)tp->snd_ssthresh * tp->prr_delivered +
			       tp->prior_cwnd - 1;
		sndcnt = div_u64(dividend, tp->prior_cwnd) - tp->prr_out;
	} else {
	//每确认一个数据包，至少可以发送一个新数据包
		sndcnt = max_t(int, tp->prr_delivered - tp->prr_out,
			       newly_acked_sacked);
		if (flag & FLAG_SND_UNA_ADVANCED && !newly_lost)
			sndcnt++;
		sndcnt = min(delta, sndcnt);
	}
	/* Force a fast retransmit upon entering fast recovery */
	sndcnt = max(sndcnt, (tp->prr_out ? 0 : 1));
	//更新拥塞窗口
	tcp_snd_cwnd_set(tp, tcp_packets_in_flight(tp) + sndcnt);
}

static inline void tcp_end_cwnd_reduction(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//新的拥塞控制算法（如BBR）有自己的拥塞窗口管理逻辑
	if (inet_csk(sk)->icsk_ca_ops->cong_control)
		return;

	/* Reset cwnd to ssthresh in CWR or Recovery (unless it's undone) */
	//传统算法的拥塞窗口重置 例如cubic
	if (tp->snd_ssthresh < TCP_INFINITE_SSTHRESH &&
	    (inet_csk(sk)->icsk_ca_state == TCP_CA_CWR || tp->undo_marker)) {
		tcp_snd_cwnd_set(tp, tp->snd_ssthresh);//拥塞窗口设置为慢启动阈值
		tp->snd_cwnd_stamp = tcp_jiffies32;
	}
	//调用拥塞算法的钩子
	tcp_ca_event(sk, CA_EVENT_COMPLETE_CWR);
}

/* Enter CWR state. Disable cwnd undo since congestion is proven with ECN */
//发送通路 和 fastalert中会调用
//当 TCP 检测到发生 ECN 拥塞或本地主机丢包时!
void tcp_enter_cwr(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->prior_ssthresh = 0;
	if (inet_csk(sk)->icsk_ca_state < TCP_CA_CWR) {
		tp->undo_marker = 0;
		tcp_init_cwnd_reduction(sk);//初始化拥塞窗口减小
		tcp_set_ca_state(sk, TCP_CA_CWR); //设置cwr状态
	}
}
EXPORT_SYMBOL(tcp_enter_cwr);
//主要是tcpack中被调用//设置乱需或者open状态 tlp中也会调用了
//相当于是一个健康检查
static void tcp_try_keep_open(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int state = TCP_CA_Open;
	//计算sack和丢包的数量  或者是否正在重传的包或者重传队列中有数据包
	if (tcp_left_out(tp) || tcp_any_retrans_done(sk))
		state = TCP_CA_Disorder;  //设置为乱需状态

	if (inet_csk(sk)->icsk_ca_state != state) {  //如果不是open状态
		tcp_set_ca_state(sk, state); //设置乱需或者open状态
		tp->high_seq = tp->snd_nxt;  //保存进入拥塞状态的的序号
	}
}

static void tcp_try_to_open(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_verify_left_out(tp);

	if (!tcp_any_retrans_done(sk))
		tp->retrans_stamp = 0;

	if (flag & FLAG_ECE)
		tcp_enter_cwr(sk);

	if (inet_csk(sk)->icsk_ca_state != TCP_CA_CWR) {
		tcp_try_keep_open(sk);
	}
}

static void tcp_mtup_probe_failed(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_mtup.search_high = icsk->icsk_mtup.probe_size - 1;
	icsk->icsk_mtup.probe_size = 0;
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMTUPFAIL);
}

static void tcp_mtup_probe_success(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	u64 val;
	//慢启动阈值
	tp->prior_ssthresh = tcp_current_ssthresh(sk);
	//根据mss计算新的cwnd，合理
	val = (u64)tcp_snd_cwnd(tp) * tcp_mss_to_mtu(sk, tp->mss_cache);
	do_div(val, icsk->icsk_mtup.probe_size);
	DEBUG_NET_WARN_ON_ONCE((u32)val != val);
	tcp_snd_cwnd_set(tp, max_t(u32, 1U, val));

	tp->snd_cwnd_cnt = 0;
	tp->snd_cwnd_stamp = tcp_jiffies32;
	tp->snd_ssthresh = tcp_current_ssthresh(sk);//重新设置慢启动阈值
	//抬高下界，并结束本轮探测
	icsk->icsk_mtup.search_low = icsk->icsk_mtup.probe_size;
	icsk->icsk_mtup.probe_size = 0;
	tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMTUPSUCCESS);
}

/* Do a simple retransmit without using the backoff mechanisms in
 * tcp_timer. This is used for path mtu discovery.
 * The socket is already locked here.
 */
//fast  alert 中调用 icmp也会调用？？？
//挑出需要重传的报文并立即重传。它不去调整拥塞窗口，只做最小化的丢失标记与重传
void tcp_simple_retransmit(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int mss;

	/* A fastopen SYN request is stored as two separate packets within
	 * the retransmit queue, this is done by tcp_send_syn_data().
	 * As a result simply checking the MSS of the frames in the queue
	 * will not work for the SYN packet.
	 *
	 * Us being here is an indication of a path MTU issue so we can
	 * assume that the fastopen SYN was lost and just mark all the
	 * frames in the retransmit queue as lost. We will use an MSS of
	 * -1 to mark all frames as lost, otherwise compute the current MSS.
	 */
	//因为是可能路径探测导致的丢包，因此肯定是先计算一个mss
	if (tp->syn_data && sk->sk_state == TCP_SYN_SENT)
		mss = -1;
	else
		mss = tcp_current_mss(sk);
	//遍历重传队列，把超过mss的包标记为丢失
	skb_rbtree_walk(skb, &sk->tcp_rtx_queue) {
		if (tcp_skb_seglen(skb) > mss)
			tcp_mark_skb_lost(sk, skb);
	}
	//清空重传用到的辅助字段
	tcp_clear_retrans_hints_partial(tp);
	//当前待重传的丢包数量
	if (!tp->lost_out)
		return;

	if (tcp_is_reno(tp))
		tcp_limit_reno_sacked(tp);

	tcp_verify_left_out(tp);

	/* Don't muck with the congestion window here.
	 * Reason is that we do not increase amount of _data_
	 * in network, but units changed and effective
	 * cwnd/ssthresh really reduced now.
	 */
	//设置 loss状态，注意这里没有缩小拥塞窗口
	if (icsk->icsk_ca_state != TCP_CA_Loss) {
		tp->high_seq = tp->snd_nxt;
		tp->snd_ssthresh = tcp_current_ssthresh(sk);
		tp->prior_ssthresh = 0;
		tp->undo_marker = 0;
		tcp_set_ca_state(sk, TCP_CA_Loss);
	}
	//重传数据包
	tcp_xmit_retransmit_queue(sk);
}
EXPORT_SYMBOL(tcp_simple_retransmit);

//tcp_rack_reo_timeout 和 tcp_fastretrans_alert 中调用
//进入 recovery状态
void tcp_enter_recovery(struct sock *sk, bool ece_ack)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mib_idx;
	//通常不会走这个
	if (tcp_is_reno(tp))
		mib_idx = LINUX_MIB_TCPRENORECOVERY;
	else
		mib_idx = LINUX_MIB_TCPSACKRECOVERY;

	NET_INC_STATS(sock_net(sk), mib_idx);
	//重置之前的慢启动阈值
	tp->prior_ssthresh = 0;
	//记录进入恢复时候的una和重传的包数
	tcp_init_undo(tp);
	//是否在恢复或者减少拥塞窗口的状态
	if (!tcp_in_cwnd_reduction(sk)) {
		if (!ece_ack) //如果不是现实拥塞通知，保存慢启动阈值
			tp->prior_ssthresh = tcp_current_ssthresh(sk);
		tcp_init_cwnd_reduction(sk);
	}
	tcp_set_ca_state(sk, TCP_CA_Recovery); //设置recovery
}

/* Process an ACK in CA_Loss state. Move to CA_Open if lost data are
 * recovered or spurious. Otherwise retransmits more on partial ACKs.
 */
static void tcp_process_loss(struct sock *sk, int flag, int num_dupack,
			     int *rexmit)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//recovered = true表示确认指针超过了进入Loss时的序列号
	bool recovered = !before(tp->snd_una, tp->high_seq);
	//如果更新了una，尝试是否可以撤销loss，如果撤销这里直接就返回了
	if ((flag & FLAG_SND_UNA_ADVANCED || rcu_access_pointer(tp->fastopen_rsk)) &&
	    tcp_try_undo_loss(sk, false))
		return;
	//tcp_enter_loss 会设置该字段
	if (tp->frto) { /* F-RTO RFC5682 sec 3.1 (sack enhanced version). */
		/* Step 3.b. A timeout is spurious if not all data are
		 * lost, i.e., never-retransmitted data are (s)acked.
		 */
		//收到了从未重传过的原始数据的SACK确认，比如345但是3丢了？ 这里直接会变成open然后返回
		if ((flag & FLAG_ORIG_SACK_ACKED) &&
		    tcp_try_undo_loss(sk, true))
			return;
		//已经发送了新数据，注意这里是sndnxt
		if (after(tp->snd_nxt, tp->high_seq)) { //应该是第二次才会进入这个分支？！！ 发现是真丢包，关闭了frto
			// 确认是真实丢包，关闭F-RTO
			if (flag & FLAG_DATA_SACKED || num_dupack)
				tp->frto = 0; /* Step 3.a. loss was real */  
		//确认了新数据，但是还没有完全恢复
		} else if (flag & FLAG_SND_UNA_ADVANCED && !recovered) { 
			tp->high_seq = tp->snd_nxt; //将恢复序列号更新为当前发送序列号
			/* Step 2.b. Try send new data (but deferred until cwnd
			 * is updated in tcp_ack()). Otherwise fall back to
			 * the conventional recovery.
			 */
			//有数据可发 && 有窗口空间
			if (!tcp_write_queue_empty(sk) &&
			    after(tcp_wnd_end(tp), tp->snd_nxt)) {
				*rexmit = REXMIT_NEW; //这个应该是标识发送新数据，貌似是frto的核心?
				return;
			}
			tp->frto = 0;
		}
	}

	if (recovered) {
		/* F-RTO RFC5682 sec 3.1 step 2.a and 1st part of step 3.a */
	//尝试恢复到open
		tcp_try_undo_recovery(sk);
		return;
	}
	if (tcp_is_reno(tp)) {
		/* A Reno DUPACK means new data in F-RTO step 2.b above are
		 * delivered. Lower inflight to clock out (re)transmissions.
		 */
		if (after(tp->snd_nxt, tp->high_seq) && num_dupack)
			tcp_add_reno_sack(sk, num_dupack, flag & FLAG_ECE);
		else if (flag & FLAG_SND_UNA_ADVANCED)
			tcp_reset_reno_sack(tp);
	}
	*rexmit = REXMIT_LOST;
}

static bool tcp_force_fast_retransmit(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//当已被 SACK 确认的最高序号超出当前累计确认序号 (snd_una) 超过一定乱序容忍度 (reordering * MSS) 时
	return after(tcp_highest_sack_seq(tp),
		     tp->snd_una + tp->reordering * tp->mss_cache);
}

/* Undo during fast recovery after partial ACK. */
//在恢复期间收到了部分数据包，是否可以撤销，返回fasle表示可以
static bool tcp_try_undo_partial(struct sock *sk, u32 prior_snd_una,
				 bool *do_lost)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//有拥塞撤销的标志，且数据包是延时到达的
	if (tp->undo_marker && tcp_packet_delayed(tp)) {
		/* Plain luck! Hole if filled with delayed
		 * packet, rather than with a retransmit. Check reordering.
		 */
		//因为收到了部分数据包，所以更新乱续容忍
		tcp_check_sack_reordering(sk, prior_snd_una, 1);

		/* We are getting evidence that the reordering degree is higher
		 * than we realized. If there are no retransmits out then we
		 * can undo. Otherwise we clock out new packets but do not
		 * mark more packets lost or retransmit more.
		 */
		//存在重传的数据包，不能撤销,注意这个字段的值在tcpack中是会减少的
		if (tp->retrans_out)
			return true;
		//重传队列是否为空
		if (!tcp_any_retrans_done(sk))
			tp->retrans_stamp = 0;

		DBGUNDO(sk, "partial recovery");
		tcp_undo_cwnd_reduction(sk, true);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPPARTIALUNDO);
		//看看是否可以变成open状态
		tcp_try_keep_open(sk);
	} else {
		/* Partial ACK arrived. Force fast retransmit. */
		//当已被 SACK 确认的最高序号超出当前累计确认序号 (snd_una) 超过一定乱序容忍度 (reordering * MSS) 时
		*do_lost = tcp_force_fast_retransmit(sk);
	}
	return false;
}

static void tcp_identify_packet_loss(struct sock *sk, int *ack_flag)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_rtx_queue_empty(sk))
		return;

	if (unlikely(tcp_is_reno(tp))) {
		tcp_newreno_mark_lost(sk, *ack_flag & FLAG_SND_UNA_ADVANCED);
	} else if (tcp_is_rack(sk)) {
		u32 prior_retrans = tp->retrans_out;
		//返回true表示通过rack标记了丢包
		if (tcp_rack_mark_lost(sk)) //注意这里会减少retrans_out
		//表示RACK已经处理了定时器逻辑，不需要再设置
			*ack_flag &= ~FLAG_SET_XMIT_TIMER;
		if (prior_retrans > tp->retrans_out)
			*ack_flag |= FLAG_LOST_RETRANS; //表示有重传包丢失
	}
}

/* Process an event, which can update packets-in-flight not trivially.
 * Main goal of this function is to calculate new estimate for left_out,
 * taking into account both packets sitting in receiver's buffer and
 * packets lost by network.
 *
 * Besides that it updates the congestion state when packet loss or ECN
 * is detected. But it does not reduce the cwnd, it is done by the
 * congestion control later.
 *
 * It does _not_ decide what to send, it is made in function
 * tcp_xmit_retransmit_queue().
 */
//tcp_ack中调用  注意，这里的重复ack的参数好像只有在reno的情况下才会调用
static void tcp_fastretrans_alert(struct sock *sk, const u32 prior_snd_una,
				  int num_dupack, int *ack_flag, int *rexmit)
{
	// ！！！！！But it does not reduce the cwnd,
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int fast_rexmit = 0, flag = *ack_flag;
	bool ece_ack = flag & FLAG_ECE;
	//收到重复ack 或者有sack且乱续超过阈值，  这个值如果开启了rack好像就没什么用了?
	bool do_lost = num_dupack || ((flag & FLAG_DATA_SACKED) &&
				      tcp_force_fast_retransmit(sk));
	//错误处理， 发出去没有被ack的为0 且sack确认的不为0
	if (!tp->packets_out && tp->sacked_out)
		tp->sacked_out = 0;

	/* Now state machine starts.
	 * A. ECE, hence prohibit cwnd undoing, the reduction is required. */
	 //显示拥塞的情况，那就禁止撤销了
	if (ece_ack)
		tp->prior_ssthresh = 0;

	/* B. In all the states check for reneging SACKs. */
	//如果存在sack撤销且推进了una，则重新设置超时定时器，给发送放机会
	if (tcp_check_sack_reneging(sk, ack_flag))
		return;

	/* C. Check consistency of the current state. */
	tcp_verify_left_out(tp);

	/* D. Check state exit conditions. State can be terminated
	 *    when high_seq is ACKed. */
	if (icsk->icsk_ca_state == TCP_CA_Open) {
		WARN_ON(tp->retrans_out != 0 && !tp->syn_data);
		tp->retrans_stamp = 0;  //因为是open所以设置为0 合理
	//不是open的情况
	} else if (!before(tp->snd_una, tp->high_seq)) { //una已经推进到了high_seq的后面，那肯定尝试撤销了
		switch (icsk->icsk_ca_state) {
		case TCP_CA_CWR:
			/* CWR is to be held something *above* high_seq
			 * is ACKed for CWR bit to reach receiver. */
			if (tp->snd_una != tp->high_seq) { //确认指针超过了进入CWR时的序列号
				//传统TCP算法中，这个函数会将拥塞窗口重置到慢启动阈值，bbr例外
				tcp_end_cwnd_reduction(sk); 
				tcp_set_ca_state(sk, TCP_CA_Open); //TCP_CA_CWR ->OPEN
			}
			break;

		case TCP_CA_Recovery:
			if (tcp_is_reno(tp))
				tcp_reset_reno_sack(tp);
			//只要不是reno就返回false,如果满足撤销的标记（有撤销的标记，没有重传过数据包？且当前确认的数据包的时间戳比重传的数据包要早）
			//会更新慢启动阈值和拥塞窗口
			if (tcp_try_undo_recovery(sk))
				return;
			//设置拥塞窗口大小为慢启动阈值
			tcp_end_cwnd_reduction(sk);
			break;
		}
	}

	/* E. Process state. */
	switch (icsk->icsk_ca_state) {
	case TCP_CA_Recovery:
		//只是重复的ack 或者sack ？，如果是reno算法，相当于什么也不做，继续走
		if (!(flag & FLAG_SND_UNA_ADVANCED)) {
			if (tcp_is_reno(tp))
				tcp_add_reno_sack(sk, num_dupack, ece_ack);
			//走到这里表示确认了部分数据，那就要尝试是否可以撤销了不能撤销返回ture ！
			//这里返回fasle的话有可能变成open或者disorder 或者仍然是recovery
		} else if (tcp_try_undo_partial(sk, prior_snd_una, &do_lost)) 
			return;
		//收到部分数据包尝试是否可以撤销（重新设置慢启动阈值和拥塞窗口），如果返回ture，下面会变成open或者乱续状态
		//不太理解为什么叫基于dsack？
		if (tcp_try_undo_dsack(sk))
		//变成open或者乱续状态
			tcp_try_keep_open(sk);
		//通过rack标记丢包
		tcp_identify_packet_loss(sk, ack_flag);
		if (icsk->icsk_ca_state != TCP_CA_Recovery) {
			//如果有被标记丢失的数据包就会进入这个分支，比如上面撤销会清楚标记，rack检测可能重新打上标记
			if (!tcp_time_to_recover(sk, flag))//是否有被mark为loss的数据包
				return;
			/* Undo reverts the recovery state. If loss is evident,
			 * starts a new recovery (e.g. reordering then loss);
			 */
			//进入recovery状态，调用拥塞算法钩子计算慢启动阈值
			tcp_enter_recovery(sk, ece_ack);
		}
		break;
	case TCP_CA_Loss:
		//loss状态的处理，如果una被推进，可能恢复到open或者走frto流程
		tcp_process_loss(sk, flag, num_dupack, rexmit);
		tcp_identify_packet_loss(sk, ack_flag); //rack处理
		if (!(icsk->icsk_ca_state == TCP_CA_Open ||  //如果不是open状态 就直接return了
		      (*ack_flag & FLAG_LOST_RETRANS))) //rack逻辑会设置这个标记
			return;
		/* Change state if cwnd is undone or retransmits are lost */
		fallthrough;
	default:
		if (tcp_is_reno(tp)) {
			if (flag & FLAG_SND_UNA_ADVANCED)
				tcp_reset_reno_sack(tp);
			tcp_add_reno_sack(sk, num_dupack, ece_ack);
		}
		//如果是open或者乱序状态
		if (icsk->icsk_ca_state <= TCP_CA_Disorder)
			tcp_try_undo_dsack(sk);
		//基于rack标记是否丢失
		tcp_identify_packet_loss(sk, ack_flag);
		if (!tcp_time_to_recover(sk, flag)) { //是否需要进入recover状态！上面rack没有标记就会尝试回到open
			//如果这里没有返走，那就一定进入恢复状态了
			tcp_try_to_open(sk, flag);
			return;
		}

		/* MTU probe failure: don't reduce cwnd */
		if (icsk->icsk_ca_state < TCP_CA_CWR &&   //open或者乱续的情况
		    icsk->icsk_mtup.probe_size &&			//正在进行mtup
		    tp->snd_una == tp->mtu_probe.probe_seq_start) {  //探测的数据包还没有被u确认
			tcp_mtup_probe_failed(sk);   //记录MTU探测失败
			/* Restores the reduction we did in tcp_mtup_probe() */
			tcp_snd_cwnd_set(tp, tcp_snd_cwnd(tp) + 1);  //恢复一个探测窗口，合理
			tcp_simple_retransmit(sk); //基于mss，标记丢失，并重传 ，直接返回
			return;
		}

		/* Otherwise enter Recovery state */
		//如果不是TCP_CA_Recovery或者 TCP_CA_Loss 会进入
		tcp_enter_recovery(sk, ece_ack);
		fast_rexmit = 1;
	}

	if (!tcp_is_rack(sk) && do_lost)
		tcp_update_scoreboard(sk, fast_rexmit);
	*rexmit = REXMIT_LOST;
}

static void tcp_update_rtt_min(struct sock *sk, u32 rtt_us, const int flag)
{
	u32 wlen = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_min_rtt_wlen) * HZ; //300s
	struct tcp_sock *tp = tcp_sk(sk);
	//如果ACK可能被延迟且当前RTT大于已知最小RTT，则忽略此次测量 直接不更新了
	if ((flag & FLAG_ACK_MAYBE_DELAYED) && rtt_us > tcp_min_rtt(tp)) {
		/* If the remote keeps returning delayed ACKs, eventually
		 * the min filter would pick it up and overestimate the
		 * prop. delay when it expires. Skip suspected delayed ACKs.
		 */
		return;
	}
	//更新rttmin字段，rtt_min其实是一个长度为3的数组，每个数组有两个元素，分别是时间和值
	minmax_running_min(&tp->rtt_min, wlen, tcp_jiffies32,
			   rtt_us ? : jiffies_to_usecs(1));
}
//三次握手收到ack创建新的sock后会调用这个第3和第6个传入的值相同，flag为synack //清理重传队列中也会调用这个函数
static bool 	tcp_ack_update_rtt(struct sock *sk, const int flag,
			       long seq_rtt_us, long sack_rtt_us,
			       long ca_rtt_us, struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Prefer RTT measured from ACK's timing to TS-ECR. This is because
	 * broken middle-boxes or peers may corrupt TS-ECR fields. But
	 * Karn's algorithm forbids taking RTT if some retransmitted data
	 * is acked (RFC6298).
	 */
	//如果 seq_rtt_us无效则尝试使用sack_rtt_us（如果有 SACK 信息）
	if (seq_rtt_us < 0)
		seq_rtt_us = sack_rtt_us;

	/* RTTM Rule: A TSecr value received in a segment is used to
	 * update the averaged RTT measurement only if the segment
	 * acknowledges some new data, i.e., only if it advances the
	 * left edge of the send window.
	 * See draft-ietf-tcplw-high-performance-00, section 3.3.
	 */
	//如果基于序列号时间戳无效，则用时间戳选项计算（如果有的话），比如三次握手中是不会走这个分支的
	if (seq_rtt_us < 0 && tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
	    flag & FLAG_ACKED) {
		//当前的时间减去回显的时间
		u32 delta = tcp_time_stamp(tp) - tp->rx_opt.rcv_tsecr;
		//单位转换转换为微妙
		if (likely(delta < INT_MAX / (USEC_PER_SEC / TCP_TS_HZ))) {
			if (!delta)
				delta = 1;
			seq_rtt_us = delta * (USEC_PER_SEC / TCP_TS_HZ);
			ca_rtt_us = seq_rtt_us;
		}
	}
	//记录rtt的结果
	rs->rtt_us = ca_rtt_us; /* RTT of last (S)ACKed packet (or -1) */
	if (seq_rtt_us < 0)
		return false;

	/* ca_rtt_us >= 0 is counting on the invariant that ca_rtt_us is
	 * always taken together with ACK, SACK, or TS-opts. Any negative
	 * values will be skipped with the seq_rtt_us < 0 check above.
	 */
	//
	tcp_update_rtt_min(sk, ca_rtt_us, flag);
	//更新平滑 RTT（SRTT）
	tcp_rtt_estimator(sk, seq_rtt_us);
	//设置rto usecs_to_jiffies((tp->srtt_us >> 3) + tp->rttvar_us);
	tcp_set_rto(sk);

	/* RFC6298: only reset backoff on valid RTT measurement. */
	inet_csk(sk)->icsk_backoff = 0;
	return true;
}

/* Compute time elapsed between (last) SYNACK and the ACK completing 3WHS. */
void tcp_synack_rtt_meas(struct sock *sk, struct request_sock *req)
{
	struct rate_sample rs;
	long rtt_us = -1L;
	//如果没有重传过，则根据当当前时间(收到ack)和发送synack的时间计算一个rtt
	if (req && !req->num_retrans && tcp_rsk(req)->snt_synack)
		rtt_us = tcp_stamp_us_delta(tcp_clock_us(), tcp_rsk(req)->snt_synack);
	//注意这里的里标志是synack
	tcp_ack_update_rtt(sk, FLAG_SYN_ACKED, rtt_us, -1L, rtt_us, &rs);
}


static void tcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_ca_ops->cong_avoid(sk, ack, acked);
	tcp_sk(sk)->snd_cwnd_stamp = tcp_jiffies32;
}

/* Restart timer after forward progress on connection.
 * RFC2988 recommends to restart timer to now+rto.
 */
void tcp_rearm_rto(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* If the retrans timer is currently being used by Fast Open
	 * for SYN-ACK retrans purpose, stay put.
	 */
	if (rcu_access_pointer(tp->fastopen_rsk))
		return;

	if (!tp->packets_out) {
		inet_csk_clear_xmit_timer(sk, ICSK_TIME_RETRANS);
	} else {
		u32 rto = inet_csk(sk)->icsk_rto;
		/* Offset the time elapsed after installing regular RTO */
		if (icsk->icsk_pending == ICSK_TIME_REO_TIMEOUT ||
		    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE) {
			s64 delta_us = tcp_rto_delta_us(sk);
			/* delta_us may not be positive if the socket is locked
			 * when the retrans timer fires and is rescheduled.
			 */
			rto = usecs_to_jiffies(max_t(int, delta_us, 1));
		}
		tcp_reset_xmit_timer(sk, ICSK_TIME_RETRANS, rto,
				     TCP_RTO_MAX);
	}
}

/* Try to schedule a loss probe; if that doesn't work, then schedule an RTO. */
static void tcp_set_xmit_timer(struct sock *sk)
{
	if (!tcp_schedule_loss_probe(sk, true))
		tcp_rearm_rto(sk);
}

/* If we get here, the whole TSO packet has not been acked. */
static u32 tcp_tso_acked(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 packets_acked;

	BUG_ON(!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una));
	//记录数据包的段数
	packets_acked = tcp_skb_pcount(skb);
	if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
		return 0;
	packets_acked -= tcp_skb_pcount(skb);

	if (packets_acked) {
		BUG_ON(tcp_skb_pcount(skb) == 0);
		BUG_ON(!before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq));
	}

	return packets_acked;
}

static void tcp_ack_tstamp(struct sock *sk, struct sk_buff *skb,
			   const struct sk_buff *ack_skb, u32 prior_snd_una)
{
	const struct skb_shared_info *shinfo;

	/* Avoid cache line misses to get skb_shinfo() and shinfo->tx_flags */
	//判断这个 skb 是否请求了 ACK 时间戳通常是没有
	if (likely(!TCP_SKB_CB(skb)->txstamp_ack))
		return;

	shinfo = skb_shinfo(skb);
	if (!before(shinfo->tskey, prior_snd_una) &&
	    before(shinfo->tskey, tcp_sk(sk)->snd_una)) {
		tcp_skb_tsorted_save(skb) {
			__skb_tstamp_tx(skb, ack_skb, NULL, sk, SCM_TSTAMP_ACK);
		} tcp_skb_tsorted_restore(skb);
	}
}

/* Remove acknowledged frames from the retransmission queue. If our packet
 * is before the ack sequence we can discard it as it's confirmed to have
 * arrived at the other end.
 */
static int tcp_clean_rtx_queue(struct sock *sk, const struct sk_buff *ack_skb,
			       u32 prior_fack, u32 prior_snd_una,
			       struct tcp_sacktag_state *sack, bool ece_ack)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u64 first_ackt, last_ackt;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 prior_sacked = tp->sacked_out;
	u32 reord = tp->snd_nxt; /* lowest acked un-retx un-sacked seq */
	struct sk_buff *skb, *next;
	bool fully_acked = true;
	long sack_rtt_us = -1L;
	long seq_rtt_us = -1L;
	long ca_rtt_us = -1L;
	u32 pkts_acked = 0;
	bool rtt_update;
	int flag = 0;

	first_ackt = 0;
	//遍历重传队列
	for (skb = skb_rb_first(&sk->tcp_rtx_queue); skb; skb = next) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		const u32 start_seq = scb->seq;
		u8 sacked = scb->sacked;
		u32 acked_pcount;

		/* Determine how many packets and what bytes were acked, tso and else */
		//结束序列号大于una 可能是部分确认
		if (after(scb->end_seq, tp->snd_una)) {
			//只有一个段，或者una在seq前面则直接break
			if (tcp_skb_pcount(skb) == 1 ||
			    !after(tp->snd_una, scb->seq))
				break;
			//部分确认的情况，直接trim数据包 ,返回0表示无法trim直接break
			acked_pcount = tcp_tso_acked(sk, skb);
			if (!acked_pcount)
				break;
			fully_acked = false;
		} else { //整个包都被确认过，直接计算ack计数
			acked_pcount = tcp_skb_pcount(skb);
		}
		//这个数据包被重传过
		if (unlikely(sacked & TCPCB_RETRANS)) {
			if (sacked & TCPCB_SACKED_RETRANS)	//也是表示重传过，有这个表示明确加过下面的计数
				tp->retrans_out -= acked_pcount;//更新重传出去的包数 
			flag |= FLAG_RETRANS_DATA_ACKED;
		} else if (!(sacked & TCPCB_SACKED_ACKED)) {//没被重传过，也没有被sack确认过
			last_ackt = tcp_skb_timestamp_us(skb); //获取数据包的发送时间戳
			WARN_ON_ONCE(last_ackt == 0);
			if (!first_ackt)			//记录本轮清理的第一个被确认的skb
				first_ackt = last_ackt;
			//记录本次被确认的原始数据里，最靠前的起始 seq （
			// 后面如果发现 reord 比之前的 prior_fack 还靠前，通常用来推断 发生了乱序）
			if (before(start_seq, reord))
				reord = start_seq;
			//其实就是确认了拥塞发送时候之前的数据，表示确认了原始的数据？
			if (!after(scb->end_seq, tp->high_seq))
				flag |= FLAG_ORIG_SACK_ACKED;
		}
		//被sack确认过
		if (sacked & TCPCB_SACKED_ACKED) {
			tp->sacked_out -= acked_pcount;
		//更新交付的数量，同时如果不是虚假重传的话，
		} else if (tcp_is_sack(tp)) {
			tcp_count_delivered(tp, acked_pcount, ece_ack);
			if (!tcp_skb_spurious_retrans(tp, skb))
				//决定是否启用rack，最后一个参数表示发送出去的时间戳
				tcp_rack_advance(tp, sacked, scb->end_seq,
						 tcp_skb_timestamp_us(skb));
		}
		//之前认为丢失但是现在确认了，修正待重传的丢包数量
		if (sacked & TCPCB_LOST)
			tp->lost_out -= acked_pcount;
		//更新发送出去还没有接收到ack的数量
		tp->packets_out -= acked_pcount;
		//累计确认了多少个段
		pkts_acked += acked_pcount;
		//bbr算法使用的字段
		tcp_rate_skb_delivered(sk, skb, sack->rate);

		/* Initial outgoing SYN's get put onto the write_queue
		 * just like anything else we transmit.  It is not
		 * true data, and if we misinform our callers that
		 * this ACK acks real data, we will erroneously exit
		 * connection startup slow start one packet too
		 * quickly.  This is severely frowned upon behavior.
		 */
		//不是syn包
		if (likely(!(scb->tcp_flags & TCPHDR_SYN))) {
			flag |= FLAG_DATA_ACKED;
		} else {
			flag |= FLAG_SYN_ACKED;
			tp->retrans_stamp = 0;
		}
		//注意如果不是整个包确认这里直接break
		if (!fully_acked)
			break;
		//用户态是否需要拿到整个数据包的时间戳？
		tcp_ack_tstamp(sk, skb, ack_skb, prior_snd_una);

		next = skb_rb_next(skb);
		if (unlikely(skb == tp->retransmit_skb_hint))
			tp->retransmit_skb_hint = NULL;
		if (unlikely(skb == tp->lost_skb_hint))
			tp->lost_skb_hint = NULL;
		tcp_highest_sack_replace(sk, skb, next);
		//从重传队列中移除
		tcp_rtx_queue_unlink_and_free(skb, sk);
	}

	if (!skb)
		//状态的计时器
		tcp_chrono_stop(sk, TCP_CHRONO_BUSY);
	//更新紧急指针发送边界，没什么用
	if (likely(between(tp->snd_up, prior_snd_una, tp->snd_una)))
		tp->snd_up = tp->snd_una;

	if (skb) {
		tcp_ack_tstamp(sk, skb, ack_skb, prior_snd_una);
		//这里处理sack 反悔的情况，没太理解
		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
			flag |= FLAG_SACK_RENEGING;
	}
	//确认了原始发送的数据，并且没有重传过的数据
	if (likely(first_ackt) && !(flag & FLAG_RETRANS_DATA_ACKED)) {
		//这里是获取两个计算rtt的样本，分别用当前的时间减去，第一个被确认的skb和最后一个被确认的skb
		seq_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, first_ackt);
		ca_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, last_ackt);

		if (pkts_acked == 1 && fully_acked && !prior_sacked &&
		    (tp->snd_una - prior_snd_una) < tp->mss_cache &&
		    sack->rate->prior_delivered + 1 == tp->delivered &&
		    !(flag & (FLAG_CA_ALERT | FLAG_SYN_ACKED))) {
			/* Conservatively mark a delayed ACK. It's typically
			 * from a lone runt packet over the round trip to
			 * a receiver w/o out-of-order or CE events.
			 */
			flag |= FLAG_ACK_MAYBE_DELAYED;
		}
	}
	//和上面类似，只不过这里是用sack的信息生成rtt样本
	if (sack->first_sackt) { //tcp_sacktag_one 中设置的
		sack_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, sack->first_sackt);
		ca_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, sack->last_sackt);
	}
	//计算平滑rtt和rto 和三次握手一样注意这里参数不一样
	rtt_update = tcp_ack_update_rtt(sk, flag, seq_rtt_us, sack_rtt_us,
					ca_rtt_us, sack->rate);
	//如果ack确认了新数据
	if (flag & FLAG_ACKED) {
		flag |= FLAG_SET_XMIT_TIMER;  /* set TLP or RTO timer */
		//mtu探测成功！
		if (unlikely(icsk->icsk_mtup.probe_size &&
			     !after(tp->mtu_probe.probe_seq_end, tp->snd_una))) {
			tcp_mtup_probe_success(sk);
		}
		//这里通常不进入
		if (tcp_is_reno(tp)) {
			tcp_remove_reno_sacks(sk, pkts_acked, ece_ack);

			/* If any of the cumulatively ACKed segments was
			 * retransmitted, non-SACK case cannot confirm that
			 * progress was due to original transmission due to
			 * lack of TCPCB_SACKED_ACKED bits even if some of
			 * the packets may have been never retransmitted.
			 */
			if (flag & FLAG_RETRANS_DATA_ACKED)
				flag &= ~FLAG_ORIG_SACK_ACKED;
		} else {
			int delta;

			/* Non-retransmitted hole got filled? That's reordering */
		//之前 SACK 认为后面已经收到，现在累计 ACK 却回过头来确认了一个更靠前的洞，就是更新乱序阈值！！
			if (before(reord, prior_fack))
				tcp_check_sack_reordering(sk, reord, 0);

			delta = prior_sacked - tp->sacked_out;
			tp->lost_cnt_hint -= min(tp->lost_cnt_hint, delta);
		}
	//如果ack没有确认新数据
	} else if (skb && rtt_update && sack_rtt_us >= 0 &&
		   sack_rtt_us > tcp_stamp_us_delta(tp->tcp_mstamp,
						    tcp_skb_timestamp_us(skb))) {
		/* Do not re-arm RTO if the sack RTT is measured from data sent
		 * after when the head was last (re)transmitted. Otherwise the
		 * timeout may continue to extend in loss recovery.
		 */
		flag |= FLAG_SET_XMIT_TIMER;  /* set TLP or RTO timer */
	}
	//是否有拥塞算法的钩子，vegas 有这个钩子
	if (icsk->icsk_ca_ops->pkts_acked) {
		struct ack_sample sample = { .pkts_acked = pkts_acked,
					     .rtt_us = sack->rate->rtt_us };

		sample.in_flight = tp->mss_cache *
			(tp->delivered - sack->rate->prior_delivered);
		icsk->icsk_ca_ops->pkts_acked(sk, &sample);
	}

#if FASTRETRANS_DEBUG > 0
	WARN_ON((int)tp->sacked_out < 0);
	WARN_ON((int)tp->lost_out < 0);
	WARN_ON((int)tp->retrans_out < 0);
	if (!tp->packets_out && tcp_is_sack(tp)) {
		icsk = inet_csk(sk);
		if (tp->lost_out) {
			pr_debug("Leak l=%u %d\n",
				 tp->lost_out, icsk->icsk_ca_state);
			tp->lost_out = 0;
		}
		if (tp->sacked_out) {
			pr_debug("Leak s=%u %d\n",
				 tp->sacked_out, icsk->icsk_ca_state);
			tp->sacked_out = 0;
		}
		if (tp->retrans_out) {
			pr_debug("Leak r=%u %d\n",
				 tp->retrans_out, icsk->icsk_ca_state);
			tp->retrans_out = 0;
		}
	}
#endif
	return flag;
}

static void tcp_ack_probe(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *head = tcp_send_head(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Was it a usable window open? */
	if (!head)
		return;
	if (!after(TCP_SKB_CB(head)->end_seq, tcp_wnd_end(tp))) {
		icsk->icsk_backoff = 0;
		icsk->icsk_probes_tstamp = 0;
		inet_csk_clear_xmit_timer(sk, ICSK_TIME_PROBE0);
		/* Socket must be waked up by subsequent tcp_data_snd_check().
		 * This function is not for random using!
		 */
	} else {
		//窗口不够用了
		unsigned long when = tcp_probe0_when(sk, TCP_RTO_MAX);

		when = tcp_clamp_probe0_to_user_timeout(sk, when);
		tcp_reset_xmit_timer(sk, ICSK_TIME_PROBE0, when, TCP_RTO_MAX);
	}
}

static inline bool tcp_ack_is_dubious(const struct sock *sk, const int flag)
{	//没有确认数据，窗口更新 ，是纯ack            //是sack 或者dsack 
	return !(flag & FLAG_NOT_DUP) || (flag & FLAG_CA_ALERT) ||
		inet_csk(sk)->icsk_ca_state != TCP_CA_Open; //不是open状态
}

/* Decide wheather to run the increase function of congestion control. */
static inline bool tcp_may_raise_cwnd(const struct sock *sk, const int flag)
{
	/* If reordering is high then always grow cwnd whenever data is
	 * delivered regardless of its ordering. Otherwise stay conservative
	 * and only grow cwnd on in-order delivery (RFC5681). A stretched ACK w/
	 * new SACK or ECE mark may first advance cwnd here and later reduce
	 * cwnd in tcp_fastretrans_alert() based on more states.
	 */
	if (tcp_sk(sk)->reordering >
	    READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_reordering))
		return flag & FLAG_FORWARD_PROGRESS;

	return flag & FLAG_DATA_ACKED;
}

/* The "ultimate" congestion control function that aims to replace the rigid
 * cwnd increase and decrease control (tcp_cong_avoid,tcp_*cwnd_reduction).
 * It's called toward the end of processing an ACK with precise rate
 * information. All transmission or retransmission are delayed afterwards.
 */
static void tcp_cong_control(struct sock *sk, u32 ack, u32 acked_sacked,
			     int flag, const struct rate_sample *rs)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	//调用拥塞算法的钩子，bbr会用到
	if (icsk->icsk_ca_ops->cong_control) {
		icsk->icsk_ca_ops->cong_control(sk, rs);
		return;
	}
	//拥塞状态
	if (tcp_in_cwnd_reduction(sk)) {
		/* Reduce cwnd if state mandates */
		tcp_cwnd_reduction(sk, acked_sacked, rs->losses, flag);
	} else if (tcp_may_raise_cwnd(sk, flag)) {//乱需严重可能提升拥塞窗口
		/* Advance cwnd if state allows */
		//拥塞避免的钩子
		tcp_cong_avoid(sk, ack, acked_sacked);
	}
	//更新pacing速率
	tcp_update_pacing_rate(sk);
}

/* Check that window update is acceptable.
 * The function assumes that snd_una<=ack<=snd_next.
 */
static inline bool tcp_may_update_window(const struct tcp_sock *tp,
					const u32 ack, const u32 ack_seq,
					const u32 nwin)
{
	return	after(ack, tp->snd_una) ||  //ACK 前进
		after(ack_seq, tp->snd_wl1) ||	//ACK 没前进 但 Seq 前进
		(ack_seq == tp->snd_wl1 && (nwin > tp->snd_wnd || !nwin)); //相桶，但窗口增大或变为0
}

/* If we update tp->snd_una, also update tp->bytes_acked */
static void tcp_snd_una_update(struct tcp_sock *tp, u32 ack)
{
	u32 delta = ack - tp->snd_una;

	sock_owned_by_me((struct sock *)tp);
	tp->bytes_acked += delta;
	tp->snd_una = ack;
}

/* If we update tp->rcv_nxt, also update tp->bytes_received */
static void tcp_rcv_nxt_update(struct tcp_sock *tp, u32 seq)
{
	u32 delta = seq - tp->rcv_nxt;

	sock_owned_by_me((struct sock *)tp);
	tp->bytes_received += delta;
	WRITE_ONCE(tp->rcv_nxt, seq);
}

/* Update our send window.
 *
 * Window update algorithm, described in RFC793/RFC1122 (used in linux-2.2
 * and in FreeBSD. NetBSD's one is even worse.) is wrong.
 */
static int tcp_ack_update_window(struct sock *sk, const struct sk_buff *skb, u32 ack,
				 u32 ack_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int flag = 0;
	u32 nwin = ntohs(tcp_hdr(skb)->window); //ack报文中通告的窗口大小
	//不是syn包计算窗口缩放后的大小，因为syn包没有窗口缩放
	if (likely(!tcp_hdr(skb)->syn))
		nwin <<= tp->rx_opt.snd_wscale;
	//判断是否允许窗口更新
	if (tcp_may_update_window(tp, ack, ack_seq, nwin)) {
		flag |= FLAG_WIN_UPDATE; 		 //更新了发送窗口
		tcp_update_wl(tp, ack_seq); //记录更新发送窗口的序列号 
		//不同就更新窗口
		if (tp->snd_wnd != nwin) {
			tp->snd_wnd = nwin;

			/* Note, it is the only place, where
			 * fast path is recovered for sending TCP.
			 */
			//注意发送恢复fast path的唯一位置
			tp->pred_flags = 0;
			//是否切换到fast的path
			tcp_fast_path_check(sk);
			//如果发送队列是空，则判断是否慢启动(由系统参数，拥塞算法等决定)
			if (!tcp_write_queue_empty(sk))
				tcp_slow_start_after_idle_check(sk);
			//更新最大值
			if (nwin > tp->max_window) {
				tp->max_window = nwin;
				//计算mss
				tcp_sync_mss(sk, inet_csk(sk)->icsk_pmtu_cookie);
			}
		}
	}
	//更新snd_una 以及确认的byte数
	tcp_snd_una_update(tp, ack);

	return flag;
}

static bool __tcp_oow_rate_limited(struct net *net, int mib_idx,
				   u32 *last_oow_ack_time)
{
	/* Paired with the WRITE_ONCE() in this function. */
	u32 val = READ_ONCE(*last_oow_ack_time);

	if (val) {
		s32 elapsed = (s32)(tcp_jiffies32 - val);

		if (0 <= elapsed &&
			//读取系统参数并和上面的间隔比较 这个系统参数默认是500毫秒
		    elapsed < READ_ONCE(net->ipv4.sysctl_tcp_invalid_ratelimit)) {
			NET_INC_STATS(net, mib_idx);
			//收到限制
			return true;	/* rate-limited: don't send yet! */
		}
	}

	/* Paired with the prior READ_ONCE() and with itself,
	 * as we might be lockless.
	 */
	//更新这个值
	WRITE_ONCE(*last_oow_ack_time, tcp_jiffies32);
	//没有限制
	return false;	/* not rate-limited: go ahead, send dupack now! */
}

/* Return true if we're currently rate-limiting out-of-window ACKs and
 * thus shouldn't send a dupack right now. We rate-limit dupacks in
 * response to out-of-window SYNs or ACKs to mitigate ACK loops or DoS
 * attacks that send repeated SYNs or ACKs for the same connection. To
 * do this, we do not send a duplicate SYNACK or ACK if the remote
 * endpoint is sending out-of-window SYNs or pure ACKs at a high rate.
 */
//限制对 SYN 或 ACK 包的重复响应
bool tcp_oow_rate_limited(struct net *net, const struct sk_buff *skb,
			  int mib_idx, u32 *last_oow_ack_time)
{
	/* Data packets without SYNs are not likely part of an ACK loop. */
	//对于有数据包，且不是syn包直接返回false
	if ((TCP_SKB_CB(skb)->seq != TCP_SKB_CB(skb)->end_seq) &&
	    !tcp_hdr(skb)->syn)
		return false;
	//是否需要限制的检查
	return __tcp_oow_rate_limited(net, mib_idx, last_oow_ack_time);
}

/* RFC 5961 7 [ACK Throttling] */
static void tcp_send_challenge_ack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	u32 count, now, ack_limit;

	/* First check our per-socket dupack rate limit. */
	if (__tcp_oow_rate_limited(net,
				   LINUX_MIB_TCPACKSKIPPEDCHALLENGE,
				   &tp->last_oow_ack_time))
		return;

	ack_limit = READ_ONCE(net->ipv4.sysctl_tcp_challenge_ack_limit);
	if (ack_limit == INT_MAX)
		goto send_ack;

	/* Then check host-wide RFC 5961 rate limit. */
	now = jiffies / HZ;
	if (now != READ_ONCE(net->ipv4.tcp_challenge_timestamp)) {
		u32 half = (ack_limit + 1) >> 1;

		WRITE_ONCE(net->ipv4.tcp_challenge_timestamp, now);
		WRITE_ONCE(net->ipv4.tcp_challenge_count,
			   get_random_u32_inclusive(half, ack_limit + half - 1));
	}
	count = READ_ONCE(net->ipv4.tcp_challenge_count);
	if (count > 0) {
		WRITE_ONCE(net->ipv4.tcp_challenge_count, count - 1);
send_ack:
		NET_INC_STATS(net, LINUX_MIB_TCPCHALLENGEACK);
		tcp_send_ack(sk);
	}
}

static void tcp_store_ts_recent(struct tcp_sock *tp)
{
	tp->rx_opt.ts_recent = tp->rx_opt.rcv_tsval;
	tp->rx_opt.ts_recent_stamp = ktime_get_seconds();
}

static void tcp_replace_ts_recent(struct tcp_sock *tp, u32 seq)
{
	//进入这个分支应该是处理异常的数据包，小心的更新时间戳？
	if (tp->rx_opt.saw_tstamp && !after(seq, tp->rcv_wup)) {
		/* PAWS bug workaround wrt. ACK frames, the PAWS discard
		 * extra check below makes sure this can only happen
		 * for pure ACK frames.  -DaveM
		 *
		 * Not only, also it occurs for expired timestamps.
		 */

		if (tcp_paws_check(&tp->rx_opt, 0))
			tcp_store_ts_recent(tp);
	}
}

/* This routine deals with acks during a TLP episode and ends an episode by
 * resetting tlp_high_seq. Ref: TLP algorithm in draft-ietf-tcpm-rack
 */
//tcp_ack中被调用
static void tcp_process_tlp_ack(struct sock *sk, u32 ack, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//没有确认到tlp的序列号，直接返回
	if (before(ack, tp->tlp_high_seq))
		return;

	if (!tp->tlp_retrans) {
		/* TLP of new data has been acknowledged */
		//TLP探测的是新数据
		tp->tlp_high_seq = 0;
	} else if (flag & FLAG_DSACK_TLP) {//收到了tlp包的重复ack
		/* This DSACK means original and TLP probe arrived; no loss */
		tp->tlp_high_seq = 0;
	//表示确实发生了丢包，这里有点疑惑，不是有可能也是延迟的情况吗？是不是因为上面没有回复sack？？
	} else if (after(ack, tp->tlp_high_seq)) {
		/* ACK advances: there was a loss, so reduce cwnd. Reset
		 * tlp_high_seq in tcp_init_cwnd_reduction()
		 */
		tcp_init_cwnd_reduction(sk);
		tcp_set_ca_state(sk, TCP_CA_CWR); //将状态设置为cwr
		tcp_end_cwnd_reduction(sk);
		tcp_try_keep_open(sk);
		NET_INC_STATS(sock_net(sk),
				LINUX_MIB_TCPLOSSPROBERECOVERY);
	//单纯的重复ack，没有推进窗口，表示就单纯的收到一个重复ack
	} else if (!(flag & (FLAG_SND_UNA_ADVANCED |
			     FLAG_NOT_DUP | FLAG_DATA_SACKED))) {
		/* Pure dupack: original and TLP probe arrived; no loss */
		tp->tlp_high_seq = 0;
	}
}

static inline void tcp_in_ack_event(struct sock *sk, u32 flags)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_ops->in_ack_event)
		icsk->icsk_ca_ops->in_ack_event(sk, flags);
}

/* Congestion control has updated the cwnd already. So if we're in
 * loss recovery then now we do any new sends (for FRTO) or
 * retransmits (for CA_Loss or CA_recovery) that make sense.
 */
static void tcp_xmit_recovery(struct sock *sk, int rexmit)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (rexmit == REXMIT_NONE || sk->sk_state == TCP_SYN_SENT)
		return;
	//根据拥塞处理的结果 决定是否从发送队列中发送数据包
	if (unlikely(rexmit == REXMIT_NEW)) {
		__tcp_push_pending_frames(sk, tcp_current_mss(sk),
					  TCP_NAGLE_OFF);
		if (after(tp->snd_nxt, tp->high_seq))
			return;
		tp->frto = 0;
	}
	//从重传队列中发送数据包
	tcp_xmit_retransmit_queue(sk);
}

/* Returns the number of packets newly acked or sacked by the current ACK */
static u32 tcp_newly_delivered(struct sock *sk, u32 prior_delivered, int flag)
{
	const struct net *net = sock_net(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 delivered;

	delivered = tp->delivered - prior_delivered;
	NET_ADD_STATS(net, LINUX_MIB_TCPDELIVERED, delivered);
	if (flag & FLAG_ECE)
		NET_ADD_STATS(net, LINUX_MIB_TCPDELIVEREDCE, delivered);

	return delivered;
}

/* This routine deals with incoming acks, but not outgoing ones. */
static int tcp_ack(struct sock *sk, const struct sk_buff *skb, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sacktag_state sack_state;
	struct rate_sample rs = { .prior_delivered = 0 };
	u32 prior_snd_una = tp->snd_una; //已经发送未被确认的序列号
	bool is_sack_reneg = tp->is_sack_reneg; //是否是sack反悔
	u32 ack_seq = TCP_SKB_CB(skb)->seq; //提取数据包的序号
	u32 ack = TCP_SKB_CB(skb)->ack_seq;///提取当前数据包确认的序列号
	int num_dupack = 0;
	int prior_packets = tp->packets_out; //发送出去没有被ack的数量
	u32 delivered = tp->delivered;		//被确认的ack总数
	u32 lost = tp->lost;				//历史丢包数
	int rexmit = REXMIT_NONE; /* Flag to (re)transmit to recover losses *///是否需要重传的标记
	u32 prior_fack;

	sack_state.first_sackt = 0;
	sack_state.rate = &rs;
	sack_state.sack_delivered = 0;

	/* We very likely will need to access rtx queue. */
	//预取
	prefetch(sk->tcp_rtx_queue.rb_node);

	/* If the ack is older than previous acks
	 * then we can probably ignore it.
	 */
	//当前确认的序列号在una之前
	if (before(ack, prior_snd_una)) {
		/* RFC 5961 5.2 [Blind Data Injection Attack].[Mitigation] */
		//这个ack太老了(可能是注入攻击)，比往前算一个窗口还要小，那就回一个挑战ack
		if (before(ack, prior_snd_una - tp->max_window)) {
			if (!(flag & FLAG_NO_CHALLENGE_ACK))
				tcp_send_challenge_ack(sk);//这里可不会真正的发送ack
			return -SKB_DROP_REASON_TCP_TOO_OLD_ACK;
		}
		goto old_ack; //返回0，外面可能也会回复挑战ack
	}

	/* If the ack includes data we haven't sent yet, discard
	 * this segment (RFC793 Section 3.9).
	 */
	//太超前了
	if (after(ack, tp->snd_nxt))
		return -SKB_DROP_REASON_TCP_ACK_UNSENT_DATA;
	//确认了新数据
	if (after(ack, prior_snd_una)) {
		flag |= FLAG_SND_UNA_ADVANCED; //设置推进ack标志了，下面会用到
		icsk->icsk_retransmits = 0;    //重传清零

#if IS_ENABLED(CONFIG_TLS_DEVICE)
		if (static_branch_unlikely(&clean_acked_data_enabled.key))
			if (icsk->icsk_clean_acked)
				icsk->icsk_clean_acked(sk, ack);
#endif
	}
	//返回una或者sack最高的序列号
	prior_fack = tcp_is_sack(tp) ? tcp_highest_sack_seq(tp) : tp->snd_una;
	//设置在途数据包数
	rs.prior_in_flight = tcp_packets_in_flight(tp);
	/* ts_recent update must be made after we are sure that the packet
	 * is in window.
	 */
	//slowpath会设置这个标志，这里会通过PAWS检查后更新时间戳
	if (flag & FLAG_UPDATE_TS_RECENT)
		tcp_replace_ts_recent(tp, TCP_SKB_CB(skb)->seq);
	//这里是fastpath
	if ((flag & (FLAG_SLOWPATH | FLAG_SND_UNA_ADVANCED)) ==
	    FLAG_SND_UNA_ADVANCED) {
		/* Window is constant, pure forward advance.
		 * No more checks are required.
		 * Note, we use the fact that SND.UNA>=SND.WL2.
		 */
		//更新发送窗口更新时候的序列号，第二个参数是数据包的序号
		tcp_update_wl(tp, ack_seq);
		//更新una和确认的字节数
		tcp_snd_una_update(tp, ack);
		//设置更新窗口标志位
		flag |= FLAG_WIN_UPDATE;
		//调用拥塞算法钩子，如果有
		tcp_in_ack_event(sk, CA_ACK_WIN_UPDATE);

		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPHPACKS);
	//这里是走slowpah
	} else {
		u32 ack_ev_flags = CA_ACK_SLOWPATH;
		//标记数据包是否携带数据
		if (ack_seq != TCP_SKB_CB(skb)->end_seq)
			flag |= FLAG_DATA;
		else
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPPUREACKS);
		//这里的第三个参数是确认号， 第四个参数ack_seq是报文的序列号
		flag |= tcp_ack_update_window(sk, skb, ack, ack_seq);
		//处理sack
		if (TCP_SKB_CB(skb)->sacked)
			flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una,
							&sack_state);
		//发生了拥塞，设置标志位
		if (tcp_ecn_rcv_ecn_echo(tp, tcp_hdr(skb))) {
			flag |= FLAG_ECE;
			ack_ev_flags |= CA_ACK_ECE;
		}
		//有sack确认的段数，需要更新确认的总数，合理
		if (sack_state.sack_delivered)
			tcp_count_delivered(tp, sack_state.sack_delivered,
					    flag & FLAG_ECE);
		//窗口是否推进了
		if (flag & FLAG_WIN_UPDATE)
			ack_ev_flags |= CA_ACK_WIN_UPDATE;
		//调用拥塞算法的钩子
		tcp_in_ack_event(sk, ack_ev_flags);
	}

	/* This is a deviation from RFC3168 since it states that:
	 * "When the TCP data sender is ready to set the CWR bit after reducing
	 * the congestion window, it SHOULD set the CWR bit only on the first
	 * new data packet that it transmits."
	 * We accept CWR on pure ACKs to be more robust
	 * with widely-deployed TCP implementations that do this.
	 */
	//如果是显示拥塞，这里立即设置回复ack的标志位，因为发送端窗口已经很小了，需要立即回复ack
	tcp_ecn_accept_cwr(sk, skb);

	/* We passed data and got it acked, remove any soft error
	 * log. Something worked...
	 */
	WRITE_ONCE(sk->sk_err_soft, 0);
	icsk->icsk_probes_out = 0;
	tp->rcv_tstamp = tcp_jiffies32;
	if (!prior_packets)
		goto no_queue;

	/* See if we can take anything off of the retransmit queue. */
	//清重传队列
	flag |= tcp_clean_rtx_queue(sk, skb, prior_fack, prior_snd_una,
				    &sack_state, flag & FLAG_ECE);
	//根据sack的处理来调整乱续增长因子进而影响丢包判断
	tcp_rack_update_reo_wnd(sk, &rs);

	if (tp->tlp_high_seq)
		tcp_process_tlp_ack(sk, ack, flag); 
	//当前ack是否可疑（	没有确认数据，窗口更新 纯ack sack 或者dsack ）
	if (tcp_ack_is_dubious(sk, flag)) {
		//是否是一个纯粹的重复ack（没有确认新数据）
		if (!(flag & (FLAG_SND_UNA_ADVANCED | 
			      FLAG_NOT_DUP | FLAG_DSACKING_ACK))) {
			num_dupack = 1;
			/* Consider if pure acks were aggregated in tcp_add_backlog() */
			//统计纯ack的计数，注意这里协议站可能会聚合纯ack
			if (!(flag & FLAG_DATA)) 
				num_dupack = max_t(u16, 1, skb_shinfo(skb)->gso_segs);
		}
		//传入的是snd_una, 重复ack的数量，ack的标志位 ，传入传出rexmit会指导下面的重传
		tcp_fastretrans_alert(sk, prior_snd_una, num_dupack, &flag,
				      &rexmit);
	}

	/* If needed, reset TLP/RTO timer when RACK doesn't set. */
	//在清理重传队列的时候可能会设置上这个标志位，比如有新的数据包被确认的时候，或者检测到乱续或者丢包 肯定需要重新设置这个定时器了
	if (flag & FLAG_SET_XMIT_TIMER)
		tcp_set_xmit_timer(sk);
		//这里会更新arp表的状态
	if ((flag & FLAG_FORWARD_PROGRESS) || !(flag & FLAG_NOT_DUP))
		sk_dst_confirm(sk);
	//更新统计字段累计收到了多少包
	delivered = tcp_newly_delivered(sk, delivered, flag);
	//更新丢包总数
	lost = tp->lost - lost;			/* freshly marked lost */
	rs.is_ack_delayed = !!(flag & FLAG_ACK_MAYBE_DELAYED);
	//更新bbr算法用到的字段
	tcp_rate_gen(sk, delivered, lost, is_sack_reneg, sack_state.rate);
	tcp_cong_control(sk, ack, delivered, flag, sack_state.rate);
	tcp_xmit_recovery(sk, rexmit);
	return 1;

no_queue:
	/* If data was DSACKed, see if we can undo a cwnd reduction. */
	if (flag & FLAG_DSACKING_ACK) {
		tcp_fastretrans_alert(sk, prior_snd_una, num_dupack, &flag,
				      &rexmit);
		////更新统计字段累计收到了多少包
		tcp_newly_delivered(sk, delivered, flag);
	}
	/* If this ack opens up a zero window, clear backoff.  It was
	 * being used to time the probes, and is probably far higher than
	 * it needs to be for normal retransmission.
	 */
	tcp_ack_probe(sk);

	if (tp->tlp_high_seq)
		tcp_process_tlp_ack(sk, ack, flag);
	return 1;

old_ack:
	/* If data was SACKed, tag it and see if we should send more data.
	 * If data was DSACKed, see if we can undo a cwnd reduction.
	 */
	if (TCP_SKB_CB(skb)->sacked) {
		flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una,
						&sack_state);
		tcp_fastretrans_alert(sk, prior_snd_una, num_dupack, &flag,
				      &rexmit);
		tcp_newly_delivered(sk, delivered, flag);
		tcp_xmit_recovery(sk, rexmit);
	}

	return 0;
}

static void tcp_parse_fastopen_option(int len, const unsigned char *cookie,
				      bool syn, struct tcp_fastopen_cookie *foc,
				      bool exp_opt)
{
	/* Valid only in SYN or SYN-ACK with an even length.  */
	if (!foc || !syn || len < 0 || (len & 1))
		return;

	if (len >= TCP_FASTOPEN_COOKIE_MIN &&
	    len <= TCP_FASTOPEN_COOKIE_MAX)
		memcpy(foc->val, cookie, len);
	else if (len != 0)
		len = -1;
	foc->len = len;
	foc->exp = exp_opt;
}

static bool smc_parse_options(const struct tcphdr *th,
			      struct tcp_options_received *opt_rx,
			      const unsigned char *ptr,
			      int opsize)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (th->syn && !(opsize & 1) &&
		    opsize >= TCPOLEN_EXP_SMC_BASE &&
		    get_unaligned_be32(ptr) == TCPOPT_SMC_MAGIC) {
			opt_rx->smc_ok = 1;
			return true;
		}
	}
#endif
	return false;
}

/* Try to parse the MSS option from the TCP header. Return 0 on failure, clamped
 * value on success.
 */
u16 tcp_parse_mss_option(const struct tcphdr *th, u16 user_mss)
{
	const unsigned char *ptr = (const unsigned char *)(th + 1);
	int length = (th->doff * 4) - sizeof(struct tcphdr);
	u16 mss = 0;

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return mss;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			if (length < 2)
				return mss;
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				return mss;
			if (opsize > length)
				return mss;	/* fail on partial options */
			if (opcode == TCPOPT_MSS && opsize == TCPOLEN_MSS) {
				u16 in_mss = get_unaligned_be16(ptr);

				if (in_mss) {
					if (user_mss && user_mss < in_mss)
						in_mss = user_mss;
					mss = in_mss;
				}
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}
	return mss;
}
EXPORT_SYMBOL_GPL(tcp_parse_mss_option);

/* Look for tcp options. Normally only called on SYN and SYNACK packets.
 * But, this can also be called on packets in the established flow when
 * the fast version below fails.
 */
void tcp_parse_options(const struct net *net,
		       const struct sk_buff *skb,
		       struct tcp_options_received *opt_rx, int estab,
		       struct tcp_fastopen_cookie *foc)
{
	const unsigned char *ptr;
	const struct tcphdr *th = tcp_hdr(skb);
	//计算选项的长度
	int length = (th->doff * 4) - sizeof(struct tcphdr);
	//指向选项的起始位置
	ptr = (const unsigned char *)(th + 1);
	opt_rx->saw_tstamp = 0;
	opt_rx->saw_unknown = 0;
	//TLV
	while (length > 0) {
		int opcode = *ptr++; //读取kind
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:   //选项结束直接return
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */ //占位 continue
			length--;
			continue;
		default:
			if (length < 2)  //剩余长度不够了 直接retunr
				return;
			opsize = *ptr++; //这个就是length
			if (opsize < 2) /* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			switch (opcode) {
			case TCPOPT_MSS://2表示mss
				if (opsize == TCPOLEN_MSS && th->syn && !estab) {//长度必须是4，且是syn包不在est
					u16 in_mss = get_unaligned_be16(ptr);//这个就是对端通告的mss大小！
					if (in_mss) {
						if (opt_rx->user_mss && //用户如果设置了mss就比较一下选择哪个
						    opt_rx->user_mss < in_mss)
							in_mss = opt_rx->user_mss;
						opt_rx->mss_clamp = in_mss;  //或者直接保存对端通告的
					}
				}
				break;
			case TCPOPT_WINDOW://3窗口缩放
				if (opsize == TCPOLEN_WINDOW && th->syn &&
				    !estab && READ_ONCE(net->ipv4.sysctl_tcp_window_scaling)) { //是否支持窗口缩放
					__u8 snd_wscale = *(__u8 *)ptr;//读取窗口缩放值
					opt_rx->wscale_ok = 1;	//标记对端支持窗口缩放
					if (snd_wscale > TCP_MAX_WSCALE) { //14 表示 1G ?
						net_info_ratelimited("%s: Illegal window scaling value %d > %u received\n",
								     __func__,
								     snd_wscale,
								     TCP_MAX_WSCALE);
						snd_wscale = TCP_MAX_WSCALE;
					}
					opt_rx->snd_wscale = snd_wscale;//保存窗口缩放大小
				}
				break;
			case TCPOPT_TIMESTAMP: //时间戳
				if ((opsize == TCPOLEN_TIMESTAMP) &&
				    ((estab && opt_rx->tstamp_ok) ||
				     (!estab && READ_ONCE(net->ipv4.sysctl_tcp_timestamps)))) { //是否开启时间戳选项
					opt_rx->saw_tstamp = 1;
					opt_rx->rcv_tsval = get_unaligned_be32(ptr); //对端的时间戳
					opt_rx->rcv_tsecr = get_unaligned_be32(ptr + 4); //对端回显的时间戳  两个值用来计算rtt?
				}
				break;
			case TCPOPT_SACK_PERM: //4 sack
				if (opsize == TCPOLEN_SACK_PERM && th->syn &&
				    !estab && READ_ONCE(net->ipv4.sysctl_tcp_sack)) { //是否开启sack选项
					opt_rx->sack_ok = TCP_SACK_SEEN; 
					tcp_sack_reset(opt_rx);  //初始化sack相关字段
				}
				break;

			case TCPOPT_SACK://这个是检查携带的sack是否和法？什么情况下会走进这个case呢？建立连接？
				if ((opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK)) &&
				   !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK) &&
				   opt_rx->sack_ok) {
					TCP_SKB_CB(skb)->sacked = (ptr - 2) - (unsigned char *)th;
				}
				break;
#ifdef CONFIG_TCP_MD5SIG
			case TCPOPT_MD5SIG:
				/* The MD5 Hash has already been
				 * checked (see tcp_v{4,6}_rcv()).
				 */
				break;
#endif
			case TCPOPT_FASTOPEN: //TFO相关， 注意这里传入了foc
				tcp_parse_fastopen_option(
					opsize - TCPOLEN_FASTOPEN_BASE,
					ptr, th->syn, foc, false);
				break;

			case TCPOPT_EXP: //实验性质的选项？。。。。
				/* Fast Open option shares code 254 using a
				 * 16 bits magic number.
				 */
				if (opsize >= TCPOLEN_EXP_FASTOPEN_BASE &&
				    get_unaligned_be16(ptr) ==
				    TCPOPT_FASTOPEN_MAGIC) {
					tcp_parse_fastopen_option(opsize -
						TCPOLEN_EXP_FASTOPEN_BASE,
						ptr + 2, th->syn, foc, true);
					break;
				}

				if (smc_parse_options(th, opt_rx, ptr, opsize))
					break;

				opt_rx->saw_unknown = 1;
				break;

			default:
				opt_rx->saw_unknown = 1;
			}
			ptr += opsize-2;
			length -= opsize;
		}
	}
}
EXPORT_SYMBOL(tcp_parse_options);

static bool tcp_parse_aligned_timestamp(struct tcp_sock *tp, const struct tcphdr *th)
{
	const __be32 *ptr = (const __be32 *)(th + 1);

	if (*ptr == htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16)
			  | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP)) {
		tp->rx_opt.saw_tstamp = 1;
		++ptr;
		tp->rx_opt.rcv_tsval = ntohl(*ptr);
		++ptr;
		if (*ptr)
			tp->rx_opt.rcv_tsecr = ntohl(*ptr) - tp->tsoffset;
		else
			tp->rx_opt.rcv_tsecr = 0;
		return true;
	}
	return false;
}

/* Fast parse options. This hopes to only see timestamps.
 * If it is wrong it falls back on tcp_parse_options().
 */
static bool tcp_fast_parse_options(const struct net *net,
				   const struct sk_buff *skb,
				   const struct tcphdr *th, struct tcp_sock *tp)
{
	/* In the spirit of fast parsing, compare doff directly to constant
	 * values.  Because equality is used, short doff can be ignored here.
	 */
	if (th->doff == (sizeof(*th) / 4)) {
		tp->rx_opt.saw_tstamp = 0;
		return false;
	} else if (tp->rx_opt.tstamp_ok &&
		   th->doff == ((sizeof(*th) + TCPOLEN_TSTAMP_ALIGNED) / 4)) {
		if (tcp_parse_aligned_timestamp(tp, th))
			return true;
	}

	tcp_parse_options(net, skb, &tp->rx_opt, 1, NULL);
	if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr)
		tp->rx_opt.rcv_tsecr -= tp->tsoffset;

	return true;
}

#ifdef CONFIG_TCP_MD5SIG
/*
 * Parse MD5 Signature option
 */
const u8 *tcp_parse_md5sig_option(const struct tcphdr *th)
{
	int length = (th->doff << 2) - sizeof(*th);
	const u8 *ptr = (const u8 *)(th + 1);

	/* If not enough data remaining, we can short cut */
	while (length >= TCPOLEN_MD5SIG) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return NULL;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2 || opsize > length)
				return NULL;
			if (opcode == TCPOPT_MD5SIG)
				return opsize == TCPOLEN_MD5SIG ? ptr : NULL;
		}
		ptr += opsize - 2;
		length -= opsize;
	}
	return NULL;
}
EXPORT_SYMBOL(tcp_parse_md5sig_option);
#endif

/* Sorry, PAWS as specified is broken wrt. pure-ACKs -DaveM
 *
 * It is not fatal. If this ACK does _not_ change critical state (seqs, window)
 * it can pass through stack. So, the following predicate verifies that
 * this segment is not used for anything but congestion avoidance or
 * fast retransmit. Moreover, we even are able to eliminate most of such
 * second order effects, if we apply some small "replay" window (~RTO)
 * to timestamp space.
 *
 * All these measures still do not guarantee that we reject wrapped ACKs
 * on networks with high bandwidth, when sequence space is recycled fastly,
 * but it guarantees that such events will be very rare and do not affect
 * connection seriously. This doesn't look nice, but alas, PAWS is really
 * buggy extension.
 *
 * [ Later note. Even worse! It is buggy for segments _with_ data. RFC
 * states that events when retransmit arrives after original data are rare.
 * It is a blatant lie. VJ forgot about fast retransmit! 8)8) It is
 * the biggest problem on large power networks even with minor reordering.
 * OK, let's give it small replay window. If peer clock is even 1hz, it is safe
 * up to bandwidth of 18Gigabit/sec. 8) ]
 */

static int tcp_disordered_ack(const struct sock *sk, const struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct tcphdr *th = tcp_hdr(skb);
	u32 seq = TCP_SKB_CB(skb)->seq;
	u32 ack = TCP_SKB_CB(skb)->ack_seq;

	return (/* 1. Pure ACK with correct sequence number. */
		(th->ack && seq == TCP_SKB_CB(skb)->end_seq && seq == tp->rcv_nxt) &&

		/* 2. ... and duplicate ACK. */
		ack == tp->snd_una &&

		/* 3. ... and does not update window. */
		!tcp_may_update_window(tp, ack, seq, ntohs(th->window) << tp->rx_opt.snd_wscale) &&

		/* 4. ... and sits in replay window. */
		(s32)(tp->rx_opt.ts_recent - tp->rx_opt.rcv_tsval) <= (inet_csk(sk)->icsk_rto * 1024) / HZ);
}

static inline bool tcp_paws_discard(const struct sock *sk,
				   const struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return !tcp_paws_check(&tp->rx_opt, TCP_PAWS_WINDOW) &&
	       !tcp_disordered_ack(sk, skb);
}

/* Check segment sequence number for validity.
 *
 * Segment controls are considered valid, if the segment
 * fits to the window after truncation to the window. Acceptability
 * of data (and SYN, FIN, of course) is checked separately.
 * See tcp_data_queue(), for example.
 *
 * Also, controls (RST is main one) are accepted using RCV.WUP instead
 * of RCV.NXT. Peer still did not advance his SND.UNA when we
 * delayed ACK, so that hisSND.UNA<=ourRCV.WUP.
 * (borrowed from freebsd)
 */

static enum skb_drop_reason tcp_sequence(const struct tcp_sock *tp,
					 u32 seq, u32 end_seq)
{
	if (before(end_seq, tp->rcv_wup))
		return SKB_DROP_REASON_TCP_OLD_SEQUENCE;

	if (after(seq, tp->rcv_nxt + tcp_receive_window(tp)))
		return SKB_DROP_REASON_TCP_INVALID_SEQUENCE;

	return SKB_NOT_DROPPED_YET;
}

/* When we get a reset we do this. */
void tcp_reset(struct sock *sk, struct sk_buff *skb)
{
	trace_tcp_receive_reset(sk);

	/* mptcp can't tell us to ignore reset pkts,
	 * so just ignore the return value of mptcp_incoming_options().
	 */
	if (sk_is_mptcp(sk))
		mptcp_incoming_options(sk, skb);

	/* We want the right error as BSD sees it (and indeed as we do). */
	switch (sk->sk_state) {
	case TCP_SYN_SENT:
		WRITE_ONCE(sk->sk_err, ECONNREFUSED);
		break;
	case TCP_CLOSE_WAIT:
		WRITE_ONCE(sk->sk_err, EPIPE);
		break;
	case TCP_CLOSE:
		return;
	default:
		WRITE_ONCE(sk->sk_err, ECONNRESET);
	}
	/* This barrier is coupled with smp_rmb() in tcp_poll() */
	smp_wmb();

	tcp_write_queue_purge(sk);
	tcp_done(sk);

	if (!sock_flag(sk, SOCK_DEAD))
		sk_error_report(sk);
}

/*
 * 	Process the FIN bit. This now behaves as it is supposed to work
 *	and the FIN takes effect when it is validly part of sequence
 *	space. Not before when we get holes.
 *
 *	If we are ESTABLISHED, a received fin moves us to CLOSE-WAIT
 *	(and thence onto LAST-ACK and finally, CLOSE, we never enter
 *	TIME-WAIT)
 *
 *	If we are in FINWAIT-1, a received FIN indicates simultaneous
 *	close and we go into CLOSING (and later onto TIME-WAIT)
 *
 *	If we are in FINWAIT-2, a received FIN moves us to TIME-WAIT.
 */
void tcp_fin(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//收到了fin包肯定需要确认
	inet_csk_schedule_ack(sk);
	//接收方向shutdown 因为对端关闭了,进程上下文从接收队列获取数据的时候会判断
	WRITE_ONCE(sk->sk_shutdown, sk->sk_shutdown | RCV_SHUTDOWN);
	//
	sock_set_flag(sk, SOCK_DONE);

	switch (sk->sk_state) {
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		/* Move to CLOSE_WAIT */
		//建连接或者客户端已经认为建立连接成功的情况下进入closewait状态
		tcp_set_state(sk, TCP_CLOSE_WAIT);
		//进入pingpong模式，因为四次挥手对时延要求高，所以回复ack要快
		inet_csk_enter_pingpong_mode(sk);
		break;
	//认为时重传的ifn不处理
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
		/* Received a retransmission of the FIN, do
		 * nothing.
		 */
		break;
	case TCP_LAST_ACK:
		/* RFC793: Remain in the LAST-ACK state. */
		break;
	//发送fin后收到fin表示同时关闭
	case TCP_FIN_WAIT1:
		/* This case occurs when a simultaneous close
		 * happens, we must ack the received FIN and
		 * enter the CLOSING state.
		 */
		//发送ack
		tcp_send_ack(sk);
		tcp_set_state(sk, TCP_CLOSING);
		break;
	case TCP_FIN_WAIT2:
		/* Received a FIN -- send ACK and enter TIME_WAIT. */
		//主动关闭的一方收到了对端的fin，发送最后一个ack 并进入tw状态，合理
		tcp_send_ack(sk);
		tcp_time_wait(sk, TCP_TIME_WAIT, 0);
		break;
	default:
		/* Only TCP_LISTEN and TCP_CLOSE are left, in these
		 * cases we should never reach this piece of code.
		 */
		pr_err("%s: Impossible, sk->sk_state=%d\n",
		       __func__, sk->sk_state);
		break;
	}

	/* It _is_ possible, that we have something out-of-order _after_ FIN.
	 * Probably, we should reset in this case. For now drop them.
	 */
	//清理乱序队列，概率很小吧，都发送fin了后面还有数据>
	skb_rbtree_purge(&tp->out_of_order_queue);
	if (tcp_is_sack(tp))
	//复位sack的信息
		tcp_sack_reset(&tp->rx_opt);
	//如果没死，则唤醒用户的进程
	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_state_change(sk);

		/* Do not send POLL_HUP for half duplex close. */
		if (sk->sk_shutdown == SHUTDOWN_MASK ||
		    sk->sk_state == TCP_CLOSE)
			sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_HUP);//两个方向都关闭
		else
			sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);//关闭了一个方向
	}
}

static inline bool tcp_sack_extend(struct tcp_sack_block *sp, u32 seq,
				  u32 end_seq)
{
	if (!after(seq, sp->end_seq) && !after(sp->start_seq, end_seq)) {
		if (before(seq, sp->start_seq))
			sp->start_seq = seq;
		if (after(end_seq, sp->end_seq))
			sp->end_seq = end_seq;
		return true;
	}
	return false;
}

static void tcp_dsack_set(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//启动用了sack
	if (tcp_is_sack(tp) && READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_dsack)) {
		int mib_idx;

		if (before(seq, tp->rcv_nxt))
			mib_idx = LINUX_MIB_TCPDSACKOLDSENT;
		else
			mib_idx = LINUX_MIB_TCPDSACKOFOSENT;

		NET_INC_STATS(sock_net(sk), mib_idx);
		//表示要发送dsack
		tp->rx_opt.dsack = 1;
		//设置区间
		tp->duplicate_sack[0].start_seq = seq;
		tp->duplicate_sack[0].end_seq = end_seq;
	}
}

static void tcp_dsack_extend(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->rx_opt.dsack)
		tcp_dsack_set(sk, seq, end_seq);
	else
		tcp_sack_extend(tp->duplicate_sack, seq, end_seq);
}

static void tcp_rcv_spurious_retrans(struct sock *sk, const struct sk_buff *skb)
{
	/* When the ACK path fails or drops most ACKs, the sender would
	 * timeout and spuriously retransmit the same segment repeatedly.
	 * The receiver remembers and reflects via DSACKs. Leverage the
	 * DSACK state and change the txhash to re-route speculatively.
	 */
	if (TCP_SKB_CB(skb)->seq == tcp_sk(sk)->duplicate_sack[0].start_seq &&
	    sk_rethink_txhash(sk))
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPDUPLICATEDATAREHASH);
}

static void tcp_send_dupack(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
	    before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_DELAYEDACKLOST);
		tcp_enter_quickack_mode(sk, TCP_MAX_QUICKACKS);

		if (tcp_is_sack(tp) && READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_dsack)) {
			u32 end_seq = TCP_SKB_CB(skb)->end_seq;

			tcp_rcv_spurious_retrans(sk, skb);
			if (after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt))
				end_seq = tp->rcv_nxt;
			tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, end_seq);
		}
	}

	tcp_send_ack(sk);
}

/* These routines update the SACK block as out-of-order packets arrive or
 * in-order packets close up the sequence space.
 */
static void tcp_sack_maybe_coalesce(struct tcp_sock *tp)
{
	int this_sack;
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	struct tcp_sack_block *swalk = sp + 1;

	/* See if the recent change to the first SACK eats into
	 * or hits the sequence space of other SACK blocks, if so coalesce.
	 */
	for (this_sack = 1; this_sack < tp->rx_opt.num_sacks;) {
		if (tcp_sack_extend(sp, swalk->start_seq, swalk->end_seq)) {
			int i;

			/* Zap SWALK, by moving every further SACK up by one slot.
			 * Decrease num_sacks.
			 */
			tp->rx_opt.num_sacks--;
			for (i = this_sack; i < tp->rx_opt.num_sacks; i++)
				sp[i] = sp[i + 1];
			continue;
		}
		this_sack++;
		swalk++;
	}
}

void tcp_sack_compress_send_ack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//直接返回
	if (!tp->compressed_ack)
		return;
	//取消压缩ack的定时器
	if (hrtimer_try_to_cancel(&tp->compressed_ack_timer) == 1)
		__sock_put(sk);

	/* Since we have to send one ack finally,
	 * substract one from tp->compressed_ack to keep
	 * LINUX_MIB_TCPACKCOMPRESSED accurate.
	 */
	//更新统计计数
	NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPACKCOMPRESSED,
		      tp->compressed_ack - 1);
	//清零
	tp->compressed_ack = 0;
	//立即发送ack
	tcp_send_ack(sk);
}

/* Reasonable amount of sack blocks included in TCP SACK option
 * The max is 4, but this becomes 3 if TCP timestamps are there.
 * Given that SACK packets might be lost, be conservative and use 2.
 */
#define TCP_SACK_BLOCKS_EXPECTED 2

static void tcp_sack_new_ofo_skb(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	int cur_sacks = tp->rx_opt.num_sacks;
	int this_sack;
	//没有，直接填充sack
	if (!cur_sacks)
		goto new_sack;
	//尝试更已右的sack合并。
	for (this_sack = 0; this_sack < cur_sacks; this_sack++, sp++) {
		if (tcp_sack_extend(sp, seq, end_seq)) {
			//合并成功
			if (this_sack >= TCP_SACK_BLOCKS_EXPECTED) //段太多
				tcp_sack_compress_send_ack(sk);	//取消压缩ack 立即发送sack信息
			/* Rotate this_sack to the first one. */
			for (; this_sack > 0; this_sack--, sp--)//合并成功冒泡排序
				swap(*sp, *(sp - 1));
			if (cur_sacks > 1)
				tcp_sack_maybe_coalesce(tp);//有多个段，尝试把相邻的在合并一下
			return;
		}
	}
	//取消压缩ack
	if (this_sack >= TCP_SACK_BLOCKS_EXPECTED)
		tcp_sack_compress_send_ack(sk);

	/* Could not find an adjacent existing SACK, build a new one,
	 * put it at the front, and shift everyone else down.  We
	 * always know there is at least one SACK present already here.
	 *
	 * If the sack array is full, forget about the last one.
	 */
	//丢掉最后一个sack  只能容纳4个
	if (this_sack >= TCP_NUM_SACKS) {
		this_sack--;
		tp->rx_opt.num_sacks--;
		sp--;
	}
	//体右移一格，给第 0 腾位置
	for (; this_sack > 0; this_sack--, sp--)
		*sp = *(sp - 1);
//这里就是真正的填充sack 的信息！
new_sack:
	/* Build the new head SACK, and we're done. */
	sp->start_seq = seq;
	sp->end_seq = end_seq;
	tp->rx_opt.num_sacks++; //注意这里更新了sack的块数
}

/* RCV.NXT advances, some SACKs should be eaten. */

static void tcp_sack_remove(struct tcp_sock *tp)
{
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	int num_sacks = tp->rx_opt.num_sacks;
	int this_sack;

	/* Empty ofo queue, hence, all the SACKs are eaten. Clear. */
	//乱序队列都空了，就没有sack块了
	if (RB_EMPTY_ROOT(&tp->out_of_order_queue)) {
		tp->rx_opt.num_sacks = 0;
		return;
	}
	//遍历每个sack块，看看是不已经被rcvnxt处理过了
	for (this_sack = 0; this_sack < num_sacks;) {
		/* Check if the start of the sack is covered by RCV.NXT. */
		if (!before(tp->rcv_nxt, sp->start_seq)) {
			int i;

			/* RCV.NXT must cover all the block! */
			WARN_ON(before(tp->rcv_nxt, sp->end_seq));

			/* Zap this SACK, by moving forward any other SACKS. */
			for (i = this_sack+1; i < num_sacks; i++)
				tp->selective_acks[i-1] = tp->selective_acks[i];
			num_sacks--;
			continue;
		}
		this_sack++;
		sp++;
	}
	tp->rx_opt.num_sacks = num_sacks;
}

/**
 * tcp_try_coalesce - try to merge skb to prior one
 * @sk: socket
 * @to: prior buffer
 * @from: buffer to add in queue
 * @fragstolen: pointer to boolean
 *
 * Before queueing skb @from after @to, try to merge them
 * to reduce overall memory use and queue lengths, if cost is small.
 * Packets in ofo or receive queues can stay a long time.
 * Better try to coalesce them right now to avoid future collapses.
 * Returns true if caller should free @from instead of queueing it
 */
static bool tcp_try_coalesce(struct sock *sk,
			     struct sk_buff *to,
			     struct sk_buff *from,
			     bool *fragstolen)
{
	int delta;

	*fragstolen = false;

	/* Its possible this segment overlaps with prior segment in queue */
	if (TCP_SKB_CB(from)->seq != TCP_SKB_CB(to)->end_seq)
		return false;

	if (!mptcp_skb_can_collapse(to, from))
		return false;

#ifdef CONFIG_TLS_DEVICE
	if (from->decrypted != to->decrypted)
		return false;
#endif

	if (!skb_try_coalesce(to, from, fragstolen, &delta))
		return false;

	atomic_add(delta, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, delta);
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRCVCOALESCE);
	TCP_SKB_CB(to)->end_seq = TCP_SKB_CB(from)->end_seq;
	TCP_SKB_CB(to)->ack_seq = TCP_SKB_CB(from)->ack_seq;
	TCP_SKB_CB(to)->tcp_flags |= TCP_SKB_CB(from)->tcp_flags;

	if (TCP_SKB_CB(from)->has_rxtstamp) {
		TCP_SKB_CB(to)->has_rxtstamp = true;
		to->tstamp = from->tstamp;
		skb_hwtstamps(to)->hwtstamp = skb_hwtstamps(from)->hwtstamp;
	}

	return true;
}

static bool tcp_ooo_try_coalesce(struct sock *sk,
			     struct sk_buff *to,
			     struct sk_buff *from,
			     bool *fragstolen)
{
	bool res = tcp_try_coalesce(sk, to, from, fragstolen);

	/* In case tcp_drop_reason() is called later, update to->gso_segs */
	if (res) {
		u32 gso_segs = max_t(u16, 1, skb_shinfo(to)->gso_segs) +
			       max_t(u16, 1, skb_shinfo(from)->gso_segs);

		skb_shinfo(to)->gso_segs = min_t(u32, gso_segs, 0xFFFF);
	}
	return res;
}

static void tcp_drop_reason(struct sock *sk, struct sk_buff *skb,
			    enum skb_drop_reason reason)
{
	sk_drops_add(sk, skb);
	kfree_skb_reason(skb, reason);
}

/* This one checks to see if we can put data from the
 * out_of_order queue into the receive_queue.
 */
static void tcp_ofo_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 dsack_high = tp->rcv_nxt;
	bool fin, fragstolen, eaten;
	struct sk_buff *skb, *tail;
	struct rb_node *p;
	//乱序队列
	p = rb_first(&tp->out_of_order_queue);
	while (p) {
		skb = rb_to_skb(p);
		//需要比下一个预期接收的大直接break
		if (after(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))
			break;
		//这里判断是否发生重叠
		if (before(TCP_SKB_CB(skb)->seq, dsack_high)) {
			__u32 dsack = dsack_high;//保存起来
			//整个skb都在旧的部分
			if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))
				dsack_high = TCP_SKB_CB(skb)->end_seq;
			//用于告诉发送端收到了重复的数据
			tcp_dsack_extend(sk, TCP_SKB_CB(skb)->seq, dsack);
		}
		p = rb_next(p);
		rb_erase(&skb->rbnode, &tp->out_of_order_queue);
		//完全是旧的数据直接 continue
		if (unlikely(!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt))) {
			tcp_drop_reason(sk, skb, SKB_DROP_REASON_TCP_OFO_DROP);
			continue;
		}
		//获取接收队列的最后一个数据包
		tail = skb_peek_tail(&sk->sk_receive_queue);
		//追加新的skb，这里注意如果序列号不正正好好的连续这里直接false
		eaten = tail && tcp_try_coalesce(sk, tail, skb, &fragstolen);
		//更新下一个待接收的序列号
		tcp_rcv_nxt_update(tp, TCP_SKB_CB(skb)->end_seq);
		fin = TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN;
		//没有追加上，入队列，这里有问题啊 部分重叠的数也入队了？？
		if (!eaten)
			__skb_queue_tail(&sk->sk_receive_queue, skb);
		else
			
			kfree_skb_partial(skb, fragstolen);
		//乱序队列中有个fin 走fin包处理逻辑
		if (unlikely(fin)) {
			tcp_fin(sk);
			/* tcp_fin() purges tp->out_of_order_queue,
			 * so we must end this loop right now.
			 */
			break;
		}
	}
}

static bool tcp_prune_ofo_queue(struct sock *sk, const struct sk_buff *in_skb);
static int tcp_prune_queue(struct sock *sk, const struct sk_buff *in_skb);

static int tcp_try_rmem_schedule(struct sock *sk, struct sk_buff *skb,
				 unsigned int size)
{
	//是否缓冲区不够了 或者内存压力之下
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
	    !sk_rmem_schedule(sk, skb, size)) {
		//合并数据包或者增大缓冲区，这里很关键，如果还是缓冲区不足，则返回-1
		if (tcp_prune_queue(sk, skb) < 0)
			return -1;
		//这里几乎不可能吧
		while (!sk_rmem_schedule(sk, skb, size)) {
			//开始丢弃乱序数据包！！！！
			if (!tcp_prune_ofo_queue(sk, skb))
				return -1;
		}
	}
	return 0;
}

static void tcp_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct rb_node **p, *parent;
	struct sk_buff *skb1;
	u32 seq, end_seq;
	bool fragstolen;

	tcp_ecn_check_ce(sk, skb);
	//判断是否内存原因无法继续处理，和外面处理逻辑一样
	if (unlikely(tcp_try_rmem_schedule(sk, skb, skb->truesize))) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFODROP);
		sk->sk_data_ready(sk);
		tcp_drop_reason(sk, skb, SKB_DROP_REASON_PROTO_MEM);
		return;
	}

	/* Disable header prediction. */
	//这里直接关掉了fastpath
	tp->pred_flags = 0;
	//设置需要回复ack 的标志
	inet_csk_schedule_ack(sk);
	//乱序包统计计数++
	tp->rcv_ooopack += max_t(u16, 1, skb_shinfo(skb)->gso_segs);
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOQUEUE); //这可以观测乱序数据包的数量
	//数据包的开始序列号
	seq = TCP_SKB_CB(skb)->seq;
	//数据包的结束序列号
	end_seq = TCP_SKB_CB(skb)->end_seq;
	//乱序队列
	p = &tp->out_of_order_queue.rb_node;
	//乱序队列为空的情况
	if (RB_EMPTY_ROOT(&tp->out_of_order_queue)) {
		/* Initial out of order segment, build 1 SACK. */
		if (tcp_is_sack(tp)) {
			//构造sack的信息
			tp->rx_opt.num_sacks = 1;
			tp->selective_acks[0].start_seq = seq;
			tp->selective_acks[0].end_seq = end_seq;
		}
		//插入乱序队列
		rb_link_node(&skb->rbnode, NULL, p);
		rb_insert_color(&skb->rbnode, &tp->out_of_order_queue);
		tp->ooo_last_skb = skb;//乱序队列中最后一个书包
		goto end;
	}

	/* In the typical case, we are adding an skb to the end of the list.
	 * Use of ooo_last_skb avoids the O(Log(N)) rbtree lookup.
	 */
	//这里是尝试将当前数据包加入到末尾skb上 注意序列号必须和最后一个连续
	//感觉通常不会走到这个逻辑吧
	if (tcp_ooo_try_coalesce(sk, tp->ooo_last_skb,
				 skb, &fragstolen)) {
coalesce_done:
		/* For non sack flows, do not grow window to force DUPACK
		 * and trigger fast retransmit.
		 */
		if (tcp_is_sack(tp))
			tcp_grow_window(sk, skb, true);
		kfree_skb_partial(skb, fragstolen);
		skb = NULL;
		goto add_sack;
	}
	/* Can avoid an rbtree lookup if we are adding skb after ooo_last_skb */
	//还在当前乱序数据包的最后一个的后面，那就直接插入就可以了
	if (!before(seq, TCP_SKB_CB(tp->ooo_last_skb)->end_seq)) {
		parent = &tp->ooo_last_skb->rbnode;
		p = &parent->rb_right;
		goto insert;
	}

	/* Find place to insert this segment. Handle overlaps on the way. */
	//真正的核心，在红黑树中查找插入点，同时处理重叠和覆盖
	parent = NULL;
	//这里p是红黑树的根
	while (*p) {
		parent = *p;
		skb1 = rb_to_skb(parent);
		//一直往左左走
		if (before(seq, TCP_SKB_CB(skb1)->seq)) {
			p = &parent->rb_left;
			continue;
		}
		//判断右边
		if (before(seq, TCP_SKB_CB(skb1)->end_seq)) {
			//新段完全被当前段覆盖 直接丢弃了，注意和外面区分，这里是乱序队列完全是旧的
			if (!after(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
				/* All the bits are present. Drop. */
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPOFOMERGE);
				tcp_drop_reason(sk, skb,
						SKB_DROP_REASON_TCP_OFOMERGE);
				skb = NULL;
				//构造sack
				tcp_dsack_set(sk, seq, end_seq);
				goto add_sack;
			}
			//部分重叠的情况
			if (after(seq, TCP_SKB_CB(skb1)->seq)) {
				/* Partial overlap. */
				tcp_dsack_set(sk, seq, TCP_SKB_CB(skb1)->end_seq);
			} else {
				/* skb's seq == skb1's seq and skb covers skb1.
				 * Replace skb1 with skb.
				 */
				//这里是一定是起点相同的情况！！！
				rb_replace_node(&skb1->rbnode, &skb->rbnode,
						&tp->out_of_order_queue);
				//设置dsack 这里是一个扩展，在原有的基础上？
				tcp_dsack_extend(sk,
						 TCP_SKB_CB(skb1)->seq,
						 TCP_SKB_CB(skb1)->end_seq);
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPOFOMERGE);
				
				tcp_drop_reason(sk, skb1,
						SKB_DROP_REASON_TCP_OFOMERGE);
				//处理右侧可能重叠的部分
				goto merge_right;
			}
		//在skb1的右侧，如果进入分支表示合并成功！
		} else if (tcp_ooo_try_coalesce(sk, skb1,
						skb, &fragstolen)) {
			goto coalesce_done;
		}
		p = &parent->rb_right;
	}
insert:
	/* Insert segment into RB tree. */
	rb_link_node(&skb->rbnode, parent, p);
	rb_insert_color(&skb->rbnode, &tp->out_of_order_queue);

merge_right:
	//把右边的重复数据段干掉!
	/* Remove other segments covered by skb. */
	while ((skb1 = skb_rb_next(skb)) != NULL) {
		//和右侧没有重叠的 直接break
		if (!after(end_seq, TCP_SKB_CB(skb1)->seq))
			break;
		//部分重叠，不处理
		if (before(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
			tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
					 end_seq);
			break;
		}
		//重叠的情况，完全覆盖，从红黑树中移除
		rb_erase(&skb1->rbnode, &tp->out_of_order_queue);
	
		tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
				 TCP_SKB_CB(skb1)->end_seq);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
		tcp_drop_reason(sk, skb1, SKB_DROP_REASON_TCP_OFOMERGE);
	}
	/* If there is no skb after us, we are the last_skb ! */
	//更新最后一个skb
	if (!skb1)
		tp->ooo_last_skb = skb;

add_sack://更新sack 的信息
	if (tcp_is_sack(tp))
		tcp_sack_new_ofo_skb(sk, seq, end_seq);
end:
//如果skb没被丢弃
	if (skb) {
		/* For non sack flows, do not grow window to force DUPACK
		 * and trigger fast retransmit.
		 */
		//尝试增大窗口，目的是让对端发送更多数据？触发快重传？
		if (tcp_is_sack(tp))
			tcp_grow_window(sk, skb, false);
		//整理skb内存布局
		skb_condense(skb);
		//内存记账！
		skb_set_owner_r(skb, sk);
	}
}

static int __must_check tcp_queue_rcv(struct sock *sk, struct sk_buff *skb,
				      bool *fragstolen)
{
	int eaten;
	//获取尾部的skb
	struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);
	//尝试把当前skb放到taii中
	eaten = (tail &&
		 tcp_try_coalesce(sk, tail,
				  skb, fragstolen)) ? 1 : 0;
	//这里肯定是要更新rcv_nxt的，合理
	tcp_rcv_nxt_update(tcp_sk(sk), TCP_SKB_CB(skb)->end_seq);
	//合并失败，直接入队
	if (!eaten) {
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		skb_set_owner_r(skb, sk);
	}
	return eaten;
}

int tcp_send_rcvq(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct sk_buff *skb;
	int err = -ENOMEM;
	int data_len = 0;
	bool fragstolen;

	if (size == 0)
		return 0;

	if (size > PAGE_SIZE) {
		int npages = min_t(size_t, size >> PAGE_SHIFT, MAX_SKB_FRAGS);

		data_len = npages << PAGE_SHIFT;
		size = data_len + (size & ~PAGE_MASK);
	}
	skb = alloc_skb_with_frags(size - data_len, data_len,
				   PAGE_ALLOC_COSTLY_ORDER,
				   &err, sk->sk_allocation);
	if (!skb)
		goto err;

	skb_put(skb, size - data_len);
	skb->data_len = data_len;
	skb->len = size;

	if (tcp_try_rmem_schedule(sk, skb, skb->truesize)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRCVQDROP);
		goto err_free;
	}

	err = skb_copy_datagram_from_iter(skb, 0, &msg->msg_iter, size);
	if (err)
		goto err_free;

	TCP_SKB_CB(skb)->seq = tcp_sk(sk)->rcv_nxt;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq + size;
	TCP_SKB_CB(skb)->ack_seq = tcp_sk(sk)->snd_una - 1;

	if (tcp_queue_rcv(sk, skb, &fragstolen)) {
		WARN_ON_ONCE(fragstolen); /* should not happen */
		__kfree_skb(skb);
	}
	return size;

err_free:
	kfree_skb(skb);
err:
	return err;

}

void tcp_data_ready(struct sock *sk)
{
	if (tcp_epollin_ready(sk, sk->sk_rcvlowat) || sock_flag(sk, SOCK_DONE))
		sk->sk_data_ready(sk);
}

static void tcp_data_queue(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	enum skb_drop_reason reason;
	bool fragstolen;
	int eaten;

	/* If a subflow has been reset, the packet should not continue
	 * to be processed, drop the packet.
	 */
	if (sk_is_mptcp(sk) && !mptcp_incoming_options(sk, skb)) {
		__kfree_skb(skb);
		return;
	}
	//空数据包
	if (TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq) {
		__kfree_skb(skb);
		return;
	}
	skb_dst_drop(skb);
	__skb_pull(skb, tcp_hdr(skb)->doff * 4);

	reason = SKB_DROP_REASON_NOT_SPECIFIED;
	tp->rx_opt.dsack = 0;

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
	//数据包时顺序到达的走这里，否则走下面进入乱序队列
	if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt) {
		//如果接收窗口变成0了，这里直接丢弃数据包，快速回复一个ack告诉对端窗口为0了
		if (tcp_receive_window(tp) == 0) {
			reason = SKB_DROP_REASON_TCP_ZEROWINDOW;
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
			goto out_of_window;
		}

		/* Ok. In sequence. In window. */
queue_and_out:
		//这里很关键，如果缓冲区大小紧张，这里可能直接丢弃乱序队列的数据包，返回-1表示无法拯救了！
		if (tcp_try_rmem_schedule(sk, skb, skb->truesize)) {
			/* TODO: maybe ratelimit these WIN 0 ACK ? */
			//立即发ack通告给对端
			inet_csk(sk)->icsk_ack.pending |=
					(ICSK_ACK_NOMEM | ICSK_ACK_NOW);
			inet_csk_schedule_ack(sk);
			//通知用户态尽力读数据！
			sk->sk_data_ready(sk);
			//receive_queue 不为空丢弃数据包
			if (skb_queue_len(&sk->sk_receive_queue)) {
				reason = SKB_DROP_REASON_PROTO_MEM;
				NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRCVQDROP);
				goto drop;
			}
			//更新内存记账，还是有机会入队的！有可能吗
			sk_forced_mem_schedule(sk, skb->truesize);
		}
		//这里是数据包入队
		eaten = tcp_queue_rcv(sk, skb, &fragstolen);
		if (skb->len)
		//计算接收端rtt mss等信息
			tcp_event_data_recv(sk, skb);
		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		//四次挥手fin包处理逻辑
			tcp_fin(sk);
		//乱序队列不为空
		if (!RB_EMPTY_ROOT(&tp->out_of_order_queue)) {
			//这里就是处理乱序队列的逻辑，尝试把乱序数据放到有序队列中！！
			tcp_ofo_queue(sk);

			/* RFC5681. 4.2. SHOULD send immediate ACK, when
			 * gap in queue is filled.
			 */
			//乱序队列为空立即回复ack
			if (RB_EMPTY_ROOT(&tp->out_of_order_queue))
				inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		}
		//数据包携带了sack选项，因为可能有些sack需要清理了
		if (tp->rx_opt.num_sacks)
			tcp_sack_remove(tp);
		//是否能走到快速路径中
		tcp_fast_path_check(sk);
		//貌似是被合并释放部分
		if (eaten > 0)
			kfree_skb_partial(skb, fragstolen);
		if (!sock_flag(sk, SOCK_DEAD))
		//通知用户
			tcp_data_ready(sk);
		return;
	}
	//完全是旧的数据
	if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) {
		//虚假重传
		tcp_rcv_spurious_retrans(sk, skb);
		/* A retransmit, 2nd most common case.  Force an immediate ack. */
		reason = SKB_DROP_REASON_TCP_OLD_DATA;
		NET_INC_STATS(sock_net(sk), LINUX_MIB_DELAYEDACKLOST);
		//告诉发送端收到了重复数据
		tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);

out_of_window:
		//进入快速 ACK 模式，可能是告诉对端收到了虚假重传了
		tcp_enter_quickack_mode(sk, TCP_MAX_QUICKACKS);
		inet_csk_schedule_ack(sk);
drop:
		//直接释放数据包
		tcp_drop_reason(sk, skb, reason);
		return;
	}

	/* Out of window. F.e. zero window probe. */
	//是否超出了接收窗口，直接释放数据包
	if (!before(TCP_SKB_CB(skb)->seq,
		    tp->rcv_nxt + tcp_receive_window(tp))) {
		reason = SKB_DROP_REASON_TCP_OVERWINDOW;
		goto out_of_window;
	}
	//如果存在部分重叠的情况
	if (before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		/* Partial packet, seq < rcv_next < end_seq */
		//设置dsack信息
		tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, tp->rcv_nxt);

		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		//没有窗口可用了 直接丢弃
		if (!tcp_receive_window(tp)) {
			reason = SKB_DROP_REASON_TCP_ZEROWINDOW;
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
			goto out_of_window;
		}
		//这里部分重叠的数据包也入队了，那怎么处理重叠的部分呢？？貌似是不处理
		goto queue_and_out;
	}
	//其他情况，进入乱序队列
	tcp_data_queue_ofo(sk, skb);
}

static struct sk_buff *tcp_skb_next(struct sk_buff *skb, struct sk_buff_head *list)
{
	if (list)
		return !skb_queue_is_last(list, skb) ? skb->next : NULL;

	return skb_rb_next(skb);
}

static struct sk_buff *tcp_collapse_one(struct sock *sk, struct sk_buff *skb,
					struct sk_buff_head *list,
					struct rb_root *root)
{
	struct sk_buff *next = tcp_skb_next(skb, list);

	if (list)
		__skb_unlink(skb, list);
	else
		rb_erase(&skb->rbnode, root);

	__kfree_skb(skb);
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRCVCOLLAPSED);

	return next;
}

/* Insert skb into rb tree, ordered by TCP_SKB_CB(skb)->seq */
void tcp_rbtree_insert(struct rb_root *root, struct sk_buff *skb)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct sk_buff *skb1;

	while (*p) {
		parent = *p;
		skb1 = rb_to_skb(parent);
		if (before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb1)->seq))
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&skb->rbnode, parent, p);
	rb_insert_color(&skb->rbnode, root);
}

/* Collapse contiguous sequence of skbs head..tail with
 * sequence numbers start..end.
 *
 * If tail is NULL, this means until the end of the queue.
 *
 * Segments with FIN/SYN are not collapsed (only because this
 * simplifies code)
 */
static void
tcp_collapse(struct sock *sk, struct sk_buff_head *list, struct rb_root *root,
	     struct sk_buff *head, struct sk_buff *tail, u32 start, u32 end)
{
	struct sk_buff *skb = head, *n;
	struct sk_buff_head tmp;
	bool end_of_skbs;

	/* First, check that queue is collapsible and find
	 * the point where collapsing can be useful.
	 */
restart:
	for (end_of_skbs = true; skb != NULL && skb != tail; skb = n) {
		n = tcp_skb_next(skb, list);

		/* No new bits? It is possible on ofo queue. */
		if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
			skb = tcp_collapse_one(sk, skb, list, root);
			if (!skb)
				break;
			goto restart;
		}

		/* The first skb to collapse is:
		 * - not SYN/FIN and
		 * - bloated or contains data before "start" or
		 *   overlaps to the next one and mptcp allow collapsing.
		 */
		if (!(TCP_SKB_CB(skb)->tcp_flags & (TCPHDR_SYN | TCPHDR_FIN)) &&
		    (tcp_win_from_space(sk, skb->truesize) > skb->len ||
		     before(TCP_SKB_CB(skb)->seq, start))) {
			end_of_skbs = false;
			break;
		}

		if (n && n != tail && mptcp_skb_can_collapse(skb, n) &&
		    TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(n)->seq) {
			end_of_skbs = false;
			break;
		}

		/* Decided to skip this, advance start seq. */
		start = TCP_SKB_CB(skb)->end_seq;
	}
	if (end_of_skbs ||
	    (TCP_SKB_CB(skb)->tcp_flags & (TCPHDR_SYN | TCPHDR_FIN)))
		return;

	__skb_queue_head_init(&tmp);

	while (before(start, end)) {
		int copy = min_t(int, SKB_MAX_ORDER(0, 0), end - start);
		struct sk_buff *nskb;

		nskb = alloc_skb(copy, GFP_ATOMIC);
		if (!nskb)
			break;

		memcpy(nskb->cb, skb->cb, sizeof(skb->cb));
#ifdef CONFIG_TLS_DEVICE
		nskb->decrypted = skb->decrypted;
#endif
		TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(nskb)->end_seq = start;
		if (list)
			__skb_queue_before(list, skb, nskb);
		else
			__skb_queue_tail(&tmp, nskb); /* defer rbtree insertion */
		skb_set_owner_r(nskb, sk);
		mptcp_skb_ext_move(nskb, skb);

		/* Copy data, releasing collapsed skbs. */
		while (copy > 0) {
			int offset = start - TCP_SKB_CB(skb)->seq;
			int size = TCP_SKB_CB(skb)->end_seq - start;

			BUG_ON(offset < 0);
			if (size > 0) {
				size = min(copy, size);
				if (skb_copy_bits(skb, offset, skb_put(nskb, size), size))
					BUG();
				TCP_SKB_CB(nskb)->end_seq += size;
				copy -= size;
				start += size;
			}
			if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
				skb = tcp_collapse_one(sk, skb, list, root);
				if (!skb ||
				    skb == tail ||
				    !mptcp_skb_can_collapse(nskb, skb) ||
				    (TCP_SKB_CB(skb)->tcp_flags & (TCPHDR_SYN | TCPHDR_FIN)))
					goto end;
#ifdef CONFIG_TLS_DEVICE
				if (skb->decrypted != nskb->decrypted)
					goto end;
#endif
			}
		}
	}
end:
	skb_queue_walk_safe(&tmp, skb, n)
		tcp_rbtree_insert(root, skb);
}

/* Collapse ofo queue. Algorithm: select contiguous sequence of skbs
 * and tcp_collapse() them until all the queue is collapsed.
 */
 //把乱序队列 out_of_order_queue（红黑树里的 skb）里
 // 能拼在一起的一段段连续区间找出来，
 // 调用 tcp_collapse() 把这些 skb 合并（collapse）
 // 成更少的 skb，以降低内存/管理开销
static void tcp_collapse_ofo_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 range_truesize, sum_tiny = 0;
	struct sk_buff *skb, *head;
	u32 start, end;
	//乱序队列拿一个数据包
	skb = skb_rb_first(&tp->out_of_order_queue);
new_range:
	if (!skb) {
		tp->ooo_last_skb = skb_rb_last(&tp->out_of_order_queue);
		return;
	}
	start = TCP_SKB_CB(skb)->seq;
	end = TCP_SKB_CB(skb)->end_seq;
	range_truesize = skb->truesize;
	//遍历数据包
	for (head = skb;;) {
		skb = skb_rb_next(skb);

		/* Range is terminated when we see a gap or when
		 * we are at the queue end.
		 */
		if (!skb ||
		    after(TCP_SKB_CB(skb)->seq, end) ||
		    before(TCP_SKB_CB(skb)->end_seq, start)) {
			/* Do not attempt collapsing tiny skbs */
			if (range_truesize != head->truesize ||
			    end - start >= SKB_WITH_OVERHEAD(PAGE_SIZE)) {
					//合并数据包
				tcp_collapse(sk, NULL, &tp->out_of_order_queue,
					     head, skb, start, end);
			} else {
				sum_tiny += range_truesize;
				if (sum_tiny > sk->sk_rcvbuf >> 3)
					return;
			}
			goto new_range;
		}

		range_truesize += skb->truesize;
		if (unlikely(before(TCP_SKB_CB(skb)->seq, start)))
			start = TCP_SKB_CB(skb)->seq;
		if (after(TCP_SKB_CB(skb)->end_seq, end))
			end = TCP_SKB_CB(skb)->end_seq;
	}
}

/*
 * Clean the out-of-order queue to make room.
 * We drop high sequences packets to :
 * 1) Let a chance for holes to be filled.
 *    This means we do not drop packets from ooo queue if their sequence
 *    is before incoming packet sequence.
 * 2) not add too big latencies if thousands of packets sit there.
 *    (But if application shrinks SO_RCVBUF, we could still end up
 *     freeing whole queue here)
 * 3) Drop at least 12.5 % of sk_rcvbuf to avoid malicious attacks.
 *
 * Return true if queue has shrunk.
 */
static bool tcp_prune_ofo_queue(struct sock *sk, const struct sk_buff *in_skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct rb_node *node, *prev;
	bool pruned = false;
	int goal;

	if (RB_EMPTY_ROOT(&tp->out_of_order_queue))
		return false;

	goal = sk->sk_rcvbuf >> 3;
	node = &tp->ooo_last_skb->rbnode;

	do {
		struct sk_buff *skb = rb_to_skb(node);

		/* If incoming skb would land last in ofo queue, stop pruning. */
		if (after(TCP_SKB_CB(in_skb)->seq, TCP_SKB_CB(skb)->seq))
			break;
		pruned = true;
		prev = rb_prev(node);
		rb_erase(node, &tp->out_of_order_queue);
		goal -= skb->truesize;
		tcp_drop_reason(sk, skb, SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE);
		tp->ooo_last_skb = rb_to_skb(prev);
		if (!prev || goal <= 0) {
			if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf &&
			    !tcp_under_memory_pressure(sk))
				break;
			goal = sk->sk_rcvbuf >> 3;
		}
		node = prev;
	} while (node);

	if (pruned) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_OFOPRUNED);
		/* Reset SACK state.  A conforming SACK implementation will
		 * do the same at a timeout based retransmit.  When a connection
		 * is in a sad state like this, we care only about integrity
		 * of the connection not performance.
		 */
		if (tp->rx_opt.sack_ok)
			tcp_sack_reset(&tp->rx_opt);
	}
	return pruned;
}

/* Reduce allocated memory if we can, trying to get
 * the socket within its memory limits again.
 *
 * Return less than zero if we should start dropping frames
 * until the socket owning process reads some of the data
 * to stabilize the situation.
 */
static int tcp_prune_queue(struct sock *sk, const struct sk_buff *in_skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	NET_INC_STATS(sock_net(sk), LINUX_MIB_PRUNECALLED);
	//超过了缓冲区大小
	if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
		tcp_clamp_window(sk);
	//内存压力之下，调整慢启动接收阈值
	else if (tcp_under_memory_pressure(sk))
		tcp_adjust_rcv_ssthresh(sk);
	//上面可能修改过缓冲区大小这里直接返回0
	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;
	//合并skb减小内存消耗
	tcp_collapse_ofo_queue(sk);
	//接收队列不为空，尝试合并接收队列
	if (!skb_queue_empty(&sk->sk_receive_queue))
		
		tcp_collapse(sk, &sk->sk_receive_queue, NULL,
			     skb_peek(&sk->sk_receive_queue),
			     NULL,
			     tp->copied_seq, tp->rcv_nxt);
	//再次判断是否小于内存限制
	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* Collapsing did not help, destructive actions follow.
	 * This must not ever occur. */
	//上述操作还是无法缓解，就开始丢弃乱序数据包！！！！从后往前删除
	//可能存在流量攻击，或者用户态不取数据包
	tcp_prune_ofo_queue(sk, in_skb);

	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* If we are really being abused, tell the caller to silently
	 * drop receive data on the floor.  It will get retransmitted
	 * and hopefully then we'll have sufficient space.
	 */
	NET_INC_STATS(sock_net(sk), LINUX_MIB_RCVPRUNED);

	/* Massive buffer overcommit. */
	tp->pred_flags = 0;
	return -1;
}

static bool tcp_should_expand_sndbuf(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* If the user specified a specific send buffer setting, do
	 * not modify it.
	 */
	//用户没有显示改过buf大小
	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK)
		return false;

	/* If we are under global TCP memory pressure, do not expand.  */
	// //读全局变量判断是否内存压力，如果存在压力，可能主动调小
	if (tcp_under_memory_pressure(sk)) {
		//如果用户没有保留内存 这里大概率是0  ，否则返回剩余的内存（也可能是0）
		int unused_mem = sk_unused_reserved_mem(sk); 

		/* Adjust sndbuf according to reserved mem. But make sure
		 * it never goes below SOCK_MIN_SNDBUF.
		 * See sk_stream_moderate_sndbuf() for more details.
		 */
		//大于两个包 主动调小
		if (unused_mem > SOCK_MIN_SNDBUF)
			WRITE_ONCE(sk->sk_sndbuf, unused_mem);

		return false;
	}

	/* If we are under soft global TCP memory pressure, do not expand.  */
//当前这个 socket 是否已经占用了过多内存
	if (sk_memory_allocated(sk) >= sk_prot_mem_limits(sk, 0))
		return false;

	/* If we filled the congestion window, do not expand.  */
	//途中的数据超过拥塞窗口，已经发出去的都大于最大并发包数了 别扩了
	if (tcp_packets_in_flight(tp) >= tcp_snd_cwnd(tp))
		return false;

	return true;
}

static void tcp_new_space(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//是否可以扩大sndbuf，这里还有可能减小
	if (tcp_should_expand_sndbuf(sk)) {
		//扩充
		tcp_sndbuf_expand(sk);
		tp->snd_cwnd_stamp = tcp_jiffies32;
	}
	//是否唤醒阻塞的进程
	INDIRECT_CALL_1(sk->sk_write_space, sk_stream_write_space, sk);
}

/* Caller made space either from:
 * 1) Freeing skbs in rtx queues (after tp->snd_una has advanced)
 * 2) Sent skbs from output queue (and thus advancing tp->snd_nxt)
 *
 * We might be able to generate EPOLLOUT to the application if:
 * 1) Space consumed in output/rtx queues is below sk->sk_sndbuf/2
 * 2) notsent amount (tp->write_seq - tp->snd_nxt) became
 *    small enough that tcp_stream_memory_free() decides it
 *    is time to generate EPOLLOUT.
 */
void tcp_check_space(struct sock *sk)
{
	/* pairs with tcp_poll() */
	smp_mb();
	//是否没有空间
	if (sk->sk_socket &&
	    test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		tcp_new_space(sk);
		//如果清除了这个标志
		if (!test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))
			tcp_chrono_stop(sk, TCP_CHRONO_SNDBUF_LIMITED);
	}
}

static inline void tcp_data_snd_check(struct sock *sk)
{
	//检查是否有待发送的数据
	tcp_push_pending_frames(sk);
	tcp_check_space(sk);
}

/*
 * Check if sending an ack is needed.
 */
//现在立刻发ack还是延迟发ack  这里注意延迟ack和压缩ack不是一个东西
static void __tcp_ack_snd_check(struct sock *sk, int ofo_possible)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned long rtt, delay;

	    /* More than one full frame received... */
		//收到的数据已经超过一个mss && （quick ack mode || 有pending || ）
	if (((tp->rcv_nxt - tp->rcv_wup) > inet_csk(sk)->icsk_ack.rcv_mss &&
	     /* ... and right edge of window advances far enough.
	      * (tcp_recvmsg() will send ACK otherwise).
	      * If application uses SO_RCVLOWAT, we want send ack now if
	      * we have not received enough bytes to satisfy the condition.
	      */
		//有多少数据还可以给应用
	    (tp->rcv_nxt - tp->copied_seq < sk->sk_rcvlowat ||
	     __tcp_select_window(sk) >= tp->rcv_wnd)) ||   //接收窗口已经大于了通告给对端的窗口大小
	    /* We ACK each frame or... */		
	    tcp_in_quickack_mode(sk) ||						//用户设置的？？
	    /* Protocol state mandates a one-time immediate ACK */
	    inet_csk(sk)->icsk_ack.pending & ICSK_ACK_NOW) {
send_now:
		//立即发送ack
		tcp_send_ack(sk);
		return;
	}
	//没有乱序的情况，那么走延迟ack，其实就是启动定时器，定时器里面分析过
	if (!ofo_possible || RB_EMPTY_ROOT(&tp->out_of_order_queue)) {
		tcp_send_delayed_ack(sk);
		return;
	}
	//这里可能回走第二个条件，乱序很严重 回直接发送ack
	if (!tcp_is_sack(tp) ||
	    tp->compressed_ack >= READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_comp_sack_nr))
		goto send_now;
	//rcv_nxt 变了 说明接收端按序推进了（某些洞被填上了）
	if (tp->compressed_ack_rcv_nxt != tp->rcv_nxt) {
		tp->compressed_ack_rcv_nxt = tp->rcv_nxt;
		tp->dup_ack_counter = 0;
	}
	//必须要超过三次才能进入延迟ack模式？
	if (tp->dup_ack_counter < TCP_FASTRETRANS_THRESH) {
		tp->dup_ack_counter++;
		goto send_now;
	}
	tp->compressed_ack++;
	if (hrtimer_is_queued(&tp->compressed_ack_timer))
		return;

	/* compress ack timer : 5 % of rtt, but no more than tcp_comp_sack_delay_ns */

	rtt = tp->rcv_rtt_est.rtt_us;
	if (tp->srtt_us && tp->srtt_us < rtt)
		rtt = tp->srtt_us;
	//计算压缩 ACK 的延迟， 这里注意上面的的rtt使用时间戳选项计算出来的！
	delay = min_t(unsigned long,
		      READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_comp_sack_delay_ns),
		      rtt * (NSEC_PER_USEC >> 3)/20);
	sock_hold(sk);
	//启动压缩ack定时器
	hrtimer_start_range_ns(&tp->compressed_ack_timer, ns_to_ktime(delay),
			       READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_comp_sack_slack_ns),
			       HRTIMER_MODE_REL_PINNED_SOFT);
}

static inline void tcp_ack_snd_check(struct sock *sk)
{
	if (!inet_csk_ack_scheduled(sk)) {
		/* We sent a data segment already. */
		return;
	}
	__tcp_ack_snd_check(sk, 1);
}

/*
 *	This routine is only called when we have urgent data
 *	signaled. Its the 'slow' part of tcp_urg. It could be
 *	moved inline now as tcp_urg is only called from one
 *	place. We handle URGent data wrong. We have to - as
 *	BSD still doesn't use the correction from RFC961.
 *	For 1003.1g we should support a new option TCP_STDURG to permit
 *	either form (or just set the sysctl tcp_stdurg).
 */

static void tcp_check_urg(struct sock *sk, const struct tcphdr *th)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 ptr = ntohs(th->urg_ptr); //提取序号
	//兼容处理
	if (ptr && !READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_stdurg))
		ptr--;
	ptr += ntohl(th->seq); //这是紧急数据的起始序号

	/* Ignore urgent data that we've already seen and read. */
	//用户已经把这部分数据已经读取了 直接返回
	if (after(tp->copied_seq, ptr))
		return;

	/* Do not replay urg ptr.
	 *
	 * NOTE: interesting situation not covered by specs.
	 * Misbehaving sender may send urg ptr, pointing to segment,
	 * which we already have in ofo queue. We are not able to fetch
	 * such data and will stay in TCP_URG_NOTYET until will be eaten
	 * by recvmsg(). Seems, we are not obliged to handle such wicked
	 * situations. But it is worth to think about possibility of some
	 * DoSes using some hypothetical application level deadlock.
	 */
	if (before(ptr, tp->rcv_nxt))
		return;

	/* Do we already have a newer (or duplicate) urgent pointer? */
	if (tp->urg_data && !after(ptr, tp->urg_seq))
		return;

	/* Tell the world about our new urgent pointer. */
	sk_send_sigurg(sk);

	/* We may be adding urgent data when the last byte read was
	 * urgent. To do this requires some care. We cannot just ignore
	 * tp->copied_seq since we would read the last urgent byte again
	 * as data, nor can we alter copied_seq until this data arrives
	 * or we break the semantics of SIOCATMARK (and thus sockatmark())
	 *
	 * NOTE. Double Dutch. Rendering to plain English: author of comment
	 * above did something sort of 	send("A", MSG_OOB); send("B", MSG_OOB);
	 * and expect that both A and B disappear from stream. This is _wrong_.
	 * Though this happens in BSD with high probability, this is occasional.
	 * Any application relying on this is buggy. Note also, that fix "works"
	 * only in this artificial test. Insert some normal data between A and B and we will
	 * decline of BSD again. Verdict: it is better to remove to trap
	 * buggy users.
	 */
	if (tp->urg_seq == tp->copied_seq && tp->urg_data &&
	    !sock_flag(sk, SOCK_URGINLINE) && tp->copied_seq != tp->rcv_nxt) {
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);
		tp->copied_seq++;
		if (skb && !before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq)) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			__kfree_skb(skb);
		}
	}

	WRITE_ONCE(tp->urg_data, TCP_URG_NOTYET);
	WRITE_ONCE(tp->urg_seq, ptr);

	/* Disable header prediction. */
	tp->pred_flags = 0;
}

/* This is the 'fast' part of urgent handling. */
static void tcp_urg(struct sock *sk, struct sk_buff *skb, const struct tcphdr *th)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Check if we get a new urgent pointer - normally not. */
	//是否设置了紧急标志位
	if (unlikely(th->urg))
		tcp_check_urg(sk, th);

	/* Do we wait for any urgent data? - normally not... */
	if (unlikely(tp->urg_data == TCP_URG_NOTYET)) {
		u32 ptr = tp->urg_seq - ntohl(th->seq) + (th->doff * 4) -
			  th->syn;

		/* Is the urgent pointer pointing into this packet? */
		if (ptr < skb->len) {
			u8 tmp;
			if (skb_copy_bits(skb, ptr, &tmp, 1))
				BUG();
			WRITE_ONCE(tp->urg_data, TCP_URG_VALID | tmp);
			if (!sock_flag(sk, SOCK_DEAD))
				sk->sk_data_ready(sk);
		}
	}
}

/* Accept RST for rcv_nxt - 1 after a FIN.
 * When tcp connections are abruptly terminated from Mac OSX (via ^C), a
 * FIN is sent followed by a RST packet. The RST is sent with the same
 * sequence number as the FIN, and thus according to RFC 5961 a challenge
 * ACK should be sent. However, Mac OSX rate limits replies to challenge
 * ACKs on the closed socket. In addition middleboxes can drop either the
 * challenge ACK or a subsequent RST.
 */
static bool tcp_reset_check(const struct sock *sk, const struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return unlikely(TCP_SKB_CB(skb)->seq == (tp->rcv_nxt - 1) &&
			(1 << sk->sk_state) & (TCPF_CLOSE_WAIT | TCPF_LAST_ACK |
					       TCPF_CLOSING));
}

/* Does PAWS and seqno based validation of an incoming segment, flags will
 * play significant role here.
 */
static bool tcp_validate_incoming(struct sock *sk, struct sk_buff *skb,
				  const struct tcphdr *th, int syn_inerr)
{
	struct tcp_sock *tp = tcp_sk(sk);
	SKB_DR(reason);

	/* RFC1323: H1. Apply PAWS check first. */
	//paws检查 检查没过进入这个分支
	if (tcp_fast_parse_options(sock_net(sk), skb, th, tp) &&
	    tp->rx_opt.saw_tstamp &&
	    tcp_paws_discard(sk, skb)) {
		if (!th->rst) {
			//如果不是rst 是syn的化回挑战ack，正常数据包就会一个dupack
			if (unlikely(th->syn))
				goto syn_challenge;
			NET_INC_STATS(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
			if (!tcp_oow_rate_limited(sock_net(sk), skb,
						  LINUX_MIB_TCPACKSKIPPEDPAWS,
						  &tp->last_oow_ack_time))
				tcp_send_dupack(sk, skb);
			SKB_DR_SET(reason, TCP_RFC7323_PAWS);
			goto discard;
		}
		/* Reset is accepted even if it did not pass PAWS. */
	}

	/* Step 1: check sequence number */
	//检查学列好是否在接收窗口内，不接受进入下面处理逻辑
	reason = tcp_sequence(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);
	if (reason) {
		/* RFC793, page 37: "In all states except SYN-SENT, all reset
		 * (RST) segments are validated by checking their SEQ-fields."
		 * And page 69: "If an incoming segment is not acceptable,
		 * an acknowledgment should be sent in reply (unless the RST
		 * bit is set, if so drop the segment and return)".
		 */
		//同上
		if (!th->rst) {
			if (th->syn)
				goto syn_challenge;
			if (!tcp_oow_rate_limited(sock_net(sk), skb,
						  LINUX_MIB_TCPACKSKIPPEDSEQ,
						  &tp->last_oow_ack_time))
				tcp_send_dupack(sk, skb);
		} else if (tcp_reset_check(sk, skb)) {
			goto reset;
		}
		goto discard;
	}

	/* Step 2: check RST bit */
	//建立连接状态下收到了rst就进入这个分支把
	if (th->rst) {
		/* RFC 5961 3.2 (extend to match against (RCV.NXT - 1) after a
		 * FIN and SACK too if available):
		 * If seq num matches RCV.NXT or (RCV.NXT - 1) after a FIN, or
		 * the right-most SACK block,
		 * then
		 *     RESET the connection
		 * else
		 *     Send a challenge ACK
		 */
		//一个合法的rst直接复位
		if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt ||
		    tcp_reset_check(sk, skb))
			goto reset;
		//如果有sack 则允许匹配最右端的sack边界
		if (tcp_is_sack(tp) && tp->rx_opt.num_sacks > 0) {
			struct tcp_sack_block *sp = &tp->selective_acks[0];
			int max_sack = sp[0].end_seq;
			int this_sack;

			for (this_sack = 1; this_sack < tp->rx_opt.num_sacks;
			     ++this_sack) {
				max_sack = after(sp[this_sack].end_seq,
						 max_sack) ?
					sp[this_sack].end_seq : max_sack;
			}

			if (TCP_SKB_CB(skb)->seq == max_sack)
				goto reset;
		}

		/* Disable TFO if RST is out-of-order
		 * and no data has been received
		 * for current active TFO socket
		 */
		//如果rst不可信，则回复挑战ack
		if (tp->syn_fastopen && !tp->data_segs_in &&
		    sk->sk_state == TCP_ESTABLISHED)
			tcp_fastopen_active_disable(sk);
		tcp_send_challenge_ack(sk);
		SKB_DR_SET(reason, TCP_RESET);
		goto discard;
	}

	/* step 3: check security and precedence [ignored] */

	/* step 4: Check for a SYN
	 * RFC 5961 4.2 : Send a challenge ack
	 */
	//这里是建立连接状态下收到syn 发一个challenge ack
	if (th->syn) {
syn_challenge:
		if (syn_inerr)
			TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNCHALLENGE);
		tcp_send_challenge_ack(sk);
		SKB_DR_SET(reason, TCP_INVALID_SYN);
		goto discard;
	}

	bpf_skops_parse_hdr(sk, skb);

	return true;

discard:
	tcp_drop_reason(sk, skb, reason);
	return false;

reset:
	tcp_reset(sk, skb);
	__kfree_skb(skb);
	return false;
}

/*
 *	TCP receive function for the ESTABLISHED state.
 *
 *	It is split into a fast path and a slow path. The fast path is
 * 	disabled when:
 *	- A zero window was announced from us - zero window probing
 *        is only handled properly in the slow path.
 *	- Out of order segments arrived.
 *	- Urgent data is expected.
 *	- There is no buffer space left
 *	- Unexpected TCP flags/window values/header lengths are received
 *	  (detected by checking the TCP header against pred_flags)
 *	- Data is sent in both directions. Fast path only supports pure senders
 *	  or pure receivers (this means either the sequence number or the ack
 *	  value must stay constant)
 *	- Unexpected TCP option.
 *
 *	When these conditions are not satisfied it drops into a standard
 *	receive procedure patterned after RFC793 to handle all cases.
 *	The first three cases are guaranteed by proper pred_flags setting,
 *	the rest is checked inline. Fast processing is turned on in
 *	tcp_data_queue when everything is OK.
 */
void tcp_rcv_established(struct sock *sk, struct sk_buff *skb)
{
	enum skb_drop_reason reason = SKB_DROP_REASON_NOT_SPECIFIED;
	const struct tcphdr *th = (const struct tcphdr *)skb->data;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int len = skb->len;

	/* TCP congestion window tracking */
	trace_tcp_probe(sk, skb);
	//更新时间戳，后面ack会用到吧
	tcp_mstamp_refresh(tp);
	//检查以下是否有关联的dst
	if (unlikely(!rcu_access_pointer(sk->sk_rx_dst)))
		inet_csk(sk)->icsk_af_ops->sk_rx_dst_set(sk, skb);
	/*
	 *	Header prediction.
	 *	The code loosely follows the one in the famous
	 *	"30 instruction TCP receive" Van Jacobson mail.
	 *
	 *	Van's trick is to deposit buffers into socket queue
	 *	on a device interrupt, to call tcp_recv function
	 *	on the receive process context and checksum and copy
	 *	the buffer to user space. smart...
	 *
	 *	Our current scheme is not silly either but we take the
	 *	extra cost of the net_bh soft interrupt processing...
	 *	We do checksum and copy also but from device to kernel.
	 */
	//还没有时间戳选项
	tp->rx_opt.saw_tstamp = 0;

	/*	pred_flags is 0xS?10 << 16 + snd_wnd
	 *	if header_prediction is to be made
	 *	'S' will always be tp->tcp_header_len >> 2
	 *	'?' will be 0 for the fast path, otherwise pred_flags is 0 to
	 *  turn it off	(when there are holes in the receive
	 *	 space for instance)
	 *	PSH flag is ignored.
	 */
	//命中首部预测（头部长度不变吧，窗口不为零），序列号正好是下一个待接收的，不能确认到还没发送的数据！
	if ((tcp_flag_word(th) & TCP_HP_BITS) == tp->pred_flags &&
	    TCP_SKB_CB(skb)->seq == tp->rcv_nxt &&
	    !after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt)) {
		int tcp_header_len = tp->tcp_header_len; //获取头部长度

		/* Timestamp header prediction: tcp_header_len
		 * is automatically equal to th->doff*4 due to pred_flags
		 * match.
		 */

		/* Check timestamp */
		//只有一个时间戳选项
		if (tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) {
			/* No? Slow path! */
			//提取时间戳选项，到两个字段中
			if (!tcp_parse_aligned_timestamp(tp, th))
				goto slow_path;

			/* If PAWS failed, check it more carefully in slow path */
			//paws 判断时间戳是否倒退？，新的时间戳比我们之前记录要小
			if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)
				goto slow_path;

			/* DO NOT update ts_recent here, if checksum fails
			 * and timestamp was corrupted part, it will result
			 * in a hung connection since we will drop all
			 * future packets due to the PAWS test.
			 */
		}
		//没有负载的情况
		if (len <= tcp_header_len) {
			/* Bulk data transfer: sender */
			//纯ack包
			if (len == tcp_header_len) {
				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len ==
				    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
				    tp->rcv_nxt == tp->rcv_wup)
					//这里是数据包有时间戳选项，把时间戳保存到tp字段中，注意和上面进行区分！
					tcp_store_ts_recent(tp);

				/* We know that such packets are checksummed
				 * on entry.
				 */
				//对ack进行处理
				tcp_ack(sk, skb, 0);
				__kfree_skb(skb);
				//检查是否有需要发送的数据
				tcp_data_snd_check(sk);
				/* When receiving pure ack in fast path, update
				 * last ts ecr directly instead of calling
				 * tcp_rcv_rtt_measure_ts()
				 */
				tp->rcv_rtt_last_tsecr = tp->rx_opt.rcv_tsecr;
				return;
			//非法，直接丢弃
			} else { /* Header too small */
				reason = SKB_DROP_REASON_PKT_TOO_SMALL;
				TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
				goto discard;
			}
		//有负载的情况
		} else {
			int eaten = 0;
			bool fragstolen = false;
			//计算校验和
			if (tcp_checksum_complete(skb))
				goto csum_error;
			//内存压力检查，这里几乎不可能把
			if ((int)skb->truesize > sk->sk_forward_alloc)
				goto step5;

			/* Predicted packet is in window by definition.
			 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
			 * Hence, check seq<=rcv_wup reduces to:
			 */
			//和上面一样跟新ts_recent
			if (tcp_header_len ==
			    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
			    tp->rcv_nxt == tp->rcv_wup)
				tcp_store_ts_recent(tp);
			//这里使用时间戳回显计算rtt,和tcpack里面计算的rtt的区别是用途不一样
			tcp_rcv_rtt_measure_ts(sk, skb);

			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPHPHITS);

			/* Bulk data transfer: receiver */
			skb_dst_drop(skb);
			__skb_pull(skb, tcp_header_len);
			//数据包入队，这里更新了rcv_nxt
			eaten = tcp_queue_rcv(sk, skb, &fragstolen);
			//估计发送端mss 接收端rtt，调整接收慢启动阈值！！！
			tcp_event_data_recv(sk, skb);
			//处理ack
			if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una) {
				/* Well, only one small jumplet in fast path... */
				tcp_ack(sk, skb, FLAG_DATA);
				//是否需要发送数据
				tcp_data_snd_check(sk);
				//判断是否需要发送ack
				if (!inet_csk_ack_scheduled(sk))
					goto no_ack;
			} else {
			//处理ack没有推进的情况
				tcp_update_wl(tp, TCP_SKB_CB(skb)->seq);
			}
			//决定是上面时候发送ack
			__tcp_ack_snd_check(sk, 0);
no_ack:
			if (eaten)
				kfree_skb_partial(skb, fragstolen);
			//唤醒用户态的read/recv
			tcp_data_ready(sk);
			return;
		}
	}
//快速路径
slow_path:
	//计算校验和
	if (len < (th->doff << 2) || tcp_checksum_complete(skb))
		goto csum_error;
	//合法性检查
	if (!th->ack && !th->rst && !th->syn) {
		reason = SKB_DROP_REASON_TCP_FLAGS;
		goto discard;
	}

	/*
	 *	Standard slow path.
	 */
	//验证合法性决定是否能继续处理
	if (!tcp_validate_incoming(sk, skb, th, 1))
		return;

step5:
	reason = tcp_ack(sk, skb, FLAG_SLOWPATH | FLAG_UPDATE_TS_RECENT);
	if ((int)reason < 0) {
		reason = -reason;
		goto discard;
	}
	//处理接收端rtt
	tcp_rcv_rtt_measure_ts(sk, skb);

	/* Process urgent data. */
	//处理紧急数据
	tcp_urg(sk, skb, th);

	/* step 7: process the segment text */
	tcp_data_queue(sk, skb);
	//检查是否有待发送的数据
	tcp_data_snd_check(sk);
	//决定什么时候发送ack
	tcp_ack_snd_check(sk);
	return;

csum_error:
	reason = SKB_DROP_REASON_TCP_CSUM;
	trace_tcp_bad_csum(skb);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);

discard:
	tcp_drop_reason(sk, skb, reason);
}
EXPORT_SYMBOL(tcp_rcv_established);
//接收synack后会调用 三次握手完成后也会调用
void tcp_init_transfer(struct sock *sk, int bpf_op, struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	//初始化pmtu探测的范围
	tcp_mtup_init(sk);
	//查一次路由，超时重传中也会用到
	icsk->icsk_af_ops->rebuild_header(sk);
	//尝试利用 历史缓存的网络性能参数（RTT、ssthresh、乱序阈值等）
	tcp_init_metrics(sk);

	/* Initialize the congestion window to start the transfer.
	 * Cut cwnd down to 1 per RFC5681 if SYN or SYN-ACK has been
	 * retransmitted. In light of RFC6298 more aggressive 1sec
	 * initRTO, we only reset cwnd when more than 1 SYN/SYN-ACK
	 * retransmission has occurred.
	 */
	//如果三次握手阶段丢包，要降低cwnd所以设置为了1
	if (tp->total_retrans > 1 && tp->undo_marker)
		tcp_snd_cwnd_set(tp, 1);
	else
	//这里有用户没有显示配置的话大概率就是10个mss
		tcp_snd_cwnd_set(tp, tcp_init_cwnd(tp, __sk_dst_get(sk)));
	//每次调整拥塞窗口的时间戳
	tp->snd_cwnd_stamp = tcp_jiffies32;
	//bpf相关
	bpf_skops_established(sk, bpf_op, skb);
	/* Initialize congestion control unless BPF initialized it already: */
	if (!icsk->icsk_ca_initialized) //调用拥塞算法初始化的钩子
		tcp_init_congestion_control(sk);
	//设置接收窗口阈值
	tcp_init_buffer_space(sk);
}

void tcp_finish_connect(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	//设置establish状态
	tcp_set_state(sk, TCP_ESTABLISHED);
	icsk->icsk_ack.lrcvtime = tcp_jiffies32;

	if (skb) {
		//将sk关联上路由信息
		icsk->icsk_af_ops->sk_rx_dst_set(sk, skb);
		security_inet_conn_established(sk, skb);
		sk_mark_napi_id(sk, skb);
	}
	//设置拥塞窗口，接收窗口阈值，tcpmtu探测的范围，调用初始化拥塞算法的钩子（如果有） RTT、ssthresh、乱序阈值
	tcp_init_transfer(sk, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, skb);

	/* Prevent spurious tcp_cwnd_restart() on first data
	 * packet.
	 */
	tp->lsndtime = tcp_jiffies32;
	//是否需要启动保活定时器
	if (sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tp));
	//如果没有设置窗口扩大因子
	if (!tp->rx_opt.snd_wscale)
	//设置收包快速路径的标志
		__tcp_fast_path_on(tp, tp->snd_wnd);
	else
		tp->pred_flags = 0;
}

static bool tcp_rcv_fastopen_synack(struct sock *sk, struct sk_buff *synack,
				    struct tcp_fastopen_cookie *cookie)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *data = tp->syn_data ? tcp_rtx_queue_head(sk) : NULL;
	u16 mss = tp->rx_opt.mss_clamp, try_exp = 0;
	bool syn_drop = false;

	if (mss == tp->rx_opt.user_mss) {
		struct tcp_options_received opt;

		/* Get original SYNACK MSS value if user MSS sets mss_clamp */
		tcp_clear_options(&opt);
		opt.user_mss = opt.mss_clamp = 0;
		tcp_parse_options(sock_net(sk), synack, &opt, 0, NULL);
		mss = opt.mss_clamp;
	}

	if (!tp->syn_fastopen) {
		/* Ignore an unsolicited cookie */
		cookie->len = -1;
	} else if (tp->total_retrans) {
		/* SYN timed out and the SYN-ACK neither has a cookie nor
		 * acknowledges data. Presumably the remote received only
		 * the retransmitted (regular) SYNs: either the original
		 * SYN-data or the corresponding SYN-ACK was dropped.
		 */
		syn_drop = (cookie->len < 0 && data);
	} else if (cookie->len < 0 && !tp->syn_data) {
		/* We requested a cookie but didn't get it. If we did not use
		 * the (old) exp opt format then try so next time (try_exp=1).
		 * Otherwise we go back to use the RFC7413 opt (try_exp=2).
		 */
		try_exp = tp->syn_fastopen_exp ? 2 : 1;
	}

	tcp_fastopen_cache_set(sk, mss, cookie, syn_drop, try_exp);

	if (data) { /* Retransmit unacked data in SYN */
		if (tp->total_retrans)
			tp->fastopen_client_fail = TFO_SYN_RETRANSMITTED;
		else
			tp->fastopen_client_fail = TFO_DATA_NOT_ACKED;
		skb_rbtree_walk_from(data)
			 tcp_mark_skb_lost(sk, data);
		tcp_xmit_retransmit_queue(sk);
		NET_INC_STATS(sock_net(sk),
				LINUX_MIB_TCPFASTOPENACTIVEFAIL);
		return true;
	}
	tp->syn_data_acked = tp->syn_data;
	if (tp->syn_data_acked) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPFASTOPENACTIVE);
		/* SYN-data is counted as two separate packets in tcp_ack() */
		if (tp->delivered > 1)
			--tp->delivered;
	}

	tcp_fastopen_add_skb(sk, synack);

	return false;
}

static void smc_check_reset_syn(struct tcp_sock *tp)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (tp->syn_smc && !tp->rx_opt.smc_ok)
			tp->syn_smc = 0;
	}
#endif
}

static void tcp_try_undo_spurious_syn(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 syn_stamp;

	/* undo_marker is set when SYN or SYNACK times out. The timeout is
	 * spurious if the ACK's timestamp option echo value matches the
	 * original SYN timestamp.
	 */
	//发送syn 或者syn ack的时间戳注意！ ，这里存的是第一次！！！
	syn_stamp = tp->retrans_stamp;
	//如果超时重传过， 且有时间戳 且 有时间错选项，且对方ack里的时间戳回显等于第一次发这个数据包的时的时间戳
	if (tp->undo_marker && syn_stamp && tp->rx_opt.saw_tstamp &&
	    syn_stamp == tp->rx_opt.rcv_tsecr)
		tp->undo_marker = 0; //撤销
}

static int tcp_rcv_synsent_state_process(struct sock *sk, struct sk_buff *skb,
					 const struct tcphdr *th)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_fastopen_cookie foc = { .len = -1 };
	int saved_clamp = tp->rx_opt.mss_clamp;
	bool fastopen_fail;
	SKB_DR(reason);
	//解析tcp选项，收到和收到syn包类似，这里时收到synack
	tcp_parse_options(sock_net(sk), skb, &tp->rx_opt, 0, &foc);
	if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr)
		tp->rx_opt.rcv_tsecr -= tp->tsoffset;
	//报文有ack
	if (th->ack) {
		/* rfc793:
		 * "If the state is SYN-SENT then
		 *    first check the ACK bit
		 *      If the ACK bit is set
		 *	  If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send
		 *        a reset (unless the RST bit is set, if so drop
		 *        the segment and return)"
		 */
		//如果 ack_seq 不在 (snd_una, snd_nxt]进入这个分支，属于异常情况 返回1
		if (!after(TCP_SKB_CB(skb)->ack_seq, tp->snd_una) ||
		    after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt)) {
			/* Previous FIN/ACK or RST/ACK might be ignored. */
			if (icsk->icsk_retransmits == 0)
				inet_csk_reset_xmit_timer(sk,
						ICSK_TIME_RETRANS,
						TCP_TIMEOUT_MIN, TCP_RTO_MAX);
			goto reset_and_undo;
		}
		//带时间戳且 rcv_tsecr 不在回显时间戳和now之间 返回1
		if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
		    !between(tp->rx_opt.rcv_tsecr, tp->retrans_stamp,
			     tcp_time_stamp(tp))) {
			NET_INC_STATS(sock_net(sk),
					LINUX_MIB_PAWSACTIVEREJECTED);
			goto reset_and_undo;
		}

		/* Now ACK is acceptable.
		 *
		 * "If the RST bit is set
		 *    If the ACK was acceptable then signal the user "error:
		 *    connection reset", drop the segment, enter CLOSED state,
		 *    delete TCB, and return."
		 */
		//rst 直接释放数据包后返回
		if (th->rst) {
			tcp_reset(sk, skb);
consume:
			__kfree_skb(skb);
			return 0;
		}

		/* rfc793:
		 *   "fifth, if neither of the SYN or RST bits is set then
		 *    drop the segment and return."
		 *
		 *    See note below!
		 *                                        --ANK(990513)
		 */
		//不带 SYN 的 ACK 直接丢弃
		if (!th->syn) {
			SKB_DR_SET(reason, TCP_FLAGS);
			goto discard_and_undo;
		}
		/* rfc793:
		 *   "If the SYN bit is on ...
		 *    are acceptable then ...
		 *    (our SYN has been ACKed), change the connection
		 *    state to ESTABLISHED..."
		 */
		//设置ecn标志位
		tcp_ecn_rcv_synack(tp, th);
		//发送窗口更新时候的序列号
		tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);
		//可能撤销超时重传的判断
		tcp_try_undo_spurious_syn(sk);
		tcp_ack(sk, skb, FLAG_SLOWPATH);

		/* Ok.. it's good. Set up sequence numbers and
		 * move to established.
		 */
		WRITE_ONCE(tp->rcv_nxt, TCP_SKB_CB(skb)->seq + 1); //更新下一个希望接收的序列号
		tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1; //记录上一次更新的rcv_nxt

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		//注意：这里是发送窗口的大小，从接收的报文中获取的
		tp->snd_wnd = ntohs(th->window);
		//不支持窗口扩大因子
		if (!tp->rx_opt.wscale_ok) {
			//窗口缩放因子设置为0
			tp->rx_opt.snd_wscale = tp->rx_opt.rcv_wscale = 0;
			tp->window_clamp = min(tp->window_clamp, 65535U);//这里大概率时65535左右
		}
		//有时间戳选项
		if (tp->rx_opt.saw_tstamp) {
			tp->rx_opt.tstamp_ok	   = 1;
			tp->tcp_header_len =
				sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
			tp->advmss	    -= TCPOLEN_TSTAMP_ALIGNED;
			//记录时间戳，注意这里PAWS机制可能会用到
			tcp_store_ts_recent(tp);
		} else {
			tp->tcp_header_len = sizeof(struct tcphdr);
		}
		//SYN 阶段协商的 MSS 只是对端的建议值 这里要重新计算msscache 这个icsk_pmtu_cookie 大概概率是发送syn包时候设置的
		tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		tcp_initialize_rcv_mss(sk);

		/* Remember, tcp_poll() does not lock socket!
		 * Change state from SYN-SENT only after copied_seq
		 * is initialized. */
		//用户进程已经读取到的位置
		WRITE_ONCE(tp->copied_seq, tp->rcv_nxt);

		smc_check_reset_syn(tp);

		smp_mb();
		//注意：这里设置了establish状态
		tcp_finish_connect(sk, skb);

		fastopen_fail = (tp->syn_fastopen || tp->syn_data) &&
				tcp_rcv_fastopen_synack(sk, skb, &foc);
		//不是dead状态
		//！！！！！也就是说connect 返回的时候是establish状态 但是还没有发送ack （阻塞模式）,如果是非阻塞模式  connect的时候返回的是synsent状态
		if (!sock_flag(sk, SOCK_DEAD)) {
			sk->sk_state_change(sk); //阻塞在 connect() 的进程被唤醒。
			sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);//异步 I/O 事件通知 epoll?
		}
		if (fastopen_fail)
			return -1;
		if (sk->sk_write_pending ||  //有待发的数据这时候刚建立连接 通常不会有吧
		    READ_ONCE(icsk->icsk_accept_queue.rskq_defer_accept) ||  //setsockopt 设置
		    inet_csk_in_pingpong_mode(sk)) { //pingpong模式
			//进入这个分支的思想是，先慢发一个ack然后快发
			/* Save one ACK. Data will be ready after
			 * several ticks, if write_pending is set.
			 *
			 * It may be deleted, but with this feature tcpdumps
			 * look so _wonderfully_ clever, that I was not able
			 * to stand against the temptation 8)     --ANK
			 */
			inet_csk_schedule_ack(sk); //设置ack pending位
			tcp_enter_quickack_mode(sk, TCP_MAX_QUICKACKS);//设置后面快发ack
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK, //启动延迟ack定时器
						  TCP_DELACK_MAX, TCP_RTO_MAX);
			//注意这里直接返回了 没有发ack
			goto consume;
		}
		//发送最后一个ack
		tcp_send_ack(sk);
		return -1;
	}

	/* No ACK in the segment */
	//没有syn sent状态下收到没有ack报文的情况
	//收到rst 直接丢弃
	if (th->rst) {
		/* rfc793:
		 * "If the RST bit is set
		 *
		 *      Otherwise (no ACK) drop the segment and return."
		 */
		SKB_DR_SET(reason, TCP_RESET);
		goto discard_and_undo;
	}

	/* PAWS check. */
	// 支持时间戳选项 序号不合法直接丢弃 PAWS机制
	if (tp->rx_opt.ts_recent_stamp && tp->rx_opt.saw_tstamp &&
	    tcp_paws_reject(&tp->rx_opt, 0)) {
		SKB_DR_SET(reason, TCP_RFC7323_PAWS);
		goto discard_and_undo;
	}
	//收到一个syn包
	if (th->syn) {
		/* We see SYN without ACK. It is attempt of
		 * simultaneous connect with crossed SYNs.
		 * Particularly, it can be connect to self.
		 */
		//注意这里设置成了syn recv  正常第三次握手短暂存活的状态！！！
		tcp_set_state(sk, TCP_SYN_RECV);
		//有时间戳选项，保存时间戳 修正tcp头长度
		if (tp->rx_opt.saw_tstamp) {
			tp->rx_opt.tstamp_ok = 1;
			tcp_store_ts_recent(tp);
			tp->tcp_header_len =
				sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
		} else {
			tp->tcp_header_len = sizeof(struct tcphdr);
		}
		//更新接收序号与用户已读指针
		WRITE_ONCE(tp->rcv_nxt, TCP_SKB_CB(skb)->seq + 1);
		WRITE_ONCE(tp->copied_seq, tp->rcv_nxt);
		tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1;

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		//握手报文不使用窗口缩放
		tp->snd_wnd    = ntohs(th->window);
		tp->snd_wl1    = TCP_SKB_CB(skb)->seq;
		tp->max_window = tp->snd_wnd;

		tcp_ecn_rcv_syn(tp, th);
		//初始化PMTU相关的字段
		tcp_mtup_init(sk);
		//重新计算mss cache  这第二个参数是发syn包的时候设置的
		tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		//设置接收mss
		tcp_initialize_rcv_mss(sk);
		//发送syn ack
		tcp_send_synack(sk);
#if 0
		/* Note, we could accept data and URG from this segment.
		 * There are no obstacles to make this (except that we must
		 * either change tcp_recvmsg() to prevent it from returning data
		 * before 3WHS completes per RFC793, or employ TCP Fast Open).
		 *
		 * However, if we ignore data in ACKless segments sometimes,
		 * we have no reasons to accept it sometimes.
		 * Also, seems the code doing it in step6 of tcp_rcv_state_process
		 * is not flawless. So, discard packet for sanity.
		 * Uncomment this return to process the data.
		 */
		return -1;
#else
		goto consume;
#endif
	}
	/* "fifth, if neither of the SYN or RST bits is set then
	 * drop the segment and return."
	 */

discard_and_undo:
	tcp_clear_options(&tp->rx_opt);
	tp->rx_opt.mss_clamp = saved_clamp;
	tcp_drop_reason(sk, skb, reason);
	return 0;

reset_and_undo:
	tcp_clear_options(&tp->rx_opt);
	tp->rx_opt.mss_clamp = saved_clamp;
	return 1;
}

static void tcp_rcv_synrecv_state_fastopen(struct sock *sk)
{
	struct request_sock *req;

	/* If we are still handling the SYNACK RTO, see if timestamp ECR allows
	 * undo. If peer SACKs triggered fast recovery, we can't undo here.
	 */
	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss)
		tcp_try_undo_loss(sk, false);

	/* Reset rtx states to prevent spurious retransmits_timed_out() */
	tcp_sk(sk)->retrans_stamp = 0;
	inet_csk(sk)->icsk_retransmits = 0;

	/* Once we leave TCP_SYN_RECV or TCP_FIN_WAIT_1,
	 * we no longer need req so release it.
	 */
	req = rcu_dereference_protected(tcp_sk(sk)->fastopen_rsk,
					lockdep_sock_is_held(sk));
	reqsk_fastopen_remove(sk, req, false);

	/* Re-arm the timer because data may have been sent out.
	 * This is similar to the regular data transmission case
	 * when new data has just been ack'ed.
	 *
	 * (TFO) - we could try to be more aggressive and
	 * retransmitting any data sooner based on when they
	 * are sent out.
	 */
	tcp_rearm_rto(sk);//fastopen
}

/*
 *	This function implements the receiving procedure of RFC 793 for
 *	all states except ESTABLISHED and TIME_WAIT.
 *	It's called from both tcp_v4_rcv and tcp_v6_rcv and should be
 *	address independent.
 */

int tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcphdr *th = tcp_hdr(skb);
	struct request_sock *req;
	int queued = 0;
	bool acceptable;
	SKB_DR(reason);

	switch (sk->sk_state) {
	case TCP_CLOSE:
		SKB_DR_SET(reason, TCP_CLOSE);
		goto discard;

	case TCP_LISTEN:
		//listen 状态收到带ack的包，直接rst
		if (th->ack)
			return 1;
		//收到rst包，直接丢弃
		if (th->rst) {
			SKB_DR_SET(reason, TCP_RESET);
			goto discard;
		}
		if (th->syn) {
			//同时置位syn和fin丢弃
			if (th->fin) {
				SKB_DR_SET(reason, TCP_FLAGS);
				goto discard;
			}
			/* It is possible that we process SYN packets from backlog,
			 * so we need to make sure to disable BH and RCU right there.
			 */
			rcu_read_lock();
			local_bh_disable();
			//调用inet_connection_sock的ops进行进一步处理  这里是在tcp_init_sock中注册的
			acceptable = icsk->icsk_af_ops->conn_request(sk, skb) >= 0;
			local_bh_enable();
			rcu_read_unlock();

			if (!acceptable)//不能够接收，比如资源不足，直接回rst
				return 1;
			//正常情况
			consume_skb(skb);
			return 0;
		}
		SKB_DR_SET(reason, TCP_FLAGS);
		goto discard;
	//同时打开也走这里
	case TCP_SYN_SENT:
		tp->rx_opt.saw_tstamp = 0;
		tcp_mstamp_refresh(tp);//更新收包时间戳
		//真正的处理函数 正常时返回-1 返回1 会发送rst 返回0 什么也不做
		queued = tcp_rcv_synsent_state_process(sk, skb, th);
		if (queued >= 0)
			return queued;

		/* Do step6 onward by hand. */
		//返回-1的情况
		//处理是否有urg 几乎不会有
		tcp_urg(sk, skb, th);
		__kfree_skb(skb);
		// 是否有数据可以发送，是否需要扩充sndbuf 或者是否需要唤醒应用层
		tcp_data_snd_check(sk);
		return 0;
	}
	//更新tp的时间戳子字段 //tcp_mstamp
	tcp_mstamp_refresh(tp);
	tp->rx_opt.saw_tstamp = 0;
	req = rcu_dereference_protected(tp->fastopen_rsk,
					lockdep_sock_is_held(sk));
	if (req) {
		bool req_stolen;

		WARN_ON_ONCE(sk->sk_state != TCP_SYN_RECV &&
		    sk->sk_state != TCP_FIN_WAIT1);

		if (!tcp_check_req(sk, skb, req, true, &req_stolen)) {
			SKB_DR_SET(reason, TCP_FASTOPEN);
			goto discard;
		}
	}
	//没有ack可能直接就丢了！！
	if (!th->ack && !th->rst && !th->syn) {
		SKB_DR_SET(reason, TCP_FLAGS);
		goto discard;
	}
	if (!tcp_validate_incoming(sk, skb, th, 0))
		return 0;

	/* step 5: check the ACK field */
	acceptable = tcp_ack(sk, skb, FLAG_SLOWPATH |
				      FLAG_UPDATE_TS_RECENT |
				      FLAG_NO_CHALLENGE_ACK) > 0;

	if (!acceptable) {
		if (sk->sk_state == TCP_SYN_RECV)
			return 1;	/* send one RST */
		tcp_send_challenge_ack(sk);
		SKB_DR_SET(reason, TCP_OLD_ACK);
		goto discard;
	}
	switch (sk->sk_state) {
	case TCP_SYN_RECV:
		tp->delivered++; /* SYN-ACK delivery isn't tracked in tcp_ack */
		if (!tp->srtt_us)
			//这里计算rtt和平滑rtt
			tcp_synack_rtt_meas(sk, req);

		if (req) {
			//如果不是TFO的话这里的req就是空
			tcp_rcv_synrecv_state_fastopen(sk);
		} else {
			//撤销超时重传导致的丢包怀疑标记
			tcp_try_undo_spurious_syn(sk);
			tp->retrans_stamp = 0;
			tcp_init_transfer(sk, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
					  skb);
			//设置用户已经读取到的序列号，这里色湖之为rcv_nxt
			WRITE_ONCE(tp->copied_seq, tp->rcv_nxt);
		}
		smp_mb();
		tcp_set_state(sk, TCP_ESTABLISHED);
		sk->sk_state_change(sk);

		/* Note, that this wakeup is only for marginal crossed SYN case.
		 * Passively open sockets are not waked up, because
		 * sk->sk_sleep == NULL and sk->sk_socket == NULL.
		 */
		//交叉syn会走这里
		if (sk->sk_socket)
			sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
		//初始化snd_una
		tp->snd_una = TCP_SKB_CB(skb)->ack_seq;
		//根据窗口和窗口缩放因子
		tp->snd_wnd = ntohs(th->window) << tp->rx_opt.snd_wscale;
		//记录发送窗口更新时候的序列号
		tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);
		//通告mss的大小减去时间戳选项
		if (tp->rx_opt.tstamp_ok)
			tp->advmss -= TCPOLEN_TSTAMP_ALIGNED;
		//这里通常不会走？ 拥塞算法没有实现钩子？
		if (!inet_csk(sk)->icsk_ca_ops->cong_control)
			tcp_update_pacing_rate(sk);

		/* Prevent spurious tcp_cwnd_restart() on first data packet */
		tp->lsndtime = tcp_jiffies32;

		tcp_initialize_rcv_mss(sk);
		//处理fastpath
		tcp_fast_path_on(tp);
		break;

	case TCP_FIN_WAIT1: {
		int tmo;

		if (req)
			tcp_rcv_synrecv_state_fastopen(sk);
		//这如果break了，表示对端还没有收到本段发出的fin
		if (tp->snd_una != tp->write_seq)
			break;
		//对端确认了本端发送的fin，这里设置为fin_wait2状态
		tcp_set_state(sk, TCP_FIN_WAIT2);
		WRITE_ONCE(sk->sk_shutdown, sk->sk_shutdown | SEND_SHUTDOWN);

		sk_dst_confirm(sk);
		//如果在close中还没有设置dead 那这里就直接推出了！ 什么情况下还么没有设置dead？ 当启用linger的时候（注意区分linger2）
		if (!sock_flag(sk, SOCK_DEAD)) {
			/* Wake up lingering close() */
			sk->sk_state_change(sk);
			break;
		}
		//不优雅的关闭了 直接关闭
		if (READ_ONCE(tp->linger2) < 0) {
			tcp_done(sk);
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
			return 1;
		}
		if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
		    after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt)) {
			/* Receive out of order FIN after close() */
			if (tp->syn_fastopen && th->fin)
				tcp_fastopen_active_disable(sk);
			tcp_done(sk);
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
			return 1;
		}

		/* 这里的代码逻辑如下：首先是围绕这个tmo来处理，这个tmo的值简单可以概括成用户是否配置，
		如果配置了那就要看这个值大还是小，如果没有配置，那就是
		走正常1分钟超时逻辑。如果用户配置了linger2 且 大于1分钟的话，
		那就先启动fin_wait2d定时器，注意这个定时器到期的时间时配置的时间减去一分钟，
		然后在这样就会先在 FIN_WAIT2 等 tmo - TIMEWAIT_LEN，
		到点再进 TIME_WAIT*/
		//用户配置的时间，或者是默认的60s
		tmo = tcp_fin_time(sk);
		//tmo超过60s的情况,这里启动fin_wait2定时器，当定时到期还没有收到对方的fin包的话当定时器到期的时候tcp_time_wait，
		// 里面会启动一个定时器，如果此时收到了fin包则会找到tw套接字重新经过60秒的时间
		// 如果还超时了则直接释放资源。
		// 如果fin_wait2定时器没有到期的时候收到了fin包，则会在下tcp_fin中调用tcp_time_wait
		if (tmo > TCP_TIMEWAIT_LEN) {
			//fin_wait2定时器
			inet_csk_reset_keepalive_timer(sk, tmo - TCP_TIMEWAIT_LEN);
		//这里是正常抓包三次挥手时候走的逻辑，如果收到fin 或者 用户锁住了sock 就会进入这个分支
		// 问题是收到fin包为什么会启动一个定时器呢？不应该直接进入timewwwai吗？？
		// 这里的逻辑如果linger2小于60秒 则启动一个时常为linger2的定时器，如果这里右fin标志后面回直接tcp_fin的处理中回直接进入timewait状态
		//如果是由于用户持有锁进入这个分支则启动一个60s的fin_wati2定时器当定时器到期还没有收到fin 的话就rst，如果期间收到了fin的话则tcp_fin会处理
		} else if (th->fin || sock_owned_by_user(sk)) {
			/* Bad case. We could lose such FIN otherwise.
			 * It is not a big problem, but it looks confusing
			 * and not so rare event. We still can lose it now,
			 * if it spins in bh_lock_sock(), but it is really
			 * marginal case.
			 */
			////对端的数据包带fin或者用户持有sock
			//fin_wait2定时器 tcp_keepalive_timer
			inet_csk_reset_keepalive_timer(sk, tmo);
		} else {
		//正常四次挥手的逻辑，没有fin 标志位，这里启动一个60s的fin_wait2定时器
		//注意这里直接创建了tw套接字，进入了tw状态，如果60s每有收到fin则直接释放资源，如果收到了fin则在
		//外层中会直接找到这个tw套接字，并重新开始计时！！！！，这个和上面linger2大于60 有点类似 本质上是防止对端不发fin 我方不释放资源
			tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
			goto consume;
		}
		break;
	}

	case TCP_CLOSING:
		if (tp->snd_una == tp->write_seq) {
			tcp_time_wait(sk, TCP_TIME_WAIT, 0);
			goto consume;
		}
		break;

	case TCP_LAST_ACK:
		//对方ack了发送的fin，四次挥手最后一个数据包已经接收到了
		if (tp->snd_una == tp->write_seq) {
			tcp_update_metrics(sk);//保存本次连接的一些信息，方便指导下次
			tcp_done(sk);
			goto consume;
		}
		break;
	}

	/* step 6: check the URG bit */
	tcp_urg(sk, skb, th);

	/* step 7: process the segment text */
	switch (sk->sk_state) {
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		if (!before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
			/* If a subflow has been reset, the packet should not
			 * continue to be processed, drop the packet.
			 */
			if (sk_is_mptcp(sk) && !mptcp_incoming_options(sk, skb))
				goto discard;
			break;
		}
		fallthrough;
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		/* RFC 793 says to queue data in these states,
		 * RFC 1122 says we MUST send a reset.
		 * BSD 4.4 also does reset.
		 */
		//收到了对端的fin
		if (sk->sk_shutdown & RCV_SHUTDOWN) {
			//如果数据包携带数据，发rst复位连接
			if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
			    after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt)) {
				NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
				tcp_reset(sk, skb);
				return 1;
			}
		}
		fallthrough;//注意这里如果是处于finwai2状态，则直接继续执行，fin包交给tcp_data_queuec处理
	case TCP_ESTABLISHED:
		tcp_data_queue(sk, skb);
		queued = 1;
		break;
	}

	/* tcp_data could move socket to TIME-WAIT */
	//不是close状态，检查是否需要发送ack或者是否需要发送数据
	if (sk->sk_state != TCP_CLOSE) {
		tcp_data_snd_check(sk);
		tcp_ack_snd_check(sk);
	}

	if (!queued) {
discard:
		tcp_drop_reason(sk, skb, reason);
	}
	return 0;

consume:
	__kfree_skb(skb);
	return 0;
}
EXPORT_SYMBOL(tcp_rcv_state_process);

static inline void pr_drop_req(struct request_sock *req, __u16 port, int family)
{
	struct inet_request_sock *ireq = inet_rsk(req);

	if (family == AF_INET)
		net_dbg_ratelimited("drop open request from %pI4/%u\n",
				    &ireq->ir_rmt_addr, port);
#if IS_ENABLED(CONFIG_IPV6)
	else if (family == AF_INET6)
		net_dbg_ratelimited("drop open request from %pI6/%u\n",
				    &ireq->ir_v6_rmt_addr, port);
#endif
}

/* RFC3168 : 6.1.1 SYN packets must not have ECT/ECN bits set
 *
 * If we receive a SYN packet with these bits set, it means a
 * network is playing bad games with TOS bits. In order to
 * avoid possible false congestion notifications, we disable
 * TCP ECN negotiation.
 *
 * Exception: tcp_ca wants ECN. This is required for DCTCP
 * congestion control: Linux DCTCP asserts ECT on all packets,
 * including SYN, which is most optimal solution; however,
 * others, such as FreeBSD do not.
 *
 * Exception: At least one of the reserved bits of the TCP header (th->res1) is
 * set, indicating the use of a future TCP extension (such as AccECN). See
 * RFC8311 §4.3 which updates RFC3168 to allow the development of such
 * extensions.
 */
static void tcp_ecn_create_request(struct request_sock *req,
				   const struct sk_buff *skb,
				   const struct sock *listen_sk,
				   const struct dst_entry *dst)
{
	const struct tcphdr *th = tcp_hdr(skb);
	const struct net *net = sock_net(listen_sk);
	bool th_ecn = th->ece && th->cwr;
	bool ect, ecn_ok;
	u32 ecn_ok_dst;
	//检查syn包中是否设置了ecn标志位
	if (!th_ecn)
		return;

	ect = !INET_ECN_is_not_ect(TCP_SKB_CB(skb)->ip_dsfield);//ip层必须要支持ecn
	ecn_ok_dst = dst_feature(dst, DST_FEATURE_ECN_MASK);
	ecn_ok = READ_ONCE(net->ipv4.sysctl_tcp_ecn) || ecn_ok_dst; //系统是否使能了ecn
	// 数据包没有ecn能力 但是系统启用了 || 拥塞算法要求启用 || 网络路径要求启用 || bpf要求启用
	if (((!ect || th->res1) && ecn_ok) || tcp_ca_needs_ecn(listen_sk) ||
	    (ecn_ok_dst & DST_FEATURE_ECN_CA) ||
	    tcp_bpf_ca_needs_ecn((struct sock *)req))
		inet_rsk(req)->ecn_ok = 1; //表示启用ecn
}

static void tcp_openreq_init(struct request_sock *req,
			     const struct tcp_options_received *rx_opt,
			     struct sk_buff *skb, const struct sock *sk)
{
	struct inet_request_sock *ireq = inet_rsk(req);

	req->rsk_rcv_wnd = 0;		/* So that tcp_send_synack() knows! *///接收窗口初始化为0
	tcp_rsk(req)->rcv_isn = TCP_SKB_CB(skb)->seq; //客户端的初始序列号
	tcp_rsk(req)->rcv_nxt = TCP_SKB_CB(skb)->seq + 1; //期望接收的下一个序列号
	tcp_rsk(req)->snt_synack = 0;
	tcp_rsk(req)->last_oow_ack_time = 0;
	//根据opt设置是否支持一些选项
	req->mss = rx_opt->mss_clamp; //mss
	req->ts_recent = rx_opt->saw_tstamp ? rx_opt->rcv_tsval : 0;
	ireq->tstamp_ok = rx_opt->tstamp_ok;
	ireq->sack_ok = rx_opt->sack_ok;
	ireq->snd_wscale = rx_opt->snd_wscale;
	ireq->wscale_ok = rx_opt->wscale_ok;
	ireq->acked = 0;
	ireq->ecn_ok = 0;
	ireq->ir_rmt_port = tcp_hdr(skb)->source; //客户端端口
	ireq->ir_num = ntohs(tcp_hdr(skb)->dest); //服务端端口
	ireq->ir_mark = inet_request_mark(sk, skb); //设置mark 是不是iptable那个mark？
#if IS_ENABLED(CONFIG_SMC)
	ireq->smc_ok = rx_opt->smc_ok && !(tcp_sk(sk)->smc_hs_congested &&
			tcp_sk(sk)->smc_hs_congested(sk));
#endif
}

//这里的第三个参数表示是否跟listensocket相关联
struct request_sock *inet_reqsk_alloc(const struct request_sock_ops *ops,
				      struct sock *sk_listener,
				      bool attach_listener)
{
	//这里申请了一个reqsock 注意：这个结构体里面包了一层sock外面是这里根据req拿到inet_request_sock
	struct request_sock *req = reqsk_alloc(ops, sk_listener,
					       attach_listener);

	if (req) {
		//这里根据req拿到inet_request_sock
		struct inet_request_sock *ireq = inet_rsk(req);
		//初始化一些字段
		ireq->ireq_opt = NULL;//ip选项相关
#if IS_ENABLED(CONFIG_IPV6)
		ireq->pktopts = NULL;
#endif
		atomic64_set(&ireq->ir_cookie, 0);
		ireq->ireq_state = TCP_NEW_SYN_RECV;//注意这里设置了TCP_NEW_SYN_RECV状态！
		write_pnet(&ireq->ireq_net, sock_net(sk_listener));//设置网络命名空间
		ireq->ireq_family = sk_listener->sk_family;
		req->timeout = TCP_TIMEOUT_INIT;//这个应该是对端如果不回ack的初始时间 1s
	}

	return req;
}
EXPORT_SYMBOL(inet_reqsk_alloc);

/*
 * Return true if a syncookie should be sent
 */
static bool tcp_syn_flood_action(const struct sock *sk, const char *proto)
{
	struct request_sock_queue *queue = &inet_csk(sk)->icsk_accept_queue;
	const char *msg = "Dropping request";
	struct net *net = sock_net(sk);
	bool want_cookie = false;
	u8 syncookies;
	//获取系统参数配置，默认是1，表示在队列慢时候启用
	syncookies = READ_ONCE(net->ipv4.sysctl_tcp_syncookies);

#ifdef CONFIG_SYN_COOKIES
	if (syncookies) {
		msg = "Sending cookies";
		want_cookie = true;
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPREQQFULLDOCOOKIES);
	} else
#endif
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPREQQFULLDROP);
	//这里的内容就是打印一次告警日志，只打印一次
	if (!READ_ONCE(queue->synflood_warned) && syncookies != 2 &&
	    xchg(&queue->synflood_warned, 1) == 0) {
		if (IS_ENABLED(CONFIG_IPV6) && sk->sk_family == AF_INET6) {
			net_info_ratelimited("%s: Possible SYN flooding on port [%pI6c]:%u. %s.\n",
					proto, inet6_rcv_saddr(sk),
					sk->sk_num, msg);
		} else {
			net_info_ratelimited("%s: Possible SYN flooding on port %pI4:%u. %s.\n",
					proto, &sk->sk_rcv_saddr,
					sk->sk_num, msg);
		}
	}
	//这里如果系统参数开启了syncookies 这里返回true
	return want_cookie;
}

static void tcp_reqsk_record_syn(const struct sock *sk,
				 struct request_sock *req,
				 const struct sk_buff *skb)
{
	//用户是否同setsockopt设置保存syn的选项，如果是1,则保存传输头部， 如果是2则保存完整头部
	if (tcp_sk(sk)->save_syn) {
		u32 len = skb_network_header_len(skb) + tcp_hdrlen(skb);
		struct saved_syn *saved_syn;
		u32 mac_hdrlen;
		void *base;

		if (tcp_sk(sk)->save_syn == 2) {  /* Save full header. */
			base = skb_mac_header(skb);
			mac_hdrlen = skb_mac_header_len(skb);
			len += mac_hdrlen; //加上mac头
		} else {
			//save_syn为1 表示base指向ip头
			base = skb_network_header(skb);
			mac_hdrlen = 0;
		}

		saved_syn = kmalloc(struct_size(saved_syn, data, len),
				    GFP_ATOMIC);
		if (saved_syn) {
			saved_syn->mac_hdrlen = mac_hdrlen;
			saved_syn->network_hdrlen = skb_network_header_len(skb);
			saved_syn->tcp_hdrlen = tcp_hdrlen(skb);
			memcpy(saved_syn->data, base, len);//根据长度拷贝数据包头
			req->saved_syn = saved_syn;
		}
	}
}

/* If a SYN cookie is required and supported, returns a clamped MSS value to be
 * used for SYN cookie generation.
 */
u16 tcp_get_syncookie_mss(struct request_sock_ops *rsk_ops,
			  const struct tcp_request_sock_ops *af_ops,
			  struct sock *sk, struct tcphdr *th)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u16 mss;

	if (READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_syncookies) != 2 &&
	    !inet_csk_reqsk_queue_is_full(sk))
		return 0;

	if (!tcp_syn_flood_action(sk, rsk_ops->slab_name))
		return 0;

	if (sk_acceptq_is_full(sk)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
		return 0;
	}

	mss = tcp_parse_mss_option(th, tp->rx_opt.user_mss);
	if (!mss)
		mss = af_ops->mss_clamp;

	return mss;
}
EXPORT_SYMBOL_GPL(tcp_get_syncookie_mss);

//收到syn包
int tcp_conn_request(struct request_sock_ops *rsk_ops,
		     const struct tcp_request_sock_ops *af_ops,
		     struct sock *sk, struct sk_buff *skb)
{
	struct tcp_fastopen_cookie foc = { .len = -1 };
	__u32 isn = TCP_SKB_CB(skb)->tcp_tw_isn;
	struct tcp_options_received tmp_opt;
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	struct sock *fastopen_sk = NULL;
	struct request_sock *req;
	bool want_cookie = false;
	struct dst_entry *dst;
	struct flowi fl;
	u8 syncookies;
	//拿到系统参数关于syncookie的配置
	syncookies = READ_ONCE(net->ipv4.sysctl_tcp_syncookies);

	/* TW buckets are converted to open requests without
	 * limitations, they conserve resources and peer is
	 * evidently real one.
	 */
	//是否启用syn cookies
	//半连接队列是否超过全连接
	//这里的isn表示初始序列号 在timewait状态的时候这个isn可能不是0
	if ((syncookies == 2 || inet_csk_reqsk_queue_is_full(sk)) && !isn) {
		//是否需要cookie
		want_cookie = tcp_syn_flood_action(sk, rsk_ops->slab_name);
		if (!want_cookie)
			goto drop;
	}
	//如果全连接队列满了，这里直接丢弃了
	if (sk_acceptq_is_full(sk)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
		goto drop;
	}
	//申请一个半连接req结构： 注意如果cookie的话后面会释放
	req = inet_reqsk_alloc(rsk_ops, sk, !want_cookie);
	if (!req)
		goto drop;
	//设置syncookies
	req->syncookie = want_cookie;
	tcp_rsk(req)->af_specific = af_ops;//挂上ops
	tcp_rsk(req)->ts_off = 0; //时间戳偏移清零
#if IS_ENABLED(CONFIG_MPTCP)
	tcp_rsk(req)->is_mptcp = 0;
#endif
	//清楚选项相关
	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = af_ops->mss_clamp; //这里是默认的536
	tmp_opt.user_mss  = tp->rx_opt.user_mss; //用户配置的mss？这里的tp是监听套接字吧，大概率是0
	//从收到的 TCP 报文头部里逐项解析 TCP 选项MSS、窗口扩大、时间戳、SACK、Fast Open、MD5等，然后把解析结果写进 opt_rx
	tcp_parse_options(sock_net(sk), skb, &tmp_opt, 0,
			  want_cookie ? NULL : &foc);
	//如果要启用syn cookie的话是不能够有时间戳和窗口缩放选项的
	if (want_cookie && !tmp_opt.saw_tstamp)
		tcp_clear_options(&tmp_opt);

	if (IS_ENABLED(CONFIG_SMC) && want_cookie)
		tmp_opt.smc_ok = 0;
	//设置是否支持时间戳
	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	//保存端口，序列号信息
	tcp_openreq_init(req, &tmp_opt, skb, sk);
	inet_rsk(req)->no_srccheck = inet_test_bit(TRANSPARENT, sk);

	/* Note: tcp_v6_init_req() might override ir_iif for link locals */
	inet_rsk(req)->ir_iif = inet_request_bound_dev_if(sk, skb);
	//调用req的ops查路由，然后拿到dst 这里调用的函数为tcp_v4_route_req(设置的req中sock的地址)
	dst = af_ops->route_req(sk, skb, &fl, req);
	if (!dst)
		goto drop_and_free;

	if (tmp_opt.tstamp_ok)
		//根据源ip目的ip算出一个时间戳偏移，这个的用处好像是相当于一个加密，防止攻击？
		tcp_rsk(req)->ts_off = af_ops->init_ts_off(net, skb);
	//没有使用使用syncookie 同时不是timewait的重用，大多数情况是这样的吧
	if (!want_cookie && !isn) {
		//注意这里获取了半连接队列的最大长度 	
		int max_syn_backlog = READ_ONCE(net->ipv4.sysctl_max_syn_backlog);

		/* Kill the following clause, if you dislike this way. */
		if (!syncookies && //没有启用syncookie
		    (max_syn_backlog - inet_csk_reqsk_queue_len(sk) < 
		     (max_syn_backlog >> 2)) &&  //队列长度超过了四分之三？
		    !tcp_peer_is_proven(req, dst)) { //从metries中查找是否历史连接过
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			//这里直接拒绝连接了
			pr_drop_req(req, ntohs(tcp_hdr(skb)->source),
				    rsk_ops->family);
			goto drop_and_release;
		}
		//否则初始化服务端的序列号tcp_v4_init_seq
		isn = af_ops->init_seq(skb);
	}
	//协商ecn
	tcp_ecn_create_request(req, skb, sk, dst);
	//syn cookie的话会走这个分支初始化序列号
	if (want_cookie) {
		isn = cookie_init_sequence(af_ops, sk, skb, &req->mss);//这里传入的mss是对端通告的大小
		//如果对端不支持时间戳，则禁用ecn
		if (!tmp_opt.tstamp_ok)
			inet_rsk(req)->ecn_ok = 0;
	}
	//这里设置了序列号
	tcp_rsk(req)->snt_isn = isn;
	tcp_rsk(req)->txhash = net_tx_rndhash();
	tcp_rsk(req)->syn_tos = TCP_SKB_CB(skb)->ip_dsfield;
	tcp_openreq_init_rwin(req, sk, dst);
	sk_rx_queue_set(req_to_sk(req), skb);
	//如果是正常握手流程
	if (!want_cookie) {
		//根据用户选项是否需要保存syn包
		tcp_reqsk_record_syn(sk, req, skb);
		fastopen_sk = tcp_try_fastopen(sk, skb, req, &foc, dst);
	}
	//TFO相关
	if (fastopen_sk) {
		af_ops->send_synack(fastopen_sk, dst, &fl, req,
				    &foc, TCP_SYNACK_FASTOPEN, skb);
		/* Add the child socket directly into the accept queue */
		if (!inet_csk_reqsk_queue_add(sk, req, fastopen_sk)) {
			reqsk_fastopen_remove(fastopen_sk, req, false);
			bh_unlock_sock(fastopen_sk);
			sock_put(fastopen_sk);
			goto drop_and_free;
		}
		sk->sk_data_ready(sk);
		bh_unlock_sock(fastopen_sk);
		sock_put(fastopen_sk);
	} else {
		tcp_rsk(req)->tfo_listener = false;
		if (!want_cookie) {
			req->timeout = tcp_timeout_init((struct sock *)req);//初始化超时重传的时间
			//将半连接结构插入到ehash中，更新半连接的数量
			inet_csk_reqsk_queue_hash_add(sk, req, req->timeout);
		}
		//发送syn_ack tcp_v4_send_synack
		af_ops->send_synack(sk, dst, &fl, req, &foc,
				    !want_cookie ? TCP_SYNACK_NORMAL :
						   TCP_SYNACK_COOKIE,
				    skb);
		//如果是syncookie 这个要释放半连接结构
		if (want_cookie) {
			reqsk_free(req);
			return 0;
		}
	}
	reqsk_put(req);
	return 0;

drop_and_release:
	dst_release(dst);
drop_and_free:
	__reqsk_free(req);
drop:
	tcp_listendrop(sk);
	return 0;
}
EXPORT_SYMBOL(tcp_conn_request);
