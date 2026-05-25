// SPDX-License-Identifier: GPL-2.0-only
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

#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/busy_poll.h>

static bool tcp_in_window(u32 seq, u32 end_seq, u32 s_win, u32 e_win)
{
	if (seq == s_win)
		return true;
	if (after(end_seq, s_win) && before(seq, e_win))
		return true;
	return seq == e_win && seq == end_seq;
}

static enum tcp_tw_status
tcp_timewait_check_oow_rate_limit(struct inet_timewait_sock *tw,
				  const struct sk_buff *skb, int mib_idx)
{
	struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);

	if (!tcp_oow_rate_limited(twsk_net(tw), skb, mib_idx,
				  &tcptw->tw_last_oow_ack_time)) {
		/* Send ACK. Note, we do not put the bucket,
		 * it will be released by caller.
		 */
		return TCP_TW_ACK;
	}

	/* We are rate-limiting, so just release the tw sock and drop skb. */
	inet_twsk_put(tw);
	return TCP_TW_SUCCESS;
}

/*
 * * Main purpose of TIME-WAIT state is to close connection gracefully,
 *   when one of ends sits in LAST-ACK or CLOSING retransmitting FIN
 *   (and, probably, tail of data) and one or more our ACKs are lost.
 * * What is TIME-WAIT timeout? It is associated with maximal packet
 *   lifetime in the internet, which results in wrong conclusion, that
 *   it is set to catch "old duplicate segments" wandering out of their path.
 *   It is not quite correct. This timeout is calculated so that it exceeds
 *   maximal retransmission timeout enough to allow to lose one (or more)
 *   segments sent by peer and our ACKs. This time may be calculated from RTO.
 * * When TIME-WAIT socket receives RST, it means that another end
 *   finally closed and we are allowed to kill TIME-WAIT too.
 * * Second purpose of TIME-WAIT is catching old duplicate segments.
 *   Well, certainly it is pure paranoia, but if we load TIME-WAIT
 *   with this semantics, we MUST NOT kill TIME-WAIT state with RSTs.
 * * If we invented some more clever way to catch duplicates
 *   (f.e. based on PAWS), we could truncate TIME-WAIT to several RTOs.
 *
 * The algorithm below is based on FORMAL INTERPRETATION of RFCs.
 * When you compare it to RFCs, please, read section SEGMENT ARRIVES
 * from the very beginning.
 *
 * NOTE. With recycling (and later with fin-wait-2) TW bucket
 * is _not_ stateless. It means, that strictly speaking we must
 * spinlock it. I do not want! Well, probability of misbehaviour
 * is ridiculously low and, seems, we could use some mb() tricks
 * to avoid misread sequence numbers, states etc.  --ANK
 *
 * We don't need to initialize tmp_out.sack_ok as we don't use the results
 */
/*- 窗口外 / PAWS 失 回 ACK（限速）
- 收到 RST 直接 `kill tw_sock`
- 收到 SYN 且 seq 合法 → 回 RST
- 防止旧连接干扰新连接建立。
- 纯 ACK / 重复 ACK  丢弃报文
- 如果不是 FIN，或者 FIN 位置不对 回RST
- 收到了和发`fin`真正进入`timewait`状态
*/
enum tcp_tw_status
tcp_timewait_state_process(struct inet_timewait_sock *tw, struct sk_buff *skb,
			   const struct tcphdr *th)
{
	struct tcp_options_received tmp_opt;
	struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
	bool paws_reject = false;

	tmp_opt.saw_tstamp = 0;
	//如果存在时间戳，再通过PAWS机制判断是否合法
	if (th->doff > (sizeof(*th) >> 2) && tcptw->tw_ts_recent_stamp) {
		tcp_parse_options(twsk_net(tw), skb, &tmp_opt, 0, NULL);

		if (tmp_opt.saw_tstamp) {
			if (tmp_opt.rcv_tsecr)
				tmp_opt.rcv_tsecr -= tcptw->tw_ts_offset;
			tmp_opt.ts_recent	= tcptw->tw_ts_recent;
			tmp_opt.ts_recent_stamp	= tcptw->tw_ts_recent_stamp;
			paws_reject = tcp_paws_reject(&tmp_opt, th->rst);
		}
	}
	//如果是finwait2状态下创建的套接字
	if (tw->tw_substate == TCP_FIN_WAIT2) {
		/* Just repeat all the checks of tcp_rcv_state_process() */

		/* Out of window, send ACK */
		//如果没有通过paws机制检查，或者超出了窗口则会回一个ack
		if (paws_reject ||
		    !tcp_in_window(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq,
				   tcptw->tw_rcv_nxt,
				   tcptw->tw_rcv_nxt + tcptw->tw_rcv_wnd))
			return tcp_timewait_check_oow_rate_limit(
				tw, skb, LINUX_MIB_TCPACKSKIPPEDFINWAIT2);
		//如果通过了检查携带rst，直接清除tw套接字释放资源
		if (th->rst)
			goto kill;
		//TCP_FIN_WAIT2状态下收到syn包 同时syn包大于下一个待接收的序列号，则直接回rst
		if (th->syn && !before(TCP_SKB_CB(skb)->seq, tcptw->tw_rcv_nxt))
			return TCP_TW_RST;

		/* Dup ACK? */
		//没有ack标志位，或者是重复的ack
		if (!th->ack ||
		    !after(TCP_SKB_CB(skb)->end_seq, tcptw->tw_rcv_nxt) ||
		    TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq) {
			inet_twsk_put(tw);
			return TCP_TW_SUCCESS; //外面默默丢弃了
		}

		/* New data or FIN. If new data arrive after half-duplex close,
		 * reset.
		 */
		//不是fin或者是新数据，直接回rst，这里是意味着finwait2就不能接对端继续发呆数据包吗？
		//注意可能是因为这里是tw套接字承载着finwait2
		if (!th->fin ||
		    TCP_SKB_CB(skb)->end_seq != tcptw->tw_rcv_nxt + 1)
			return TCP_TW_RST;

		/* FIN arrived, enter true time-wait state. */
		//走到这里表示收到了合法的fin包
		tw->tw_substate	  = TCP_TIME_WAIT;
		//更新下一个待接收的序号
		tcptw->tw_rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (tmp_opt.saw_tstamp) {
			tcptw->tw_ts_recent_stamp = ktime_get_seconds();
			tcptw->tw_ts_recent	  = tmp_opt.rcv_tsval;
		}
		//注意这里是重新开始tw 计时
		inet_twsk_reschedule(tw, TCP_TIMEWAIT_LEN);
		return TCP_TW_ACK;
	}

	/*
	 *	Now real TIME-WAIT state.
	 *
	 *	RFC 1122:
	 *	"When a connection is [...] on TIME-WAIT state [...]
	 *	[a TCP] MAY accept a new SYN from the remote TCP to
	 *	reopen the connection directly, if it:
	 *
	 *	(1)  assigns its initial sequence number for the new
	 *	connection to be larger than the largest sequence
	 *	number it used on the previous connection incarnation,
	 *	and
	 *
	 *	(2)  returns to TIME-WAIT state if the SYN turns out
	 *	to be an old duplicate".
	 */
	//正常timewait状态的处理，通过了检查如果是纯ack或者是rst
	if (!paws_reject &&
	    (TCP_SKB_CB(skb)->seq == tcptw->tw_rcv_nxt &&
	     (TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq || th->rst))) {
		/* In window segment, it may be only reset or bare ack. */
		//如果收到了rst 直接释放资源
		if (th->rst) {
			/* This is TIME_WAIT assassination, in two flavors.
			 * Oh well... nobody has a sufficient solution to this
			 * protocol bug yet.
			 */
			if (!READ_ONCE(twsk_net(tw)->ipv4.sysctl_tcp_rfc1337)) {
kill:
				inet_twsk_deschedule_put(tw);
				return TCP_TW_SUCCESS;
			}
		} else {
			//重新开始定时器，因为可能是ack丢失了
			inet_twsk_reschedule(tw, TCP_TIMEWAIT_LEN);
		}

		if (tmp_opt.saw_tstamp) {
			tcptw->tw_ts_recent	  = tmp_opt.rcv_tsval;
			tcptw->tw_ts_recent_stamp = ktime_get_seconds();
		}

		inet_twsk_put(tw);
		return TCP_TW_SUCCESS;
	}

	/* Out of window segment.

	   All the segments are ACKed immediately.

	   The only exception is new SYN. We accept it, if it is
	   not old duplicate and we are not in danger to be killed
	   by delayed old duplicates. RFC check is that it has
	   newer sequence number works at rates <40Mbit/sec.
	   However, if paws works, it is reliable AND even more,
	   we even may relax silly seq space cutoff.

	   RED-PEN: we violate main RFC requirement, if this SYN will appear
	   old duplicate (i.e. we receive RST in reply to SYN-ACK),
	   we must return socket to time-wait state. It is not good,
	   but not fatal yet.
	 */
	//窗口外的数据包，如果是纯syn包，注意这里会重新在外面找listne套接字
	if (th->syn && !th->rst && !th->ack && !paws_reject &&
	    (after(TCP_SKB_CB(skb)->seq, tcptw->tw_rcv_nxt) ||//序列号大于下一个待接收的
	     (tmp_opt.saw_tstamp &&
	      (s32)(tcptw->tw_ts_recent - tmp_opt.rcv_tsval) < 0))) {//时间戳合理
		u32 isn = tcptw->tw_snd_nxt + 65535 + 2;//必须大于旧连接的序列号
		if (isn == 0)
			isn++;
		TCP_SKB_CB(skb)->tcp_tw_isn = isn;
		return TCP_TW_SYN;
	}
	//由于PAWS拒绝
	if (paws_reject)
		__NET_INC_STATS(twsk_net(tw), LINUX_MIB_PAWSESTABREJECTED);
	//没有携带rst，但是由于序列号被拒绝 会ack，但是限速
	if (!th->rst) {
		/* In this case we must reset the TIMEWAIT timer.
		 *
		 * If it is ACKless SYN it may be both old duplicate
		 * and new good SYN with random sequence number <rcv_nxt.
		 * Do not reschedule in the last case.
		 */
		if (paws_reject || th->ack)
			inet_twsk_reschedule(tw, TCP_TIMEWAIT_LEN);

		return tcp_timewait_check_oow_rate_limit(
			tw, skb, LINUX_MIB_TCPACKSKIPPEDTIMEWAIT);
	}
	inet_twsk_put(tw);
	return TCP_TW_SUCCESS;
}
EXPORT_SYMBOL(tcp_timewait_state_process);

static void tcp_time_wait_init(struct sock *sk, struct tcp_timewait_sock *tcptw)
{
#ifdef CONFIG_TCP_MD5SIG
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_md5sig_key *key;

	/*
	 * The timewait bucket does not have the key DB from the
	 * sock structure. We just make a quick copy of the
	 * md5 key being used (if indeed we are using one)
	 * so the timewait ack generating code has the key.
	 */
	tcptw->tw_md5_key = NULL;
	if (!static_branch_unlikely(&tcp_md5_needed.key))
		return;

	key = tp->af_specific->md5_lookup(sk, sk);
	if (key) {
		tcptw->tw_md5_key = kmemdup(key, sizeof(*key), GFP_ATOMIC);
		if (!tcptw->tw_md5_key)
			return;
		if (!tcp_alloc_md5sig_pool())
			goto out_free;
		if (!static_key_fast_inc_not_disabled(&tcp_md5_needed.key.key))
			goto out_free;
	}
	return;
out_free:
	WARN_ON_ONCE(1);
	kfree(tcptw->tw_md5_key);
	tcptw->tw_md5_key = NULL;
#endif
}

/*
 * Move a socket to time-wait or dead fin-wait-2 state.
 */
void tcp_time_wait(struct sock *sk, int state, int timeo)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	struct inet_timewait_sock *tw;
	//申请一个tw，并挂一个tw的定时器，这里注意是有可能直接创建失败的。
	tw = inet_twsk_alloc(sk, &net->ipv4.tcp_death_row, state);
	//把必要的字段复制到tw中
	if (tw) {
		struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
		const int rto = (icsk->icsk_rto << 2) - (icsk->icsk_rto >> 1);

		tw->tw_transparent	= inet_test_bit(TRANSPARENT, sk);
		tw->tw_mark		= sk->sk_mark;
		tw->tw_priority		= sk->sk_priority;
		tw->tw_rcv_wscale	= tp->rx_opt.rcv_wscale;
		tcptw->tw_rcv_nxt	= tp->rcv_nxt;
		tcptw->tw_snd_nxt	= tp->snd_nxt;
		tcptw->tw_rcv_wnd	= tcp_receive_window(tp);
		tcptw->tw_ts_recent	= tp->rx_opt.ts_recent;
		tcptw->tw_ts_recent_stamp = tp->rx_opt.ts_recent_stamp;
		tcptw->tw_ts_offset	= tp->tsoffset;
		tcptw->tw_last_oow_ack_time = 0;
		tcptw->tw_tx_delay	= tp->tcp_tx_delay;
		tw->tw_txhash		= sk->sk_txhash;
#if IS_ENABLED(CONFIG_IPV6)
		if (tw->tw_family == PF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);

			tw->tw_v6_daddr = sk->sk_v6_daddr;
			tw->tw_v6_rcv_saddr = sk->sk_v6_rcv_saddr;
			tw->tw_tclass = np->tclass;
			tw->tw_flowlabel = be32_to_cpu(np->flow_label & IPV6_FLOWLABEL_MASK);
			tw->tw_ipv6only = sk->sk_ipv6only;
		}
#endif

		tcp_time_wait_init(sk, tcptw);

		/* Get the TIME_WAIT timeout firing. */
		//确保比rto时间要长
		if (timeo < rto)
			timeo = rto;

		if (state == TCP_TIME_WAIT)
			timeo = TCP_TIMEWAIT_LEN;

		/* tw_timer is pinned, so we need to make sure BH are disabled
		 * in following section, otherwise timer handler could run before
		 * we complete the initialization.
		 */
		local_bh_disable();
		//启动定时器
		inet_twsk_schedule(tw, timeo);
		/* Linkage updates.
		 * Note that access to tw after this point is illegal.
		 */
		//hashdance，把完全的sk从ehash中移除 换成tw sock插入进去
		inet_twsk_hashdance(tw, sk, net->ipv4.tcp_death_row.hashinfo);
		local_bh_enable();
	} else {
		/* Sorry, if we're out of memory, just CLOSE this
		 * socket up.  We've got bigger problems than
		 * non-graceful socket closings.
		 */
		NET_INC_STATS(net, LINUX_MIB_TCPTIMEWAITOVERFLOW);
	}
	//保存本次连接的拥塞信息，指导下次同一条流的三次握手
	tcp_update_metrics(sk);
	tcp_done(sk);
}
EXPORT_SYMBOL(tcp_time_wait);

void tcp_twsk_destructor(struct sock *sk)
{
#ifdef CONFIG_TCP_MD5SIG
	if (static_branch_unlikely(&tcp_md5_needed.key)) {
		struct tcp_timewait_sock *twsk = tcp_twsk(sk);

		if (twsk->tw_md5_key) {
			kfree_rcu(twsk->tw_md5_key, rcu);
			static_branch_slow_dec_deferred(&tcp_md5_needed);
		}
	}
#endif
}
EXPORT_SYMBOL_GPL(tcp_twsk_destructor);

void tcp_twsk_purge(struct list_head *net_exit_list, int family)
{
	bool purged_once = false;
	struct net *net;

	list_for_each_entry(net, net_exit_list, exit_list) {
		if (net->ipv4.tcp_death_row.hashinfo->pernet) {
			/* Even if tw_refcount == 1, we must clean up kernel reqsk */
			inet_twsk_purge(net->ipv4.tcp_death_row.hashinfo, family);
		} else if (!purged_once) {
			/* The last refcount is decremented in tcp_sk_exit_batch() */
			if (refcount_read(&net->ipv4.tcp_death_row.tw_refcount) == 1)
				continue;

			inet_twsk_purge(&tcp_hashinfo, family);
			purged_once = true;
		}
	}
}
EXPORT_SYMBOL_GPL(tcp_twsk_purge);

/* Warning : This function is called without sk_listener being locked.
 * Be sure to read socket fields once, as their value could change under us.
 */
//收到syn包会调用
void tcp_openreq_init_rwin(struct request_sock *req,
			   const struct sock *sk_listener,
			   const struct dst_entry *dst)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	const struct tcp_sock *tp = tcp_sk(sk_listener);
	//这里注意 大概返回1200/4096倍的rcv_buf的大小?
	int full_space = tcp_full_space(sk_listener);
	u32 window_clamp;
	__u8 rcv_wscale;
	u32 rcv_wnd;
	int mss;
	//用户如果有就用用户的mss，否则大概率根据mtu算一个
	mss = tcp_mss_clamp(tp, dst_metric_advmss(dst));
	//这里看用户是否set吧？
	window_clamp = READ_ONCE(tp->window_clamp);
	/* Set this up on the first call only */
	//这里大概率是0吧
	req->rsk_window_clamp = window_clamp ? : dst_metric(dst, RTAX_WINDOW);

	/* limit the window selection if the user enforce a smaller rx buffer */
	//这里大概率也不会走
	if (sk_listener->sk_userlocks & SOCK_RCVBUF_LOCK &&
	    (req->rsk_window_clamp > full_space || req->rsk_window_clamp == 0))
		req->rsk_window_clamp = full_space;
	//大概率也返回0
	rcv_wnd = tcp_rwnd_init_bpf((struct sock *)req);
	if (rcv_wnd == 0)
	//大概率也返回0
		rcv_wnd = dst_metric(dst, RTAX_INITRWND);
	else if (full_space < rcv_wnd * mss)
		full_space = rcv_wnd * mss;

	/* tcp_full_space because it is guaranteed to be the first packet */
	//根据监听sk，最大可用空间大小，mss，是否开启窗口缩放，等来计算一个窗口缩放因子，这里设置了rsk_rcv_wnd
	tcp_select_initial_window(sk_listener, full_space,
		mss - (ireq->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0),
		&req->rsk_rcv_wnd,
		&req->rsk_window_clamp,
		ireq->wscale_ok,
		&rcv_wscale,
		rcv_wnd);
	ireq->rcv_wscale = rcv_wscale;//传入传出的窗口缩放因子，会synack的时候会用到
}
EXPORT_SYMBOL(tcp_openreq_init_rwin);

static void tcp_ecn_openreq_child(struct tcp_sock *tp,
				  const struct request_sock *req)
{
	tp->ecn_flags = inet_rsk(req)->ecn_ok ? TCP_ECN_OK : 0;
}

void tcp_ca_openreq_child(struct sock *sk, const struct dst_entry *dst)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 ca_key = dst_metric(dst, RTAX_CC_ALGO);
	bool ca_got_dst = false;
	//看看用户是否配置,大概率不走这里优先从路由表 metric 获取指定的拥塞控制算法
	if (ca_key != TCP_CA_UNSPEC) {
		const struct tcp_congestion_ops *ca;

		rcu_read_lock();
		ca = tcp_ca_find_key(ca_key);
		if (likely(ca && bpf_try_module_get(ca, ca->owner))) {
			icsk->icsk_ca_dst_locked = tcp_ca_dst_locked(dst);
			icsk->icsk_ca_ops = ca;
			ca_got_dst = true;
		}
		rcu_read_unlock();
	}
	//如果用户们没有配置，则调用tcp_assign_congestion_control使用系统默认的
	/* If no valid choice made yet, assign current system default ca. */
	if (!ca_got_dst &&
	    (!icsk->icsk_ca_setsockopt ||
	     !bpf_try_module_get(icsk->icsk_ca_ops, icsk->icsk_ca_ops->owner)))
		tcp_assign_congestion_control(sk);
	//注意这里设置了拥塞状态
	tcp_set_ca_state(sk, TCP_CA_Open); //创建req sock
}
EXPORT_SYMBOL_GPL(tcp_ca_openreq_child);

static void smc_check_reset_syn_req(const struct tcp_sock *oldtp,
				    struct request_sock *req,
				    struct tcp_sock *newtp)
{
#if IS_ENABLED(CONFIG_SMC)
	struct inet_request_sock *ireq;

	if (static_branch_unlikely(&tcp_have_smc)) {
		ireq = inet_rsk(req);
		if (oldtp->syn_smc && !ireq->smc_ok)
			newtp->syn_smc = 0;
	}
#endif
}

/* This is not only more efficient than what we used to do, it eliminates
 * a lot of code duplication between IPv4/IPv6 SYN recv processing. -DaveM
 *
 * Actually, we could lots of memory writes here. tp of listening
 * socket contains all necessary default parameters.
 */
 //三次握手服务端接收ack会调用，这里第一个参数是监听sk吧 主要工作就是完成初始化
struct sock *tcp_create_openreq_child(const struct sock *sk,
				      struct request_sock *req,
				      struct sk_buff *skb)
{
	//申请一个sock结构，并初始化相关字段
	struct sock *newsk = inet_csk_clone_lock(sk, req, GFP_ATOMIC);
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_request_sock *treq = tcp_rsk(req);
	struct inet_connection_sock *newicsk;
	const struct tcp_sock *oldtp;
	struct tcp_sock *newtp;
	u32 seq;

	if (!newsk)
		return NULL;

	newicsk = inet_csk(newsk);
	newtp = tcp_sk(newsk);
	oldtp = tcp_sk(sk);
	//smc相关
	smc_check_reset_syn_req(oldtp, req, newtp);

	/* Now setup tcp_sock */
	newtp->pred_flags = 0;
	//设置上一次更新的rcv_nxt
	seq = treq->rcv_isn + 1;
	newtp->rcv_wup = seq;
	WRITE_ONCE(newtp->copied_seq, seq);
	//这里设置了下一个接收的序号
	WRITE_ONCE(newtp->rcv_nxt, seq);
	//初始化接受了多少个段
	newtp->segs_in = 1;

	seq = treq->snt_isn + 1;
	//下一个等待确认的序号
	newtp->snd_sml = newtp->snd_una = seq;
	WRITE_ONCE(newtp->snd_nxt, seq);
	newtp->snd_up = seq;
	//这里初始化了tsq队列！
	INIT_LIST_HEAD(&newtp->tsq_node);
	INIT_LIST_HEAD(&newtp->tsorted_sent_queue);
	//更新接收窗口 fastpath会用到？？
	tcp_init_wl(newtp, treq->rcv_isn);

	minmax_reset(&newtp->rtt_min, tcp_jiffies32, ~0U);
	//设置最后一个数据包接收的时间
	newicsk->icsk_ack.lrcvtime = tcp_jiffies32;

	newtp->lsndtime = tcp_jiffies32;
	newsk->sk_txhash = READ_ONCE(treq->txhash);
	//重传计数
	newtp->total_retrans = req->num_retrans;
	//这里初始化了多个定时器
	tcp_init_xmit_timers(newsk);
	WRITE_ONCE(newtp->write_seq, newtp->pushed_seq = treq->snt_isn + 1);//下一个要发送的序列号
	//保活定时器，这里会启动吗？
	if (sock_flag(newsk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(newsk,
					       keepalive_time_when(newtp));

	newtp->rx_opt.tstamp_ok = ireq->tstamp_ok; //是否支持时间戳选项
	newtp->rx_opt.sack_ok = ireq->sack_ok;		//是否支持sack选项
	newtp->window_clamp = req->rsk_window_clamp; //窗口大小，从req直接赋值tcp_select_initial_window
	newtp->rcv_ssthresh = req->rsk_rcv_wnd;  //慢启动的初始值tcp_select_initial_window
	newtp->rcv_wnd = req->rsk_rcv_wnd;			//设置接收窗口的大小
	newtp->rx_opt.wscale_ok = ireq->wscale_ok; //是否支持窗口缩放
	if (newtp->rx_opt.wscale_ok) {//保存窗口缩放因子
		newtp->rx_opt.snd_wscale = ireq->snd_wscale; 
		newtp->rx_opt.rcv_wscale = ireq->rcv_wscale;
	} else {
		newtp->rx_opt.snd_wscale = newtp->rx_opt.rcv_wscale = 0;//不支持窗口u缩放
		newtp->window_clamp = min(newtp->window_clamp, 65535U); //设置为最大65535
	}
	////这里计算了发送窗口大小，是接受的窗口大小和缩放因子计算得到
	newtp->snd_wnd = ntohs(tcp_hdr(skb)->window) << newtp->rx_opt.snd_wscale;
	//最大窗口大小
	newtp->max_window = newtp->snd_wnd;
	//如果开启了时间戳选项，更新相关字段，并修改tcp头的长度
	if (newtp->rx_opt.tstamp_ok) {
		newtp->rx_opt.ts_recent = READ_ONCE(req->ts_recent);
		newtp->rx_opt.ts_recent_stamp = ktime_get_seconds();
		newtp->tcp_header_len = sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
	} else {
		newtp->rx_opt.ts_recent_stamp = 0;
		newtp->tcp_header_len = sizeof(struct tcphdr);
	}
	//是否冲传过syn ack
	if (req->num_timeout) {
		newtp->undo_marker = treq->snt_isn;//记录synaack的序列号这意味着，后续任何对序列号​​大于等于​​ snt_isn的数据的确认，都可能用于判断此次 SYN-ACK 重传是否必要
		newtp->retrans_stamp = div_u64(treq->snt_synack,//重传的时间戳
					       USEC_PER_SEC / TCP_TS_HZ);
	}
	newtp->tsoffset = treq->ts_off;//记录时间戳偏移
#ifdef CONFIG_TCP_MD5SIG
	newtp->md5sig_info = NULL;	/*XXX*/
#endif
	if (skb->len >= TCP_MSS_DEFAULT + newtp->tcp_header_len)
		newicsk->icsk_ack.last_seg_size = skb->len - newtp->tcp_header_len; //记录最后一个段的大小
	newtp->rx_opt.mss_clamp = req->mss; //协商的mss
	tcp_ecn_openreq_child(newtp, req); //是否支持ecn
	newtp->fastopen_req = NULL;
	RCU_INIT_POINTER(newtp->fastopen_rsk, NULL);

	newtp->bpf_chg_cc_inprogress = 0;
	tcp_bpf_clone(sk, newsk);

	__TCP_INC_STATS(sock_net(sk), TCP_MIB_PASSIVEOPENS);

	return newsk;
}
EXPORT_SYMBOL(tcp_create_openreq_child);

/*
 * Process an incoming packet for SYN_RECV sockets represented as a
 * request_sock. Normally sk is the listener socket but for TFO it
 * points to the child socket.
 *
 * XXX (TFO) - The current impl contains a special check for ack
 * validation and inside tcp_v4_reqsk_send_ack(). Can we do better?
 *
 * We don't need to initialize tmp_opt.sack_ok as we don't use the results
 *
 * Note: If @fastopen is true, this can be called from process context.
 *       Otherwise, this is from BH context.
 */
/*
解析 TCP 选项 & PAWS 检查
处理 SYN 重传（对端重发 SYN） → 触发重发 SYN+ACK 并重置定时器
验证 ACK 是否有效（非 TFO）：ACK 对不上的直接交给监听 socket 回 RST
校验序列号是否在窗口内（不在→发一个 ACK（挑战 ACK）然后丢弃）
更新时间戳最近值 ts_recent（仅在合适条件）
剥离越界的 SYN 位（SYN 被认为是“超窗的一个 bit”会被去掉）
若报文带 RST 或 SYN → 走“胚胎期复位”路径（统计 + RST/drop）
确认 ACK 必须置位（否则静默丢弃）
非 TFO：TCP_DEFER_ACCEPT 做“空 ACK 丢弃”（应用要求有数据才唤醒）
创建子 socket（由半连接变成全连接）→ hashdance 完成三次握手
监听队列溢出：根据 sysctl 行为选择丢弃或发 RST
错误/复位路径清理 request，并更新统计
*/
struct sock *tcp_check_req(struct sock *sk, struct sk_buff *skb,
			   struct request_sock *req,
			   bool fastopen, bool *req_stolen)
{
	struct tcp_options_received tmp_opt;
	struct sock *child;
	const struct tcphdr *th = tcp_hdr(skb);
	__be32 flg = tcp_flag_word(th) & (TCP_FLAG_RST|TCP_FLAG_SYN|TCP_FLAG_ACK);
	bool paws_reject = false;
	bool own_req;

	tmp_opt.saw_tstamp = 0;
	if (th->doff > (sizeof(struct tcphdr)>>2)) {
		//处理数据包的选项，在接收syn段的时候调用过了
		tcp_parse_options(sock_net(sk), skb, &tmp_opt, 0, NULL);
		//有时间戳选项
		if (tmp_opt.saw_tstamp) {
			tmp_opt.ts_recent = READ_ONCE(req->ts_recent);//注意：这里是之前收到syn包中的时间戳
			if (tmp_opt.rcv_tsecr)//回显的时间戳
				tmp_opt.rcv_tsecr -= tcp_rsk(req)->ts_off;//减去偏移
			/* We do not store true stamp, but it is not required,
			 * it can be estimated (approximately)
			 * from another data.
			 */
			//计算一个时间点，用当前时间，减去第二次握手可以容忍的最大时间，也就是不会有比这个时间点更早的包？？这个时间用来是否可能发生序列号回绕
			tmp_opt.ts_recent_stamp = ktime_get_seconds() - reqsk_timeout(req, TCP_RTO_MAX) / HZ;
			//返回false表示通过
			paws_reject = tcp_paws_reject(&tmp_opt, th->rst);
		}
	}

	/* Check for pure retransmitted SYN. */
	//处理纯syn包的重传，这里其实就是重新调用了一下send_synack
	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn &&
	    flg == TCP_FLAG_SYN &&
	    !paws_reject) {
		/*
		 * RFC793 draws (Incorrectly! It was fixed in RFC1122)
		 * this case on figure 6 and figure 8, but formal
		 * protocol description says NOTHING.
		 * To be more exact, it says that we should send ACK,
		 * because this segment (at least, if it has no data)
		 * is out of window.
		 *
		 *  CONCLUSION: RFC793 (even with RFC1122) DOES NOT
		 *  describe SYN-RECV state. All the description
		 *  is wrong, we cannot believe to it and should
		 *  rely only on common sense and implementation
		 *  experience.
		 *
		 * Enforce "SYN-ACK" according to figure 8, figure 6
		 * of RFC793, fixed by RFC1122.
		 *
		 * Note that even if there is new data in the SYN packet
		 * they will be thrown away too.
		 *
		 * Reset timer after retransmitting SYNACK, similar to
		 * the idea of fast retransmit in recovery.
		 */
		//这里传入了last_oow_ack_time,也就是上次发送synack的时间，需要进行安全相关的检查
		//如果检查通过了直接重传synack包并重新设置synack定时器
		if (!tcp_oow_rate_limited(sock_net(sk), skb,
					  LINUX_MIB_TCPACKSKIPPEDSYNRECV,
					  &tcp_rsk(req)->last_oow_ack_time) &&

		    !inet_rtx_syn_ack(sk, req)) {//重传synack
			unsigned long expires = jiffies;

			expires += reqsk_timeout(req, TCP_RTO_MAX);
			if (!fastopen)
				mod_timer_pending(&req->rsk_timer, expires);
			else
				req->rsk_timer.expires = expires;
		}
		return NULL;//外面什么也不做
	}

	/* Further reproduces section "SEGMENT ARRIVES"
	   for state SYN-RECEIVED of RFC793.
	   It is broken, however, it does not work only
	   when SYNs are crossed.

	   You would think that SYN crossing is impossible here, since
	   we should have a SYN_SENT socket (from connect()) on our end,
	   but this is not true if the crossed SYNs were sent to both
	   ends by a malicious third party.  We must defend against this,
	   and to do that we first verify the ACK (as per RFC793, page
	   36) and reset if it is invalid.  Is this a true full defense?
	   To convince ourselves, let us consider a way in which the ACK
	   test can still pass in this 'malicious crossed SYNs' case.
	   Malicious sender sends identical SYNs (and thus identical sequence
	   numbers) to both A and B:

		A: gets SYN, seq=7
		B: gets SYN, seq=7

	   By our good fortune, both A and B select the same initial
	   send sequence number of seven :-)

		A: sends SYN|ACK, seq=7, ack_seq=8
		B: sends SYN|ACK, seq=7, ack_seq=8

	   So we are now A eating this SYN|ACK, ACK test passes.  So
	   does sequence test, SYN is truncated, and thus we consider
	   it a bare ACK.

	   If icsk->icsk_accept_queue.rskq_defer_accept, we silently drop this
	   bare ACK.  Otherwise, we create an established connection.  Both
	   ends (listening sockets) accept the new incoming connection and try
	   to talk to each other. 8-)

	   Note: This case is both harmless, and rare.  Possibility is about the
	   same as us discovering intelligent life on another plant tomorrow.

	   But generally, we should (RFC lies!) to accept ACK
	   from SYNACK both here and in tcp_rcv_state_process().
	   tcp_rcv_state_process() does not, hence, we do not too.

	   Note that the case is absolutely generic:
	   we cannot optimize anything here without
	   violating protocol. All the checks must be made
	   before attempt to create socket.
	 */

	/* RFC793 page 36: "If the connection is in any non-synchronized state ...
	 *                  and the incoming segment acknowledges something not yet
	 *                  sent (the segment carries an unacceptable ACK) ...
	 *                  a reset is sent."
	 *
	 * Invalid ACK: reset will be sent by listening socket.
	 * Note that the ACK validity check for a Fast Open socket is done
	 * elsewhere and is checked directly against the child socket rather
	 * than req because user data may have been sent out.
	 */
	//这个好像叫做处理交叉syn，或者ack不合法这里返回了listen sock listensock会回rst
	if ((flg & TCP_FLAG_ACK) && !fastopen &&
	    (TCP_SKB_CB(skb)->ack_seq !=
	     tcp_rsk(req)->snt_isn + 1))
		return sk;

	/* Also, it would be not so bad idea to check rcv_tsecr, which
	 * is essentially ACK extension and too early or too late values
	 * should cause reset in unsynchronized states.
	 */

	/* RFC793: "first check sequence number". */
	//注意：这里如果paws不通过的话，或者序号不在接收窗口内（这里感觉和上面的判断有点冲突呢？ 上面仅保证的是ack？
	// 因为走到这个分支可能不光是ack?上面分支直接就rst了， 这里可能是回一个挑战ack）比如ack正确，但数据包太大了？？？ 或者 paw返回ture？
	if (paws_reject || !tcp_in_window(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq,
					  tcp_rsk(req)->rcv_nxt, tcp_rsk(req)->rcv_nxt + req->rsk_rcv_wnd)) {
		/* Out of window: send ACK and drop. */
		if (!(flg & TCP_FLAG_RST) && //没有rst段，回一个挑战ack
		    !tcp_oow_rate_limited(sock_net(sk), skb,
					  LINUX_MIB_TCPACKSKIPPEDSYNRECV,
					  &tcp_rsk(req)->last_oow_ack_time))
			req->rsk_ops->send_ack(sk, skb, req);
		if (paws_reject)
			NET_INC_STATS(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
		return NULL;//默默丢弃
	}

	/* In sequence, PAWS is OK. */

	/* TODO: We probably should defer ts_recent change once
	 * we take ownership of @req.
	 */
	//如果启用了时间戳选项，且序列号在下一个期待接收的后面就更新req的时间戳
	if (tmp_opt.saw_tstamp && !after(TCP_SKB_CB(skb)->seq, tcp_rsk(req)->rcv_nxt))
		WRITE_ONCE(req->ts_recent, tmp_opt.rcv_tsval);
	//如果收到数据包的序列号等于对端三次握手的序列号，就清掉syn标志 这是为什么呢？？？，防止后续影响处理？？
	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn) {
		/* Truncate SYN, it is out of window starting
		   at tcp_rsk(req)->rcv_isn + 1. */
		flg &= ~TCP_FLAG_SYN;
	}

	/* RFC793: "second check the RST bit" and
	 *	   "fourth, check the SYN bit"
	 */
	//走到这里表示已经验证过ack的合法性，正常情况下应该只有ack，这里直接goto
	if (flg & (TCP_FLAG_RST|TCP_FLAG_SYN)) {
		TCP_INC_STATS(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
		goto embryonic_reset;
	}

	/* ACK sequence verified above, just make sure ACK is
	 * set.  If ACK not set, just silently drop the packet.
	 *
	 * XXX (TFO) - if we ever allow "data after SYN", the
	 * following check needs to be removed.
	 */
	//上面判断过 ack_seq == snt_isn + 1 这里再次确定报文一定带ack，感觉这个函数里面的逻辑有点乱套啊
	if (!(flg & TCP_FLAG_ACK))
		return NULL;

	/* For Fast Open no more processing is needed (sk is the
	 * child socket).
	 */
	if (fastopen)
		return sk;

	/* While TCP_DEFER_ACCEPT is active, drop bare ACK. */
	//用户set sockopt设置rskq_defer_accept 则默默丢弃不带数据的ack
	if (req->num_timeout < READ_ONCE(inet_csk(sk)->icsk_accept_queue.rskq_defer_accept) &&
	    TCP_SKB_CB(skb)->end_seq == tcp_rsk(req)->rcv_isn + 1) {
		inet_rsk(req)->acked = 1;
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPDEFERACCEPTDROP);
		return NULL; //外层什么也不做
	}

	/* OK, ACK is valid, create big socket and
	 * feed this segment to it. It will repeat all
	 * the tests. THIS SEGMENT MUST MOVE SOCKET TO
	 * ESTABLISHED STATE. If it will be dropped after
	 * socket is created, wait for troubles.
	 */
	//这里返回了新创建的sock，并插入了ehash移除了原来的req
	child = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, NULL,
							 req, &own_req);
	if (!child)
		goto listen_overflow;
	//这里直接跳过
	if (own_req && rsk_drop_req(req)) {
		reqsk_queue_removed(&inet_csk(req->rsk_listener)->icsk_accept_queue, req);
		inet_csk_reqsk_queue_drop_and_put(req->rsk_listener, req);
		return child;
	}
	//skb的hash 给到sk的hash
	sock_rps_save_rxhash(child, skb);
	//注意这里更新了rtt
	tcp_synack_rtt_meas(child, req);
	*req_stolen = !own_req;
	//这里加入全连接队列
	return inet_csk_complete_hashdance(sk, child, req, own_req);

listen_overflow:
	if (sk != req->rsk_listener)
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMIGRATEREQFAILURE);

	if (!READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_abort_on_overflow)) {
		inet_rsk(req)->acked = 1;
		return NULL;
	}

embryonic_reset:
	//如果收到的包不含rst 那就主动回一个rst
	if (!(flg & TCP_FLAG_RST)) {
		/* Received a bad SYN pkt - for TFO We try not to reset
		 * the local connection unless it's really necessary to
		 * avoid becoming vulnerable to outside attack aiming at
		 * resetting legit local connections.
		 */
		req->rsk_ops->send_reset(sk, skb);
	} else if (fastopen) { /* received a valid RST pkt */
		reqsk_fastopen_remove(sk, req, true);
		tcp_reset(sk, skb);
	}
	if (!fastopen) {
		//从监听 socket 的半连接队列里移除一个 request_sock
		bool unlinked = inet_csk_reqsk_queue_drop(sk, req);

		if (unlinked)
			__NET_INC_STATS(sock_net(sk), LINUX_MIB_EMBRYONICRSTS);
		*req_stolen = !unlinked; //表示不要二次释放
	}
	return NULL;
}
EXPORT_SYMBOL(tcp_check_req);

/*
 * Queue segment on the new socket if the new socket is active,
 * otherwise we just shortcircuit this and continue with
 * the new socket.
 *
 * For the vast majority of cases child->sk_state will be TCP_SYN_RECV
 * when entering. But other states are possible due to a race condition
 * where after __inet_lookup_established() fails but before the listener
 * locked is obtained, other packets cause the same connection to
 * be created.
 */

int tcp_child_process(struct sock *parent, struct sock *child,
		      struct sk_buff *skb)
	__releases(&((child)->sk_lock.slock))
{
	int ret = 0;
	//三次握手被动打开接收ack走到这里后这里应该是syn_rcv的状态
	int state = child->sk_state;

	/* record sk_napi_id and sk_rx_queue_mapping of child. */
	//这里设置了用那个队列和napi
	sk_mark_napi_id_set(child, skb);

	tcp_segs_in(tcp_sk(child), skb);
	//三次握手收到ack后这里用户进程会操作sock吗？ 可能有其他的进程调用？
	if (!sock_owned_by_user(child)) {
		ret = tcp_rcv_state_process(child, skb);
		/* Wakeup parent, send SIGIO */
		if (state == TCP_SYN_RECV && child->sk_state != state)
			parent->sk_data_ready(parent);
	} else {
		/* Alas, it is possible again, because we do lookup
		 * in main socket hash table and lock on listening
		 * socket does not protect us more.
		 */
		__sk_add_backlog(child, skb);
	}

	bh_unlock_sock(child);
	sock_put(child);
	return ret;
}
EXPORT_SYMBOL(tcp_child_process);
