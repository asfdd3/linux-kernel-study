// SPDX-License-Identifier: GPL-2.0
#include <linux/tcp.h>
#include <net/tcp.h>
//这个函数是核心！！！
static u32 tcp_rack_reo_wnd(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	//是否存在乱续，由tcp_check_sack_reordering设置
	if (!tp->reord_seen) {
		/* If reordering has not been observed, be aggressive during
		 * the recovery or starting the recovery by DUPACK threshold.
		 */
		//快恢复或者是loss，直接返回0 表示乱续容忍时间窗口是0
		if (inet_csk(sk)->icsk_ca_state >= TCP_CA_Recovery)
			return 0;
//sack确认的数量比乱需容忍的值要大  同时没有禁用TCP_RACK_NO_DUPTHRESH直接返回0 
		if (tp->sacked_out >= tp->reordering &&
		    !(READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_recovery) &
		      TCP_RACK_NO_DUPTHRESH))
			return 0;
	}

	/* To be more reordering resilient, allow min_rtt/4 settling delay.
	 * Use min_rtt instead of the smoothed RTT because reordering is
	 * often a path property and less related to queuing or delayed ACKs.
	 * Upon receiving DSACKs, linearly increase the window up to the
	 * smoothed RTT.
	 */
	return min((tcp_min_rtt(tp) >> 2) * tp->rack.reo_wnd_steps,
		   tp->srtt_us >> 3);
}

s32 tcp_rack_skb_timeout(struct tcp_sock *tp, struct sk_buff *skb, u32 reo_wnd)
{
	return tp->rack.rtt_us + reo_wnd - //平均 RTT 时间
	       tcp_stamp_us_delta(tp->tcp_mstamp, tcp_skb_timestamp_us(skb));//当前时间点与这个skb最近一次发送的时间间隔
}

/* RACK loss detection (IETF draft draft-ietf-tcpm-rack-01):
 *
 * Marks a packet lost, if some packet sent later has been (s)acked.
 * The underlying idea is similar to the traditional dupthresh and FACK
 * but they look at different metrics:
 *
 * dupthresh: 3 OOO packets delivered (packet count)
 * FACK: sequence delta to highest sacked sequence (sequence space)
 * RACK: sent time delta to the latest delivered packet (time domain)
 *
 * The advantage of RACK is it applies to both original and retransmitted
 * packet and therefore is robust against tail losses. Another advantage
 * is being more resilient to reordering by simply allowing some
 * "settling delay", instead of tweaking the dupthresh.
 *
 * When tcp_rack_detect_loss() detects some packets are lost and we
 * are not already in the CA_Recovery state, either tcp_rack_reo_timeout()
 * or tcp_time_to_recover()'s "Trick#1: the loss is proven" code path will
 * make us enter the CA_Recovery state.
 */
static void  tcp_rack_detect_loss(struct sock *sk, u32 *reo_timeout)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb, *n;
	u32 reo_wnd;

	*reo_timeout = 0;
	//reo_wnd的单位为时间，返回0或者根据rtt算一个值，取决于统计乱续数据包的字段
	reo_wnd = tcp_rack_reo_wnd(sk);
	//遍历已经发送按按时间排序的数据包队列
	list_for_each_entry_safe(skb, n, &tp->tsorted_sent_queue,
				 tcp_tsorted_anchor) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		s32 remaining;

		/* Skip ones marked lost but not yet retransmitted */
		//跳过已经标记丢失的数据包
		if ((scb->sacked & TCPCB_LOST) &&
		    !(scb->sacked & TCPCB_SACKED_RETRANS))
			continue;
		//返回false的条件是，当前数据包的时间戳在当前rack时间戳的前面。。。，表示没问题。所以直接beak 合理
		if (!tcp_skb_sent_after(tp->rack.mstamp,
					tcp_skb_timestamp_us(skb),
					tp->rack.end_seq, scb->end_seq))
			break;

		/* A packet is lost if it has not been s/acked beyond
		 * the recent RTT plus the reordering window.
		 */
		//内部根据rtt和上面算出来到窗口时间 减去这个数据包已经发出取得时间得到一个超时时间
		remaining = tcp_rack_skb_timeout(tp, skb, reo_wnd);
		if (remaining <= 0) {
			//没有剩余时间了，直接标记为丢失数据包
			tcp_mark_skb_lost(sk, skb);
			//这里把数据包从按时间排序的队列中移除了？？？，那需要重传的包在哪拿到呢？貌似是重传队列
			list_del_init(&skb->tcp_tsorted_anchor);
		} else {
			/* Record maximum wait time */
			//传入传出这个timeout
			*reo_timeout = max_t(u32, *reo_timeout, remaining);
		}
	}
}
//tcpack中最终会调用
bool tcp_rack_mark_lost(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 timeout;
	//tcp_rack_advance 中设置
	if (!tp->rack.advanced)
		return false;

	/* Reset the advanced flag to avoid unnecessary queue scanning */
	tp->rack.advanced = 0;
	//标记丢失的数据包，拿到timeout
	tcp_rack_detect_loss(sk, &timeout);
	if (timeout) {
		timeout = usecs_to_jiffies(timeout + TCP_TIMEOUT_MIN_US);
		//启动RACK定时器
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_REO_TIMEOUT,
					  timeout, inet_csk(sk)->icsk_rto);
	}
	return !!timeout;
}

/* Record the most recently (re)sent time among the (s)acked packets
 * This is "Step 3: Advance RACK.xmit_time and update RACK.RTT" from
 * draft-cheng-tcpm-rack-00.txt
 */
//tcp_ack中最中会调用到这个函数
void tcp_rack_advance(struct tcp_sock *tp, u8 sacked, u32 end_seq,
		      u64 xmit_time)
{
	u32 rtt_us;
	//计算当前数据包的rtt
	rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, xmit_time);
	//小于最小rtt可能是乱续导致的，直接return
	if (rtt_us < tcp_min_rtt(tp) && (sacked & TCPCB_RETRANS)) {
		/* If the sacked packet was retransmitted, it's ambiguous
		 * whether the retransmission or the original (or the prior
		 * retransmission) was sacked.
		 *
		 * If the original is lost, there is no ambiguity. Otherwise
		 * we assume the original can be delayed up to aRTT + min_rtt.
		 * the aRTT term is bounded by the fast recovery or timeout,
		 * so it's at least one RTT (i.e., retransmission is at least
		 * an RTT later).
		 */
		return;
	}
	//设置rack用到的标志，这个很关键
	tp->rack.advanced = 1;
	//保存rtt
	tp->rack.rtt_us = rtt_us;
	//更新当前数据包的时间戳和序列好到 rack使用的相关字段中
	if (tcp_skb_sent_after(xmit_time, tp->rack.mstamp,
			       end_seq, tp->rack.end_seq)) {
		tp->rack.mstamp = xmit_time;
		tp->rack.end_seq = end_seq;
	}
}

/* We have waited long enough to accommodate reordering. Mark the expired
 * packets lost and retransmit them.
 */
void tcp_rack_reo_timeout(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 timeout, prior_inflight;
	u32 lost = tp->lost;
	//计算在网络中飞行的包的数量
	prior_inflight = tcp_packets_in_flight(tp);
	//遍历按时间排序的数据包队列，根据时间戳，会将数据包标记为loss
	tcp_rack_detect_loss(sk, &timeout);
	//如果现在这两个值不相等了，则证明认为有包丢失了，如果此时不再快速恢复状态则恩据到快速恢复状态，并调用注册的拥塞算法的钩子
	if (prior_inflight != tcp_packets_in_flight(tp)) {
		if (inet_csk(sk)->icsk_ca_state != TCP_CA_Recovery) {
			tcp_enter_recovery(sk, false);
			if (!inet_csk(sk)->icsk_ca_ops->cong_control)
				tcp_cwnd_reduction(sk, 1, tp->lost - lost, 0);
		}
		//重传数据包
		tcp_xmit_retransmit_queue(sk);
	}
	//设置了重传定时器，用来兜底？
	if (inet_csk(sk)->icsk_pending != ICSK_TIME_RETRANS)
		tcp_rearm_rto(sk);
}

/* Updates the RACK's reo_wnd based on DSACK and no. of recoveries.
 *
 * If a DSACK is received that seems like it may have been due to reordering
 * triggering fast recovery, increment reo_wnd by min_rtt/4 (upper bounded
 * by srtt), since there is possibility that spurious retransmission was
 * due to reordering delay longer than reo_wnd.
 *
 * Persist the current reo_wnd value for TCP_RACK_RECOVERY_THRESH (16)
 * no. of successful recoveries (accounts for full DSACK-based loss
 * recovery undo). After that, reset it to default (min_rtt/4).
 *
 * At max, reo_wnd is incremented only once per rtt. So that the new
 * DSACK on which we are reacting, is due to the spurious retx (approx)
 * after the reo_wnd has been updated last time.
 *
 * reo_wnd is tracked in terms of steps (of min_rtt/4), rather than
 * absolute value to account for change in rtt.
 */
void tcp_rack_update_reo_wnd(struct sock *sk, struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//默认不进入会在个分支
	if ((READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_recovery) &
	     TCP_RACK_STATIC_REO_WND) ||
	    !rs->prior_delivered)  //本次速率采样区间开始时确认的包数
		return;

	/* Disregard DSACK if a rtt has not passed since we adjusted reo_wnd */
	//还没有经过一个完整的RTT
	if (before(rs->prior_delivered, tp->rack.last_delivered))
		tp->rack.dsack_seen = 0;

	/* Adjust the reo_wnd if update is pending */
	//这个是处理sack中设置的，如果看到了daack就增大reo_wnd_steps，这个值会影响rack是否标记为丢包，合理
	if (tp->rack.dsack_seen) {
		tp->rack.reo_wnd_steps = min_t(u32, 0xFF,
					       tp->rack.reo_wnd_steps + 1);
		tp->rack.dsack_seen = 0;
		tp->rack.last_delivered = tp->delivered;
		tp->rack.reo_wnd_persist = TCP_RACK_RECOVERY_THRESH;
	} else if (!tp->rack.reo_wnd_persist) {//这个值是误判丢包的数量
		tp->rack.reo_wnd_steps = 1;
	}
}

/* RFC6582 NewReno recovery for non-SACK connection. It simply retransmits
 * the next unacked packet upon receiving
 * a) three or more DUPACKs to start the fast recovery
 * b) an ACK acknowledging new data during the fast recovery.
 */
void tcp_newreno_mark_lost(struct sock *sk, bool snd_una_advanced)
{
	const u8 state = inet_csk(sk)->icsk_ca_state;
	struct tcp_sock *tp = tcp_sk(sk);

	if ((state < TCP_CA_Recovery && tp->sacked_out >= tp->reordering) ||
	    (state == TCP_CA_Recovery && snd_una_advanced)) {
		struct sk_buff *skb = tcp_rtx_queue_head(sk);
		u32 mss;

		if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
			return;

		mss = tcp_skb_mss(skb);
		if (tcp_skb_pcount(skb) > 1 && skb->len > mss)
			tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb,
				     mss, mss, GFP_ATOMIC);

		tcp_mark_skb_lost(sk, skb);
	}
}
