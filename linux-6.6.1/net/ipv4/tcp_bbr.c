/* Bottleneck Bandwidth and RTT (BBR) congestion control
 *
 * BBR congestion control computes the sending rate based on the delivery
 * rate (throughput) estimated from ACKs. In a nutshell:
 *
 *   On each ACK, update our model of the network path:
 *      bottleneck_bandwidth = windowed_max(delivered / elapsed, 10 round trips)
 *      min_rtt = windowed_min(rtt, 10 seconds)
 *   pacing_rate = pacing_gain * bottleneck_bandwidth
 *   cwnd = max(cwnd_gain * bottleneck_bandwidth * min_rtt, 4)
 *
 * The core algorithm does not react directly to packet losses or delays,
 * although BBR may adjust the size of next send per ACK when loss is
 * observed, or adjust the sending rate if it estimates there is a
 * traffic policer, in order to keep the drop rate reasonable.
 *
 * Here is a state transition diagram for BBR:
 *
 *             |
 *             V
 *    +---> STARTUP  ----+
 *    |        |         |
 *    |        V         |
 *    |      DRAIN   ----+
 *    |        |         |
 *    |        V         |
 *    +---> PROBE_BW ----+
 *    |      ^    |      |
 *    |      |    |      |
 *    |      +----+      |
 *    |                  |
 *    +---- PROBE_RTT <--+
 *
 * A BBR flow starts in STARTUP, and ramps up its sending rate quickly.
 * When it estimates the pipe is full, it enters DRAIN to drain the queue.
 * In steady state a BBR flow only uses PROBE_BW and PROBE_RTT.
 * A long-lived BBR flow spends the vast majority of its time remaining
 * (repeatedly) in PROBE_BW, fully probing and utilizing the pipe's bandwidth
 * in a fair manner, with a small, bounded queue. *If* a flow has been
 * continuously sending for the entire min_rtt window, and hasn't seen an RTT
 * sample that matches or decreases its min_rtt estimate for 10 seconds, then
 * it briefly enters PROBE_RTT to cut inflight to a minimum value to re-probe
 * the path's two-way propagation delay (min_rtt). When exiting PROBE_RTT, if
 * we estimated that we reached the full bw of the pipe then we enter PROBE_BW;
 * otherwise we enter STARTUP to try to fill the pipe.
 *
 * BBR is described in detail in:
 *   "BBR: Congestion-Based Congestion Control",
 *   Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh,
 *   Van Jacobson. ACM Queue, Vol. 14 No. 5, September-October 2016.
 *
 * There is a public e-mail list for discussing BBR development and testing:
 *   https://groups.google.com/forum/#!forum/bbr-dev
 *
 * NOTE: BBR might be used with the fq qdisc ("man tc-fq") with pacing enabled,
 * otherwise TCP stack falls back to an internal pacing using one high
 * resolution timer per TCP socket and may use more resources.
 */
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode {
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
	BBR_DRAIN,	/* drain any queue created during startup */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
	BBR_PROBE_RTT,	/* cut inflight to min to probe min_rtt */
};

/* BBR congestion control block */
struct bbr {
	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */	//更新最小rtt的时间戳
	u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */ //probe状态下结束的时间戳
	struct minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
	u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */	//rtt_cnt
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
	u64	cycle_mstamp;	     /* time of this cycle phase start */ //8 相位时间戳
	u32     mode:3,		     /* current bbr_mode in state machine */
		prev_ca_state:3,     /* CA state on previous ACK */
		packet_conservation:1,  /* use packet conservation? */
		round_start:1,	     /* start of packet-timed tx->ack round? */
		idle_restart:1,	     /* restarting after idle? */			//从idle态重新开始
		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
		unused:13,
		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
		lt_rtt_cnt:7,	     /* round trips in long-term interval */
		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
	u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
	u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
	u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
	u32	lt_last_lost;	     /* LT intvl start: tp->lost */
	u32	pacing_gain:10,	/* current gain for setting pacing rate */
		cwnd_gain:10,	/* current gain for setting cwnd */
		full_bw_reached:1,   /* reached full bw in Startup? */ //是否达到最大带宽标志
		full_bw_cnt:2,	/* number of rounds without large bw gains */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
		has_seen_rtt:1, /* have we seen an RTT sample yet? */
		unused_b:5;
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */ 	//保存拥塞窗口的时候会用到
	u32	full_bw;	/* recent bw, to estimate if pipe is full */  //最大带宽

	/* For tracking ACK aggregation: */
	u64	ack_epoch_mstamp;	/* start of ACK sampling epoch */  //统计ack聚合开始的时间戳
	u16	extra_acked[2];		/* max excess data ACKed in epoch */   //聚合ack 单位cwnd
	u32	ack_epoch_acked:20,	/* packets (S)ACKed in sampling epoch */ //累计ack的数量
		extra_acked_win_rtts:5,	/* age of extra_acked, in round trips */ //ACK 聚合统计窗口已经经历了多少个 RT
		extra_acked_win_idx:1,	/* current index in extra_acked array */
		unused_c:6;
};

#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */

/* Window length of bw filter (in rounds): */
static const int bbr_bw_rtts = CYCLE_LEN + 2; //10个rtt
/* Window length of min_rtt filter (in sec): */
static const u32 bbr_min_rtt_win_sec = 10;
/* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode: */
static const u32 bbr_probe_rtt_mode_ms = 200;
/* Skip TSO below the following bandwidth (bits/sec): */
static const int bbr_min_tso_rate = 1200000;

/* Pace at ~1% below estimated bw, on average, to reduce queue at bottleneck.
 * In order to help drive the network toward lower queues and low latency while
 * maintaining high utilization, the average pacing rate aims to be slightly
 * lower than the estimated bandwidth. This is an important aspect of the
 * design.
 */
static const int bbr_pacing_margin_percent = 1;

/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would:
 */
static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;
/* The pacing gain of 1/high_gain in BBR_DRAIN is calculated to typically drain
 * the queue created in BBR_STARTUP in a single round:
 */
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
static const int bbr_cwnd_gain  = BBR_UNIT * 2;
/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
static const int bbr_pacing_gain[] = {
	BBR_UNIT * 5 / 4,	/* probe for more available bw */
	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};
/* Randomize the starting gain cycling phase over N phases: */
static const u32 bbr_cycle_rand = 7;

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const u32 bbr_cwnd_min_target = 4;

/* To estimate if BBR_STARTUP mode (i.e. high_gain) has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available: */
static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
/* But after 3 rounds w/o significant bw growth, estimate pipe is full: */
static const u32 bbr_full_bw_cnt = 3;

/* "long-term" ("LT") bandwidth estimator parameters... */
/* The minimum number of rounds in an LT bw sampling interval: */
static const u32 bbr_lt_intvl_min_rtts = 4;
/* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
static const u32 bbr_lt_loss_thresh = 50;
/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
static const u32 bbr_lt_bw_ratio = BBR_UNIT / 8;
/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
static const u32 bbr_lt_bw_diff = 4000 / 8;
/* If we estimate we're policed, use lt_bw for this many round trips: */
static const u32 bbr_lt_bw_max_rtts = 48;

/* Gain factor for adding extra_acked to target cwnd: */
static const int bbr_extra_acked_gain = BBR_UNIT;
/* Window length of extra_acked window. */
static const u32 bbr_extra_acked_win_rtts = 5;
/* Max allowed val for ack_epoch_acked, after which sampling epoch is reset */
static const u32 bbr_ack_epoch_acked_reset_thresh = 1U << 20;
/* Time period for clamping cwnd increment due to ack aggregation */
static const u32 bbr_extra_acked_max_us = 100 * 1000;

static void bbr_check_probe_rtt_done(struct sock *sk);

/* Do we estimate that STARTUP filled the pipe? */
static bool bbr_full_bw_reached(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return bbr->full_bw_reached;
}

/* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
//采样得到的带宽
static u32 bbr_max_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return minmax_get(&bbr->bw);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
static u32 bbr_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return bbr->lt_use_bw ? bbr->lt_bw : bbr_max_bw(sk);
}

/* Return maximum extra acked in past k-2k round trips,
 * where k = bbr_extra_acked_win_rtts.
 */
static u16 bbr_extra_acked(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return max(bbr->extra_acked[0], bbr->extra_acked[1]);
}

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
static u64 bbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	unsigned int mss = tcp_sk(sk)->mss_cache;

	rate *= mss;// pkt/µs → bytes/µs
	rate *= gain;
	rate >>= BBR_SCALE; //去掉缩放
	rate *= USEC_PER_SEC / 100 * (100 - bbr_pacing_margin_percent); //把 µs 换算成秒乘 0.99
	return rate >> BW_SCALE; //去掉缩放
}

/* Convert a BBR bw and gain factor to a pacing rate in bytes per second. */
static unsigned long bbr_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	u64 rate = bw;

	rate = bbr_rate_bytes_per_sec(sk, rate, gain);// 转为 bytes/s
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}

/* Initialize pacing rate to: high_gain * init_cwnd / RTT. */
static void bbr_init_pacing_rate_from_rtt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;
	u32 rtt_us;

	if (tp->srtt_us) {		/* any RTT sample yet? *///平滑rtt
		rtt_us = max(tp->srtt_us >> 3, 1U);
		bbr->has_seen_rtt = 1;
	} else {			 /* no RTT sample yet */
		rtt_us = USEC_PER_MSEC;	 /* use nominal default RTT *///1ms
	}
	bw = (u64)tcp_snd_cwnd(tp) * BW_UNIT;
	do_div(bw, rtt_us);////计算bw
	sk->sk_pacing_rate = bbr_bw_to_pacing_rate(sk, bw, bbr_high_gain);
}

/* Pace using current bw estimate and a gain factor. */
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	unsigned long rate = bbr_bw_to_pacing_rate(sk, bw, gain);  	 //计算pacing速率

	if (unlikely(!bbr->has_seen_rtt && tp->srtt_us)) 			 //没有rtt?
		bbr_init_pacing_rate_from_rtt(sk); 						 //没有记录rtt的情况，设置rtt 计算bw
	if (bbr_full_bw_reached(sk) || rate > sk->sk_pacing_rate)	 //达到最大带宽，或者大于pacing速率
		sk->sk_pacing_rate = rate;
}

/* override sysctl_tcp_min_tso_segs */
__bpf_kfunc static u32 bbr_min_tso_segs(struct sock *sk)
{
	return sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
}

static u32 bbr_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 segs, bytes;

	/* Sort of tcp_tso_autosize() but ignoring
	 * driver provided sk_gso_max_size.
	 */
	bytes = min_t(unsigned long,
		      sk->sk_pacing_rate >> READ_ONCE(sk->sk_pacing_shift), //字节数
		      GSO_LEGACY_MAX_SIZE - 1 - MAX_TCP_HEADER); //64k左右
	segs = max_t(u32, bytes / tp->mss_cache, bbr_min_tso_segs(sk)); //根据字节和段数计算最大的段数

	return min(segs, 0x7FU);
}

/* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
static void bbr_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	//不是recovery抓给你太，且不是BBR_PROBE_RTT状态，保存发送的拥塞窗口
	if (bbr->prev_ca_state < TCP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
		bbr->prior_cwnd = tcp_snd_cwnd(tp);  /* this cwnd is good enough */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		bbr->prior_cwnd = max(bbr->prior_cwnd, tcp_snd_cwnd(tp));//异常条件下更新发送窗口
}

__bpf_kfunc static void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (event == CA_EVENT_TX_START && tp->app_limited) { //开始发送数据，且应用发送的慢
		bbr->idle_restart = 1;
		bbr->ack_epoch_mstamp = tp->tcp_mstamp;			//重置 ACK 统计周期的起始时间戳 聚合ack会用到
		bbr->ack_epoch_acked = 0;						//清零本周期累计 ACK 的字节数
		/* Avoid pointless buffer overflows: pace at est. bw if we don't
		 * need more speed (we're restarting from idle and app-limited).
		 */
		if (bbr->mode == BBR_PROBE_BW)					//稳态模式下设置gain为1
			bbr_set_pacing_rate(sk, bbr_bw(sk), BBR_UNIT);
		else if (bbr->mode == BBR_PROBE_RTT)			//rtt探测模式下
			bbr_check_probe_rtt_done(sk);				//可能切换到start  或者 稳态
	}
}

/* Calculate bdp based on min RTT and the estimated bottleneck bandwidth:
 *
 * bdp = ceil(bw * min_rtt * gain)
 *
 * The key factor, gain, controls the amount of queue. While a small gain
 * builds a smaller queue, it becomes more vulnerable to noise in RTT
 * measurements (e.g., delayed ACKs or other ACK compression effects). This
 * noise may cause BBR to under-estimate the rate.
 */
static u32 bbr_bdp(struct sock *sk, u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bdp;
	u64 w;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: TCP_INIT_CWND.
	 */
	if (unlikely(bbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return TCP_INIT_CWND;  /* be safe: cap at default initial cwnd*/

	w = (u64)bw * bbr->min_rtt_us;

	/* Apply a gain to the given value, remove the BW_SCALE shift, and
	 * round the value up to avoid a negative feedback loop.
	 */
	bdp = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

	return bdp;
}

/* To achieve full performance in high-speed paths, we budget enough cwnd to
 * fit full-sized skbs in-flight on both end hosts to fully utilize the path:
 *   - one skb in sending host Qdisc,
 *   - one skb in sending host TSO/GSO engine
 *   - one skb being received by receiver host LRO/GRO/delayed-ACK engine
 * Don't worry, at low rates (bbr_min_tso_rate) this won't bloat cwnd because
 * in such cases tso_segs_goal is 1. The minimum cwnd is 4 packets,
 * which allows 2 outstanding 2-packet sequences, to try to keep pipe
 * full even with ACK-every-other-packet delayed ACKs.
 */
static u32 bbr_quantization_budget(struct sock *sk, u32 cwnd)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* Allow enough full-sized skbs in flight to utilize end systems. */
	cwnd += 3 * bbr_tso_segs_goal(sk); //qdisc tso/gso LRG/GRO

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	cwnd = (cwnd + 1) & ~1U;// 偶数？

	/* Ensure gain cycling gets inflight above BDP even for small BDPs. */
	if (bbr->mode == BBR_PROBE_BW && bbr->cycle_idx == 0) //第一个相位
		cwnd += 2;

	return cwnd; //增加后的cwnd
}

/* Find inflight based on min RTT and the estimated bottleneck bandwidth. */
static u32 bbr_inflight(struct sock *sk, u32 bw, int gain)
{
	u32 inflight;

	inflight = bbr_bdp(sk, bw, gain); //基于最小的rtt和gain获取在飞行的包数
	inflight = bbr_quantization_budget(sk, inflight);

	return inflight;
}

/* With pacing at lower layers, there's often less data "in the network" than
 * "in flight". With TSQ and departure time pacing at lower layers (e.g. fq),
 * we often have several skbs queued in the pacing layer with a pre-scheduled
 * earliest departure time (EDT). BBR adapts its pacing rate based on the
 * inflight level that it estimates has already been "baked in" by previous
 * departure time decisions. We calculate a rough estimate of the number of our
 * packets that might be in the network at the earliest departure time for the
 * next skb scheduled:
 *   in_network_at_edt = inflight_at_edt - (EDT - now) * bw
 * If we're increasing inflight, then we want to know if the transmit of the
 * EDT skb will push inflight above the target, so inflight_at_edt includes
 * bbr_tso_segs_goal() from the skb departing at EDT. If decreasing inflight,
 * then estimate if inflight will sink too low just before the EDT transmit.
 */
//修正底层pacing的影响 在网络中的数据往往少于在传输中的数据
static u32 bbr_packets_in_net_at_edt(struct sock *sk, u32 inflight_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 now_ns, edt_ns, interval_us;
	u32 interval_delivered, inflight_at_edt;

	now_ns = tp->tcp_clock_cache; 											//缓存的时间
	edt_ns = max(tp->tcp_wstamp_ns, now_ns); 								//发包的时间
	interval_us = div_u64(edt_ns - now_ns, NSEC_PER_USEC);//发包的时间减去缓存的时间
	interval_delivered = (u64)bbr_bw(sk) * interval_us >> BW_SCALE;			 //数据包应该发出去的数量
	inflight_at_edt = inflight_now;											 //保存一下当前在途中的段数
	if (bbr->pacing_gain > BBR_UNIT)              /* increasing inflight */ //处于探测带宽阶段
		inflight_at_edt += bbr_tso_segs_goal(sk);  /* include EDT skb */ //
	if (interval_delivered >= inflight_at_edt) 								//这里类似是排空
		return 0;
	return inflight_at_edt - interval_delivered;							//这个应该是网络中实际在飞行的包数
}

/* Find the cwnd increment based on estimate of ack aggregation */
static u32 bbr_ack_aggregation_cwnd(struct sock *sk)
{
	u32 max_aggr_cwnd, aggr_cwnd = 0;
	//表示连接已经完成启动阶段（Startup），管道带宽已探测完成
	if (bbr_extra_acked_gain && bbr_full_bw_reached(sk)) {
		max_aggr_cwnd = ((u64)bbr_bw(sk) * bbr_extra_acked_max_us) //钳制
				/ BW_UNIT;
		aggr_cwnd = (bbr_extra_acked_gain * bbr_extra_acked(sk)) //计算额外的cwnd
			     >> BBR_SCALE;
		aggr_cwnd = min(aggr_cwnd, max_aggr_cwnd); //取一个最小值
	}

	return aggr_cwnd;
}

/* An optimization in BBR to reduce losses: On the first round of recovery, we
 * follow the packet conservation principle: send P packets per P packets acked.
 * After that, we slow-start and send at most 2*P packets per P packets acked.
 * After recovery finishes, or upon undo, we restore the cwnd we had when
 * recovery started (capped by the target cwnd based on estimated BDP).
 *
 * TODO(ycheng/ncardwell): implement a rate-based approach.
 */
static bool bbr_set_cwnd_to_recover_or_restore(
	struct sock *sk, const struct rate_sample *rs, u32 acked, u32 *new_cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u8 prev_state = bbr->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tcp_snd_cwnd(tp);

	/* An ACK for P pkts should release at most 2*P packets. We do this
	 * in two steps. First, here we deduct the number of lost packets.
	 * Then, in bbr_set_cwnd() we slow start up toward the target cwnd.
	 */
	//减去丢包数
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);
	//进入recovery状态，且上次不是这个状态，表示刚进入这个状态
	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		/* Starting 1st round of Recovery, so do packet conservation. */
		bbr->packet_conservation = 1; //包守恒
		bbr->next_rtt_delivered = tp->delivered;  /* start round now */ //当前确认的数据包数
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = tcp_packets_in_flight(tp) + acked;
		//从更严重的状态到 正常状态或者乱序
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) { 
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		cwnd = max(cwnd, bbr->prior_cwnd); //相当于撤销
		bbr->packet_conservation = 0; //关闭包守恒
	}
	bbr->prev_ca_state = state;//记录本次的状态
	//在包守恒模式下
	if (bbr->packet_conservation) {
		*new_cwnd = max(cwnd, tcp_packets_in_flight(tp) + acked);
		return true;	/* yes, using packet conservation */
	}
	*new_cwnd = cwnd;
	return false;
}

/* Slow-start up toward target cwnd (if bw estimate is growing, or packet loss
 * has drawn us down below target), or snap down to target if we're above it.
 */
static void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 u32 acked, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cwnd = tcp_snd_cwnd(tp), target_cwnd = 0;
	//确认报文段的个数
	if (!acked)
		goto done;  /* no packet fully ACKed; just apply caps */
	//设置cwnd 如果是包守恒（第一轮进入recovery）就就直接返回了
	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
		goto done;
	//根据bw(段数/us)计算bdp
	target_cwnd = bbr_bdp(sk, bw, gain);

	/* Increment the cwnd to account for excess ACKed data that seems
	 * due to aggregation (of data and/or ACKs) visible in the ACK stream.
	 */
	//考虑聚合后的cwnd
	target_cwnd += bbr_ack_aggregation_cwnd(sk);
	//考虑tc 和tso/gso等
	target_cwnd = bbr_quantization_budget(sk, target_cwnd);

	/* If we're below target cwnd, slow start cwnd toward target cwnd. */
	//是否达到最大带宽
	if (bbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
	//每次按 +acked 线性涨，但不超过 target_cwnd（BDP×gain 得到的目标）。
		cwnd = min(cwnd + acked, target_cwnd);
	else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND) //Startup 阶段
		cwnd = cwnd + acked;
	cwnd = max(cwnd, bbr_cwnd_min_target);//确保大于4

done:
	tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));	/* apply global cap */ //设置拥塞窗口
	if (bbr->mode == BBR_PROBE_RTT)  /* drain queue, refresh min_rtt */ //probe状态的特殊处理
		tcp_snd_cwnd_set(tp, min(tcp_snd_cwnd(tp), bbr_cwnd_min_target));
}

/* End cycle phase if it's time and/or we hit the phase's in-flight target. */
static bool bbr_is_next_cycle_phase(struct sock *sk,
				    const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	//从本相位开始的时间（cycle_mstamp）到现在（delivered_mstamp）是否已超过一个 min_rtt
	bool is_full_length =
		tcp_stamp_us_delta(tp->delivered_mstamp, bbr->cycle_mstamp) >
		bbr->min_rtt_us;
	u32 inflight, bw;

	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
	 * use the pipe without increasing the queue.
	 */
	//正常速率 ，貌似使用ltbw的时候才会设置
	if (bbr->pacing_gain == BBR_UNIT)
		return is_full_length;		/* just use wall clock time */
	//实际在途中的数据包
	inflight = bbr_packets_in_net_at_edt(sk, rs->prior_in_flight);
	bw = bbr_max_bw(sk); //获取bw

	/* A pacing_gain > 1.0 probes for bw by trying to raise inflight to at
	 * least pacing_gain*BDP; this may take more than min_rtt if min_rtt is
	 * small (e.g. on a LAN). We do not persist if packets are lost, since
	 * a path with small buffers may not hold that much.
	 */
	if (bbr->pacing_gain > BBR_UNIT)						//速率增长阶段
		return is_full_length &&							//到切换周期了
			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */ //出现丢包
			 inflight >= bbr_inflight(sk, bw, bbr->pacing_gain)); 

	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
	 * probing didn't find more bw. If inflight falls to match BDP then we
	 * estimate queue is drained; persisting would underutilize the pipe.
	 */
	return is_full_length ||		//相位时间到了，或者没到但是当前在途数据量已经回落到或低于正常BDP水平
		inflight <= bbr_inflight(sk, bw, BBR_UNIT);
}

static void bbr_advance_cycle_phase(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	//这里和理论不太一样，这里有可能随机的 这个更合理！
	bbr->cycle_idx = (bbr->cycle_idx + 1) & (CYCLE_LEN - 1);
	bbr->cycle_mstamp = tp->delivered_mstamp; //当前 gain 周期（phase）的开始时间
}

/* Gain cycling: cycle pacing gain to converge to fair share of available bw. */
static void bbr_update_cycle_phase(struct sock *sk,
				   const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	//稳态阶段，且需要进入到下一个
	if (bbr->mode == BBR_PROBE_BW && bbr_is_next_cycle_phase(sk, rs))
		bbr_advance_cycle_phase(sk);
}

static void bbr_reset_startup_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_STARTUP;
}

static void bbr_reset_probe_bw_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_PROBE_BW; // 进入带宽探测模式，这个是稳态
	bbr->cycle_idx = CYCLE_LEN - 1 - get_random_u32_below(bbr_cycle_rand); //0 - 7 去一个随机数
	bbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle */
}
//rttprobe调用
static void bbr_reset_mode(struct sock *sk)
{
	if (!bbr_full_bw_reached(sk)) //通常是true吧
		bbr_reset_startup_mode(sk); //不是ture 进入到BBR_STARTUP状态
	else
		bbr_reset_probe_bw_mode(sk); //通常走这个分支
}

/* Start a new long-term sampling interval. */
static void bbr_reset_lt_bw_sampling_interval(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_last_stamp = div_u64(tp->delivered_mstamp, USEC_PER_MSEC);
	bbr->lt_last_delivered = tp->delivered;
	bbr->lt_last_lost = tp->lost; 	//丢包数量
	bbr->lt_rtt_cnt = 0; 			//清零长期采样周期内的 RTT 计数
}

/* Completely reset long-term bandwidth sampling. */
static void bbr_reset_lt_bw_sampling(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_bw = 0; 			//长期平均带宽
	bbr->lt_use_bw = 0;		    //表示当前不使用 lt_bw 来替代普通的带宽估计
	bbr->lt_is_sampling = false; //当前没有在进行长期采样
	bbr_reset_lt_bw_sampling_interval(sk);
}
//比较当前周期测得的带宽 bw 与上一次 bbr->lt_bw判断带宽变化是否稳定
//如果稳定，则启用长期带宽模式
/* Long-term bw sampling interval is done. Estimate whether we're policed. */
static void bbr_lt_bw_interval_done(struct sock *sk, u32 bw)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 diff;

	if (bbr->lt_bw) {  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		diff = abs(bw - bbr->lt_bw);
		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * bbr->lt_bw) ||   //和上次比相差不大
		    (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <= //两次带宽样本的绝对差值
		     bbr_lt_bw_diff)) { //4kb per sec
			/* All criteria are met; estimate we're policed. */
			bbr->lt_bw = (bw + bbr->lt_bw) >> 1;  /* avg 2 intvls */ //平均
			bbr->lt_use_bw = 1; //使用长期bw
			bbr->pacing_gain = BBR_UNIT;  /* try to avoid drops */
			bbr->lt_rtt_cnt = 0;
			return;
		}
	}
	bbr->lt_bw = bw; //包/us
	bbr_reset_lt_bw_sampling_interval(sk); //reset 长期采样
}

/* Token-bucket traffic policers are common (see "An Internet-Wide Analysis of
 * Traffic Policing", SIGCOMM 2016). BBR detects token-bucket policers and
 * explicitly models their policed rate, to reduce unnecessary losses. We
 * estimate that we're policed if we see 2 consecutive sampling intervals with
 * consistent throughput and high packet loss. If we think we're being policed,
 * set lt_bw to the "long-term" average delivery rate from those 2 intervals.
 */
//检测是否被令牌桶限速，并估计长期带宽
static void bbr_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 lost, delivered;
	u64 bw;
	u32 t;
	//已经使用长期带宽了
	if (bbr->lt_use_bw) {	/* already using long-term rate, lt_bw? */
		if (bbr->mode == BBR_PROBE_BW && bbr->round_start &&  //处于稳态，且当前的ack是新的计时轮次中的
		    ++bbr->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {  //最多维持多少个rtt使用lt_bw 。这里是48
			bbr_reset_lt_bw_sampling(sk);    /* stop using lt_bw */ //复位使用到的字段
			bbr_reset_probe_bw_mode(sk);  /* restart gain cycling */ //进入带宽探测模式
		}
		return;
	}

	/* Wait for the first loss before sampling, to let the policer exhaust
	 * its tokens and estimate the steady-state rate allowed by the policer.
	 * Starting samples earlier includes bursts that over-estimate the bw.
	 */
	//没有开始长期采样
	if (!bbr->lt_is_sampling) {
		if (!rs->losses) //没有丢包，直接返回
			return;
		bbr_reset_lt_bw_sampling_interval(sk);
		bbr->lt_is_sampling = true;
	}

	/* To avoid underestimates, reset sampling if we run out of data. */
	if (rs->is_app_limited) { //用户发的太慢直接返回
		bbr_reset_lt_bw_sampling(sk);
		return;
	}
	//当前ACK属于一个新的RTT轮次的起点
	if (bbr->round_start)
		bbr->lt_rtt_cnt++;	//一个新的RTT周期完成
	if (bbr->lt_rtt_cnt < bbr_lt_intvl_min_rtts)//太短，不统计 至少要经过4个rtt！
		return;		/* sampling interval needs to be longer */
	if (bbr->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) { //太长也不考虑
		bbr_reset_lt_bw_sampling(sk);  /* interval is too long */
		return;
	}

	/* End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	if (!rs->losses) //没有丢包直接返回
		return;

	/* Calculate packets lost and delivered in sampling interval. */
	lost = tp->lost - bbr->lt_last_lost; //采样期间丢失的数据包
	delivered = tp->delivered - bbr->lt_last_delivered; //采样期间发送的数据包
	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)//20%
		return;

	/* Find average delivery rate in this sampling interval. */
	//上述采样所用的时间 ms
	t = div_u64(tp->delivered_mstamp, USEC_PER_MSEC) - bbr->lt_last_stamp;
	if ((s32)t < 1) //时间太短 返回
		return;		/* interval is less than one ms, so wait */
	/* Check if can multiply without overflow */
	if (t >= ~0U / USEC_PER_MSEC) { //太长也不行
		bbr_reset_lt_bw_sampling(sk);  /* interval too long; reset */
		return;
	}
	t *= USEC_PER_MSEC;
	bw = (u64)delivered * BW_UNIT;
	do_div(bw, t);
	bbr_lt_bw_interval_done(sk, bw);
}

/* Estimate the bandwidth based on how fast packets are delivered */
static void bbr_update_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;
	//这里上来就设置为0 
	bbr->round_start = 0;
	//不合法检查
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	//是否可以进入到新的一轮，本次速率采样区间开始时的确认包数 每个rtt进入一次
	if (!before(rs->prior_delivered, bbr->next_rtt_delivered)) {
		bbr->next_rtt_delivered = tp->delivered; //
		bbr->rtt_cnt++;  //轮次++
		bbr->round_start = 1; //标记新一轮开始
		bbr->packet_conservation = 0; //清掉包守恒
	}
	//长期带宽估计，被限速的时候会启用长期bw？
	bbr_lt_bw_sampling(sk, rs);

	/* Divide delivered by the interval to find a (lower bound) bottleneck
	 * bandwidth sample. Delivered is in packets and interval_us in uS and
	 * ratio will be <<1 for most connections. So delivered is first scaled.
	 */
	//计算本次ack的样本的bw
	bw = div64_long((u64)rs->delivered * BW_UNIT, rs->interval_us);

	/* If this sample is application-limited, it is likely to have a very
	 * low delivered count that represents application behavior rather than
	 * the available network rate. Such a sample could drag down estimated
	 * bw, causing needless slow-down. Thus, to continue to send at the
	 * last measured network rate, we filter out app-limited samples unless
	 * they describe the path bw at least as well as our bw model.
	 *
	 * So the goal during app-limited phase is to proceed with the best
	 * network rate no matter how long. We automatically leave this
	 * phase when app writes faster than the network can deliver :)
	 */
	//用户没有发送的太慢
	if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) {
		/* Incorporate new sample into our max bw filter. */
		//min_max rtt测量也用到， 这里是的窗口是10 个rtt，记录的是最大带宽
		minmax_running_max(&bbr->bw, bbr_bw_rtts, bbr->rtt_cnt, bw);
	}
}

/* Estimates the windowed max degree of ack aggregation.
 * This is used to provision extra in-flight data to keep sending during
 * inter-ACK silences.
 *
 * Degree of ack aggregation is estimated as extra data acked beyond expected.
 *
 * max_extra_acked = "maximum recent excess data ACKed beyond max_bw * interval"
 * cwnd += max_extra_acked
 *
 * Max extra_acked is clamped by cwnd and bw * bbr_extra_acked_max_us (100 ms).
 * Max filter is an approximate sliding window of 5-10 (packet timed) round
 * trips.
 */
//计算可能的聚合的ack数量
static void bbr_update_ack_aggregation(struct sock *sk,
				       const struct rate_sample *rs)
{
	u32 epoch_us, expected_acked, extra_acked;
	struct bbr *bbr = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	//合法性检查
	if (!bbr_extra_acked_gain || rs->acked_sacked <= 0 ||
	    rs->delivered < 0 || rs->interval_us <= 0)
		return;
	//新的rtt轮次
	if (bbr->round_start) {
		bbr->extra_acked_win_rtts = min(0x1F,
						bbr->extra_acked_win_rtts + 1);
		if (bbr->extra_acked_win_rtts >= bbr_extra_acked_win_rtts) { //5轮新的rtt就切换窗口槽
			bbr->extra_acked_win_rtts = 0;
			bbr->extra_acked_win_idx = bbr->extra_acked_win_idx ? //设置使用的是哪个窗口 这里是交替使用？ 
						   0 : 1;
			bbr->extra_acked[bbr->extra_acked_win_idx] = 0;
		}
	}

	/* Compute how many packets we expected to be delivered over epoch. */
	////收报时间戳 - 统计ack聚合开始的时间戳
	epoch_us = tcp_stamp_us_delta(tp->delivered_mstamp,  
				      bbr->ack_epoch_mstamp);			
	expected_acked = ((u64)bbr_bw(sk) * epoch_us) / BW_UNIT; //计算期望的包数

	/* Reset the aggregation epoch if ACK rate is below expected rate or
	 * significantly large no. of ack received since epoch (potentially
	 * quite old epoch).
	 */
	if (bbr->ack_epoch_acked <= expected_acked ||   //实际 ACK 的包数 ≤ 理论应当 ACK 的包数。
	    (bbr->ack_epoch_acked + rs->acked_sacked >=   //如果自从本 epoch 开始累计收到的 ACK 数太多
	     bbr_ack_epoch_acked_reset_thresh)) {
		bbr->ack_epoch_acked = 0;					//清除计数
		bbr->ack_epoch_mstamp = tp->delivered_mstamp; //重新开始
		expected_acked = 0;
	}

	/* Compute excess data delivered, beyond what was expected. */
    //累计的ack计数
	bbr->ack_epoch_acked = min_t(u32, 0xFFFFF,
				     bbr->ack_epoch_acked + rs->acked_sacked); 
	extra_acked = bbr->ack_epoch_acked - expected_acked; 	//累计的减去期望的，是聚合的
	extra_acked = min(extra_acked, tcp_snd_cwnd(tp));		//钳制一下
	if (extra_acked > bbr->extra_acked[bbr->extra_acked_win_idx])
		bbr->extra_acked[bbr->extra_acked_win_idx] = extra_acked;  ///更新聚合ack的窗口
}

/* Estimate when the pipe is full, using the change in delivery rate: BBR
 * estimates that STARTUP filled the pipe if the estimated bw hasn't changed by
 * at least bbr_full_bw_thresh (25%) after bbr_full_bw_cnt (3) non-app-limited
 * rounds. Why 3 rounds: 1: rwin autotuning grows the rwin, 2: we fill the
 * higher rwin, 3: we get higher delivery rate samples. Or transient
 * cross-traffic or radio noise can go away. CUBIC Hystart shares a similar
 * design goal, but uses delay and inter-ACK spacing instead of bandwidth.
 */
//判断是否达到最大速率：若连续 3 个 RTT 都未超过 25% 增长，则认为带宽上限已探测到
static void bbr_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw_thresh;
	//管道已经满了  或者不是新一轮的开始，或者用户发包太慢
	if (bbr_full_bw_reached(sk) || !bbr->round_start || rs->is_app_limited)
		return;
	//最大带宽*1.25
	bw_thresh = (u64)bbr->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
	if (bbr_max_bw(sk) >= bw_thresh) { //采样结果大于最大带宽*1.25
		bbr->full_bw = bbr_max_bw(sk); //更新最大带宽
		bbr->full_bw_cnt = 0;
		return;
	}
	++bbr->full_bw_cnt;
	bbr->full_bw_reached = bbr->full_bw_cnt >= bbr_full_bw_cnt; //是否达到最大带宽标志
}

/* If pipe is probably full, drain the queue and then enter steady-state. */
static void bbr_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	//BBR_STARTUP 且已经达到最大带宽
	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
		bbr->mode = BBR_DRAIN;	/* drain queue we created */
		tcp_sk(sk)->snd_ssthresh = 				 //设置慢启动阈值，就为最大带宽
				bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT);
	}	/* fall through to check if in-flight is already small: */
	if (bbr->mode == BBR_DRAIN && //网络中实际的数据包，小于正常管道的容量
	    bbr_packets_in_net_at_edt(sk, tcp_packets_in_flight(tcp_sk(sk))) <=
	    bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT))
		bbr_reset_probe_bw_mode(sk);  /* we estimate queue is drained */ //这里设置为为了稳态
}

static void bbr_check_probe_rtt_done(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	//已设置结束时间戳，但是时间还诶到
	if (!(bbr->probe_rtt_done_stamp &&
	      after(tcp_jiffies32, bbr->probe_rtt_done_stamp)))
		return;
	//重置最小RTT的更新时间戳，确保10秒内不会再次进入PROBE_RTT模式。
	bbr->min_rtt_stamp = tcp_jiffies32;  /* wait a while until PROBE_RTT */
	tcp_snd_cwnd_set(tp, max(tcp_snd_cwnd(tp), bbr->prior_cwnd)); //还原回去原来的窗口
	bbr_reset_mode(sk); //切换到稳态或者startup
}

/* The goal of PROBE_RTT mode is to have BBR flows cooperatively and
 * periodically drain the bottleneck queue, to converge to measure the true
 * min_rtt (unloaded propagation delay). This allows the flows to keep queues
 * small (reducing queuing delay and packet loss) and achieve fairness among
 * BBR flows.
 *
 * The min_rtt filter window is 10 seconds. When the min_rtt estimate expires,
 * we enter PROBE_RTT mode and cap the cwnd at bbr_cwnd_min_target=4 packets.
 * After at least bbr_probe_rtt_mode_ms=200ms and at least one packet-timed
 * round trip elapsed with that flight size <= 4, we leave PROBE_RTT mode and
 * re-enter the previous mode. BBR uses 200ms to approximately bound the
 * performance penalty of PROBE_RTT's cwnd capping to roughly 2% (200ms/10s).
 *
 * Note that flows need only pay 2% if they are busy sending over the last 10
 * seconds. Interactive applications (e.g., Web, RPCs, video chunks) often have
 * natural silences or low-rate periods within 10 seconds where the rate is low
 * enough for long enough to drain its queue in the bottleneck. We pick up
 * these min RTT measurements opportunistically with our min_rtt filter. :-)
 */
static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool filter_expired;

	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	//记录的最小rtt的时间是否已经过期了  这里阈值是10s
	filter_expired = after(tcp_jiffies32,
			       bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);
	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us < bbr->min_rtt_us ||
	     (filter_expired && !rs->is_ack_delayed))) {
		bbr->min_rtt_us = rs->rtt_us;  					//更新最小rtt
		bbr->min_rtt_stamp = tcp_jiffies32; 
	}
	//进入PROBE_RTT模式
	if (bbr_probe_rtt_mode_ms > 0 && filter_expired &&
	    !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) {
		bbr->mode = BBR_PROBE_RTT;  /* dip, drain queue */ 			//设置为BBR_PROBE_RTT
		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */ 	//保存拥塞窗口
		bbr->probe_rtt_done_stamp = 0;  							//表示 PROBE_RTT模式刚开始
	}

	if (bbr->mode == BBR_PROBE_RTT) {
		/* Ignore low rate samples during this mode. */
		//这里直接标记为应用受限
		tp->app_limited = 
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
		/* Maintain min packets in flight for max(200 ms, 1 round). */
		if (!bbr->probe_rtt_done_stamp &&  //刚开始probe阶段
		     tcp_packets_in_flight(tp) <= bbr_cwnd_min_target) { 	//在途数据包小于四个
			bbr->probe_rtt_done_stamp = tcp_jiffies32 +  			//设置结束时间
				msecs_to_jiffies(bbr_probe_rtt_mode_ms);
			bbr->probe_rtt_round_done = 0;   						// 重置回合完成标志
			bbr->next_rtt_delivered = tp->delivered;  				//用于检测rtt round
		} else if (bbr->probe_rtt_done_stamp) {
			if (bbr->round_start)  									//新一轮的开始
				bbr->probe_rtt_round_done = 1; 					    //标记新一轮的结束
			if (bbr->probe_rtt_round_done)  						//如果一个rtt结束了
				bbr_check_probe_rtt_done(sk);
		}
	}
	/* Restart after idle ends only once we process a new S/ACK for data */
	if (rs->delivered > 0)
		bbr->idle_restart = 0;
}

static void bbr_update_gains(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	switch (bbr->mode) {
	case BBR_STARTUP:
		bbr->pacing_gain = bbr_high_gain; //2.885
		bbr->cwnd_gain	 = bbr_high_gain; //2.885
		break;
	case BBR_DRAIN:
		bbr->pacing_gain = bbr_drain_gain;	/* slow, to drain */ //上面的倒数
		bbr->cwnd_gain	 = bbr_high_gain;	/* keep cwnd */
		break;
	case BBR_PROBE_BW:
		bbr->pacing_gain = (bbr->lt_use_bw ?
				    BBR_UNIT :					//1
				    bbr_pacing_gain[bbr->cycle_idx]); //8个相位的值
		bbr->cwnd_gain	 = bbr_cwnd_gain;
		break;
	case BBR_PROBE_RTT:
		bbr->pacing_gain = BBR_UNIT; //1
		bbr->cwnd_gain	 = BBR_UNIT;
		break;
	default:
		WARN_ONCE(1, "BBR bad mode: %u\n", bbr->mode);
		break;
	}
}

static void bbr_update_model(struct sock *sk, const struct rate_sample *rs)
{
	//更新bw，
	bbr_update_bw(sk, rs);
	//计算聚合ack的数量
	bbr_update_ack_aggregation(sk, rs);
	//相位变换
	bbr_update_cycle_phase(sk, rs);
	//是否达到最大速率
	bbr_check_full_bw_reached(sk, rs);
	//是否需要排空，或者设置为稳态
	bbr_check_drain(sk, rs);
	//更新最小rtt 是否进入到probe rtt 或者start up
	bbr_update_min_rtt(sk, rs);
	//根据不同状态设置影响pacing 和cwnd的参数
	bbr_update_gains(sk);
}

__bpf_kfunc static void bbr_main(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw;
	//
	bbr_update_model(sk, rs);
	//拿到当前的带宽估计，最大或者是长期的
	bw = bbr_bw(sk);
	//设置发包速率
	bbr_set_pacing_rate(sk, bw, bbr->pacing_gain);
	//计算cwnd
	bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain);
}

__bpf_kfunc static void bbr_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->prior_cwnd = 0;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH; 	//这里是无限大
	bbr->rtt_cnt = 0;							//包计时轮次计数器
	bbr->next_rtt_delivered = tp->delivered; 	//当前轮的结束 delivered 值
	bbr->prev_ca_state = TCP_CA_Open;			//Open
	bbr->packet_conservation = 0;				//包守恒标志

	bbr->probe_rtt_done_stamp = 0; 				//probe结束的时间戳
	bbr->probe_rtt_round_done = 0;				//probe完成一轮
	bbr->min_rtt_us = tcp_min_rtt(tp); 			//最小rtt
	bbr->min_rtt_stamp = tcp_jiffies32; 		//记录rtt的时间
	minmax_reset(&bbr->bw, bbr->rtt_cnt, 0);  /* init max bw to 0 */

	bbr->has_seen_rtt = 0;
	bbr_init_pacing_rate_from_rtt(sk); 			//计算发包速率 pacingrate！

	bbr->round_start = 0;						// 是否是新一轮的ack
	bbr->idle_restart = 0;	 					// 是否处于应用空闲后重启
	bbr->full_bw_reached = 0;  					//是否达到最大带宽
	bbr->full_bw = 0;							//最大带宽
	bbr->full_bw_cnt = 0;						//连续未显著增长的轮次
	bbr->cycle_mstamp = 0;						//PROBE_BW 8 相位循环的起点时间清零
	bbr->cycle_idx = 0;							//相位索引
	bbr_reset_lt_bw_sampling(sk);  				//长期带宽采样
	bbr_reset_startup_mode(sk);  				//初始状态 STARTUP 模式

	bbr->ack_epoch_mstamp = tp->tcp_mstamp; 	//ACK 聚合统计周期的起点时间
	bbr->ack_epoch_acked = 0;					//累计收到的 ACK 数量
	bbr->extra_acked_win_rtts = 0;				 //管理ack聚合的情况
	bbr->extra_acked_win_idx = 0;
	bbr->extra_acked[0] = 0;
	bbr->extra_acked[1] = 0;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED); //发包通路上会判断这个标志
}

__bpf_kfunc static u32 bbr_sndbuf_expand(struct sock *sk)
{
	/* Provision 3 * cwnd since BBR may slow-start even during recovery. */
	return 3;
}

/* In theory BBR does not need to undo the cwnd since it does not
 * always reduce cwnd on losses (see bbr_main()). Keep it for now.
 */
//撤销的时候用到
__bpf_kfunc static u32 bbr_undo_cwnd(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	//复位最大带宽
	bbr->full_bw = 0;   /* spurious slow-down; reset full pipe detection */
	bbr->full_bw_cnt = 0;
	bbr_reset_lt_bw_sampling(sk); //重置长期带宽采样
	return tcp_snd_cwnd(tcp_sk(sk));//设置回之前的窗口大小
}

/* Entering loss recovery, so save cwnd for when we exit or undo recovery. */
__bpf_kfunc static u32 bbr_ssthresh(struct sock *sk)
{
	bbr_save_cwnd(sk);				 //保存之前的cwnd
	return tcp_sk(sk)->snd_ssthresh; //注意，这里没有改变慢启动阈值，因为不依靠丢包
}

static size_t bbr_get_info(struct sock *sk, u32 ext, int *attr,
			   union tcp_cc_info *info)
{
	if (ext & (1 << (INET_DIAG_BBRINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct bbr *bbr = inet_csk_ca(sk);
		u64 bw = bbr_bw(sk);

		bw = bw * tp->mss_cache * USEC_PER_SEC >> BW_SCALE;
		memset(&info->bbr, 0, sizeof(info->bbr));
		info->bbr.bbr_bw_lo		= (u32)bw;
		info->bbr.bbr_bw_hi		= (u32)(bw >> 32);
		info->bbr.bbr_min_rtt		= bbr->min_rtt_us;
		info->bbr.bbr_pacing_gain	= bbr->pacing_gain;
		info->bbr.bbr_cwnd_gain		= bbr->cwnd_gain;
		*attr = INET_DIAG_BBRINFO;
		return sizeof(info->bbr);
	}
	return 0;
}

__bpf_kfunc static void bbr_set_state(struct sock *sk, u8 new_state)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };

		bbr->prev_ca_state = TCP_CA_Loss;
		bbr->full_bw = 0;		//复位带宽信息
		bbr->round_start = 1;	/* treat RTO like end of a round */ //新的一轮
		bbr_lt_bw_sampling(sk, &rs);
	}
}
//注意没有拥塞避免的回调
static struct tcp_congestion_ops tcp_bbr_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,	// 不受限的算法类型，可被任意 socket 使用（非专用）
	.name		= "bbr",					
	.owner		= THIS_MODULE,			
	.init		= bbr_init,						// 初始化函数：每条连接建立时调用，初始化 BBR 的内部状态（min_rtt、bw 等）
	.cong_control	= bbr_main,					// bbr控制核心函数！！！！！！！！！！！！,每次收到tcp_ack中会调用
	.sndbuf_expand	= bbr_sndbuf_expand,		// 发送缓存扩展函数：三次握手建立连接时调用.收报路径也会调用
	.undo_cwnd	= bbr_undo_cwnd,				// 撤销 cwnd 缩减：如果丢包判断错误（如 DSACK 撤销），恢复 cwnd 到丢包前的值
	.cwnd_event	= bbr_cwnd_event,				// cwnd 事件处理这里bbr只处理用户发包太慢
	.ssthresh	= bbr_ssthresh,					// 计算慢启动阈值：进入丢包恢复时调用，BBR 不使用传统 ssthresh，通常直接返回当前值
	.min_tso_segs	= bbr_min_tso_segs,			// 设置最小 TSO 分段数
	.get_info	= bbr_get_info,					// 导出 BBR 运行时信息
	.set_state	= bbr_set_state,				// 状态切换回调
};
BTF_SET8_START(tcp_bbr_check_kfunc_ids)
#ifdef CONFIG_X86
#ifdef CONFIG_DYNAMIC_FTRACE
BTF_ID_FLAGS(func, bbr_init)
BTF_ID_FLAGS(func, bbr_main)
BTF_ID_FLAGS(func, bbr_sndbuf_expand)
BTF_ID_FLAGS(func, bbr_undo_cwnd)
BTF_ID_FLAGS(func, bbr_cwnd_event)
BTF_ID_FLAGS(func, bbr_ssthresh)
BTF_ID_FLAGS(func, bbr_min_tso_segs)
BTF_ID_FLAGS(func, bbr_set_state)
#endif
#endif
BTF_SET8_END(tcp_bbr_check_kfunc_ids)

static const struct btf_kfunc_id_set tcp_bbr_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &tcp_bbr_check_kfunc_ids,
};

static int __init bbr_register(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct bbr) > ICSK_CA_PRIV_SIZE);

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &tcp_bbr_kfunc_set);
	if (ret < 0)
		return ret;
	return tcp_register_congestion_control(&tcp_bbr_cong_ops);
}

static void __exit bbr_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_bbr_cong_ops);
}

module_init(bbr_register);
module_exit(bbr_unregister);

MODULE_AUTHOR("Van Jacobson <vanj@google.com>");
MODULE_AUTHOR("Neal Cardwell <ncardwell@google.com>");
MODULE_AUTHOR("Yuchung Cheng <ycheng@google.com>");
MODULE_AUTHOR("Soheil Hassas Yeganeh <soheil@google.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP BBR (Bottleneck Bandwidth and RTT)");
