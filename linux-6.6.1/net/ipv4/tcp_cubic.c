// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4000U)	/* 4 ms */
#define HYSTART_DELAY_MAX	(16000U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh __read_mostly;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

static int hystart __read_mostly = 1;
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;
static int hystart_ack_delta_us __read_mostly = 2000;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta_us, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta_us, "spacing between ack's indicating train (usecs)");

/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32	last_max_cwnd;	/* last maximum snd_cwnd */ //上一次出现丢包前的最大拥塞窗口
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
	u32	delay_min;	/* min delay (usec) */ //当前观测到的最小往返时延
	u32	epoch_start;	/* beginning of an epoch */ //当前增长周期（从最新一次拥塞事件后）开始的时间戳  算t的时候用到！
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
	u16	unused;
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found;		/* the exit point is found? */
	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
};

static inline void bictcp_reset(struct bictcp *ca)
{
	memset(ca, 0, offsetof(struct bictcp, unused));
	ca->found = 0;
}

static inline u32 bictcp_clock_us(const struct sock *sk)
{
	return tcp_sk(sk)->tcp_mstamp;
}

static inline void bictcp_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = bictcp_clock_us(sk); //复位时间戳
	ca->end_seq = tp->snd_nxt; //记录当前发送的下一个序列号
	ca->curr_rtt = ~0U;  // 重置 RTT 测量
	ca->sample_cnt = 0;
}

__bpf_kfunc static void cubictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);
	//memset
	bictcp_reset(ca);
	//默认是1 ，检测到拥塞迹象时提前退出慢启动
	if (hystart)
		bictcp_hystart_reset(sk);
	//是否设置了初始化了慢启动阈值
	if (!hystart && initial_ssthresh) 
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

__bpf_kfunc static void cubictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_TX_START) {
		struct bictcp *ca = inet_csk_ca(sk);
		u32 now = tcp_jiffies32;
		s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (after(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
{
	u32 delta, bic_target, max_cnt;
	u64 offs, t;
	//ack的总数
	ca->ack_cnt += acked;	/* count the number of ACKed packets */
	//拥塞窗口没有变化，且时间太短了
	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update ca->cnt at most once per jiffy.
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	//是否处于一个增长周期 且在同一个时间片内，意思就是每个jiffy最多计算一次Cubic
	if (ca->epoch_start && tcp_jiffies32 == ca->last_time)
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;  //记录当前拥塞窗口
	ca->last_time = tcp_jiffies32; //记录当前时间戳
	//== 0表示上次发生过拥塞，或者第一次？
	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_jiffies32;	/* record beginning */ //记录新周期开始的时间戳
		ca->ack_cnt = acked;			/* start counting */ //传入的ack数目
		ca->tcp_cwnd = cwnd;			/* syn with cubic */ //保存当前的拥塞窗口

		if (ca->last_max_cwnd <= cwnd) {  //历史最大窗口是否小于本次的拥塞窗口
			ca->bic_K = 0;       		//立即开始快速增长？
			ca->bic_origin_point = cwnd; //当前窗口为起点
		} else { //低于最大的拥塞窗口
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			//从当前窗口恢复到历史最大窗口所需的预估时间
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */
	//当前增长周期开始到现在经过的时间
	t = (s32)(tcp_jiffies32 - ca->epoch_start);
	//加一个最小rtt 是干什么的
	t += usecs_to_jiffies(ca->delay_min);
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ);

	if (t < ca->bic_K)		//计算/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	//相当于delta = C × (t - K)³
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);  //这个是计算窗口差值
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta; //恢复
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta; //超越

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		//计算多少个ack增加拥塞窗口
		ca->cnt = cwnd / (bic_target - cwnd);
	} else { //不正常的情况，极慢
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	 //如果刚开始，确保增长的别太慢
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;
		//计算reno 多少ack加拥塞窗口
		delta = (cwnd * scale) >> 3; //每 RTT +1 cwnd？ 这里不太懂
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}
		//比reno还慢，用reno的
		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	//    //至少收到两个ack 窗口才能加1 
	ca->cnt = max(ca->cnt, 2U);
}

__bpf_kfunc static void cubictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	//是否被拥塞窗口限制，该字段在发包的时候被设置
	if (!tcp_is_cwnd_limited(sk))
		return;
	//当前拥塞窗口小于慢启动阈值
	if (tcp_in_slow_start(tp)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	//传入剩余ack的数量
	bictcp_update(ca, tcp_snd_cwnd(tp), acked);
	//更新拥塞窗口
	tcp_cong_avoid_ai(tp, ca->cnt, acked);
}

__bpf_kfunc static u32 cubictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	//表示当前的 CUBIC 增长周期结束，拥塞避免会用到
	ca->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	//当前 cwnd 比上一次的最大窗口小, 并且启用了快速收敛 就说明这次丢包发生在带宽下降的情况下
	//如果开启 fast_convergence，新的历史最大窗口 = 当前窗口*0.85 即比上一次最大值更小一点，防止继续过冲
	//last_max_cwnd影响拥塞避免阶段的计算
	if (tcp_snd_cwnd(tp) < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tcp_snd_cwnd(tp) * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else //带宽没变差
		ca->last_max_cwnd = tcp_snd_cwnd(tp); //就直接把当前 cwnd 当成新的最大窗口 Wmax
	//cwnd减少到70%
	return max((tcp_snd_cwnd(tp) * beta) / BICTCP_BETA_SCALE, 2U);
}
//要重新计算 Wmax K epoch_start 等参数
__bpf_kfunc static void cubictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		bictcp_reset(inet_csk_ca(sk));
		bictcp_hystart_reset(sk);
	}
}

/* Account for TSO/GRO delays.
 * Otherwise short RTT flows could get too small ssthresh, since during
 * slow start we begin with small TSO packets and ca->delay_min would
 * not account for long aggregation delay when TSO packets get bigger.
 * Ideally even with a very small RTT we would like to have at least one
 * TSO packet being sent and received by GRO, and another one in qdisc layer.
 * We apply another 100% factor because @rate is doubled at this point.
 * We cap the cushion to 1ms.
 */
static u32 hystart_ack_delay(const struct sock *sk)
{
	unsigned long rate;

	rate = READ_ONCE(sk->sk_pacing_rate);
	if (!rate)
		return 0;
	return min_t(u64, USEC_PER_MSEC,
		     div64_ul((u64)sk->sk_gso_max_size * 4 * USEC_PER_SEC, rate));
}

static void hystart_update(struct sock *sk, u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 threshold;
	//una 在最后一个序号后面，更新end
	if (after(tp->snd_una, ca->end_seq))
		bictcp_hystart_reset(sk);

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now = bictcp_clock_us(sk); //拿到当前时间

		/* first detection parameter - ack-train detection */
		//两个ack的时间的差值小于阈值的话，表示的是ack很密集？，很密集表示网络要出现拥塞了？
		//因为ack可能在链路中被挤积压了？？
		if ((s32)(now - ca->last_ack) <= hystart_ack_delta_us) {
			ca->last_ack = now;
			//最小rtt加上 一个1ms以下的时间（qdisc, TSO ,GSO考虑进来）
			threshold = ca->delay_min + hystart_ack_delay(sk);

			/* Hystart ack train triggers if we get ack past
			 * ca->delay_min/2.
			 * Pacing might have delayed packets up to RTT/2
			 * during slow start.
			 */
			//没有用pacing 除2
			if (sk->sk_pacing_status == SK_PACING_NONE)
				threshold >>= 1;
			//这一轮（到end——seq之前叫做一轮） ACK 已经持续得比认为正常的时间更久
			if ((s32)(now - ca->round_start) > threshold) {
				ca->found = 1;
				pr_debug("hystart_ack_train (%u > %u) delay_min %u (+ ack_delay %u) cwnd %u\n",
					 now - ca->round_start, threshold,
					 ca->delay_min, hystart_ack_delay(sk), tcp_snd_cwnd(tp));
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINCWND,
					      tcp_snd_cwnd(tp));
				tp->snd_ssthresh = tcp_snd_cwnd(tp); //设置慢启动阈值
			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) {
		/* obtain the minimum delay of more than sampling packets */
		if (ca->curr_rtt > delay)
			ca->curr_rtt = delay; //更新一轮中rtt的最小值
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
			ca->sample_cnt++;  //先采样几次
		} else {
			//如果这一轮中rtt明显高于历史最高rtt 直接设置慢启动阈值
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
				ca->found = 1;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYCWND,
					      tcp_snd_cwnd(tp));
				tp->snd_ssthresh = tcp_snd_cwnd(tp);
			}
		}
	}
}
//每次收到ACK时， RTT 采样给HyStart提供数据
__bpf_kfunc static void cubictcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 delay;

	/* Some calls are for duplicates without timetamps */
	//直接返回
	if (sample->rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	//快恢复一秒内不采样
	if (ca->epoch_start && (s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
		return;
	//更新当前 RTT
	delay = sample->rtt_us;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	//记录最小rtt
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	//在慢启动状态是否可以提前结束慢启动，进入拥塞避免
	if (!ca->found && tcp_in_slow_start(tp) && hystart &&
	    tcp_snd_cwnd(tp) >= hystart_low_window)
		hystart_update(sk, delay);
}

static struct tcp_congestion_ops cubictcp __read_mostly = {
	.init		= cubictcp_init,		//三次握手完成的时候会调用
	.ssthresh	= cubictcp_recalc_ssthresh,  //进入恢复状态的时候会调用，重新计算慢启动阈值
	.cong_avoid	= cubictcp_cong_avoid,	//拥塞避免阶段会调用
	.set_state	= cubictcp_state,		//状态转换的时候会调用
	.undo_cwnd	= tcp_reno_undo_cwnd,  //拥塞窗口撤销的时候调用
	.cwnd_event	= cubictcp_cwnd_event, //多个地方会调用，在发送的通路上回调用cubic注册的这个钩子
	.pkts_acked     = cubictcp_acked,	//清理重传队列回调用，是否需要提前退出慢启动
	.owner		= THIS_MODULE,
	.name		= "cubic",
};

BTF_SET8_START(tcp_cubic_check_kfunc_ids)
#ifdef CONFIG_X86
#ifdef CONFIG_DYNAMIC_FTRACE
BTF_ID_FLAGS(func, cubictcp_init)
BTF_ID_FLAGS(func, cubictcp_recalc_ssthresh)
BTF_ID_FLAGS(func, cubictcp_cong_avoid)
BTF_ID_FLAGS(func, cubictcp_state)
BTF_ID_FLAGS(func, cubictcp_cwnd_event)
BTF_ID_FLAGS(func, cubictcp_acked)
#endif
#endif
BTF_SET8_END(tcp_cubic_check_kfunc_ids)

static const struct btf_kfunc_id_set tcp_cubic_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &tcp_cubic_check_kfunc_ids,
};

static int __init cubictcp_register(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */
	// TCP友好性用到 beta_scale 用来把 CUBIC 的增长速度调成和 Reno 相当
	beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3
		/ (BICTCP_BETA_SCALE - beta);

	//算C用到
	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */
	//算K的时候用到
	/* divide by bic_scale and by constant Srtt (100ms) */
	do_div(cube_factor, bic_scale * 10);
	//bfp相关
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &tcp_cubic_kfunc_set);
	if (ret < 0)
		return ret;
	return tcp_register_congestion_control(&cubictcp);
}

static void __exit cubictcp_unregister(void)
{
	tcp_unregister_congestion_control(&cubictcp);
}

module_init(cubictcp_register);
module_exit(cubictcp_unregister);

MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CUBIC TCP");
MODULE_VERSION("2.3");
