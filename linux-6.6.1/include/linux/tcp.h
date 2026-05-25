/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H


#include <linux/skbuff.h>
#include <linux/win_minmax.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>
#include <uapi/linux/tcp.h>

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int __tcp_hdrlen(const struct tcphdr *th)
{
	return th->doff * 4;
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return __tcp_hdrlen(tcp_hdr(skb));
}

static inline struct tcphdr *inner_tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_inner_transport_header(skb);
}

static inline unsigned int inner_tcp_hdrlen(const struct sk_buff *skb)
{
	return inner_tcp_hdr(skb)->doff * 4;
}

/**
 * skb_tcp_all_headers - Returns size of all headers for a TCP packet
 * @skb: buffer
 *
 * Used in TX path, for a packet known to be a TCP one.
 *
 * if (skb_is_gso(skb)) {
 *         int hlen = skb_tcp_all_headers(skb);
 *         ...
 */
static inline int skb_tcp_all_headers(const struct sk_buff *skb)
{
	return skb_transport_offset(skb) + tcp_hdrlen(skb);
}

/**
 * skb_inner_tcp_all_headers - Returns size of all headers for an encap TCP packet
 * @skb: buffer
 *
 * Used in TX path, for a packet known to be a TCP one.
 *
 * if (skb_is_gso(skb) && skb->encapsulation) {
 *         int hlen = skb_inner_tcp_all_headers(skb);
 *         ...
 */
static inline int skb_inner_tcp_all_headers(const struct sk_buff *skb)
{
	return skb_inner_transport_offset(skb) + inner_tcp_hdrlen(skb);
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* TCP Fast Open */
#define TCP_FASTOPEN_COOKIE_MIN	4	/* Min Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_MAX	16	/* Max Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_SIZE 8	/* the size employed by this impl. */

/* TCP Fast Open Cookie as stored in memory */
struct tcp_fastopen_cookie {
	__le64	val[DIV_ROUND_UP(TCP_FASTOPEN_COOKIE_MAX, sizeof(u64))];
	s8	len;
	bool	exp;	/* In RFC6994 experimental option format */
};

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

/*These are used to set the sack_ok field in struct tcp_options_received */
#define TCP_SACK_SEEN     (1 << 0)   /*1 = peer is SACK capable, */
#define TCP_DSACK_SEEN    (1 << 2)   /*1 = DSACK was received from peer*/ //收到dsack

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	int	ts_recent_stamp;/* Time we stored ts_recent (for aging) */ //这之前的貌似就丢掉？？ 收到ack创建新sock的时候也会用到
	u32	ts_recent;	/* Time stamp to echo next		*/   //三次握手被动打开方 收到syn包的时间戳用这个保存
	u32	rcv_tsval;	/* Time stamp value             	*/ //解析选项保存的对端时间戳
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/  //回显的时间戳
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/    //是否支持时间戳
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/ //对端是否支持窗口扩大因子，
		sack_ok : 3,	/* SACK seen on SYN packet		*/			//是否支持sack
		smc_ok : 1,	/* SMC seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/ //对端声明窗口扩大因子值
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
	u8	saw_unknown:1,	/* Received unknown option		*/
		unused:7;
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;	/* mss requested by user in ioctl	*/
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

static inline void tcp_clear_options(struct tcp_options_received *rx_opt)
{
	rx_opt->tstamp_ok = rx_opt->sack_ok = 0; //时间戳，sack 清零
	rx_opt->wscale_ok = rx_opt->snd_wscale = 0; //对端是否支持窗口扩大因子， 对端声明窗口扩大因子值
#if IS_ENABLED(CONFIG_SMC)
	rx_opt->smc_ok = 0;
#endif
}

/* This is the max number of SACKS that we'll generate and process. It's safe
 * to increase this, although since:
 *   size = TCPOLEN_SACK_BASE_ALIGNED (4) + n * TCPOLEN_SACK_PERBLOCK (8)
 * only four options will fit in a standard TCP header */
#define TCP_NUM_SACKS 4

struct tcp_request_sock_ops;

struct tcp_request_sock {
	struct inet_request_sock 	req;
	const struct tcp_request_sock_ops *af_specific;
	u64				snt_synack; /* first SYNACK sent time *///第一次发送syn ack的时间 send_synack中会设置
	bool				tfo_listener;
	bool				is_mptcp;
#if IS_ENABLED(CONFIG_MPTCP)
	bool				drop_req;
#endif
	u32				txhash;  //txhash 接收syn时候设置的
	u32				rcv_isn; //客户端的初始序列号 tcp_openreq_init 会设置
	u32				snt_isn; //序列号，计算得到的
	u32				ts_off; //时间戳偏移
	u32				last_oow_ack_time; /* last SYNACK */ //上次发送synack的时间
	u32				rcv_nxt; /* the ack # by SYNACK. For
						  * FastOpen it's the seq#
						  * after data-in-SYN.
						  */
	u8				syn_tos;
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

#define TCP_RMEM_TO_WIN_SCALE 8

struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;				//inet_connection_sock
	u16	tcp_header_len;	/* Bytes of tcp header to send	*/	//tcp头部长度
	u16	gso_segs;	/* Max number of segs per GSO packet	*///分段数量 64k/mss

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */	
	__be32	pred_flags;									//一个标志位根据首部长和ack还有窗口大小计算，用于预测是否能走快速路径收包

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
	u64	bytes_received;	/* RFC4898 tcpEStatsAppHCThruOctetsReceived  //实际接收的字节数，也就是确认的字节数
				 * sum(delta(rcv_nxt)), or how many bytes
				 * were acked.
				 */
	u32	segs_in;	/* RFC4898 tcpEStatsPerfSegsIn             //接收了多少个段
				 * total number of segments in.
				 */
	u32	data_segs_in;	/* RFC4898 tcpEStatsPerfDataSegsIn		//与上面类似，表示接收了多少个有payload的段
				 * total number of data segments in.
				 */
 	u32	rcv_nxt;	/* What we want to receive next 	*/       //下一个想要接收报文的序号
	u32	copied_seq;	/* Head of yet unread data		*/				//用户进程已经读取到的位置
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/		//上一次更新的rcv_nxt，延迟ack可能会用到，应该叫上次通告对端窗口时候序列号？
 	u32	snd_nxt;	/* Next sequence we send		*/				//下一个待发送的序列号
	u32	segs_out;	/* RFC4898 tcpEStatsPerfSegsOut					//发出去的段数
				 * The total number of segments sent.
				 */
	u32	data_segs_out;	/* RFC4898 tcpEStatsPerfDataSegsOut			//发出去的段数，包括没有payload的
				 * total number of data segments sent.
				 */
	u64	bytes_sent;	/* RFC4898 tcpEStatsPerfHCDataOctetsOut			//发送出去的字节数，不包括头部长度
				 * total number of data bytes sent.
				 */
	u64	bytes_acked;	/* RFC4898 tcpEStatsAppHCThruOctetsAcked	//对端已经确认的字节总数
				 * sum(delta(snd_una)), or how many bytes
				 * were acked.
				 */
	u32	dsack_dups;	/* RFC4898 tcpEStatsStackDSACKDups				//重复ack的数量，可能是
				 * total number of DSACK blocks received
				 */
 	u32	snd_una;	/* First byte we want an ack for	*/			//发送出去未确认的序号 //三次握手收到ack的处理逻辑为为ack_seq
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */  //发送小于mss的数据包的最后一个字节的序列号 ，nagle算法用到 tcp_minshall_update
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */  //接收数据包的时间戳，tcpack中赋值
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */		//记录发包时间用于计算rtt
	u32	last_oow_ack_time;  /* timestamp of last out-of-window ACK */		//收到了乱续的ack ，可以根据这个时间触发重传
	//延迟或合并 ACK 时，会将当前的 rcv_nxt（接收窗口的下一个期望序列号）暂存到 compressed_ack_rcv_nxt
	u32	compressed_ack_rcv_nxt;										
	
	u32	tsoffset;	/* timestamp offset */ //tcp三次握手时间确定这个值，确保相对tcp的时间是单调递增的，计算时间戳的时候会用到
	//将 TCP Socket 挂载到全局的 tsq_tasklet 任务队列中，实现 异步批量释放发送队列内存
	struct list_head tsq_node; /* anchor in tsq_tasklet.head list */ //把当前sock放入软中断中等待调度
	struct list_head tsorted_sent_queue; /* time-sorted sent but un-SACKed skbs *///时间排序的已发送但未确认队列，发送的时候会将skb挂到这里

	u32	snd_wl1;	/* Sequence for window update		*/  //发送窗口更新时候的序列号
	u32	snd_wnd;	/* The window we expect to receive	*/		//发送窗口大小，从接收数据包的字段中获取
	u32	max_window;	/* Maximal window ever seen from peer	*/  //最大接收窗口值,从tcp的窗口字段找到
	u32	mss_cache;	/* Cached effective mss, not including SACKS */ //经过一系列计算后得到的最终mss 根据窗口大小，通告大小，pmtu得到的值

	u32	window_clamp;	/* Maximal window to advertise		*/	//最大缓冲区大小 //setsockopt可以设置？ //三次握手收到ack会设置 //发送syn包的时候会设置//接收synack也可能会设置 //tcp_init_buffer_space
	u32	rcv_ssthresh;	/* Current window clamp			*/   //三次握手中创建新sock的时候会设置 //	newtp->rcv_ssthresh = req->rsk_rcv_wnd;  //慢启动的初始值tcp_select_initial_window，貌似影响通告给对端窗口的大小
	u8	scaling_ratio;	/* see tcp_win_from_space() */			//窗口缩放因子
	/* Information of the most recently (s)acked skb */
	struct tcp_rack {
		u64 mstamp; /* (Re)sent time of the skb */ //记录数据包​​最近一次发送或重传的时间戳
		u32 rtt_us;  /* Associated RTT */ //通过 ACK 报文的确认时间与数据包发送时间的差值计算得到
		u32 end_seq; /* Ending TCP sequence of the skb */	//​​最近被确认的数据包的结束序列号
		u32 last_delivered; /* tp->delivered at last reo_wnd adj */  //之前传输已被接受的数量
		u8 reo_wnd_steps;   /* Allowed reordering window */  //调整乱续窗口的因子，在收到dsack的时候会更新
#define TCP_RACK_RECOVERY_THRESH 16
		u8 reo_wnd_persist:5, /* No. of recovery since last adj */ //误判丢包，增加这个值，真是丢包就减少这个值，目的是减少乱续容忍但是对丢包敏感
		   dsack_seen:1, /* Whether DSACK seen after last adj */			//发送端收到重复选择ack的时候设置
		   advanced:1;	 /* mstamp advanced since last lost marking */  //表示更新了rack的字段？可能处罚重传？ //undo_loss中会设置
	} rack;
	u16	advmss;		/* Advertised MSS			*/
	u8	compressed_ack;	//收到乱续包的时候会增加  不立即发送ack
	u8	dup_ack_counter:2, 	//重复ack的数量
		tlp_retrans:1,	/* TLP is a retransmission */ //Tail Loss Probe重传 标识的是新包还是重传队列中的包！
		unused:5;
	u32	chrono_start;	/* Start time in jiffies of a TCP chrono */
	//测量 TCP 连接在不同状态下的耗时，例如接收窗口不足的时候
	u32	chrono_stat[3];	
	//当前的类型
	u8	chrono_type:2,	/* current chronograph type */
	//标记为应用层限速，应该是限制cwnd的增长，initsock的时候就会设这为1
		rate_app_limited:1,  /* rate_{delivered,interval_us} limited? */
	//TFO 标志通过setsockopt设置，允许发syn包的时候携带数据
		fastopen_connect:1, /* FASTOPEN_CONNECT sockopt */
	//在没有cookie的情况下也允许syn包携带数据
		fastopen_no_cookie:1, /* Allow send/recv SYN+data without a cookie */
		/*接收端收到乱序数据包（如序列号25-30），暂存于out_of_order_queue队列，并通过SACK块（25-31）告知发送端。
当接收缓冲区不足（sk_rmem_alloc超过sk_rcvbuf阈值），内核清理乱序队列（调用tcp_prune_ofo_queue），丢弃已SACK确认的数据。
发送端后续收到ACK时，发现之前SACK确认的数据未被接收端最终确认（ACK未覆盖SACK范围），判定为SACK reneging，设置is_sack_reneg:1*/
		is_sack_reneg:1,    /* in recovery from loss with SACK reneg? */  //enterloss中会设置
		fastopen_client_fail:2; /* reason why fastopen failed */
		//用了3bit 禁用  cork(等待) 和push(立即发送)
	u8	nonagle     : 4,/* Disable Nagle algorithm?             */ //tcp_skb_entail 会设置
	//线性重传机制，而不是指数退避，setsockopt设置
		thin_lto    : 1,/* Use linear timeouts for thin streams */
	//用户获取msg的时候可以获取队列中剩余的字节数
		recvmsg_inq : 1,/* Indicate # of bytes in queue upon recvmsg */
		//热迁移场景发送数据包的时候会用到
		repair      : 1,
		//tcp_enter_loss中设置该标志位，用于判断虚假丢包，如果是虚假丢包，就快速撤销丢包状态
		frto        : 1;/* F-RTO (RFC5682) activated in CA_Loss */ //进入loss发包 因为可能是假的 所以有这个
	u8	repair_queue; //setsockopt设置，热迁移场景用到
	u8	save_syn:2,	/* Save headers of SYN packet */ //setsocktopt设置，服务端收到syn包后，决定是否提取包头
		syn_data:1,	/* SYN includes data */ //syn包是否携带数据，fastopen相关
		syn_fastopen:1,	/* SYN includes Fast Open option */ //用户设置，是否启用fastopen
		syn_fastopen_exp:1,/* SYN includes Fast Open exp. option */
		syn_fastopen_ch:1, /* Active TFO re-enabling probe */
		syn_data_acked:1,/* data in SYN is acked by SYN-ACK */ //标记syn包携带数据后，是否被对端确认
		is_cwnd_limited:1;/* forward progress limited by snd_cwnd? *///由于拥塞窗口无法发包
	u32	tlp_high_seq;	/* snd_nxt at the time of TLP */ //丢包探测报文的序号


	u32	tcp_tx_delay;	/* delay (in usec) added to TX packets *///setscokopt设置，transmit的时候会add_tx_dleay
	u64	tcp_wstamp_ns;	/* departure time for next sent data packet */ //pacing 会用到，每次发送一个数据包后会更新这个值 //__tcp_transmit_skb设置
	u64	tcp_clock_cache; /* cache last tcp_clock_ns() tcp_write_xmit(see tcp_mstamp_refresh()) *///当前时间缓存从寄存器读出来的时间戳tcp_clock_ns，避免反复获取，就缓存起来了

/* RTT measurement */ 
	u64	tcp_mstamp;	/* most recent packet received/sent */  //收发包的时间戳也是tcp_mstamp_refresh tcp_write_xmit设置的   tcp_rcv_state_process会更新
	//计算rtt相关，清除重传队列的时候会用到下面一系列变量
	u32	srtt_us;	/* smoothed round trip time << 3 in usecs */ //平滑后的rtt ，会右移3位
	u32	mdev_us;	/* medium deviation			*/	//衡量rtt的波动程度，。。。
	u32	mdev_max_us;	/* maximal mdev for the last rtt period	*/ //最近 1 个 RTT 周期内最大偏差
	u32	rttvar_us;	/* smoothed mdev_max			*/   //平滑的 RTT 偏差估值，用于最终计算 RTO，是一个瞬时的波动？
	u32	rtt_seq;	/* sequence number to update rttvar	*/ //计算rtt对应数据包的序列号
	struct  minmax rtt_min;  //连接历史中的最小 RTT 值 tcp_ack中调用

	u32	packets_out;	/* Packets which are "in flight"	*/ //发送的时候会设置这个值， 表示发出去还没有收到ack的数量
	u32	retrans_out;	/* Retransmitted packets out		*/ //重传的时候会加这个值，ack的处理中会减
	u32	max_packets_out;  /* max packets_out in last window */  //发送的时候会更新这个值，拥塞算法会用到
	u32	cwnd_usage_seq;  /* right edge of cwnd usage tracking flight */ //同上tcp_cwnd_validate会用到

	u16	urg_data;	/* Saved octet of OOB data and control flags */ //收到带外数据的时候会设置这个字段？
	u8	ecn_flags;	/* ECN status bits.			*/      //  发送syn包的时候开启ecn会设置这个字段，或者收到网络中的ecn包
	u8	keepalive_probes; /* num of allowed keep alive probes	*/  //set设置，保活探测超过这个设置就直接error
	u32	reordering;	/* Packet reordering metric.		*/     //乱序容忍度，newreno会用到，其他地方还会用到吗？  enterloss中会设置
	u32	reord_seen;	/* number of data packet reordering events */   //乱序包的数量，rack会用到 tcp_rack_reo_wnd
	u32	snd_up;		/* Urgent pointer		*/    //发送方会设置，oob数据的序号

/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt; //存储接收到的tcp选项，时间戳，scak，mss //好像发送也用比如发送syn

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold		*/ //snd_ssthresh慢启动阈值
 	u32	snd_cwnd;	/* Sending congestion window		*/  //发送放能发多少个mss
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/	//tcpack中处理拥塞的时候会根据ack设置并使用该值如bic
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */  //拥塞窗口的最大值
	u32	snd_cwnd_used;										// 等于packetout 为发送出去还没有确认的包数
	u32	snd_cwnd_stamp;										// 每次调整拥塞窗口的时间戳，在发送方调整拥塞窗口的时候会用到
	u32	prior_cwnd;	/* cwnd right before starting loss recovery */ //enterloss 的时候记录丢包前的值
	u32	prr_delivered;	/* Number of newly delivered packets to  //影响cwnd sack的数量会决定这个值
				 * receiver in Recovery. */
	u32	prr_out;	/* Total number of pkts sent during Recovery. *///快恢复状态中发包数量，也包括重传的
	u32	delivered;	/* Total data packets delivered incl. rexmits */	//被确认的ack总数，包括重传确认的，拥塞控制会用到
	u32	delivered_ce;	/* Like the above but only ECE marked packets */		//ack中带有ece的总数
	u32	lost;		/* Total data packets lost incl. rexmits */			//历史丢包总数，多个地方会设置
	u32	app_limited;	/* limited until "delivered" reaches this val */  //是否受限与应用程序？发送的时候也会设置 bbr算法会用到，初始化时不为0 收到数据包后会修改这个值
	u64	first_tx_mstamp;  /* start of window send phase */			//发送的时候记录的时间戳  ，ack中也会用到，供拥塞算法使用？

	u64	delivered_mstamp; /* time we reached "delivered" */					//bbr算法使用发送的时候会设置，处理ack的时候也会设置
	u32	rate_delivered;    /* saved rate sample: packets delivered */		//用于计算发速率 tcp_rate_gen 中被设置
	u32	rate_interval_us;  /* saved rate sample: time elapsed */				//时间间隔 同上， 这两个字段都是为了计算tcp的实施传输速率 ss命令可以获取


 	u32	rcv_wnd;	/* Current receiver window		*/						//接收窗口的大小
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */			//发送缓冲区中最后一个字节的下一个序列号 下一个要发送的序列!!! tcp_sendmsg_locked
	u32	notsent_lowat;	/* TCP_NOTSENT_LOWAT */								//通过set设置的一个低水位线，会和未发送的字节比较，如果小于，就表示内存不足，好像发送就会阻塞？
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */		//设置push标志位的时候的序列号
	u32	lost_out;	/* Lost packets			*/								//当前待重传的丢包的数量 //tcp_mark_skb_lost+
	u32	sacked_out;	/* SACK'd packets			*/							//sack确认包的数量

	struct hrtimer	pacing_timer;											//tsq的定时器，init tcp_sock的时候会设置，注意：软中的也调用这个注册的函数在free的时候
	struct hrtimer	compressed_ack_timer;									//延迟sack定时器。

	/* from STCP, retrans queue hinting */			
	struct sk_buff* lost_skb_hint;											//定位第一个丢失的包 ，优化性能？
	struct sk_buff *retransmit_skb_hint;									//下一个要重传的数据包

	/* OOO segments go in this rbtree. Socket lock must be held. */			//tcp的乱续队列
	struct rb_root	out_of_order_queue;										
	struct sk_buff	*ooo_last_skb; /* cache rb_last(out_of_order_queue) */	//乱续队列中欧给你最后一个数据包

	/* SACKs data, these 2 need to be together (see tcp_options_write) */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */					
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/			//发送端收到sack

	struct tcp_sack_block recv_sack_cache[4];									//接收端生成sack

	struct sk_buff *highest_sack;   /* skb just after the highest				//已经被接收段确认的最高序列号的数据包？？？
					 * skb with SACKed bit set
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */

	int     lost_cnt_hint;													//处理重传队列用到，一个数量，是丢包标记前未处理的数据包数量

	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/				//保存原来的慢启动阈值
	u32	high_seq;	/* snd_nxt at onset of congestion	*/					//进入拥塞控制状态后下一个待发送的序列号 ，会与是否完全被ack调比较

	u32	retrans_stamp;	/* Timestamp of the last retransmit,					//第一次重传的时间戳 ？ 超时重传中会使用这个时间
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* snd_una upon a new recovery episode. */			//记录的是序号，enterloss或者回复时候保存的una
	int	undo_retrans;	/* number of undoable retransmissions. */				//记录进入恢复阶段时的重传包数，用于判断是否真是丢包？？未确认重传包数量，在重传逻辑中被赋值
	u64	bytes_retrans;	/* RFC4898 tcpEStatsPerfOctetsRetrans					//重传skb字节书
				 * Total data bytes retransmitted
				 */
	u32	total_retrans;	/* Total retransmits for entire connection */				//总计重传数和上面的一样__tcp_retransmit_skb中++

	u32	urg_seq;	/* Seq of received urgent pointer */							//指向紧急数据的序列号
	unsigned int		keepalive_time;	  /* time before keep alive takes place */	//保活时间不活跃后多久探测一次
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */ //探测失败后多久在探测一次

	int			linger2;															//finwait2状态的保持时间


/* Sock_ops bpf program related variables */
#ifdef CONFIG_BPF
	u8	bpf_sock_ops_cb_flags;  /* Control calling BPF programs
					 * values defined in uapi/linux/tcp.h
					 */
	u8	bpf_chg_cc_inprogress:1; /* In the middle of
					  * bpf_setsockopt(TCP_CONGESTION),
					  * it is to avoid the bpf_tcp_cc->init()
					  * to recur itself by calling
					  * bpf_setsockopt(TCP_CONGESTION, "itself").
					  */
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) (TP->bpf_sock_ops_cb_flags & ARG)
#else
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) 0
#endif

	u16 timeout_rehash;	/* Timeout-triggered rehash attempts */					//超时处理中会重设hash值，表示重设hash值的次数

	u32 rcv_ooopack; /* Received out-of-order packets, for tcpinfo */          //乱续数据包总数

/* Receiver side RTT estimation */
	u32 rcv_rtt_last_tsecr;
	struct {
		u32	rtt_us;
		u32	seq;
		u64	time;
	} rcv_rtt_est;																//接收方的rtt,处理ack的时候会用到

/* Receiver queue space */
	struct {
		u32	space;
		u32	seq;
		u64	time;
	} rcvq_space;				//三次握手收到ack会设置

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;													//发送探测包的时候会设置
		u32		  probe_seq_end;
	} mtu_probe;																	//mtu探测的消息
	u32     plb_rehash;     /* PLB-triggered rehash attempts */						//拥塞算法会用到
	u32	mtu_info; /* We received an ICMP_FRAG_NEEDED / ICMPV6_PKT_TOOBIG			//没发现哪里会用到
			   * while socket was owned by user.
			   */
#if IS_ENABLED(CONFIG_MPTCP)
	bool	is_mptcp;
#endif
#if IS_ENABLED(CONFIG_SMC)
	bool	(*smc_hs_congested)(const struct sock *sk);
	bool	syn_smc;	/* SYN includes SMC */
#endif

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	__rcu *md5sig_info;
#endif

/* TCP fastopen related information */
	struct tcp_fastopen_request *fastopen_req;								//管理TFO的结构，sendmsgtfo会设置里面的字段
	/* fastopen_rsk points to request_sock that resulted in this big
	 * socket. Used to retransmit SYNACKs etc.
	 */
	struct request_sock __rcu *fastopen_rsk;								//requset sock
	struct saved_syn *saved_syn;											//服务端收到syn包时候保存的syn包信息
};

enum tsq_enum {
	TSQ_THROTTLED, //tcp push中会设置这个标志 smqcheck也会设置这个标志位
	TSQ_QUEUED,
	TCP_TSQ_DEFERRED,	   /* tcp_tasklet_func() found socket was owned */
	TCP_WRITE_TIMER_DEFERRED,  /* tcp_write_timer() found socket was owned */
	TCP_DELACK_TIMER_DEFERRED, /* tcp_delack_timer() found socket was owned */
	TCP_MTU_REDUCED_DEFERRED,  /* tcp_v{4|6}_err() could not call
				    * tcp_v{4|6}_mtu_reduced()
				    */
};

enum tsq_flags {
	TSQF_THROTTLED			= (1UL << TSQ_THROTTLED),
	TSQF_QUEUED			= (1UL << TSQ_QUEUED),
	TCPF_TSQ_DEFERRED		= (1UL << TCP_TSQ_DEFERRED),
	TCPF_WRITE_TIMER_DEFERRED	= (1UL << TCP_WRITE_TIMER_DEFERRED),
	TCPF_DELACK_TIMER_DEFERRED	= (1UL << TCP_DELACK_TIMER_DEFERRED),
	TCPF_MTU_REDUCED_DEFERRED	= (1UL << TCP_MTU_REDUCED_DEFERRED),
};

#define tcp_sk(ptr) container_of_const(ptr, struct tcp_sock, inet_conn.icsk_inet.sk)

/* Variant of tcp_sk() upgrading a const sock to a read/write tcp socket.
 * Used in context of (lockless) tcp listeners.
 */
#define tcp_sk_rw(ptr) container_of(ptr, struct tcp_sock, inet_conn.icsk_inet.sk)

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
#define tw_rcv_nxt tw_sk.__tw_common.skc_tw_rcv_nxt
#define tw_snd_nxt tw_sk.__tw_common.skc_tw_snd_nxt
	u32			  tw_rcv_wnd;
	u32			  tw_ts_offset;
	u32			  tw_ts_recent;

	/* The time we sent the last out-of-window ACK: */
	u32			  tw_last_oow_ack_time;

	int			  tw_ts_recent_stamp;
	u32			  tw_tx_delay;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key	  *tw_md5_key;
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

static inline bool tcp_passive_fastopen(const struct sock *sk)
{
	return sk->sk_state == TCP_SYN_RECV &&
	       rcu_access_pointer(tcp_sk(sk)->fastopen_rsk) != NULL;
}

static inline void fastopen_queue_tune(struct sock *sk, int backlog)
{
	struct request_sock_queue *queue = &inet_csk(sk)->icsk_accept_queue;
	int somaxconn = READ_ONCE(sock_net(sk)->core.sysctl_somaxconn);

	WRITE_ONCE(queue->fastopenq.max_qlen, min_t(unsigned int, backlog, somaxconn));
}

static inline void tcp_move_syn(struct tcp_sock *tp,
				struct request_sock *req)
{
	tp->saved_syn = req->saved_syn;
	req->saved_syn = NULL;
}

static inline void tcp_saved_syn_free(struct tcp_sock *tp)
{
	kfree(tp->saved_syn);
	tp->saved_syn = NULL;
}

static inline u32 tcp_saved_syn_len(const struct saved_syn *saved_syn)
{
	return saved_syn->mac_hdrlen + saved_syn->network_hdrlen +
		saved_syn->tcp_hdrlen;
}

struct sk_buff *tcp_get_timestamping_opt_stats(const struct sock *sk,
					       const struct sk_buff *orig_skb,
					       const struct sk_buff *ack_skb);

static inline u16 tcp_mss_clamp(const struct tcp_sock *tp, u16 mss)
{
	/* We use READ_ONCE() here because socket might not be locked.
	 * This happens for listeners.
	 */
	u16 user_mss = READ_ONCE(tp->rx_opt.user_mss);

	return (user_mss && user_mss < mss) ? user_mss : mss;
}

int tcp_skb_shift(struct sk_buff *to, struct sk_buff *from, int pcount,
		  int shiftlen);

void __tcp_sock_set_cork(struct sock *sk, bool on);
void tcp_sock_set_cork(struct sock *sk, bool on);
int tcp_sock_set_keepcnt(struct sock *sk, int val);
int tcp_sock_set_keepidle_locked(struct sock *sk, int val);
int tcp_sock_set_keepidle(struct sock *sk, int val);
int tcp_sock_set_keepintvl(struct sock *sk, int val);
void __tcp_sock_set_nodelay(struct sock *sk, bool on);
void tcp_sock_set_nodelay(struct sock *sk);
void tcp_sock_set_quickack(struct sock *sk, int val);
int tcp_sock_set_syncnt(struct sock *sk, int val);
int tcp_sock_set_user_timeout(struct sock *sk, int val);

#endif	/* _LINUX_TCP_H */
