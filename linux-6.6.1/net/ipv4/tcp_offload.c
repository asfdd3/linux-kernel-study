// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	IPV4 GSO/GRO offload support
 *	Linux INET implementation
 *
 *	TCPv4 GSO/GRO support
 */

#include <linux/indirect_call_wrapper.h>
#include <linux/skbuff.h>
#include <net/gro.h>
#include <net/gso.h>
#include <net/tcp.h>
#include <net/protocol.h>

static void tcp_gso_tstamp(struct sk_buff *skb, unsigned int ts_seq,
			   unsigned int seq, unsigned int mss)
{
	while (skb) {
		if (before(ts_seq, seq + mss)) {
			skb_shinfo(skb)->tx_flags |= SKBTX_SW_TSTAMP;
			skb_shinfo(skb)->tskey = ts_seq;
			return;
		}

		skb = skb->next;
		seq += mss;
	}
}

static struct sk_buff *tcp4_gso_segment(struct sk_buff *skb,
					netdev_features_t features)
{
	if (!(skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4))
		return ERR_PTR(-EINVAL);

	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
		return ERR_PTR(-EINVAL);

	if (unlikely(skb->ip_summed != CHECKSUM_PARTIAL)) {
		const struct iphdr *iph = ip_hdr(skb);
		struct tcphdr *th = tcp_hdr(skb);

		/* Set up checksum pseudo header, usually expect stack to
		 * have done this already.
		 */

		th->check = 0;
		skb->ip_summed = CHECKSUM_PARTIAL;
		__tcp_v4_send_check(skb, iph->saddr, iph->daddr);
	}

	return tcp_gso_segment(skb, features);
}

struct sk_buff *tcp_gso_segment(struct sk_buff *skb,
				netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	unsigned int sum_truesize = 0;
	struct tcphdr *th;
	unsigned int thlen;
	unsigned int seq;
	unsigned int oldlen;
	unsigned int mss;
	struct sk_buff *gso_skb = skb;
	__sum16 newcheck;
	bool ooo_okay, copy_destructor;
	__wsum delta;

	th = tcp_hdr(skb);
	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	if (!pskb_may_pull(skb, thlen))
		goto out;

	oldlen = ~skb->len;
	__skb_pull(skb, thlen);

	mss = skb_shinfo(skb)->gso_size;
	if (unlikely(skb->len <= mss))
		goto out;

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		/* Packet is from an untrusted source, reset gso_segs. */

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss);

		segs = NULL;
		goto out;
	}

	copy_destructor = gso_skb->destructor == tcp_wfree;
	ooo_okay = gso_skb->ooo_okay;
	/* All segments but the first should have ooo_okay cleared */
	skb->ooo_okay = 0;

	segs = skb_segment(skb, features);
	if (IS_ERR(segs))
		goto out;

	/* Only first segment might have ooo_okay set */
	segs->ooo_okay = ooo_okay;

	/* GSO partial and frag_list segmentation only requires splitting
	 * the frame into an MSS multiple and possibly a remainder, both
	 * cases return a GSO skb. So update the mss now.
	 */
	if (skb_is_gso(segs))
		mss *= skb_shinfo(segs)->gso_segs;

	delta = (__force __wsum)htonl(oldlen + thlen + mss);

	skb = segs;
	th = tcp_hdr(skb);
	seq = ntohl(th->seq);

	if (unlikely(skb_shinfo(gso_skb)->tx_flags & SKBTX_SW_TSTAMP))
		tcp_gso_tstamp(segs, skb_shinfo(gso_skb)->tskey, seq, mss);

	newcheck = ~csum_fold(csum_add(csum_unfold(th->check), delta));

	while (skb->next) {
		th->fin = th->psh = 0;
		th->check = newcheck;

		if (skb->ip_summed == CHECKSUM_PARTIAL)
			gso_reset_checksum(skb, ~th->check);
		else
			th->check = gso_make_checksum(skb, ~th->check);

		seq += mss;
		if (copy_destructor) {
			skb->destructor = gso_skb->destructor;
			skb->sk = gso_skb->sk;
			sum_truesize += skb->truesize;
		}
		skb = skb->next;
		th = tcp_hdr(skb);

		th->seq = htonl(seq);
		th->cwr = 0;
	}

	/* Following permits TCP Small Queues to work well with GSO :
	 * The callback to TCP stack will be called at the time last frag
	 * is freed at TX completion, and not right now when gso_skb
	 * is freed by GSO engine
	 */
	if (copy_destructor) {
		int delta;

		swap(gso_skb->sk, skb->sk);
		swap(gso_skb->destructor, skb->destructor);
		sum_truesize += skb->truesize;
		delta = sum_truesize - gso_skb->truesize;
		/* In some pathological cases, delta can be negative.
		 * We need to either use refcount_add() or refcount_sub_and_test()
		 */
		if (likely(delta >= 0))
			refcount_add(delta, &skb->sk->sk_wmem_alloc);
		else
			WARN_ON_ONCE(refcount_sub_and_test(-delta, &skb->sk->sk_wmem_alloc));
	}

	delta = (__force __wsum)htonl(oldlen +
				      (skb_tail_pointer(skb) -
				       skb_transport_header(skb)) +
				      skb->data_len);
	th->check = ~csum_fold(csum_add(csum_unfold(th->check), delta));
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		gso_reset_checksum(skb, ~th->check);
	else
		th->check = gso_make_checksum(skb, ~th->check);
out:
	return segs;
}

struct sk_buff *tcp_gro_receive(struct list_head *head, struct sk_buff *skb)
{
	struct sk_buff *pp = NULL;
	struct sk_buff *p;
	struct tcphdr *th;
	struct tcphdr *th2;
	unsigned int len;
	unsigned int thlen;
	__be32 flags;
	unsigned int mss = 1;
	unsigned int hlen;
	unsigned int off;
	int flush = 1;
	int i;
	//拿到tcp头
	off = skb_gro_offset(skb);
	hlen = off + sizeof(*th);
	th = skb_gro_header(skb, hlen, off);
	if (unlikely(!th))
		goto out;
	//检查头部长度
	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	hlen = off + thlen;
	if (skb_gro_header_hard(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}
	//把tcp头拉掉
	skb_gro_pull(skb, thlen);
	//payload的长度
	len = skb_gro_len(skb);
	flags = tcp_flag_word(th);

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)//不是同一条流就直接过
			continue;

		th2 = tcp_hdr(p);
		//端口是否一致
		if (*(u32 *)&th->source ^ *(u32 *)&th2->source) {
			NAPI_GRO_CB(p)->same_flow = 0;//不一致直接 = 0
			continue;
		}

		goto found;
	}
	p = NULL;
	goto out_check_final;

found:
	/* Include the IP ID check below from the inner most IP hdr */
	//不能有cwr  tcp标志必须一致，ack序号必须一致
	//tcp选项也必须一致
	flush = NAPI_GRO_CB(p)->flush;
	flush |= (__force int)(flags & TCP_FLAG_CWR);
	flush |= (__force int)((flags ^ tcp_flag_word(th2)) &
		  ~(TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH));
	flush |= (__force int)(th->ack_seq ^ th2->ack_seq);
	//这里比较选项，注意时间戳
	for (i = sizeof(*th); i < thlen; i += 4)
		flush |= *(u32 *)((u8 *)th + i) ^
			 *(u32 *)((u8 *)th2 + i);

	/* When we receive our second frame we can made a decision on if we
	 * continue this flow as an atomic flow with a fixed ID or if we use
	 * an incrementing ID.
	 */
	//IP ID 相关检查 //这里第二个包走上面的分支吧
	if (NAPI_GRO_CB(p)->flush_id != 1 ||
	    NAPI_GRO_CB(p)->count != 1 ||  
	    !NAPI_GRO_CB(p)->is_atomic)
		flush |= NAPI_GRO_CB(p)->flush_id;
	// NAPI_GRO_CB(p)->flush_id == 1
	// NAPI_GRO_CB(p)->count == 1
	// NAPI_GRO_CB(p)->is_atomic == true 的情况
	else
		NAPI_GRO_CB(p)->is_atomic = false;
	
	mss = skb_shinfo(p)->gso_size;//注意这里的的gso_size是上设置的

	/* If skb is a GRO packet, make sure its gso_size matches prior packet mss.
	 * If it is a single frame, do not aggregate it if its length
	 * is bigger than our mss.
	 */
	if (unlikely(skb_is_gso(skb)))
		flush |= (mss != skb_shinfo(skb)->gso_size); 
	else
		flush |= (len - 1) >= mss;//是不是GRO中已经合并的包要大？
	//序列号是不是完全符合预期
	flush |= (ntohl(th2->seq) + skb_gro_len(p)) ^ ntohl(th->seq);
#ifdef CONFIG_TLS_DEVICE
	flush |= p->decrypted ^ skb->decrypted;
#endif
	//真正的合并
	if (flush || skb_gro_receive(p, skb)) {
		mss = 1;
		goto out_check_final;
	}

	tcp_flag_word(th2) |= flags & (TCP_FLAG_FIN | TCP_FLAG_PSH);

out_check_final:
	/* Force a flush if last segment is smaller than mss. */
	//这里几乎不可能吧
	if (unlikely(skb_is_gso(skb)))
		flush = len != NAPI_GRO_CB(skb)->count * skb_shinfo(skb)->gso_size;
	else
		flush = len < mss;//如果小于了mss 可能是最后一个段要flush ，合理
	//如果新包有这些标志也强制flush
	flush |= (__force int)(flags & (TCP_FLAG_URG | TCP_FLAG_PSH |
					TCP_FLAG_RST | TCP_FLAG_SYN | //注意这里可能是直接跳转过来的
					TCP_FLAG_FIN));
	//如果找到了候选旧包 p，并且现在满足下面任意一个条件，旧把旧包反出去
	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush))
		pp = p;

out:
	NAPI_GRO_CB(skb)->flush |= (flush != 0);

	return pp;
}

void tcp_gro_complete(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	//重建 TCP checksum 语义
	skb->csum_start = (unsigned char *)th - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;
	//设置段数
	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;
	//cwr处理
	if (th->cwr)
		skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;

	if (skb->encapsulation)
		skb->inner_transport_header = skb->transport_header;
}
EXPORT_SYMBOL(tcp_gro_complete);

INDIRECT_CALLABLE_SCOPE
struct sk_buff *tcp4_gro_receive(struct list_head *head, struct sk_buff *skb)
{
	/* Don't bother verifying checksum if we're going to flush anyway. */
	//如果flush 等于 0 则计算校验和，也就是说大概率在这里计算校验和
	if (!NAPI_GRO_CB(skb)->flush &&
	    skb_gro_checksum_validate(skb, IPPROTO_TCP,
				      inet_gro_compute_pseudo)) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	return tcp_gro_receive(head, skb);
}

INDIRECT_CALLABLE_SCOPE int tcp4_gro_complete(struct sk_buff *skb, int thoff)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	//重新设置校验和
	th->check = ~tcp_v4_check(skb->len - thoff, iph->saddr,
				  iph->daddr, 0);
	//标记是一个GSO报文
	skb_shinfo(skb)->gso_type |= SKB_GSO_TCPV4;

	if (NAPI_GRO_CB(skb)->is_atomic)
		skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_FIXEDID;

	tcp_gro_complete(skb);
	return 0;
}

static const struct net_offload tcpv4_offload = {
	.callbacks = {
		.gso_segment	=	tcp4_gso_segment,
		.gro_receive	=	tcp4_gro_receive,
		.gro_complete	=	tcp4_gro_complete,
	},
};

int __init tcpv4_offload_init(void)
{
	return inet_add_offload(&tcpv4_offload, IPPROTO_TCP);
}
