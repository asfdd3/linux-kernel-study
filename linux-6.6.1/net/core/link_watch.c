// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux network device link state notification
 *
 * Author:
 *     Stefan Rompf <sux@loplof.de>
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <net/sock.h>
#include <net/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/bitops.h>
#include <linux/types.h>

#include "dev.h"

enum lw_bits {
	LW_URGENT = 0,
};

static unsigned long linkwatch_flags;
static unsigned long linkwatch_nextevent;

static void linkwatch_event(struct work_struct *dummy);
static DECLARE_DELAYED_WORK(linkwatch_work, linkwatch_event);

static LIST_HEAD(lweventlist);
static DEFINE_SPINLOCK(lweventlist_lock);

static unsigned char default_operstate(const struct net_device *dev)
{
	//testing 直接返回
	if (netif_testing(dev))
		return IF_OPER_TESTING;

	/* Some uppers (DSA) have additional sources for being down, so
	 * first check whether lower is indeed the source of its down state.
	 */
	//没有link的情况
	if (!netif_carrier_ok(dev)) {
		//通常返回if index
		int iflink = dev_get_iflink(dev);
		struct net_device *peer;
		//直接返回
		if (iflink == dev->ifindex)
			return IF_OPER_DOWN;

		peer = __dev_get_by_index(dev_net(dev), iflink);
		if (!peer)
			return IF_OPER_DOWN;

		return netif_carrier_ok(peer) ? IF_OPER_DOWN :
						IF_OPER_LOWERLAYERDOWN;
	}
	//link up的情况 802.1x
	if (netif_dormant(dev))
		return IF_OPER_DORMANT;
	//正常可用的
	return IF_OPER_UP;
}


static void rfc2863_policy(struct net_device *dev)
{
	//根据当前设备的状态设置一个默认的运行状态
	unsigned char operstate = default_operstate(dev);
	//状态没改变，直接返回
	if (operstate == dev->operstate)
		return;

	write_lock(&dev_base_lock);
	//根据link_mode 修改状态，注意这是用户设置的
	switch(dev->link_mode) {
	case IF_LINK_MODE_TESTING:
		if (operstate == IF_OPER_UP)
			operstate = IF_OPER_TESTING;
		break;

	case IF_LINK_MODE_DORMANT:
		if (operstate == IF_OPER_UP)
			operstate = IF_OPER_DORMANT;
		break;
	case IF_LINK_MODE_DEFAULT:
	default:
		break;
	}
	//重新设置
	dev->operstate = operstate;

	write_unlock(&dev_base_lock);
}


void linkwatch_init_dev(struct net_device *dev)
{
	/* Handle pre-registration link state changes */
	//如果当前还没有link up
	if (!netif_carrier_ok(dev) || netif_dormant(dev) ||
	//设备正在处于testing状态
	    netif_testing(dev))
		rfc2863_policy(dev);//满足三个条件之一就调用
}


static bool linkwatch_urgent_event(struct net_device *dev)
{
	//没逻辑up
	if (!netif_running(dev))
		return false;
	//依赖另一个设备
	if (dev->ifindex != dev_get_iflink(dev))
		return true;
	//LAG相关设备
	if (netif_is_lag_port(dev) || netif_is_lag_master(dev))
		return true;
	//qdsc 正在变化
	return netif_carrier_ok(dev) &&	qdisc_tx_changing(dev);
}


static void linkwatch_add_event(struct net_device *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&lweventlist_lock, flags);
	if (list_empty(&dev->link_watch_list)) {
		list_add_tail(&dev->link_watch_list, &lweventlist);
		netdev_hold(dev, &dev->linkwatch_dev_tracker, GFP_ATOMIC);
	}
	spin_unlock_irqrestore(&lweventlist_lock, flags);
}


static void linkwatch_schedule_work(int urgent)
{
	unsigned long delay = linkwatch_nextevent - jiffies;

	if (test_bit(LW_URGENT, &linkwatch_flags))
		return;

	/* Minimise down-time: drop delay for up event. */
	if (urgent) {
		if (test_and_set_bit(LW_URGENT, &linkwatch_flags))
			return;
		delay = 0;
	}

	/* If we wrap around we'll delay it by at most HZ. */
	if (delay > HZ)
		delay = 0;

	/*
	 * If urgent, schedule immediate execution; otherwise, don't
	 * override the existing timer.
	 */
	if (test_bit(LW_URGENT, &linkwatch_flags))
		mod_delayed_work(system_wq, &linkwatch_work, 0);
	else
		schedule_delayed_work(&linkwatch_work, delay);
}


static void linkwatch_do_dev(struct net_device *dev)
{
	/*
	 * Make sure the above read is complete since it can be
	 * rewritten as soon as we clear the bit below.
	 */
	smp_mb__before_atomic();

	/* We are about to handle this device,
	 * so new events can be accepted
	 */
	//清除pending位
	clear_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state);
	//更新 operstate 也就是用户看到的是否up
	rfc2863_policy(dev);
	//设备逻辑上up了
	if (dev->flags & IFF_UP) {
		//link up
		if (netif_carrier_ok(dev))
			dev_activate(dev);//激活发送队列
		else
			dev_deactivate(dev);//这里把tc队列 替换成noop 所以发包都被noop丢弃了(如果是link down的话)
		//关键！ 这里是 netdev  的 change的的通知链 
		//因为change表示link up link down
		netdev_state_change(dev);
	}
	/* Note: our callers are responsible for calling netdev_tracker_free().
	 * This is the reason we use __dev_put() instead of dev_put().
	 */
	__dev_put(dev);
}

static void __linkwatch_run_queue(int urgent_only)
{
#define MAX_DO_DEV_PER_LOOP	100
	//一次最多处理多少个设备
	int do_dev = MAX_DO_DEV_PER_LOOP;
	struct net_device *dev;
	LIST_HEAD(wrk);

	/* Give urgent case more budget */
	//紧急的话变成200个
	if (urgent_only)
		do_dev += MAX_DO_DEV_PER_LOOP;

	/*
	 * Limit the number of linkwatch events to one
	 * per second so that a runaway driver does not
	 * cause a storm of messages on the netlink
	 * socket.  This limit does not apply to up events
	 * while the device qdisc is down.
	 */
	//下次linkwatch事件在1s后
	if (!urgent_only)
		linkwatch_nextevent = jiffies + HZ;
	/* Limit wrap-around effect on delay. */
	else if (time_after(linkwatch_nextevent, jiffies + HZ))
		linkwatch_nextevent = jiffies;

	clear_bit(LW_URGENT, &linkwatch_flags);

	spin_lock_irq(&lweventlist_lock);
	//把全局 lweventlist 里的所有事件一次性搬到本地 wrk
	list_splice_init(&lweventlist, &wrk);
	//循环处理每个设备
	while (!list_empty(&wrk) && do_dev > 0) {

		dev = list_first_entry(&wrk, struct net_device, link_watch_list);
		list_del_init(&dev->link_watch_list);
		//跳过不需要处理的设备
		if (!netif_device_present(dev) ||
		    (urgent_only && !linkwatch_urgent_event(dev))) {
			list_add_tail(&dev->link_watch_list, &lweventlist);
			continue;
		}
		/* We must free netdev tracker under
		 * the spinlock protection.
		 */
		netdev_tracker_free(dev, &dev->linkwatch_dev_tracker);
		spin_unlock_irq(&lweventlist_lock);
		linkwatch_do_dev(dev); //真正的核心
		do_dev--;
		spin_lock_irq(&lweventlist_lock);
	}

	/* Add the remaining work back to lweventlist */
	//在重新挂回去
	list_splice_init(&wrk, &lweventlist);
	//如果没空，继续调度
	if (!list_empty(&lweventlist))
		linkwatch_schedule_work(0);
	spin_unlock_irq(&lweventlist_lock);
}

void linkwatch_forget_dev(struct net_device *dev)
{
	unsigned long flags;
	int clean = 0;

	spin_lock_irqsave(&lweventlist_lock, flags);
	if (!list_empty(&dev->link_watch_list)) {
		list_del_init(&dev->link_watch_list);
		clean = 1;
		/* We must release netdev tracker under
		 * the spinlock protection.
		 */
		netdev_tracker_free(dev, &dev->linkwatch_dev_tracker);
	}
	spin_unlock_irqrestore(&lweventlist_lock, flags);
	if (clean)
		linkwatch_do_dev(dev);
}


/* Must be called with the rtnl semaphore held */
void linkwatch_run_queue(void)
{
	__linkwatch_run_queue(0);
}


static void linkwatch_event(struct work_struct *dummy)
{
	rtnl_lock();
	__linkwatch_run_queue(time_after(linkwatch_nextevent, jiffies));
	rtnl_unlock();
}


void linkwatch_fire_event(struct net_device *dev)
{
	//判断是不是紧急事件
	bool urgent = linkwatch_urgent_event(dev);
	//是否已经有 pending 的 linkwatch 事件
	if (!test_and_set_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state)) {
		linkwatch_add_event(dev); //加入linkwatch事件队列，其实就是挂到链表中
	} else if (!urgent) //已经pending了 但是不紧急，直接返回
		return;
	//紧急的 已经pending 那就重新调度
	//其实就是根据是否紧急，决定什么时候调度linkwatch_event
	linkwatch_schedule_work(urgent);
}
EXPORT_SYMBOL(linkwatch_fire_event);
