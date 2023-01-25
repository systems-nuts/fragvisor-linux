/* Copyright (C) 2009 Red Hat, Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * virtio-net server in host kernel.
 */
#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uio.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/net.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/if_macvlan.h>
#include <linux/if_vlan.h>

#include <net/sock.h>

#include "vhost.h"

#ifdef CONFIG_POPCORN_HYPE
#define DEBUG
#include <popcorn/debug.h>
#include <popcorn/hype_kvm.h>
#endif

#ifdef CONFIG_POPCORN_HYPE
static size_t khype_peek_head_len(struct vhost_net *net);
static void __khype_send_rx_notification(struct vhost_net *);
static int khype_tun_sendmsg(struct vhost_net *net, struct msghdr *msg);
static int khype_tun_recvmsg(struct vhost_net *net, struct msghdr *msg, size_t sock_len,  int flags);
extern void khype_send_rx_notification(rx_notification_request_t *req);
extern size_t khype_peek_head_len_request(int vhost);
extern int khype_recvmsg_delegate(delegate_recvmsg_request_t *, struct msghdr *);
extern int khype_tunfd_delegate(delegate_tunfd_request_t *req);
#endif

static int experimental_zcopytx = 1;
module_param(experimental_zcopytx, int, 0444);
MODULE_PARM_DESC(experimental_zcopytx, "Enable Zero Copy TX;"
		                       " 1 -Enable; 0 - Disable");

#define handle_tx 	vhost_handle_tx
#define handle_rx 	vhost_handle_rx

/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define VHOST_NET_WEIGHT 0x80000

/* MAX number of TX used buffers for outstanding zerocopy */
#define VHOST_MAX_PEND 128
#define VHOST_GOODCOPY_LEN 256

/*
 * For transmit, used buffer len is unused; we override it to track buffer
 * status internally; used for zerocopy tx only.
 */
/* Lower device DMA failed */
#define VHOST_DMA_FAILED_LEN	((__force __virtio32)3)
/* Lower device DMA done */
#define VHOST_DMA_DONE_LEN	((__force __virtio32)2)
/* Lower device DMA in progress */
#define VHOST_DMA_IN_PROGRESS	((__force __virtio32)1)
/* Buffer unused */
#define VHOST_DMA_CLEAR_LEN	((__force __virtio32)0)

#define VHOST_DMA_IS_DONE(len) ((__force u32)(len) >= (__force u32)VHOST_DMA_DONE_LEN)

enum {
	VHOST_NET_FEATURES = VHOST_FEATURES |
			 (1ULL << VHOST_NET_F_VIRTIO_NET_HDR) |
			 (1ULL << VIRTIO_NET_F_MRG_RXBUF)
};

enum {
	VHOST_NET_VQ_RX = 0,
	VHOST_NET_VQ_TX = 1,
	VHOST_NET_VQ_MAX = 2,
};

struct vhost_net_ubuf_ref {
	/* refcount follows semantics similar to kref:
	 *  0: object is released
	 *  1: no outstanding ubufs
	 * >1: outstanding ubufs
	 */
	atomic_t refcount;
	wait_queue_head_t wait;
	struct vhost_virtqueue *vq;
};

struct vhost_net_virtqueue {
	struct vhost_virtqueue vq;
	size_t vhost_hlen;
	size_t sock_hlen;
	/* vhost zerocopy support fields below: */
	/* last used idx for outstanding DMA zerocopy buffers */
	int upend_idx;
	/* first used idx for DMA done zerocopy buffers */
	int done_idx;
	/* an array of userspace buffers info */
	struct ubuf_info *ubuf_info;
	/* Reference counting for outstanding ubufs.
	 * Protected by vq mutex. Writers must also take device mutex. */
	struct vhost_net_ubuf_ref *ubufs;
};

struct vhost_net {
	struct vhost_dev dev;
	struct vhost_net_virtqueue vqs[VHOST_NET_VQ_MAX];
	struct vhost_poll poll[VHOST_NET_VQ_MAX];
	/* Number of TX recently submitted.
	 * Protected by tx vq lock. */
	unsigned tx_packets;
	/* Number of times zerocopy TX recently failed.
	 * Protected by tx vq lock. */
	unsigned tx_zcopy_err;
	/* Flush in progress. Protected by tx vq lock. */
	bool tx_flush;
#ifdef CONFIG_POPCORN_HYPE
	/* index in __hype_vhosts */
	int __hype_vhost;
#endif
};

static unsigned vhost_net_zcopy_mask __read_mostly;

static void vhost_net_enable_zcopy(int vq)
{
	vhost_net_zcopy_mask |= 0x1 << vq;
	VHOSTPK("enabling zc for vq=%d, nid=%d\n", vq, my_nid);
}

static struct vhost_net_ubuf_ref *
vhost_net_ubuf_alloc(struct vhost_virtqueue *vq, bool zcopy)
{
	struct vhost_net_ubuf_ref *ubufs;
	/* No zero copy backend? Nothing to count. */
	if (!zcopy)
		return NULL;
	ubufs = kmalloc(sizeof(*ubufs), GFP_KERNEL);
	if (!ubufs)
		return ERR_PTR(-ENOMEM);
	atomic_set(&ubufs->refcount, 1);
	init_waitqueue_head(&ubufs->wait);
	ubufs->vq = vq;
	return ubufs;
}

static int vhost_net_ubuf_put(struct vhost_net_ubuf_ref *ubufs)
{
	int r = atomic_sub_return(1, &ubufs->refcount);
	if (unlikely(!r))
		wake_up(&ubufs->wait);
	return r;
}

static void vhost_net_ubuf_put_and_wait(struct vhost_net_ubuf_ref *ubufs)
{
	vhost_net_ubuf_put(ubufs);
	wait_event(ubufs->wait, !atomic_read(&ubufs->refcount));
}

static void vhost_net_ubuf_put_wait_and_free(struct vhost_net_ubuf_ref *ubufs)
{
	vhost_net_ubuf_put_and_wait(ubufs);
	kfree(ubufs);
}

static void vhost_net_clear_ubuf_info(struct vhost_net *n)
{
	int i;

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		kfree(n->vqs[i].ubuf_info);
		n->vqs[i].ubuf_info = NULL;
	}
}

static int vhost_net_set_ubuf_info(struct vhost_net *n)
{
	bool zcopy;
	int i;

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		zcopy = vhost_net_zcopy_mask & (0x1 << i);
		if (!zcopy)
			continue;
		n->vqs[i].ubuf_info = kmalloc(sizeof(*n->vqs[i].ubuf_info) *
					      UIO_MAXIOV, GFP_KERNEL);
		if  (!n->vqs[i].ubuf_info)
			goto err;
	}
	return 0;

err:
	vhost_net_clear_ubuf_info(n);
	return -ENOMEM;
}

static void vhost_net_vq_reset(struct vhost_net *n)
{
	int i;

	vhost_net_clear_ubuf_info(n);

	for (i = 0; i < VHOST_NET_VQ_MAX; i++) {
		n->vqs[i].done_idx = 0;
		n->vqs[i].upend_idx = 0;
		n->vqs[i].ubufs = NULL;
		n->vqs[i].vhost_hlen = 0;
		n->vqs[i].sock_hlen = 0;
	}

}

static void vhost_net_tx_packet(struct vhost_net *net)
{
	++net->tx_packets;
	if (net->tx_packets < 1024)
		return;
	net->tx_packets = 0;
	net->tx_zcopy_err = 0;
}

static void vhost_net_tx_err(struct vhost_net *net)
{
	++net->tx_zcopy_err;
}

static bool vhost_net_tx_select_zcopy(struct vhost_net *net)
{
	/* TX flush waits for outstanding DMAs to be done.
	 * Don't start new DMAs.
	 */
	return !net->tx_flush &&
		net->tx_packets / 64 >= net->tx_zcopy_err;
}

static bool vhost_sock_zcopy(struct socket *sock)
{
	return unlikely(experimental_zcopytx) &&
		sock_flag(sock->sk, SOCK_ZEROCOPY);
}

/* In case of DMA done not in order in lower device driver for some reason.
 * upend_idx is used to track end of used idx, done_idx is used to track head
 * of used idx. Once lower device DMA done contiguously, we will signal KVM
 * guest used idx.
 */
static void vhost_zerocopy_signal_used(struct vhost_net *net,
				       struct vhost_virtqueue *vq)
{
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);
	int i, add;
	int j = 0;

	for (i = nvq->done_idx; i != nvq->upend_idx; i = (i + 1) % UIO_MAXIOV) {
		if (vq->heads[i].len == VHOST_DMA_FAILED_LEN)
			vhost_net_tx_err(net);
		if (VHOST_DMA_IS_DONE(vq->heads[i].len)) {
			vq->heads[i].len = VHOST_DMA_CLEAR_LEN;
			++j;
		} else
			break;
	}
	while (j) {
		add = min(UIO_MAXIOV - nvq->done_idx, j);
		vhost_add_used_and_signal_n(vq->dev, vq,
					    &vq->heads[nvq->done_idx], add);
		nvq->done_idx = (nvq->done_idx + add) % UIO_MAXIOV;
		j -= add;
	}
}

static void vhost_zerocopy_callback(struct ubuf_info *ubuf, bool success)
{
	struct vhost_net_ubuf_ref *ubufs = ubuf->ctx;
	struct vhost_virtqueue *vq = ubufs->vq;
	int cnt;

	rcu_read_lock_bh();

	/* set len to mark this desc buffers done DMA */
	vq->heads[ubuf->desc].len = success ?
		VHOST_DMA_DONE_LEN : VHOST_DMA_FAILED_LEN;
	cnt = vhost_net_ubuf_put(ubufs);

	/*
	 * Trigger polling thread if guest stopped submitting new buffers:
	 * in this case, the refcount after decrement will eventually reach 1.
	 * We also trigger polling periodically after each 16 packets
	 * (the value 16 here is more or less arbitrary, it's tuned to trigger
	 * less than 10% of times).
	 */
	if (cnt <= 1 || !(cnt % 16))
		vhost_poll_queue(&vq->poll);

	rcu_read_unlock_bh();
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
void vhost_handle_tx(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct vhost_virtqueue *vq = &nvq->vq;
	unsigned out, in;
	int head;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	size_t len, total_len = 0;
	int err;
	size_t hdr_size;
	struct socket *sock;
	struct vhost_net_ubuf_ref *uninitialized_var(ubufs);
	bool zcopy, zcopy_used;

#ifdef CONFIG_POPCORN_HYPE
	CRITICALNETPK("\tpophype: vhost-net: %s: %s():\n", __FILE__, __func__);
#endif
#if POPHYPE_NET_OPTIMIZE
    {
        static u64 cnt = 0;
        cnt++;
        if ((cnt > 70 && cnt < 100) || !(cnt % 1000)) {
            POP_PK("\tpophype: vhost-net: opti: vanilla: <%d> %s: %s(): "
				"(vhost_net)net %p (vhost_dev)&net->dev %p "
				"(vhost_virtqueue)(&nvq(&net->vqs[VHOST_NET_VQ_TX])->vq)vq %p "
				"#%llu\n",
				smp_processor_id(), __FILE__, __func__,
				net, &net->dev, vq, cnt);
        }
    }
#endif

	mutex_lock(&vq->mutex);
	sock = vq->private_data;
	if (!sock)
		goto out;

	vhost_disable_notify(&net->dev, vq);

	hdr_size = nvq->vhost_hlen;
	zcopy = nvq->ubufs;

	for (;;) {
		/* Release DMAs done buffers first */
		if (zcopy)
			vhost_zerocopy_signal_used(net, vq);

		/* If more outstanding DMAs, queue the work.
		 * Handle upend_idx wrap around
		 */
		if (unlikely((nvq->upend_idx + vq->num - VHOST_MAX_PEND)
			      % UIO_MAXIOV == nvq->done_idx))
			break;

#if POPHYPE_NET_OPTIMIZE
		/* Our delegation optmization doesn't need to do this, going through vq */
#endif
		head = vhost_get_vq_desc(vq, vq->iov,
					 ARRAY_SIZE(vq->iov),
					 &out, &in,
					 NULL, NULL);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&net->dev, vq))) {
				vhost_disable_notify(&net->dev, vq);
				continue;
			}
			break;
		}
		if (in) {
			vq_err(vq, "Unexpected descriptor format for TX: "
			       "out %d, int %d\n", out, in);
			break;
		}
		/* Skip header. TODO: support TSO. */
		len = iov_length(vq->iov, out);
		iov_iter_init(&msg.msg_iter, WRITE, vq->iov, out, len);
		iov_iter_advance(&msg.msg_iter, hdr_size);
		/* Sanity check */
		if (!msg_data_left(&msg)) {
			vq_err(vq, "Unexpected header len for TX: "
			       "%zd expected %zd\n",
			       len, hdr_size);
			break;
		}
		len = msg_data_left(&msg);

		zcopy_used = zcopy && len >= VHOST_GOODCOPY_LEN
				   && (nvq->upend_idx + 1) % UIO_MAXIOV !=
				      nvq->done_idx
				   && vhost_net_tx_select_zcopy(net);
#if POPHYPE_NET_OPTIMIZE
		{
			// TODO !len is worng I think
			static u64 cnt = 0;
			cnt++;
			if ((cnt > 70 && cnt < 100) || !(cnt % 1000)) {
				POP_PK("\t(kernel) pophype: vhost-net: opti: vanilla: <%d> %s: %s(): "
					 "zcopy_used %d (0) vq->iov %p len %lu (nr_segs) out %d in %d "
					"[sock %p] hdr_size(nvq->vhost_hlen) %d #%llu\n",
					smp_processor_id(), __FILE__, __func__,
					zcopy_used, vq->iov, len, out, in, sock, hdr_size, cnt);
				/* zcopy_used 1 when len is large like XXX to xxxx */
			}
			// 09/25 debug
			if (len == 233) {
				POP_PK("\n\n\n\t\t%s(): === THERE IS STILL A HOPE ===\n\n\n\n", __func__);
			}
		}
#endif

		/* use msg_control to pass vhost zerocopy ubuf info to skb */
		if (zcopy_used) {
			struct ubuf_info *ubuf;
			ubuf = nvq->ubuf_info + nvq->upend_idx;

			vq->heads[nvq->upend_idx].id = cpu_to_vhost32(vq, head);
			vq->heads[nvq->upend_idx].len = VHOST_DMA_IN_PROGRESS;
			ubuf->callback = vhost_zerocopy_callback;
			ubuf->ctx = nvq->ubufs;
			ubuf->desc = nvq->upend_idx;
			msg.msg_control = ubuf;
			msg.msg_controllen = sizeof(ubuf);
			ubufs = nvq->ubufs;
			atomic_inc(&ubufs->refcount);
			nvq->upend_idx = (nvq->upend_idx + 1) % UIO_MAXIOV;
		} else {
			msg.msg_control = NULL;
			ubufs = NULL;
		}
		/* TODO: Check specific error and bomb out unless ENOBUFS? */
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_ORIGIN_NODE
		VHOSTPKTX("->sendmsg: node=%d\n", my_nid);
		err = sock->ops->sendmsg(sock, &msg, len);
		VHOSTPKTX("handle_tx: sendmsg: err=%d\n", err);
#else
		VHOSTPKTX("khype_tun_sendmsg: nid=%d\n", my_nid);
		err = khype_tun_sendmsg(net, &msg);
		VHOSTPK("handle_tx: khype: err=%d\n", err);
#endif /* CONFIG_PCN_ORIGIN_NODE */
#else
		err = sock->ops->sendmsg(sock, &msg, len);
#endif /* CONFIG_POPCORN_HYPE */
		if (unlikely(err < 0)) {
			if (zcopy_used) {
				vhost_net_ubuf_put(ubufs);
				nvq->upend_idx = ((unsigned)nvq->upend_idx - 1)
					% UIO_MAXIOV;
			}
			vhost_discard_vq_desc(vq, 1);
			break;
		}
		if (err != len)
			pr_debug("Truncated TX packet: "
				 " len %d != %zd\n", err, len);
		if (!zcopy_used) {
#if POPHYPE_NET_OPTIMIZE
			/* update virtqueue used ring (e.g. used_elem, last_used_idx) */
#endif
			vhost_add_used_and_signal(&net->dev, vq, head, 0);
		} else
			vhost_zerocopy_signal_used(net, vq);
		VHOSTPKRX("handle_tx: packet sent: vq=%d, head=%d\n", net->__hype_vhost, head);
		total_len += len;
		vhost_net_tx_packet(net);
		if (unlikely(total_len >= VHOST_NET_WEIGHT)) {
			vhost_poll_queue(&vq->poll);
			break;
		}
	}
out:
	mutex_unlock(&vq->mutex);
	VHOSTPKTX("handle_tx: leaving!!\n");
}

static int peek_head_len(struct sock *sk, struct vhost_net *net)
{
	struct sk_buff *head;
	int len = 0;
	unsigned long flags;

#ifndef CONFIG_POPCORN_ORIGIN_NODE
	/* ask origin */
	VHOSTPKRX("peek_head_len: sending request\n");
	len = khype_peek_head_len(net);
	VHOSTPKRX("peek_head_len: got response: sock_len=%d\n", len);
	return len;
#else
	spin_lock_irqsave(&sk->sk_receive_queue.lock, flags);
	head = skb_peek(&sk->sk_receive_queue);
	if (likely(head)) {
		len = head->len;
		if (skb_vlan_tag_present(head))
			len += VLAN_HLEN;
	}

	spin_unlock_irqrestore(&sk->sk_receive_queue.lock, flags);
#endif
	return len;
}

/* This is a multi-buffer version of vhost_get_desc, that works if
 *	vq has read descriptors only.
 * @vq		- the relevant virtqueue
 * @datalen	- data length we'll be reading
 * @iovcount	- returned count of io vectors we fill
 * @log		- vhost log
 * @log_num	- log offset
 * @quota       - headcount quota, 1 for big buffer
 *	returns number of buffer heads allocated, negative on error
 */
static int get_rx_bufs(struct vhost_virtqueue *vq,
		       struct vring_used_elem *heads,
		       int datalen,
		       unsigned *iovcount,
		       struct vhost_log *log,
		       unsigned *log_num,
		       unsigned int quota)
{
	unsigned int out, in;
	int seg = 0;
	int headcount = 0;
	unsigned d;
	int r, nlogs = 0;
	/* len is always initialized before use since we are always called with
	 * datalen > 0.
	 */
	u32 uninitialized_var(len);

	while (datalen > 0 && headcount < quota) {
		if (unlikely(seg >= UIO_MAXIOV)) {
			r = -ENOBUFS;
			goto err;
		}
		r = vhost_get_vq_desc(vq, vq->iov + seg,
				      ARRAY_SIZE(vq->iov) - seg, &out,
				      &in, log, log_num);
		if (unlikely(r < 0))
			goto err;

		d = r;
		if (d == vq->num) {
			r = 0;
			goto err;
		}
		if (unlikely(out || in <= 0)) {
			vq_err(vq, "unexpected descriptor format for RX: "
				"out %d, in %d\n", out, in);
			r = -EINVAL;
			goto err;
		}
		if (unlikely(log)) {
			nlogs += *log_num;
			log += *log_num;
		}
		heads[headcount].id = cpu_to_vhost32(vq, d);
		len = iov_length(vq->iov + seg, in);
		heads[headcount].len = cpu_to_vhost32(vq, len);
		datalen -= len;
		++headcount;
		seg += in;
	}
	heads[headcount - 1].len = cpu_to_vhost32(vq, len + datalen);
	*iovcount = seg;
	if (unlikely(log))
		*log_num = nlogs;

	/* Detect overrun */
	if (unlikely(datalen > 0)) {
		r = UIO_MAXIOV + 1;
		goto err;
	}
	return headcount;
err:
	vhost_discard_vq_desc(vq, headcount);
	return r;
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
void vhost_handle_rx(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_RX];
	struct vhost_virtqueue *vq = &nvq->vq;
	unsigned uninitialized_var(in), log;
	struct vhost_log *vq_log;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL, /* FIXME: get and handle RX aux data. */
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	struct virtio_net_hdr hdr = {
		.flags = 0,
		.gso_type = VIRTIO_NET_HDR_GSO_NONE
	};
	size_t total_len = 0;
	int err, mergeable;
	s16 headcount;
	size_t vhost_hlen, sock_hlen;
	size_t vhost_len, sock_len;
	struct socket *sock;
	struct iov_iter fixup;
	__virtio16 num_buffers;

#ifdef CONFIG_POPCORN_HYPE
	/* kernel host */
	CRITICALNETPK("\tpophype: vhost-net: %s: %s():\n", __FILE__, __func__);
#endif

	mutex_lock(&vq->mutex);
	sock = vq->private_data;
	if (!sock)
		goto out;
	vhost_disable_notify(&net->dev, vq);

	vhost_hlen = nvq->vhost_hlen;
	sock_hlen = nvq->sock_hlen;

	vq_log = unlikely(vhost_has_feature(vq, VHOST_F_LOG_ALL)) ?
		vq->log : NULL;
	mergeable = vhost_has_feature(vq, VIRTIO_NET_F_MRG_RXBUF);

	while ((sock_len = peek_head_len(sock->sk, net))) {
		sock_len += sock_hlen;
		vhost_len = sock_len + vhost_hlen;
		headcount = get_rx_bufs(vq, vq->heads, vhost_len,
					&in, vq_log, &log,
					likely(mergeable) ? UIO_MAXIOV : 1);
#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
		if (my_nid)
#endif
			VHOSTPKRX("handle_rx: entered loop: sock_len=%d (sock_hlen=%d vhost_hlen=%d), headcount=%d\n", sock_len, sock_hlen, vhost_hlen, headcount);
		/* On error, stop handling until the next kick. */
		if (unlikely(headcount < 0))
			break;
		/* On overrun, truncate and discard */
		if (unlikely(headcount > UIO_MAXIOV)) {
			iov_iter_init(&msg.msg_iter, READ, vq->iov, 1, 1);
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_ORIGIN_NODE
			err = sock->ops->recvmsg(sock, &msg,
						1, MSG_DONTWAIT | MSG_TRUNC);
#else
			err = khype_tun_recvmsg(net, &msg,
						1, MSG_DONTWAIT | MSG_TRUNC);
#endif /* CONFIG_POPCORN_ORIGIN_NODE */
#else
			err = sock->ops->recvmsg(sock, &msg,
						 1, MSG_DONTWAIT | MSG_TRUNC);
#endif /* CONFIG_POPCORN_HYPE */
			pr_debug("Discarded rx packet: len %zd\n", sock_len);
#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
			if (my_nid)
#endif
				VHOSTPKRX("handle_rx: continue: discarded packet headcount > UIO_MAXIOV\n");
			continue;
		}
		/* OK, now we need to know about added descriptors. */
		if (!headcount) {
			if (unlikely(vhost_enable_notify(&net->dev, vq))) {
				/* They have slipped one in as we were
				 * doing that: check again. */
				vhost_disable_notify(&net->dev, vq);
#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
				if (my_nid)
#endif
					VHOSTPKRX("handle_rx: continue: !headcount\n");
				continue;
			}
			/* Nothing new?  Wait for eventfd to tell us
			 * they refilled. */
#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
			if (my_nid)
				VHOSTPKRX("handle_rx: break: nothing new\n");
#endif
			break;
		}
		/* We don't need to be notified again. */
		iov_iter_init(&msg.msg_iter, READ, vq->iov, in, vhost_len);
		fixup = msg.msg_iter;
		if (unlikely((vhost_hlen))) {
			/* We will supply the header ourselves
			 * TODO: support TSO.
			 */
			iov_iter_advance(&msg.msg_iter, vhost_hlen);
		}
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_ORIGIN_NODE
		err = sock->ops->recvmsg(sock, &msg,
					sock_len, MSG_DONTWAIT | MSG_TRUNC);
#else
		err = khype_tun_recvmsg(net, &msg,
					sock_len, MSG_DONTWAIT | MSG_TRUNC);
#endif /* CONFIG_POPCORN_ORIGIN_NODE */
#else
		err = sock->ops->recvmsg(sock, &msg,
					 sock_len, MSG_DONTWAIT | MSG_TRUNC);
#endif /* CONFIG_POPCORN_HYPE */
		/* Userspace might have consumed the packet meanwhile:
		 * it's not supposed to do this usually, but might be hard
		 * to prevent. Discard data we got (if any) and keep going. */
		if (unlikely(err != sock_len)) {
			pr_debug("Discarded rx packet: "
				 " len %d, expected %zd\n", err, sock_len);
			vhost_discard_vq_desc(vq, headcount);
#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
			if (my_nid)
#endif
				VHOSTPKRX("handle_rx: discarded packet: err != sock_len\n");
			continue;
		}
		/* Supply virtio_net_hdr if VHOST_NET_F_VIRTIO_NET_HDR */
		if (unlikely(vhost_hlen)) {
			if (copy_to_iter(&hdr, sizeof(hdr),
					 &fixup) != sizeof(hdr)) {
				vq_err(vq, "Unable to write vnet_hdr "
				       "at addr %p\n", vq->iov->iov_base);
#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
			if (my_nid)
#endif
					VHOSTPKRX("handle_rx: break: unable to handle vnet_hdr\n");
				break;
			}
		} else {
			/* Header came from socket; we'll need to patch
			 * ->num_buffers over if VIRTIO_NET_F_MRG_RXBUF
			 */
			iov_iter_advance(&fixup, sizeof(hdr));
		}
		/* TODO: Should check and handle checksum. */

		num_buffers = cpu_to_vhost16(vq, headcount);
		if (likely(mergeable) &&
		    copy_to_iter(&num_buffers, sizeof num_buffers,
				 &fixup) != sizeof num_buffers) {
			vq_err(vq, "Failed num_buffers write");
			vhost_discard_vq_desc(vq, headcount);
#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
			if (my_nid)
#endif
				VHOSTPKRX("handle_rx: break: failed num writes\n");
			break;
		}
#ifdef CONFIG_POPCORN_HYPE
		/* kernel host */
		CRITICALNETPK("%s %s(): vhost_signal -> eventfd_signal\n",
										__FILE__, __func__);
		{
			static u64 cnt = 0;
			cnt++;
			if ((cnt > 70 && cnt < 100) || !(cnt % 1000)) {
				VHOSTNET_OPTIMIZE_PK("\tpophype: vhost-net: <%d> %s: %s(): "
						"(vhost_dev)(&net->dev)dev %p (vhost_virtqueue)vq %p "
						"vq->heads %p #%llu\n",
						smp_processor_id(), __FILE__, __func__,
						&net->dev, vq, vq->heads, cnt);
			}
		}
#endif
#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
			if (my_nid)
#endif
				VHOSTPKRX("handle_rx: copied data to iter, signaling guest! qp=%d, nid=%d\n", net->__hype_vhost, my_nid);
		vhost_add_used_and_signal_n(&net->dev, vq, vq->heads,
					    headcount);
		if (unlikely(vq_log))
			vhost_log_write(vq, vq_log, log, vhost_len);
		total_len += vhost_len;
		if (unlikely(total_len >= VHOST_NET_WEIGHT)) {
			vhost_poll_queue(&vq->poll);
			break;
		}
	}
out:
	mutex_unlock(&vq->mutex);
#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
	if (my_nid)
#endif
		VHOSTPKRX("handle_rx: leaving sock_len=%d, qp=%d\n", sock_len, net->__hype_vhost);
}

static void handle_tx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_net *net = container_of(vq->dev, struct vhost_net, dev);
	VHOSTPKTX("%s\n", __func__);
	handle_tx(net);
}

static void handle_rx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_net *net = container_of(vq->dev, struct vhost_net, dev);
#ifdef CONFIG_POPCORN_HYPE
	int qp = net->__hype_vhost;
	if (!my_nid && qp) {
		__khype_send_rx_notification(net);
		VHOSTPKRX("handle_rx_kick qp=%d, nid=%d\n", net->__hype_vhost, my_nid);
		return;
	}
#endif
	handle_rx(net);
}

static void handle_tx_net(struct vhost_work *work)
{
	struct vhost_net *net = container_of(work, struct vhost_net,
					     poll[VHOST_NET_VQ_TX].work);
	handle_tx(net);
}

static void handle_rx_net(struct vhost_work *work)
{
	struct vhost_net *net = container_of(work, struct vhost_net,
					     poll[VHOST_NET_VQ_RX].work);
#ifdef CONFIG_POPCORN_HYPE
	int qp = net->__hype_vhost;
	/* host kernel */
	if (!my_nid && qp) {
		__khype_send_rx_notification(net);
		VHOSTPK("handle_rx_net: returned from rx_notification: vhost=%d\n", qp);
		return;
	}
#endif
	handle_rx(net);
}

#ifdef CONFIG_POPCORN_HYPE
/* Karim's vhost_net optimizations */
static void __khype_send_rx_notification(struct vhost_net *net)
{
       struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_RX];
       struct vhost_virtqueue *vq = &nvq->vq;
       rx_notification_request_t *req;
       struct socket *sock;
       size_t sock_len;
       int r;

       /* Normally we take vq->mutex but it doesn't make sense
        * in our case.
        **/
       sock = vq->private_data;
       BUG_ON(!sock);

       /* avoid sending if we don't have data (false positive) */
       sock_len = peek_head_len(sock->sk, net);
       if (!sock_len)
               return;

       req = pcn_kmsg_get(sizeof(*req));
       BUG_ON(!req);
    req->vhost = net->__hype_vhost;

               VHOSTPKRX("khype_send_rx_notification: req->vhost=%d (%p)\n", req->vhost, net);

    khype_send_rx_notification(req);
}

void khype_handle_rx(struct vhost_net *net)
{
       struct vhost_poll *poll = &net->poll[VHOST_NET_VQ_RX];

       VHOSTPKRX("khype_handle_rx: waking up worker\n");
       vhost_poll_queue(poll);
}

/* peek_head_len delegation */
static size_t khype_peek_head_len(struct vhost_net *net)
{
       int vhost = net->__hype_vhost;

       return khype_peek_head_len_request(vhost);
}

size_t khype_service_peek_head_len(struct vhost_net *net)
{
    struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_RX];
    struct vhost_virtqueue *vq = &nvq->vq;
    struct socket *sock;
    size_t sock_len;

       /* Normally we take vq->mutex but it doesn't make sense
        * in our case.
        **/
    sock = vq->private_data;
    sock_len = peek_head_len(sock->sk, net);

    return sock_len;
}

/* recvmsg delegation */
static int khype_tun_recvmsg(struct vhost_net *net, struct msghdr *msg,
                                 size_t sock_len, int flags)
{
       delegate_recvmsg_request_t req;
       int r;

       req.vhost = net->__hype_vhost;
       req.sock_len = sock_len;
       req.flags = flags;

               VHOSTPKRX("khype_tun_recvmsg: req->sock_len=%d, req->flags=%d, req->vhost=%d\n", req.sock_len, flags, req.vhost);
       r = khype_recvmsg_delegate(&req, msg);

               VHOSTPKRX("khype_tun_recvmsg: returned: r=%d\n", r);

       return r;
}
/* processing recvmsg delegation */
int khype_vhost_recvmsg_delegate(struct vhost_net *net, char *data, size_t sock_len, int *flags)
{
       mm_segment_t oldfs = get_fs();
       struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_RX];
       struct vhost_virtqueue *vq = &nvq->vq;
       struct msghdr msg = {
               .msg_name = NULL,
               .msg_namelen = 0,
               .msg_control = NULL, /* FIXME: get and handle RX aux data. */
               .msg_controllen = 0,
               .msg_flags = MSG_DONTWAIT,
       };
       struct iovec iov = {
               .iov_base = data,
               .iov_len = sock_len
       };
       struct socket *sock;
       int r = 0;

       set_fs(USER_DS);
       use_mm(__hype_gctx.rc->mm);

       mutex_lock(&vq->mutex);
       sock = vq->private_data;
       if (!sock)
               goto out;

#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
       if (net->__hype_vhost == 1)
#endif
               VHOSTPKRX("khype_vhost_recvmsg_delegate: local.sock_len=%d, \n", peek_head_len(sock->sk, net));

       iov_iter_init(&msg.msg_iter, READ, &iov, 1, sock_len);

#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
       if (net->__hype_vhost == 1)
#endif
               VHOSTPKRX("khype_vhost_recvmsg_delegate: sock_len=%d, iter.count=%d\n", sock_len, msg.msg_iter.count);

       r = sock->ops->recvmsg(sock, &msg, sock_len, MSG_DONTWAIT | MSG_TRUNC);
       *flags = msg.msg_flags;
out:
       mutex_unlock(&vq->mutex);
       unuse_mm(__hype_gctx.rc->mm);
       set_fs(oldfs);

#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
       if (net->__hype_vhost == 1)
#endif
               VHOSTPKRX("khype_vhost_recvmsg_delegate: done! sock_len=%d, r=%d, iter.count=%d, MSG_TRUNC=%d\n", sock_len, r, msg.msg_iter.count, !!(*flags & MSG_TRUNC));
       return r;
}


/* tunfd delegation */
/* called from remote node */
static int khype_tun_sendmsg(struct vhost_net *net, struct msghdr *msg)
{
    delegate_tunfd_request_t *req;
       struct iov_iter *i = &msg->msg_iter;
       struct iovec *iov;
       int len = i->count;
       int r = 0;

       req = kmalloc(sizeof(*req) + len, GFP_KERNEL);
       if (!req)
               BUG();

       /* copy packet's data from userspace to kmsg */
       if (copy_from_iter(req->packet, len, i) != len)
               BUG();

       req->psize = len;
       req->vhost = net->__hype_vhost;

       VHOSTPKTX("khype_tun_sendmsg: req->psize=%x, req->vhost=%x\n", req->psize, req->vhost);

       /* this call blocks until we receive response from origin */
       r = khype_tunfd_delegate(req);

       VHOSTPKTX("khype_tun_sendmsg: return=%d\n", r);

    kfree(req);
    return r;
}

/* called from origin to service khype_tun_sendmsg() */
int khype_vhost_tunfd_delegate(char *data, size_t psize, struct vhost_net *net)
{
    struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
    struct vhost_virtqueue *vq = &nvq->vq;
    struct socket *sock;
       struct msghdr msg = {
               .msg_name = NULL,
               .msg_namelen = 0,
               .msg_control = NULL,
               .msg_controllen = 0,
               .msg_flags = MSG_DONTWAIT,
       };
       int r;
       bool is_kvec;

       sock = vq->private_data;
       if (!sock) {
               r = -ENOENT;
               goto out;
       }

#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
       if (net->__hype_vhost == 1)
#endif
               VHOSTPKTX("entered khype_vhost_tunfd_delegate\n");

       /* rebuild iovec */
       vq->iov[0].iov_base = data;
       vq->iov[0].iov_len = psize;

       iov_iter_init(&msg.msg_iter, WRITE, vq->iov, 1, psize);
       r = sock->ops->sendmsg(sock, &msg, psize);

#ifdef CONFIG_PCN_PRINTK_NO_ORIGIN
       if (net->__hype_vhost == 1)
#endif
               VHOSTPKTX("return from khype_vhost_tunfd_delegate = %d\n", r);
out:
       return r;
}
#endif


static int vhost_net_open(struct inode *inode, struct file *f)
{
	struct vhost_net *n;
	struct vhost_dev *dev;
	struct vhost_virtqueue **vqs;
	int i;

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("===================== (guest) start %s(): ====================\n"
			"\tpophype: vhost-net: vhost_net_init -> vhost_net.open "
			"\"devname:vhost-net\" ->vhost_dev_init() "
			"and ->vhost_poll_init() * 2 (handle_tx_net & handle_rx_net). "
			"vhost_net (1 per qp) = "
			"ONE vhost_dev + TWO vhost_virtqueue vqs (tx&rx)"
													"\n\n", __func__);
#endif

	n = kmalloc(sizeof *n, GFP_KERNEL | __GFP_NOWARN | __GFP_REPEAT);
	if (!n) {
		n = vmalloc(sizeof *n);
		if (!n)
			return -ENOMEM;
	}
	vqs = kmalloc(VHOST_NET_VQ_MAX * sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		kvfree(n);
		return -ENOMEM;
	}

	dev = &n->dev;
	vqs[VHOST_NET_VQ_TX] = &n->vqs[VHOST_NET_VQ_TX].vq;
	vqs[VHOST_NET_VQ_RX] = &n->vqs[VHOST_NET_VQ_RX].vq;
	n->vqs[VHOST_NET_VQ_TX].vq.handle_kick = handle_tx_kick;
	n->vqs[VHOST_NET_VQ_RX].vq.handle_kick = handle_rx_kick;
	for (i = 0; i < VHOST_NET_VQ_MAX; i++) {
		n->vqs[i].ubufs = NULL;
		n->vqs[i].ubuf_info = NULL;
		n->vqs[i].upend_idx = 0;
		n->vqs[i].done_idx = 0;
		n->vqs[i].vhost_hlen = 0;
		n->vqs[i].sock_hlen = 0;
	}
	vhost_dev_init(dev, vqs, VHOST_NET_VQ_MAX);

	vhost_poll_init(n->poll + VHOST_NET_VQ_TX, handle_tx_net, POLLOUT, dev);
	vhost_poll_init(n->poll + VHOST_NET_VQ_RX, handle_rx_net, POLLIN, dev);

	f->private_data = n;
#ifdef CONFIG_POPCORN_HYPE // #if POPHYPE_GUEST_NET_OPTIMIZE
	POP_PK("\t(guest) pophype: vhost-net: opti: <%d> %s: %s(): "
			"(struct vhost_virtqueue) vqs %p "
			"[[[[[ Jack vqs[VHOST_NET_VQ_TX] [[[%p]]] (shared) "
					"vqs[VHOST_NET_VQ_RX] [[[%p]]] (shared) ]]]]]"
			"(This also explain why there is no MQ in vhost)\n",
			smp_processor_id(), __FILE__, __func__,
			vqs, vqs[VHOST_NET_VQ_TX], vqs[VHOST_NET_VQ_RX]);
	POP_PK("\t(guest) pophype: vhost-net: opti: <%d> %s: %s(): "
			"((vhost_dev)dev)->memory %p "
			"((1 per qp) vhost_net %p -> vhost_dev %p -> "
			"(vqs %p)vhost_virtqueue[TX/RX])\n",
			smp_processor_id(), __FILE__, __func__,
			dev->memory,
			n, dev, vqs);
	//POP_PK("\tpophype: vhost-net: opti: <%d> %s: %s(): "
	//		"n->poll %p + (VHOST_NET_VQ_TX 0) / (VHOST_NET_VQ_TX 1)\n",
	//		smp_processor_id(), __FILE__, __func__,
	//		n->poll);
#endif

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t(guest) pophype: vhost-net: vhost_net_init -> vhost_net.open dev %p created DONE\n"
			"==================== %s() end ======================\n\n\n", dev, __func__);
#endif
#ifdef CONFIG_POPCORN_HYPE
       /* TODO: check for limits */
       __hype_gctx.__hype_vhosts[__hype_gctx.__hype_vhost] = n;
       n->__hype_vhost = __hype_gctx.__hype_vhost++;
       __hype_gctx.tsk = current;
       __hype_gctx.rc = current->mm->remote;
       /* since module is compiled in-kernel
        * we need to call this here */
    /* allow zc only on origin */
    if (experimental_zcopytx && !my_nid)
        vhost_net_enable_zcopy(VHOST_NET_VQ_TX);
#endif

	return 0;
}

static void vhost_net_disable_vq(struct vhost_net *n,
				 struct vhost_virtqueue *vq)
{
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);
	struct vhost_poll *poll = n->poll + (nvq - n->vqs);
	if (!vq->private_data)
		return;
	vhost_poll_stop(poll);
}

#if POPHYPE_NET_OPTIMIZE
//struct socket *pophype_origin_host_tun_sock;
extern struct socket *pophype_origin_host_tun_sock;
#endif
static int vhost_net_enable_vq(struct vhost_net *n,
				struct vhost_virtqueue *vq)
{
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);
	struct vhost_poll *poll = n->poll + (nvq - n->vqs);
	struct socket *sock;

#if POPHYPE_NET_OPTIMIZE
	POP_PK("%s: %s(): Jack vq->private_data = (struct socket) *sock = %p\n",
										__FILE__, __func__, vq->private_data);
	WARN_ON("NEVER");
	pophype_origin_host_tun_sock = vq->private_data;
#endif

	sock = vq->private_data;
	if (!sock)
		return 0;

	return vhost_poll_start(poll, sock->file);
}

static struct socket *vhost_net_stop_vq(struct vhost_net *n,
					struct vhost_virtqueue *vq)
{
	struct socket *sock;

	mutex_lock(&vq->mutex);
	sock = vq->private_data;
	vhost_net_disable_vq(n, vq);
	vq->private_data = NULL;
	mutex_unlock(&vq->mutex);
	return sock;
}

static void vhost_net_stop(struct vhost_net *n, struct socket **tx_sock,
			   struct socket **rx_sock)
{
	*tx_sock = vhost_net_stop_vq(n, &n->vqs[VHOST_NET_VQ_TX].vq);
	*rx_sock = vhost_net_stop_vq(n, &n->vqs[VHOST_NET_VQ_RX].vq);
}

static void vhost_net_flush_vq(struct vhost_net *n, int index)
{
	vhost_poll_flush(n->poll + index);
	vhost_poll_flush(&n->vqs[index].vq.poll);
}

static void vhost_net_flush(struct vhost_net *n)
{
	vhost_net_flush_vq(n, VHOST_NET_VQ_TX);
	vhost_net_flush_vq(n, VHOST_NET_VQ_RX);
	if (n->vqs[VHOST_NET_VQ_TX].ubufs) {
		mutex_lock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
		n->tx_flush = true;
		mutex_unlock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
		/* Wait for all lower device DMAs done. */
		vhost_net_ubuf_put_and_wait(n->vqs[VHOST_NET_VQ_TX].ubufs);
		mutex_lock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
		n->tx_flush = false;
		atomic_set(&n->vqs[VHOST_NET_VQ_TX].ubufs->refcount, 1);
		mutex_unlock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
	}
}

static int vhost_net_release(struct inode *inode, struct file *f)
{
	struct vhost_net *n = f->private_data;
	struct socket *tx_sock;
	struct socket *rx_sock;

	vhost_net_stop(n, &tx_sock, &rx_sock);
	vhost_net_flush(n);
	vhost_dev_stop(&n->dev);
	vhost_dev_cleanup(&n->dev, false);
	vhost_net_vq_reset(n);
	if (tx_sock)
		sockfd_put(tx_sock);
	if (rx_sock)
		sockfd_put(rx_sock);
	/* Make sure no callbacks are outstanding */
	synchronize_rcu_bh();
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_net_flush(n);
	kfree(n->dev.vqs);
	kvfree(n);
	return 0;
}

static struct socket *get_raw_socket(int fd)
{
	struct {
		struct sockaddr_ll sa;
		char  buf[MAX_ADDR_LEN];
	} uaddr;
	int uaddr_len = sizeof uaddr, r;
	struct socket *sock = sockfd_lookup(fd, &r);

	if (!sock)
		return ERR_PTR(-ENOTSOCK);

	/* Parameter checking */
	if (sock->sk->sk_type != SOCK_RAW) {
		r = -ESOCKTNOSUPPORT;
		goto err;
	}

	r = sock->ops->getname(sock, (struct sockaddr *)&uaddr.sa,
			       &uaddr_len, 0);
	if (r)
		goto err;

	if (uaddr.sa.sll_family != AF_PACKET) {
		r = -EPFNOSUPPORT;
		goto err;
	}
	return sock;
err:
	sockfd_put(sock);
	return ERR_PTR(r);
}

static struct socket *get_tap_socket(int fd)
{
	struct file *file = fget(fd);
	struct socket *sock;

	if (!file)
		return ERR_PTR(-EBADF);
	sock = tun_get_socket(file);
	if (!IS_ERR(sock))
		return sock;
	sock = macvtap_get_socket(file);
	if (IS_ERR(sock))
		fput(file);
	return sock;
}

static struct socket *get_socket(int fd)
{
	struct socket *sock;

	/* special case to disable backend */
	if (fd == -1)
		return NULL;
	sock = get_raw_socket(fd);
	if (!IS_ERR(sock))
		return sock;
	sock = get_tap_socket(fd);
	if (!IS_ERR(sock))
		return sock;
	return ERR_PTR(-ENOTSOCK);
}

static long vhost_net_set_backend(struct vhost_net *n, unsigned index, int fd)
{
	struct socket *sock, *oldsock;
	struct vhost_virtqueue *vq;
	struct vhost_net_virtqueue *nvq;
	struct vhost_net_ubuf_ref *ubufs, *oldubufs = NULL;
	int r;

	mutex_lock(&n->dev.mutex);
	r = vhost_dev_check_owner(&n->dev);
	if (r)
		goto err;

	if (index >= VHOST_NET_VQ_MAX) {
		r = -ENOBUFS;
		goto err;
	}
	vq = &n->vqs[index].vq;
	nvq = &n->vqs[index];
#ifdef CONFIG_POPCORN_HYPE
	POP_PK("(host) %s(): init: fd %d queue index %d (0rx/1tx) "
			"vq %p = nvq %p (%s)\n",
			__func__, fd, index, vq, nvq, __FILE__);
#endif
	mutex_lock(&vq->mutex);

	/* Verify that ring has been setup correctly. */
	if (!vhost_vq_access_ok(vq)) {
		r = -EFAULT;
		goto err_vq;
	}
	sock = get_socket(fd);
	if (IS_ERR(sock)) {
		r = PTR_ERR(sock);
		goto err_vq;
	}

	/* start polling new socket */
	oldsock = vq->private_data;
	if (sock != oldsock) {
#ifdef CONFIG_POPCORN_HYPE
		ubufs = vhost_net_ubuf_alloc(vq,
					sock && vhost_sock_zcopy(sock) && !my_nid);
#else
		ubufs = vhost_net_ubuf_alloc(vq,
					     sock && vhost_sock_zcopy(sock));
#endif
		if (IS_ERR(ubufs)) {
			r = PTR_ERR(ubufs);
			goto err_ubufs;
		}

		vhost_net_disable_vq(n, vq);
		vq->private_data = sock;
		r = vhost_init_used(vq);
		if (r)
			goto err_used;
		r = vhost_net_enable_vq(n, vq);
		if (r)
			goto err_used;

		oldubufs = nvq->ubufs;
		nvq->ubufs = ubufs;

		n->tx_packets = 0;
		n->tx_zcopy_err = 0;
		n->tx_flush = false;
	}

	mutex_unlock(&vq->mutex);

	if (oldubufs) {
		vhost_net_ubuf_put_wait_and_free(oldubufs);
		mutex_lock(&vq->mutex);
		vhost_zerocopy_signal_used(n, vq);
		mutex_unlock(&vq->mutex);
	}

	if (oldsock) {
		vhost_net_flush_vq(n, index);
		sockfd_put(oldsock);
	}

	mutex_unlock(&n->dev.mutex);
	return 0;

err_used:
	vq->private_data = oldsock;
	vhost_net_enable_vq(n, vq);
	if (ubufs)
		vhost_net_ubuf_put_wait_and_free(ubufs);
err_ubufs:
	sockfd_put(sock);
err_vq:
	mutex_unlock(&vq->mutex);
err:
	mutex_unlock(&n->dev.mutex);
	return r;
}

static long vhost_net_reset_owner(struct vhost_net *n)
{
	struct socket *tx_sock = NULL;
	struct socket *rx_sock = NULL;
	long err;
	struct vhost_memory *memory;

	mutex_lock(&n->dev.mutex);
	err = vhost_dev_check_owner(&n->dev);
	if (err)
		goto done;
	memory = vhost_dev_reset_owner_prepare();
	if (!memory) {
		err = -ENOMEM;
		goto done;
	}
	vhost_net_stop(n, &tx_sock, &rx_sock);
	vhost_net_flush(n);
	vhost_dev_stop(&n->dev);
	vhost_dev_reset_owner(&n->dev, memory);
	vhost_net_vq_reset(n);
done:
	mutex_unlock(&n->dev.mutex);
	if (tx_sock)
		sockfd_put(tx_sock);
	if (rx_sock)
		sockfd_put(rx_sock);
	return err;
}

static int vhost_net_set_features(struct vhost_net *n, u64 features)
{
	size_t vhost_hlen, sock_hlen, hdr_len;
	int i;

	hdr_len = (features & ((1ULL << VIRTIO_NET_F_MRG_RXBUF) |
			       (1ULL << VIRTIO_F_VERSION_1))) ?
			sizeof(struct virtio_net_hdr_mrg_rxbuf) :
			sizeof(struct virtio_net_hdr);
	if (features & (1 << VHOST_NET_F_VIRTIO_NET_HDR)) {
		/* vhost provides vnet_hdr */
		vhost_hlen = hdr_len;
		sock_hlen = 0;
	} else {
		/* socket provides vnet_hdr */
		vhost_hlen = 0;
		sock_hlen = hdr_len;
	}
	mutex_lock(&n->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&n->dev)) {
		mutex_unlock(&n->dev.mutex);
		return -EFAULT;
	}
	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		mutex_lock(&n->vqs[i].vq.mutex);
		n->vqs[i].vq.acked_features = features;
		n->vqs[i].vhost_hlen = vhost_hlen;
		n->vqs[i].sock_hlen = sock_hlen;
		mutex_unlock(&n->vqs[i].vq.mutex);
	}
	mutex_unlock(&n->dev.mutex);
	VHOSTPK("vhost_net_set_features: vq=%d, vhost_hlen=%d, sock_hlen=%d\n", i, vhost_hlen, sock_hlen);
	return 0;
}

static long vhost_net_set_owner(struct vhost_net *n)
{
	int r;

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t\t%s: %s(): start ->kthread_create(vhost_worker)\n",
											__FILE__, __func__);
#endif

	mutex_lock(&n->dev.mutex);
	if (vhost_dev_has_owner(&n->dev)) {
		r = -EBUSY;
		goto out;
	}
	r = vhost_net_set_ubuf_info(n);
	if (r)
		goto out;
	r = vhost_dev_set_owner(&n->dev);
	if (r)
		vhost_net_clear_ubuf_info(n);
	vhost_net_flush(n);
out:
	mutex_unlock(&n->dev.mutex);
#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t\t%s: %s(): done ->kthread_create(vhost_worker)\n",
											__FILE__, __func__);
#endif
	return r;
}

static long vhost_net_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
	struct vhost_net *n = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	struct vhost_vring_file backend;
	u64 features;
	int r;

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t%s %s(): fd %d ioctl 0x%x\n",
			//"host_usr rip 0x%lx guest_kern rip 0x%lx\n",
			__FILE__, __func__,
			popcorn_file_to_fd(current, f, false), ioctl);
			//instruction_pointer(current_pt_regs()),
			//((dsm_traffic_t)(pophype_show_guest_rip_rsp(0x0), false)).rip); /* just wanna show rip */
#endif
	switch (ioctl) {
	case VHOST_NET_SET_BACKEND:
#ifdef CONFIG_POPCORN_HYPE
        POP_PK("\t\tpophype: vhost-net: %s: %s(): VHOST_NET_SET_BACKEND\n",
                                                        __FILE__, __func__);
#endif
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;
		return vhost_net_set_backend(n, backend.index, backend.fd);
	case VHOST_GET_FEATURES:
		features = VHOST_NET_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, featurep, sizeof features))
			return -EFAULT;
		if (features & ~VHOST_NET_FEATURES)
			return -EOPNOTSUPP;
		return vhost_net_set_features(n, features);
	case VHOST_RESET_OWNER:
		return vhost_net_reset_owner(n);
	case VHOST_SET_OWNER:
#ifdef CONFIG_POPCORN_HYPE
		POP_PK("\t\tpophype: vhost-net: %s: %s(): "
				"ioctl 0x%x = 0x%x (VHOST_SET_OWNER)\n",
				__FILE__, __func__, ioctl, VHOST_SET_OWNER);
#endif
		return vhost_net_set_owner(n);
	default:
		mutex_lock(&n->dev.mutex);
		r = vhost_dev_ioctl(&n->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&n->dev, ioctl, argp);
		else
			vhost_net_flush(n);
		mutex_unlock(&n->dev.mutex);
		return r;
	}
}

#ifdef CONFIG_COMPAT
static long vhost_net_compat_ioctl(struct file *f, unsigned int ioctl,
				   unsigned long arg)
{
	return vhost_net_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vhost_net_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_net_release,
	.unlocked_ioctl = vhost_net_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_net_compat_ioctl,
#endif
	.open           = vhost_net_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_net_misc = {
	.minor = VHOST_NET_MINOR,
	.name = "vhost-net",
	.fops = &vhost_net_fops,
};

static int vhost_net_init(void)
{
	if (experimental_zcopytx)
		vhost_net_enable_zcopy(VHOST_NET_VQ_TX);
	return misc_register(&vhost_net_misc);
}
module_init(vhost_net_init);

static void vhost_net_exit(void)
{
	misc_deregister(&vhost_net_misc);
}
module_exit(vhost_net_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Michael S. Tsirkin");
MODULE_DESCRIPTION("Host kernel accelerator for virtio net");
MODULE_ALIAS_MISCDEV(VHOST_NET_MINOR);
MODULE_ALIAS("devname:vhost-net");
