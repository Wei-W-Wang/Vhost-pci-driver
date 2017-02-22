/* A network driver using vhost-pci.
 *
 * Copyright 2016 Wei Wang <wei.w.wang@intel.com> Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/vhost_pci_net.h>
#include <linux/scatterlist.h>
#include <linux/if_vlan.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/average.h>
#include <linux/pci.h>
#include <net/busy_poll.h>

static int napi_weight = NAPI_POLL_WEIGHT;
module_param(napi_weight, int, 0444);

#define GOOD_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define GOOD_COPY_LEN	128

/* Minimum alignment for mergeable packet buffers. */
#define MERGEABLE_BUFFER_ALIGN max(L1_CACHE_BYTES, 256)

/* RX packet size EWMA. The average packet size is used to determine the packet
 * buffer size when refilling RX rings. As the entire RX ring may be refilled
 * at once, the weight is chosen so that the EWMA will be insensitive to short-
 * term, transient changes in packet size.
 */
DECLARE_EWMA(pkt_len, 1, 64)

struct ctrlq_buf {
	char *buf;

	/* size of the buffer in *buf above */
	size_t size;

	/* used length of the buffer */
	size_t len;

	/* offset in the buf from which to consume data */
	size_t offset;

	/* If sgpages == 0 then buf is used */
	unsigned int sgpages;

	/* sg is used if spages > 0. sg must be the last in is struct */
	struct scatterlist sg[0];
};

struct vpnet_stats {
	struct u64_stats_sync tx_syncp;
	struct u64_stats_sync rx_syncp;
	u64 tx_bytes;
	u64 tx_packets;

	u64 rx_bytes;
	u64 rx_packets;
};

struct peer_region_info {
	uint64_t start;
	uint64_t end;
	uint64_t offset;
};

struct peer_mem_info {
	void *pmem_base;
	uint32_t nregions;
	struct peer_region_info regions[MAX_GUEST_REGION];
};

struct peer_virtqueue {
	/* Last available index we saw. */
	u16 last_avail_idx;

	/* Last index we used. */
	u16 last_used_idx;

	int enabled;
	struct vring vring;
};

struct vpnet_rx_engine {
	/* Virtqueue associated with this rx engine */
	struct virtqueue *vq;

	struct peer_virtqueue peer_tx;

	u16 last_avail_idx;

	struct napi_struct napi;

	/* Chain pages by the private ptr. */
	struct page *pages;

	/* Average packet length for mergeable receive buffers. */
	struct ewma_pkt_len mrg_avg_pkt_len;

	/* Page frag for packet buffer allocation. */
	struct page_frag alloc_frag;

	/* RX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Name of this receive queue: input.$index */
	char name[40];
};

struct vpnet_tx_engine {
	/* Virtqueue associated with this tx engine */
	struct virtqueue *vq;
	struct peer_virtqueue peer_rx;

	/* Name of the tx engine: output.$index */
	char name[40];
};

struct vpnet_info {
	struct virtio_device *vdev;
	struct net_device *dev;

	struct vpnet_tx_engine *tx;
	struct vpnet_rx_engine *rx;

	/*
	 * Control receivq: host to gust
	 */
	struct virtqueue *ctrlq;

	struct work_struct ctrlq_work;

	/* # queues used by the device */
	u16 vq_pairs;

	/* Packet virtio header size used by the peer */
	u8 peer_hdr_len;

	struct peer_mem_info pmem_info;

	/* Active statistics */
	struct vpnet_stats __percpu *stats;

	bool big_packets;

	bool mergeable_rx_bufs;

	/* Work struct for refilling if we run low on memory. */
	struct delayed_work refill;

	/* Work struct for config space updates */
	struct work_struct config_work;

	/* Does the affinity hint is set for virtqueues? */
	bool affinity_hint_set;

	/* CPU hot plug notifier */
	struct notifier_block nb;
};

struct vpnet_tx_peer_buf {
	volatile void *addr;
	u32 len;
};

static inline uint64_t peer_to_local(struct peer_mem_info *pmem_info, uint64_t peer_gpa)
{
	void *pmem_base = pmem_info->pmem_base;
	uint32_t i, nregions = pmem_info->nregions;
	struct peer_region_info *regions = pmem_info->regions;

	for (i = 0; i < nregions; i++) {
		if (peer_gpa > regions[i].start && peer_gpa < regions[i].end)
			return (peer_gpa - regions[i].start
				+ regions[i].offset
				+ (uint64_t)pmem_base);
	}
	return 0;
}

static unsigned int get_mergeable_buf_len(struct ewma_pkt_len *avg_pkt_len)
{
	const size_t hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	unsigned int len;

	len = hdr_len + clamp_t(unsigned int, ewma_pkt_len_read(avg_pkt_len),
			GOOD_PACKET_LEN, PAGE_SIZE - hdr_len);
	return ALIGN(len, MERGEABLE_BUFFER_ALIGN);
}

static void *mergeable_ctx_to_buf_address(unsigned long mrg_ctx)
{
	return (void *)(mrg_ctx & -MERGEABLE_BUFFER_ALIGN);
}

static unsigned long mergeable_buf_to_ctx(void *buf, unsigned int truesize)
{
	unsigned int size = truesize / MERGEABLE_BUFFER_ALIGN;
	return (unsigned long)buf | (size - 1);
}

static int vpnet_add_recvbuf_mergeable(struct vpnet_rx_engine *rx, gfp_t gfp)
{
	struct page_frag *alloc_frag = &rx->alloc_frag;
	char *buf;
	unsigned long ctx;
	int err;
	unsigned int len, hole;

	len = get_mergeable_buf_len(&rx->mrg_avg_pkt_len);

	if (unlikely(!skb_page_frag_refill(len, alloc_frag, gfp)))
		return -ENOMEM;

	buf = (char *)page_address(alloc_frag->page) + alloc_frag->offset;
	ctx = mergeable_buf_to_ctx(buf, len);
	get_page(alloc_frag->page);
	alloc_frag->offset += len;
	hole = alloc_frag->size - alloc_frag->offset;
	if (hole < len) {
		/* To avoid internal fragmentation, if there is very likely not
		 * enough space for another buffer, add the remaining space to
		 * the current buffer. This extra space is not included in
		 * the truesize stored in ctx.
		 */
		len += hole;
		alloc_frag->offset += hole;
	}

	sg_init_one(rx->sg, buf, len);
	err = virtqueue_add_inbuf(rx->vq, rx->sg, 1, (void *)ctx, gfp);
	if (err < 0)
		put_page(virt_to_head_page(buf));

	return err;
}

/*
 * Returns false if we couldn't fill entirely (OOM).
 *
 * Normally run in the receive path, but can also be run from ndo_open
 * before we're receiving packets, or from refill_work which is
 * careful to disable receiving (using napi_disable).
 */
static bool vpnet_try_fill_recv(struct vpnet_info *vi, struct vpnet_rx_engine *rx,
			  gfp_t gfp)
{
	int err;
	bool oom;

	gfp |= __GFP_COLD;
	do {
		err = vpnet_add_recvbuf_mergeable(rx, gfp);

		oom = err == -ENOMEM;
		if (err) {
			printk(KERN_EMERG"%s called: Out of Memory \n", __func__);
			break;
		}
	} while (rx->vq->num_free);
	return !oom;
}

static void vpnet_napi_enable(struct vpnet_rx_engine *rx)
{
	napi_enable(&rx->napi);

	/* If all buffers were filled by other side before we napi_enabled, we
	 * won't get another interrupt, so process any outstanding packets
	 * now.  virtnet_poll wants re-enable the queue, so we disable here.
	 * We synchronize against interrupts via NAPI_STATE_SCHED */
	if (napi_schedule_prep(&rx->napi)) {
		virtqueue_disable_cb(rx->vq);
		local_bh_disable();
		__napi_schedule(&rx->napi);
		local_bh_enable();
	}
}

static void refill_work(struct work_struct *work)
{
	struct vpnet_info *vi =
		container_of(work, struct vpnet_info, refill.work);
	bool still_empty;
	int i;

	for (i = 0; i < vi->vq_pairs; i++) {
		struct vpnet_rx_engine *rx = &vi->rx[i];

		napi_disable(&rx->napi);
		still_empty = !vpnet_try_fill_recv(vi, rx, GFP_KERNEL);
		vpnet_napi_enable(rx);

		/* In theory, this can happen: if we don't get any buffers in
		 * we will *never* try to fill again.
		 */
		if (still_empty)
			schedule_delayed_work(&vi->refill, HZ/2);
	}
}

/* FIXME */
static inline bool mrq_more_avail(struct peer_virtqueue *pvq)
{
	/* <CF: virtio16_to_cpu> */
	return pvq->vring.avail->idx - pvq->last_avail_idx > 0 ? 1 : 0;
}

static void __add_peer_used_n(struct peer_virtqueue *pvq,
			struct vring_used_elem *heads,
			unsigned count)
{
	volatile struct vring *pvring = &pvq->vring;
	volatile struct vring_used_elem *used;
	int start;

	start = pvq->last_used_idx & (pvring->num - 1);
	used = pvring->used->ring + start;
	if (count == 1) {
		used->id = heads[0].id;
		used->len = heads[0].len;
	} else {
		memcpy((void *)used, heads, count * sizeof(*used));
	}
	pvq->last_used_idx += count;
}

static int vpnet_add_peer_used_n(struct peer_virtqueue *pvq,
				struct vring_used_elem *heads,
				unsigned count)
{
	volatile struct vring *pvring = &pvq->vring;
	int start, n;

	start = pvq->last_used_idx & (pvring->num - 1);
	n = pvring->num - start;
	/* Boundary check*/
	if (n < count) {
		__add_peer_used_n(pvq, heads, n);
		count -= n;
		heads += n;
	}
	__add_peer_used_n(pvq, heads, count);

	/* order guarantee: buf filled before index updated */
	smp_wmb();

	pvring->used->idx = pvq->last_used_idx;

	return 0;
}

static unsigned vpnet_next_desc(struct vring_desc *desc)
{
	unsigned int next;

	/* If this descriptor says it doesn't chain, we're done. */
	if (!(desc->flags &  VRING_DESC_F_NEXT))
		return -1U;

	/* Check they're not leading us off end of descriptors. */
	next = desc->next;

	/* Make sure compiler knows to grab that: we don't want it changing! */
	/* We will use the result as an index in an array, so most
	 * architectures only need a compiler barrier here. */
	read_barrier_depends();

	return next;
}

static void *vpnet_rx_get_buf(struct vpnet_rx_engine *rx, u32 *len)
{
	return virtqueue_get_avail_buf(rx->vq, &rx->last_avail_idx, len);
}

static inline struct virtio_net_hdr_mrg_rxbuf *skb_vnet_hdr(struct sk_buff *skb)
{
	return (struct virtio_net_hdr_mrg_rxbuf *)skb->cb;
}

/* Called from bottom half context */
static struct sk_buff *vpnet_page_to_skb(struct vpnet_info *vi,
					 struct vpnet_rx_engine *rx,
					 struct page *page,
					 unsigned int offset,
					 unsigned int len,
					 unsigned int truesize)
{
	struct sk_buff *skb;
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	unsigned int copy, hdr_len, hdr_padded_len;
	char *p;

	p = page_address(page) + offset;

	/* copy small packet so we can reuse these pages for small data */
	skb = napi_alloc_skb(&rx->napi, GOOD_COPY_LEN);
	if (unlikely(!skb))
		return NULL;

	hdr = skb_vnet_hdr(skb);
	hdr_len = vi->peer_hdr_len;

	hdr_padded_len = sizeof *hdr;
	memcpy(hdr, p, hdr_len);

	len -= hdr_len;
	offset += hdr_padded_len;
	p += hdr_padded_len;

	copy = len;
	if (copy > skb_tailroom(skb)) {
//		printk(KERN_EMERG"%s called: Not copy all: only %d \n", __func__, copy);
		copy = skb_tailroom(skb);
	}
	memcpy(skb_put(skb, copy), p, copy);

	len -= copy;
	offset += copy;

	if (len) {
//		printk(KERN_EMERG"%s called: remaining len = %d \n", __func__, len);
		skb_add_rx_frag(skb, 0, page, offset, len, truesize);
	} else
		put_page(page);

	return skb;
}

static unsigned int mergeable_ctx_to_buf_truesize(unsigned long mrg_ctx)
{
	unsigned int truesize = mrg_ctx & (MERGEABLE_BUFFER_ALIGN - 1);
	return (truesize + 1) * MERGEABLE_BUFFER_ALIGN;
}

struct sk_buff *vpnet_buf_to_skb(struct vpnet_info *vi,
				  struct vpnet_rx_engine *rx,
				  void *buf, u32 len)
{
	struct sk_buff *skb;
	struct page *page = virt_to_head_page(buf);
	int offset = buf - page_address(page);
	unsigned int truesize = max(len, mergeable_ctx_to_buf_truesize((unsigned long)buf));

	skb = vpnet_page_to_skb(vi, rx, page, offset, len, truesize);
	return skb;
}

/* FIXME: temporarily not used */
static void disable_peer_notify(struct peer_virtqueue *pvq)
{
//	volatile __virtio16 *flags = &pvq->vring.used->flags;

//	*flags |= VRING_USED_F_NO_NOTIFY;
}

static void enable_peer_notify(struct peer_virtqueue *pvq)
{
//	volatile __virtio16 *flags = &pvq->vring.used->flags;

//	*flags |= ~VRING_USED_F_NO_NOTIFY;
}

static bool vpnet_rx_engine_poll(struct vpnet_rx_engine *rx)
{
	struct peer_virtqueue *peer_tx = &rx->peer_tx;
	struct vring *peer_vring = &peer_tx->vring;
	struct vring_avail *peer_avail = peer_vring->avail;
        volatile u16 *peer_avail_idx = &peer_avail->idx;

	if (*peer_avail_idx == peer_tx->last_avail_idx)
		return 0;

	/* Sanity check: abnormally too many packts */
	if (unlikely((u16)(*peer_avail_idx - peer_tx->last_avail_idx) >
	    peer_vring->num)) {
		printk(KERN_EMERG"%s called: abnormally too many packts in peer tx, *peer_avail_idx=%d, peer_tx->last_avail_idx = %d  \n", __func__, *peer_avail_idx, peer_tx->last_avail_idx);
		return 0;
	}

	return 1;
}

static unsigned int receive_buf(struct vpnet_rx_engine *rx)
{

	struct vpnet_info *vi = rx->vq->vdev->priv;
	struct peer_mem_info *pmem_info = &vi->pmem_info;
	struct peer_virtqueue *peer_tx = &rx->peer_tx;
	struct vring *peer_vring = &peer_tx->vring;
	struct vring_avail *peer_avail = peer_vring->avail;
	u16 peer_start;

	struct vring_desc *peer_desc;
	void *peer_buf, *my_buf;
	unsigned int i, peer_head, my_buf_len, received = 0;

	volatile struct virtio_net_hdr_mrg_rxbuf *hdr;

	struct vring_used_elem peer_used;
	struct net_device *dev = vi->dev;
	__virtio16 pkt_len;
	struct sk_buff *skb;
	struct vpnet_stats *stats = this_cpu_ptr(vi->stats);

	/*1. got a buf to receive? */
	if (!vpnet_rx_engine_poll(rx))
		return 0;

	/* 2. Get peer_buf */
	peer_start = peer_tx->last_avail_idx & (peer_vring->num - 1);
	/* grab the next head descriptor number */
	peer_head = peer_avail->ring[peer_start];
	/* Sanity check */
	if (unlikely(peer_head > peer_vring->num)) {
		printk(KERN_EMERG"%s called: vring_head > vr->num \n",
		       __func__);
		return 0;
	}
	/* OK, peer vq is ready to grab.. Let's go! */
	i = peer_head;

	do {
rbuf_retry:
		/* 3. check my vq: can we get free buffer to receive the packets */
		my_buf = vpnet_rx_get_buf(vi->rx, &my_buf_len);
		/* No more avail buf? Let's fill some */
		if (my_buf == NULL) {
			printk(KERN_EMERG"%s called: r_buf==========NULL\n", __func__);
			if (!vpnet_try_fill_recv(vi, rx, GFP_ATOMIC)) {
				schedule_delayed_work(&vi->refill, 0);
				return 0;
			}
			/* Looks like we've got some fresh buffer..yeah! */
			goto rbuf_retry;
		}
		my_buf = mergeable_ctx_to_buf_address((unsigned long)my_buf);

		peer_desc = peer_vring->desc + i;
		peer_buf = (void *)peer_to_local(pmem_info, peer_desc->addr);
		if (peer_buf == NULL) {
			printk(KERN_EMERG"%s called: peer_buf == null", __func__);
			return 0;
		}

		hdr = peer_buf;
		pkt_len = hdr->hdr.pkt_len;

		/* 4. Copy */
		memcpy(my_buf, (void *)peer_buf, hdr->hdr.pkt_len);

		/* 5. skb delivery */
		skb = vpnet_buf_to_skb(vi, rx, my_buf, hdr->hdr.pkt_len);
		skb->protocol = eth_type_trans(skb, dev);
		napi_gro_receive(&rx->napi, skb);

		/* 6. statistics update */
		u64_stats_update_begin(&stats->rx_syncp);
		stats->rx_bytes += skb->len;
		stats->rx_packets++;
		u64_stats_update_end(&stats->rx_syncp);
		received++;
	} while((i = vpnet_next_desc(peer_desc)) != -1);

	/* 7. peer Used */
	peer_used.id = peer_head;
	peer_used.len = pkt_len;
	vpnet_add_peer_used_n(peer_tx, &peer_used, 1);
	(peer_tx->last_avail_idx)++;

	ewma_pkt_len_add(&rx->mrg_avg_pkt_len, skb->len);

	return received;
}

static int vpnet_rx_engine_run(struct vpnet_rx_engine *rx, int budget)
{
	struct vpnet_info *vi = rx->vq->vdev->priv;
	unsigned int received = 0;

	while (received < budget &&
	       vpnet_rx_engine_poll(rx)) {
		received = receive_buf(rx);
	}

	if (rx->vq->num_free > virtqueue_get_vring_size(rx->vq) / 2) {
		if (!vpnet_try_fill_recv(vi, rx, GFP_ATOMIC)) {
			printk(KERN_EMERG"%s called: delay the rx buffer fill \n", __func__);
			schedule_delayed_work(&vi->refill, 0);
		}
	}

	return received;
}

static int vpnet_poll(struct napi_struct *napi, int budget)
{
	struct vpnet_rx_engine *rx =
		container_of(napi, struct vpnet_rx_engine, napi);
	unsigned int received = 0;

	received = vpnet_rx_engine_run(rx, budget);

	/* Out of Packets */
	if (received < budget) {
		enable_peer_notify(&rx->peer_tx);
		napi_complete_done(napi, received);
		if (unlikely(vpnet_rx_engine_poll(rx)) &&
		    napi_schedule_prep(napi)) {
			disable_peer_notify(&rx->peer_tx);
			__napi_schedule(napi);

		}
	}

	return received;
}

static int vpnet_alloc_engines(struct vpnet_info *vi)
{
	int i;
	u16 vq_pairs = vi->vq_pairs;

	vi->tx = kzalloc(sizeof(struct vpnet_tx_engine) * vq_pairs, GFP_KERNEL);
	if (!vi->tx)
		goto err_tx;
	vi->rx = kzalloc(sizeof(struct vpnet_rx_engine) * vq_pairs, GFP_KERNEL);
	if (!vi->rx)
		goto err_rx;

	INIT_DELAYED_WORK(&vi->refill, refill_work);
	for (i = 0; i < vq_pairs; i++) {
		vi->rx[i].pages = NULL;
		netif_napi_add(vi->dev, &vi->rx[i].napi, vpnet_poll,
			       napi_weight);

		sg_init_table(vi->rx[i].sg, ARRAY_SIZE(vi->rx[i].sg));
		ewma_pkt_len_init(&vi->rx[i].mrg_avg_pkt_len);
	}

	return 0;

err_rx:
	kfree(vi->tx);
err_tx:
	return -ENOMEM;
}

static void vpnet_free_buf(struct ctrlq_buf *buf)
{
	unsigned int i;

	for (i = 0; i < buf->sgpages; i++) {
		struct page *page = sg_page(&buf->sg[i]);
		if (!page)
			break;
		put_page(page);
	}
	kfree(buf->buf);
	kfree(buf);
}

static int vpnet_add_inbuf(struct virtqueue *vq, struct ctrlq_buf *buf)
{
	struct scatterlist sg[1];
	int ret;

	sg_init_one(sg, buf->buf, buf->size);

	ret = virtqueue_add_inbuf(vq, sg, 1, buf, GFP_ATOMIC);
//	virtqueue_kick(vq);
	if (!ret)
		ret = vq->num_free;
	return ret;
}

static void handle_pmem_msg(struct vpnet_info *vi,
			    struct peer_mem_msg *pmem_msg)
{
	struct peer_mem_info *pmem_info = &vi->pmem_info;
	struct peer_region_info *pregion_info;
	struct pmem_region_msg *pregion_msg;
	uint32_t nregions, i;

	nregions = pmem_msg->nregions;
	pmem_info->nregions = nregions;
	for (i = 0; i < nregions; i++) {
		pregion_info = &pmem_info->regions[i];
		pregion_msg = &pmem_msg->regions[i];
		pregion_info->start = pregion_msg->gpa;
		pregion_info->end = pregion_msg->gpa + pregion_msg->size;
		if (i == 0)
			pregion_info->offset = 0;
		else
			pregion_info->offset = pmem_info->regions[i-1].offset +
						pmem_msg->regions[i-1].size;
	}
}

#define VPNET_PEER_RX 0
#define VPNET_PEER_TX 1
static void handle_pvq_msg(struct vpnet_info *vi,
                               struct peer_vqs_msg *pvqs_msg)
{
	struct peer_virtqueue *peer_rx, *peer_tx;
	struct peer_vq_msg *pvq_msg;
	struct peer_mem_info *pmem_info = &vi->pmem_info;
	uint32_t i, total_vqs;
	struct vring *peer_vring;
	void *desc_addr, *avail_addr, *used_addr;
printk(KERN_EMERG"%s called.. 1\n", __func__);

	total_vqs = pvqs_msg->nvqs;
	if (total_vqs != vi->vq_pairs * 2)
		printk("%s called: peer_virtqueue_num error \n", __func__);

	for (i = 0; i < total_vqs; i++) {
		pvq_msg = &pvqs_msg->pvq_msg[i];
		peer_rx = &vi->tx[i/2].peer_rx;
		peer_tx = &vi->rx[i/2].peer_tx;
		desc_addr = (void *)peer_to_local(pmem_info, pvq_msg->desc_gpa);
		avail_addr = (void *)peer_to_local(pmem_info, pvq_msg->avail_gpa);
		used_addr = (void *)peer_to_local(pmem_info, pvq_msg->used_gpa);

		if (pvq_msg->vring_num % 2 == VPNET_PEER_RX) {
			peer_vring = &peer_rx->vring;
			peer_vring->num = 256;
			peer_vring->desc = desc_addr;
			peer_vring->avail = avail_addr;
			peer_vring->used = used_addr;
			peer_rx->last_avail_idx = 0;
			peer_rx->last_used_idx = 0;
			peer_rx->enabled = pvq_msg->vring_enable;
		} else {
			peer_vring = &peer_tx->vring;
			peer_vring->num = 256;
			peer_vring->desc = desc_addr;
			peer_vring->avail = avail_addr;
			peer_vring->used = used_addr;
			peer_tx->last_avail_idx = 0;
			peer_tx->last_used_idx = 0;
			peer_tx->enabled = pvq_msg->vring_enable;
		}
	}
}

static void vpnet_config_changed_work(struct work_struct *work)
{
	struct vpnet_info *vi =
		container_of(work, struct vpnet_info, config_work);
	u16 value;

	virtio_cread(vi->vdev, struct vhost_pci_net_config, status, &value);

	if (value & VPNET_S_LINK_UP) {
		netif_carrier_on(vi->dev);
		printk(KERN_EMERG"%s called: LINK UP \n", __func__);
	} else {
		netif_carrier_off(vi->dev);
		printk(KERN_EMERG"%s called: LINK DOWN \n", __func__);
	}
}

static void vpnet_config_changed(struct virtio_device *vdev)
{
	struct vpnet_info *vi = vdev->priv;

	schedule_work(&vi->config_work);
}
static void ctrlq_work_handler(struct work_struct *work)
{
	struct ctrlq_buf *buf;
	struct vpnet_controlq_msg *msg;
	struct peer_mem_msg *pmem_msg;
        struct peer_vqs_msg *pvqs_msg;
	struct vpnet_info *vi;
	struct virtqueue *ctrlq;
	unsigned int len;

	vi = container_of(work, struct vpnet_info, ctrlq_work);
	ctrlq = vi->ctrlq;

	while ((buf = virtqueue_get_buf(ctrlq, &len))) {
		buf->len = len;
		buf->offset = 0;
		msg = (struct vpnet_controlq_msg *)buf->buf;
		switch (msg->class) {
		case VHOST_PCI_CTRL_PEER_MEM_MSG:
			pmem_msg = &msg->payload.pmem_msg;
			handle_pmem_msg(vi, pmem_msg);
			break;
		case VHOST_PCI_CTRL_PEER_VQ_MSG:
			pvqs_msg = &msg->payload.pvqs_msg;
			handle_pvq_msg(vi, pvqs_msg);
			break;
		default:
			printk("%s called: default.. \n", __func__);
		}

		if (vpnet_add_inbuf(ctrlq, buf) < 0) {
			printk("%s: Error adding buffer to queue \n", __func__);
			vpnet_free_buf(buf);
		}
	}
}

static void ctrlq_intr(struct virtqueue *ctrlq)
{
	struct vpnet_info *vi = ctrlq->vdev->priv;

	schedule_work(&vi->ctrlq_work);
}
#if 0
/* Converting between virtqueue no. and kernel tx/rx queue no.
 * 0:rx0 1:tx0 2:rx1 3:tx1 ... 2N:rxN 2N+1:txN 2N+2:cvq
 */
static int vq2tx(struct virtqueue *vq)
{
	return (vq->index - 1) / 2;
}
#endif

static int vq2rx(struct virtqueue *vq)
{
	return vq->index / 2;
}

static void skb_recv_done(struct virtqueue *vq)
{
	struct vpnet_info *vi = vq->vdev->priv;
	struct vpnet_rx_engine *rx = &vi->rx[vq2rx(vq)];
	/* Schedule NAPI, Suppress further interrupts if successful. */
	if (napi_schedule_prep(&rx->napi)) {
		disable_peer_notify(&rx->peer_tx);
		__napi_schedule(&rx->napi);
	}
}

static void skb_xmit_done(struct virtqueue *vq)
{
//	printk(KERN_EMERG"%s called..\n", __func__);
#if 0
	struct vpnet_info *vi = vq->vdev->priv;
	struct vpnet_tx_engine *tx = &vi->tx[vq2tx(vq)];

	if (tx->peer_rx.vring.desc) {
		disable_peer_notify(&tx->peer_rx);

		/* We were probably waiting for more output buffers. */
		netif_wake_subqueue(vi->dev, vq2tx(vq));
	}
#endif
}

static int rxq2vq(int rxq)
{
	return rxq * 2;
}

static int txq2vq(int txq)
{
	return txq * 2 + 1;
}

static int vpnet_find_vqs(struct vpnet_info *vi)
{
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	int ret = -ENOMEM;
	uint32_t i, total_vqs;
	const char **names;
	u16 vq_pairs = vi->vq_pairs;

	total_vqs = vq_pairs * 2 + 1;
	/* Allocate space for find_vqs parameters */
	vqs = kzalloc(total_vqs * sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vq;
	callbacks = kmalloc(total_vqs * sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks)
		goto err_callback;
	names = kmalloc(total_vqs * sizeof(*names), GFP_KERNEL);
	if (!names)
		goto err_names;

        /* Controlq Parameters */
	names[total_vqs - 1] = "controlq";
        callbacks[total_vqs - 1] = ctrlq_intr;

        /* tx/rx vq Parameters */
	for (i = 0; i < vq_pairs; i++) {
		callbacks[rxq2vq(i)] = skb_recv_done;
		callbacks[txq2vq(i)] = skb_xmit_done;
		sprintf(vi->rx[i].name, "input.%d", i);
		sprintf(vi->tx[i].name, "output.%d", i);
		names[rxq2vq(i)] = vi->rx[i].name;
		names[txq2vq(i)] = vi->tx[i].name;
	}

	ret = vi->vdev->config->find_vqs(vi->vdev, total_vqs, vqs, callbacks,
					 names);
	if (ret)
		goto err_find;

	vi->ctrlq = vqs[total_vqs - 1];
	for (i = 0; i < vq_pairs; i++) {
		vi->rx[i].vq = vqs[rxq2vq(i)];
		vi->tx[i].vq = vqs[txq2vq(i)];
		vring_set_remote_peer_support(vi->rx[i].vq, true);
		vring_set_remote_peer_support(vi->tx[i].vq, true);
	}

	kfree(names);
	kfree(callbacks);
	kfree(vqs);

	return 0;

err_find:
	kfree(names);
err_names:
	kfree(callbacks);
err_callback:
	kfree(vqs);
err_vq:
	return ret;
}

static void vpnet_free_queues(struct vpnet_info *vi)
{
	int i;

	for (i = 0; i < vi->vq_pairs; i++) {
		napi_hash_del(&vi->rx[i].napi);
		netif_napi_del(&vi->rx[i].napi);
	}

	kfree(vi->rx);
	kfree(vi->tx);
}

static int vpnet_init_engines(struct vpnet_info *vi)
{
	int ret;

	/* Allocate own queues */
	ret = vpnet_alloc_engines(vi);
	if (ret)
		goto err;

	ret = vpnet_find_vqs(vi);
	if (ret)
		goto err_free;

	return 0;

err_free:
	vpnet_free_queues(vi);
err:
	return ret;
}

static int vpnet_open(struct net_device *dev)
{
	struct vpnet_info *vi = netdev_priv(dev);
	int i;
	printk(KERN_EMERG"%s called..\n", __func__);

	for (i = 0; i < vi->vq_pairs; i++) {
		/* Make sure we have some buffers: if oom use wq. */
		if (!vpnet_try_fill_recv(vi, &vi->rx[i], GFP_KERNEL))
			schedule_delayed_work(&vi->refill, 0);
		vpnet_napi_enable(&vi->rx[i]);
	}

	return 0;
}

static int vpnet_close(struct net_device *dev)
{
	printk(KERN_EMERG"%s called..\n", __func__);
	return 0;
}

static noinline u32 vpnet_tx_get_peer_buf(struct vpnet_info *vi, struct vpnet_tx_peer_buf *buf)
{
	struct peer_virtqueue *peer_rx = &vi->tx[0].peer_rx;
	struct peer_mem_info *pmem_info = &vi->pmem_info;
	volatile struct vring *rx_vring = &peer_rx->vring;
	volatile struct vring_avail *rx_avail = rx_vring->avail;
	volatile u16 *avail_idx = &rx_avail->idx;
	unsigned int head, start;
	struct vring_desc *desc;

	/* wait if the peer haven't got fresh buf ready */
	while (peer_rx->last_avail_idx == *avail_idx);

	start = peer_rx->last_avail_idx & (rx_vring->num - 1);
	/* grab the next head descriptor number */
	head = rx_avail->ring[start];
	/* Sanity check */
	if (unlikely(head > rx_vring->num)) {
		printk(KERN_EMERG"%s called: vring_head > rx_vring->num \n",
		       __func__);
		return 0;
	}

	desc = rx_vring->desc + head;
	buf->addr = (volatile void *)peer_to_local(pmem_info, desc->addr);
	buf->len = desc->len;
	(peer_rx->last_avail_idx)++;
	return head;
}

static inline void vpnet_tx_engine_run(struct vpnet_info *vi, void *data, u64 len)
{
	struct vpnet_tx_peer_buf buf;
	struct vring_used_elem head;

	head.id = vpnet_tx_get_peer_buf(vi, &buf);
	if (len > buf.len) {
		/* FIXME */
		printk(KERN_EMERG"%s called: large len: len = %lld, buf.len = %d\n", __func__, len, buf.len);
		len = buf.len;
	}
	memcpy((void *)buf.addr, data, len);
	head.len = len;
	vpnet_add_peer_used_n(&vi->tx[0].peer_rx, &head, 1);
}

static int xmit_skb(struct vpnet_info *vi, struct sk_buff *skb)
{
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	unsigned hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);

	/* Even if we can, don't push here yet as this would skew
	 * csum_start offset below. */
	hdr = (struct virtio_net_hdr_mrg_rxbuf *)(skb->data - hdr_len);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		hdr->hdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		hdr->hdr.csum_start = __cpu_to_virtio16(1, skb_checksum_start_offset(skb));
		hdr->hdr.csum_offset = __cpu_to_virtio16(1, skb->csum_offset);
	} else {
		hdr->hdr.flags = 0;
		hdr->hdr.csum_offset = hdr->hdr.csum_start = 0;
	}

	if (skb_is_gso(skb)) {
		hdr->hdr.hdr_len = __cpu_to_virtio16(1, skb_headlen(skb));
		hdr->hdr.gso_size = __cpu_to_virtio16(1, skb_shinfo(skb)->gso_size);
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4)
			hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		else if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6)
			hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		else if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP)
			hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_UDP;
		else
			BUG();
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCP_ECN)
			hdr->hdr.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
	} else {
		hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
		hdr->hdr.gso_size = hdr->hdr.hdr_len = 0;
	}
	hdr->num_buffers = 1;

	__skb_push(skb, hdr_len);
	vpnet_tx_engine_run(vi, skb->data, (u64)skb->len);
	__skb_pull(skb, hdr_len);

	return 0;
}

static inline bool should_notify_peer(struct peer_virtqueue *pvq)
{
	volatile __virtio16 *flags = &pvq->vring.avail->flags;

	if (*flags & VRING_AVAIL_F_NO_INTERRUPT)
		return 0;
	else
		return 1;
}

static netdev_tx_t start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct vpnet_info *vi = netdev_priv(dev);
	struct vpnet_stats *stats = this_cpu_ptr(vi->stats);

	xmit_skb(vi, skb);

	stats->tx_bytes += skb->len;
	stats->tx_packets++;
	u64_stats_update_end(&stats->tx_syncp);

	/* free sthe sending skb */
	skb_orphan(skb);
	nf_reset(skb);
	dev_kfree_skb_any(skb);

	if (should_notify_peer(&vi->tx[0].peer_rx))
		virtqueue_notify(vi->tx[0].vq);

	return NETDEV_TX_OK;
}

static int vpnet_set_mac_address(struct net_device *dev, void *p)
{
	printk("%s called..\n", __func__);
	return 0;
}

static void vpnet_set_rx_mode(struct net_device *dev)
{
	printk("%s called..\n", __func__);
}

#define MIN_MTU 68
#define MAX_MTU 65535

static int vpnet_change_mtu(struct net_device *dev, int new_mtu)
{
	struct vpnet_info *vi = netdev_priv(dev);
	if (new_mtu < MIN_MTU || new_mtu > MAX_MTU)
		return -EINVAL;

	if (new_mtu == 60001){
		printk(KERN_EMERG"%s called: 60001 \n", __func__);
//		netif_carrier_on(vi->dev);
//		vpnet_mirrored_rq_avail_get_buf(vi);
		virtqueue_kick(vi->tx->vq);
		return 0;
	} else if (new_mtu == 60002) {
		printk(KERN_EMERG"%s called: 60002 \n", __func__);
//		netif_carrier_off(vi->dev);
		virtqueue_kick(vi->rx->vq);
		return 0;
	}

	dev->mtu = new_mtu;
	return 0;
}

static struct rtnl_link_stats64 *vpnet_stats_func(struct net_device *dev,
					       struct rtnl_link_stats64 *tot)
{
	struct vpnet_info *vi = netdev_priv(dev);
	int cpu;
	unsigned int start;

	for_each_possible_cpu(cpu) {
		struct vpnet_stats *stats = per_cpu_ptr(vi->stats, cpu);
		u64 tpackets, tbytes, rpackets, rbytes;

		do {
			start = u64_stats_fetch_begin_irq(&stats->tx_syncp);
			tpackets = stats->tx_packets;
			tbytes   = stats->tx_bytes;
		} while (u64_stats_fetch_retry_irq(&stats->tx_syncp, start));

		do {
			start = u64_stats_fetch_begin_irq(&stats->rx_syncp);
			rpackets = stats->rx_packets;
			rbytes   = stats->rx_bytes;
		} while (u64_stats_fetch_retry_irq(&stats->rx_syncp, start));

		tot->rx_packets += rpackets;
		tot->tx_packets += tpackets;
		tot->rx_bytes   += rbytes;
		tot->tx_bytes   += tbytes;
	}

	tot->tx_dropped = dev->stats.tx_dropped;
	tot->tx_fifo_errors = dev->stats.tx_fifo_errors;
	tot->rx_dropped = dev->stats.rx_dropped;
	tot->rx_length_errors = dev->stats.rx_length_errors;
	tot->rx_frame_errors = dev->stats.rx_frame_errors;

	return tot;
}

static int vpnet_vlan_rx_add_vid(struct net_device *dev,
				   __be16 proto, u16 vid)
{
	printk("%s called..\n", __func__);
	return 0;
}

static int vpnet_vlan_rx_kill_vid(struct net_device *dev,
				    __be16 proto, u16 vid)
{
	printk("%s called..\n", __func__);
	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void vpnet_netpoll(struct net_device *dev)
{
	printk("%s called..\n", __func__);
}
#endif

#ifdef CONFIG_NET_RX_BUSY_POLL
/* must be called with local_bh_disable()d */
static int vpnet_busy_poll(struct napi_struct *napi)
{
	printk("%s called..\n", __func__);
	return 0;
}
#endif	/* CONFIG_NET_RX_BUSY_POLL */

static const struct net_device_ops vpnet_netdev = {
	.ndo_open            = vpnet_open,
	.ndo_stop   	     = vpnet_close,
	.ndo_start_xmit      = start_xmit,
	.ndo_validate_addr   = eth_validate_addr,
	.ndo_set_mac_address = vpnet_set_mac_address,
	.ndo_set_rx_mode     = vpnet_set_rx_mode,
	.ndo_change_mtu	     = vpnet_change_mtu,
	.ndo_get_stats64     = vpnet_stats_func,
	.ndo_vlan_rx_add_vid = vpnet_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = vpnet_vlan_rx_kill_vid,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = vpnet_netpoll,
#endif
#ifdef CONFIG_NET_RX_BUSY_POLL
	.ndo_busy_poll		= vpnet_busy_poll,
#endif
};

static void vpnet_get_drvinfo(struct net_device *dev,
				struct ethtool_drvinfo *info)
{
	printk("%s called..\n", __func__);
}

static void vpnet_get_ringparam(struct net_device *dev,
				struct ethtool_ringparam *ring)
{
	printk("%s called..\n", __func__);
}

/* TODO: Eliminate OOO packets during switching */
static int vpnet_set_channels(struct net_device *dev,
				struct ethtool_channels *channels)
{
	printk("%s called..\n", __func__);
	return 0;
}

static void vpnet_get_channels(struct net_device *dev,
				 struct ethtool_channels *channels)
{
	printk("%s called..\n", __func__);
}

static int vpnet_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	printk("%s called..\n", __func__);
	return 0;
}

static int vpnet_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	printk("%s called..\n", __func__);
	return 0;
}

static struct ctrlq_buf *vpnet_alloc_buf(struct virtqueue *vq, size_t buf_size,
				       int pages)
{
	struct ctrlq_buf *buf;

	/*
	 * Allocate buffer and the sg list. The sg list array is allocated
	 * directly after the ctrlq_buffer struct.
	 */
	buf = kmalloc(sizeof(*buf) + sizeof(struct scatterlist) * pages,
		      GFP_KERNEL);
	if (!buf)
		goto fail;

	buf->sgpages = pages;
	if (pages > 0) {
		buf->buf = NULL;
		return buf;
	}

	buf->buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf->buf)
		goto free_buf;
	buf->len = 0;
	buf->offset = 0;
	buf->size = buf_size;
	return buf;

free_buf:
	kfree(buf);
fail:
	return NULL;
}

static unsigned int vpnet_fill_queue(struct virtqueue *vq)
{
	struct ctrlq_buf *buf;
	unsigned int nr_added_bufs;
	int ret;

	nr_added_bufs = 0;
	do {
		buf = vpnet_alloc_buf(vq, PAGE_SIZE, 0);
		if (!buf)
			break;

		ret = vpnet_add_inbuf(vq, buf);
		if (ret < 0) {
			vpnet_free_buf(buf);
			break;
		}
		nr_added_bufs++;
	} while (ret > 0);

	return nr_added_bufs;
}

static const struct ethtool_ops vpnet_ethtool_ops = {
	.get_drvinfo = vpnet_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_ringparam = vpnet_get_ringparam,
	.set_channels = vpnet_set_channels,
	.get_channels = vpnet_get_channels,
	.get_ts_info = ethtool_op_get_ts_info,
	.get_settings = vpnet_get_settings,
	.set_settings = vpnet_set_settings,
};

static int vpnet_probe(struct virtio_device *vdev)
{
	int i, err;
	struct net_device *dev;
	struct vpnet_info *vi;
	struct peer_mem_info *pmem_info;
	struct device *host_dev;
	struct pci_dev *pci_dev;
	u64 bar2_base, bar2_len;
	u16 vq_pairs;
	unsigned int nr_added_bufs;

	virtio_cread((vdev), struct vhost_pci_net_config, vq_pairs, &vq_pairs);
	/* Allocate ourselves a network device with room for our info */
	dev = alloc_etherdev_mq(sizeof(struct vpnet_info), vq_pairs);
	if (!dev)
		return -ENOMEM;

	/* Set up network device as normal. */
	dev->priv_flags |= IFF_UNICAST_FLT | IFF_LIVE_ADDR_CHANGE;
	dev->netdev_ops = &vpnet_netdev;
	dev->features = NETIF_F_HIGHDMA;

	dev->ethtool_ops = &vpnet_ethtool_ops;
	SET_NETDEV_DEV(dev, &vdev->dev);

	eth_hw_addr_random(dev);
	/* Set up our device-specific information */
	vi = netdev_priv(dev);
	vi->dev = dev;
	vi->vdev = vdev;
	vdev->priv = vi;
	vi->stats = alloc_percpu(struct vpnet_stats);
	vi->peer_hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	err = -ENOMEM;
	if (vi->stats == NULL)
		goto free;

	for_each_possible_cpu(i) {
		struct vpnet_stats *vpnet_stats;
		vpnet_stats = per_cpu_ptr(vi->stats, i);
		u64_stats_init(&vpnet_stats->tx_syncp);
		u64_stats_init(&vpnet_stats->rx_syncp);
	}
        vi->vq_pairs = vq_pairs;
	if (vpnet_init_engines(vi) < 0)
		goto free;

	INIT_WORK(&vi->ctrlq_work, &ctrlq_work_handler);
	INIT_WORK(&vi->config_work, vpnet_config_changed_work);

	nr_added_bufs = vpnet_fill_queue(vi->ctrlq);
	if (!nr_added_bufs) {
		printk(KERN_EMERG"%s called: Error allocating inbufs\n", __func__);
		goto free;
	}

	host_dev = vdev->dev.parent;
	pmem_info = &vi->pmem_info;
	if (dev_is_pci(host_dev)) {
		pci_dev = to_pci_dev(host_dev);
		bar2_base = pci_resource_start(pci_dev, 2);
		bar2_len = pci_resource_len(pci_dev, 2);
		pmem_info->pmem_base = ioremap_cache(bar2_base, bar2_len);
		printk(KERN_EMERG"%s called: pmem_base = %p \n", __func__, pmem_info->pmem_base);
	}

	err = register_netdev(dev);
	if (err) {
		printk(KERN_EMERG"Vhost_pci_net called: registering device failed\n");
		goto free;
	}

	netif_carrier_off(dev);

	virtio_device_ready(vdev);

	return 0;
free:
	free_netdev(dev);
	return err;
}

#if 0
static void free_unused_bufs(struct vpnet_info *vi)
{
	void *buf;
	int i;

	for (i = 0; i < vi->rq_num; i++) {
		struct virtqueue *vq = vi->rq[i].vq;

		while ((buf = virtqueue_detach_unused_buf(vq)) != NULL) {
			if (vi->mergeable_rx_bufs) {
				unsigned long ctx = (unsigned long)buf;
				void *base = mergeable_ctx_to_buf_address(ctx);
				put_page(virt_to_head_page(base));
			} else if (vi->big_packets) {
	//			give_pages(&vi->rq[i], buf);
			} else {
	//			dev_kfree_skb(buf);
			}
		}
	}
}

static void vpnet_del_vqs(struct vpnet_info *vi)
{
	struct virtio_device *vdev = vi->vdev;

//	virtnet_clean_affinity(vi, -1);

	vdev->config->del_vqs(vdev);

	vpnet_free_queues(vi);
}

static void free_receive_page_frags(struct vpnet_info *vi)
{
	int i;
	for (i = 0; i < vi->rq_num; i++)
		if (vi->rq[i].alloc_frag.page)
			put_page(vi->rq[i].alloc_frag.page);
}

static struct page *get_a_page(struct receive_queue *rq, gfp_t gfp_mask)
{
	struct page *p = rq->pages;

	if (p) {
		rq->pages = (struct page *)p->private;
		/* clear private here, it is used to chain pages */
		p->private = 0;
	} else
		p = alloc_page(gfp_mask);
	return p;
}

static void free_receive_bufs(struct vpnet_info *vi)
{
	int i;

	for (i = 0; i < vi->rq_num; i++) {
		while (vi->rq[i].pages)
			__free_pages(get_a_page(&vi->rq[i], GFP_KERNEL), 0);
	}
}

static void remove_vq_common(struct vpnet_info *vi)
{
	vi->vdev->config->reset(vi->vdev);

	/* Free unused buffers in rq, if any. */
	free_unused_bufs(vi);

//	free_receive_bufs(vi);

	free_receive_page_frags(vi);

	vpnet_del_vqs(vi);
}
#endif

static void vpnet_remove(struct virtio_device *vdev)
{
	printk("\n %s called:.. \n", __func__);
#if 0
	struct vpnet_info *vi = vdev->priv;
	struct peer_mem_info *pmem_info = &vi->pmem_info;

        iounmap(pmem_info->pmem_base);
	/* Make sure no work handler is accessing the device. */
	flush_work(&vi->config_work);
	flush_work(&vi->ctrlq_work);

	unregister_netdev(vi->dev);

//	remove_vq_common(vi);

	free_percpu(vi->stats);
	free_netdev(vi->dev);
#endif
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_VHOST_PCI_NET, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_CTRL_VQ,
        VIRTIO_NET_F_MQ,
};

#ifdef CONFIG_PM_SLEEP
static int vpnet_freeze(struct virtio_device *vdev)
{
	printk("%s called..\n", __func__);
	return 0;
}

static int vpnet_restore(struct virtio_device *vdev)
{
	printk("%s called..\n", __func__);
	return 0;
}
#endif

static struct virtio_driver vhost_pci_net_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	vpnet_probe,
	.remove =	vpnet_remove,
	.config_changed = vpnet_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze =	vpnet_freeze,
	.restore =	vpnet_restore,
#endif
};

module_virtio_driver(vhost_pci_net_driver);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Vhost-pci network driver");
MODULE_LICENSE("GPL");
