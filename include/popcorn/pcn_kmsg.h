/**
 * Header file for Popcorn inter-kernel messaging layer
 *
 * (C) Ben Shelton   <beshelto@vt.edu> 2013
 *     Sang-Hoon Kim <sanghoon@vt.edu> 2017-2018
 */

#ifndef __POPCORN_PCN_KMSG_H__
#define __POPCORN_PCN_KMSG_H__

#include <linux/types.h>

#define MULTI_CONN_PER_NODE 0

//#define MAX_POPCORN_THREADS ARM_THREADS
#define MAX_POPCORN_THREADS 96

/* Enumerate message types */
enum pcn_kmsg_type {
	/* Thread migration */
	PCN_KMSG_TYPE_NODE_INFO,
	PCN_KMSG_TYPE_STAT_START,
	PCN_KMSG_TYPE_TASK_MIGRATE,
	PCN_KMSG_TYPE_TASK_MIGRATE_BACK,
	PCN_KMSG_TYPE_TASK_PAIRING,
	PCN_KMSG_TYPE_TASK_EXIT_ORIGIN,
	PCN_KMSG_TYPE_TASK_EXIT_REMOTE,

	/* VMA synchronization */
	PCN_KMSG_TYPE_VMA_INFO_REQUEST,
	PCN_KMSG_TYPE_VMA_INFO_RESPONSE,
	PCN_KMSG_TYPE_VMA_OP_REQUEST,
	PCN_KMSG_TYPE_VMA_OP_RESPONSE,

	/* Page consistency protocol */
	PCN_KMSG_TYPE_REMOTE_PAGE_REQUEST,
	PCN_KMSG_TYPE_REMOTE_PAGE_RESPONSE,
	PCN_KMSG_TYPE_REMOTE_PAGE_RESPONSE_SHORT,
	PCN_KMSG_TYPE_PAGE_INVALIDATE_REQUEST,
	PCN_KMSG_TYPE_PAGE_INVALIDATE_RESPONSE,
	PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH,	/* XXX page flush is not working now */
	PCN_KMSG_TYPE_REMOTE_PAGE_RELEASE,
	PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH_ACK,

	/* Distributed futex */
	PCN_KMSG_TYPE_FUTEX_REQUEST,
	PCN_KMSG_TYPE_FUTEX_RESPONSE,
	PCN_KMSG_TYPE_STAT_END,

	/* Performance experiments */
	PCN_KMSG_TYPE_TEST_REQUEST,
	PCN_KMSG_TYPE_TEST_RESPONSE,
	PCN_KMSG_TYPE_TEST_RDMA_REQUEST,
	PCN_KMSG_TYPE_TEST_RDMA_RESPONSE,
	PCN_KMSG_TYPE_TEST_RDMA_DSMRR_REQUEST,
	PCN_KMSG_TYPE_TEST_RDMA_DSMRR_RESPONSE,

	/* Provide the single system image */
	PCN_KMSG_TYPE_REMOTE_PROC_CPUINFO_REQUEST,
	PCN_KMSG_TYPE_REMOTE_PROC_CPUINFO_RESPONSE,
	PCN_KMSG_TYPE_REMOTE_PROC_MEMINFO_REQUEST,
	PCN_KMSG_TYPE_REMOTE_PROC_MEMINFO_RESPONSE,
	PCN_KMSG_TYPE_REMOTE_PROC_PS_REQUEST,
	PCN_KMSG_TYPE_REMOTE_PROC_PS_RESPONSE,

	/* Hype */
	PCN_KMSG_TYPE_REMOTE_KVM_CREATE_REQUEST, /* !used */
	PCN_KMSG_TYPE_REMOTE_KVM_CREATE_RESPONSE, /* !used */

	PCN_KMSG_TYPE_ORIGIN_SIPI_REQUEST, /* !used */
	PCN_KMSG_TYPE_ORIGIN_SIPI_RESPONSE, /* !used */
	PCN_KMSG_TYPE_ORIGIN_BROADCAST_ACCEPT_IRQ_REQUEST, /* !used */
	PCN_KMSG_TYPE_ORIGIN_BROADCAST_ACCEPT_IRQ_RESPONSE, /* !used */
	PCN_KMSG_TYPE_ORIGIN_BROADCAST_APIC_REG_WRITE_REQUEST,
	PCN_KMSG_TYPE_ORIGIN_BROADCAST_APIC_REG_WRITE_RESPONSE,

	PCN_KMSG_TYPE_IPI_REQUEST,
	PCN_KMSG_TYPE_IPI_RESPONSE,

	PCN_KMSG_TYPE_SIG_REQUEST,
	PCN_KMSG_TYPE_SIG_RESPONSE,

	PCN_KMSG_TYPE_REMOTE_CHECKIN_VCPU_PID_REQUEST,
	PCN_KMSG_TYPE_REMOTE_CHECKIN_VCPU_PID_RESPONSE,
	PCN_KMSG_TYPE_ORIGIN_CHECKIN_VCPU_PID_REQUEST,
	PCN_KMSG_TYPE_ORIGIN_CHECKIN_VCPU_PID_RESPONSE,

	/* Pophype migration - sync up vcpu info */
	PCN_KMSG_TYPE_UPDATE_VCPU_REQUEST,
	PCN_KMSG_TYPE_UPDATE_VCPU_RESPONSE,

	/* File op */
	PCN_KMSG_TYPE_REMOTE_OPEN_REQUEST,
	PCN_KMSG_TYPE_REMOTE_OPEN_RESPONSE,

	PCN_KMSG_TYPE_DELEGATE_RW_REQUEST,
	PCN_KMSG_TYPE_DELEGATE_RW_RESPONSE,
//	PCN_KMSG_TYPE_ORIGIN_OPEN_REQUEST,

	/* remote asks other remote tgids */
	PCN_KMSG_TYPE_REMOTE_ASK_ORIGIN_TGID_REQUEST,
	PCN_KMSG_TYPE_ORIGIN_ASK_REMOTE_TGID_REQUEST,
	PCN_KMSG_TYPE_ORIGIN_ASK_REMOTE_TGID_RESPONSE,
	PCN_KMSG_TYPE_REMOTE_ASK_ORIGIN_TGID_RESPONSE,

	PCN_KMSG_TYPE_ORIGIN_BROADCAST_CPU_TABLE_REQUEST,
	PCN_KMSG_TYPE_ORIGIN_BROADCAST_CPU_TABLE_RESPONSE,
	PCN_KMSG_TYPE_UPDATE_CPU_TABLE_REQUEST_FIELDS,

	/* vhost-net: eventfd delegation */
	PCN_KMSG_TYPE_DELEGATE_EVENTFD_REQUEST,
	PCN_KMSG_TYPE_DELEGATE_EVENTFD_RESPONSE,

	/* vhost-net: optimization */
	PCN_KMSG_TYPE_DELEGATE_SKB_TX_REQUEST,
	PCN_KMSG_TYPE_DELEGATE_SKB_TX_RESPONSE,
	PCN_KMSG_TYPE_DELEGATE_NET_MSG_TX_REQUEST,
	PCN_KMSG_TYPE_DELEGATE_NET_MSG_TX_RESPONSE,

	      /* vhost-net: delegate tun->ops->sendmsg() */
       PCN_KMSG_TYPE_DELEGATE_TUNFD_REQUEST,
       PCN_KMSG_TYPE_DELEGATE_TUNFD_RESPONSE,

       /* vhost-net: send rx notification to remote */
       PCN_KMSG_TYPE_RX_NOTIFICATION_REQUEST,
       PCN_KMSG_TYPE_RX_NOTIFICATION_RESPONSE,

       /* vhost-net: peek_head_len() delegation */
       PCN_KMSG_TYPE_PEEK_HEAD_LEN_REQUEST,
       PCN_KMSG_TYPE_PEEK_HEAD_LEN_RESPONSE,

       /* vhost-net: tun->ops->recvmsg() delegation */
       PCN_KMSG_TYPE_DELEGATE_RECVMSG_REQUEST,
       PCN_KMSG_TYPE_DELEGATE_RECVMSG_RESPONSE,

	/* Schedule server */
	PCN_KMSG_TYPE_SCHED_PERIODIC,		/* XXX sched requires help!! */

	PCN_KMSG_TYPE_MAX
};

/* Enumerate message priority. XXX Priority is not supported yet. */
enum pcn_kmsg_prio {
	PCN_KMSG_PRIO_LOW,
	PCN_KMSG_PRIO_NORMAL,
	PCN_KMSG_PRIO_HIGH,
};

/* Message header */
struct pcn_kmsg_hdr {
	int from_nid			:6;	///* max node = 15 */
	enum pcn_kmsg_prio prio	:2;
	enum pcn_kmsg_type type	:8; ///* max type = 127 */
#if MULTI_CONN_PER_NODE
	unsigned int channel;		///* max node = */
#endif
	size_t size;
} __attribute__((packed));

#define PCN_KMSG_FROM_NID(x) \
	(((struct pcn_kmsg_message *)x)->header.from_nid)
#define PCN_KMSG_SIZE(x) (sizeof(struct pcn_kmsg_hdr) + x)

#define PCN_KMSG_MAX_SIZE (32UL << 10)
#define PCN_KMSG_MAX_PAYLOAD_SIZE \
	(PCN_KMSG_MAX_SIZE - sizeof(struct pcn_kmsg_hdr))


#define DEFINE_PCN_KMSG(type, fields) \
	typedef struct {				\
		struct pcn_kmsg_hdr header;	\
		fields;				\
	} __attribute__((packed)) type

struct pcn_kmsg_message {
	struct pcn_kmsg_hdr header;
	unsigned char payload[PCN_KMSG_MAX_PAYLOAD_SIZE];
} __attribute__((packed));

void pcn_kmsg_dump(struct pcn_kmsg_message *msg);


/* SETUP */

/* Function pointer to callback functions */
typedef int (*pcn_kmsg_cbftn)(struct pcn_kmsg_message *);

/* Register a callback function to handle the message type */
int pcn_kmsg_register_callback(enum pcn_kmsg_type type, pcn_kmsg_cbftn callback);

/* Unregister a callback function for the message type */
int pcn_kmsg_unregister_callback(enum pcn_kmsg_type type);


/* MESSAGING */

/**
 * Send @msg whose size is @msg_size to the node @dest_nid.
 * @msg is sent synchronously; it is safe to deallocate @msg after the return.
 */
int pcn_kmsg_send(enum pcn_kmsg_type type, int dest_nid, void *msg, size_t msg_size);

/**
 * Post @msg whose size is @msg_size to be sent to the node @dest_nid.
 * The message should be allocated through pcn_kmsg_get(), and the message
 * is reclaimed automatically once it is sent.
 */
int pcn_kmsg_post(enum pcn_kmsg_type type, int dest_nid, void *msg, size_t msg_size);

/**
 * Get message buffer for posting. Note pcn_kmsg_put() is for returning
 * unused buffer without posting it; posted message is reclaimed automatically.
 */
void *pcn_kmsg_get(size_t size);
void pcn_kmsg_put(void *msg);

/**
 * Process the received messag @msg. Each message layer should start processing
 * the request by calling this function
 */
void pcn_kmsg_process(struct pcn_kmsg_message *msg);

/**
 * Return received message @msg after handling to recyle it. @msg becomes
 * unavailable after the call. Make sure return received messages otherwise
 * the message layer will panick.
 */
void pcn_kmsg_done(void *msg);

/**
 * Print out transport-specific statistics into @buffer
 */
void pcn_kmsg_stat(struct seq_file *seq, void *v);


struct pcn_kmsg_rdma_handle {
	u32 rkey;
	void *addr;
	dma_addr_t dma_addr;
	void *private;
};

/**
 * Pin @buffer for RDMA and get @rdma_addr and @rdma_key.
 */
struct pcn_kmsg_rdma_handle *pcn_kmsg_pin_rdma_buffer(void *buffer, size_t size);

void pcn_kmsg_unpin_rdma_buffer(struct pcn_kmsg_rdma_handle *handle);

int pcn_kmsg_rdma_write(int dest_nid, dma_addr_t rdma_addr, void *addr, size_t size, u32 rdma_key);

int pcn_kmsg_rdma_read(int from_nid, void *addr, dma_addr_t rdma_addr, size_t size, u32 rdma_key);

/* TRANSPORT DESCRIPTOR */
enum {
	PCN_KMSG_FEATURE_RDMA = 1,
};

/**
 * Check the features that the transport layer provides. Return true iff all
 * features are supported.
 */
bool pcn_kmsg_has_features(unsigned int features);

struct pcn_kmsg_transport {
	char *name;
	unsigned long features;

	struct pcn_kmsg_message *(*get)(size_t);
	void (*put)(struct pcn_kmsg_message *);

	int (*send)(int, struct pcn_kmsg_message *, size_t);
	int (*post)(int, struct pcn_kmsg_message *, size_t);
	void (*done)(struct pcn_kmsg_message *);

	void (*stat)(struct seq_file *, void *);

	struct pcn_kmsg_rdma_handle *(*pin_rdma_buffer)(void *, size_t);
	void (*unpin_rdma_buffer)(struct pcn_kmsg_rdma_handle *);
	int (*rdma_write)(int, dma_addr_t, void *, size_t, u32);
	int (*rdma_read)(int, void *, dma_addr_t, size_t, u32);
};

void pcn_kmsg_set_transport(struct pcn_kmsg_transport *tr);

#endif /* __POPCORN_PCN_KMSG_H__ */
