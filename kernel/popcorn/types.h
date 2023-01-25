#ifndef __POPCORN_TYPES_H__
#define __POPCORN_TYPES_H__

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>

#include <popcorn/pcn_kmsg.h>
#include <popcorn/regset.h>

#include <popcorn/hype_file.h>
#include <popcorn/hype_kvm.h>
#include <popcorn/hype.h>

#include <asm/kvm_host.h>
#include <linux/kvm_host.h>

#include <linux/skbuff.h> // vhost-net optimication

#define MAX_POPCORN_VCPU 32 /* HACK: not sure why including popcorn/hype_kvm.h doesn't work */

#define FAULTS_HASH 31
#define MAX_PCN_NAME_LEN 255
/**
 * Remote execution context
 */
struct remote_context {
	struct list_head list;
	atomic_t count;
	struct mm_struct *mm;

	int tgid;
	bool for_remote;

	/* Tracking page status */
	struct radix_tree_root pages;

	/* For page replication protocol */
	spinlock_t faults_lock[FAULTS_HASH];
	struct hlist_head faults[FAULTS_HASH];

	/* For VMA management */
	spinlock_t vmas_lock;
	struct list_head vmas;

	/* Remote worker */
	bool stop_remote_worker;

	struct task_struct *remote_worker;
	struct completion remote_works_ready;
	spinlock_t remote_works_lock;
	struct list_head remote_works;

	pid_t remote_tgids[MAX_POPCORN_NODES];
};

struct remote_context *__get_mm_remote(struct mm_struct *mm);
struct remote_context *get_task_remote(struct task_struct *tsk);
bool put_task_remote(struct task_struct *tsk);
bool __put_task_remote(struct remote_context *rc);


/**
 * Process migration
 */
#define BACK_MIGRATION_FIELDS \
	int remote_nid;\
	pid_t remote_pid;\
	pid_t origin_pid;\
	unsigned int personality;\
	/* \
	unsigned long def_flags;\
	sigset_t remote_blocked;\
	sigset_t remote_real_blocked;\
	sigset_t remote_saved_sigmask;\
	struct sigpending remote_pending;\
	unsigned long sas_ss_sp;\
	size_t sas_ss_size;\
	struct k_sigaction action[_NSIG]; \
	*/ \
	struct field_arch arch;
DEFINE_PCN_KMSG(back_migration_request_t, BACK_MIGRATION_FIELDS);

#define CLONE_FIELDS \
	pid_t origin_tgid;\
	pid_t origin_pid;\
	unsigned long task_size; \
	unsigned long stack_start; \
	unsigned long env_start;\
	unsigned long env_end;\
	unsigned long arg_start;\
	unsigned long arg_end;\
	unsigned long start_brk;\
	unsigned long brk;\
	unsigned long start_code ;\
	unsigned long end_code;\
	unsigned long start_data;\
	unsigned long end_data;\
	unsigned int personality;\
	unsigned long def_flags;\
	char exe_path[512];\
	/* \
	sigset_t remote_blocked;\
	sigset_t remote_real_blocked;\
	sigset_t remote_saved_sigmask;\
	struct sigpending remote_pending;\
	unsigned long sas_ss_sp;\
	size_t sas_ss_size;\
	struct k_sigaction action[_NSIG];\
	*/ \
	struct field_arch arch;
DEFINE_PCN_KMSG(clone_request_t, CLONE_FIELDS);


/**
 * This message is sent in response to a clone request.
 * Its purpose is to notify the requesting cpu that make
 * the specified pid is executing on behalf of the
 * requesting cpu.
 */
#define REMOTE_TASK_PAIRING_FIELDS \
	pid_t my_tgid; \
	pid_t my_pid; \
	pid_t your_pid;
DEFINE_PCN_KMSG(remote_task_pairing_t, REMOTE_TASK_PAIRING_FIELDS);


#define REMOTE_TASK_EXIT_FIELDS  \
	pid_t origin_pid; \
	pid_t remote_pid; \
	int exit_code;
DEFINE_PCN_KMSG(remote_task_exit_t, REMOTE_TASK_EXIT_FIELDS);

#define ORIGIN_TASK_EXIT_FIELDS \
	pid_t origin_pid; \
	pid_t remote_pid; \
	int exit_code;
DEFINE_PCN_KMSG(origin_task_exit_t, ORIGIN_TASK_EXIT_FIELDS);


/**
 * VMA management
 */
#define VMA_INFO_REQUEST_FIELDS \
	pid_t origin_pid; \
	pid_t remote_pid; \
	unsigned long addr;
DEFINE_PCN_KMSG(vma_info_request_t, VMA_INFO_REQUEST_FIELDS);

#define VMA_INFO_RESPONSE_FIELDS \
	pid_t remote_pid; \
	int result; \
	unsigned long addr; \
	unsigned long vm_start; \
	unsigned long vm_end; \
	unsigned long vm_flags;	\
	unsigned long vm_pgoff; \
	char vm_file_path[512];
DEFINE_PCN_KMSG(vma_info_response_t, VMA_INFO_RESPONSE_FIELDS);

#define vma_info_anon(x) ((x)->vm_file_path[0] == '\0' ? true : false)


#define VMA_OP_REQUEST_FIELDS \
	pid_t origin_pid; \
	pid_t remote_pid; \
	int remote_ws; \
	int operation; \
	union { \
		unsigned long addr; \
		unsigned long start; \
		unsigned long brk; \
	}; \
	union { \
		unsigned long len;		/* mmap */ \
		unsigned long old_len;	/* mremap */ \
	}; \
	union { \
		unsigned long prot;		/* mmap */ \
		int behavior;			/* madvise */ \
		unsigned long new_len;	/* mremap */ \
	}; \
	unsigned long flags;		/* mmap, remap */ \
	union { \
		unsigned long pgoff;	/* mmap */ \
		unsigned long new_addr;	/* mremap */ \
	}; \
	int fd; \
	char path[512];
DEFINE_PCN_KMSG(vma_op_request_t, VMA_OP_REQUEST_FIELDS);

#define VMA_OP_RESPONSE_FIELDS \
	pid_t origin_pid; \
	pid_t remote_pid; \
	int remote_ws; \
	int operation; \
	long ret; \
	union { \
		unsigned long addr; \
		unsigned long start; \
		unsigned long brk; \
	}; \
	unsigned long len;
DEFINE_PCN_KMSG(vma_op_response_t, VMA_OP_RESPONSE_FIELDS);


/**
 * Page management
 */
#define REMOTE_PAGE_REQUEST_FIELDS \
	pid_t origin_pid; \
	int origin_ws; \
	pid_t remote_pid; \
	unsigned long addr; \
	unsigned long fault_flags; \
	unsigned long instr_addr; \
	dma_addr_t rdma_addr; \
	u32 rdma_key;
DEFINE_PCN_KMSG(remote_page_request_t, REMOTE_PAGE_REQUEST_FIELDS);

#define REMOTE_PAGE_RESPONSE_COMMON_FIELDS \
	pid_t remote_pid; \
	pid_t origin_pid; \
	int origin_ws; \
	unsigned long addr; \
	int result;

#define REMOTE_PAGE_RESPONSE_FIELDS \
	REMOTE_PAGE_RESPONSE_COMMON_FIELDS \
	unsigned char page[PAGE_SIZE];
DEFINE_PCN_KMSG(remote_page_response_t, REMOTE_PAGE_RESPONSE_FIELDS);

#define REMOTE_PAGE_GRANT_FIELDS \
	REMOTE_PAGE_RESPONSE_COMMON_FIELDS
DEFINE_PCN_KMSG(remote_page_response_short_t, REMOTE_PAGE_GRANT_FIELDS);


#define REMOTE_PAGE_FLUSH_COMMON_FIELDS \
	pid_t origin_pid; \
	int remote_nid; \
	pid_t remote_pid; \
	int remote_ws; \
	unsigned long addr; \
	unsigned long flags;

#define REMOTE_PAGE_FLUSH_FIELDS \
	REMOTE_PAGE_FLUSH_COMMON_FIELDS \
	unsigned char page[PAGE_SIZE];
DEFINE_PCN_KMSG(remote_page_flush_t, REMOTE_PAGE_FLUSH_FIELDS);

#define REMOTE_PAGE_RELEASE_FIELDS \
	REMOTE_PAGE_FLUSH_COMMON_FIELDS
DEFINE_PCN_KMSG(remote_page_release_t, REMOTE_PAGE_RELEASE_FIELDS);

#define REMOTE_PAGE_FLUSH_ACK_FIELDS \
	int remote_ws; \
	unsigned long flags;
DEFINE_PCN_KMSG(remote_page_flush_ack_t, REMOTE_PAGE_FLUSH_ACK_FIELDS);


#define PAGE_INVALIDATE_REQUEST_FIELDS \
	pid_t origin_pid; \
	int origin_ws; \
	pid_t remote_pid; \
	unsigned long addr;
DEFINE_PCN_KMSG(page_invalidate_request_t, PAGE_INVALIDATE_REQUEST_FIELDS);

#define PAGE_INVALIDATE_RESPONSE_FIELDS \
	pid_t origin_pid; \
	int origin_ws; \
	pid_t remote_pid;
DEFINE_PCN_KMSG(page_invalidate_response_t, PAGE_INVALIDATE_RESPONSE_FIELDS);


/**
 * Futex
 */
#define REMOTE_FUTEX_REQ_FIELDS \
	pid_t origin_pid; \
	int remote_ws; \
	int op; \
	u32 val; \
	struct timespec ts; \
	void *uaddr; \
	void *uaddr2; \
	u32 val2; \
	u32 val3;
DEFINE_PCN_KMSG(remote_futex_request, REMOTE_FUTEX_REQ_FIELDS);

#define REMOTE_FUTEX_RES_FIELDS \
	int remote_ws; \
	long ret;
DEFINE_PCN_KMSG(remote_futex_response, REMOTE_FUTEX_RES_FIELDS);

/**
 * Node information
 */
#define NODE_INFO_FIELDS \
	int nid; \
	int bundle_id; \
	int arch;
DEFINE_PCN_KMSG(node_info_t, NODE_INFO_FIELDS);


/**
 * Schedule server. Not yet completely ported though
 */
#define SCHED_PERIODIC_FIELDS \
	int power_1; \
	int power_2; \
	int power_3;
DEFINE_PCN_KMSG(sched_periodic_req, SCHED_PERIODIC_FIELDS);

/**
 * Hype
 */
#define REMOTE_HYPE_COMMON_FIELDS \
	pid_t from_pid; \
	pid_t origin_pid; \
	int ws; \

// open
#define REMOTE_OPEN_COMMON_FIELDS \
	pid_t from_pid; \
	pid_t origin_pid; \
	int ws; \
	int fd;
//	int ret;

/* using */
#define ORIGIN_HYPE_COMMON_FIELDS \
	pid_t from_pid; \
	pid_t remote_pid; \
	int ws; \
	int fd; \
	int ret;

#define REMOTE_OPEN_REQUEST_FIELDS \
	REMOTE_OPEN_COMMON_FIELDS \
	int flags; \
	int mode; \
	char filename[MAX_PCN_NAME_LEN];
DEFINE_PCN_KMSG(remote_open_request_t, REMOTE_OPEN_REQUEST_FIELDS);

#define REMOTE_OPEN_RESPONSE_FIELDS \
	REMOTE_OPEN_COMMON_FIELDS
DEFINE_PCN_KMSG(remote_open_response_t, REMOTE_OPEN_RESPONSE_FIELDS);

// delegate rw
//	int pos; // not need to exchange pos. Always use origin's pos // so recycle definition of  REMOTE_OPEN
#define MAX_POPCONR_FILE_RW_SIZE 255

#define DELEGATE_RW_REQUEST_FIELDS \
	REMOTE_OPEN_COMMON_FIELDS \
	size_t count; \
	bool is_read; \
	char buf[MAX_POPCONR_FILE_RW_SIZE];
DEFINE_PCN_KMSG(delegate_rw_request_t, DELEGATE_RW_REQUEST_FIELDS);

#define DELEGATE_RW_RESPONSE_FIELDS \
	REMOTE_OPEN_COMMON_FIELDS \
	int ret; \
	char buf[MAX_POPCONR_FILE_RW_SIZE];
DEFINE_PCN_KMSG(delegate_rw_response_t, DELEGATE_RW_RESPONSE_FIELDS);


// kvm
#define REMOTE_KVM_CREATE_REQUEST_FIELDS \
	REMOTE_HYPE_COMMON_FIELDS \
	unsigned long type;
DEFINE_PCN_KMSG(remote_kvm_create_request_t, REMOTE_KVM_CREATE_REQUEST_FIELDS);

#define REMOTE_KVM_CREATE_RESPONSE_FIELDS \
	REMOTE_HYPE_COMMON_FIELDS \
	int fd;
DEFINE_PCN_KMSG(remote_kvm_create_response_t, REMOTE_KVM_CREATE_RESPONSE_FIELDS);

DEFINE_PCN_KMSG(pophype_request_t, ORIGIN_HYPE_COMMON_FIELDS);
#define REMOTE_CHECKIN_VCPU_PID_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int origin_pid; \
	int from_nid;
DEFINE_PCN_KMSG(pophype_response_t, REMOTE_CHECKIN_VCPU_PID_RESPONSE_FIELDS);

// not used
#define ORIGIN_CHECKIN_VCPU_PID_REQEUST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int from_nid;
DEFINE_PCN_KMSG(pophype_origin_checkin_vcpu_request_t, ORIGIN_CHECKIN_VCPU_PID_REQEUST_FIELDS);

#define ORIGIN_SIPI_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int vcpu_id; \
	int vector;
DEFINE_PCN_KMSG(origin_sipi_request_t, ORIGIN_SIPI_REQUEST_FIELDS);

#define ORIGIN_SIPI_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS
DEFINE_PCN_KMSG(origin_sipi_response_t, ORIGIN_SIPI_RESPONSE_FIELDS);

#define IPI_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	struct kvm_lapic_irq irq;
DEFINE_PCN_KMSG(ipi_request_t, IPI_REQUEST_FIELDS);
//	int vcpu_id;
//int vector;

#define IPI_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	struct kvm_lapic_irq irq;
DEFINE_PCN_KMSG(ipi_response_t, IPI_RESPONSE_FIELDS);

#define SIG_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int target_tgid; \
	int target_pid; \
	int usr_sig; \
	struct siginfo siginfo;
DEFINE_PCN_KMSG(sig_request_t, SIG_REQUEST_FIELDS);

#define SIG_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int target_pid;
DEFINE_PCN_KMSG(sig_response_t, SIG_RESPONSE_FIELDS);

#define ORIGIN_HYPE_COMMON_FIELDS \
	pid_t from_pid; \
	pid_t remote_pid; \
	int ws; \
	int fd; \
	int ret;

#define ORIGIN_BROADCAST_ACCEPT_IRQ_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int delivery_mode; \
	int vcpu_id; \
	int vector; \
	int level; \
	int trig_mode; \
	int dest_map;
DEFINE_PCN_KMSG(origin_broadcast_accept_irq_request_t, ORIGIN_BROADCAST_ACCEPT_IRQ_REQUEST_FIELDS);

#define ORIGIN_BROADCAST_ACCEPT_IRQ_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS
DEFINE_PCN_KMSG(origin_broadcast_accept_irq_response_t, ORIGIN_BROADCAST_ACCEPT_IRQ_RESPONSE_FIELDS);

#define ORIGIN_BROADCAST_APIC_REG_WRITE_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int vcpu_id; \
	u32 reg; \
	u32 val;
DEFINE_PCN_KMSG(origin_broadcast_apic_reg_write_request_t, ORIGIN_BROADCAST_APIC_REG_WRITE_REQUEST_FIELDS);

#define ORIGIN_BROADCAST_APIC_REG_WRITE_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS
DEFINE_PCN_KMSG(origin_broadcast_apic_reg_write_response_t, ORIGIN_BROADCAST_APIC_REG_WRITE_RESPONSE_FIELDS);


#define ORIGIN_BROADCAST_CPU_TABLE_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int vcpu_to_nid[MAX_POPCORN_VCPU];
DEFINE_PCN_KMSG(origin_broadcast_cpu_table_request_t, ORIGIN_BROADCAST_CPU_TABLE_REQUEST_FIELDS);

#define ORIGIN_BROADCAST_CPU_TABLE_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS
DEFINE_PCN_KMSG(origin_broadcast_cpu_table_response_t, ORIGIN_BROADCAST_CPU_TABLE_RESPONSE_FIELDS);

#define UPDATE_CPU_TABLE_REQUEST_FIELDS \
	int migrated_vcpu; \
	int migrate_to_nid;
DEFINE_PCN_KMSG(update_cpu_table_request_t, UPDATE_CPU_TABLE_REQUEST_FIELDS);


/* remote asks remote_tgid = remote->origin origin->remote remote->origin origin->remote */
// ORIGIN_HYPE_COMMON_FIELDS is a bad name // because not origin but remote
#define REMOTE_ASK_ORIGIN_TGID_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int src_tgid; \
	int dst_nid; \
	int origin_pid
DEFINE_PCN_KMSG(remote_ask_origin_tgid_request_t, REMOTE_ASK_ORIGIN_TGID_REQUEST_FIELDS);

#define REMOTE_ASK_ORIGIN_TGID_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int dst_tgid;
DEFINE_PCN_KMSG(remote_ask_origin_tgid_response_t, REMOTE_ASK_ORIGIN_TGID_RESPONSE_FIELDS);
//int dst_tgid;
//int src_tgid;
//int origin_pid
#define ORIGIN_ASK_REMOTE_TGID_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int src_nid; \
	int src_tgid;
DEFINE_PCN_KMSG(origin_ask_remote_tgid_request_t, ORIGIN_ASK_REMOTE_TGID_REQUEST_FIELDS);

/***
 * Pophype migration
 */
#define MAX_MSR_ENTRIES 25
struct pophype_kvm_msrs {
    __u32 nmsrs; /* number of msrs in entries */
    __u32 pad;
    struct kvm_msr_entry entries[MAX_MSR_ENTRIES];
};
#define UPDATE_VCPU_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	struct kvm_vcpu vcpu; \
	struct kvm_regs regs; \
	struct kvm_mp_state mp_state; \
	struct kvm_sregs sregs; \
	struct kvm_fpu fpu; \
	struct kvm_xcrs xcrs; \
	struct kvm_lapic_state lapic; \
	struct kvm_xsave xsave; \
	struct kvm_vcpu_events vcpu_events; \
	struct pophype_kvm_msrs msrs; \
	u64 pae_root[4]; \
	u64 pdptrs[4]; /*pae*/ \
	u64 guest_sysenter_rsp; \
	u32 guest_sysenter_cs; \
	u64 guest_sysenter_rip;
DEFINE_PCN_KMSG(update_vcpu_request_t, UPDATE_VCPU_REQUEST_FIELDS);

#define UPDATE_VCPU_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS
DEFINE_PCN_KMSG(update_vcpu_response_t, UPDATE_VCPU_RESPONSE_FIELDS);


/***
 * vhost-net eventfd
 */
#define DELEGATE_EVENTFD_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int eventfd_fd; \
	__u64 n;
DEFINE_PCN_KMSG(delegate_eventfd_request_t, DELEGATE_EVENTFD_REQUEST_FIELDS);

#define DELEGATE_EVENTFD_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	int eventfd_fd; \
	__u64 n;
DEFINE_PCN_KMSG(delegate_eventfd_response_t, DELEGATE_EVENTFD_RESPONSE_FIELDS);

/*
 * vhost_net karim's optimizations
 */
#define DELEGATE_TUNFD_REQUEST_FIELDS \
       ORIGIN_HYPE_COMMON_FIELDS \
       int vhost; \
       size_t psize; \
       unsigned char packet[0];
DEFINE_PCN_KMSG(delegate_tunfd_request_t, DELEGATE_TUNFD_REQUEST_FIELDS);

#define DELEGATE_TUNFD_RESPONSE_FIELDS \
       ORIGIN_HYPE_COMMON_FIELDS \
       int vhost; \
       size_t psize; \
       char packet[0];
DEFINE_PCN_KMSG(delegate_tunfd_response_t, DELEGATE_TUNFD_RESPONSE_FIELDS);

/*
* RX notifications
**/

#define RX_NOTIFICATION_REQUEST_FIELDS \
       ORIGIN_HYPE_COMMON_FIELDS \
       int vhost;
DEFINE_PCN_KMSG(rx_notification_request_t, RX_NOTIFICATION_REQUEST_FIELDS);

/*
* peek_head_len() RPC
**/

#define PEEK_HEAD_LEN_REQUEST_FIELDS \
    ORIGIN_HYPE_COMMON_FIELDS \
    int vhost;
DEFINE_PCN_KMSG(peek_head_len_request_t, PEEK_HEAD_LEN_REQUEST_FIELDS);

#define PEEK_HEAD_LEN_RESPONSE_FIELDS \
    ORIGIN_HYPE_COMMON_FIELDS \
    size_t sock_len;
DEFINE_PCN_KMSG(peek_head_len_response_t, PEEK_HEAD_LEN_RESPONSE_FIELDS);

/*
* recvmsg() delegation
**/
#define DELEGATE_RECVMSG_REQUEST_FIELDS \
       ORIGIN_HYPE_COMMON_FIELDS \
       int vhost; \
       size_t sock_len; \
       int flags;
DEFINE_PCN_KMSG(delegate_recvmsg_request_t, DELEGATE_RECVMSG_REQUEST_FIELDS);

#define DELEGATE_RECVMSG_RESPONSE_FIELDS \
       ORIGIN_HYPE_COMMON_FIELDS \
       int vhost; \
       int flags; \
       char data[0]; /* size of data is in ret field */
DEFINE_PCN_KMSG(delegate_recvmsg_response_t, DELEGATE_RECVMSG_RESPONSE_FIELDS);

/***
 * vhost-net optimization
 */
//struct rx_copy_msg {
struct pophype_skb {
	//struct pcn_kmsg_hdr header;
	//struct ft_pid creator;
	//int filter_id;
	//int is_child;
    //__be16 dport;
    //__be32 daddr;
	//long long pckt_id;
    //long long local_tx;

    ktime_t tstamp;
	char cb[48];
    union {
			__wsum          csum;
			struct {
				__u16   csum_start;
				__u16   csum_offset;
			};
	}; // pophype - old
	__u32 priority; // pophype - old
	kmemcheck_bitfield_begin(flags1); // pophype - old
	//__u8 		local_df:1, // pophype - new doesn't have
	__u8		cloned:1,
			ip_summed:2,
			nohdr:1,
			nfctinfo:3;
	__u8		pkt_type:3,
			fclone:2,
			ipvs_property:1,
			peeked:1,
			nf_trace:1;
	kmemcheck_bitfield_end(flags1);
	__be16 protocol;
	int skb_iif;
#ifdef CONFIG_NET_SCHED
        __u16 tc_index;       /* traffic control index */
#ifdef CONFIG_NET_CLS_ACT
        __u16 tc_verd;        /* traffic control verdict */
#endif
#endif
    //__u32 rxhash;	// pophype - new doesn't have
    kmemcheck_bitfield_begin(flags2);
#ifdef CONFIG_IPV6_NDISC_NODETYPE
	__u8 ndisc_nodetype:2;
#endif
	//__u8 ooo_okay:1; // pophype - new doesn't have
	//__u8 l4_rxhash:1; // pophype - new doesn't have
	kmemcheck_bitfield_end(flags2);
#ifdef CONFIG_NETWORK_SECMARK
        __u32 secmark;
#endif
    union {
                __u32           mark;
                __u32           dropcount;
        };
    __u16 vlan_tci;
    int transport_header_off;
        int network_header_off;
        int mac_header_off;

    int headerlen;
        int datalen;
        int taillen;
    //NOTE: data must be the last field;
    char data;
};


#define DELEGATE_SKB_TX_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	struct pophype_skb pskb;
DEFINE_PCN_KMSG(delegate_skb_tx_request_t, DELEGATE_SKB_TX_REQUEST_FIELDS);

#define DELEGATE_SKB_TX_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS
DEFINE_PCN_KMSG(delegate_skb_tx_response_t, DELEGATE_SKB_TX_RESPONSE_FIELDS);

#include <linux/socket.h>
#define DELEGATE_NET_MSG_TX_REQUEST_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS \
	struct pophype_msghdr pmsghdr;
DEFINE_PCN_KMSG(delegate_net_msg_tx_request_t, DELEGATE_NET_MSG_TX_REQUEST_FIELDS);

#define DELEGATE_NET_MSG_TX_RESPONSE_FIELDS \
	ORIGIN_HYPE_COMMON_FIELDS
DEFINE_PCN_KMSG(delegate_net_msg_tx_response_t, DELEGATE_NET_MSG_TX_RESPONSE_FIELDS);




/**
 * Message routing using work queues
 */
extern struct workqueue_struct *popcorn_wq;
extern struct workqueue_struct *popcorn_ordered_wq;

struct pcn_kmsg_work {
	struct work_struct work;
	void *msg;
};

static inline int __handle_popcorn_work(struct pcn_kmsg_message *msg, void (*handler)(struct work_struct *), struct workqueue_struct *wq)
{
	struct pcn_kmsg_work *w = kmalloc(sizeof(*w), GFP_ATOMIC);
	BUG_ON(!w);

	w->msg = msg;
	INIT_WORK(&w->work, handler);
	smp_wmb();
	queue_work(wq, &w->work);

	return 0;
}

int request_remote_work(pid_t pid, struct pcn_kmsg_message *req);

#define DEFINE_KMSG_WQ_HANDLER(x) \
static inline int handle_##x(struct pcn_kmsg_message *msg) {\
	return __handle_popcorn_work(msg, process_##x, popcorn_wq);\
}
#define DEFINE_KMSG_ORDERED_WQ_HANDLER(x) \
static inline int handle_##x(struct pcn_kmsg_message *msg) {\
	return __handle_popcorn_work(msg, process_##x, popcorn_ordered_wq);\
}
#define DEFINE_KMSG_RW_HANDLER(x,type,member) \
static inline int handle_##x(struct pcn_kmsg_message *msg) {\
	type *req = (type *)msg; \
	return request_remote_work(req->member, msg); \
}

#define REGISTER_KMSG_WQ_HANDLER(x, y) \
	pcn_kmsg_register_callback(x, handle_##y)

#define REGISTER_KMSG_HANDLER(x, y) \
	pcn_kmsg_register_callback(x, handle_##y)

#define START_KMSG_WORK(type, name, work) \
	struct pcn_kmsg_work *__pcn_kmsg_work__ = (struct pcn_kmsg_work *)(work); \
	type *name = __pcn_kmsg_work__->msg

#define END_KMSG_WORK(name) \
	pcn_kmsg_done(name); \
	kfree(__pcn_kmsg_work__);


#include <linux/sched.h>

static inline struct task_struct *__get_task_struct(pid_t pid)
{
	struct task_struct *tsk = NULL;
	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	if (likely(tsk)) {
		get_task_struct(tsk);
	}
	rcu_read_unlock();
	return tsk;
}

#endif /* __TYPES_H__ */
