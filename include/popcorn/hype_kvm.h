/*
 * hype_kvm.h
 * Copyright (C) 2019 jackchuang <jackchuang@mir7>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef HYPE_KVM_H
#define HYPE_KVM_H

#include <popcorn/hype.h>

#include <linux/types.h>
#include <linux/compiler.h>

#include <linux/kvm_host.h>

#include <linux/delay.h>


/* vhost-net: eventfd */
#include <linux/kvm_irqfd.h>
#include <linux/eventfd.h>

#include <linux/skbuff.h> // vhost-net optimication

/* Debug */
#define FD_DEBUG_THREDSHOLD_LOW 10
#define FD_DEBUG_THREDSHOLD_HIGH 20

#define MAX_POPCORN_VCPU 32 /* Since current pophype migration assumption (including lkvm implementation, 1vcpu on 1 node), This value should not be less than MAX_POPCORN_NODES(32). */

#define POPCORN_HOST_NID 0
#define FD_START 3 /* look up fd from this f. io and other files */ // wrong since kvm start 4 or 5
#define MAX_POPCORN_FD (MAX_POPCORN_VCPU + 30)
//MAX_POPCORN_FD 30

#define POPHYPE_ORIGIN_TAP_NAME "tap0"

/*
 * Which cpu on which node and info
 */
struct hype_node_info_t {
    struct kvm_vcpu *vcpu;
    struct kvm_run *run;
    int vcpu_id;
	int fd;
    unsigned long uaddr;
	bool on_mynid; /* TODO - so that show_guest_rip can do fastpath*/
	struct task_struct *tsk; /* buffer this for debugging */
	int remote_pid; /* Remote vCPU thread pid at origin */
	int origin_pid; /* Original pid at origin for remote vCPU thread for lookup */
};
extern struct hype_node_info_t *hype_node_info[MAX_POPCORN_NODES][MAX_POPCORN_VCPU]; /* Attention: [MY_NID][FD] set by ./kernel/popcorn/vma_server.c pophype mmap() feature */

extern void *popcorn_vcpu_op;

#define VCPU_FD_BASE 11 /* TODO BAD hardcode */
extern int popcorn_vcpu_cnt;
extern int first_fd_after_vcpufd;

//struct popcorn_vcpu_info popcorn_vcpu_infos[MAX_POPCORN_VCPU];


/*
 * vhost-net: eventfd ctx for delegation
 */
struct hype_eventfd_info_t {
	// int fd; // already in idx
	// fd f = fdget(fd);
	// struct file *file = &f.file
	struct eventfd_ctx *eventfd_ctx;
	struct kvm_kernel_irqfd *irqfd; /* Not sure if needed. Just in case */
};
extern struct hype_eventfd_info_t *hype_eventfd_info[MAX_POPCORN_FD]; /* [fd_idx] */
int eventfd_ctx_to_fd(struct eventfd_ctx *eventfd_ctx); /* generate at remote */
__u64 pophype_eventfd_delegate(int eventfd_fd, __u64 n); /* retrive at origin */

/*
 * DSM VM info
 */
#define MAX_VM_STACK_DEBUG 5
//struct _dsm_traffic
typedef struct {
    unsigned long addr; /* faulting addr */
    unsigned long rip;
    unsigned long rbp;
    unsigned long rsp;
    unsigned long stack[MAX_VM_STACK_DEBUG];
    unsigned long cnt; /* freq */
//    unsigned long long time; /* total */
} dsm_traffic_t;


/* others */
#define REMOTE_CANNOT_DOWN_MMAP_SEM (-78)

int popcorn_kvm_dev_ioctl_create_vm_tsk(unsigned long type);
void popcorn_broadcast_apic_reg_write(int vcpu_id, u32 reg, u32 val);
void popcorn_broadcast_accept_irq(int vcpu_id, int delivery_mode, int vector, int level, int trig_mode, int dest_map);
int popcorn_send_ipi(struct kvm_vcpu *dst_vcpu, struct kvm_lapic_irq *irq, unsigned long *dest_map);
void popcorn_send_sipi(int vcpu_id, int vector);

int popcorn_broadcast_sig(int usr_sig);
int pophype_do_send_specific_at_remote(pid_t tgid, pid_t pid, int sig, struct siginfo *info); /* kernel/signal.c */

int pophype_available_vcpu(void);
void pophype_set_cpu0(void);

int popcorn_get_hnid(void);
int popcorn_vcpuid_to_nid(int vcpu_id);
int vcpuid_to_fd(int vcpu_id);
bool popcorn_on_right_nid(int vcpu_id);
int vcpuid_to_nid(int vcpu_id);
void popcorn_show_gcpu_table(void);

/* debug - reg dump */
dsm_traffic_t pophype_show_guest_rip_rsp(unsigned long host_addr, bool show, struct kvm_vcpu *vcpu);

/* arch/x86/kvm/lapic.c */
int popcorn_kvm_apic_set_irq(struct kvm_vcpu *vcpu, struct kvm_lapic_irq *irq, unsigned long *dest_map); // used for SIPI special cases
int popcorn_apic_inject_ipi(struct kvm_lapic *apic, struct kvm_lapic_irq *irq, int dst_vcpu_id);
int popcorn_apic_accept_irq(struct kvm_lapic *apic, int delivery_mode, int vector, int level, int trig_mode, unsigned long *dest_map);

int popcorn_file_to_fd(struct task_struct *tsk, struct file *file, bool is_vcpu);

/* Pophype migration */
int popcorn_update_remote_vcpu(int dst_nid, int dst_vcpu);

/* vhost-net optimization - at remote */
struct pophype_skb *guest_skb_to_pophype_skb(struct sk_buff *skb); // guest - create
void delegate_skb_tx_hypercall(struct pophype_skb *skb, int pskb_size); // guest - estory
int delegate_skb_tx(struct pophype_skb *pskb_gva, int pskb_size); // host

void guest_delegate_net_msg_tx_hypercall(struct sock *sk, struct msghdr *msg, size_t size);
void delegate_net_msg_tx(struct pophype_msghdr __user *pmsg, int pmsghdr_size);

/* virtio-blk iowrite delegation to origin*/
void popcorn_handle_virtio_blk_iowrite(void);

/* vhost_net karim optimizations */

struct __hype_ctx {
       struct task_struct              *tsk; /* lkvm */
       struct remote_context   *rc;
       struct vhost_net                *__hype_vhosts[16];
       size_t volatile                 __sock_lens[16];
    int                                        __hype_vhost;           /* index */
};

/* this structure is accessed from vhost kthread worker */
extern struct __hype_ctx __hype_gctx;

/* To identify this apic irq insertion is from remote */
/* We found dest_map is always NULL in our use cases */
/* If dest_map is not always NULL, everything related to REMOTE_APIC is a HACK !!! */
/* Can we capture !!dest_map case? yes, TODO */
#define REMOTE_APIC ((void*)0x1000) /* FROM REMOTE */
#endif /* !HYPE_KVM_H */
