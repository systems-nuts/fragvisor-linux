/**
 * @file page_server.c
 *
 * Popcorn Linux page server implementation
 * This work was an extension of Marina Sadini MS Thesis, but totally revamped
 * for multi-threaded setup.
 *
 * @author Sang-Hoon Kim, SSRG Virginia Tech 2017
 */

#include <linux/compiler.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>
#include <linux/wait.h>
#include <linux/ptrace.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/radix-tree.h>

#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>

#include <asm/vmx.h>
#include <popcorn/types.h>
#include <popcorn/bundle.h>
#include <popcorn/pcn_kmsg.h>
#include <popcorn/hype_kvm.h>
#include <popcorn/debug.h>

#include "types.h"
#include "pgtable.h"
#include "wait_station.h"
#include "page_server.h"
#include "fh_action.h"

#include "trace_events.h"


#ifdef CONFIG_POPCORN_HYPE
#include <linux/mmu_notifier.h>
#define HYPE_RETRY (-78)
//#define KERNEL_PGS (PAGE_SIZE * 1024 * 1024 / 1024)
#define KERNEL_PGS (0xd0000 + 0x30000) // 0xd0000 + 0x30000 = 1048576 // works
//#define KERNEL_PGS (2017020) // try debuging 1117020

/*
 * Eighter one
 */
/* when debuging ap */
//#define ORIGIN_PGFAULT_SKIP (48000 + KERNEL_PGS)
////#define REMOTE_PGFAULT_SKIP (0 + KERNEL_PGS) // standard
//#define REMOTE_PGFAULT_SKIP (0 + KERNEL_PGS + 1000) // faster
//#define PGFAULT_REQ_AT_ORIGIN_SKIP (0 + KERNEL_PGS)
//#define PGFAULT_REQ_AT_REMOTE_SKIP (0 + 0)

/* when mount_root() debugging */
//  >>
//  1142478
//- 1048576
//    70000

//   1099214
// - 1048576
//     50000
//  >>
//#define ORIGIN_PGFAULT_SKIP (95000 + KERNEL_PGS)
#define ORIGIN_PGFAULT_SKIP (115000 + KERNEL_PGS)
//#define REMOTE_PGFAULT_SKIP (0 + KERNEL_PGS + 50000) // faster
#define REMOTE_PGFAULT_SKIP (0 + KERNEL_PGS + 65000) // faster
//1130111
// 1048576

#define PGFAULT_REQ_AT_ORIGIN_SKIP (40000 + KERNEL_PGS)
//#define PGFAULT_REQ_AT_REMOTE_SKIP (0 + 22000)
#define PGFAULT_REQ_AT_REMOTE_SKIP (0 + 50000)

// 1117044

// PAGEFAULT_
//   1076801  1089362
// - 1048576
//     28000

// remote
// 22044
// PAGEFAULT_

/* mount_root() */
// origin pg 1114693 1100000
// remote pg 1079782 1070000
// origin inv
// remote inv 51404 50000

// origin
//		## PAGEFAULT [8730] 700990 R 429eb4 54 8000000000000865 vm_ops ffffffffa04835c0 #1115512
//[  957.232533] 			>>[8748] 700000 ffff88084f3e5460 #1142478
//[  957.232534] 			  [8748] ->[2696/1] 700000 r 0 #1076800
// 			->REMOTE_PAGE_REQUEST [8748] 700000 W(INV) 429f15 from [2696/1] #1076801
//[  957.264378] 			>>[8748] 700000 ffff88084f3e5460 #1142480
//[  957.264379] 			  [8748] ->[2696/1] 700000 r 1000 #1076801


// remote
//	## PAGEFAULT [2696] 7ffec1f1b000 W 468797 1 8000000000000866           (null) #1081141
//[ 1040.983829]  =[2696] 7ffec1f1b000 ffff880859daecd0 INVALIDATE_PAGE
//[ 1040.983831]   [2696] ->[8748/0] 7ffec1f1b000 instr 468797
//[ 1040.989298] 			>>[2696] 7ffec1f1b000 ffff880859daecd0 #1099175
//[ 1041.003993]
//
//			->REMOTE_PAGE_REQUEST [2614] 7fffefff3000 R 468797 from [8747/0] ***#22044***
//[ 1041.444157] 			  [2614] ->[8747/0] 7fffefff3000 r 0 #22044
//[ 1041.449692]  =[2696] 7fffefff3000 ffff88085252f208 INVALIDATE_PAGE
//[ 1041.449754]
//		INVALIDATE_PAGE [2614] 7fffefff3000 [8747/0] #48738
//		[ 1041.449756]   [2614] inv 7fffefff3000 but local write ongoing, wait
//		[ 1041.449757]  +[2614] 7fffefff3000 ffff88085252f208 (follower) #48738
//		[ 1041.476176]   [2696] ->[8748/0] 7fffefff3000 instr 468797
//		[ 1041.481654] 			>>[2696] 7fffefff3000 ffff88085252f208 #1099214
//		[ 1041.487534]  =[2614] 7fffefff3000 ffff88085252f208 (inv follower done)
//		[ 1041.494191]


/*** origin revoke remote INVALIDATE_PAGE
 *  revoke	->
 *				INV
 *			<-
 */
// smp debug
//#define COMM_INV_CNT (47500) // 47633 // works right before smp boot process
// mount_root() debug

// 101000: first bash
// 51500: last use
// 47633 // works right before smp boot process
#define COMM_INV_CNT (123000) // 150000(good for manually dynamic debug) has to run 3t one time to see the logs
#define ORIGIN_REVOKE (COMM_INV_CNT)
#define REMOTE_REVOKE (0)
#define ORIGIN_INVPG (0)
#define REMOTE_INVPG (COMM_INV_CNT) // + 0xc0000 + 0x30000)





/* remotefault at remote RETRY */
//#define RETRY_REMOTEFAULT 100000000 //good
//#define RETRY_ORIGINFAULT_AT_ORIGIN 100
#define RETRY_ORIGINFAULT_AT_ORIGIN 10000000
//#define RETRY_REMOTEFAULT 1000 // bad
//#define RETRY_REMOTEFAULT 100
#define RETRY_REMOTEFAULT 10
#define RETRY_REMOTEFAULT_GIVEUP 1 /* issue BUG() at origin */

/* DSM traffic debug */
//#define MAX_VM_STACK_DEBUG 3
//struct dsm_pgfault {
//	unsigned long addr; /* faulting addr */
//	unsigned long inst;
//	unsigned long rbp;
//	unsigned long rsp;
//	unsigned long stack[MAX_VM_STACK_DEBUG];
//	unsigned long cnt; /* freq */
//	unsigned long long time; /* total */
//};
//typedef struct {
//	unsigned long addr; /* faulting addr */
//	unsigned long inst;
//	unsigned long rbp;
//	unsigned long rsp;
//	unsigned long stack[MAX_VM_STACK_DEBUG];
//	unsigned long cnt; /* freq */
//	unsigned long long time; /* total */
//} dsm_traffic_t;
#define DSM_TRAFFIC_PG_CNT 6500
#define DSM_TRAFFIC_INST_CNT 1500 // change to dynamic otherwise waste time to tune
#define DSM_TRAFFIC_RSP_CNT 10 // change to dynamic otherwise waste time to tune
/* [*][0] indicates the addr; */
//struct dsm_pgfault **dsm_traffic = NULL;
dsm_traffic_t ***dsm_traffic = NULL; /* TODO move this to trace... out of mem */
unsigned long dsm_traffic_pg_cnt = DSM_TRAFFIC_PG_CNT;
unsigned long dsm_traffic_inst_cnt = DSM_TRAFFIC_INST_CNT;
unsigned long dsm_traffic_rsp_cnt = DSM_TRAFFIC_RSP_CNT;
unsigned long max_dsm_traffic_pg_cnt;
unsigned long max_dsm_traffic_inst_cnt;
unsigned long max_dsm_traffic_rsp_cnt;


static unsigned long all_local_dsm_traffic_cnt = 0;
static unsigned long dbg_dsm_traffic_cnt = 0; /* vmdsm cnt */
static unsigned long dbg_dsm_traffic_good_cnt = 0; /* vmdsm cnt */

static unsigned long g_lfal_retry_cnt = 0;
#endif

/* (##)localfault -> (-/=)follower/leader -> (>>)finish
 * 											fault_flags pte_flags(pte_val)
 * ## PAGEFAULT [3249] 7ffec1f1a000 W 468267 d 8000000000000866
 *  =[3249] 7ffec1f1a000 replicated not mine ffff88084ed3ebe0(fh)
 * >>[3249] 7ffec1f1a000 ffff88084ed3ebe0(fh)
 *
 *
 * (->)send
 * REMOTE_PAGE_REQUEST [3251] 7ffec1802000 R 468267 from [2692/1]
 * >>[3251] 7ffec1802000 ffff88083697ba00
 *   [3251] ->[2692/1] 0
 *
 * (>>)last_fini (>)!last_fini
 *  >[3251] 7ffec1802000 ffff88083697ba00
 * >>[3251] 7ffec1802000 ffff88083697ba00
 *
 *
 * INVALIDATION:
 *  +[] (optional)(found fh existing (foller))
 *  =[] (done leader/follower)
 * no >>[]
 *
 *
 * =[] at remote: only inv complet and
 */
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
#define MICROSECOND 1000000
atomic64_t mm_cnt = ATOMIC64_INIT(0);
atomic64_t mm_time_ns = ATOMIC64_INIT(0);

/* local origin & it has to bring from remote (RW)*/
//atomic64_t ptef_ns = ATOMIC64_INIT(0);
//atomic64_t ptef_cnt = ATOMIC64_INIT(0);
/* local_origin & __claim_remote_page(1)(!pg_mine)(RW) */
atomic64_t clr_ns = ATOMIC64_INIT(0);
atomic64_t clr_cnt = ATOMIC64_INIT(0);

/* local_origin & !pg_mine & !send_revoke_msg & is_page */
atomic64_t fp_ns = ATOMIC64_INIT(0);
atomic64_t fp_cnt = ATOMIC64_INIT(0);

/* local_origin & !pg_mine & !send_revoke_msg & is_page */
atomic64_t fpin_ns = ATOMIC64_INIT(0);
atomic64_t fpin_cnt = ATOMIC64_INIT(0);
atomic64_t fpinh_ns = ATOMIC64_INIT(0);
atomic64_t fpinh_cnt = ATOMIC64_INIT(0);

/* __claim_local_page(pg_mine) & origin */
atomic64_t inv_ns = ATOMIC64_INIT(0);
atomic64_t inv_cnt = ATOMIC64_INIT(0);

/* process_page_invalidate_request */
atomic64_t invh_ns = ATOMIC64_INIT(0);
atomic64_t invh_cnt = ATOMIC64_INIT(0);
/* full rr fault time */
atomic64_t fph_ns = ATOMIC64_INIT(0);
atomic64_t fph_cnt = ATOMIC64_INIT(0);
#endif

bool pophype_debug = false; /* pophype DSM force all printks */

inline void page_server_start_mm_fault(unsigned long address)
{
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	if (!distributed_process(current)) return;
	if (current->fault_address == 0 ||
			current->fault_address != address) {
		current->fault_address = address;
		current->fault_retry = 0;
		current->fault_start = ktime_get();
		current->fault_address = address;
	}
#endif
}

inline int page_server_end_mm_fault(int ret)
{
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	if (!distributed_process(current)) return ret;

	if (ret & VM_FAULT_RETRY) {
		current->fault_retry++;
	} else if (!(ret & VM_FAULT_ERROR)) {
		ktime_t dt, fault_end = ktime_get();

		dt = ktime_sub(fault_end, current->fault_start);
		trace_pgfault_stat(instruction_pointer(current_pt_regs()),
				current->fault_address, ret,
				current->fault_retry, ktime_to_ns(dt));
		current->fault_address = 0;
        if (ktime_to_ns(dt) < 1000 * MICROSECOND) { /* noise filter */
            atomic64_add(ktime_to_ns(dt), &mm_time_ns);
            atomic64_inc(&mm_cnt);
        }
	}
#endif
	return ret;
}

void pf_time_stat(struct seq_file *seq, void *v)
{
#ifdef CONFIG_POPCORN_STAT
	if (seq) {
		seq_printf(seq, "%4s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
					"mm", (atomic64_read(&mm_time_ns) / 1000) / MICROSECOND,
							(atomic64_read(&mm_time_ns) / 1000)  % MICROSECOND,
					"cnt", atomic64_read(&mm_cnt),
					"per", atomic64_read(&mm_cnt) ?
					 atomic64_read(&mm_time_ns)/atomic64_read(&mm_cnt)/1000 : 0);

		//seq_printf(seq, "%4s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
		//			"ptef", (atomic64_read(&ptef_ns) / 1000) / MICROSECOND,
		//					(atomic64_read(&ptef_ns) / 1000)  % MICROSECOND,
		//			"cnt", atomic64_read(&ptef_cnt),
		//			"per", atomic64_read(&ptef_cnt) ?
		//			 atomic64_read(&ptef_ns)/atomic64_read(&ptef_cnt)/1000 : 0);

		seq_printf(seq, "%4s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
					"clr", (atomic64_read(&clr_ns) / 1000) / MICROSECOND,
							(atomic64_read(&clr_ns) / 1000)  % MICROSECOND,
					"cnt", atomic64_read(&clr_cnt),
					"per", atomic64_read(&clr_cnt) ?
					 atomic64_read(&clr_ns)/atomic64_read(&clr_cnt)/1000 : 0);

		/* R: only page (R+!pg_mine) */
		seq_printf(seq, "%4s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
			"fp", (atomic64_read(&fp_ns) / 1000) / MICROSECOND,
					(atomic64_read(&fp_ns) / 1000)  % MICROSECOND,
			"cnt", atomic64_read(&fp_cnt),
			"per", atomic64_read(&fp_cnt) ?
			 atomic64_read(&fp_ns)/atomic64_read(&fp_cnt)/1000 : 0);

		seq_printf(seq, "%4s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
			"fph", (atomic64_read(&fph_ns) / 1000) / MICROSECOND,
					(atomic64_read(&fph_ns) / 1000)  % MICROSECOND,
			"cnt", atomic64_read(&fph_cnt),
			"per", atomic64_read(&fph_cnt) ?
			 atomic64_read(&fph_ns)/atomic64_read(&fph_cnt)/1000 : 0);

		/* W: only inv */
		seq_printf(seq, "%4s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
			"inv", (atomic64_read(&inv_ns) / 1000) / MICROSECOND,
					(atomic64_read(&inv_ns) / 1000)  % MICROSECOND,
			"cnt", atomic64_read(&inv_cnt),
			"per", atomic64_read(&inv_cnt) ?
			 atomic64_read(&inv_ns)/atomic64_read(&inv_cnt)/1000 : 0);

		seq_printf(seq, "%4s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
			"invh", (atomic64_read(&invh_ns) / 1000) / MICROSECOND,
					(atomic64_read(&invh_ns) / 1000)  % MICROSECOND,
			"cnt", atomic64_read(&invh_cnt),
			"per", atomic64_read(&invh_cnt) ?
			 atomic64_read(&invh_ns)/atomic64_read(&invh_cnt)/1000 : 0);

		/* W: page + inv */
		seq_printf(seq, "%4s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
			"fpiv", (atomic64_read(&fpin_ns) / 1000) / MICROSECOND,
					(atomic64_read(&fpin_ns) / 1000)  % MICROSECOND,
			"cnt", atomic64_read(&fpin_cnt),
			"per", atomic64_read(&fpin_cnt) ?
			 atomic64_read(&fpin_ns)/atomic64_read(&fpin_cnt)/1000 : 0);
		seq_printf(seq, "%5s  %9ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
			"fpivh", (atomic64_read(&fpinh_ns) / 1000) / MICROSECOND,
					(atomic64_read(&fpinh_ns) / 1000)  % MICROSECOND,
			"cnt", atomic64_read(&fpinh_cnt),
			"per", atomic64_read(&fpinh_cnt) ?
			 atomic64_read(&fpinh_ns)/atomic64_read(&fpinh_cnt)/1000 : 0);
	} else {
        atomic64_set(&mm_cnt, 0);
        atomic64_set(&mm_time_ns, 0);

		//atomic64_set(&ptef_cnt, 0);
		//atomic64_set(&ptef_ns, 0);
		atomic64_set(&clr_cnt, 0);
		atomic64_set(&clr_ns, 0);
		atomic64_set(&fp_ns, 0);
		atomic64_set(&fp_cnt, 0);
		atomic64_set(&fph_ns, 0);
		atomic64_set(&fph_cnt, 0);

		atomic64_set(&inv_cnt, 0);
		atomic64_set(&inv_ns, 0);
		atomic64_set(&invh_cnt, 0);
		atomic64_set(&invh_ns, 0);

		atomic64_set(&fpin_ns, 0);
		atomic64_set(&fpin_cnt, 0);
		atomic64_set(&fpinh_ns, 0);
		atomic64_set(&fpinh_cnt, 0);
	}
#endif
}

void write_dsm_traffic (dsm_traffic_t *_dsm_traffic,
									unsigned long addr,
									unsigned long rip,
									unsigned long rbp,
									unsigned long rsp,
									unsigned long stack0,
									unsigned long stack1,
									unsigned long stack2,
									unsigned long cnt) {
	_dsm_traffic->addr = addr;
	_dsm_traffic->rip = rip;
	_dsm_traffic->rbp = rbp;
	_dsm_traffic->rsp = rsp;
//	_dsm_traffic->stack[0] = stack0;
//	_dsm_traffic->stack[1] = stack1;
//	_dsm_traffic->stack[2] = stack2;
//	_dsm_traffic->cnt = cnt;
}

/* address: full addr
 * addr: page algiend addr
 */
//#include <kvm/kvm_cache_regs.h>
#include "../../arch/x86/kvm/kvm_cache_regs.h"
#define __ex_clear(x, reg) \
	____kvm_handle_fault_on_reboot(x, "xor " reg " , " reg)
static __always_inline unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}
void __dsm_traffic_collect(unsigned long address, unsigned long addr, char op, struct kvm_vcpu *vcpu, unsigned long ns, unsigned long real_gva, unsigned long _exit_qualification)
{
#if HYPE_PERF_CRITICAL_DSM_TRAFFIC_DEBUG
	//all_local_dsm_traffic_cnt++;

	/* From handle_ept_violation */
	unsigned long exit_qualification = vcpu->arch.exit_qualification;
	unsigned long rip = kvm_rip_read(vcpu);
	int gla_validity = (exit_qualification >> 7) & 0x3;
	gpa_t gla = -1;

	if (gla_validity & 0x1)
		gla = vmcs_readl(GUEST_LINEAR_ADDRESS); // check Table 27-7 Intel manual
	/* rip, gla, exit_qualification */


	/* debug DSM trafic perf slow down */
	/* Usage:
	 * within 2 echo > /proc/popcorn_debug, do you want to
	 *		trace & rank ALL pgafault or only the following tops?
	 */
	if (pophype_debug) { /* Controlled by /proc/popcorn_debug */
		/* all or specific addresses extract by popcorn_trace top 30 */
		/* For lemp */
			//unsigned long inst;
			dsm_traffic_t __dsm_traffic;
#if HYPE_PERF_CRITICAL_DSM_TRAFFIC_PRINTK
			//dsm_traffic_t _dsm_traffic;
			//dbg_dsm_traffic_cnt++;
			/* show cnt */
			//POP_PK("pophype: do kvm_reg_dump() 0x%lx #%lu\n",
			//					address, dbg_dsm_traffic_cnt);
			//_dsm_traffic = pophype_show_guest_rip_rsp(address, true);
			//if (_dsm_traffic.rip != 0) {
			//}
#endif

#if 1
			__dsm_traffic = pophype_show_guest_rip_rsp(address, false, vcpu);
			dbg_dsm_traffic_cnt++;

			/* Trace: todo show it in trace */
			all_local_dsm_traffic_cnt++;
			//if (__dsm_traffic.rip != 0)
			{
				int kvm_mp_state = KVM_MP_STATE_UNKNOW;
				if (vcpu) {
					kvm_mp_state = vcpu->arch.mp_state;
					//#define KVM_MP_STATE_RUNNABLE          0
					//#define KVM_MP_STATE_UNINITIALIZED     1
					//#define KVM_MP_STATE_INIT_RECEIVED     2
					//#define KVM_MP_STATE_HALTED            3
					//#define KVM_MP_STATE_SIPI_RECEIVED     4
					//#define KVM_MP_STATE_STOPPED           5
					//#define KVM_MP_STATE_CHECK_STOP        6
					//#define KVM_MP_STATE_OPERATING         7
					//#define KVM_MP_STATE_LOAD              8
					//#define KVM_MP_STATE_UNKNOW            9
				} else {
					printk(KERN_ERR "%s() %d:\n", __func__, __LINE__);
				}
				dbg_dsm_traffic_good_cnt++;
				//#include "arch/x86/include/asm/kvm_host.h"
				//printk("%d\n", kvm_x86_ops->get_cpl(vcpu));
				//printk("%lu\n", kvm_get_linear_rip(vcpu));

				// cpl
				// arch/x86/kvm/x86.c ->
				// kvm_x86_ops->get_cpl(vcpu)

				// node
				//enum {
				//    OUTSIDE_GUEST_MODE, 			0
				//    IN_GUEST_MODE,				1
				//    EXITING_GUEST_MODE,			2
				//    READING_SHADOW_PAGE_TABLES,	3
				//};
				trace_vmdsm_traffic(addr, op, __dsm_traffic.rip,
						__dsm_traffic.rbp, __dsm_traffic.rsp,
						__dsm_traffic.stack[0], __dsm_traffic.stack[1],
						__dsm_traffic.stack[2], __dsm_traffic.stack[3],
						__dsm_traffic.stack[4], address, kvm_mp_state, ns,
						kvm_x86_ops->get_cpl(vcpu), vcpu->mode,
						kvm_get_linear_rip(vcpu),
						gla, exit_qualification);
			}
#endif

		}
#endif
}

/* NOT USED */
void dsm_traffic_collect(unsigned long address, unsigned long addr, char op, unsigned long ns)
{
	__dsm_traffic_collect(address, addr, op, NULL, ns, -1, -1);
}

void dsm_traffic_collect_vcpu(unsigned long address, unsigned long addr, char op, struct kvm_vcpu *vcpu, unsigned long ns, unsigned long real_gva, unsigned long exit_qualification)
{
	__dsm_traffic_collect(address, addr, op, vcpu, ns, real_gva, exit_qualification);
}

extern atomic64_t kvm_eptfault_ns;
extern atomic64_t kvm_eptfault_cnt;
void dsm_traffic_stat(struct seq_file *seq, void *v)
{
#if defined(CONFIG_POPCORN_HYPE) && defined(CONFIG_POPCORN_STAT)
	/*
	 * Order it:
	 *		cat /proc/popcorn_debug | sort -nrk 7 (test)
	 * 		sort -rk 7 out
	 * TODO: sum time
	 */
	//if (seq && dsm_traffic) {
	if (seq) {
		seq_printf(seq, "=== pophype vmdsm info (sanity check) ===\n");
		seq_printf(seq, "g_lfal_retry_cnt %lu\n", g_lfal_retry_cnt);
		seq_printf(seq, "%8s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
						"eptfault", (atomic64_read(&kvm_eptfault_ns) / 1000) / MICROSECOND,
								(atomic64_read(&kvm_eptfault_ns) / 1000)  % MICROSECOND,
								"cnt", atomic64_read(&kvm_eptfault_cnt),
								"per", atomic64_read(&kvm_eptfault_cnt) ?
								atomic64_read(&kvm_eptfault_ns) / atomic64_read(&kvm_eptfault_cnt) / 1000 : 0);
		seq_printf(seq, "=========================================\n");
		seq_printf(seq, "all_local_dsm_traffic_cnt %lu\n", // all_prob
									all_local_dsm_traffic_cnt);
		//seq_printf(seq, "dbg_dsm_traffic_cnt all %lu\n", dbg_dsm_traffic_cnt);
		seq_printf(seq, "dbg_dsm_traffic_good_cnt %lu\n", // trace_cnt
									dbg_dsm_traffic_good_cnt);
#if 0
		int i, j, k;
		seq_printf(seq, "Usage: cat /proc/popcorn_debug | sort -nrk 11\n");
		for (i = 0; i < dsm_traffic_pg_cnt; i++) {
			if (dsm_traffic[i][0][0].addr) {
				for (j = 0; j < dsm_traffic_inst_cnt; j++) {
					if (dsm_traffic[i][j][0].rip) {
						for (k = 0; k < dsm_traffic_rsp_cnt; k++) {
							if (dsm_traffic[i][j][k].cnt > 1000 ) {
								seq_printf(seq, "[%d][%d] addr: 0x%-12lx "
									"rip: 0x%-12lx "
									"rbp: 0x%-12lx rsp: 0x%-12lx"
									"cnt: %-12lu\n",
									i,j, dsm_traffic[i][j][k].addr,
									dsm_traffic[i][j][k].rip,
									dsm_traffic[i][j][k].rbp,
									dsm_traffic[i][j][k].rsp,
									/* TODO tack[] */
									dsm_traffic[i][j][k].cnt);
							}
						}
					}
				}
			}
		}
#endif
	} else { /* write */
		all_local_dsm_traffic_cnt = 0;
		dbg_dsm_traffic_cnt = 0;
		dbg_dsm_traffic_good_cnt = 0;
		atomic64_set(&kvm_eptfault_ns, 0);
		atomic64_set(&kvm_eptfault_cnt, 0);
	}
#endif
}

static inline int __fault_hash_key(unsigned long address)
{
	return (address >> PAGE_SHIFT) % FAULTS_HASH;
}

/**************************************************************************
 * Page ownership tracking mechanism
 */
#define PER_PAGE_INFO_SIZE \
		(sizeof(unsigned long) * BITS_TO_LONGS(MAX_POPCORN_NODES))
#define PAGE_INFO_PER_REGION (PAGE_SIZE / PER_PAGE_INFO_SIZE)

static inline void __get_page_info_key(unsigned long addr, unsigned long *key, unsigned long *offset)
{
	unsigned long paddr = addr >> PAGE_SHIFT;
	*key = paddr / PAGE_INFO_PER_REGION;
	*offset = (paddr % PAGE_INFO_PER_REGION) *
			(PER_PAGE_INFO_SIZE / sizeof(unsigned long));
}

static inline struct page *__get_page_info_page(struct mm_struct *mm, unsigned long addr, unsigned long *offset)
{
	unsigned long key;
	struct page *page;
	struct remote_context *rc = mm->remote;
	__get_page_info_key(addr, &key, offset);

	page = radix_tree_lookup(&rc->pages, key);
	if (!page) return NULL;

	return page;
}

static inline unsigned long *__get_page_info_mapped(struct mm_struct *mm, unsigned long addr, unsigned long *offset)
{
	unsigned long key;
	struct page *page;
	struct remote_context *rc = mm->remote;
	__get_page_info_key(addr, &key, offset);

	page = radix_tree_lookup(&rc->pages, key);
	if (!page) return NULL;

	return (unsigned long *)kmap_atomic(page) + *offset;
}

void free_remote_context_pages(struct remote_context *rc)
{
	int nr_pages;
	const int FREE_BATCH = 16;
	struct page *pages[FREE_BATCH];

	do {
		int i;
		nr_pages = radix_tree_gang_lookup(&rc->pages,
				(void **)pages, 0, FREE_BATCH);

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pages[i];
			radix_tree_delete(&rc->pages, page_private(page));
			__free_page(page);
		}
	} while (nr_pages == FREE_BATCH);
}

#define PI_FLAG_COWED 62
#define PI_FLAG_DISTRIBUTED 63

static struct page *__lookup_page_info_page(struct remote_context *rc, unsigned long key)
{
	struct page *page = radix_tree_lookup(&rc->pages, key);
	if (!page) {
		int ret;
		page = alloc_page(GFP_ATOMIC | __GFP_ZERO);
		BUG_ON(!page);
		set_page_private(page, key);

		ret = radix_tree_insert(&rc->pages, key, page);
		BUG_ON(ret);
	}
	return page;
}

static inline void SetPageDistributed(struct mm_struct *mm, unsigned long addr)
{
	unsigned long key, offset;
	unsigned long *region;
	struct page *page;
	struct remote_context *rc = mm->remote;
	__get_page_info_key(addr, &key, &offset);

	page = __lookup_page_info_page(rc, key);
	region = kmap_atomic(page);
	set_bit(PI_FLAG_DISTRIBUTED, region + offset);
	kunmap_atomic(region);
}

static inline void SetPageCowed(struct mm_struct *mm, unsigned long addr)
{
	unsigned long key, offset;
	unsigned long *region;
	struct page *page;
	struct remote_context *rc = mm->remote;
	__get_page_info_key(addr, &key, &offset);

	page = __lookup_page_info_page(rc, key);
	region = kmap_atomic(page);
	set_bit(PI_FLAG_COWED, region + offset);
	kunmap_atomic(region);
}

static inline void ClearPageInfo(struct mm_struct *mm, unsigned long addr)
{
	unsigned long offset;
	unsigned long *pi = __get_page_info_mapped(mm, addr, &offset);

	if (!pi) return;
	clear_bit(PI_FLAG_DISTRIBUTED, pi);
	clear_bit(PI_FLAG_COWED, pi);
	bitmap_clear(pi, 0, MAX_POPCORN_NODES);
	kunmap_atomic(pi - offset);
}

static inline bool PageDistributed(struct mm_struct *mm, unsigned long addr)
{
	unsigned long offset;
	unsigned long *pi = __get_page_info_mapped(mm, addr, &offset);
	bool ret;

	if (!pi) return false;
	ret = test_bit(PI_FLAG_DISTRIBUTED, pi);
	kunmap_atomic(pi - offset);
	return ret;
}

static inline bool PageCowed(struct mm_struct *mm, unsigned long addr)
{
	unsigned long offset;
	unsigned long *pi = __get_page_info_mapped(mm, addr, &offset);
	bool ret;

	if (!pi) return false;
	ret = test_bit(PI_FLAG_COWED, pi);
	kunmap_atomic(pi - offset);
	return ret;
}

static inline bool page_is_mine(struct mm_struct *mm, unsigned long addr)
{
	unsigned long offset;
	unsigned long *pi = __get_page_info_mapped(mm, addr, &offset);
	bool ret = true;

	if (!pi) return true;
	if (!test_bit(PI_FLAG_DISTRIBUTED, pi)) goto out;
	ret = test_bit(my_nid, pi);
out:
	kunmap_atomic(pi - offset);
	return ret;
}

bool page_is_mine_pub(struct mm_struct *mm, unsigned long addr)
{
	unsigned long offset;
	unsigned long *pi = __get_page_info_mapped(mm, addr, &offset);
	bool ret = true;

	if (!pi) return true;
	if (!test_bit(PI_FLAG_DISTRIBUTED, pi)) goto out;
	ret = test_bit(my_nid, pi);
out:
	kunmap_atomic(pi - offset);
	return ret;
}

static inline bool test_page_owner(int nid, struct mm_struct *mm, unsigned long addr)
{
	unsigned long offset;
	unsigned long *pi = __get_page_info_mapped(mm, addr, &offset);
	bool ret;

	if (!pi) return false;
	ret = test_bit(nid, pi);
	kunmap_atomic(pi - offset);
	return ret;
}

static inline void set_page_owner(int nid, struct mm_struct *mm, unsigned long addr)
{
	unsigned long offset;
	unsigned long *pi = __get_page_info_mapped(mm, addr, &offset);
	set_bit(nid, pi);
	kunmap_atomic(pi - offset);
}

static inline void clear_page_owner(int nid, struct mm_struct *mm, unsigned long addr)
{
	unsigned long offset;
	unsigned long *pi = __get_page_info_mapped(mm, addr, &offset);
	if (!pi) return;

	clear_bit(nid, pi);
	kunmap_atomic(pi - offset);
}


/**************************************************************************
 * Fault tracking mechanism
 */
enum {
	FAULT_HANDLE_WRITE = 0x01,
	FAULT_HANDLE_INVALIDATE = 0x02,
	FAULT_HANDLE_REMOTE = 0x04,
};

static struct kmem_cache *__fault_handle_cache = NULL;

struct fault_handle {
	struct hlist_node list;

	unsigned long addr;
	unsigned long flags;

	unsigned int limit;
	pid_t pid;
	int ret;

	atomic_t pendings;
	atomic_t pendings_retry;
	wait_queue_head_t waits;
	wait_queue_head_t waits_retry;
	struct remote_context *rc;

	struct completion *complete;
};

static struct fault_handle *__alloc_fault_handle(struct task_struct *tsk, unsigned long addr)
{
	struct fault_handle *fh =
			kmem_cache_alloc(__fault_handle_cache, GFP_ATOMIC);
	int fk = __fault_hash_key(addr);
	BUG_ON(!fh);

	INIT_HLIST_NODE(&fh->list);

	fh->addr = addr;
	fh->flags = 0;

	init_waitqueue_head(&fh->waits);
	init_waitqueue_head(&fh->waits_retry);
	atomic_set(&fh->pendings, 1);
	atomic_set(&fh->pendings_retry, 0);
	fh->limit = 0;
	fh->ret = 0;
	fh->rc = get_task_remote(tsk);
	fh->pid = tsk->pid;
	fh->complete = NULL;

	hlist_add_head(&fh->list, &fh->rc->faults[fk]);
	return fh;
}

/* remote fault */
static struct fault_handle *__start_invalidation(struct task_struct *tsk, unsigned long addr, spinlock_t *ptl)
{
	unsigned long flags;
	struct remote_context *rc = get_task_remote(tsk);
	struct fault_handle *fh;
	bool found = false;
	DECLARE_COMPLETION_ONSTACK(complete);
	int fk = __fault_hash_key(addr);
#ifdef CONFIG_POPCORN_HYPE
	static unsigned long start_inv_cnt = 0;
	volatile unsigned long inv_thre;
#endif

	spin_lock_irqsave(&rc->faults_lock[fk], flags);
	hlist_for_each_entry(fh, &rc->faults[fk], list) {
		if (fh->addr == addr) {
			PGPRINTK("  [%d] inv %lx but %s %s ongoing, wait\n", tsk->pid,
				fh->addr,
				fh->flags & FAULT_HANDLE_REMOTE ? "remote" : "local",
				fh->flags & FAULT_HANDLE_WRITE ? "write" : "read");
			BUG_ON(fh->flags & FAULT_HANDLE_INVALIDATE);
			fh->flags |= FAULT_HANDLE_INVALIDATE;
			fh->complete = &complete;
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&rc->faults_lock[fk], flags);
	put_task_remote(tsk);

#ifdef CONFIG_POPCORN_HYPE
	start_inv_cnt++;
	if (tsk->at_remote) {
		inv_thre = REMOTE_INVPG;
	} else {
		inv_thre = ORIGIN_INVPG;
	}
	/* origin revoke remote INVALIDATE_PAGE */
#endif
	if (found) {
		spin_unlock(ptl);
#ifdef CONFIG_POPCORN_HYPE
		if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
			((start_inv_cnt > inv_thre || INTERESTED_GVA(addr)) &&
			NOTINTERESTED_GVA(addr))) {
			//PGPRINTK(" +[%d] %lx %p (follower) #%lu\n",
			//			tsk->pid, addr, fh, start_inv_cnt);
		}
#endif
		wait_for_completion(&complete);
#ifdef CONFIG_POPCORN_HYPE
		if (pophype_debug ||
		//if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
			((start_inv_cnt > inv_thre || INTERESTED_GVA(addr)) &&
			NOTINTERESTED_GVA(addr))) {
			//PGPRINTK(" =[%d] %lx %p (inv follower done)\n", tsk->pid, addr, fh);
		}
#else
		PGPRINTK(" =[%d] %lx %p (inv follower done)\n", tsk->pid, addr, fh);
#endif
		spin_lock(ptl);
	} else {
		fh = NULL;
#ifdef CONFIG_POPCORN_HYPE
		if (pophype_debug ||
		//if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
			((start_inv_cnt > inv_thre || INTERESTED_GVA(addr)) &&
			NOTINTERESTED_GVA(addr))) {
			//PGPRINTK(" =[%d] %lx (inv leader) #%lu\n",
			//			tsk->pid, addr, start_inv_cnt);
		}
#else
		PGPRINTK(" =[%d] %lx (inv leader)\n", tsk->pid, addr);
#endif
	}
	return fh;
}

static void __finish_invalidation(struct fault_handle *fh)
{
	unsigned long flags;
	int fk;

	if (!fh) return;
	fk = __fault_hash_key(fh->addr);

	BUG_ON(atomic_read(&fh->pendings));
	spin_lock_irqsave(&fh->rc->faults_lock[fk], flags);
	hlist_del(&fh->list);
	spin_unlock_irqrestore(&fh->rc->faults_lock[fk], flags);

	__put_task_remote(fh->rc);
	if (atomic_read(&fh->pendings_retry)) {
		wake_up_all(&fh->waits_retry);
	} else {
		kmem_cache_free(__fault_handle_cache, fh);
	}
}

static struct fault_handle *__start_fault_handling(struct task_struct *tsk, unsigned long addr, unsigned long fault_flags, spinlock_t *ptl, bool *leader)
	__releases(ptl)
{
	unsigned long flags;
	struct fault_handle *fh;
	bool found = false;
	struct remote_context *rc = get_task_remote(tsk);
	DEFINE_WAIT(wait);
	int fk = __fault_hash_key(addr);

	spin_lock_irqsave(&rc->faults_lock[fk], flags);
	spin_unlock(ptl);

	hlist_for_each_entry(fh, &rc->faults[fk], list) {
		if (fh->addr == addr) {
			found = true;
			break;
		}
	}

	if (found) {
		unsigned long action =
				get_fh_action(tsk->at_remote, fh->flags, fault_flags);

#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(action == FH_ACTION_INVALID);
#endif
		if (action & FH_ACTION_RETRY) {
			if (action & FH_ACTION_WAIT) {
#ifdef CONFIG_POPCORN_HYPE
				if (NOTINTERESTED_GVA(addr) || pophype_debug) {
					PGPRINTK("  [%d] waits %lx fh %p %lx cannot coalesce\n",
												tsk->pid, addr, fh, fh->addr);
				}
#endif
				goto out_wait_retry;
			}
			goto out_retry;
		}
#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(action != FH_ACTION_FOLLOW);
#endif

		if (fh->limit++ > FH_ACTION_MAX_FOLLOWER) {
#ifdef CONFIG_POPCORN_HYPE
			if (NOTINTERESTED_GVA(addr) || pophype_debug) {
				PGPRINTK("  [%d] waits %lx fh %p %lx too many followes\n",
											tsk->pid, addr, fh, fh->addr);
			}
#endif
			goto out_wait_retry;
		}

		atomic_inc(&fh->pendings);
#ifndef CONFIG_POPCORN_DEBUG_PAGE_SERVER
		prepare_to_wait(&fh->waits, &wait, TASK_UNINTERRUPTIBLE);
#else
		prepare_to_wait_exclusive(&fh->waits, &wait, TASK_UNINTERRUPTIBLE);
#endif
		spin_unlock_irqrestore(&rc->faults_lock[fk], flags);
		PGPRINTK(" +[%d] %lx %p\n", tsk->pid, addr, fh);
		put_task_remote(tsk);

		io_schedule();
		finish_wait(&fh->waits, &wait);

		fh->pid = tsk->pid;
		*leader = false;
		return fh;
	}

	fh = __alloc_fault_handle(tsk, addr);
	fh->flags |= fault_for_write(fault_flags) ? FAULT_HANDLE_WRITE : 0;
	fh->flags |= (fault_flags & FAULT_FLAG_REMOTE) ? FAULT_HANDLE_REMOTE : 0;

	spin_unlock_irqrestore(&rc->faults_lock[fk], flags);
	put_task_remote(tsk);

	*leader = true;
	return fh;

out_wait_retry:
	atomic_inc(&fh->pendings_retry);
	prepare_to_wait(&fh->waits_retry, &wait, TASK_UNINTERRUPTIBLE);
	spin_unlock_irqrestore(&rc->faults_lock[fk], flags);
	put_task_remote(tsk);

#ifdef CONFIG_POPCORN_HYPE
#else
	PGPRINTK("  [%d] waits %p too many followes/fh cannot coalesce\n",
														tsk->pid, fh);
#endif
	io_schedule();
	finish_wait(&fh->waits_retry, &wait);
	if (atomic_dec_and_test(&fh->pendings_retry)) {
		kmem_cache_free(__fault_handle_cache, fh);
	}
	return NULL;

out_retry:
	spin_unlock_irqrestore(&rc->faults_lock[fk], flags);
	put_task_remote(tsk);

#ifdef CONFIG_POPCORN_HYPE
	if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
		((distributed_process(tsk) &&
		INTERESTED_GVA(addr)) &&
		NOTINTERESTED_GVA(addr))) {
		PGPRINTK("\t\t  [%d] locked. retry 0x%lx %p\n", tsk->pid, addr, fh);
	} else {
		//PGPRINTK("  [%d] locked. retry %p\n", tsk->pid, fh);
	}
#else
	PGPRINTK("  [%d] locked. retry %p\n", tsk->pid, fh);
#endif
	return NULL;
}

static bool __finish_fault_handling(struct fault_handle *fh)
{
	unsigned long flags;
	bool last = false;
	int fk = __fault_hash_key(fh->addr);

	spin_lock_irqsave(&fh->rc->faults_lock[fk], flags);
	if (atomic_dec_return(&fh->pendings)) {
		PGPRINTK(" >[%d] %lx %p\n", fh->pid, fh->addr, fh);
#ifndef CONFIG_POPCORN_DEBUG_PAGE_SERVER
		wake_up_all(&fh->waits);
#else
		wake_up(&fh->waits);
#endif
	} else {
#ifdef CONFIG_POPCORN_HYPE
		static unsigned long origin_pgfault_fini_cnt = 0;
		unsigned long origin_pgfault_fini_thre;
		origin_pgfault_fini_cnt++;
		if (current->at_remote)
			origin_pgfault_fini_thre = REMOTE_PGFAULT_SKIP;
		else
			origin_pgfault_fini_thre = ORIGIN_PGFAULT_SKIP;

		if (pophype_debug ||
		//if (pophype_debug || INTERESTED_GVA_2AFTER4(fh->addr) ||
			((origin_pgfault_fini_cnt > origin_pgfault_fini_thre ||
			INTERESTED_GVA(fh->addr)) &&
			NOTINTERESTED_GVA(fh->addr))) {
			//PGPRINTK("\t\t\t>>[%d] %lx %p #%lu\n",
			//		fh->pid, fh->addr, fh, origin_pgfault_fini_cnt);
		}
#else
		PGPRINTK(">>[%d] %lx %p\n", fh->pid, fh->addr, fh);
#endif
		if (fh->complete) {
			complete(fh->complete);
		} else {
			hlist_del(&fh->list);
			last = true;
		}
	}
	spin_unlock_irqrestore(&fh->rc->faults_lock[fk], flags);

	if (last) {
		__put_task_remote(fh->rc);
		if (atomic_read(&fh->pendings_retry)) {
			wake_up_all(&fh->waits_retry);
		} else {
			kmem_cache_free(__fault_handle_cache, fh);
		}
	}
	return last;
}


/**************************************************************************
 * Helper functions for PTE following
 */
static pte_t *__get_pte_at(struct mm_struct *mm, unsigned long addr, pmd_t **ppmd, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (!pgd || pgd_none(*pgd)) return NULL;

	pud = pud_offset(pgd, addr);
	if (!pud || pud_none(*pud)) return NULL;

	pmd = pmd_offset(pud, addr);
	if (!pmd || pmd_none(*pmd)) return NULL;

	*ppmd = pmd;
	*ptlp = pte_lockptr(mm, pmd);

	return pte_offset_map(pmd, addr);
}

static pte_t *__get_pte_at_alloc(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, pmd_t **ppmd, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, addr);
	if (!pgd) return NULL;

	pud = pud_alloc(mm, pgd, addr);
	if (!pud) return NULL;

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd) return NULL;

	pte = pte_alloc_map(mm, vma, pmd, addr);

	*ppmd = pmd;
	*ptlp = pte_lockptr(mm, pmd);
	return pte;
}

static struct page *__find_page_at(struct mm_struct *mm, unsigned long addr, pte_t **ptep, spinlock_t **ptlp)
{
	pmd_t *pmd;
	pte_t *pte = NULL;
	spinlock_t *ptl = NULL;
	struct page *page = ERR_PTR(-ENOMEM);

	pte = __get_pte_at(mm, addr, &pmd, &ptl);

	if (pte == NULL) {
		pte = NULL;
		ptl = NULL;
		page = ERR_PTR(-EINVAL);
		goto out;
	}

	if (pte_none(*pte)) {
		pte_unmap(pte);
		pte = NULL;
		ptl = NULL;
		page = ERR_PTR(-ENOENT);
		goto out;
	}

	spin_lock(ptl);
	page = pte_page(*pte);
	get_page(page);

out:
	*ptep = pte;
	*ptlp = ptl;
	return page;
}


/**************************************************************************
 * Panicked by bug!!!!!
 */
void page_server_panic(bool condition, struct mm_struct *mm, unsigned long address, pte_t *pte, pte_t pte_val)
{
	unsigned long *pi;
	unsigned long pi_val = -1;
	unsigned long offset;
	if (!condition) return;

	pi = __get_page_info_mapped(mm, address, &offset);
	if (pi) {
		pi_val = *pi;
		kunmap_atomic(pi - offset);
	}

	printk(KERN_ERR "------------------ Start panicking -----------------\n");
	printk(KERN_ERR "%s: %lx %p %lx %p %lx\n", __func__,
			address, pi, pi_val, pte, pte_flags(pte_val));
	show_regs(current_pt_regs());
	BUG_ON("Page server panicked!!");
}


/**************************************************************************
 * Flush pages to the origin
 */
enum {
	FLUSH_FLAG_START = 0x01,
	FLUSH_FLAG_FLUSH = 0x02,
	FLUSH_FLAG_RELEASE = 0x04,
	FLUSH_FLAG_LAST = 0x10,
};


static void process_remote_page_flush(struct work_struct *work)
{
	START_KMSG_WORK(remote_page_flush_t, req, work);
	unsigned long addr = req->addr;
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct remote_context *rc;
	struct page *page;
	pte_t *pte, entry;
	spinlock_t *ptl;
	void *paddr;
	struct vm_area_struct *vma;
	remote_page_flush_ack_t res = {
		.remote_ws = req->remote_ws,
	};

	PGPRINTK("  [%d] flush ->[%d/%d] %lx\n",
			req->origin_pid, req->remote_pid, req->remote_nid, addr);

	tsk = __get_task_struct(req->origin_pid);
	if (!tsk) goto out_free;

	mm = get_task_mm(tsk);
	rc = get_task_remote(tsk);

	if (req->flags & FLUSH_FLAG_START) {
		res.flags = FLUSH_FLAG_START;
		pcn_kmsg_send(PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH_ACK,
				req->remote_nid, &res, sizeof(res));
		goto out_put;
	} else if (req->flags & FLUSH_FLAG_LAST) {
		res.flags = FLUSH_FLAG_LAST;
		pcn_kmsg_send(PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH_ACK,
				req->remote_nid, &res, sizeof(res));
		goto out_put;
	}

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	BUG_ON(!vma || vma->vm_start > addr);

	page = __find_page_at(mm, addr, &pte, &ptl);
	BUG_ON(IS_ERR(page));

	/* XXX should be outside of ptl lock */
	if (req->flags & FLUSH_FLAG_FLUSH) {
		paddr = kmap(page);
		copy_to_user_page(vma, page, addr, paddr, req->page, PAGE_SIZE);
		kunmap(page);
	}

	SetPageDistributed(mm, addr);
	set_page_owner(my_nid, mm, addr);
	clear_page_owner(req->remote_nid, mm, addr);

	/* XXX Should update through clear_flush and set */
	entry = pte_make_valid(*pte);

	set_pte_at_notify(mm, addr, pte, entry);
	update_mmu_cache(vma, addr, pte);
	flush_tlb_page(vma, addr);

	put_page(page);

	pte_unmap_unlock(pte, ptl);
	up_read(&mm->mmap_sem);

out_put:
	put_task_remote(tsk);
	put_task_struct(tsk);
	mmput(mm);

out_free:
	END_KMSG_WORK(req);
}


static int __do_pte_flush(pte_t *pte, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	remote_page_flush_t *req = walk->private;
	struct vm_area_struct *vma = walk->vma;
	struct page *page;
	int req_size;
	enum pcn_kmsg_type req_type;
	char type;

	if (pte_none(*pte)) return 0;

	page = pte_page(*pte);
	BUG_ON(!page);

	if (test_page_owner(my_nid, vma->vm_mm, addr)) {
		req->addr = addr;
		if ((vma->vm_flags & VM_WRITE) && pte_write(*pte)) {
			void *paddr;
			flush_cache_page(vma, addr, page_to_pfn(page));
			paddr = kmap_atomic(page);
			copy_from_user_page(walk->vma, page, addr, req->page, paddr, PAGE_SIZE);
			kunmap_atomic(paddr);

			req_type = PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH;
			req_size = sizeof(remote_page_flush_t);
			req->flags = FLUSH_FLAG_FLUSH;
			type = '*';
		} else {
			req_type = PCN_KMSG_TYPE_REMOTE_PAGE_RELEASE;
			req_size = sizeof(remote_page_release_t);
			req->flags = FLUSH_FLAG_RELEASE;
			type = '+';
		}
		clear_page_owner(my_nid, vma->vm_mm, addr);

		pcn_kmsg_send(req_type, current->origin_nid, req, req_size);
	} else {
		*pte = pte_make_valid(*pte);
		type = '-';
	}
	PGPRINTK("  [%d] %c %lx\n", current->pid, type, addr);

	return 0;
}


int page_server_flush_remote_pages(struct remote_context *rc)
{
	remote_page_flush_t *req = kmalloc(sizeof(*req), GFP_KERNEL);
	struct mm_struct *mm = rc->mm;
	struct mm_walk walk = {
		.pte_entry = __do_pte_flush,
		.mm = mm,
		.private = req,
	};
	struct vm_area_struct *vma;
	struct wait_station *ws = get_wait_station(current);

	BUG_ON(!req);

	PGPRINTK("FLUSH_REMOTE_PAGES [%d]\n", current->pid);

	req->remote_nid = my_nid;
	req->remote_pid = current->pid;
	req->remote_ws = ws->id;
	req->origin_pid = current->origin_pid;
	req->addr = 0;

	/* Notify the start synchronously */
	req->flags = FLUSH_FLAG_START;
	pcn_kmsg_send(PCN_KMSG_TYPE_REMOTE_PAGE_RELEASE,
			current->origin_nid, req, sizeof(*req));
	wait_at_station(ws);

	/* Send pages asynchronously */
	ws = get_wait_station(current);
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		walk.vma = vma;
		walk_page_vma(vma, &walk);
	}
	up_read(&mm->mmap_sem);

	/* Notify the completion synchronously */
	req->flags = FLUSH_FLAG_LAST;
	pcn_kmsg_send(PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH,
			current->origin_nid, req, sizeof(*req));
	wait_at_station(ws);

	kfree(req);

	// XXX: make sure there is no backlog.
	msleep(1000);

	return 0;
}

static int handle_remote_page_flush_ack(struct pcn_kmsg_message *msg)
{
	remote_page_flush_ack_t *req = (remote_page_flush_ack_t *)msg;
	struct wait_station *ws = wait_station(req->remote_ws);

	complete(&ws->pendings);

	pcn_kmsg_done(req);
	return 0;
}


/**************************************************************************
 * Page invalidation protocol (remote fault - got a revoking msg from remote)
 */
static void __do_invalidate_page(struct task_struct *tsk, page_invalidate_request_t *req)
{
	struct mm_struct *mm = get_task_mm(tsk);
	struct vm_area_struct *vma;
	pmd_t *pmd;
	pte_t *pte, entry;
	spinlock_t *ptl;
	int ret = 0;
	unsigned long addr = req->addr;
	struct fault_handle *fh;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_STAT
	{
		static unsigned long do_inv_cnt = 0;
		volatile unsigned long do_inv_thre;
		do_inv_cnt++;
		if (tsk->at_remote) {
			do_inv_thre = REMOTE_INVPG;
		} else {
			do_inv_thre = ORIGIN_INVPG;
		}

		/* origin revoke remote INVALIDATE_PAGE*/
		//if ((do_inv_cnt > do_inv_thre ||
		//	INTERESTED_GVA(addr)) &&
		//	NOTINTERESTED_GVA(addr)) {
		//if (do_inv_cnt > do_inv_thre || pophype_debug) { /* commented out since im debugging */
		if (INTERESTED_GVA_2AFTER4(addr)) {
			PGPRINTK("\n\t\tINVALIDATE_PAGE [%d] %lx [%d/%d] #%lu\n",
						tsk->pid, addr, req->origin_pid,
						PCN_KMSG_FROM_NID(req), do_inv_cnt);
		}
	}
#endif
#else
	PGPRINTK("\n\t\tINVALIDATE_PAGE [%d] %lx [%d/%d]\n", tsk->pid, addr,
				req->origin_pid, PCN_KMSG_FROM_NID(req));
#endif
	pte = __get_pte_at(mm, addr, &pmd, &ptl);
	if (!pte) goto out;

	spin_lock(ptl);
	fh = __start_invalidation(tsk, addr, ptl);

	clear_page_owner(my_nid, mm, addr);

	BUG_ON(!pte_present(*pte));
	entry = ptep_clear_flush(vma, addr, pte);
	entry = pte_make_invalid(entry);
#ifdef CONFIG_POPCORN_HYPE
	/* kvm_mmu_notifier_invalidate_page */
	mmu_notifier_invalidate_page(mm, addr);
#endif

	set_pte_at_notify(mm, addr, pte, entry);
	update_mmu_cache(vma, addr, pte);

	__finish_invalidation(fh);
	pte_unmap_unlock(pte, ptl);

out:
	up_read(&mm->mmap_sem);
	mmput(mm);
}

static void process_page_invalidate_request(struct work_struct *work)
{
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, invh_end, invh_start = ktime_get();
#endif
	START_KMSG_WORK(page_invalidate_request_t, req, work);
	page_invalidate_response_t *res;
	struct task_struct *tsk;

	res = pcn_kmsg_get(sizeof(*res));
	res->origin_pid = req->origin_pid;
	res->origin_ws = req->origin_ws;
	res->remote_pid = req->remote_pid;

	/* Only home issues invalidate requests. Hence, I am a remote */
	tsk = __get_task_struct(req->remote_pid);
	if (!tsk) {
		PGPRINTK("%s: no such process %d %d %lx\n", __func__,
				req->origin_pid, req->remote_pid, req->addr);
		pcn_kmsg_put(res);
		goto out_free;
	}

	__do_invalidate_page(tsk, req);

#ifdef CONFIG_POPCORN_HYPE
	{
		static unsigned long process_inv_cnt = 0;
		unsigned long process_inv_thre;
		process_inv_cnt++;
		if (current->at_remote)
			process_inv_thre = REMOTE_PGFAULT_SKIP;
		else
			process_inv_thre = ORIGIN_PGFAULT_SKIP;

		//if (pophype_debug || INTERESTED_GVA_2AFTER4(req->addr) ||
		if (pophype_debug ||
			((process_inv_cnt > process_inv_thre ||
			INTERESTED_GVA(req->addr)) &&
			NOTINTERESTED_GVA(req->addr))) {
			//PGPRINTK("\t\t>>[%d] ->[%d/%d] (INV)\n", req->remote_pid, res->origin_pid,
			//		PCN_KMSG_FROM_NID(req));
		}
	}
#else
	PGPRINTK("\t\t>>[%d] ->[%d/%d]\n", req->remote_pid, res->origin_pid,
			PCN_KMSG_FROM_NID(req));
#endif
	pcn_kmsg_post(PCN_KMSG_TYPE_PAGE_INVALIDATE_RESPONSE,
			PCN_KMSG_FROM_NID(req), res, sizeof(*res));

	put_task_struct(tsk);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	invh_end = ktime_get();
	dt = ktime_sub(invh_end, invh_start);
	atomic64_add(ktime_to_ns(dt), &invh_ns);
	atomic64_inc(&invh_cnt);
#endif

out_free:
	END_KMSG_WORK(req);
}


static int handle_page_invalidate_response(struct pcn_kmsg_message *msg)
{
	page_invalidate_response_t *res = (page_invalidate_response_t *)msg;
	struct wait_station *ws = wait_station(res->origin_ws);

	if (atomic_dec_and_test(&ws->pendings_count)) {
		complete(&ws->pendings);
	}

	pcn_kmsg_done(res);
	return 0;
}

/* Me sending a msg to revoke others ownership */
static void __revoke_page_ownership(struct task_struct *tsk, int nid, pid_t pid, unsigned long addr, int ws_id)
{
#ifdef CONFIG_POPCORN_HYPE
	static unsigned long revoke_cnt = 0;
	volatile unsigned long revoke_thre;
#endif
	page_invalidate_request_t *req = pcn_kmsg_get(sizeof(*req));

	req->addr = addr;
	req->origin_pid = tsk->pid;
	req->origin_ws = ws_id;
	req->remote_pid = pid;

#ifdef CONFIG_POPCORN_HYPE
	revoke_cnt++;
	if (current->at_remote) {
		revoke_thre = REMOTE_REVOKE;
	} else {
		revoke_thre = ORIGIN_REVOKE;
	}
	/* origin revoke remote INVALIDATE_PAGE*/
	if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
		((revoke_cnt > revoke_thre ||
		INTERESTED_GVA(addr)) &&
		NOTINTERESTED_GVA(addr))) {
		PGPRINTK("\t\t  [%d] revoke %lx [%d/%d] #%lu\n",
				tsk->pid, addr, pid, nid, revoke_cnt);
	}
#else
	PGPRINTK("  [%d] revoke %lx [%d/%d]\n", tsk->pid, addr, pid, nid);
#endif
	pcn_kmsg_post(PCN_KMSG_TYPE_PAGE_INVALIDATE_REQUEST, nid, req, sizeof(*req));
}


/**************************************************************************
 * Voluntarily release page ownership
 */
int process_madvise_release_from_remote(int from_nid, unsigned long start, unsigned long end)
{
	struct mm_struct *mm;
	unsigned long addr;
	int nr_pages = 0;

	mm = get_task_mm(current);
	for (addr = start; addr < end; addr += PAGE_SIZE) {
		pmd_t *pmd;
		pte_t *pte;
		spinlock_t *ptl;
		pte = __get_pte_at(mm, addr, &pmd, &ptl);
		if (!pte) continue;
		spin_lock(ptl);
		if (!pte_none(*pte)) {
			clear_page_owner(from_nid, mm, addr);
			nr_pages++;
		}
		pte_unmap_unlock(pte, ptl);
	}
	mmput(mm);
	VSPRINTK("  [%d] %d %d / %ld %lx-%lx\n", current->pid, from_nid,
			nr_pages, (end - start) / PAGE_SIZE, start, end);
	return 0;
}

int page_server_release_page_ownership(struct vm_area_struct *vma, unsigned long addr)
{
	struct mm_struct *mm = vma->vm_mm;
	pmd_t *pmd;
	pte_t *pte;
	pte_t pte_val;
	spinlock_t *ptl;

	pte = __get_pte_at(mm, addr, &pmd, &ptl);
	if (!pte) return 0;

	spin_lock(ptl);
	if (pte_none(*pte) || !pte_present(*pte)) {
		pte_unmap_unlock(pte, ptl);
		return 0;
	}

	clear_page_owner(my_nid, mm, addr);
	pte_val = ptep_clear_flush(vma, addr, pte);
	pte_val = pte_make_invalid(pte_val);
#ifdef CONFIG_POPCORN_HYPE
	/* kvm_mmu_notifier_invalidate_page */
	mmu_notifier_invalidate_page(mm, addr);
#endif

	set_pte_at_notify(mm, addr, pte, pte_val);
	update_mmu_cache(vma, addr, pte);
	pte_unmap_unlock(pte, ptl);
	return 1;
}


/**************************************************************************
 * Handle page faults happened at remote nodes.
 */
static int handle_remote_page_response(struct pcn_kmsg_message *msg)
{
	remote_page_response_t *res = (remote_page_response_t *)msg;
	struct wait_station *ws = wait_station(res->origin_ws);

#ifdef CONFIG_POPCORN_HYPE
	static unsigned long pg_response_cnt = 0;
	unsigned long pg_response_thre;
	//struct task_struct *tsk = __get_task_struct(res->remote_pid);
	pg_response_cnt++;
	if (current->at_remote)
		pg_response_thre = REMOTE_PGFAULT_SKIP;
	else
		pg_response_thre = ORIGIN_PGFAULT_SKIP;

	if ((pg_response_cnt > pg_response_thre) &&
		NOTINTERESTED_GVA(res->addr)) {
		PGPRINTK("  [%d] <-[%d/%d] %lx %x\n", // TODO make sure I can see it
				ws->pid, res->remote_pid, PCN_KMSG_FROM_NID(res),
				res->addr, res->result);
	}
#else
	PGPRINTK("  [%d] <-[%d/%d] %lx %x\n",
			ws->pid, res->remote_pid, PCN_KMSG_FROM_NID(res),
			res->addr, res->result);
#endif
	ws->private = res;

	if (atomic_dec_and_test(&ws->pendings_count))
		complete(&ws->pendings);
	return 0;
}

#define TRANSFER_PAGE_WITH_RDMA \
		pcn_kmsg_has_features(PCN_KMSG_FEATURE_RDMA)

static int __request_remote_page(struct task_struct *tsk, int from_nid, pid_t from_pid, unsigned long addr, unsigned long fault_flags, int ws_id, struct pcn_kmsg_rdma_handle **rh)
{
	remote_page_request_t *req;

	*rh = NULL;

	req = pcn_kmsg_get(sizeof(*req));
	req->addr = addr;
	req->fault_flags = fault_flags;

	req->origin_pid = tsk->pid;
	req->origin_ws = ws_id;

	req->remote_pid = from_pid;
	req->instr_addr = instruction_pointer(current_pt_regs());

	if (TRANSFER_PAGE_WITH_RDMA) {
		struct pcn_kmsg_rdma_handle *handle =
				pcn_kmsg_pin_rdma_buffer(NULL, PAGE_SIZE);
		if (IS_ERR(handle)) {
			pcn_kmsg_put(req);
			return PTR_ERR(handle);
		}
		*rh = handle;
		req->rdma_addr = handle->dma_addr;
		req->rdma_key = handle->rkey;
	} else {
		req->rdma_addr = 0;
		req->rdma_key = 0;
	}

#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_CHECK_SANITY
	if (!req) {
		DDPRINTK("PROBLEMATIC ADDR [[[%lx]]]\n", addr);
		dump_stack();
		msleep(60*1000);
	}
	if (from_pid < 0 || from_nid < 0) {
		printk(KERN_ERR "  BAD [%d] ->[%d/%d] addr %lx instr %lx\n", tsk->pid,
							from_pid, from_nid, addr, req->instr_addr);
		dump_stack();
		msleep(60*1000);
	}
#endif

	{
		static unsigned long pg_req_cnt = 0;
		unsigned long pg_req_thre;
		pg_req_cnt++;
		if (current->at_remote)
			pg_req_thre = REMOTE_PGFAULT_SKIP;
		else
			pg_req_thre = ORIGIN_PGFAULT_SKIP;

		if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
			((pg_req_cnt > pg_req_thre ||
			INTERESTED_GVA(addr)) &&
			NOTINTERESTED_GVA(addr))) {
			PGPRINTK("  [%d] ->[%d/%d] %lx instr %lx\n", tsk->pid,
					from_pid, from_nid, addr, req->instr_addr);
		}
	}
#else
	PGPRINTK("  [%d] ->[%d/%d] %lx %lx\n", tsk->pid,
			from_pid, from_nid, addr, req->instr_addr);
#endif
	pcn_kmsg_post(PCN_KMSG_TYPE_REMOTE_PAGE_REQUEST,
			from_nid, req, sizeof(*req));
	return 0;
}

static remote_page_response_t *__fetch_page_from_origin(struct task_struct *tsk, struct vm_area_struct *vma, unsigned long addr, unsigned long fault_flags, struct page *page)
{
	remote_page_response_t *rp;
	struct wait_station *ws = get_wait_station(tsk);
	struct pcn_kmsg_rdma_handle *rh;

#if 0
#ifdef CONFIG_POPCORN_HYPE
	BUG_ON(!tsk);
	if (tsk->origin_nid < 0 || tsk->origin_pid < 0) {
		printk("  BAD [%d] ->[%d/%d] addr %lx instr %lx\n", tsk->pid,
						tsk->origin_nid, tsk->origin_pid,
						instruction_pointer(current_pt_regs()));
		dump_stack();
	}
#endif
#endif

	__request_remote_page(tsk, tsk->origin_nid, tsk->origin_pid,
			addr, fault_flags, ws->id, &rh);

	rp = wait_at_station(ws);
	if (rp->result == 0) {
		void *paddr = kmap(page);
		if (TRANSFER_PAGE_WITH_RDMA) {
			copy_to_user_page(vma, page, addr, paddr, rh->addr, PAGE_SIZE);
		} else {
			copy_to_user_page(vma, page, addr, paddr, rp->page, PAGE_SIZE);
		}
		kunmap(page);
		flush_dcache_page(page);
		__SetPageUptodate(page);
	}

	if (rh) pcn_kmsg_unpin_rdma_buffer(rh);

	return rp;
}

static int __claim_remote_page(struct task_struct *tsk, struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, unsigned long fault_flags, struct page *page, int local_origin)
{
	int peers;
	unsigned int random = prandom_u32();
	struct wait_station *ws;
	struct remote_context *rc = __get_mm_remote(mm);
	remote_page_response_t *rp;
	int from, from_nid;
	/* Read when @from becomes zero and save the nid to @from_nid */
	int nid;
	struct pcn_kmsg_rdma_handle *rh = NULL;
	unsigned long offset;
	struct page *pip = __get_page_info_page(mm, addr, &offset);
	unsigned long *pi = (unsigned long *)kmap(pip) + offset;
#ifdef CONFIG_POPCORN_HYPE
	int origin_retry = 0;
	int ret = 0; /* hyper fail = HYPE_RETRY */
	bool is_clean_bit = false;
#endif
	int page_trans = 0;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	//int revoke = 0;
	ktime_t fp_start;
	if (local_origin) /* aka !pg_mine */
		fp_start = ktime_get();
#endif
#ifdef CONFIG_POPCORN_HYPE
//reclaimrpg: /* not used now return to outside and retry outside to release fh & ptl*/
#endif
	BUG_ON(!pip);

	peers = bitmap_weight(pi, MAX_POPCORN_NODES);

	if (test_bit(my_nid, pi)) {
		peers--; /* page is mine */
	}
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_CHECK_SANITY
	/* no longer need this since I put retry outside this function */
	if (!origin_retry) {
		page_server_panic(peers == 0, mm, addr, NULL, __pte(0));
	} // else { DON'T LET RETY CHECK PANIC }
	else {
		printk(" [%d] %lx peers==0 (%s) pte_flags(__pte(0)) %lx "
				"from_nid %d RETRY#%d\n",
				tsk->pid, addr,
				peers == 0 ? "*****true(BUG - NOT DISTRIBUTED)*****" :
														"false(GOOD)",
				pte_flags(__pte(0)), from_nid, origin_retry);
	}
#endif
#else
#ifdef CONFIG_POPCORN_CHECK_SANITY
	page_server_panic(peers == 0, mm, addr, NULL, __pte(0));
#endif
#endif
	from = random % peers;

	// PGPRINTK("  [%d] fetch %lx from %d peers\n", tsk->pid, addr, peers);

	if (fault_for_read(fault_flags)) {
		peers = 1;
	}
	ws = get_wait_station_multiple(tsk, peers);

	for_each_set_bit(nid, pi, MAX_POPCORN_NODES) {
		pid_t pid = rc->remote_tgids[nid];
		if (nid == my_nid) continue;
		if (from-- == 0) {
			from_nid = nid;
			__request_remote_page(tsk, nid, pid, addr, fault_flags, ws->id, &rh);
		} else {
			if (fault_for_write(fault_flags)) {
#ifdef CONFIG_POPCORN_HYPE
				BUG_ON("Two nodes shouldn't send stand along inv");
#endif
				clear_bit(nid, pi);
				__revoke_page_ownership(tsk, nid, pid, addr, ws->id);
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
				//revoke = 1;
				//BUG_ON(revoke && "Two nodes shouldn't send stand along inv");
				BUG_ON("Two nodes shouldn't send stand along inv");
#endif
			}
		}
		if (--peers == 0) break;
	}

	rp = wait_at_station(ws);

	/* Popcorn assume this is 100% succ */
	if (fault_for_write(fault_flags)) {
		clear_bit(from_nid, pi); /* got page ownership from from_nid */
#ifdef CONFIG_POPCORN_HYPE
		is_clean_bit = true;
#endif
	}

	if (rp->result == 0) {
		void *paddr = kmap(page);
		if (TRANSFER_PAGE_WITH_RDMA) {
			copy_to_user_page(vma, page, addr, paddr, rh->addr, PAGE_SIZE);
		} else {
			copy_to_user_page(vma, page, addr, paddr, rp->page, PAGE_SIZE);
		}
		kunmap(page);
		flush_dcache_page(page);
		__SetPageUptodate(page);
		page_trans = 1;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
		//page_trans = 1; // TODO have a look
#endif
	}
	//pcn_kmsg_done(rp);
	//if (rh) pcn_kmsg_unpin_rdma_buffer(rh);

#ifdef CONFIG_POPCORN_HYPE
	if (!my_nid && /* origin */
		local_origin && /* !pg_mine */
		!page_trans)
	{
		if (rp->result != 0 && is_clean_bit) {
			printk("Jack - %d %x wrong\n", rp->result, rp->result); /* retry = 78 */
		}
		//BUG_ON("!pg_mine must transfer page");
		if (NOTINTERESTED_GVA(addr)) {
			printk(" [%d] %lx !pg_mine but must succ RETRY (Wierd - "
								"my patch applied)\n", tsk->pid, addr);
		}
		/* pophype: restore states */
		if (is_clean_bit) {
			set_bit(from_nid, pi);
		}

		//schedule(); // testing
		//udelay(100); // good
		//BUG_ON(++origin_retry > RETRY_ORIGINFAULT_AT_ORIGIN);
		//goto reclaimrpg;
		ret = HYPE_RETRY;
	}
#endif
	pcn_kmsg_done(rp);
	if (rh) pcn_kmsg_unpin_rdma_buffer(rh);

	__put_task_remote(rc);
	kunmap(pip);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	//if (!my_nid && local_origin && !revoke && page_trans) {
	//if (!my_nid && local_origin && page_trans) {
	if (!my_nid && local_origin) {
		if (fault_for_write(fault_flags)) { /* page + inv */
			ktime_t dt, fp_end = ktime_get();
			dt = ktime_sub(fp_end, fp_start);
			atomic64_add(ktime_to_ns(dt), &fpin_ns);
			atomic64_inc(&fpin_cnt);
		} else { /* page + !inv  */
		//if (page_trans) {
			ktime_t dt, fp_end = ktime_get();
			dt = ktime_sub(fp_end, fp_start);
			atomic64_add(ktime_to_ns(dt), &fp_ns);
			atomic64_inc(&fp_cnt);
		//}
		}

		///* Jack: DON'T CATCH FOR HYPE_RETRY release all locks outside */
		//if (!page_trans)
		//	BUG_ON("!pg_mine must transfer page");
	}
#endif
#ifdef CONFIG_POPCORN_HYPE
	return ret;
#else
	return 0;
#endif
}


static void __claim_local_page(struct task_struct *tsk, unsigned long addr, int except_nid)
{
	struct mm_struct *mm = tsk->mm;
	unsigned long offset;
	struct page *pip = __get_page_info_page(mm, addr, &offset);
	unsigned long *pi;
	int peers;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	int is_inv = 0;
	ktime_t dt, inv_end, inv_start;
#endif

	if (!pip) return; /* skip claiming non-distributed page */
	pi = (unsigned long *)kmap(pip) + offset;
	peers = bitmap_weight(pi, MAX_POPCORN_NODES);
	if (!peers) {
		kunmap(pip);
		return;	/* skip claiming the page that is not distributed */
	}

	BUG_ON(!test_bit(except_nid, pi));
	peers--;	/* exclude except_nid from peers */

	if (test_bit(my_nid, pi) && except_nid != my_nid) peers--;

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	inv_start = ktime_get();
#endif

	if (peers > 0) {
		int nid;
		struct remote_context *rc = get_task_remote(tsk);
		struct wait_station *ws = get_wait_station_multiple(tsk, peers);

		for_each_set_bit(nid, pi, MAX_POPCORN_NODES) {
			pid_t pid = rc->remote_tgids[nid];
			if (nid == except_nid || nid == my_nid) continue;

			clear_bit(nid, pi);
			__revoke_page_ownership(tsk, nid, pid, addr, ws->id);
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
			is_inv = 1;
#endif
		}
		put_task_remote(tsk);

		wait_at_station(ws);
	}

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	if (is_inv) {
		inv_end = ktime_get();
		dt = ktime_sub(inv_end, inv_start);
		atomic64_add(ktime_to_ns(dt), &inv_ns);
		atomic64_inc(&inv_cnt);
	}
#endif

	kunmap(pip);
}

void page_server_zap_pte(struct vm_area_struct *vma, unsigned long addr, pte_t *pte, pte_t *pteval)
{
	if (!vma->vm_mm->remote) return;

	ClearPageInfo(vma->vm_mm, addr);

	*pteval = pte_make_valid(*pte);
	*pteval = pte_mkyoung(*pteval);
	if (ptep_set_access_flags(vma, addr, pte, *pteval, 1)) {
		update_mmu_cache(vma, addr, pte);
	}
#ifdef CONFIG_POPCORN_DEBUG_VERBOSE
	PGPRINTK("  [%d] zap %lx\n", current->pid, addr);
#endif
}

static void __make_pte_valid(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long addr,
		unsigned long fault_flags, pte_t *pte)
{
	pte_t entry;

	entry = ptep_clear_flush(vma, addr, pte);
	entry = pte_make_valid(entry);

	if (fault_for_write(fault_flags)) {
		entry = pte_mkwrite(entry);
		entry = pte_mkdirty(entry);
	} else {
		entry = pte_wrprotect(entry);
	}
	entry = pte_mkyoung(entry);

	set_pte_at_notify(mm, addr, pte, entry);
	update_mmu_cache(vma, addr, pte);
	// flush_tlb_page(vma, addr);

	SetPageDistributed(mm, addr);
	set_page_owner(my_nid, mm, addr);
}


/**************************************************************************
 * Remote fault handler at a remote location
 */
static int __handle_remotefault_at_remote(struct task_struct *tsk, struct mm_struct *mm, struct vm_area_struct *vma, remote_page_request_t *req, remote_page_response_t *res)
{
	unsigned long addr = req->addr;
	unsigned fault_flags = req->fault_flags | FAULT_FLAG_REMOTE;
	unsigned char *paddr;
	struct page *page;

	spinlock_t *ptl;
	pmd_t *pmd;
	pte_t *pte;
	pte_t entry;

	struct fault_handle *fh;
	bool leader;
#if 0
#ifdef CONFIG_POPCORN_HYPE
	/* debug */
	static unsigned long process_rr_cnt = 0;
	unsigned long process_rr_thre;
	process_rr_cnt++;
	process_rr_thre = PGFAULT_REQ_AT_REMOTE_SKIP;
	if (process_rr_cnt > process_rr_thre) {
		PGPRINTK("  rr1[%d] %lx %c %lx from [%d/%d]\n",
				req->remote_pid, req->addr,
				fault_for_write(req->fault_flags) ? 'W' : 'R',
				req->instr_addr, req->origin_pid, PCN_KMSG_FROM_NID(req));
	}
#endif
#endif
	pte = __get_pte_at(mm, addr, &pmd, &ptl);
	if (!pte) {
		PGPRINTK("  [%d] No PTE!!\n", tsk->pid);
		return VM_FAULT_OOM;
	}

	spin_lock(ptl);
#if 0
#ifdef CONFIG_POPCORN_HYPE
	if (process_rr_cnt > process_rr_thre) {
		PGPRINTK("  rr2[%d] %lx %c %lx from [%d/%d]\n",
				req->remote_pid, req->addr,
				fault_for_write(req->fault_flags) ? 'W' : 'R',
				req->instr_addr, req->origin_pid, PCN_KMSG_FROM_NID(req));
	}
#endif
#endif
	fh = __start_fault_handling(tsk, addr, fault_flags, ptl, &leader);
	if (!fh) {
		pte_unmap(pte);
		return VM_FAULT_LOCKED;
	}

	if (pte_none(*pte)) {
		pte_unmap(pte);
		return VM_FAULT_SIGSEGV;
	}

#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!page_is_mine(mm, addr));
#endif
#if 0
#ifdef CONFIG_POPCORN_HYPE
	if (process_rr_cnt > process_rr_thre) {
		PGPRINTK("  rr3[%d] %lx %c %lx from [%d/%d]\n",
				req->remote_pid, req->addr,
				fault_for_write(req->fault_flags) ? 'W' : 'R',
				req->instr_addr, req->origin_pid, PCN_KMSG_FROM_NID(req));
	}
#endif
#endif

	spin_lock(ptl);
#if 0
#ifdef CONFIG_POPCORN_HYPE
	if (process_rr_cnt > process_rr_thre) {
		PGPRINTK("  rr4[%d] %lx %c %lx from [%d/%d]\n",
				req->remote_pid, req->addr,
				fault_for_write(req->fault_flags) ? 'W' : 'R',
				req->instr_addr, req->origin_pid, PCN_KMSG_FROM_NID(req));
	}
#endif
#endif
	SetPageDistributed(mm, addr);
	entry = ptep_clear_flush(vma, addr, pte);

	if (fault_for_write(fault_flags)) {
		clear_page_owner(my_nid, mm, addr);
		entry = pte_make_invalid(entry);
#ifdef CONFIG_POPCORN_HYPE
		/* kvm_mmu_notifier_invalidate_page */
		mmu_notifier_invalidate_page(mm, addr);
#endif
	} else {
		/* shared-read page - write protect */
		entry = pte_wrprotect(entry);
	}

	set_pte_at_notify(mm, addr, pte, entry);
	update_mmu_cache(vma, addr, pte);
	pte_unmap_unlock(pte, ptl);

	page = vm_normal_page(vma, addr, *pte);
	BUG_ON(!page);
	flush_cache_page(vma, addr, page_to_pfn(page));
	if (TRANSFER_PAGE_WITH_RDMA) {
		paddr = kmap(page);
		pcn_kmsg_rdma_write(PCN_KMSG_FROM_NID(req),
				req->rdma_addr, paddr, PAGE_SIZE, req->rdma_key);
		kunmap(page);
	} else {
		paddr = kmap_atomic(page);
		copy_from_user_page(vma, page, addr, res->page, paddr, PAGE_SIZE);
		kunmap_atomic(paddr);
	}

#if 0
#ifdef CONFIG_POPCORN_HYPE
	if (process_rr_cnt > process_rr_thre) {
		PGPRINTK("  rr5[%d] %lx %c %lx from [%d/%d]\n",
				req->remote_pid, req->addr,
				fault_for_write(req->fault_flags) ? 'W' : 'R',
				req->instr_addr, req->origin_pid, PCN_KMSG_FROM_NID(req));
	}
#endif
#endif
	__finish_fault_handling(fh);
	return 0;
}



/**************************************************************************
 * Remote fault handler at the origin
 */
static int __handle_remotefault_at_origin(struct task_struct *tsk, struct mm_struct *mm, struct vm_area_struct *vma, remote_page_request_t *req, remote_page_response_t *res)
{
	int from_nid = PCN_KMSG_FROM_NID(req);
	unsigned long addr = req->addr;
	unsigned long fault_flags = req->fault_flags | FAULT_FLAG_REMOTE;
	unsigned char *paddr;
	struct page *page;

	spinlock_t *ptl;
	pmd_t *pmd;
	pte_t *pte;

	struct fault_handle *fh;
	bool leader;
	bool grant = false;

again:
	pte = __get_pte_at_alloc(mm, vma, addr, &pmd, &ptl);
	if (!pte) {
		PGPRINTK("  [%d] No PTE!!\n", tsk->pid);
		return VM_FAULT_OOM;
	}

	spin_lock(ptl);
	if (pte_none(*pte)) {
		int ret;
		spin_unlock(ptl);
#ifdef CONFIG_POPCORN_HYPE
		/* Too many so commented out */
		//PGPRINTK("  [%d] handle local fault at origin\n", tsk->pid);
#else
		PGPRINTK("  [%d] handle local fault at origin\n", tsk->pid);
#endif
		ret = handle_pte_fault_origin(mm, vma, addr, pte, pmd, fault_flags);
		/* returned with pte unmapped */
		if (ret & VM_FAULT_RETRY) {
			/* mmap_sem is released during do_fault */
			return VM_FAULT_RETRY;
		}
		if (fault_for_write(fault_flags) && !vma_is_anonymous(vma))
			SetPageCowed(mm, addr);
		goto again;
	}

	fh = __start_fault_handling(tsk, addr, fault_flags, ptl, &leader);

	/**
	 * Indicates the same page is handled at the origin and it might cause
	 * this node to be blocked recursively. This prevents forming the loop
	 * by releasing everything from remote.
	 */
	if (!fh) {
		pte_unmap(pte);
		up_read(&mm->mmap_sem); /* To match the sematic for VM_FAULT_RETRY */
		return VM_FAULT_RETRY;
	}

	page = get_normal_page(vma, addr, pte);
	BUG_ON(!page);

	if (leader) {
		/* Prepare the page if it is not mine. This should be leader */
		pte_t entry;

#ifdef CONFIG_POPCORN_HYPE
	{
		static unsigned long remote_at_origin_cnt = 0;
		unsigned long remote_at_origin_thre;
		remote_at_origin_cnt++;
		if (current->at_remote)
			remote_at_origin_thre = REMOTE_PGFAULT_SKIP;
		else
			remote_at_origin_thre = ORIGIN_PGFAULT_SKIP;

		//if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
		if (pophype_debug ||
			((remote_at_origin_cnt > remote_at_origin_thre ||
			INTERESTED_GVA(addr)) &&
			NOTINTERESTED_GVA(addr))) {
			//PGPRINTK("\t\t\t =[%d] %s%s %p %s\n",
			//	tsk->pid, page_is_mine(mm, addr) ? "origin " : "",
			//	test_page_owner(from_nid, mm, addr) ? "remote": "", fh,
			//	fault_for_write(fault_flags) ? "INV" : "");
		}
	}
#else
		PGPRINTK("\t\t =[%d] %s%s %p\n",
				tsk->pid, page_is_mine(mm, addr) ? "origin " : "",
				test_page_owner(from_nid, mm, addr) ? "remote": "", fh);
#endif
		if (test_page_owner(from_nid, mm, addr)) {
			BUG_ON(fault_for_read(fault_flags) && "Read fault from owner??");
			__claim_local_page(tsk, addr, from_nid);
			grant = true;
		} else {
			if (!page_is_mine(mm, addr)) {
				//BUG_ON("rr: 2-node case will never happen");
				int r = __claim_remote_page(tsk, mm, vma, addr, fault_flags, page, 0);
#if defined(CONFIG_POPCORN_HYPE) && defined(CONFIG_POPCORN_CHECK_SANITY)
				BUG_ON(r == HYPE_RETRY);
#endif
			} else {
				if (fault_for_write(fault_flags))
					__claim_local_page(tsk, addr, my_nid); /* 2-node: bypass it */
			}
		}
		spin_lock(ptl);

		SetPageDistributed(mm, addr);
		set_page_owner(from_nid, mm, addr);

		entry = ptep_clear_flush(vma, addr, pte);
		if (fault_for_write(fault_flags)) {
			clear_page_owner(my_nid, mm, addr);
			entry = pte_make_invalid(entry);
#ifdef CONFIG_POPCORN_HYPE
			/* kvm_mmu_notifier_invalidate_page */
			mmu_notifier_invalidate_page(mm, addr);
#endif
		} else {
			entry = pte_make_valid(entry); /* For remote-claimed case */
			entry = pte_wrprotect(entry);
			set_page_owner(my_nid, mm, addr);
		}
		set_pte_at_notify(mm, addr, pte, entry);
		update_mmu_cache(vma, addr, pte);

		spin_unlock(ptl);
	}
	pte_unmap(pte);

	if (!grant) {
		flush_cache_page(vma, addr, page_to_pfn(page));
		if (TRANSFER_PAGE_WITH_RDMA) {
			paddr = kmap(page);
			pcn_kmsg_rdma_write(PCN_KMSG_FROM_NID(req),
					req->rdma_addr, paddr, PAGE_SIZE, req->rdma_key);
			kunmap(page);
		} else {
			paddr = kmap_atomic(page);
			copy_from_user_page(vma, page, addr, res->page, paddr, PAGE_SIZE);
			kunmap_atomic(paddr);
		}
	}

	__finish_fault_handling(fh);
	return grant ? VM_FAULT_CONTINUE : 0;
}


/**
 * Entry point to remote fault handler
 *
 * To accelerate the ownership grant by skipping transferring page data,
 * the response might be multiplexed between remote_page_response_short_t and
 * remote_page_response_t.
 */
static void process_remote_page_request(struct work_struct *work)
{
	START_KMSG_WORK(remote_page_request_t, req, work);
	remote_page_response_t *res;
	int from_nid = PCN_KMSG_FROM_NID(req);
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int res_size;
	enum pcn_kmsg_type res_type;
	int down_read_retry = 0;
#ifdef CONFIG_POPCORN_HYPE
	/* debug */
	static unsigned long process_remote_cnt = 0;
	unsigned long process_remote_thre;
#endif
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	int rr = 0;
	ktime_t fph_start = ktime_get();
#endif

	if (TRANSFER_PAGE_WITH_RDMA) {
		res = pcn_kmsg_get(sizeof(remote_page_response_short_t));
	} else {
		res = pcn_kmsg_get(sizeof(*res));
	}

again:
	tsk = __get_task_struct(req->remote_pid);
	if (!tsk) {
		res->result = VM_FAULT_SIGBUS;
		PGPRINTK("  [%d] not found\n", req->remote_pid);
		goto out;
	}
	mm = get_task_mm(tsk);

#ifdef CONFIG_POPCORN_HYPE
	/* debug */
	process_remote_cnt++;
	if (tsk->at_remote)
		process_remote_thre = PGFAULT_REQ_AT_REMOTE_SKIP;
	else
		process_remote_thre = PGFAULT_REQ_AT_ORIGIN_SKIP;

	if (pophype_debug || INTERESTED_GVA_2AFTER4(req->addr) ||
		((process_remote_cnt > process_remote_thre ||
		INTERESTED_GVA(req->addr)) &&
		NOTINTERESTED_GVA(req->addr))) {
		PGPRINTK("\n\t=>REMOTE_PAGE_REQUEST [%d] %lx %s %lx from [%d/%d] "
				"#%ld\n",
				req->remote_pid, req->addr,
				fault_for_write(req->fault_flags) ? "W(INV)" : "R",
				req->instr_addr, req->origin_pid, from_nid,
				process_remote_cnt);
	}
#else
	PGPRINTK("\n\t=>REMOTE_PAGE_REQUEST [%d] %lx %c %lx from [%d/%d]\n",
			req->remote_pid, req->addr,
			fault_for_write(req->fault_flags) ? 'W' : 'R',
			req->instr_addr, req->origin_pid, from_nid);
#endif

	while (!down_read_trylock(&mm->mmap_sem)) {
#ifdef CONFIG_POPCORN_HYPE
		//BUG_ON(down_read_retry > 20);
#endif
//#ifdef CONFIG_POPCORN_HYPE
//		if (down_read_retry++ > 4) { /* who hold it at remote? */
//#else
		if (!tsk->at_remote && down_read_retry++ > 4) {
//#endif
			res->result = VM_FAULT_RETRY;
			goto out_up;
		}
#ifdef CONFIG_POPCORN_HYPE
		if (tsk->at_remote) {
			/* ORIGIN IS SURE THAT THIS REMOTE HAS THE PAGE and MUST FIX IT.
			   That's the current request from this remote at remote should
				return a retry to this remote so that this remote
				can handle origin's works first*/
			down_read_retry++;
		}
		//BUG() // 0x7ffec1a0c000
		// from origin __claim_remote_page -> __request_remote_page
		// from remote  __fetch_page_from_origin -> __request_remote_page
		//Jack for the speed
		if (!(down_read_retry % (RETRY_REMOTEFAULT / 10))) {
			if (NOTINTERESTED_GVA(req->addr)) {
				PGPRINTK("\t\t [%d] mmlk %lx by[%d/%ld] retry#%d "
						"MINE %s letbugatorigin %s\n",
						//"in_atomic() %s\n",
						req->remote_pid, req->addr,
						mm->mmap_sem.owner ? mm->mmap_sem.owner->pid : -78,
						mm->mmap_sem.count,
						down_read_retry,
						page_is_mine(mm, req->addr) ? "O" : "X",
						RETRY_REMOTEFAULT_GIVEUP ? "O" : "X");
						//in_atomic() ? "O" : "X");
			}
#ifdef CONFIG_POPCORN_CHECK_SANITY
			BUG_ON(in_atomic());
#endif
		}

#ifdef CONFIG_POPCORN_CHECK_SANITY
#if HYPE_PERF_CRITICAL_DEBUG
		if (!page_is_mine(mm, req->addr)) { /* DSM corrupted */
			printk(KERN_ERR "\n\n\n\n"
				"  BAD [%d] ->[%d/%d] addr %lx %c instr %lx."
				"pophype lets it pass for testing "
				"since this is just a rr case isn't it?\n\n\n",
				tsk->pid, req->remote_pid, from_nid, req->addr,
				fault_for_write(req->fault_flags) ? 'W' : 'R', req->instr_addr);
			//dump_stack();
			//BUG();
		}
#endif
#endif

		if (tsk->at_remote && down_read_retry > RETRY_REMOTEFAULT) {
			if (RETRY_REMOTEFAULT_GIVEUP) {
			/* Remote should not return RETRY but.....let's BUG() at origin */
				res->result = VM_FAULT_RETRY;
				goto out_up; /* correct */
			}
		}
#endif
		/* retrying */
		//udelay(100);
		io_schedule();
	}
	vma = find_vma(mm, req->addr);
	if (!vma || vma->vm_start > req->addr) {
		res->result = VM_FAULT_SIGBUS;
		goto out_up;
	}

#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(vma->vm_flags & VM_EXEC);
#endif

	if (tsk->at_remote) {
		res->result = __handle_remotefault_at_remote(tsk, mm, vma, req, res);
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
		if (res->result == 0)
			rr = 1;
#endif
	} else {
		res->result = __handle_remotefault_at_origin(tsk, mm, vma, req, res);
	}

out_up:
	if (res->result != VM_FAULT_RETRY) {
		/* replying VM_FAULT_RETRY means didn't get the mmap_sem */
		up_read(&mm->mmap_sem);
	}
	mmput(mm);
	put_task_struct(tsk);

	if (res->result == VM_FAULT_LOCKED) {
		goto again;
	}

out:
	if (res->result != 0 || TRANSFER_PAGE_WITH_RDMA) {
		res_type = PCN_KMSG_TYPE_REMOTE_PAGE_RESPONSE_SHORT;
		res_size = sizeof(remote_page_response_short_t);
	} else {
		res_type = PCN_KMSG_TYPE_REMOTE_PAGE_RESPONSE;
		res_size = sizeof(remote_page_response_t);
	}
	res->addr = req->addr;
	res->remote_pid = req->remote_pid;

	res->origin_pid = req->origin_pid;
	res->origin_ws = req->origin_ws;

#ifdef CONFIG_POPCORN_HYPE
	if (pophype_debug || INTERESTED_GVA_2AFTER4(req->addr) ||
		((process_remote_cnt > process_remote_thre ||
		INTERESTED_GVA(req->addr)) &&
		NOTINTERESTED_GVA(req->addr))) {
		PGPRINTK("\t\t\t  [%d] ->[%d/%d] %lx r %x #%ld\n", req->remote_pid,
					res->origin_pid, from_nid, res->addr,
					res->result, process_remote_cnt);
	}
#else
	PGPRINTK("  [%d] ->[%d/%d] %lx %x\n", req->remote_pid,
			res->origin_pid, from_nid, res->addr, res->result);
#endif

	trace_pgfault(from_nid, req->remote_pid,
			fault_for_write(req->fault_flags) ? 'W' : 'R',
			req->instr_addr, req->addr, res->result);

	pcn_kmsg_post(res_type, from_nid, res, res_size);

	END_KMSG_WORK(req);
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	if (rr) {
		ktime_t dt, fph_end = ktime_get();
		dt = ktime_sub(fph_end, fph_start);
		atomic64_add(ktime_to_ns(dt), &fph_ns);
		atomic64_inc(&fph_cnt);
	}
#endif
}


/**************************************************************************
 * Exclusively keep a user page to the current node. Should put the user
 * page after use. This routine is similar to localfault handler at origin
 * thus may be refactored.
 */
int page_server_get_userpage(u32 __user *uaddr, struct fault_handle **handle, char *mode)
{
	unsigned long addr = (unsigned long)uaddr & PAGE_MASK;
	struct mm_struct *mm;
	struct vm_area_struct *vma;

	const unsigned long fault_flags = 0;
	struct fault_handle *fh = NULL;
	spinlock_t *ptl;
	pmd_t *pmd;
	pte_t *pte;

	bool leader;
	int ret = 0;

	*handle = NULL;
	if (!distributed_process(current)) return 0;

	mm = get_task_mm(current);
retry:
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr) {
		ret = -EINVAL;
		goto out;
	}

	pte = __get_pte_at(mm, addr, &pmd, &ptl);
	if (!pte) {
		ret = -EINVAL;
		goto out;
	}
	spin_lock(ptl);
	fh = __start_fault_handling(current, addr, fault_flags, ptl, &leader);
	if (!fh) {
		pte_unmap(pte);
		up_read(&mm->mmap_sem);
		io_schedule();
		goto retry;
	}

	/*
	PGPRINTK(" %c[%d] gup %s %p %p\n", leader ? '=' : '-', current->pid, mode,
		fh, uaddr);
	*/

	if (leader && !page_is_mine(mm, addr)) {
		struct page *page = get_normal_page(vma, addr, pte);
#ifdef CONFIG_POPCORN_HYPE
		int ret = __claim_remote_page(current, mm, vma, addr, fault_flags, page, 0);
		BUG_ON(ret == HYPE_RETRY);
#else
		 __claim_remote_page(current, mm, vma, addr, fault_flags, page, 0);
#endif
		spin_lock(ptl);
		__make_pte_valid(mm, vma, addr, fault_flags, pte);
		spin_unlock(ptl);
	}
	pte_unmap(pte);
	ret = 0;

out:
	*handle = fh;
	up_read(&mm->mmap_sem);
	mmput(mm);
	return ret;
}

void page_server_put_userpage(struct fault_handle *fh, char *mode)
{
	if (!fh) return;

	__finish_fault_handling(fh);
}


/**************************************************************************
 * Local fault handler at the remote
 */
static int __handle_localfault_at_remote(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long addr,
		pmd_t *pmd, pte_t *pte, pte_t pte_val,
		unsigned int fault_flags, unsigned long address)
{
	spinlock_t *ptl;
	struct page *page;
	bool populated = false;
	struct mem_cgroup *memcg;
	int ret = 0;

	struct fault_handle *fh;
	bool leader;
	remote_page_response_t *rp;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t fp_start, fpin_start;
	ktime_t dt, inv_end, inv_start;
#endif

#if 0
#ifdef CONFIG_POPCORN_HYPE
	if (addr == 0x7ffff4fdd000) {
		printk("%s(): jack %p %p "
				"(I think we didn't have DSM working for this resion "
				"so this is the problem)\n",
				__func__, vma->vm_ops, vma->vm_ops->fault);
	}
#endif
#endif

	if (anon_vma_prepare(vma)) {
		BUG_ON("Cannot prepare vma for anonymous page");
		pte_unmap(pte);
		return VM_FAULT_SIGBUS;
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);

	if (!pte_same(*pte, pte_val)) {
		pte_unmap_unlock(pte, ptl);
		PGPRINTK("  [%d] %lx already handled\n", current->pid, addr);
		return 0;
	}
	fh = __start_fault_handling(current, addr, fault_flags, ptl, &leader);
	if (!fh) {
		pte_unmap(pte);
		up_read(&mm->mmap_sem);
#ifdef CONFIG_POPCORN_HYPE
#if HYPE_PERF_CRITICAL_DSM_TRAFFIC_PRINTK
		/* Handled outside */
		if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
			(INTERESTED_GVA(addr) && NOTINTERESTED_GVA(addr)))
#else
		if (INTERESTED_GVA_2AFTER4(addr) ||
			(INTERESTED_GVA(addr) && NOTINTERESTED_GVA(addr)))
#endif
		{
			printk("\t\t(remote) !![%d] %lx !fh ->RETRY\n",
					current->pid, addr); /* 1c0* happens a lot */
		}
#endif
		return VM_FAULT_RETRY;
	}

#ifdef CONFIG_POPCORN_HYPE
	{
		static unsigned long local_at_remote_cnt = 0;
		unsigned long local_at_remote_thre;
		local_at_remote_cnt++;
		if (current->at_remote)
			local_at_remote_thre = REMOTE_PGFAULT_SKIP;
		else
			local_at_remote_thre = ORIGIN_PGFAULT_SKIP;

		if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
			((local_at_remote_cnt > local_at_remote_thre ||
			INTERESTED_GVA(addr)) &&
			NOTINTERESTED_GVA(addr))) {
			PGPRINTK(" %c[%d] %lx %p %s\n",
				leader ? '=' : '-', current->pid, addr, fh,
				fault_for_write(fault_flags) ? "INVALIDATE_PAGE" : "");
		}
	}
#else
	PGPRINTK(" %c[%d] %lx %p\n", leader ? '=' : '-', current->pid, addr, fh);
#endif
	if (!leader) {
		pte_unmap(pte);
		ret = fh->ret;
		if (ret) {
#ifdef CONFIG_POPCORN_HYPE
			// many even idle in bash
			PGPRINTK("  $$[%d] 0x%lx not leader ret 0x%x\n",
									current->pid, addr, ret);
#endif
			up_read(&mm->mmap_sem);
		}
		goto out_follower;
	}

	if (pte_none(*pte) || !(page = vm_normal_page(vma, addr, *pte))) {
		page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, addr);
		BUG_ON(!page);

		if (mem_cgroup_try_charge(page, mm, GFP_KERNEL, &memcg)) {
			BUG();
		}
		populated = true;
	}
	get_page(page);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	fp_start = fpin_start = inv_start = ktime_get();
#endif

#if 0
#ifdef CONFIG_POPCORN_HYPE
	BUG_ON(!current);
	if (current->origin_nid < 0 || current->origin_pid < 0) {
		printk("  BAD [%d] ->[%d/%d] addr %lx instr %llx\n", current->pid,
				current->origin_nid, current->origin_pid,
				instruction_pointer(current_pt_regs()));
		dump_stack();
	}
#endif
#endif
	rp = __fetch_page_from_origin(current, vma, addr, fault_flags, page);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	if (page_is_mine(mm, addr)) {
		if (fault_for_write(fault_flags)) {
			if (rp->result == VM_FAULT_CONTINUE) { /* W: inv lat */
				inv_end = ktime_get();
				dt = ktime_sub(inv_end, inv_start);
				atomic64_add(ktime_to_ns(dt), &inv_ns);
				atomic64_inc(&inv_cnt);
			} else if (!rp->result) { /* W: inv + page transferred */
				// X -> W
				ktime_t dt, fpin_end = ktime_get();
				dt = ktime_sub(fpin_end, fpin_start);
				atomic64_add(ktime_to_ns(dt), &fpin_ns);
				atomic64_inc(&fpin_cnt);
			}
		}
	} else { /* fp only page */
		if (fault_for_read(fault_flags)) {
			ktime_t dt, fp_end = ktime_get();
			dt = ktime_sub(fp_end, fp_start);
			atomic64_add(ktime_to_ns(dt), &fp_ns);
			atomic64_inc(&fp_cnt);
		}
		if (fault_for_write(fault_flags)) { /* w: inv + page transferred */
				ktime_t dt, fpin_end = ktime_get();
				dt = ktime_sub(fpin_end, fpin_start);
				atomic64_add(ktime_to_ns(dt), &fpin_ns);
				atomic64_inc(&fpin_cnt);
		}
	}
#endif

	if (rp->result && rp->result != VM_FAULT_CONTINUE) {
		if (rp->result != VM_FAULT_RETRY) {
#ifdef CONFIG_POPCORN_HYPE
			printk("  $$[%d] 0x%lx failed ret 0x%x TODO\n",
							current->pid, addr, rp->result);
			printk("  $$[%d] 0x%lx failed ret 0x%x TODO\n",
							current->pid, addr, rp->result);
			printk("  $$[%d] 0x%lx failed ret 0x%x TODO\n",
							current->pid, addr, rp->result);
			//printk("  $$[%d] failed 0x%x\n", current->pid, rp->result);
			if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
				(INTERESTED_GVA(addr) && NOTINTERESTED_GVA(addr))) {
				printk("  $$[%d] 0x%lx failed ret 0x%x TODO\n",
								current->pid, addr, rp->result);
			}
#else
			PGPRINTK("  [%d] failed 0x%x\n", current->pid, rp->result);
#endif
		}
#ifdef CONFIG_POPCORN_HYPE
		else {
			DSMRETRYPRINTK("  !![%d] fpfo->lfr 0x%lx ret 0x%x "
							"[[[ RETRY UNLOCKED ]]]\n",
							current->pid, addr, rp->result);
			// remote
		}
		/* eighter RETRY or FAIL - UNLOCK */
#endif

		ret = rp->result;
		pte_unmap(pte);
		up_read(&mm->mmap_sem);
#ifdef CONFIG_POPCORN_HYPE
		/* Handled outside */
		/* TODO  HYPE - BUG: bad unlock balance detected! 0521
			VM_FAULT_KILLED
				//VM_FAULT_RETRY
					err VM_FAULT_FALLBACK

			VM_FAULT_LOCKED
			VM_FAULT_NOPAGE
					err VM_FAULT_SIGSEGV
					err VM_FAULT_HWPOISON_LARGE
					err VM_FAULT_HWPOISON

			ERR
			(VM_FAULT_OOM | VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV | \
			 VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE | \
						  VM_FAULT_FALLBACK)
		*/
		/* do I handle this RETRY WELL? */
#endif
		goto out_free;
	}

	if (rp->result == VM_FAULT_CONTINUE) {
		/**
		 * Page ownership is granted without transferring the page data
		 * since this node already owns the up-to-dated page
		 */
		pte_t entry;
		BUG_ON(populated);

		spin_lock(ptl);
		entry = pte_make_valid(*pte);

		if (fault_for_write(fault_flags)) {
			entry = pte_mkwrite(entry);
			entry = pte_mkdirty(entry);
		} else {
			entry = pte_wrprotect(entry);
		}
		entry = pte_mkyoung(entry);

		if (ptep_set_access_flags(vma, addr, pte, entry, 1)) {
			update_mmu_cache(vma, addr, pte);
		}
	} else {
		spin_lock(ptl);
		if (populated) {
			do_set_pte(vma, addr, page, pte, fault_for_write(fault_flags), true);
			mem_cgroup_commit_charge(page, memcg, false);
			lru_cache_add_active_or_unevictable(page, vma);
		} else {
			__make_pte_valid(mm, vma, addr, fault_flags, pte);
		}
	}
	SetPageDistributed(mm, addr);
	set_page_owner(my_nid, mm, addr);
	pte_unmap_unlock(pte, ptl);
	ret = 0;	/* The leader squashes both 0 and VM_FAULT_CONTINUE to 0 */
//	dsm_traffic_collect(address, addr,
//			fault_for_write(fault_flags) ? 'W' : 'R'); /* pophype */

out_free:
	put_page(page);
	pcn_kmsg_done(rp);
	fh->ret = ret;

out_follower:
	__finish_fault_handling(fh);
	return ret;
}



static bool __handle_copy_on_write(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long addr,
		pte_t *pte, pte_t *pte_val, unsigned int fault_flags)
{
	if (vma_is_anonymous(vma) || fault_for_read(fault_flags)) return false;
#ifdef CONFIG_POPCORN_HYPE
	if(vma->vm_flags & VM_SHARED) {
		printk("fault addr %lx %lx - %lx\n"
				"since we touch all *vcpu3pg at remote in the end\n",
			addr, vma->vm_start, vma->vm_end);
		dump_stack();
		return false; /* hacking: dealing with rw-s files
				anon_inode:kvm-vcpu:0, /[aio] (deleted), /dev/zero (deleted) */
	}
#else
	BUG_ON(vma->vm_flags & VM_SHARED);
#endif

	/**
	 * We need to determine whether the page is already cowed or not to
	 * avoid unnecessary cows. But there is no explicit data structure that
	 * bookkeeping such information. Also, explicitly tracking every CoW
	 * including non-distributed processes is not desirable due to the
	 * high frequency of CoW.
	 * Fortunately, private vma is not flushed, implying the PTE dirty bit
	 * is not cleared but kept throughout its lifetime. If the dirty bit is
	 * set for a page, the page is written previously, which implies the page
	 * is CoWed!!!
	 */
	if (pte_dirty(*pte_val)) return false;

	if (PageCowed(mm, addr)) return false;

	if (cow_file_at_origin(mm, vma, addr, pte)) return false;

	*pte_val = *pte;
	SetPageCowed(mm, addr);

	return true;
}


/**************************************************************************
 * Local fault handler at the origin
 */
static int __handle_localfault_at_origin(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long addr,
		pmd_t *pmd, pte_t *pte, pte_t pte_val, unsigned int fault_flags,
		unsigned long address)
{
	spinlock_t *ptl;

	struct fault_handle *fh;
	bool leader;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	bool remote_fault = false;
	//ktime_t ptef_start = ktime_get();
#endif
#ifdef CONFIG_POPCORN_HYPE
	unsigned long lfal_retry_cnt = 0;
	int ret;
	static unsigned long origin_pgfault_fresh_cnt = 0;
	origin_pgfault_fresh_cnt++;
lfal_retry:
	ret = 0;
#endif

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);

	if (!pte_same(*pte, pte_val)) {
		pte_unmap_unlock(pte, ptl);
		PGPRINTK("  [%d] %lx already handled\n", current->pid, addr);
		return 0;
	}

	/* Fresh access to the address. Handle locally since we are at the origin */
	if (pte_none(pte_val)) {
		BUG_ON(pte_present(pte_val));
		spin_unlock(ptl);
#ifdef CONFIG_POPCORN_HYPE
		if (origin_pgfault_fresh_cnt > ORIGIN_PGFAULT_SKIP) {
			PGPRINTK("  [%d] fresh at origin. continue\n", current->pid);
		}
#else
		PGPRINTK("  [%d] fresh at origin. continue\n", current->pid);
#endif
		return VM_FAULT_CONTINUE;
	}

	/* Nothing to do with DSM (e.g. COW). Handle locally */
	if (!PageDistributed(mm, addr)) {
		spin_unlock(ptl);
		PGPRINTK("  [%d] local at origin. continue\n", current->pid);
		return VM_FAULT_CONTINUE;
	}

	fh = __start_fault_handling(current, addr, fault_flags, ptl, &leader);
	if (!fh) {
		pte_unmap(pte);
		up_read(&mm->mmap_sem);
#ifdef CONFIG_POPCORN_HYPE
#if HYPE_PERF_CRITICAL_DSM_TRAFFIC_PRINTK
		if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
			(INTERESTED_GVA(addr) && NOTINTERESTED_GVA(addr)))
#else
		if (INTERESTED_GVA_2AFTER4(addr) ||
			(INTERESTED_GVA(addr) && NOTINTERESTED_GVA(addr)))
#endif
		{
			printk("\t\t(origin) !![%d] %lx !fh ->RETRY\n",
					current->pid, addr); /* 1c0* happens a lot */
		}
#endif
		return VM_FAULT_RETRY;
	}

#ifdef CONFIG_POPCORN_HYPE
	if (pophype_debug ||  INTERESTED_GVA_2AFTER4(addr) ||
		((origin_pgfault_fresh_cnt > ORIGIN_PGFAULT_SKIP ||
		INTERESTED_GVA(addr)) &&
		NOTINTERESTED_GVA(addr))) {
		PGPRINTK(" %c[%d] %lx replicated %sMINE %p %s #%lu\n",
			leader ? '=' : ' ', current->pid, addr,
			page_is_mine(mm, addr) ? "" : "*NOT* ", fh,
			page_is_mine(mm, addr) ? "" : "=>", lfal_retry_cnt);
	}
#else
	/* Handle replicated page via the memory consistency protocol */
	PGPRINTK(" %c[%d] %lx replicated %sMINE %p %s\n",
			leader ? '=' : ' ', current->pid, addr,
			page_is_mine(mm, addr) ? "" : "*NOT* ", fh,
			page_is_mine(mm, addr) ? "" : "=>");
#endif
	if (!leader) {
		pte_unmap(pte);
		goto out_wakeup;
	}

	__handle_copy_on_write(mm, vma, addr, pte, &pte_val, fault_flags);

	if (page_is_mine(mm, addr)) {
		if (fault_for_read(fault_flags)) {
			/* Racy exit */
			pte_unmap(pte);
			goto out_wakeup;
		}

		__claim_local_page(current, addr, my_nid);

		spin_lock(ptl);
		pte_val = pte_mkwrite(pte_val);
		pte_val = pte_mkdirty(pte_val);
		pte_val = pte_mkyoung(pte_val);

		if (ptep_set_access_flags(vma, addr, pte, pte_val, 1)) {
			update_mmu_cache(vma, addr, pte);
		}
	} else {
		struct page *page = vm_normal_page(vma, addr, pte_val);
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
		ktime_t dt, clr_end, clr_start = ktime_get();
#endif
		BUG_ON(!page);

#ifdef CONFIG_POPCORN_HYPE
		ret = __claim_remote_page(current, mm, vma, addr, fault_flags, page, 1);
		/* !page_mine must transffer */
		if (ret == HYPE_RETRY) {
			pte_unmap(pte);
			goto out_wakeup; // aka origin_retry_out // don't change pte
		}
#else
		__claim_remote_page(current, mm, vma, addr, fault_flags, page, 1);
#endif

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
		clr_end = ktime_get();
		dt = ktime_sub(clr_end, clr_start);
		atomic64_add(ktime_to_ns(dt), &clr_ns);
		atomic64_inc(&clr_cnt);
		remote_fault = true;
#endif

		spin_lock(ptl);
		__make_pte_valid(mm, vma, addr, fault_flags, pte);
	}
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!test_page_owner(my_nid, mm, addr));
#endif
	pte_unmap_unlock(pte, ptl);
//	dsm_traffic_collect(address, addr, /* pophype */
//			fault_for_write(fault_flags) ? 'W' : 'R');

out_wakeup:
	__finish_fault_handling(fh);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	if (remote_fault) {
		//ktime_t dt, ptef_end = ktime_get();
		//dt = ktime_sub(ptef_end, ptef_start);
		//atomic64_add(ktime_to_ns(dt), &ptef_ns);
		//atomic64_inc(&ptef_cnt);
	}
#endif

#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_STAT
	if (ret == HYPE_RETRY) {
		//udelay(100);
		lfal_retry_cnt++;
		g_lfal_retry_cnt++;
		goto lfal_retry;
	}
#endif
#endif
	return 0;
}


/**
 * Function:
 *	page_server_handle_pte_fault
 *
 * Description:
 *	Handle PTE faults with Popcorn page replication protocol.
 *  down_read(&mm->mmap_sem) is already held when getting in.
 *  DO NOT FORGET to unmap pte before returning non-VM_FAULT_CONTINUE.
 *
 * Input:
 *	All are from the PTE handler
 *
 * Return values:
 *	VM_FAULT_CONTINUE when the page fault can be handled locally.
 *	0 if the fault is fetched remotely and fixed.
 *  ERROR otherwise
 */
int page_server_handle_pte_fault(
		struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd, pte_t *pte, pte_t pte_val,
		unsigned int fault_flags)
{
	unsigned long addr = address & PAGE_MASK;
	int ret = 0;

	might_sleep();

#ifdef CONFIG_POPCORN_HYPE
#ifdef HYPE_PERF_DSM_TRAFFIC_PK
	if (current->at_remote) {
		static unsigned long remote_pgfault_cnt = 0;
		remote_pgfault_cnt++;
		if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
			((remote_pgfault_cnt > REMOTE_PGFAULT_SKIP
			|| INTERESTED_GVA(addr)) &&
			NOTINTERESTED_GVA(addr))) {

// 11/05/19 uncommented
//			if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
//				INTERESTED_GVA(addr))
//				goto force_pk;

			if (((((addr >> PAGE_SHIFT) >> 16) >> 8) & 0xfff) == 0x7ff) {
				if ((((addr >> PAGE_SHIFT) >> 16) & 0xff) != 0xec) {
					goto skip_printk; /* lose info but fast */
				}
			}
//force_pk:
			PGPRINTK("\n\t## PAGEFAULT [%d] %lx %c %lx %x %lx %s%p #%lu\n",
					current->pid, address,
					fault_for_write(fault_flags) ? 'W' : 'R',
					instruction_pointer(current_pt_regs()),
					fault_flags, pte_flags(pte_val),
					vma->vm_ops ? "vm_ops " : "", vma->vm_ops,
					remote_pgfault_cnt);
		}
	} else {
		static unsigned long origin_pgfault_cnt = 0;
		origin_pgfault_cnt++;
		if (pophype_debug || INTERESTED_GVA_2AFTER4(addr) ||
			((origin_pgfault_cnt > ORIGIN_PGFAULT_SKIP ||
			INTERESTED_GVA(addr)) &&
			NOTINTERESTED_GVA(addr))) {
			PGPRINTK("\n\t## PAGEFAULT [%d] %lx %c %lx %x %lx %s%p #%lu\n",
					current->pid, address,
					fault_for_write(fault_flags) ? 'W' : 'R',
					instruction_pointer(current_pt_regs()),
					fault_flags, pte_flags(pte_val),
					vma->vm_ops ? "vm_ops " : "", vma->vm_ops,
					origin_pgfault_cnt);
		}
	}


skip_printk:
#endif
#else
	PGPRINTK("\n## PAGEFAULT [%d] %lx %c %lx %x %lx\n",
				current->pid, address,
				fault_for_write(fault_flags) ? 'W' : 'R',
				instruction_pointer(current_pt_regs()),
				fault_flags, pte_flags(pte_val));
#endif

	/**
	 * Thread at the origin
	 */
	if (!current->at_remote) {
		ret = __handle_localfault_at_origin(
				mm, vma, addr, pmd, pte, pte_val, fault_flags, address);
		goto out;
	}

	/**
	 * Thread running at a remote
	 *
	 * Fault handling at the remote side is simpler than at the origin.
	 * There will be no copy-on-write case at the remote since no thread
	 * creation is allowed at the remote side.
	 */
	if (pte_none(pte_val)) {
		/* Can we handle the fault locally? */
		if (vma->vm_flags & VM_EXEC) {
			PGPRINTK("  [%d] VM_EXEC. continue\n", current->pid);
			ret = VM_FAULT_CONTINUE;
			goto out;
		}
		if (!vma_is_anonymous(vma) &&
				((vma->vm_flags & (VM_WRITE | VM_SHARED)) == 0)) {
#ifdef CONFIG_POPCORN_HYPE
			printk("\n\n\n*****************************\n"
					"THIS ASSUMPTION MAY KILL ME\n"
					"*****************************\n\n\n\n");
			WARN_ON(1);
#endif
			PGPRINTK("  [%d] locally file-mapped read-only. continue\n",
					current->pid);
			ret = VM_FAULT_CONTINUE;
			goto out;
		}
#ifdef CONFIG_POPCORN_HYPE
		if (!vma_is_anonymous(vma) &&
				vma->vm_flags & VM_SHARED) {
			PGPRINTK("  [%d] VM_VCPU. locally file-mmapped shared. continue "
					"vma->vm_ops %p popcorn_vcpu_op %p\n",
					current->pid, vma->vm_ops, popcorn_vcpu_op);
			/* debug */
			if (!popcorn_vcpu_op || (vma->vm_ops != popcorn_vcpu_op))  {
				POP_PK("\t\tThis I'm NOT interested!!!\n");
			}
			ret = VM_FAULT_CONTINUE;
			goto out;
		}
#endif
	}

	if (!pte_present(pte_val)) {
		/* Remote page fault */
		ret = __handle_localfault_at_remote(
				mm, vma, addr, pmd, pte, pte_val, fault_flags, address);
		goto out;
	}

	if ((vma->vm_flags & VM_WRITE) &&
			fault_for_write(fault_flags) && !pte_write(pte_val)) {
		/* wr-protected for keeping page consistency */
		ret = __handle_localfault_at_remote(
				mm, vma, addr, pmd, pte, pte_val, fault_flags, address);
		goto out;
	}

	pte_unmap(pte);
	PGPRINTK("  [%d] might be fixed by others???\n", current->pid);
	ret = 0;

out:
////	if (!current->at_remote)
////		dsm_traffic_collect(address, addr,
////				fault_for_write(fault_flags) ? 'W' : 'R');

	trace_pgfault(my_nid, current->pid,
			fault_for_write(fault_flags) ? 'W' : 'R',
			instruction_pointer(current_pt_regs()), addr, ret);

	return ret;
}


/**************************************************************************
 * Routing popcorn messages to workers
 */
DEFINE_KMSG_WQ_HANDLER(remote_page_request);
DEFINE_KMSG_WQ_HANDLER(page_invalidate_request);
DEFINE_KMSG_ORDERED_WQ_HANDLER(remote_page_flush);

int __init page_server_init(void)
{
	//int i, j;
	REGISTER_KMSG_WQ_HANDLER(
			PCN_KMSG_TYPE_REMOTE_PAGE_REQUEST, remote_page_request);
	REGISTER_KMSG_HANDLER(
			PCN_KMSG_TYPE_REMOTE_PAGE_RESPONSE, remote_page_response);
	REGISTER_KMSG_HANDLER(
			PCN_KMSG_TYPE_REMOTE_PAGE_RESPONSE_SHORT, remote_page_response);
	REGISTER_KMSG_WQ_HANDLER(
			PCN_KMSG_TYPE_PAGE_INVALIDATE_REQUEST, page_invalidate_request);
	REGISTER_KMSG_HANDLER(
			PCN_KMSG_TYPE_PAGE_INVALIDATE_RESPONSE, page_invalidate_response);
	REGISTER_KMSG_WQ_HANDLER(
			PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH, remote_page_flush);
	REGISTER_KMSG_WQ_HANDLER(
			PCN_KMSG_TYPE_REMOTE_PAGE_RELEASE, remote_page_flush);
	REGISTER_KMSG_HANDLER(
			PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH_ACK, remote_page_flush_ack);

	__fault_handle_cache = kmem_cache_create("fault_handle",
			sizeof(struct fault_handle), 0, 0, NULL);

#if POPHYPE_HOST_KERNEL /* guest mem is on host, so don't waste */
#if 0
//	for (i = 0; i < dsm_traffic_pg_cnt; i++) {
//		for (j = 0; j < dsm_traffic_inst_cnt; j++) {
//			dsm_traffic[i][j].addr = 0;
//			dsm_traffic[i][j].inst = 0;
//			dsm_traffic[i][j].cnt = 0;
//		}
//	}
	/*
	 * dsm_traffic[ptr list]		-> [ptr list]		-> [real content]
	 * [dsm_traffic_pg_cnt]	* [dsm_traffic_inst_cnt]
	 *									* [dsm_traffic_inst_cnt * dsm_traffic_t]
	 */
	printk("Pophype: debug dsm_traffic init %lu MB init (takes a while...)\n",
				(sizeof(dsm_traffic_t) * dsm_traffic_rsp_cnt *
				dsm_traffic_inst_cnt * dsm_traffic_pg_cnt) / 1024 / 1024);
	printk("Pophype: dsm_traffic %lu * %lu * %lu * %lu B\n",
				sizeof(dsm_traffic_t), dsm_traffic_rsp_cnt,
				dsm_traffic_inst_cnt, dsm_traffic_pg_cnt);
	//dsm_traffic = kzalloc(dsm_traffic_pg_cnt * sizeof(void*), GFP_KERNEL);
	//dsm_traffic = kzalloc(sizeof(dsm_traffic_t) *
	//				dsm_traffic_inst_cnt * dsm_traffic_rsp_cnt, GFP_KERNEL);
	dsm_traffic = kzalloc(sizeof(void *) *
						dsm_traffic_pg_cnt, GFP_KERNEL);
	BUG_ON(!dsm_traffic);
	for (i = 0; i < dsm_traffic_pg_cnt; i++) {
		//dsm_traffic[i] = (struct dsm_pgfault *)
		//	kzalloc(sizeof(struct dsm_pgfault) *
		//								dsm_traffic_inst_cnt, GFP_KERNEL);
		dsm_traffic[i] = (dsm_traffic_t **)
				kzalloc(sizeof(void *) * dsm_traffic_inst_cnt, GFP_KERNEL);
			//kzalloc(sizeof(dsm_traffic_t) *
			//							dsm_traffic_inst_cnt, GFP_KERNEL);
		BUG_ON(!dsm_traffic[i]);
		for (j = 0; j < dsm_traffic_inst_cnt; j++) {
			dsm_traffic[i][j] = (dsm_traffic_t *)
				kzalloc(sizeof(dsm_traffic_t) *
											dsm_traffic_rsp_cnt, GFP_KERNEL);
			BUG_ON(!dsm_traffic[i][j]);
		}
	}
#endif
#endif
	return 0;
}
