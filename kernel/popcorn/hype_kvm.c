/**
 * @file hype_kvm.c
 *
 *
 * @author Ho-Ren (Jack) Chuang, SSRG Virginia Tech 2019
 *
 * Distributed under terms of the MIT license.
 */
#include <popcorn/hype_kvm.h>

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mod_devicetable.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/trace_events.h>
#include <linux/slab.h>

#include <asm/perf_event.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/debugreg.h>
#include <asm/kvm_para.h>
#include <asm/nospec-branch.h>

#include <asm/virtext.h>

#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <linux/kvm_host.h>

#include <linux/kvm_types.h>

#include <kvm/iodev.h>

#include <linux/mm.h>
#include <linux/tboot.h>
#include <linux/hrtimer.h>
#include <linux/nospec.h>

#include <asm/kvm_host.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/desc.h>
#include <asm/vmx.h>
#include <asm/virtext.h>
#include <asm/mce.h>
#include <asm/fpu/internal.h>
#include <asm/perf_event.h>
#include <asm/debugreg.h>
#include <asm/kexec.h>
#include <asm/apic.h>
#include <asm/irq_remapping.h>

#include <linux/file.h>
#include <linux/delay.h>

#include "../arch/x86/kvm/lapic.h" // Jack arch
#include "../arch/x86/kvm/x86.h" // Jack arch
#include <linux/smpboot.h>

#include <linux/syscalls.h>

//#include <linux/skbuff.h> // vhost-net optimication

#include <linux/netdevice.h> // pophype - net optimize
#include <linux/virtio_net.h>

#ifdef CONFIG_POPCORN_HYPE
#include <popcorn/debug.h>
//static unsigned long all_cnt = 0;
unsigned long all_cnt = 0;
unsigned long *kvaddr;
#define DEBUG_THRESHOLD_LOW 3500
#define DEBUG_THRESHOLD_UP 4000
#endif

/* Maintain remote vCPU thread PIDs at origin
			in order for broadcasting signals */
//struct pophype_vcpu_info[MAX_POPCORN_VCPU] = {
//	int node; // note == my_nid => at_remote
//	int pid;
//	struct kvm_vcpu *vcpu_at_origin;
//}

struct __hype_ctx __hype_gctx = {
       .__hype_vhost = 0,
       .tsk = NULL,
       .rc = NULL
};

struct hype_node_info_t *hype_node_info[MAX_POPCORN_NODES][MAX_POPCORN_VCPU]; /* Attention: [MY_NID][FD] */ /* extern in ./include/popcorn/hype_kvm.h */

extern int replay_kvm_dev_ioctl_create_vm_tsk(struct task_struct *tsk, unsigned long type);
//struct popcorn_vcpu_info popcorn_vcpu_infos[MAX_POPCORN_VCPU];

/* smp on/offline */
bool my_hype_cpu[MAX_POPCORN_VCPU];

/* smp testing points by dsm instead of printk */
bool **hype_callin_dynamic_alloc;
bool hype_callin[HYPE_DEBUG_POINT_MAX + 1][MAX_POPCORN_NODES]; /* since from 1 */
//              { false, false, false, false, false, false, false };

int g_popcorn_vcpu_cnt = 0;
int first_fd_after_vcpufd = 0;
/* if -a 1 -b 2 =>
	-a 1: gvcpu_to_nid[0] = 0(node),
	-b 2: gvcpu_to_nid[1]: 1(node) gvcpu_to_nid[2]: 1(node) */
//int gvcpu_to_nid[MAX_POPCORN_VCPU];
atomic64_t gvcpu_to_nid[MAX_POPCORN_VCPU] = ATOMIC64_INIT(0);
//atomic64_read(&gvcpu_to_nid[vcpu_id]);
//atomic64_set(&gvcpu_to_nid[vcpu_id], 0);

/* pophype migration */
static spinlock_t phmigrate;
//spin_lock(&phmigrate);
//spin_unlock(&phmigrate);


/***
 * Statistic
 */
unsigned long eventfd_delegate_cnt = 0;
atomic64_t eventfd_delegated_cnt = ATOMIC64_INIT(0);

/*******************************************************************************
 * Utils
 */
/* ref: ./Documentation/x86/x86_64/mm.txt
		./arch/x86/include/asm/pgtable_64_types.h */
// ffffc90000022ee8
bool is_valid_rbp (u64 next_rbp_gva) {
	if (!next_rbp_gva || next_rbp_gva == (0UL - 1)
		|| !((next_rbp_gva >= 0xffff880000000000 && next_rbp_gva <= 0xffffc7ffffffffff) /* O - direct mapping of all phys e.g. 0xffff880xxxxxxxxx = rsp */
			|| (next_rbp_gva >= 0xffffffff80000000 && next_rbp_gva <= 0xffffffffa0000000) /* O - kernel text mapping, from phys 0 e.g. ffffffff81xxxxxx  = rip */
			|| (next_rbp_gva >= 0xffffc90000000000 && next_rbp_gva <= 0xffffe8ffffffffff)) /* teseting - vmalloc/ioremap space  e.g. rsp = ffffc900000xxxxx */
		) {
		return false;
	}
	return true;
}
/* VM stack walk */
void vm_stack_walk(struct kvm_regs *kvm_regs, dsm_traffic_t *_dsm_traffic, int fd) {
	/*
	 * VM addr translation refs: include/linux/kvm_host.h
	 */
	/* walk stack
	 *	Ref: ./arch/x86/kernel/dumpstack.c
	 *			print_context_stack()
	 *			print_context_stack_bp()
	 *  User: backtrace()
	 *	More: grbp 0x0 -> grbp_hva 0x7ffac0000000 (base)
	 *
	 *	----------------| ...				|	H
	 *	ebp + 8bytes -> | old eip (ret addr)|
	 *	ebp + 0bytes -> | old ebp			| <----------
	 *					| ...				|			|
	 *			rsp ->	| ...				|			|
	 *	----------------| ...				|			|
	 *	ebp + 8bytes -> | old eip (ret addr)|			|
	 *	ebp + 0bytes -> | old ebp-----------|------------ copy_from_usr()
	 *					| ...				|	L
	 * Push (H->L): add item + rsp--
	 * Pop (L->H): remove item + rsp++
	 *
	 *
	 * first rbp is on ffff88xxxxxxxxxx, then ffffffff81xxxxxx
	 */
	/* gva -> gpa - ref:  arch/x86/kvm/x86.c kvm_mmu_gva_to_gpa_system() */
	int cnt = 0, i;
	//int err_cnt = 0;
	struct kvm_translation tr;
	unsigned long *frame; /* stack frame page in host kvaddr */
	//unsigned long *kvaddr, *frame; /* stack frame page in host kvaddr */
	unsigned long gpa, gfn, ofs, grbp_hva;
	unsigned long next_rbp_gva = kvm_regs->rbp;

#if DEBUG_VMDSM_TRACE_SKIP_STACK
	goto err_skip;
#endif

	all_cnt++;
	if (((kvm_regs->rip >> PAGE_SHIFT) == 0xffffffff81198) // TODO USE FINCTION NAME
		&& (all_cnt > DEBUG_THRESHOLD_LOW  && all_cnt < DEBUG_THRESHOLD_UP)) {
		VM_DSM_COLLECT_PK("\t%lu %d: - 1 rip 0x%llx [rbp 0x%lx] "
						"dbg (0x%llx ?= 0 0x%llx 0x%lx)\n",
						all_cnt, cnt, kvm_regs->rip, next_rbp_gva,
						(kvm_regs->rip >> PAGE_SHIFT ^ 0xffffffff81198),
						kvm_regs->rip >> PAGE_SHIFT, 0xffffffff81198);
	}

	if (!is_valid_rbp(next_rbp_gva))
		goto err;

	/* guest pgt walk */
	tr.linear_address = next_rbp_gva;
	kvm_arch_vcpu_ioctl_translate(
				hype_node_info[my_nid][fd]->vcpu, &tr);
	gpa = tr.physical_address;

	if (gpa == 0UL - 1)
		goto __err;

	if (((kvm_regs->rip >> PAGE_SHIFT) == 0xffffffff81198)
		&& (all_cnt > DEBUG_THRESHOLD_LOW  && all_cnt < DEBUG_THRESHOLD_UP)) {
		VM_DSM_COLLECT_PK("\t%lu %d: - 2 rip 0x%llx [rbp 0x%lx] gpa 0x%lx\n",
							all_cnt, cnt, kvm_regs->rip, next_rbp_gva, gpa);
	}
	/* host - gpa -> gfn */
	gfn = gpa >> PAGE_SHIFT;
	ofs = gpa % PAGE_SIZE;
	grbp_hva = kvm_vcpu_gfn_to_hva(
				hype_node_info[my_nid][fd]->vcpu, gfn);
	grbp_hva += ofs;
	if (((kvm_regs->rip >> PAGE_SHIFT) == 0xffffffff81198)
		&& (all_cnt > DEBUG_THRESHOLD_LOW  && all_cnt < DEBUG_THRESHOLD_UP)) {
		VM_DSM_COLLECT_PK("\t%lu %d: - 3 rip 0x%llx "
							"[rbp 0x%lx] start grbp_hva 0x%lx\n",
							all_cnt, cnt, kvm_regs->rip, next_rbp_gva, grbp_hva);
	}

	if (copy_from_user(kvaddr,
				(const void __user *)grbp_hva, sizeof(long) * 2)) {
		printk(KERN_ERR "%lu %d: [BUG] rip 0x%llx next_rbp_gva 0x%lx -> "
				"gpa 0x%lx -> grbp_hva 0x%lx while copying\n",
				all_cnt, cnt, kvm_regs->rip, next_rbp_gva, gpa, grbp_hva);
		goto _err;
	}

	frame = (unsigned long *)kvaddr;
	do { /* vaniila walk stack code */
		unsigned long ret_addr = *(frame + 1);
		unsigned long next_rbp_gva = *frame;
		if (((kvm_regs->rip >> PAGE_SHIFT) == 0xffffffff81198)
			&& (all_cnt > DEBUG_THRESHOLD_LOW  && all_cnt < DEBUG_THRESHOLD_UP)) {
			VM_DSM_COLLECT_PK("\t%lu %d: - 4 rip 0x%llx "
							"next_rbp 0x%lx ret_addr [0x%lx]\n",
							all_cnt, cnt, kvm_regs->rip, next_rbp_gva, ret_addr);
		}
		_dsm_traffic->stack[cnt] = ret_addr;
		cnt++;

		/* Check next ptr */
		if (!is_valid_rbp(next_rbp_gva))
			goto err;

		/* Start translate */
		/* gva -> gpa */
		tr.linear_address = next_rbp_gva;
		kvm_arch_vcpu_ioctl_translate(
					hype_node_info[my_nid][fd]->vcpu, &tr);
		gpa = tr.physical_address;

		if (((kvm_regs->rip >> PAGE_SHIFT) == 0xffffffff81198)
			&& (all_cnt > DEBUG_THRESHOLD_LOW  && all_cnt < DEBUG_THRESHOLD_UP)) {
			VM_DSM_COLLECT_PK("\t\t%lu %d: - 5 rip 0x%llx "
								"[next rbp] gva 0x%lx -> gpa 0x%lx\n",
								all_cnt, cnt, kvm_regs->rip, next_rbp_gva, gpa);
		}

		if (gpa == 0UL - 1)
			goto __err;

		/* gva -> gfn */
		gfn = (gpa) >> PAGE_SHIFT;
		ofs = (gpa) % PAGE_SIZE;
		/* gva -> gfn -> hva */
		grbp_hva = kvm_vcpu_gfn_to_hva(
					hype_node_info[my_nid][fd]->vcpu, gfn);
		grbp_hva += ofs;
		/* hva */
		/* copy */
		if (copy_from_user(kvaddr,
				(const void __user *)grbp_hva, sizeof(long) * 2)) {
			printk(KERN_ERR "%lu %d: [BUG] rip 0x%llx next_rbp_gva 0x%lx -> "
				"gpa 0x%lx -> grbp_hva 0x%lx while copying\n",
				all_cnt, cnt, kvm_regs->rip, next_rbp_gva, gpa, grbp_hva);
			goto _err;
		}
		frame = kvaddr;
	} while (cnt < MAX_VM_STACK_DEBUG);

	if (((kvm_regs->rip >> PAGE_SHIFT) == 0xffffffff81198)
		&& (all_cnt > DEBUG_THRESHOLD_LOW  && all_cnt < DEBUG_THRESHOLD_UP)) {
		VM_DSM_COLLECT_PK("\t%lu %d: - 6 rip 0x%llx [rbp 0x%llx] done\n",
						all_cnt, cnt, kvm_regs->rip, kvm_regs->rbp);
		VM_DSM_COLLECT_PK("\n");
	}
	return;

err: /* !is_valid_rbp */
	/* if you see rsp = ffffxxxxxxxxxxxx and rbp = dddddddddddddddd, check
	 * ./Documentation/x86/x86_64/mm.txt to find where is the rsp from
	 * and try to filter it out or mark it.
	 * And,
	 * rsp = 7fffffffxxxx + rbp = dddddddddddddddd is from userspace
	 */
	for (i = cnt; i < MAX_VM_STACK_DEBUG; i++)
		_dsm_traffic->stack[i] = 0xdddddddddddddddd;
	if (((kvm_regs->rip >> PAGE_SHIFT) == 0xffffffff81198)
		&& (all_cnt > DEBUG_THRESHOLD_LOW  && all_cnt < DEBUG_THRESHOLD_UP)) {
		VM_DSM_COLLECT_PK("\n");
	}
	return;

_err:
	for (i = cnt; i < MAX_VM_STACK_DEBUG; i++)
		_dsm_traffic->stack[i] = 0xeeeeeeeeeeeeeeee;
	if (((kvm_regs->rip >> PAGE_SHIFT) == 0xffffffff81198)
		&& (all_cnt > DEBUG_THRESHOLD_LOW  && all_cnt < DEBUG_THRESHOLD_UP)) {
		VM_DSM_COLLECT_PK("\n");
	}
	return;

__err:
	for (i = cnt; i < MAX_VM_STACK_DEBUG; i++)
		_dsm_traffic->stack[i] = 0UL - 1;
	if (((kvm_regs->rip >> PAGE_SHIFT) == 0xffffffff81198)
		&& (all_cnt > DEBUG_THRESHOLD_LOW  && all_cnt < DEBUG_THRESHOLD_UP)) {
		VM_DSM_COLLECT_PK("\n");
	}
	return;

err_skip:
	for (i = cnt; i < MAX_VM_STACK_DEBUG; i++)
		_dsm_traffic->stack[i] = 0xaaaaaaaaaaaaaaaa;
	return;
}

/* For dumping vm regs
 *	Ref:
 *		Kern: ./arch/x86/kvm/x86.c kvm_arch_vcpu_ioctl_get_regs()
 *		Usr:
 *			signal(SIGUSR1, handle_sigusr1);
 *			static void handle_sigusr1(int sig) {
 *				kvm_cpu__show_registers(vcpu)
 *			}
 *			search: SIGUSR1
 *			stack:
 *				x86/kvm-cpu.c: kvm_cpu__show_code()
 *					kvm__dump_mem() // walk stack
 */
//struct kvm_vcpu *pophype_vcpu[MAX_POPCORN_VCPU];
//unsigned long pophype_show_guest_rip_rsp(unsigned long host_addr)
dsm_traffic_t pophype_show_guest_rip_rsp(unsigned long host_addr, bool show, struct kvm_vcpu *vcpu)
{
	int i;
	bool found = false;
	//unsigned long inst = -1;
	//struct dsm_pgfault *;
		//.inst = 0,
	struct kvm_regs *kvm_regs;
	dsm_traffic_t _dsm_traffic = {
		.rip = 0,
		.addr = 0,
		.rbp = 0,
		.rsp = 0,
		//.stack[] = {0, 0, 0, 0, 0},
		.cnt = 1,
		//.time = 0
	};
	for (i = 0; i < MAX_VM_STACK_DEBUG; i++) {
		_dsm_traffic.stack[i] = 0;
	}

	kvm_regs = kzalloc(sizeof(struct kvm_regs), GFP_ATOMIC);
	BUG_ON(!kvm_regs);

	/* TODO: use kvm_vcpu struct directly.... */
	for (i = 0; i < MAX_POPCORN_VCPU; i++) {
		//if (hype_node_info[my_nid][i]->on_mynid) /* fastpath -
		//													not implemented */
		if (my_nid == popcorn_vcpuid_to_nid(i)) {
			int fd = i + VCPU_FD_BASE; /* TODO - this is a HACK.
									Use syscall to get correct info from usr */
			if (hype_node_info[my_nid][fd]->vcpu) {
				BUG_ON(vcpu != hype_node_info[my_nid][fd]->vcpu);
				BUG_ON(vcpu->vcpu_id !=					/* post-prelim check */
						hype_node_info[my_nid][fd]->vcpu->vcpu_id);
				kvm_arch_vcpu_ioctl_get_regs(
					hype_node_info[my_nid][fd]->vcpu, kvm_regs); /* TODO BUG
															THIS IS A HACK */
				found = true;

				/* RSP walk stack */
				vm_stack_walk(kvm_regs, &_dsm_traffic, fd);

#if HYPE_PERF_CRITICAL_DSM_TRAFFIC_PRINTK
				if (show) {
					POP_PK("pophype: dsm dbg: 0x%lx guest-vcpu%d "
							"ip 0x%llx sp 0x%llx rbp 0x%llx\n",
							host_addr, i, kvm_regs->rip,
							kvm_regs->rsp, kvm_regs->rbp);
				}
#endif
			}
			break;
		}
	}
	if (found) {
		_dsm_traffic.rip = kvm_regs->rip;
		_dsm_traffic.rsp = kvm_regs->rsp;
		_dsm_traffic.rbp = kvm_regs->rbp;
		//_dsm_traffic.stack[0] = ;
	}
	kfree(kvm_regs);
#if HYPE_PERF_CRITICAL_DSM_TRAFFIC_PRINTK
	//printk("=======\n=======\n\n");
#endif
	return _dsm_traffic;
}

#ifdef CONFIG_POPCORN_STAT
/* Stat */
atomic64_t apic_reg_write_ns = ATOMIC64_INIT(0);
atomic64_t apic_reg_write_cnt = ATOMIC64_INIT(0);
atomic64_t apic_reg_write_handle_ns = ATOMIC64_INIT(0);
atomic64_t apic_reg_write_handle_cnt = ATOMIC64_INIT(0);

atomic64_t ipi_ns = ATOMIC64_INIT(0);
atomic64_t ipi_cnt = ATOMIC64_INIT(0);
atomic64_t ipi_handle_ns = ATOMIC64_INIT(0);
atomic64_t ipi_handle_cnt = ATOMIC64_INIT(0);
atomic64_t update_vcpu_ns = ATOMIC64_INIT(0);
atomic64_t update_vcpu_cnt = ATOMIC64_INIT(0);
atomic64_t update_vcpu_handle_ns = ATOMIC64_INIT(0);
atomic64_t update_vcpu_handle_cnt = ATOMIC64_INIT(0);
atomic64_t update_vcpu_run_handle_ns = ATOMIC64_INIT(0);
atomic64_t update_vcpu_run_handle_cnt = ATOMIC64_INIT(0);

atomic64_t sig_ns = ATOMIC64_INIT(0);
atomic64_t sig_cnt = ATOMIC64_INIT(0);
atomic64_t sig_handle_ns = ATOMIC64_INIT(0);
atomic64_t sig_handle_cnt = ATOMIC64_INIT(0);
#endif
//atomic64_inc(&mm_cnt);
#if 0 /* example */
atomic64_t invh_ns = ATOMIC64_INIT(0);
atomic64_t invh_cnt = ATOMIC64_INIT(0);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, invh_end, invh_start = ktime_get();
#endif

	...(target)...

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	invh_end = ktime_get();
	dt = ktime_sub(invh_end, invh_start);
	atomic64_add(ktime_to_ns(dt), &invh_ns);
	atomic64_inc(&invh_cnt);
#endif
#endif

void pophype_set_cpu(int cpu)
{
    cpumask_var_t new_mask;
	u64 vcpu_id = cpu, retried = 0;

	might_sleep();
	BUG_ON(!alloc_cpumask_var(&new_mask, GFP_KERNEL)); /* return -ENOMEM; */
#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t\tpophype: %s(): in_atomic() %d current <%d> future <%llu>\n",
						__func__, in_atomic(), smp_processor_id(), vcpu_id);
#endif
	while (smp_processor_id() != vcpu_id) {
		//BUG_ON(cpumask_parse_user("1", 2, new_value));
		cpumask_clear(new_mask);
		cpumask_set_cpu(vcpu_id, new_mask); /* vcpu 0x0 = cpumask 0x01 */

		/* thread affinity */
		sched_setaffinity(current->pid, new_mask);

		/* XXX */
		if (retried) {
			volatile int i, j;
			for (i = 0; i < 1000*1000*1000; i++)
				for (j = 0; j < 10; j++)
					; //io_schedule(); cannot sleep
		}

		retried++;
	}
    free_cpumask_var(new_mask);
#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t\tpophype: %s(): on <%d> retried %llu\n",
				__func__, smp_processor_id(), retried);
#endif
}

void pophype_set_cpu0(void)
{
#if !POPHYPE_HOST_KERNEL
    // typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;
    // typedef struct cpumask *cpumask_var_t;
	//int ret;
    cpumask_var_t new_mask;
	u64 vcpu_id = 0, retried = 0;

	might_sleep();
	BUG_ON(!alloc_cpumask_var(&new_mask, GFP_KERNEL)); /* return -ENOMEM; */

	POP_PK("\t\tpophype: %s(): current <%d> future <%llu>\n",
						__func__, smp_processor_id(), vcpu_id);
	while (smp_processor_id() != vcpu_id) {
		//BUG_ON(cpumask_parse_user("1", 2, new_value));
		cpumask_clear(new_mask);
		cpumask_set_cpu(vcpu_id, new_mask); /* vcpu 0x0 = cpumask 0x01 */

		/* thread affinity */
		sched_setaffinity(current->pid, new_mask);

		/* XXX */
		if (retried)
			io_schedule();

		retried++;
	}
    free_cpumask_var(new_mask);
	POP_PK("\t\tpophype: %s(): on <%d> retried %llu\n",
				__func__, smp_processor_id(), retried);

	/* irq affinity */
	// struct irq_desc *desc = irq_to_desc(irq);
//	if (desc) {
//		if (desc->irq_data.chip) {
//			if (desc->irq_data.chip->irq_set_affinity) {
//				AFFPRINTK("%s() check: smp_irq_set_affinity_callback() %p name %s\n",
//						__func__, desc->irq_data.chip->irq_set_affinity,
//									desc->irq_data.chip->name);
//			} else {
//				AFFPRINTK("%s() check: !smp_irq_set_affinity_callback() \n", __func__);
//			}
//		} else {
//			AFFPRINTK("%s() check: !desc->irq_data.chip case\n", __func__);
//		}
//	} else {
//		AFFPRINTK("%s() check: !desc case\n", __func__);
//	}
	//ret = irq_set_affinity(port->irq, new_value);
	//if (ret < 0)
	//	printk(KERN_ERR "\n\n\t\t\tERROR: [%d] %s(): cannot set irq\n\n\n",
	//												current->pid, __func__);
#endif
}

/*
 * lkvm user space version - vcpuid_to_nid();
 */
int popcorn_vcpuid_to_nid(int vcpu_id)
{
	if (atomic64_read(&gvcpu_to_nid[vcpu_id]) >= 0) {
		/* debug */
		//printk("asking vcpu_id %d returning nid %ld\n",
		//				vcpu_id, atomic64_read(&gvcpu_to_nid[vcpu_id]));
		return atomic64_read(&gvcpu_to_nid[vcpu_id]);
	}

	printk(KERN_ERR "vcpu_id %d is not registered\n", vcpu_id);
	dump_stack();
	BUG();
}

inline void popcorn_show_gcpu_table(void) {
	/* Only suppor 4vcpu now */
#if HPMIGRATION_DEBUG /* debug */
	printk("atomic64_read(&gvcpu_to_nid[0-4] %ld %ld %ld %ld\n",
#else
	PHMIGRATEPRINTK("atomic64_read(&gvcpu_to_nid[0-4] %ld %ld %ld %ld\n",
#endif
			atomic64_read(&gvcpu_to_nid[0]), atomic64_read(&gvcpu_to_nid[1]),
			atomic64_read(&gvcpu_to_nid[2]), atomic64_read(&gvcpu_to_nid[3]));
}

#ifdef CONFIG_POPCORN_CHECK_SANITY
inline bool popcorn_on_right_nid(int vcpu_id)
{
	if (my_nid == popcorn_vcpuid_to_nid(vcpu_id))
		return true;
	return false;
}
#else
inline bool popcorn_on_right_node(int vcpu)
{
	return true;
}
#endif


/* caller must have installed gvcpu_to_nid[] */
int pophype_available_vcpu(void)
{
	int i, accu_cnt = 0;
		for (i = 0; i < MAX_POPCORN_VCPU; i++) {
			if (atomic64_read(&gvcpu_to_nid[i]) >= 0) {
				accu_cnt++;
			}
		}
	//printk("pophype total vcpu %d\n", accu_cnt);
	return accu_cnt;
}


/*******************************
 * Debug utils
 *******************************/
/* Call this function in hypervisor only (NOT USEFUL printk works already) */
//#define MAX_NID 8
#include <linux/fdtable.h>
//extern int sys_close(unsigned int fd);
//#define LEN 255
int popcorn_get_hnid(void)
{
#if 0
    int i, fd, flags = O_RDONLY;
	char init_echo_name[] = "/jack_echo"; // TODO fox
	char path[LEN];

	//for (i = 0; i <= MAX_POPCORN_NODES; i++) {
	for (i = 4; i <= 5; i++) {
		int ofs = 0;
		memset(path, 0, LEN);
		ofs += snprintf(path, LEN,
				//(sizeof(init_echo_name) - 0) * sizeof(*init_echo_name),
													"%s", init_echo_name);
		//ofs += snprintf(path + ofs, sizeof(char), "%d", i);
		ofs += snprintf(path + ofs, LEN, "%d", i);
		printk("try open \"%s\" size %lu ofs %d\n", path,
			(sizeof(init_echo_name) - 0) * sizeof(*init_echo_name), ofs);
		fd = do_sys_open(AT_FDCWD , path, flags, 0);
		if (fd >= 0) {
			sys_close(fd);
			return i;
		}
	}
#endif
	return -1;
}

/* ref fd_install() */
int popcorn_file_to_fd(struct task_struct *tsk, struct file *file, bool is_vcpu)
{
	struct fdtable *fdt = rcu_dereference_sched(tsk->files->fdt);
	int fd = -1, max_fd;
	bool good = false;
	BUG_ON(!file);

	if (is_vcpu)
		max_fd = MAX_POPCORN_VCPU;
	else
		max_fd = MAX_POPCORN_FD;

	/* This is not precise */
	for (fd = FD_START; fd < max_fd; fd++) {
		//printk("fd %d fdt->fd[fd] %p file %p\n", fd, fdt ? fdt->fd[fd] : NULL, file);
		if (fdt->fd[fd]) {
			if (fdt->fd[fd] == file) {
				good = true;
				break;
			}
		} else
			break; /* fastpath - continuous fd assumption */
	}
	rcu_read_unlock_sched();
	if (!good) {
		printk(KERN_ERR "Cannot find the fd for file %p\n", file);
		//BUG_ON(!good);
	}
	return fd;
}

/*******************************
 * NID VCPU mapping
 *******************************/
/* register this vcpu to my node */
void register_local_vcpu(int vcpu_id)
{
	my_hype_cpu[vcpu_id] = true;
}

/* lookup - is vcpu_id on mynid? */
bool is_local_vcpu(int vcpu_id)
{
	return my_hype_cpu[vcpu_id];
}


/*******************************
 * Delegations  *reqs & handlers)
 *******************************/
// This kernel implementation is not being used. Instead user solution is taken.
// popcorn version of kvm_dev_ioctl_create_vm()
// TODO am I using?
// NOT USEING
int popcorn_kvm_dev_ioctl_create_vm_tsk(unsigned long type)
{
	/******************************************************/
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	/******************************************************/

	if (!current->at_remote) { // origin - broadcast
		printk("TODO: implement\n");
		BUG();
	} else { // remote - delegation and reply
		remote_kvm_create_request_t *req = kmalloc(sizeof(*req), GFP_KERNEL);
		struct wait_station *ws = get_wait_station(current);
		remote_kvm_create_response_t *res;
		struct remote_context *rc = current->mm->remote;
		//int dfd = AT_FDCWD;
		int tmp_fd = -999;
		BUG_ON(!rc || !req);
		req->from_pid = current->pid;
		req->origin_pid = rc->remote_tgids[0]; // lookup the pid on origin
		req->ws = ws->id;

		req->type = type;

		HPPRINTK("[%d] #working# [[kvm_create]]- delegating to origin "
							"req->type %lu\n", current->pid, req->type);
        pcn_kmsg_send(PCN_KMSG_TYPE_REMOTE_KVM_CREATE_REQUEST,
									0, req, sizeof(*req));
		res = wait_at_station(ws);

		// anon mapping using
		HPPRINTK("[%d] #working# [[kvm_create]] - replaying and matching "
				"origin replys res->fd [[%d]] with struct file* for "
				" at remote\n", current->pid, res->fd);
		// replay kvm_create but use res->fd; to map with file_struct
		tmp_fd = replay_kvm_dev_ioctl_create_vm_tsk(current, type);

		HPPRINTK("[%d] replay returns tmp_fd [[%d]] at remote\n\n",
												current->pid, tmp_fd);

		kfree(req);
		pcn_kmsg_done(res);
		return tmp_fd;
	}
	return -999;
}


static void process_remote_kvm_create_request(struct work_struct *work)
{
    START_KMSG_WORK(remote_kvm_create_request_t, req, work);
    remote_kvm_create_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->origin_pid);
	unsigned long type = req->type;

	HPPRINTK("[from%d/origin%d]#working# [[kvm_create]] at origin\n",
										req->from_pid, req->origin_pid);

	BUG_ON(!tsk && "No task exist");
	BUG_ON(tsk->at_remote);

	HPPRINTK("[from%d/origin%d]\n", req->from_pid, tsk->pid);

	/* remote is trying to create a vm */
	res->fd = replay_kvm_dev_ioctl_create_vm_tsk(tsk, type);

    res->from_pid = req->from_pid;
	res->ws = req->ws;

	HPPRINTK("#working# [[kvm_create]] at origin DONE fd %d ->\n\n",
												res->fd);
    pcn_kmsg_post(PCN_KMSG_TYPE_REMOTE_KVM_CREATE_RESPONSE,
							from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
}

static int handle_remote_kvm_create_response(struct pcn_kmsg_message *msg)
{
    remote_kvm_create_response_t *res = (remote_kvm_create_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;

	complete(&ws->pendings);
    return 0;
}

int vcpuid_to_fd(int vcpu_id)
{
	return VCPU_FD_BASE + vcpu_id;
}

/* Only partial req will be broadcast now: APIC_DFR(don't care vcpu?) */
/* //TODO rename now is bidirection - Bidirection now */ // no need
/* TODO rename: vcpu_id -> from vcpu_id (broadcasting this info to every other nodes) */
void popcorn_broadcast_apic_reg_write(int vcpu_id, u32 reg, u32 val)
{
	origin_broadcast_apic_reg_write_response_t *res;
	origin_broadcast_apic_reg_write_request_t *req;
	struct remote_context *rc = current->mm->remote;
	struct wait_station *ws;
	int nid;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, apic_reg_write_end, apic_reg_write_start = ktime_get();
#endif

#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!rc);
#endif

	POP_PK("%s(): => <brodcast> for registering apic->vcpu_id %d\n",
													__func__, vcpu_id);

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	BUG_ON(!req);

	req->from_pid = current->pid;

	req->fd = vcpuid_to_fd(vcpu_id);
	req->vcpu_id = vcpu_id;
	req->reg = reg;
	req->val = val;

	for (nid = 0; nid < get_popcorn_nodes(); nid++) {
		if (nid == my_nid) continue;
		POP_PK("%s(): pop_hype broadcast reg %x val %x => [%d] <%d>\n",
										__func__, reg, val, nid, vcpu_id);
		ws = get_wait_station(current);
		req->ws = ws->id;
		req->remote_pid = rc->remote_tgids[nid];
#ifdef CONFIG_POPCORN_CHECK_SANITY
		if (!req->remote_pid) {
			printk(KERN_ERR "req->remote_pid %d to [%d]", req->remote_pid, nid);
			BUG_ON(!req->remote_pid); // seems buggy at remote
		}
#endif

		pcn_kmsg_send(PCN_KMSG_TYPE_ORIGIN_BROADCAST_APIC_REG_WRITE_REQUEST,
													nid, req, sizeof(*req));
		res = wait_at_station(ws);
		BUG_ON(res->ret);
		pcn_kmsg_done(res);
	}

	kfree(req);
#ifdef CONFIG_POPCORN_STAT
	apic_reg_write_end = ktime_get();
	dt = ktime_sub(apic_reg_write_end, apic_reg_write_start);
	atomic64_add(ktime_to_ns(dt), &apic_reg_write_ns);
	atomic64_inc(&apic_reg_write_cnt);
#endif
}



/***
 * vhost-net: eventfd table (e.g. eventfd ctx, fd)
 */
int eventfd_ctx_to_fd(struct eventfd_ctx *eventfd_ctx)
{
	int i;
	CRITICALNETPK("\t\t%s(): eventfd_ctx %p to fd ?\n",
							__func__, eventfd_ctx);
	for (i = FD_START; i < MAX_POPCORN_FD; i++) {
		if (!hype_eventfd_info[i]) continue;
		if (hype_eventfd_info[i]->eventfd_ctx == eventfd_ctx) {
			CRITICALNETPK("\t\t%s(): matched - eventfd_ctx %p fd %d\n",
									__func__, eventfd_ctx, i);
			return i;
		}
	}
	BUG();
	return -1;
}

struct eventfd_ctx *eventfd_fd_to_ctx(int eventfd_fd)
{
	//struct eventfd_ctx *eventfd_ctx;
	int retry, retry_limit = 1000000;

retry:
	if (likely(hype_eventfd_info[eventfd_fd])) {
		CRITICALNETPK("retrive ctx %p for fd %d\n",
			hype_eventfd_info[eventfd_fd]->eventfd_ctx, eventfd_fd);
		return hype_eventfd_info[eventfd_fd]->eventfd_ctx;
	} else {
		retry++;
		if (retry < retry_limit) {
			io_schedule();
			goto retry;
		}
		/* When it happens, usually it's not race condition. */
		printk(KERN_ERR "CANNOT FIND eventfd ctx for fd %d\n", eventfd_fd);
		dump_stack();
		BUG();
	}
}

#define SKIP_EVENTFD_DELEGATE_RESPONSE 1
/* 11/05/19 add #if 0 to implement nonblocking */
__u64 pophype_eventfd_delegate(int eventfd_fd, __u64 n)
{
	delegate_eventfd_request_t *req;
#if !SKIP_EVENTFD_DELEGATE_RESPONSE
	delegate_eventfd_response_t *res;
	struct wait_station *ws;
#endif
	struct remote_context *rc = current->mm->remote;
	int dst_nid = POPCORN_HOST_NID; /* delegation */
	__u64 res_n;
	/* Common done */
	static int cnt = 0;
	///int abc;

	CRITICALNETPK("\n[DELEG EVENTFD] %s(): fd %d =>\n",
							__func__, eventfd_fd);
	/* Common */
	if (my_nid == dst_nid) {
		printk(KERN_ERR "skip this self delegation... #%d\n", ++cnt);
		return 100000; /* prevented from outside as well */
	}
	req = kmalloc(sizeof(*req), GFP_KERNEL);
	BUG_ON(!req || !rc);
#if !SKIP_EVENTFD_DELEGATE_RESPONSE
	ws = get_wait_station(current);
	req->ws = ws->id;
#endif
	req->from_pid = current->pid;

	/* customize */
	req->eventfd_fd = eventfd_fd; /* will be converted to ctx */
	req->n = n;

	req->remote_pid = rc->remote_tgids[dst_nid];
	pcn_kmsg_send(PCN_KMSG_TYPE_DELEGATE_EVENTFD_REQUEST,
								dst_nid, req, sizeof(*req));
#ifdef CONFIG_POPCORN_STAT
	eventfd_delegate_cnt++;
#endif

#if !SKIP_EVENTFD_DELEGATE_RESPONSE
	res = wait_at_station(ws);
	res_n = res->n;
	pcn_kmsg_done(res);
	res_n = res->n;
#else
	res_n = n;
#endif
	kfree(req);

	/* self checking */
	if (res_n != n)
		CRITICALNETPK("[WATCHOUT] n has been changed!!!\n");
	return res_n;
}

/* 11/05/19 add #if 0 to implement nonblocking */
extern __u64 pophype_eventfd_signal(struct eventfd_ctx *ctx, __u64 n);
static void process_eventfd_delegate_request(struct work_struct *work)
{
    START_KMSG_WORK(delegate_eventfd_request_t, req, work);
#if !SKIP_EVENTFD_DELEGATE_RESPONSE
    delegate_eventfd_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
#endif
    //struct task_struct *tsk = __get_task_struct(req->remote_pid);
	//
	static int cnt = 0;
	struct eventfd_ctx *eventfd_ctx;
	__u64 n;

#ifdef CONFIG_POPCORN_STAT
	atomic64_inc(&eventfd_delegated_cnt);
	cnt++;
#endif

	CRITICALNETPK("\n => [DELEG EVENTFD] %s(): fd %d #%d\n",
							__func__, req->eventfd_fd, cnt);
	/* Convert */
	eventfd_ctx = eventfd_fd_to_ctx(req->eventfd_fd);

	/* Perform delegation work */
	n = pophype_eventfd_signal(eventfd_ctx, req->n);

#if !SKIP_EVENTFD_DELEGATE_RESPONSE
	res->n = n;
	res->eventfd_fd = req->eventfd_fd;

	//res->ret = ret;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_DELEGATE_EVENTFD_RESPONSE,
								from_nid, res, sizeof(*res));
#endif
    END_KMSG_WORK(req);
}

static int handle_eventfd_delegate_response(struct pcn_kmsg_message *msg)
{
	delegate_eventfd_response_t *res = (delegate_eventfd_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);
	/* common done */
	static int cnt = 0;
	cnt++;
#if SKIP_EVENTFD_DELEGATE_RESPONSE
	BUG();
#endif
	/* customize */
	CRITICALNETPK("\n<< [DELEG EVENTFD] %s(): fd %d n %llu #%d\n",
							__func__, res->eventfd_fd, res->n, cnt);

	/* common */
    ws->private = res;
	complete(&ws->pendings);

	/* customize */
    return res->n;
}


/*******************************************************************************
 * MSG
 */

///* origin_ : initiated by origin
// * remote_ : initiated by remote */
extern int popcorn_apic_reg_write(struct kvm_lapic *apic, u32 reg, u32 val);
static void process_origin_broadcast_apic_reg_write_request(struct work_struct *work)
{
    START_KMSG_WORK(origin_broadcast_apic_reg_write_request_t, req, work);
    origin_broadcast_apic_reg_write_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->remote_pid);
	struct kvm_lapic *apic;
	struct fd __fd;
	unsigned long v;
	struct file *filp;
	struct kvm_vcpu *vcpu;
	int ret = 0;
	u32 reg = req->reg;
	u32 val = req->val;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, apic_reg_write_handle_end, apic_reg_write_handle_start = ktime_get();
#endif

	if (!tsk) {
		printk(KERN_ERR "from [%d/%d]\n\n\n", from_nid, req->remote_pid);
		BUG_ON(!tsk && "No task exist");
	}
	IPIINITPRINTK("%s(): fd fd fd %d tsk->files %p\n",
				__func__, req->fd, tsk->files);
				///////////////tsk??????? but how remote can do it...
	//struct fd __fd = fdget(req->fd);
	v = fget_light_tsk(tsk, req->fd, FMODE_PATH);
	__fd = (struct fd){(struct file *)(v & ~3),v & 3};
	IPIINITPRINTK("%s(): struct fd &__fd %p\n", __func__, (void *)&__fd);
	filp = __fd.file;
	BUG_ON(!filp); /* check run.sh lkvm argv
						highly likely you don't have enough CPU online */
	vcpu = filp->private_data;
	BUG_ON(!vcpu);
	fdput(__fd);
	IPIINITPRINTK("%s(): reg 0x%x val 0x%x ***fd %d <%d>***\n",
					__func__, reg, val, req->fd, vcpu->vcpu_id);

	//BUG_ON(from_nid || !tsk->at_remote);
	BUG_ON(req->fd < 0);

	apic = vcpu->arch.apic;
	BUG_ON(!apic);

	/* Popcorn proxy */
	ret = popcorn_apic_reg_write(apic, reg, val);

	IPIINITPRINTK("%s(): apic %p reg 0x%x val 0x%x ret (%s)\n",
				__func__, apic, reg, val, !ret ? "GOOD" : "BAD");

	res->ret = ret;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_ORIGIN_BROADCAST_APIC_REG_WRITE_RESPONSE,
											from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	apic_reg_write_handle_end = ktime_get();
	dt = ktime_sub(apic_reg_write_handle_end, apic_reg_write_handle_start);
	atomic64_add(ktime_to_ns(dt), &apic_reg_write_handle_ns);
	atomic64_inc(&apic_reg_write_handle_cnt);
#endif
}

static int handle_origin_broadcast_apic_reg_write_response(struct pcn_kmsg_message *msg)
{
    origin_broadcast_apic_reg_write_response_t *res =
		(origin_broadcast_apic_reg_write_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;

	complete(&ws->pendings);

    return 0;
}

/* SIPI */
/* TODO rename vcpu_id to target_vcpu_id */
/* TODO rename: DONT USE BROADCAST. this is a redirect */
/* NOT USED */
void popcorn_broadcast_accept_irq(int vcpu_id, int delivery_mode, int vector, int level, int trig_mode, int dest_map)
{
	origin_broadcast_accept_irq_response_t *res;
	origin_broadcast_accept_irq_request_t *req;
	struct remote_context *rc = current->mm->remote;
	struct wait_station *ws;
	int nid;

	/******************************************************/
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	/******************************************************/

	BUG_ON("NOT USED");

	if (!rc)
		return;

	req = kmalloc(sizeof(*req), GFP_ATOMIC);
	ws = get_wait_station(current);
#ifdef CONFIG_POPCORN_CHECK_SANITY
	if (current->at_remote || my_nid > 0 || !req || vcpu_id <= 0) {
		printk("[%d/%d] req %p BUG()\n", my_nid, current->pid, req);
		BUG();
	}
#endif

	req->from_pid = current->pid;
	nid = popcorn_vcpuid_to_nid(vcpu_id);
	POP_PK("%s(): => [%d] <%d>\n", __func__, nid, vcpu_id);
	req->remote_pid = rc->remote_tgids[nid];
	req->ws = ws->id;

	req->fd = vcpuid_to_fd(vcpu_id); /* HACK TODO */
	req->vcpu_id = vcpu_id;
	req->delivery_mode = delivery_mode;
	req->vector = vector;
	req->level = level;
	req->trig_mode = trig_mode;
	req->dest_map = dest_map;

	pcn_kmsg_send(PCN_KMSG_TYPE_ORIGIN_BROADCAST_ACCEPT_IRQ_REQUEST,
												nid, req, sizeof(*req));
#if 0
//	printk("%s(): TESTING NOT TO SLEEP WHILE SENDING IPI to remote\n", __func__);
//	int cnt, loop = 1000000*100; // 100000000*100=60s so ~600m
//    for (cnt = 0; cnt < loop; cnt++) {
//        cpu_relax();
//    }
//	printk("%s(): FORGET ABOUT res THIS IS A BUG\n", __func__);
//	kfree(req);
//	rcu_read_unlock();
	res = wait_at_station(ws);
	BUG_ON(res->ret);

	kfree(req);
	pcn_kmsg_done(res);
//	rcu_read_lock();
#else
	res = wait_at_station(ws);
	BUG_ON(res->ret);

	kfree(req);
	pcn_kmsg_done(res);
#endif
}

///* origin_ : initiated by origin
// * remote_ : initiated by remote */
/* Similar to __apic_accept_irq() */
static void process_origin_broadcast_accept_irq_request(struct work_struct *work)
{
    START_KMSG_WORK(origin_broadcast_accept_irq_request_t, req, work);
    origin_broadcast_accept_irq_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->remote_pid);
	struct fd __fd = fdget(req->fd);
	struct file *filp = __fd.file;
	struct kvm_vcpu *vcpu = filp->private_data;
	struct kvm_lapic *apic;
	int ret = 0;
	int delivery_mode = req->delivery_mode;
	fdput(__fd);

	/******************************************************/
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	/******************************************************/
	BUG_ON("NOT USED");

	BUG_ON(!tsk && "No task exist");
	BUG_ON(from_nid || !tsk->at_remote || !my_nid);
	BUG_ON(req->fd < 0);
	BUG_ON(!filp);

	BUG_ON(!vcpu);
	apic = vcpu->arch.apic;
	BUG_ON(!apic);

	printk("\t\t-> GOT IPI IRQ mode %d from origin: "
					"fd %d vid %d filp %p vcpu %p\n",
					delivery_mode, req->fd, req->vcpu_id, filp, vcpu);

	//popcorn_apic_accept_irq(apic, delivery_mode,
	//						vector, level, trig_mode, dest_map);
	ret = popcorn_apic_accept_irq(apic, delivery_mode, 0, 0, 0, NULL);

	res->ret = ret;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_ORIGIN_BROADCAST_ACCEPT_IRQ_RESPONSE,
											from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
}

static int handle_origin_broadcast_accept_irq_response(struct pcn_kmsg_message *msg)
{
    origin_broadcast_accept_irq_response_t *res =
		(origin_broadcast_accept_irq_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;

	complete(&ws->pendings);

    return 0;
}

/* NOT USED */
void popcorn_send_sipi(int vcpu_id, int vector)
{
	origin_sipi_response_t *res;
	origin_sipi_request_t *req;
	struct remote_context *rc = current->mm->remote;
	struct wait_station *ws;
	int nid;

	/******************************************************/
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG(); BUG();
	/******************************************************/
	BUG(); BUG(); BUG(); /* TODO: BUG */
	BUG(); BUG(); BUG(); /* TODO: BUG */
	BUG(); BUG(); BUG(); /* TODO: BUG */
	if (!rc)
		return;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	ws = get_wait_station(current);
	BUG_ON(current->at_remote);
	BUG_ON(!req);

	req->from_pid = current->pid;
	printk("\t%s(): TODO give right node ttable for vcpu->node&fd\n", __func__);
	printk("\t%s(): TODO give right node ttable for vcpu->node&fd\n", __func__);
	printk("\t%s(): TODO give right node ttable for vcpu->node&fd\n", __func__);
	nid = popcorn_vcpuid_to_nid(vcpu_id);
	req->remote_pid = rc->remote_tgids[nid]; /* look for remote worker pid */
	req->ws = ws->id;

	/*  BUG TODO get the right fd  kvm 4 vcpu12*/
	printk("\t%s(): TODO giving right fd (now fixed 12)\n", __func__);
	printk("\t%s(): TODO giving right fd (now fixed 12)\n", __func__);
	printk("\t%s(): TODO giving right fd (now fixed 12)\n", __func__);
	req->fd = 12;
	req->vcpu_id = vcpu_id;
	req->vector = vector;

	pcn_kmsg_send(PCN_KMSG_TYPE_ORIGIN_SIPI_REQUEST,
								nid, req, sizeof(*req));
	res = wait_at_station(ws);
	BUG_ON(res->ret);

	kfree(req);
	pcn_kmsg_done(res);
}


/* origin_ : initiated by origin
 * remote_ : initiated by remote */
static void process_origin_sipi_request(struct work_struct *work)
{
    START_KMSG_WORK(origin_sipi_request_t, req, work);
    origin_sipi_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->remote_pid);
	struct fd __fd = fdget(req->fd);
	struct file *filp = __fd.file;
	/* DEPENDS ON fd 12/kvm_fd*/
	//struct kvm *kvm = filp->private_data;
	struct kvm_vcpu *vcpu = filp->private_data;
//fdput(__fd);
	struct kvm_lapic *apic;

	BUG_ON(from_nid);
	BUG_ON(!tsk && "No task exist");
	BUG_ON(!tsk->at_remote);
	BUG_ON(req->fd < 0);
	BUG_ON(!filp);
//	BUG_ON(!kvm);

	printk("%s(): req [fd %d vcpu_id %d] to get *filp %p (matched???) vcpu %p\n",
								__func__, req->fd, req->vcpu_id, __fd.file, vcpu);
//	printk("  [%d] (using) treat as \"%s\"\n", current->pid, path);

	//struct kvm_vcpu *vcpu = kvm_get_vcpu_by_id(kvm, req->vcpu_id);
	BUG_ON(!vcpu);
	apic = vcpu->arch.apic;
	BUG_ON(!apic);

	/* hacking!!!!!!!!!!!!! - post init (APIC_DM_INIT) */
	BUG(); BUG(); BUG(); /* TODO: BUG */
#if 0
	static int cnt = 0;
	if (!cnt) { // only does 1 time to prove im right
		/* assumes that there are only KVM_APIC_INIT/SIPI */
		apic->pending_events = (1UL << KVM_APIC_INIT);
		smp_wmb();
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		kvm_vcpu_kick(vcpu);
		cnt = 1;
	}
#endif

	/* start sipi */
	printk("%s(): [%d]->req fd %d vcpu %d vector 0x%x\n",
			__func__, from_nid, req->fd, req->vcpu_id, req->vector);
	apic->sipi_vector = req->vector; /* AP will read it. */
	/* make sure sipi_vector is visible for the receiver */
	smp_wmb();
	set_bit(KVM_APIC_SIPI, &apic->pending_events);
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	kvm_vcpu_kick(vcpu);

	res->ret = 0;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_ORIGIN_SIPI_RESPONSE,
							from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
	fdput(__fd);
}

// send
static int handle_origin_sipi_response(struct pcn_kmsg_message *msg)
{
    origin_sipi_response_t *res = (origin_sipi_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;

	complete(&ws->pendings);

    return 0;
}

/****
 * rack info
 */
static void process_origin_broadcast_cpu_table_request(struct work_struct *work)
{
    START_KMSG_WORK(origin_broadcast_cpu_table_request_t, req, work);
    origin_broadcast_cpu_table_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->remote_pid);
	int ret = 0, i;

#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!tsk);
#endif

	POP_PK("\t\t => %s(): [%d/%d]\n", __func__, my_nid, req->remote_pid);

	/* load to my (remote) gvcpu_to_nid */
	//memcpy(gvcpu_to_nid, req->vcpu_to_nid, sizeof(*gvcpu_to_nid) * MAX_POPCORN_VCPU);
	for (i = 0; i < MAX_POPCORN_VCPU; i++) {
		atomic64_set(&gvcpu_to_nid[i], req->vcpu_to_nid[i]);
	}

	{
		g_popcorn_vcpu_cnt = pophype_available_vcpu();
		POP_PK("\t(remote) %s(): calculated g_popcorn_vcpu_cnt = %d\n",
				__func__, g_popcorn_vcpu_cnt);
		first_fd_after_vcpufd = g_popcorn_vcpu_cnt + VCPU_FD_BASE;
	}

	res->ret = ret;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_ORIGIN_BROADCAST_CPU_TABLE_RESPONSE,
											from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
}

static int handle_origin_broadcast_cpu_table_response(struct pcn_kmsg_message *msg)
{
    origin_broadcast_cpu_table_response_t *res =
		(origin_broadcast_cpu_table_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;

	complete(&ws->pendings);
	POP_PK("%s():\n", __func__);

    return 0;
}

// <*> only origin does it
SYSCALL_DEFINE1(popcorn_broadcast_cpu_table, int __user *, vcpu_to_nid)
{
	origin_broadcast_cpu_table_request_t *req;
	struct remote_context *rc = current->mm->remote;
	struct wait_station *ws;
	int i;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	BUG_ON(current->at_remote || !req || !rc); /* check your msg_layer!! */
	req->from_pid = current->pid;

	//POP_PK("\t%s(): TODO give right node table for vcpu->node&fd\n", __func__);

	/* customize */
	{
		int lvcpu_to_nid[MAX_POPCORN_VCPU];
		POP_PK("%s(): nodes %d / %d\n", __func__, get_popcorn_nodes(), MAX_POPCORN_VCPU);
		if (copy_from_user(lvcpu_to_nid, vcpu_to_nid, sizeof(int) * MAX_POPCORN_VCPU))
			BUG(); /* or return -EFAULT; */
		for (i = 0; i < MAX_POPCORN_VCPU; i++) {
			atomic64_set(&gvcpu_to_nid[i], lvcpu_to_nid[i]);
		}

		g_popcorn_vcpu_cnt = pophype_available_vcpu();

		POP_PK("\t(origin) %s(): calculated g_popcorn_vcpu_cnt = %d\n",
				__func__, g_popcorn_vcpu_cnt);
		first_fd_after_vcpufd = g_popcorn_vcpu_cnt + VCPU_FD_BASE;
		POP_PK("%s(): all set\n\n", __func__);

		/* for ingroming remotes' tables */
		memcpy(req->vcpu_to_nid, lvcpu_to_nid, sizeof(*lvcpu_to_nid) * MAX_POPCORN_VCPU);
	}


	for (i = 0; i < get_popcorn_nodes(); i++) {
		origin_broadcast_cpu_table_response_t *res;
		if (my_nid == i) continue;
		ws = get_wait_station(current);
		req->ws = ws->id;
		req->remote_pid = rc->remote_tgids[i]; /* look for remote worker pid */
		while (!req->remote_pid) {
			printk(KERN_ERR "\tOrigin runs too fast. "
					"Wait for remote thread inited. "
					"Or forgot migrating thread before calling this func!\n");
			msleep(100);
			req->remote_pid = rc->remote_tgids[i];
		}
#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(!req->remote_pid);
#endif

		POP_PK("\t\t%s(): => [%d/%d]\n", __func__, i, req->remote_pid);
		pcn_kmsg_send(PCN_KMSG_TYPE_ORIGIN_BROADCAST_CPU_TABLE_REQUEST,
													i, req, sizeof(*req));
		res = wait_at_station(ws);
		BUG_ON(res->ret);
		pcn_kmsg_done(res);
	}

	kfree(req);
//////////////////////////////////

	return false;
}

/* README: move to other place
we need to register vcpu thread pid table at origin and remote.
pophype_checkin_vcpu_pid: TODO
pophype_origin_checkin_vcpu_pid: origin saves remote's pid (and respond with its)
	Remote migrates back to origin and invoke this function sending the pid to the remote node.

*/

/* <*> only origin does it
	rename to origin BROADCAST vcpu pid
	from_nid is the node id asking origin to perform this function */
SYSCALL_DEFINE1(pophype_origin_checkin_vcpu_pid, int __user, from_nid)
{
	pophype_request_t *req;
	struct remote_context *rc = current->mm->remote;
	struct wait_station *ws;
	int nid;
	pophype_response_t *res;
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(my_nid);
#endif
	SIGVPRINTK("\t\t%s(): pid %d\n",
			__func__,  current->pid);

	// argument not used.
	//hype_node_info[from_nid][VCPU_FD_BASE + from_nid]->origin_pid =
	//													current->pid;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	BUG_ON(!req);
	req->from_pid = current->pid;

	/* The remove nid asking origin to broadcast this */
	//req->from_nid = from_nid;

	nid = from_nid;
	BUG_ON(nid == my_nid);
	// only to from_nid or every one?
	//for (nid = 0; nid < get_popcorn_nodes(); nid++) {
	//	if (nid == my_nid) continue;
		ws = get_wait_station(current);
		req->ws = ws->id;
		req->remote_pid = rc->remote_tgids[nid];

		pcn_kmsg_send(PCN_KMSG_TYPE_ORIGIN_CHECKIN_VCPU_PID_REQUEST,
										nid, req, sizeof(*req));
		res = wait_at_station(ws);
		BUG_ON(res->ret);
		pcn_kmsg_done(res);
	//}

	kfree(req);
	return false;
}

/* <!*> only remote does it */
/* TODO rename corresponding to remote_checkin_vcpu_pid not checkin_vcpu_pid */
SYSCALL_DEFINE1(pophype_remote_checkin_vcpu_pid, int __user, pid)
{
	pophype_request_t *req;
	struct remote_context *rc = current->mm->remote;
	struct wait_station *ws;
	int origin = 0;
	pophype_response_t *res;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!my_nid || !current->at_remote || !req || !rc);
#endif
	req->from_pid = current->pid;

	/* customize */
	// none

	ws = get_wait_station(current);
	req->ws = ws->id;
	req->from_pid = current->pid;
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!req->remote_pid);

	{
	struct task_struct *p;
	p = find_task_by_vpid(current->pid);
	SIGVPRINTK("\t\t<< %s(): sanity check p %p curr->pid %d\n",
			__func__, p,  current->pid);
	}
#endif

//	SIGVPRINTK("\t\t%s(): checkin "
//			"this vcpu thread's pid %d at origin => origin\n",
//			__func__,  current->pid);
	pcn_kmsg_send(PCN_KMSG_TYPE_REMOTE_CHECKIN_VCPU_PID_REQUEST,
										origin, req, sizeof(*req));

	// Optimization - no need to sync
	res = wait_at_station(ws);
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(res->ret);
#endif
	pcn_kmsg_done(res);

	/* 1st[] indicates the pid on this node
		2nd[] indicates the vcpu id */
	hype_node_info[my_nid][VCPU_FD_BASE + origin]->remote_pid =
												current->pid;
	//hype_node_info[my_nid][VCPU_FD_BASE + my_nid]->origin_pid =
	//											res->origin_pid;
	SIGVPRINTK("\t\t<< %s(): checkin curr->pid %d "
			"install hype_node_info[%d][%d]->remote_pid %d\n",
			//"install hype_node_info[%d][%d]->remote_pid %d ->origin_pid %d\n",
			__func__,  current->pid,
			my_nid, VCPU_FD_BASE + my_nid, current->pid);
			//, res->origin_pid);

	kfree(req);
	return false;
}


// called in host userspace x86#: 381
// TODO: rename to pophype_prepare_vcpu_migrate
SYSCALL_DEFINE1(pophype_migrate_on_hostusr, int, vcpu_id)
{
    int fd = vcpu_id + VCPU_FD_BASE;
    struct kvm_vcpu *vcpu = hype_node_info[my_nid][fd]->vcpu;
//  int dst_nid = a0;
    PHGMIGRATEPRINTK("[%d] <%d> %s %d %s(): Start save <%d>\n",
            current->pid, smp_processor_id(),
            __FILE__, __LINE__, __func__, vcpu->vcpu_id);
    //PHGMIGRATEPRINTK("[%d] <%d> %s %d %s(): Start\n",
    //              current->pid, smp_processor_id(), __FILE__, __LINE__, __func__);
    //kvm_hypercall2(KVM_HC_POPHYPE_MIGRATE, a0, a1);
    //printk("\n\n%s(): TODO dst_nid %d a1 %d\n\n", __func__, dst_nid, a1);
    //PHGMIGRATEPRINTK("[%d] <%d> %s %d %s(): "
    //              "Done for debugging and see this printk (GO HOME!!!!!!!!)\n",
    //              current->pid, smp_processor_id(), __FILE__, __LINE__, __func__);

    BUG_ON(!vcpu);

    /******/
    /* save state for pophype migration */
    /******/
    /* uhype states */
    pophype_save_vcpu_states(vcpu);

    PHGMIGRATEPRINTK("[%d] <%d> %s %d %s(): Done save <%d> - "
            "you can now call migrate from host user\n",
            current->pid, smp_processor_id(),
            __FILE__, __LINE__, __func__, vcpu->vcpu_id);

    return 0;
}

/* Because the invoker is not the target vcpu thread */
SYSCALL_DEFINE1(pophype_vcpu_migrate_trigger, int __user, vcpu_id)
{
	int fd = vcpu_id + VCPU_FD_BASE; /* TODO - this is a HACK. */
	struct kvm_vcpu *vcpu = hype_node_info[my_nid][fd]->vcpu;

	SIGVPRINTK("\t\t[%d] %s(): I wanna migrate vcpu<%d> %p\n",
				current->pid, __func__, vcpu_id, vcpu);
	BUG_ON(!vcpu);

	smp_wmb();
	//set_bit(KVM_APIC_SIPI, &apic->pending_events); //TODO MY bit but not sure tihs will make vm exit to usr
/////////
	// case APIC_DM_REMRD:
	vcpu->arch.pv.pv_unhalted = 1;
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	kvm_vcpu_kick(vcpu);

	kvm_make_request(KVM_REQ_CLOCK_UPDATE, vcpu);
	kvm_vcpu_kick(vcpu);
/////////
	kvm_make_request(KVM_REQ_VCPU_MIGRATION, vcpu);
	//set_bit(KVM_REQ_VCPU_MIGRATION, &vcpu->requests);
	kvm_vcpu_kick(vcpu);
	kvm_make_request(KVM_REQ_VCPU_MIGRATION, vcpu);
	kvm_vcpu_kick(vcpu);
	kvm_make_request(KVM_REQ_VCPU_MIGRATION, vcpu);
	kvm_vcpu_kick(vcpu);
	//kvm_arch_vcpu_should_kick(vcpu);
	//smp_send_reschedule(vcpu->vcpu_id);
	smp_send_reschedule(vcpu->cpu);
	//smp_send_reschedule(get_cpu());
	//smp_send_reschedule(vcpu->vcpu_id);
{
    int me;
    int cpu = vcpu->cpu;
    wait_queue_head_t *wqp;

    wqp = kvm_arch_vcpu_wq(vcpu);
    if (waitqueue_active(wqp)) {
        wake_up_interruptible(wqp);
        ++vcpu->stat.halt_wakeup;
    }

    me = get_cpu();
	printk("vcpu->cpu %d me %d vcpu->vcpu_id %d\n",
			cpu, me, vcpu->vcpu_id);
    if (cpu != me && (unsigned)cpu < nr_cpu_ids && cpu_online(cpu))
        if (kvm_arch_vcpu_should_kick(vcpu))
            smp_send_reschedule(cpu);
    put_cpu();

}
	SIGVPRINTK("\t\t[%d] %s(): kicked vcpu<%d> %p\n",
			current->pid, __func__, vcpu->vcpu_id, vcpu);

#if 0
	{
//#include <kvm/iodev.h>
//#include <kvm/ioapic.h>
//#include "../arch/x86/kvm/ioapic.h" // Jack arch
//#include "../arch/x86/kvm/irq_comm.c" // Jack arch
#include "../arch/x86/kvm/irq.h" // Jack arch
//#include <asm/kvm_host.h>
//#include <linux/kvm_host.h>
//#include <linux/kvm_host.h>
//#include <linux/slab.h>
//#include <linux/export.h>
//#include <trace/events/kvm.h>
		int apicid = vcpu->vcpu_id;
		struct kvm_lapic_irq lapic_irq;

		lapic_irq.shorthand = 0;
		lapic_irq.dest_mode = 0;
		lapic_irq.dest_id = apicid;
		lapic_irq.msi_redir_hint = false;

		lapic_irq.delivery_mode = APIC_DM_REMRD;
		kvm_irq_delivery_to_apic(vcpu->kvm, NULL, &lapic_irq, NULL);

		SIGVPRINTK("\t\t[%d] %s(): kicked vcpu<%d> - 2\n",
					current->pid, __func__, vcpu->vcpu_id);
	}
#endif
	return 0;
}

/* Update vcpu - let other remote nodes know the current global vCPU view */
static void popcorn_update_cpu_table(int migrated_vcpu, int migrate_to_nid)
{
	int nid;
	/* Testing my protection implementation in __build_and_check_msg() pcn_kmsg.c */
	for (nid = 0; nid < MAX_POPCORN_NODES; nid++) {
	//for (nid = 0; nid < get_popcorn_nodes(); nid++) {
			update_cpu_table_request_t *req; // new
		if (nid == migrate_to_nid || nid == my_nid) continue; /* handled in migration routines */
		//update_cpu_table_request_t *req; // origin
		req = pcn_kmsg_get(sizeof(*req)); // new
		// test online

		//req = pcn_kmsg_get(sizeof(*req));
		/* Custom */
		req->migrated_vcpu = migrated_vcpu;
		req->migrate_to_nid = migrate_to_nid;
		//req->migrate_from_nid = my_nid; /* always from me to others */

		/* This will release req!! */
		if(pcn_kmsg_post(PCN_KMSG_TYPE_UPDATE_CPU_TABLE_REQUEST_FIELDS,
										nid, req, sizeof(*req))) {
			PHMIGRATEPRINTK("FAIL: %s %d %s(): to [%d]\n",
							__FILE__, __LINE__, __func__, nid); /* debug */
		}
		//pcn_kmsg_put(req); // origin
	}
}

/* (remote) -  */
static void process_update_cpu_table_request(struct work_struct *work)
{
	START_KMSG_WORK(update_cpu_table_request_t, req, work);

	atomic64_set(&gvcpu_to_nid[req->migrated_vcpu], req->migrate_to_nid);
	PHMIGRATEPRINTK("-> got vcpu table updated gvcpu_to_nid[%d] = %d\n",
								req->migrated_vcpu, req->migrate_to_nid);
#if HPMIGRATION_DEBUG /* debug */
	{
		static int cnt = 0;
		cnt++;
		POP_PK("\t-> <%d> on [%d] #%d\n",
				req->migrated_vcpu, req->migrate_to_nid, cnt);
		popcorn_show_gcpu_table();
	}
#endif

	END_KMSG_WORK(req);
}

/*
 * KVM_IPI - needed since cannot know dst_cpu until kvm_irq_delivery_to_apic_fast()
 * ret: succ cnt
 */
int popcorn_send_ipi(struct kvm_vcpu *dst_vcpu, struct kvm_lapic_irq *irq, unsigned long *dest_map)
{
	ipi_response_t *res; /* kvm_ipi_req/res */
	ipi_request_t *req;
	struct remote_context *rc = current->mm->remote;
	struct wait_station *ws;
	int r = 0, dst_nid = popcorn_vcpuid_to_nid(dst_vcpu->vcpu_id);
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, ipi_end, ipi_start = ktime_get();
#endif
#ifdef CONFIG_POPCORN_CHECK_SANITY
	static int popcorn_ipi_at_atomic_cnt = 0;
	if (in_interrupt() || in_atomic() || irqs_disabled()) {
		popcorn_ipi_at_atomic_cnt++;
		if (popcorn_ipi_at_atomic_cnt < 1000 ||
			!(popcorn_ipi_at_atomic_cnt % 10000) ) {
			FTPRINTK("%s(): my_nid %d dst_vcpu %d [%d] "
				"in int %s atomic %s irq_disable %s #%d\n",
				__func__, my_nid, dst_vcpu->vcpu_id, dst_nid,
				in_interrupt() ? "O":"X", in_atomic() ? "O":"X",
				irqs_disabled() ? "O":"X", popcorn_ipi_at_atomic_cnt);
			//dump_stack(); // at runtime from vhost-net's handle_rx
		}
	}
#endif
	if (my_nid == dst_nid) return r; /* prevented at the outside as well */

	//req = kmalloc(sizeof(*req), GFP_KERNEL);
	req = kmalloc(sizeof(*req), GFP_ATOMIC);
	ws = get_wait_station(current);
	//BUG_ON(current->at_remote || !req || !rc);
	BUG_ON(!req || !rc);
	req->from_pid = current->pid;
	req->ws = ws->id;

	/* customize */

	req->fd = vcpuid_to_fd(dst_vcpu->vcpu_id);

	/* This is my assumption (always !dest_map except our pophype request)
											for using REMOTE_APIC */
	BUG_ON(dest_map);

	/* No pte inside */
	memcpy(&req->irq, irq, sizeof(*irq));

	/* p2p */
	//BUG_ON(my_nid == dst_vcpu) continue;
	IPIVPRINTK("\t\t%s(): =kvmipi> [%d] <%d> irq->delivery_mode 0x%x "
				"->dest_id <%u>\n",
				__func__, dst_nid, dst_vcpu->vcpu_id,
				irq->delivery_mode, irq->dest_id);
	req->remote_pid = rc->remote_tgids[dst_nid];
	pcn_kmsg_send(PCN_KMSG_TYPE_IPI_REQUEST, dst_nid, req, sizeof(*req));
	res = wait_at_station(ws);
	r += res->ret;
	pcn_kmsg_done(res);

	kfree(req);
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ipi_end = ktime_get();
	dt = ktime_sub(ipi_end, ipi_start);
	atomic64_add(ktime_to_ns(dt), &ipi_ns);
	atomic64_inc(&ipi_cnt);
#endif

	return r;
}

static void process_ipi_request(struct work_struct *work)
{
    START_KMSG_WORK(ipi_request_t, req, work);
    ipi_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->remote_pid);
	int ret = 0;
	struct fd dst_fd;
	unsigned long v;
	struct file *filp;
	struct kvm_vcpu *vcpu; // TODO rename to dst_vcpu
	struct kvm_lapic *apic; /* Source vcpu's apic */
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, ipi_handle_end, ipi_handle_start = ktime_get();
#endif
	//struct kvm_lapic *apic;
	/* cust */
	//int *lcpus = req->cpus;
	//int lcpus[255];
	//u32 reg = req->reg;

	/* Do remotely */
	//struct kvm_vcpu *vcpu;
	struct kvm_lapic_irq *irq = &req->irq;
	unsigned long *dest_map = NULL; // TODO no need to support so far
	BUG_ON(!tsk && "No task exist");

	v = fget_light_tsk(tsk, req->fd, FMODE_PATH);
	dst_fd = (struct fd){(struct file *)(v & ~3),v & 3};
	filp = dst_fd.file;
	BUG_ON(!filp);
	vcpu = filp->private_data;
	BUG_ON(!vcpu);
	fdput(dst_fd);

	// too many mode=0
	if (irq->delivery_mode) { // dbg
		IPIVPRINTK("\t\t => %s(): -> irq->dest_id <%d> **fd %d <%d>** "
					"irq->delivery_mode 0x%x\n",
					__func__, irq->dest_id, req->fd,
					vcpu->vcpu_id, irq->delivery_mode);
	}

	/* Source vcpu's apic */
	apic = vcpu->arch.apic;

	/* HACK? not really? just for my convenience */
	/* trick: at this moment irq->delivery_mode alredy defined */
	/* TODO */
	/* BUG TODO now it redo on all cpus..... */
	/* BUG should I do tsk struct? but the ipi is just one cpu TODO TOD TODO BUG */
	// BUG
	// BUG
	if (irq->delivery_mode == APIC_DM_STARTUP ||
		irq->delivery_mode == APIC_DM_INIT) { // ICR's two SIPI (1..., 2...)
		// a INIT-SIPI-SIPI (ISS) sequence
		ret = popcorn_kvm_apic_set_irq(vcpu, irq, dest_map);
	} else { /* other ICRs and others (watchout including 0 APIC_DM_FIXED) */
		/* DM_FIXED means broadcast and low priority? (from kvm_irq_delivery_to_apic()) */
#if HYPE_PERF_CRITICAL_DEBUG
		static unsigned long dm_fixed_cnt = 0;
		if (irq->delivery_mode == APIC_DM_FIXED) {
			dm_fixed_cnt++;
			if (dm_fixed_cnt < 300 || !(dm_fixed_cnt % 10000)) {
				POP_PK("\t => from remote got APIC_DM_FIXED #%lu\n", dm_fixed_cnt);
			}
		} else {
			printk(KERN_ERR "\t => From remote. " /* Never */
					"These are the delivery_mode that I don't know 0x%x\n",
														irq->delivery_mode);
		}
#endif

		ret = popcorn_apic_inject_ipi(apic, irq, vcpu->vcpu_id);
	}

	IPIVPRINTK("\t\t >> %s(): done ***fd %d <%d>***\n",
					__func__, req->fd, vcpu->vcpu_id);

	// THIS IS FOR DEBUGGIN PLZ KILL (TODO also kill in types.h)
	//memcpy(&res->irq, irq, sizeof(*irq));

	res->ret = ret;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_IPI_RESPONSE,
					from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ipi_handle_end = ktime_get();
	dt = ktime_sub(ipi_handle_end, ipi_handle_start);
	atomic64_add(ktime_to_ns(dt), &ipi_handle_ns);
	atomic64_inc(&ipi_handle_cnt);
#endif
}

static int handle_ipi_response(struct pcn_kmsg_message *msg)
{
	ipi_response_t *res = (ipi_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

	// THIS IS FOR DEBUGGIN PLZ KILL (also in types.h)
	struct kvm_lapic_irq *irq = &res->irq;
	static int cnt = 0;
	cnt++;

    ws->private = res;

	complete(&ws->pendings);
	if (irq->delivery_mode) {
		IPIVPRINTK("\t\t << %s(): mode 0x%x #%d\n", __func__, irq->delivery_mode, cnt);
	}

    return res->ret;
}

/**
 * Pophype signal broadcast (redirection to all remote nodes)
 * Important:
#if 0
 */
int popcorn_broadcast_sig(int usr_sig)
{
	sig_response_t *res;
	sig_request_t *req;
	struct remote_context *rc = current->mm->remote;
	struct wait_station *ws;
	int r = 0, nid;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, sig_end, sig_start = ktime_get();
#endif

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	//BUG_ON(current->at_remote || !req || !rc);
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!req || !rc);
#endif
	req->from_pid = current->pid;

	/* customize */
	//req->fd = vcpuid_to_fd(dst_vcpu->vcpu_id);
	req->usr_sig = usr_sig;
	/* do_tkill */
	//struct siginfo info = {};
	req->siginfo.si_signo = usr_sig;
	req->siginfo.si_errno = 0;
	req->siginfo.si_code = SI_TKILL;
	//req->siginfo.si_pid = task_tgid_vnr(current);
	//req->siginfo.si_uid = from_kuid_munged(current_user_ns(), current_uid());


	for (nid = 0; nid < get_popcorn_nodes(); nid++) {
		if (nid == my_nid) continue;
#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(!hype_node_info[nid][VCPU_FD_BASE + nid]);
#endif
		SIGVPRINTK("%s(): pop_hype broadcast => [%d] "
				"(expect pid  = origin tsk %p remote %d)\n",
				__func__, nid,
				hype_node_info[nid][VCPU_FD_BASE + nid]->tsk,
				//hype_node_info[nid][VCPU_FD_BASE + nid]->tsk->pid,
				hype_node_info[nid][VCPU_FD_BASE + nid]->remote_pid); /* Attention: aAssuming 1 vcpu on 1 node */
		ws = get_wait_station(current);
		req->ws = ws->id;

		/* customize */
		//req->remote_pid = rc->remote_tgids[nid];
		//req->siginfo.si_pid = rc->remote_tgids[nid];
		req->remote_pid =
				hype_node_info[nid][VCPU_FD_BASE + nid]->remote_pid;
		req->siginfo.si_pid =
				hype_node_info[nid][VCPU_FD_BASE + nid]->remote_pid;
		/* Permission - need updated at remote */
		//req->siginfo.si_uid = from_kuid_munged(current_user_ns(), current_uid());
		//req->target_pid = rc->remote_tgids[nid];
		//req->target_tgid = rc->remote_tgids[nid];
		req->target_pid = hype_node_info[nid][VCPU_FD_BASE + nid]->remote_pid;
		req->target_tgid = hype_node_info[nid][VCPU_FD_BASE + nid]->remote_pid;
		printk("TODO BUG should be right at remote or just put a # <= 0\n");
		printk("TODO: req->targetpid/tgid are hacking\n");
#ifdef CONFIG_POPCORN_CHECK_SANITY
		if (!req->remote_pid) {
			printk(KERN_ERR "req->remote_pid %d to [%d]", req->remote_pid, nid);
			BUG_ON(!req->remote_pid); // seems buggy at remote
		}
#endif

		pcn_kmsg_send(PCN_KMSG_TYPE_SIG_REQUEST,
						nid, req, sizeof(*req));
		res = wait_at_station(ws);
#ifdef CONFIG_POPCORN_CHECK_SANITY
		//BUG_ON(res->ret);
#endif
		r += res->ret;
		pcn_kmsg_done(res);
	}


	kfree(req);
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	sig_end = ktime_get();
	dt = ktime_sub(sig_end, sig_start);
	atomic64_add(ktime_to_ns(dt), &sig_ns);
	atomic64_inc(&sig_cnt);
#endif

	return r;
}

static void process_sig_request(struct work_struct *work)
{
    START_KMSG_WORK(sig_request_t, req, work);
    sig_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
   // struct task_struct *tsk = __get_task_struct(req->remote_pid);
	struct task_struct *tsk = __get_task_struct(req->target_pid);
	int ret = 0;
	//struct fd dst_fd;
	//unsigned long v;
	//struct file *filp;
	//struct kvm_vcpu *vcpu; // TODO rename to dst_vcpu
	//struct kvm_lapic *apic; /* Source vcpu's apic */
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, sig_handle_end, sig_handle_start = ktime_get();
#endif
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!my_nid);
#endif

	/* Reply signal operationsy */
	//struct siginfo *siginfo = &req->siginfo;
	SIGVPRINTK("\t\t -> %s(): call pophype_do_send_specific_at_remote() "
				"with usr_sig %d target tgid %d [pid %d]\n",
					__func__, req->usr_sig, req->target_tgid, req->target_pid);

	// uid: check __task_cred(task) at include/linux/cred.h
	// ns: check
	//struct task_struct *tsk = __get_task_struct(req->remote_pid);
	//struct user_namespace *ns = task_active_pid_ns(__get_task_struct(target_pid));
	//req->siginfo.si_uid = from_kuid_munged(current_user_ns(), current_uid());
	//req->siginfo.si_uid = from_kuid_munged(&init_user_ns, current_uid());
	req->siginfo.si_uid = from_kuid_munged(&init_user_ns, task_uid(tsk));
	SIGVPRINTK("\t\t %s(): trying si_uid %d\n",
					__func__, req->siginfo.si_uid);
	ret = pophype_do_send_specific_at_remote(req->target_tgid,
					req->target_pid, req->usr_sig, &req->siginfo);
	SIGVPRINTK("\t\t >> %s(): done ret = %d\n", __func__, ret);
#ifdef CONFIG_POPCORN_CHECK_SANITY
	//BUG_ON(ret);
#endif

	/* ACK results */
	res->ret = ret;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_SIG_RESPONSE,
					from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	sig_handle_end = ktime_get();
	dt = ktime_sub(sig_handle_end, sig_handle_start);
	atomic64_add(ktime_to_ns(dt), &sig_handle_ns);
	atomic64_inc(&sig_handle_cnt);
#endif
}

static int handle_sig_response(struct pcn_kmsg_message *msg)
{
	sig_response_t *res = (sig_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

	// THIS IS FOR DEBUGGIN PLZ KILL (also in types.h)
	static int cnt = 0;
	cnt++;

    ws->private = res;

	complete(&ws->pendings);
	SIGVPRINTK("\t\t << %s(): #%d\n", __func__, cnt);

    return res->ret;
}

/*****/
static void process_checkin_vcpu_pid_request(struct work_struct *work)
{
    START_KMSG_WORK(pophype_request_t, req, work);
    pophype_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
   // struct task_struct *tsk = __get_task_struct(req->remote_pid);
	int ret = 0;
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(my_nid);
#endif

	/* assumption: 1 vcpu on 1 node */
	SIGVPRINTK("\t\t -> %s(): [%d] install vcpu<%d> pid %d at origin. "
				"My pid %d (hype_node_info[][]->remote_pid %d\n",
				__func__, current->pid, from_nid, req->from_pid,
				current->pid, req->from_pid);
	/* current->pid is wrong. use rc */

	hype_node_info[from_nid][VCPU_FD_BASE + from_nid]->remote_pid =
														req->from_pid;
	//res->origin_pid = current->pid;

	SIGVPRINTK("\t\t << %s(): done\n", __func__);



	/* ACK results */
	res->ret = ret;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_REMOTE_CHECKIN_VCPU_PID_RESPONSE,
					from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
}

static int handle_checkin_vcpu_pid_response(struct pcn_kmsg_message *msg)
{
	pophype_response_t *res = (pophype_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

	// THIS IS FOR DEBUGGIN PLZ KILL (also in types.h)
	static int cnt = 0;
	cnt++;

    ws->private = res;

	complete(&ws->pendings);
	//SIGVPRINTK("\t\t << %s(): res->origin_pid %d #%d\n",
	//						__func__, res->origin_pid, cnt);
	SIGVPRINTK("\t\t << %s():#%d\n", __func__, cnt);

    return res->ret;
}

/*****/
static void process_origin_checkin_vcpu_pid_request(struct work_struct *work)
{
    START_KMSG_WORK(pophype_request_t, req, work);
    pophype_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
   // struct task_struct *tsk = __get_task_struct(req->remote_pid);
	int ret = 0;
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!my_nid);
#endif

	/* assumption: 1 vcpu on 1 node */
	SIGVPRINTK("\t\t -> %s(): [%d] install vcpu<%d> pid %d at remote. "
				"My pid %d (hype_node_info[%d][%d]->origin_pid "
				"= req->from_pid %d)\n",
					__func__, current->pid, from_nid,
					req->from_pid, current->pid,
					from_nid, VCPU_FD_BASE + from_nid,
					req->from_pid);
	/* current->pid is wrong. use rc */

	BUG_ON(from_nid); /* only from origin */
	hype_node_info[from_nid][VCPU_FD_BASE + from_nid]->origin_pid =
														req->from_pid;

	SIGVPRINTK("\t\t << %s(): done\n", __func__);

	/* ACK results */
	res->ret = ret;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_ORIGIN_CHECKIN_VCPU_PID_RESPONSE,
					from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
}

static int handle_origin_checkin_vcpu_pid_response(struct pcn_kmsg_message *msg)
{
	pophype_response_t *res = (pophype_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

	// THIS IS FOR DEBUGGIN PLZ KILL (also in types.h)
	static int cnt = 0;
	cnt++;

    ws->private = res;

	complete(&ws->pendings);
	SIGVPRINTK("\t\t << %s(): #%d\n",
						__func__, cnt);

    return res->ret;
}

/* Karim's vhost optimizations */
void khype_send_rx_notification(rx_notification_request_t *req)
{
       struct remote_context *rc = NULL;
    int dst_nid = req->vhost;
    struct wait_station *ws = NULL;
    int r = 0;

    rc = __hype_gctx.rc;
    req->from_pid = current->pid;
    req->remote_pid = rc->remote_tgids[dst_nid];


      VHOSTPKRX("khype_rx_notification_delegate: nid=%d\n", dst_nid);

       pcn_kmsg_post(PCN_KMSG_TYPE_RX_NOTIFICATION_REQUEST,
                                dst_nid, req, sizeof(*req));
}

extern void khype_handle_rx(struct vhost_net *);
static void process_rx_notification_request(struct work_struct *work)
{
    START_KMSG_WORK(rx_notification_request_t, req, work);

    int from_nid = PCN_KMSG_FROM_NID(req);
    struct vhost_net *net;

    net = __hype_gctx.__hype_vhosts[req->vhost];
    VHOSTPKRX("process_rx_notification_request: nid=%d, vhost=%d\n", my_nid, req->vhost);
       khype_handle_rx(net);

    END_KMSG_WORK(req);
}

/* peek_head_len delegation */
size_t khype_peek_head_len_request(int vhost)
{
       peek_head_len_request_t req;
       peek_head_len_response_t *res = NULL;
    struct remote_context *rc = NULL;
    int dst_nid = POPCORN_HOST_NID;
    struct wait_station *ws = NULL;
       size_t sock_len;

    rc = __hype_gctx.rc;
    ws = get_wait_station(current);
    BUG_ON(!ws);

    req.ws = ws->id;
    req.from_pid = current->pid;
       req.vhost = vhost;
    req.remote_pid = rc->remote_tgids[dst_nid];

    VHOSTPKRX("khype_peek_head_len_request\n");
    pcn_kmsg_send(PCN_KMSG_TYPE_PEEK_HEAD_LEN_REQUEST,
                                dst_nid, &req, sizeof(req));
    res = wait_at_station(ws);
    sock_len = res->sock_len;
       VHOSTPKRX("khype_peek_head_len_request: returned! sock_len=%zu\n", sock_len);

    pcn_kmsg_done(res);
    return sock_len;
}

extern size_t khype_service_peek_head_len(struct vhost_net *net);
static void process_peek_head_len_request(struct work_struct *work)
{
    START_KMSG_WORK(peek_head_len_request_t, req, work);
    peek_head_len_response_t *res;
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct vhost_net *net;
    size_t sock_len;

    net = __hype_gctx.__hype_vhosts[req->vhost];
    res = pcn_kmsg_get(sizeof(*res));
    BUG_ON(!res);

    if (req->vhost == 1) {
		VHOSTPKRX("process_peek_head_len_request: req->vhost=%d (%p)\n", req->vhost, net);
	}

	sock_len = khype_service_peek_head_len(net);

	if (req->vhost == 1) {
		VHOSTPKRX("process_peek_head_len_request: serviced! sock_len=%zu\n", sock_len);
	}

    res->ret = 0;
	res->sock_len = sock_len;
	res->from_pid = req->from_pid;
    res->ws = req->ws;
    pcn_kmsg_post(PCN_KMSG_TYPE_PEEK_HEAD_LEN_RESPONSE,
                                from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
}

static int handle_peek_head_len_response(struct pcn_kmsg_message *msg)
{
    peek_head_len_response_t *res = (peek_head_len_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;
    complete(&ws->pendings);

    return res->ret;
}

/* recvmsg delegation */
int khype_recvmsg_delegate(delegate_recvmsg_request_t *req,
                                                  struct msghdr *msg)
{
       delegate_recvmsg_response_t *res = NULL;
    struct remote_context *rc = NULL;
    int dst_nid = POPCORN_HOST_NID;
    struct wait_station *ws = NULL;
    int r = 0, rem;

    rc = __hype_gctx.rc;

    BUG_ON(!current);
    ws = get_wait_station(current);
    BUG_ON(!ws);

    req->ws = ws->id;
    req->from_pid = current->pid;

    req->remote_pid = rc->remote_tgids[dst_nid];
    VHOSTPKRX("sending recvmsg delegation to origin\n");
    pcn_kmsg_send(PCN_KMSG_TYPE_DELEGATE_RECVMSG_REQUEST,
                                dst_nid, req, sizeof(*req));
    res = wait_at_station(ws);
    r = res->ret; /* number of bytes read */

#if 0
       if (r != req->sock_len) {
               pcn_kmsg_done(res); //JACK
               return r;
       }
#endif
       /* copy msg data (packet) to iter */
       VHOSTPKRX("khype_recvmsg_delegate: calling copy_to_iter: len=%d, iter: type=%d, count=%d, offset=%d, nrsegs=%d\n",
                                                                               res->ret, msg->msg_iter.type, msg->msg_iter.count, msg->msg_iter.iov_offset, msg->msg_iter.nr_segs);
       barrier();
       rem = copy_to_iter(res->data, res->ret, &msg->msg_iter);

       VHOSTPKRX("khype_recvmsg_delegate: called copy_to_iter: len=%d, iter: type=%d, count=%d, offset=%d, nrsegs=%d, rem=%d\n",
                                                                               res->ret, msg->msg_iter.type, msg->msg_iter.count, msg->msg_iter.iov_offset, msg->msg_iter.nr_segs, rem);
       msg->msg_flags |= res->flags;

    pcn_kmsg_done(res);
    return r;
}

extern int khype_vhost_recvmsg_delegate(struct vhost_net *, char *, size_t, int *);
static void process_recvmsg_delegate_request(struct work_struct *work)
{
    START_KMSG_WORK(delegate_recvmsg_request_t, req, work);
    delegate_recvmsg_response_t *res;
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct vhost_net *net;
    int flags, r;

    net = __hype_gctx.__hype_vhosts[req->vhost];
       res = pcn_kmsg_get(sizeof(*res) + req->sock_len);
       BUG_ON(!res);

       if (req->vhost == 1)
       VHOSTPKRX("process_recvmsg_request: req->sock_len=%d, req->vhost=%d (%p)\n", req->sock_len, req->vhost, net);

    r = khype_vhost_recvmsg_delegate(net, res->data, req->sock_len, &flags);

    res->ret = r;
       res->flags = flags;
    res->vhost = req->vhost;
    res->from_pid = req->from_pid;
    res->ws = req->ws;
    pcn_kmsg_post(PCN_KMSG_TYPE_DELEGATE_RECVMSG_RESPONSE,
                                from_nid, res, sizeof(*res) + req->sock_len);
    END_KMSG_WORK(req);
}

static int handle_recvmsg_delegate_response(struct pcn_kmsg_message *msg)
{
    delegate_recvmsg_response_t *res = (delegate_recvmsg_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;
    complete(&ws->pendings);

    return res->ret;
}

/* tunfd delegation */

int khype_tunfd_delegate(delegate_tunfd_request_t *req)
{
       delegate_tunfd_response_t *res = NULL;
       struct remote_context *rc = NULL;
       int dst_nid = POPCORN_HOST_NID;
       struct wait_station *ws = NULL;
       int r = 0;

       VHOSTPKTX("delegate: tsk.name=%s ->mm=%p rc=%p\n", __hype_gctx.tsk->comm, __hype_gctx.tsk->mm, __hype_gctx.rc);

       rc = __hype_gctx.rc;

       BUG_ON(!current);
       ws = get_wait_station(current);
       BUG_ON(!ws);

       req->ws = ws->id;
       req->from_pid = current->pid;

       req->remote_pid = rc->remote_tgids[dst_nid];
       VHOSTPKTX("sending tunfd delegation to origin\n");
       pcn_kmsg_send(PCN_KMSG_TYPE_DELEGATE_TUNFD_REQUEST,
											dst_nid, req, sizeof(*req) + req->psize);

       VHOSTPKTX("khype_tunfd_delegate: returning to handle_tx\n");
       res = wait_at_station(ws);
       r = res->ret;

       pcn_kmsg_done(res);
       return r;
}

extern int khype_vhost_tunfd_delegate(char *, size_t, struct vhost_net *);
static void process_tunfd_delegate_request(struct work_struct *work)
{
    START_KMSG_WORK(delegate_tunfd_request_t, req, work);
    delegate_tunfd_response_t *res = pcn_kmsg_get(sizeof(*res));

    int from_nid = PCN_KMSG_FROM_NID(req);
       struct vhost_net *net;
       int r;

       net = __hype_gctx.__hype_vhosts[req->vhost];

    	VHOSTPKTX("process_tunfd_request: req->psize=%x, req->vhost=%x\n", req->psize, req->vhost);

       r = khype_vhost_tunfd_delegate(req->packet, req->psize, net);

    res->ret = r;
    res->vhost = req->vhost;

    res->from_pid = req->from_pid;
    res->ws = req->ws;
    pcn_kmsg_post(PCN_KMSG_TYPE_DELEGATE_TUNFD_RESPONSE,
                                from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
}

static int handle_tunfd_delegate_response(struct pcn_kmsg_message *msg)
{
       delegate_tunfd_response_t *res = (delegate_tunfd_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

       VHOSTPKTX("recieved delegation response r=%d\n", res->ret);

    ws->private = res;
       complete(&ws->pendings);

    return res->ret;
}


/************
 * Pophype migration - copy kvm/vcpu states
 */
/* for arch/x86/kvm/vmx.c to call (fail)
 * TODO check how arch/x86/kvm/vmx.c call a function from outside.
 */

void show_cpu_states(struct kvm_vcpu *dst_vcpu, struct kvm_vcpu *src_vcpu)
{
#if POPHYPE_MIGRATE_DEBUG
	BUG_ON(!src_vcpu);
	if (!dst_vcpu)
		dst_vcpu = src_vcpu;
	PHMIGRATEPRINTK("\n--------- %s(): vcpu states (common) start (not up-to-date) ----------\n", __func__);
	PHMIGRATEPRINTK("\t[ck] [vcpu] [old] -> [new]\n");
	PHMIGRATEPRINTK("\t[ck] [vcpu] *kvm %p -?> %p\n", dst_vcpu->kvm, src_vcpu->kvm);
#ifdef CONFIG_PREEMPT_NOTIFIERS
	PHMIGRATEPRINTK("\t[ck] [vcpu] &vcpu->preempt_notifier %p -?> %p (changed)\n", &dst_vcpu->preempt_notifier, &src_vcpu->preempt_notifier);
#endif
	PHMIGRATEPRINTK("\t[ck] [vcpu] cpu %d -?> %d\n", dst_vcpu->cpu, src_vcpu->cpu);
	PHMIGRATEPRINTK("\t[ck] [vcpu] vcpu_id %d -?> %d\n", dst_vcpu->vcpu_id, src_vcpu->vcpu_id);
#ifdef CONFIG_POPCORN_HYPE
	PHMIGRATEPRINTK("\t[ck] [vcpu] nid %d -?> %d (todo)\n", dst_vcpu->nid, src_vcpu->nid);
	PHMIGRATEPRINTK("\t[ck] [vcpu] vaddr %lx -?> %lx\n", dst_vcpu->vaddr, src_vcpu->vaddr);
#endif
	PHMIGRATEPRINTK("\t[ck] [vcpu] srcu_idx %d -?> %d (changed)\n", dst_vcpu->srcu_idx, src_vcpu->srcu_idx);
	PHMIGRATEPRINTK("\t[ck] [vcpu] mode %d -?> %d\n", dst_vcpu->mode, src_vcpu->mode);
	PHMIGRATEPRINTK("\t[ck] [vcpu] requests %lu -?> %lu\n", dst_vcpu->requests, src_vcpu->requests);
	PHMIGRATEPRINTK("\t[ck] [vcpu] guest_debug %lu -?> %lu\n", dst_vcpu->guest_debug, src_vcpu->guest_debug);

	PHMIGRATEPRINTK("\t[ck] [vcpu] pre_pcpu %d -?> %d\n", dst_vcpu->pre_pcpu, src_vcpu->pre_pcpu);
	//PHMIGRATEPRINTK("\t[ck] [vcpu] &blocked_vcpu_list %p -?> %p\n", dst_vcpu, src_vcpu);

	//PHMIGRATEPRINTK("\t[ck] [vcpu] &mutex %p -?> %p\n", dst_vcpu, src_vcpu);
	PHMIGRATEPRINTK("\t[ck] [vcpu] *run %p -?> %p\n", dst_vcpu->run, src_vcpu->run);

	PHMIGRATEPRINTK("\t[ck] [vcpu] fpu_active %d -?> %d\n", dst_vcpu->fpu_active, src_vcpu->fpu_active);
	PHMIGRATEPRINTK("\t[ck] [vcpu] guest_fpu_loaded %d -?> %d\n", dst_vcpu->guest_fpu_loaded, src_vcpu->guest_fpu_loaded);
	PHMIGRATEPRINTK("\t[ck] [vcpu] guest_xcr0_loaded %d -?> %d\n", dst_vcpu->guest_xcr0_loaded, src_vcpu->guest_xcr0_loaded);
	PHMIGRATEPRINTK("\t[ck] [vcpu] fpu_counter %c -?> %c\n", dst_vcpu->fpu_counter, src_vcpu->fpu_counter);
	//PHMIGRATEPRINTK("\t[ck] [vcpu] &wq %p -?> \n", dst_vcpu, src_vcpu);
	PHMIGRATEPRINTK("\t[ck] [vcpu] *pid %p -?> %p (fine)\n", dst_vcpu->pid, src_vcpu->pid);
	PHMIGRATEPRINTK("\t[ck] [vcpu] sigset_active %d -?> %d\n", dst_vcpu->sigset_active, src_vcpu->sigset_active);
	//PHMIGRATEPRINTK("\t[ck] [vcpu] &sigset %p -?> \n", dst_vcpu, src_vcpu);
	//PHMIGRATEPRINTK("\t[ck] [vcpu] &stat %p -?> \n", dst_vcpu, src_vcpu);
	PHMIGRATEPRINTK("\t[ck] [vcpu] halt_poll_ns %u -?> %u\n", dst_vcpu->halt_poll_ns, src_vcpu->halt_poll_ns);

#ifdef CONFIG_HAS_IOMEM
	PHMIGRATEPRINTK("\t[ck] [vcpu] mmio_needed %d -?> %d\n", dst_vcpu->mmio_needed, src_vcpu->mmio_needed);
	PHMIGRATEPRINTK("\t[ck] [vcpu] mmio_read_completed %d -?> %d\n", dst_vcpu->mmio_read_completed, src_vcpu->mmio_read_completed);
	PHMIGRATEPRINTK("\t[ck] [vcpu] mmio_is_write %d -?> %d\n", dst_vcpu->mmio_is_write, src_vcpu->mmio_is_write);
	PHMIGRATEPRINTK("\t[ck] [vcpu] mmio_cur_fragment %d -?> %d\n", dst_vcpu->mmio_cur_fragment, src_vcpu->mmio_cur_fragment);
	PHMIGRATEPRINTK("\t[ck] [vcpu] mmio_nr_fragments %d -?> %d\n", dst_vcpu->mmio_nr_fragments, src_vcpu->mmio_nr_fragments);
	//PHMIGRATEPRINTK("\t[ck] [vcpu] &mmio_fragments[KVM_MAX_MMIO_FRAGMENTS] %p -?> \n", dst_vcpu, src_vcpu);
#endif

#ifdef CONFIG_KVM_ASYNC_PF
	//PHMIGRATEPRINTK("\t[ck] [vcpu] &async_pf %p -?> \n", dst_vcpu, src_vcpu);
#endif
#ifdef CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT
	//PHMIGRATEPRINTK("\t[ck] [vcpu] &spin_loop %p -?> \n", dst_vcpu, src_vcpu);
#endif
	PHMIGRATEPRINTK("\t[ck] [vcpu] preempted %d -?> %d\n", dst_vcpu->preempted, src_vcpu->preempted);
	//PHMIGRATEPRINTK("\t[ck] [vcpu] &arch %p -?> %p\n", &dst_vcpu->arch, &src_vcpu->arch);
#if 0
	PHMIGRATEPRINTK("\t[ck] [vcpu]  -?> \n", dst_vcpu, src_vcpu);
	PHMIGRATEPRINTK("\t[ck] [vcpu]  -?> \n", dst_vcpu, src_vcpu);
	PHMIGRATEPRINTK("\t[ck] [vcpu]  -?> \n", dst_vcpu, src_vcpu);
#endif
	PHMIGRATEPRINTK("--------- vcpu->arch.mmu ----------\n");
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu %p != %p (nonsense)\n",
							 &dst_vcpu->arch.mmu, &src_vcpu->arch.mmu);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.page_fault %p == %p\n",
				dst_vcpu->arch.mmu.page_fault, src_vcpu->arch.mmu.page_fault);

	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.set_cr3 %p != %p "
		"(checking now init_kvm_tdp_mmu) [host kernel function ptr*, DONT NOT OVERWRITE] \n",
					dst_vcpu->arch.mmu.set_cr3, src_vcpu->arch.mmu.set_cr3);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.get_pdptr %p == %p\n",
					dst_vcpu->arch.mmu.get_pdptr, src_vcpu->arch.mmu.get_pdptr);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.inject_page_fault %p == %p\n",
					dst_vcpu->arch.mmu.inject_page_fault, src_vcpu->arch.mmu.inject_page_fault);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.gva_to_gpa %p != %p (checking init_kvm_tdp_mmu)\n",
					dst_vcpu->arch.mmu.gva_to_gpa, src_vcpu->arch.mmu.gva_to_gpa);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.translate_gpa %p == %p\n",
					dst_vcpu->arch.mmu.translate_gpa, src_vcpu->arch.mmu.translate_gpa);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.sync_page %p == %p\n",
					dst_vcpu->arch.mmu.sync_page, src_vcpu->arch.mmu.sync_page);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.invlpg %p == %p\n",
					dst_vcpu->arch.mmu.invlpg, src_vcpu->arch.mmu.invlpg);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.update_pte %p == %p\n",
					dst_vcpu->arch.mmu.update_pte, src_vcpu->arch.mmu.update_pte);

	PHMIGRATEPRINTK("\t[installed] dst_vcpu->arch.mmu.root_hpa 0%llx != 0x%llx "
					"(ept root)(from vcpu->arch.mmu.pae_root)\n",
					dst_vcpu->arch.mmu.root_hpa, src_vcpu->arch.mmu.root_hpa);
	PHMIGRATEPRINTK("\t[installed] dst_vcpu->arch.mmu.root_level %d != %d (will be set in init_kvm_tdp_mmu)\n",
					dst_vcpu->arch.mmu.root_level, src_vcpu->arch.mmu.root_level);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.shadow_root_level %d == %d (checking now init_kvm_tdp_mmu)\n",
					dst_vcpu->arch.mmu.shadow_root_level, src_vcpu->arch.mmu.shadow_root_level);
	PHMIGRATEPRINTK("\t[ck] dst_vcpu->arch.mmu.direct_map %d == %d\n",
					dst_vcpu->arch.mmu.direct_map, src_vcpu->arch.mmu.direct_map);
	PHMIGRATEPRINTK("\t[installed] dst_vcpu->arch.mmu.pae_root (ptr*) %p != %p (to arch.mmu.root_hpa)\n",
					dst_vcpu->arch.mmu.pae_root, src_vcpu->arch.mmu.pae_root);
	{ int i;
		for (i = 0; i < 4; ++i) {
			PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.pae_root[%d] %llx (*pae_root check retmoe)\n", i,
								dst_vcpu->arch.mmu.pae_root[i]);
		}
	}

	PHMIGRATEPRINTK("--------- vcpu->arch.mmu.base_role ----------\n");
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.base_role\n");
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.base_role.level %u %u\n",
					dst_vcpu->arch.mmu.base_role.level, src_vcpu->arch.mmu.base_role.level);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.base_role.direct %u %u\n",
					dst_vcpu->arch.mmu.base_role.direct, src_vcpu->arch.mmu.base_role.direct);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.base_role.cr4_pae %u %u\n",
					dst_vcpu->arch.mmu.base_role.cr4_pae, src_vcpu->arch.mmu.base_role.cr4_pae);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.base_role.access %u %u\n",
					dst_vcpu->arch.mmu.base_role.access, src_vcpu->arch.mmu.base_role.access);

	PHMIGRATEPRINTK("--------- vcpu->arch ----------\n");
	//vcpu->arch.regs_dirty // cpu_run rwiil reload guest states .........so my states will be gone?
	PHMIGRATEPRINTK("\t[ck] vcpu->arch.regs_dirty %x %x (bitmap, check if = 1)\n",
					dst_vcpu->arch.regs_dirty, src_vcpu->arch.regs_dirty);
	//PHMIGRATEPRINTK("\t [ck] vcpu->kvm.arch.mmu_page_hash[0] %llx %llx\n",
	//				dst_vcpu->kvm->arch.mmu_page_hash[0], src_vcpu->kvm->arch.mmu_page_hash[0]);
					// struct hlist_head mmu_page_hash[KVM_NUM_MMU_PAGES]; // Hash table of struct kvm_mmu_page.
	PHMIGRATEPRINTK("\t [ck] vcpu->kvm.arch.mmu_page_hash %p %p ([KVM_NUM_MMU_PAGES])\n",
					dst_vcpu->kvm->arch.mmu_page_hash, src_vcpu->kvm->arch.mmu_page_hash);

	{ int i;
		for (i = 0; i < 4; ++i) {
			PHMIGRATEPRINTK("\t [ck] vcpu->arch.walk_mmu->pdptrs[%d] %llx %llx\n", i,
					dst_vcpu->arch.walk_mmu->pdptrs[i], src_vcpu->arch.walk_mmu->pdptrs[i]);
		}
	}


//	PHMIGRATEPRINTK("\t [ck] vcpu->arch. %u %u\n",
//					dst_vcpu->arch., src_vcpu->arch.);
//	PHMIGRATEPRINTK("\t [ck] vcpu->arch. %u %u\n",
//					dst_vcpu->arch., src_vcpu->arch.);
	//PHMIGRATEPRINTK("\t [ck] vcpu->arch. %u %u\n",
	//				dst_vcpu->arch., src_vcpu->arch.);
	PHMIGRATEPRINTK("TODO more\n");

	PHMIGRATEPRINTK("--------- %s(): vcpu states (common) end (not up-to-date) ----------\n", __func__);
#endif
}

/*
 * Ask a target node to update their vcpu info by using this nodes's vcpu info
 * ret:
 * caller: ier vcpu on my node and invoke this func to broascast
 */
#ifdef CONFIG_POPCORN_CHECK_SANITY
//extern void pophype_dump_vmcs(void);
extern bool is_saved_vcpu;
#endif
int popcorn_update_remote_vcpu(int dst_nid, int dst_vcpu)
//struct kvm_vcpu *dst_vcpu, struct kvm_lapic_irq *irq, unsigned long *dest_map)
{
	update_vcpu_response_t *res; /* kvm_ipi_req/res */
	update_vcpu_request_t *req;
	struct remote_context *rc = current->mm->remote;
	struct wait_station *ws;
	int r = 0;
	struct kvm_vcpu *vcpu;
	//, dst_nid = popcorn_vcpuid_to_nid(dst_vcpu->vcpu_id);
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, update_vcpu_end, update_vcpu_start = ktime_get();
#endif
#if HPMIGRATION_DEBUG /* debug */
	static int cnt = 0;
	cnt++;
	printk("%s(): <%d> pophype migration to [%d] start => #%d\n",
									__func__, dst_vcpu, dst_nid, cnt);
#endif

#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!is_saved_vcpu);
#endif

	/* common */
//#ifdef CONFIG_POPCORN_CHECK_SANITY
	if (my_nid == dst_nid) {
		printk(KERN_ERR "ERROR: %s(): my_nid == dst_nid\n", __func__);
		BUG_ON(my_nid == dst_nid);
	}
//#endif
	req = kmalloc(sizeof(*req), GFP_KERNEL);
	ws = get_wait_station(current);
	BUG_ON(!req || !rc);
	req->from_pid = current->pid;
	req->ws = ws->id;

	/* customize */

	/* lock everywhere */
	atomic64_set(&gvcpu_to_nid[dst_vcpu], dst_nid);
	popcorn_update_cpu_table(dst_vcpu, dst_nid);

	/* Use req->fd to indicate which vcpu it should use */
	req->fd = vcpuid_to_fd(dst_vcpu); /* assumption: 1 vcpu on 1 node */
	vcpu = hype_node_info[my_nid][req->fd]->vcpu;
	BUG_ON(vcpu != hype_node_info[my_nid][VCPU_FD_BASE + dst_vcpu]->vcpu); /* assumption: 1 vcpu on 1 node */

	memcpy(&req->vcpu, vcpu, sizeof(*vcpu)); //////LOOKS WRONG. am I using it?
	PHMIGRATEPRINTK("%s(): ***********memcopy vcpu************** \n", __func__);
	PHMIGRATEPRINTK("%s(): ***********memcopy vcpu************** \n", __func__);
	PHMIGRATEPRINTK("%s(): ***********memcopy vcpu************** \n", __func__);
	PHMIGRATEPRINTK("%s(): TODO hardcode vcpu 1 now -> (fix it)\n", __func__);


	PHMIGRATEPRINTK("\n=========== %s(): <%d> [ck] start "
					"(this is outdated state, too late, just as refs) "
					"=================\n", __func__, current->pid);
	show_cpu_states(NULL, vcpu); // this is too late
	/* define arch/x86/include/asm/kvm_host.h */
	pophype_dump_vmcs();
	PHMIGRATEPRINTK("\n\n");

	{
		struct kvm_mp_state *mp_state = pophype_get_mp_state(vcpu->vcpu_id);
		struct kvm_regs *regs = pophype_get_regs(vcpu->vcpu_id);
		struct kvm_sregs *sregs = pophype_get_sregs(vcpu->vcpu_id);
		struct kvm_fpu *fpu = pophype_get_fpu(vcpu->vcpu_id);
		struct kvm_xcrs *xcrs = pophype_get_xcrs(vcpu->vcpu_id);
		struct kvm_lapic_state *lapic = pophype_get_lapic(vcpu->vcpu_id);
		struct kvm_xsave *xsave = pophype_get_xsave(vcpu->vcpu_id);
		struct kvm_vcpu_events *vcpu_events = pophype_get_vcpu_event(vcpu->vcpu_id);
		//struct kvm_msrs *msrs = pophype_get_msrs(); // use my which has enough memory
		struct pophype_kvm_msrs *msrs = pophype_get_msrs(vcpu->vcpu_id);

		PHMIGRATEPRINTK("[pophype] set req - get kvm_mpstate (=vcpu->arch.?)\n");
		memcpy(&req->mp_state, mp_state, sizeof(*mp_state));
		PHMIGRATEPRINTK("\t\t\t get kvm_mpstate mp_state %d (=vcpu->arch.?)\n", mp_state->mp_state);
		PHMIGRATEPRINTK("[pophype] set req - get kvm_regs (=vcpu->arch.regs)\n");
		memcpy(&req->regs, regs, sizeof(*regs));
		PHMIGRATEPRINTK("[pophype] set req - get kvm_sregs (=vcpu->arch.?)\n");
		memcpy(&req->sregs, sregs, sizeof(*sregs));
		PHMIGRATEPRINTK("[pophype] set req - get kvm_fpu (=vcpu->arch.?)\n");
		memcpy(&req->fpu, fpu, sizeof(*fpu));

		PHMIGRATEPRINTK("[pophype] set req - get kvm_xcrs\n");
		memcpy(&req->xcrs, xcrs, sizeof(*xcrs));
		PHMIGRATEPRINTK("[pophype] set req - get kvm_lapic\n");
		memcpy(&req->lapic, lapic, sizeof(*lapic));
		PHMIGRATEPRINTK("[pophype] set req - get xsave\n");
		memcpy(&req->xsave, xsave, sizeof(*xsave));
		PHMIGRATEPRINTK("[pophype] set req - get vcpu_events\n");
		memcpy(&req->vcpu_events, vcpu_events, sizeof(*vcpu_events));
		PHMIGRATEPRINTK("[pophype] set req - get msrs\n");
		memcpy(&req->msrs, msrs, sizeof(*msrs));
		PHMIGRATEPRINTK("\t\t*msrs check size %d in req %d\n", msrs->nmsrs, req->msrs.nmsrs);

		PHMIGRATEPRINTK("Jack rip ret %llx req %llx\n", regs->rip, req->regs.rip);
		PHMIGRATEPRINTK("Jack cr0 ret %llx req %llx\n", sregs->cr0, req->sregs.cr0);
		PHMIGRATEPRINTK("Jack cr3 ret %llx req %llx\n", sregs->cr3, req->sregs.cr3);


		PHMIGRATEPRINTK("DON'T GET STATES HERE (WRONG STATES). "
				"Do it in arch/x86/kvm/x86.c KVM_RET_POPHYPE_MIGRATE\n");
	}

	/* check */
	PHMIGRATEPRINTK("\n============ show ================\n");
	PHMIGRATEPRINTK("%s(): vcpu %d %p (->)\n", __func__, vcpu->vcpu_id, vcpu);
	PHMIGRATEPRINTK(" [ins] INSTALL [ck] CHECK\n");

	PHMIGRATEPRINTK("\t [ck] vcpu->arch.cr0 %lx\n", vcpu->arch.cr0);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.cr2 %lx\n", vcpu->arch.cr2);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.cr3 %lx\n", vcpu->arch.cr3);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.cr4 %lx\n", vcpu->arch.cr4);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.cr8 %lx\n", vcpu->arch.cr8);

	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic %p\n", vcpu->arch.apic);

	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mp_state %u\n", vcpu->arch.mp_state);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.ia32_misc_enable_msr %llu\n", vcpu->arch.ia32_misc_enable_msr);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.smbase %llx\n", vcpu->arch.smbase);

	{	int i = 0;
		PHMIGRATEPRINTK("\n\t vcpu->arch.regs[i] (kvm_register_write) "
						"enum kvm_reg {"
						"RAX, RCX, RDX, RBX, RSP[4] "
						"RBP RSI RDI R8 R9[9] "
						"R10 R11 R12 R13 R14 R15 RIP }\n");
		for (i = 0; i < NR_VCPU_REGS; i++) {
			PHMIGRATEPRINTK("\t vcpu->arch.regs[%d] 0x%lx\n",
										i, vcpu->arch.regs[i]);
		}
		PHMIGRATEPRINTK("\n\n");
	}

	PHMIGRATEPRINTK("------- pointers notes -----\n");
	PHMIGRATEPRINTK("\t-> [ck] vcpu->* [pointers] *kvm *run *pid \n");
	PHMIGRATEPRINTK("\t-> [ck] vcpu->arch.* [pointers] [*apic] *walk_mmu *pio_data *mce_banks\n");
	PHMIGRATEPRINTK("----------------------\n");
	PHMIGRATEPRINTK("\n");

	PHMIGRATEPRINTK("\n");
	PHMIGRATEPRINTK("\t -- [local only] arch.apic->* [local only] -- \n");
	PHMIGRATEPRINTK("\t -- [local only] arch.apic->* (CANNOT DIRECTLY CPY) [local only] -- \n");
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic->base_address %lx\n", vcpu->arch.apic->base_address);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic->sw_enabled %d\n", vcpu->arch.apic->sw_enabled);
	PHMIGRATEPRINTK("\t [ck]*** vcpu->arch.apic_base %llx\n", vcpu->arch.apic_base);
	PHMIGRATEPRINTK("\t [ck]*** arch.efer %llx\n", vcpu->arch.efer);
	//nmi*
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic->vapic_addr %llx\n", vcpu->arch.apic->vapic_addr);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic->vcpu %p (check)\n", vcpu->arch.apic->vcpu);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic->regs %p\n", vcpu->arch.apic->regs);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic->pending_events %lx\n", vcpu->arch.apic->pending_events);
	PHMIGRATEPRINTK("\n");


	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu %p\n", &vcpu->arch.mmu);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.page_fault %p\n", vcpu->arch.mmu.page_fault);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.root_hpa 0x%llx\n", vcpu->arch.mmu.root_hpa);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.walk_mmu %p\n", vcpu->arch.walk_mmu);

	PHMIGRATEPRINTK("\t [ck] vcpu->arch.exit_qualification %lx\n", vcpu->arch.exit_qualification);

	PHMIGRATEPRINTK("\t [ck] vcpu->arch.pending_external_vector %d\n", vcpu->arch.pending_external_vector);

	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.set_cr3 %p (=kvm_x86_ops->set_tdp_cr3)\n", vcpu->arch.mmu.set_cr3);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.get_pdptr %p\n", vcpu->arch.mmu.get_pdptr);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.inject_page_fault %p\n", vcpu->arch.mmu.inject_page_fault);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.gva_to_gpa %p\n", vcpu->arch.mmu.gva_to_gpa);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.translate_gpa %p\n", vcpu->arch.mmu.translate_gpa);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.sync_page %p\n", vcpu->arch.mmu.sync_page);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.invlpg %p\n", vcpu->arch.mmu.invlpg);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.update_pte %p\n", vcpu->arch.mmu.update_pte);

	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.root_hpa 0x%llx (ept root?) (from pae_root)\n", vcpu->arch.mmu.root_hpa);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.root_level %d\n", vcpu->arch.mmu.root_level);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.shadow_root_level %d ((checking now init_kvm_tdp_mmu))\n", vcpu->arch.mmu.shadow_root_level);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.direct_map %d\n", vcpu->arch.mmu.direct_map);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.pae_root %p (to root_hpa) [TODO this is a ptr, so memcpy]\n", vcpu->arch.mmu.pae_root);
	{ int i;
		for (i = 0; i < 4; ++i)
			PHMIGRATEPRINTK("\t [ck] vcpu->arch.mmu.pae_root[%d] %llx\n", i, vcpu->arch.mmu.pae_root[i]);
	}

	PHMIGRATEPRINTK("=========== show end =============\n\n");

	/* common */
	req->remote_pid = rc->remote_tgids[dst_nid];
	pcn_kmsg_send(PCN_KMSG_TYPE_UPDATE_VCPU_REQUEST,
							dst_nid, req, sizeof(*req));
	res = wait_at_station(ws);
	r = res->ret;
	pcn_kmsg_done(res);

	kfree(req);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	update_vcpu_end = ktime_get();
	dt = ktime_sub(update_vcpu_end, update_vcpu_start);
	atomic64_add(ktime_to_ns(dt), &update_vcpu_ns);
	atomic64_inc(&update_vcpu_cnt);
#endif
#if HPMIGRATION_DEBUG /* debug */
	printk("%s(): <%d> pophype migration to [%d] end => #%d\n",
									__func__, dst_vcpu, dst_nid, cnt);
#endif

	return r;
}


static void process_update_vcpu_request(struct work_struct *work)
{
    START_KMSG_WORK(update_vcpu_request_t, req, work);
    update_vcpu_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->remote_pid);
	int ret = 0, overwrite = 1;
	struct fd dst_fd;
	unsigned long v;
	struct file *filp;
	struct kvm_vcpu *dst_vcpu;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	ktime_t dt, update_vcpu_handle_end, update_vcpu_handle_start = ktime_get();
#endif
#if HPMIGRATION_DEBUG /* debug */
	static int cnt = 0;
#endif
	BUG_ON(!tsk && "No task exist");

	/* fd to kvm_vcpu struct */
	v = fget_light_tsk(tsk, req->fd, FMODE_PATH);
	dst_fd = (struct fd){(struct file *)(v & ~3),v & 3};
	filp = dst_fd.file;
	BUG_ON(!filp);
	dst_vcpu = filp->private_data;
	BUG_ON(!dst_vcpu);
	fdput(dst_fd);

#if HPMIGRATION_DEBUG /* debug */
	cnt++;
	printk("=> %s(): migrating vcpu <%d> %p start #%d\n",
			__func__, dst_vcpu->vcpu_id, dst_vcpu, cnt);
#endif

	/* lock everywhere */
	atomic64_set(&gvcpu_to_nid[dst_vcpu->vcpu_id], my_nid);

	PHMIGRATEPRINTK("\n=========== [%d] [ck] start =================\n", current->pid);
	pophype_dump_vmcs(); /* maybe not that important */
	PHMIGRATEPRINTK("\n\n");


	/* P.S. vmcs write will check host inkernel metadata like apic */
	/* Change in-kernel data */
	PHMIGRATEPRINTK("-> %s(): vcpu <%d> %p\n", __func__,
							dst_vcpu->vcpu_id, dst_vcpu);
	PHMIGRATEPRINTK("-> [ins] INSTALL [ck] CHECK\n");
	PHMIGRATEPRINTK("--------- registers ----------\n");
	// move to update_vmcs
	{	int i = 0;
		PHMIGRATEPRINTK("\n\t vcpu->arch.regs[i] (kvm_register_write) "
						"enum kvm_reg {"
						"RAX, RCX, RDX, RBX, RSP[4] "
						"RBP RSI RDI R8 R9[9] "
						"R10 R11 R12 R13 R14 R15 RIP }\n");
		for (i = 0; i < NR_VCPU_REGS; i++) {
			PHMIGRATEPRINTK("\t vcpu->arch.regs[%d] [old] 0x%lx -> [new] 0x%lx\n",
						i, dst_vcpu->arch.regs[i], req->vcpu.arch.regs[i]);
////			dst_vcpu->arch.regs[i] = req->vcpu.arch.regs[i];
		}
		PHMIGRATEPRINTK("\n\n");
	}


	PHMIGRATEPRINTK("--------- segment registers ----------\n");
	PHMIGRATEPRINTK("cs ss ds es fs gs tr ldt (dtable) gdt idt\n"); // TODO segments



	PHMIGRATEPRINTK("--------- APIC ----------\n");
	//efer*
	//nmi*
	PHMIGRATEPRINTK("\t [check] arch.apic %p != %p\n",
					dst_vcpu->arch.apic, req->vcpu.arch.apic);
	PHMIGRATEPRINTK("\t [check] arch.apic %p != %p\n",
					dst_vcpu->arch.apic, req->vcpu.arch.apic);
	PHMIGRATEPRINTK("\t [check]* arch.apic_base %llx -> %llx (out dated) (done in sregs)\n",
					dst_vcpu->arch.apic_base, req->vcpu.arch.apic_base);

	PHMIGRATEPRINTK("\t -- arch.apic->* (CANNOT DIRECTLY CPY) [local only] -- \n");
	PHMIGRATEPRINTK("\t [check] arch.apic->vapic_addr %llx -> %llx\n",
					dst_vcpu->arch.apic->vapic_addr, req->vcpu.arch.apic->vapic_addr);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic->vcpu %p ?= %p(check)\n",
						dst_vcpu->arch.apic->vcpu, req->vcpu.arch.apic->vcpu);
	PHMIGRATEPRINTK("\t-> [check] arch.apic->regs %p != %p\n",
					dst_vcpu->arch.apic->regs, req->vcpu.arch.apic->regs);
	PHMIGRATEPRINTK("\t-> [check] arch.apic->pending_events %lx -> %lx\n",
					dst_vcpu->arch.apic->pending_events, req->vcpu.arch.apic->pending_events);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic->sw_enabled %d\n", dst_vcpu->arch.apic->sw_enabled);
	PHMIGRATEPRINTK("\t [ck] vcpu->arch.apic->base_address %lx\n", dst_vcpu->arch.apic->base_address);

	PHMIGRATEPRINTK("\t-> [ins] arch.efer %llx -> %llx *** (out dated) (done in sregs)\n",
					dst_vcpu->arch.efer, req->vcpu.arch.efer);
//	dst_vcpu->arch.efer = req->vcpu.arch.efer; // testing guest efer
	PHMIGRATEPRINTK("\t-> [ins] arch.mp_state %d -> %d\n",
					dst_vcpu->arch.mp_state, req->vcpu.arch.mp_state);
	//dst_vcpu->arch.mp_state = req->vcpu.arch.mp_state;
//	dst_vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	PHMIGRATEPRINTK("\t-> [ins] arch.ia32_misc_enable_msr %llu -> %llu\n",
					dst_vcpu->arch.ia32_misc_enable_msr,
					req->vcpu.arch.ia32_misc_enable_msr);
//	dst_vcpu->arch.ia32_misc_enable_msr = req->vcpu.arch.ia32_misc_enable_msr; //tesing guest efer
	PHMIGRATEPRINTK("\t-> [check] arch.smbase %llx == %llx\n",
					dst_vcpu->arch.smbase, req->vcpu.arch.smbase);

	// TODO sregs->interrupt_bitmap


	PHMIGRATEPRINTK("\n");
	//PHMIGRATEPRINTK("\t-> [check] arch.apic->* [local only] \n");
	//PHMIGRATEPRINTK("\t-> [check] arch.apic->base_address %llx -> %llx\n",
	//				dst_vcpu->arch.apic->base_address, req->vcpu.arch.apic->base_address);
	//PHMIGRATEPRINTK("\t-> [check] arch.apic->vapic_addr %llx -> %llx\n",
	//				dst_vcpu->arch.apic->vapic_addr, req->vcpu.arch.apic->vapic_addr);
	//PHMIGRATEPRINTK("\t-> [check] arch.apic->vcpu %p != %p (check)\n",
	//				dst_vcpu->arch.apic->vcpu, req->vcpu.arch.apic->vcpu);
	//PHMIGRATEPRINTK("\t-> [check] arch.apic->regs %p != %p\n",
	//				dst_vcpu->arch.apic->regs, req->vcpu.arch.apic->regs);
	//PHMIGRATEPRINTK("\t-> [check] arch.apic->pending_events %llx -> %llx\n",
	//				dst_vcpu->arch.apic->pending_events, req->vcpu.arch.apic->pending_events);
	PHMIGRATEPRINTK("\n");


	PHMIGRATEPRINTK("------- pointers notes -----\n");
	PHMIGRATEPRINTK("\t-> [ck] vcpu->* [pointers] *kvm *run *pid \n");
	PHMIGRATEPRINTK("\t-> [ck] vcpu->arch.* [pointers] [*apic] *walk_mmu *pio_data *mce_banks\n");
	PHMIGRATEPRINTK("----------------------\n");
	PHMIGRATEPRINTK("\n");
	PHMIGRATEPRINTK("\t-> [ck] dst_vcpu->arch.walk_mmu *ptr %p != %p\n",
						dst_vcpu->arch.walk_mmu, req->vcpu.arch.walk_mmu);

	//PHMIGRATEPRINTK("\t-> [ck] dst_vcpu->arch.mmu 0x%lx != 0x%lx\n",
	//						 dst_vcpu->arch.mmu, req->vcpu.arch.mmu);
	PHMIGRATEPRINTK("\t-> [ck] dst_vcpu->arch.mmu 0x%p != 0x%p\n",
							 &dst_vcpu->arch.mmu, &req->vcpu.arch.mmu);
	PHMIGRATEPRINTK("\t-> [ck] dst_vcpu->arch.mmu.page_fault %p == %p\n",
				dst_vcpu->arch.mmu.page_fault, req->vcpu.arch.mmu.page_fault);

	PHMIGRATEPRINTK("\t-> [ck] dst_vcpu->arch.mmu.set_cr3 %p != %p (checking now init_kvm_tdp_mmu) [host kernel function ptr*, DONT NOT OVERWRITE] \n",
						dst_vcpu->arch.mmu.set_cr3, req->vcpu.arch.mmu.set_cr3);
	//PHMIGRATEPRINTK("\t-> [ins] dst_vcpu->arch.mmu.set_cr3 %p != %p (checking now init_kvm_tdp_mmu)\n",
	//					dst_vcpu->arch.mmu.set_cr3, req->vcpu.arch.mmu.set_cr3);
	//dst_vcpu->arch.mmu.set_cr3, req->vcpu.arch.mmu.set_cr3; // not important // don't set
	PHMIGRATEPRINTK("\t-> [check] dst_vcpu->arch.mmu.get_pdptr %p == %p\n",
						dst_vcpu->arch.mmu.get_pdptr, req->vcpu.arch.mmu.get_pdptr);
	PHMIGRATEPRINTK("\t-> [check] dst_vcpu->arch.mmu.inject_page_fault %p == %p\n",
						dst_vcpu->arch.mmu.inject_page_fault, req->vcpu.arch.mmu.inject_page_fault);
	PHMIGRATEPRINTK("\t-> [check] dst_vcpu->arch.mmu.gva_to_gpa %p != %p (checking init_kvm_tdp_mmu)\n",
						dst_vcpu->arch.mmu.gva_to_gpa, req->vcpu.arch.mmu.gva_to_gpa);
	PHMIGRATEPRINTK("\t-> [check] dst_vcpu->arch.mmu.translate_gpa %p == %p\n",
						dst_vcpu->arch.mmu.translate_gpa, req->vcpu.arch.mmu.translate_gpa);
	PHMIGRATEPRINTK("\t-> [check] dst_vcpu->arch.mmu.sync_page %p == %p\n",
						dst_vcpu->arch.mmu.sync_page, req->vcpu.arch.mmu.sync_page);
	PHMIGRATEPRINTK("\t-> [check] dst_vcpu->arch.mmu.invlpg %p == %p\n",
						dst_vcpu->arch.mmu.invlpg, req->vcpu.arch.mmu.invlpg);
	PHMIGRATEPRINTK("\t-> [check] dst_vcpu->arch.mmu.update_pte %p == %p\n",
						dst_vcpu->arch.mmu.update_pte, req->vcpu.arch.mmu.update_pte);

	PHMIGRATEPRINTK("\t-> [ins] dst_vcpu->arch.mmu.root_hpa 0%llx != 0x%llx (ept root)(not from vcpu->arch.mmu.pae_root)\n",
						dst_vcpu->arch.mmu.root_hpa, req->vcpu.arch.mmu.root_hpa);
////	dst_vcpu->arch.mmu.root_hpa = req->vcpu.arch.mmu.root_hpa;
	PHMIGRATEPRINTK("\t-> [ins] dst_vcpu->arch.mmu.root_level %d != %d (will be set in init_kvm_tdp_mmu)\n",
						dst_vcpu->arch.mmu.root_level, req->vcpu.arch.mmu.root_level);
////	dst_vcpu->arch.mmu.root_level = req->vcpu.arch.mmu.root_level;
	PHMIGRATEPRINTK("\t-> [check] dst_vcpu->arch.mmu.shadow_root_level %d == %d (checking now init_kvm_tdp_mmu)\n",
						dst_vcpu->arch.mmu.shadow_root_level, req->vcpu.arch.mmu.shadow_root_level);
	PHMIGRATEPRINTK("\t-> [check] dst_vcpu->arch.mmu.direct_map %d == %d\n",
						dst_vcpu->arch.mmu.direct_map, req->vcpu.arch.mmu.direct_map);
	//PHMIGRATEPRINTK("\t-> [ins] dst_vcpu->arch.mmu.pae_root %p != %p (not to arch.mmu.root_hpa)\n",
	//					dst_vcpu->arch.mmu.pae_root, req->vcpu.arch.mmu.pae_root);
////	//dst_vcpu->arch.mmu.pae_root = req->vcpu.arch.mmu.pae_root;
	/* vcpu->arch.mmu.root_hpa = __pa(vcpu->arch.mmu.pae_root); in mmu_alloc_direct_roots() */
	// overwrite
	//{ int i;
	//	for (i = 0; i < 4; ++i) {
	//		PHMIGRATEPRINTK("\t\t[ins] vcpu->arch.mmu.pae_root[%d] %llx %llx\n", i,
	//			//dst_vcpu->arch.mmu.pae_root[i], req->vcpu.arch.mmu.pae_root[i]); /* *ptr - don't use */
	//			dst_vcpu->arch.mmu.pae_root[i] = req->pae_root[i];
	//	}
	//}


	PHMIGRATEPRINTK("\t-> [install] arch.exit_qualification %lx -> %lx\n",
		dst_vcpu->arch.exit_qualification, req->vcpu.arch.exit_qualification);
////	dst_vcpu->arch.exit_qualification = req->vcpu.arch.exit_qualification;

	PHMIGRATEPRINTK("\t-> [check] arch.pending_external_vector %d -> %d\n",
						dst_vcpu->arch.pending_external_vector,
						req->vcpu.arch.pending_external_vector);

	PHMIGRATEPRINTK("--------- arch-spec registers ----------\n");
	PHMIGRATEPRINTK("1. from req->vcpu.arch.cr*\n");
	PHMIGRATEPRINTK("\t-> [ins] arch.cr0 %lx -> %lx\n",
					dst_vcpu->arch.cr0, req->vcpu.arch.cr0);
	PHMIGRATEPRINTK("\t-> [ins] arch.cr2 %lx -> %lx\n",
					dst_vcpu->arch.cr2, req->vcpu.arch.cr2);
	PHMIGRATEPRINTK("\t-> [ins] arch.cr3 %lx -> %lx\n",
					dst_vcpu->arch.cr3, req->vcpu.arch.cr3);
	PHMIGRATEPRINTK("\t-> [ins] arch.cr4 %lx -> %lx\n",
					dst_vcpu->arch.cr4, req->vcpu.arch.cr4);
	PHMIGRATEPRINTK("\t-> [ins] arch.cr8 %lx -> %lx\n",
					dst_vcpu->arch.cr8, req->vcpu.arch.cr8);
	PHMIGRATEPRINTK("\n");
	PHMIGRATEPRINTK("2. from req->sregs.cr*\n");
	PHMIGRATEPRINTK("\t-> [ins] arch.cr0 %lx -> %llx\n",
					dst_vcpu->arch.cr0, req->sregs.cr0);
	PHMIGRATEPRINTK("\t-> [ins] arch.cr2 %lx -> %llx\n",
					dst_vcpu->arch.cr2, req->sregs.cr2);
	PHMIGRATEPRINTK("\t-> [ins] arch.cr3 %lx -> %llx\n",
					dst_vcpu->arch.cr3, req->sregs.cr3);
	PHMIGRATEPRINTK("\t-> [ins] arch.cr4 %lx -> %llx\n",
					dst_vcpu->arch.cr4, req->sregs.cr4);
	PHMIGRATEPRINTK("\t-> [ins] arch.cr8 %lx -> %llx\n",
					dst_vcpu->arch.cr8, req->sregs.cr8);

	PHMIGRATEPRINTK("--- arch-spec registers: select src 2. ---\n");
	PHMIGRATEPRINTK("[rip from req %llx]\n", req->regs.rip);
	PHMIGRATEPRINTK("[cr0 from req %llx]\n", req->sregs.cr0);


	/* overwrite */
	/* vmcs write will check host inkernel metadata like apic */
	{ /* check vmcs, start to overwrite vmcs */
		struct kvm_vcpu *vcpu = hype_node_info[my_nid][req->fd]->vcpu; /* VMCS load to the right vCPU */
		struct kvm_regs *regs = &req->regs;
		struct kvm_mp_state *mp_state = &req->mp_state;
		struct kvm_sregs *sregs = &req->sregs;
		struct kvm_fpu *fpu = &req->fpu;

		struct kvm_xcrs *xcrs = &req->xcrs;
		struct kvm_lapic_state *lapic = &req->lapic;
		struct kvm_xsave *xsave = &req->xsave;
		struct kvm_vcpu_events *vcpu_events = &req->vcpu_events;
		struct pophype_kvm_msrs *msrs = &req->msrs; // ./arch/x86/include/uapi/asm/kvm.h
		//struct kvm_run* kvm_run = &req->kvm_run;

		if (overwrite) {
			//int cpu = dst_vcpu->vcpu_id; //TODO harcode
			//int cpu = 1; //TODO harcode
			int cpu = smp_processor_id(); // TODO TESTING I THINK THIS IS RIGHT cuz vmcs is per cpu and sohuld match with current cpu. Let vmx_vcpu_load to reload the current host(smp) cpu
			//int cpu = get_cpu(); // upgraded. Remember put_cpu();
			//int cpu = 1; // TODO NO NO NO we need to know which host CPU will be used...........
//			int cpu;

			PHMIGRATEPRINTK("\n[phmigrate] ---------------------------------------------\n");
			PHMIGRATEPRINTK("[phmigrate] ---------------------------------------------\n");
			PHMIGRATEPRINTK("[phmigrate] ------------- vcpu_load on host cpu %d ---------\n", cpu);
			PHMIGRATEPRINTK("[phmigrate] ---------------------------------------------\n");
			PHMIGRATEPRINTK("[phmigrate] ---------------------------------------------\n");
			PHMIGRATEPRINTK("[phmigrate] (start) ***load vmcx*** for (dst_vcpu) so that I can write (TODO cpu=hardcode)\n");
#if 1
			{ /* Remember to unlock */
				/* Since ft, I'm trying to use wrapper functions
				of kvm_arch_vcpu_load(). Testing now. */

				/// 111111
				/// 111111
				/// 111111
//				cpu = get_cpu();
				kvm_arch_vcpu_load(dst_vcpu, cpu); /* change vcpu->cpu and load vmcs*/ /* IMPORTANT: match kvm_arch_vcpu_put */
//				put_cpu();


//				/// 2222222
//				/// 2222222
//				/// 2222222
////				int _cpu;
//
//				//if (mutex_lock_killable(&vcpu->mutex))
//				//	return -EINTR;
//				BUG_ON(mutex_lock_killable(&vcpu->mutex));
//
//				cpu = get_cpu();
////				_cpu = get_cpu();
//				preempt_notifier_register(&vcpu->preempt_notifier);
//				kvm_arch_vcpu_load(dst_vcpu, cpu);
////				put_cpu();
			}
#else

			BUG_ON(vcpu_load(dst_vcpu));
#endif
			PHMIGRATEPRINTK("[phmigrate] (done) load vmcx for (dst_vcpu) so that I can write (TODO cpu=hardcode)\n");
			//if it works, move pophype_update_vmcs related to cpu to here
			//PHMIGRATEPRINTK("[phmigrate] (mp_state overwrite)\n");
			//vcpu->arch.mp_state = KVM_MP_STATE_UNINITIALIZED;
			//vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE; // will be overwritten by kvm_xxx_set_mpstate() with this mp_state->mp_state
			PHMIGRATEPRINTK("[phmigrate] will overwrite mp_state->mp_state to %d "
							"(expect 0: RUNNABLE 1: UNINITIALIZED 3: HALTED (for FT))\n",
							 mp_state->mp_state);
		}


		PHMIGRATEPRINTK("\n ---------------- 2nd dump_vmcs start ----------------------\n");
		pophype_dump_vmcs(); /* maybe not that important */
		PHMIGRATEPRINTK("---------------- 2nd dump_vmcs end ----------------------\n\n");

		PHMIGRATEPRINTK("\n ---------------- before overwrite start ----------------------\n");
		show_cpu_states(dst_vcpu, &req->vcpu);
		PHMIGRATEPRINTK("\n ---------------- before overwrite end ----------------------\n");


		if (overwrite) { /* check vmcs */
			int r = 0;

			/* keep overwriting */
			PHMIGRATEPRINTK(" --- keep updateing current vmcs <%d> ---\n", vcpu->vcpu_id);
			/* kvm_arch_vcpu_ioctl_set_*() */
			PHMIGRATEPRINTK("[pophype] get from req - set [kvm_sregs] (=vcpu->arch.?)\n");
			//PHMIGRATEPRINTK("[pophype] get from req - set kvm_sregs (=vcpu->arch.?) [[[SKIP]]]\n");
			r = kvm_arch_vcpu_ioctl_set_sregs(vcpu, sregs); // ./virt/kvm/kvm_main.c
			WARN_ON(r);

			PHMIGRATEPRINTK("[pophype] get from req - set [kvm_regs] (=vcpu->arch.?)\n");
			kvm_arch_vcpu_ioctl_set_regs(vcpu, regs); // ./virt/kvm/kvm_main.c

			PHMIGRATEPRINTK("[pophype] get from req - set [msr]\n");
			PHMIGRATEPRINTK("\t\t*msrs check size %d in req %d\n", msrs->nmsrs, req->msrs.nmsrs);
			r = pophype_msr_io(vcpu, msrs, pophype_do_set_msr, 0); // KVM_SET_MSRS // TODO POPHYPE and argp
			WARN_ON(r);
//			struct kvm_msrs _msrs;
//			r = pophype_msr_io(vcpu, &_msrs, pophype_do_set_msr, 0); // KVM_SET_MSRS // TODO POPHYPE and argp
//			WARN_ON(r);
//			memcpy(&req->msrs, &_msrs, sizeof(struct kvm_msrs));
//			PHMIGRATEPRINTK("_msrs check size %d in req %d\n", _msrs.nmsrs, req->msrs.nmsrs);

			PHMIGRATEPRINTK("[pophype] get from req - set [xcrs]\n");
			r = pophype_vcpu_ioctl_x86_set_xcrs(vcpu, xcrs); // KVM_SET_XCRS
//			WARN_ON(r);

			PHMIGRATEPRINTK("[pophype] get from req - set kvm_mpstate (=vcpu->arch.?)\n");
			kvm_arch_vcpu_ioctl_set_mpstate(vcpu, mp_state); // ./virt/kvm/kvm_main.c

			PHMIGRATEPRINTK("[pophype] get from req - set [lapic]\n");
			r = pophype_vcpu_ioctl_set_lapic(vcpu, lapic); // KVM_SET_LAPIC
			WARN_ON(r);

			PHMIGRATEPRINTK("[pophype] get from req - set kvm_fpu (=vcpu->arch.?)\n");
			kvm_arch_vcpu_ioctl_set_fpu(vcpu, fpu); // ./virt/kvm/kvm_main.c

			PHMIGRATEPRINTK("[pophype] get from req - set [xsave]\n");
			r = pophype_vcpu_ioctl_x86_set_xsave(vcpu, xsave); // KVM_SET_XSAVE
			WARN_ON(r);

			PHMIGRATEPRINTK("[pophype] get from req - set [vcpu_events]\n");
			r = pophype_vcpu_ioctl_x86_set_vcpu_events(vcpu, vcpu_events); //KVM_SET_VCPU_EVENTS
			WARN_ON(r);

			//PHMIGRATEPRINTK("[pophype] get from req - set [kvm_run]\n");
			//memcpy(vcpu->run, kvm_run, sizeof(struct kvm_run));

			PHMIGRATEPRINTK(" --- end ---\n");
		}

		PHMIGRATEPRINTK("[reg] rax 0x%lx rbx 0x%lx rcx 0x%lx rdx 0x%lx rsi 0x%lx "
				"rdi 0x%lx rsp 0x%lx rbp 0x%lx    "
#ifdef CONFIG_X86_64
				"r8 0x%lx r9 0x%lx r10 0x%lx"
#endif
				"\n",
				kvm_register_read(vcpu, VCPU_REGS_RAX),
				kvm_register_read(vcpu, VCPU_REGS_RBX),
				kvm_register_read(vcpu, VCPU_REGS_RCX),
				kvm_register_read(vcpu, VCPU_REGS_RDX),
				kvm_register_read(vcpu, VCPU_REGS_RSI),
				kvm_register_read(vcpu, VCPU_REGS_RDI),
				kvm_register_read(vcpu, VCPU_REGS_RSP),
				kvm_register_read(vcpu, VCPU_REGS_RBP),
#ifdef CONFIG_X86_64
				kvm_register_read(vcpu, VCPU_REGS_R8),
				kvm_register_read(vcpu, VCPU_REGS_R9),
				kvm_register_read(vcpu, VCPU_REGS_R10)
#endif
				);
	} // end over write

	PHMIGRATEPRINTK("\n ---------------- after overwrite start ----------------------\n");
	show_cpu_states(dst_vcpu, &req->vcpu);
	PHMIGRATEPRINTK("\n ---------------- after overwrite end ----------------------\n");

	PHMIGRATEPRINTK("============== [%d] [ck] end =================\n\n", current->pid);

#if 1 // teseting
	if (overwrite) {
		/* Testing: using wrapper functions of kvm_arch_vcpu_put() */

		// 11111
		kvm_arch_vcpu_put(dst_vcpu); /* IMPORTANT: match kvm_arch_vcpu_load() */


		// 222222
		//vcpu_put(dst_vcpu);
	}
#else
#endif

	res->ret = ret;
    res->from_pid = req->from_pid;
	res->ws = req->ws;
	pcn_kmsg_post(PCN_KMSG_TYPE_UPDATE_VCPU_RESPONSE,
					from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);

#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	update_vcpu_handle_end = ktime_get();
	dt = ktime_sub(update_vcpu_handle_end, update_vcpu_handle_start);
	atomic64_add(ktime_to_ns(dt), &update_vcpu_handle_ns);
	atomic64_inc(&update_vcpu_handle_cnt);
#endif

	popcorn_show_gcpu_table();
#if HPMIGRATION_DEBUG /* debug */
	printk("=> %s(): migrating vcpu <%d> %p end #%d\n",
				__func__, dst_vcpu->vcpu_id, dst_vcpu, cnt);
#endif
//////////// testing kvm_vcpu_ioctl /// migration not performed yet
#if 0 //debug
{
int j;
struct kvm_sregs kvm_sregs;
for (j=0;j<30;j++) {
printk("\t\t%s(): killme test vcpu <%d> %p start #%d\n",
				__func__, dst_vcpu->vcpu_id, dst_vcpu, j);}

printk("\t\t%s(): killme test vcpu <%d> %p save vcpu states - 0\n",
				__func__, dst_vcpu->vcpu_id, dst_vcpu);
pophype_save_vcpu_states(dst_vcpu);
printk("\t\t%s(): killme test vcpu <%d> %p test get kvm_sregs - 1\n",
				__func__, dst_vcpu->vcpu_id, dst_vcpu);
j = kvm_arch_vcpu_ioctl_get_sregs(dst_vcpu, &kvm_sregs);
printk("\t\t%s(): killme test vcpu <%d> %p test get kvm_sregs - 2\n",
				__func__, dst_vcpu->vcpu_id, dst_vcpu);

for (j=0;j<20;j++) {
printk("\t\t%s(): killme test vcpu <%d> %p end (states loaded, !migrated) #%d\n",
				__func__, dst_vcpu->vcpu_id, dst_vcpu, j);}
}
#endif
/////
}

static int handle_update_vcpu_response(struct pcn_kmsg_message *msg)
{
	update_vcpu_response_t *res = (update_vcpu_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;

	complete(&ws->pendings);
	PHMIGRATEPRINTK("-> %s():\n", __func__);

	popcorn_show_gcpu_table();

	/* Going to migration */
    return res->ret;
}


/**************************************************************************
 * Pophpye net optimization - msghdr
 */
/* Gusrt conver to msg-transfferable data struct */
struct pophype_msghdr *create_pmsghdr_from_msghdr(struct msghdr *msg, int *pmsghdr_size)
{
	struct pophype_msghdr *pmsghdr = kmalloc(sizeof(*pmsghdr), GFP_ATOMIC);
	BUG_ON(!pmsghdr);

	pmsghdr->msg_namelen = msg->msg_namelen;
	if (msg->msg_name) // && msg->msg_namelen)
		memcpy(&pmsghdr->msg_name, msg->msg_name, msg->msg_namelen); //
	else {
		POP_PK("%s(): debug msg->msg_name %s\n",
				__func__, msg->msg_name ? "O" : "X");
		//printk("%s(): debug msg->msg_name %s\n", __func__, msg->msg_name);
	}
	pmsghdr->msg_flags = msg->msg_flags;

	BUG_ON(msg->msg_iter.count != msg->msg_iter.iov->iov_len); /* what's this */

	/* struct iov_iter msg_iter; */
	pmsghdr->type = msg->msg_iter.type;
	pmsghdr->iov_offset = msg->msg_iter.iov_offset;
	pmsghdr->count = msg->msg_iter.count;
	pmsghdr->nr_segs = msg->msg_iter.nr_segs;
	pmsghdr->iov_len = msg->msg_iter.iov->iov_len;
	if (msg->msg_iter.iov->iov_len) {
		/* From user */
		BUG_ON(msg->msg_iter.iov->iov_len > POPHYPE_MSGHDR_BUF_SIZE); /* We constraint this */
		BUG_ON(copy_from_user(pmsghdr->iov_base,
				msg->msg_iter.iov->iov_base, msg->msg_iter.iov->iov_len));
	} else {
		printk(KERN_ERR "%s(): !len\n", __func__);
		goto out;
	}

	/* return real struct size with real payload */
	//*pmsghdr_size = sizeof(struct pophype_msghdr) - (int)PAGE_SIZE
	*pmsghdr_size = sizeof(struct pophype_msghdr) - POPHYPE_MSGHDR_BUF_SIZE
								+ msg->msg_iter.iov->iov_len;
	//VHOSTNET_OPTIMIZE_PK("%s(): pmsghdr_size %d "
	//			"sizeof(struct pophype_msghdr) %lu - (int)PAGE_SIZE (%lu) + "
	//			"msg->msg_iter.iov->iov_len (%lu)\n",
	//			__func__, *pmsghdr_size,
	//			sizeof(struct pophype_msghdr),
	//			PAGE_SIZE, msg->msg_iter.iov->iov_len);


#if 0
	{ // guest kernel
		struct kernel_msghdr kmsghdr = {
			.msg_name = NULL,
			.msg_namelen = 0,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = MSG_DONTWAIT,
		};
		int len;
		struct iov_iter *from;
		ssize_t n;
		struct virtio_net_hdr gso = { 0 };
		// ck local 2
		printk("====== [remote (local intact data) start] ======\n");

		len = msg->msg_iter.count;
		printk("[ck] msg->msg_iter.nr_segs %lu\n", msg->msg_iter.nr_segs);

		from = &msg->msg_iter;

		// ONLY-1 can work
		printk("1. (usr) Do the same (copy from user) type %d\n", msg->msg_iter.type);
		n = copy_from_iter(&gso, sizeof(gso), from);
		BUG_ON(n != sizeof(gso));
		printk("[ck] copy_from_iter -> "
				"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
										//tun16_to_cpu(tun, gso.hdr_len), len);
										be16_to_cpu((__force __be16)gso.hdr_len),
										le16_to_cpu((__force __le16)gso.hdr_len),
										len);

		printk("2. (usr) memcpy type %d\n", msg->msg_iter.type);
		memcpy(&gso, from, sizeof(gso));
		printk("[ck] memcpy -> "
				"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
										//tun16_to_cpu(tun, gso.hdr_len), len);
										be16_to_cpu((__force __be16)gso.hdr_len),
										le16_to_cpu((__force __le16)gso.hdr_len),
										len);


		/******* BUG dont use this********/
		msg->msg_iter.type = ITER_KVEC; // im in kern // [Pophype]
//////		printk("3. (kern) Do the same (copy from user) type %d\n", msg->msg_iter.type);
//////		n = copy_from_iter(&gso, sizeof(gso), from);
//////		BUG_ON(n != sizeof(gso));
//////		printk("[ck] copy_from_iter -> "
//////				"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
//////										//tun16_to_cpu(tun, gso.hdr_len), len);
//////										be16_to_cpu((__force __be16)gso.hdr_len),
//////										le16_to_cpu((__force __le16)gso.hdr_len),
//////										len);
		printk("4. (kernel) memcpy type %d\n", msg->msg_iter.type);
		memcpy(&gso, from, sizeof(gso));
		printk("[ck] memcpy -> "
				"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
										//tun16_to_cpu(tun, gso.hdr_len), len);
										be16_to_cpu((__force __be16)gso.hdr_len),
										le16_to_cpu((__force __le16)gso.hdr_len),
										len);
		printk("[thought] I think kvaddr may be a problem to copy_from_iter(usr) 3.4.\n");
		printk("=====================================\n");


	}
#endif
	return pmsghdr;
out:
	if (pmsghdr)
		kfree(pmsghdr);
	return NULL;
}

//struct msghdr {
//    void        *msg_name;  /* ptr to socket address structure */
//    int     msg_namelen;    /* size of socket address structure */
//    struct iov_iter msg_iter;   /* data */
//    void        *msg_control;   /* ancillary data */
//    __kernel_size_t msg_controllen; /* ancillary data buffer length */
//    unsigned int    msg_flags;  /* flags on received message */
//    struct kiocb    *msg_iocb;  /* ptr to iocb for async requests */
//};
//
//struct pophype_msghdr {
//    char msg_name[128];
//    int msg_namelen; //128
//    struct iov_iter msg_iter;   /* data */
//    //void        *msg_control;   /* ancillary data */
//    //__kernel_size_t msg_controllen; /* ancillary data buffer length */
//    unsigned int    msg_flags;
//    //struct kiocb    *msg_iocb;
//};

#include <linux/socket.h>
void guest_delegate_net_msg_tx_hypercall(struct sock *sk,
							struct msghdr *msg, size_t size)
{
	//struct tcp_sock *tp = tcp_sk(sk); // TODO include // TODO get more info from sk
	struct pophype_msghdr *pmsghdr;
	int pmsghdr_size; /* real size to transffer */

	pmsghdr = create_pmsghdr_from_msghdr(msg, &pmsghdr_size);
	VHOSTNET_OPTIMIZE_PK("%s(): START (guest vanilla) msghdr size %lu "
						"pmsghdr_size(new my dynamic msg size) %d\n",
								__func__, size, pmsghdr_size);

	// TODO here I need pmsghdr

	kvm_hypercall2(KVM_HC_POPHYPE_NET_MSG_DELEGATE,
					(unsigned long)pmsghdr, pmsghdr_size);
	kfree(pmsghdr);
}

//debug
void create_msghdr_from_pmsghdr(struct kernel_msghdr *kmsg, struct pophype_msghdr *pmsghdr);
//!debug
void delegate_net_msg_tx(struct pophype_msghdr __user *pmsghdr, int pmsghdr_size)
//struct sock *sk,
{
	delegate_net_msg_tx_request_t *req;
	delegate_net_msg_tx_response_t *res;
	struct wait_station *ws;
	struct remote_context *rc = current->mm->remote;
	int r, dst_nid = 0; /* delegation to origin */

    int req_size = sizeof(*req);

	unsigned long gpa, gfn, ofs, pmsghdr_hva;
	struct kvm_translation tr;
	int my_cpu = my_nid; // TODO HACK but this is puzzlehype
	int fd = my_cpu + VCPU_FD_BASE;

	unsigned long target_gva = (unsigned long)pmsghdr;


	VHOSTNET_OPTIMIZE_PK("%s(): START\n", __func__);

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
	/* Convert skb from guest to host first */
	/* gva -> gspa */
	tr.linear_address = (unsigned long)target_gva;
	kvm_arch_vcpu_ioctl_translate(
				hype_node_info[my_nid][fd]->vcpu, &tr);
	gpa = tr.physical_address;

	/* host - gpa -> gfn */
    gfn = gpa >> PAGE_SHIFT;
    ofs = gpa % PAGE_SIZE;
    pmsghdr_hva = kvm_vcpu_gfn_to_hva(
                hype_node_info[my_nid][fd]->vcpu, gfn);
	pmsghdr_hva += ofs;

	VHOSTNET_OPTIMIZE_PK("(host requester) %s(): (guest<%d>) START "
			"msg(target_gva) %p gpa 0x%lx "
			"pmsghdr_hva 0x%lx (void*)pmsghdr_hva %p "
			"pmsghdr_size %d (from user->hypercall->)\n",
			__func__, my_cpu, pmsghdr, gpa, pmsghdr_hva, (void*)pmsghdr_hva,
			pmsghdr_size);

    req = kmalloc(sizeof(*req), GFP_KERNEL);

	//#################################
	//#################################
	/* common msg */
	//req = kmalloc(sizeof(*req), GFP_KERNEL);
	ws = get_wait_station(current);
	BUG_ON(!req || !rc);
	req->from_pid = current->pid;
	req->ws = ws->id;
	//req->->pmsghdr;
	/* pophype specifi */
	req->fd = vcpuid_to_fd(my_cpu);
	//#################################
	//#################################

	VHOSTNET_OPTIMIZE_PK("%s(): TEST1\n", __func__);
	BUG_ON(copy_from_user(&req->pmsghdr, (void*)pmsghdr_hva, pmsghdr_size)); // from user buff
	VHOSTNET_OPTIMIZE_PK("%s(): TEST2\n", __func__);

	req_size = sizeof(*req); /* using all size now. Re-calculate to optimize */
	// req_size - sizeof(pophype_msghdr) + pmsghdr_size; // optimized version - teset it


	VHOSTNET_OPTIMIZE_PK("[ck] %s(): pmsghdr.count %lu .nr_segs %lu .iov_offset %lu\n",
						__func__,
						req->pmsghdr.count,
						req->pmsghdr.nr_segs,
						req->pmsghdr.iov_offset);
#if 0
	{
		//ssize_t n;
		//struct virtio_net_hdr gso = { 0 };
		//struct iov_iter *from = &req->pmsghdr.msg_iter;
		//printk("[ck] test\n");
		//printk("1. (usr) Do the same (copy from user) type %d\n", kmsghdr.msg_iter.type);
		//n = copy_from_iter(&gso, sizeof(gso), from);
		//BUG_ON(n != sizeof(gso));
		struct kernel_msghdr kmsghdr = {
			.msg_name = NULL,
			.msg_namelen = 0,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = MSG_DONTWAIT,
		};
		int len;
		struct iov_iter *from;
		ssize_t n;
		struct virtio_net_hdr gso = { 0 };
		// ck local 1
		create_msghdr_from_pmsghdr(&kmsghdr, &req->pmsghdr);
		// ck local 2

		len = kmsghdr.msg_iter.count;
		printk("[ck] kmsghdr.msg_iter.nr_segs %lu\n", kmsghdr.msg_iter.nr_segs);

		from = &kmsghdr.msg_iter;

		printk("====== [remote (local restore) start] ======\n");
		printk("1. (usr) Do the same (copy from user) type %d\n", kmsghdr.msg_iter.type);
		n = copy_from_iter(&gso, sizeof(gso), from);
		BUG_ON(n != sizeof(gso));
		printk("[ck] copy_from_iter -> "
				"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
										//tun16_to_cpu(tun, gso.hdr_len), len);
										be16_to_cpu((__force __be16)gso.hdr_len),
										le16_to_cpu((__force __le16)gso.hdr_len),
										len);

		printk("2. (usr) memcpy type %d\n", kmsghdr.msg_iter.type);
		memcpy(&gso, from, sizeof(gso));
		printk("[ck] memcpy -> "
				"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
										//tun16_to_cpu(tun, gso.hdr_len), len);
										be16_to_cpu((__force __be16)gso.hdr_len),
										le16_to_cpu((__force __le16)gso.hdr_len),
										len);

		kmsghdr.msg_iter.type = ITER_KVEC; // im in kern // [Pophype]
		printk("3. (kern) Do the same (copy from user) type %d\n", kmsghdr.msg_iter.type);
		n = copy_from_iter(&gso, sizeof(gso), from);
		BUG_ON(n != sizeof(gso));
		printk("[ck] copy_from_iter -> "
				"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
										//tun16_to_cpu(tun, gso.hdr_len), len);
										be16_to_cpu((__force __be16)gso.hdr_len),
										le16_to_cpu((__force __le16)gso.hdr_len),
										len);

		printk("4. (kernel) memcpy type %d\n", kmsghdr.msg_iter.type);
		memcpy(&gso, from, sizeof(gso));
		printk("[ck] memcpy -> "
				"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
										//tun16_to_cpu(tun, gso.hdr_len), len);
										be16_to_cpu((__force __be16)gso.hdr_len),
										le16_to_cpu((__force __le16)gso.hdr_len),
										len);
		printk("[thought] I think kvaddr may be a problem to copy_from_iter(usr) 3.4.\n");
		printk("=====================================\n");


		kfree(kmsghdr.msg_iter.iov->iov_base);
		kfree(kmsghdr.msg_iter.iov);

	}
#endif

	VHOSTNET_OPTIMIZE_PK("%s(): =>\n\n", __func__);
    /* common */
    req->remote_pid = rc->remote_tgids[dst_nid];
	pcn_kmsg_send(PCN_KMSG_TYPE_DELEGATE_NET_MSG_TX_REQUEST,
									dst_nid, req, req_size);
    res = wait_at_station(ws);
    r = res->ret;
    pcn_kmsg_done(res);

    kfree(req);
}


void create_msghdr_from_pmsghdr(struct kernel_msghdr *kmsg, struct pophype_msghdr *pmsghdr)
{
//	VHOSTNET_OPTIMIZE_PK("\t %s(): ck0 \n", __func__);
	//kmsg->msg_namelen = kmsg->msg_namelen;
	kmsg->msg_name = kmalloc(128, GFP_KERNEL);
	BUG_ON(!kmsg->msg_name);
	//memcpy(kmsg->msg_name, &pmsghdr->msg_name, kmsg->msg_name, 128); //
	//kfree(kmsg->msg_name);
	//kmsg->msg_name = NULL;
	kmsg->msg_flags = pmsghdr->msg_flags; // handle_tx sets MSG_DONTWAIT

	/* struct iov_iter msg_iter; */
	kmsg->msg_iter.type = pmsghdr->type | ITER_KVEC; // @!!!!!!!!!!!!!!!!! WRITE (guest) | ITER_KVEC 0919/////
	kmsg->msg_iter.iov_offset = pmsghdr->iov_offset;
	kmsg->msg_iter.count = pmsghdr->count;
	kmsg->msg_iter.nr_segs = pmsghdr->nr_segs;

	kmsg->msg_iter.iov = kmalloc(sizeof(*kmsg->msg_iter.iov), GFP_KERNEL);
	BUG_ON(!kmsg->msg_iter.iov);
	kmsg->msg_iter.iov->iov_len = pmsghdr->iov_len;
	kmsg->msg_iter.iov->iov_base =
			kmalloc(kmsg->msg_iter.iov->iov_len, GFP_KERNEL);
	BUG_ON(!kmsg->msg_iter.iov->iov_base);
	memcpy(kmsg->msg_iter.iov->iov_base, pmsghdr->iov_base, pmsghdr->iov_len);
}

#include <linux/net.h>
//extern struct socket *pophype_origin_host_tun_sock;
struct socket *pophype_origin_host_tun_sock;
static void process_delegate_net_msg_tx_request(struct work_struct *work)
{
    START_KMSG_WORK(delegate_net_msg_tx_request_t, req, work);
    delegate_net_msg_tx_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->remote_pid);
	int ret = 0;
	struct fd dst_fd;
	unsigned long v;
	struct file *filp;
	//struct kvm_vcpu *dst_vcpu;
	struct kvm_vcpu *vcpu;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	//ktime_t dt, delegate_skb_tx_handle_end, delegate_skb_tx_handle_start = ktime_get();
#endif
#if HPMIGRATION_DEBUG /* debug */
	static int cnt = 0;
#endif
	struct kernel_msghdr kmsghdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_control = NULL,
        .msg_controllen = 0,
        //.msg_flags = MSG_DONTWAIT, /* guest kernel uses this */
        //.msg_flags = 0,
    };

	BUG_ON(!tsk && "No task exist");
	VHOSTNET_OPTIMIZE_PK("\n=> [*] %s():\n", __func__);

    v = fget_light_tsk(tsk, req->fd, FMODE_PATH);
    dst_fd = (struct fd){(struct file *)(v & ~3),v & 3};
    VHOSTNET_OPTIMIZE_PK("%s(): struct fd & dst_fd %p\n",
									__func__, (void *)&dst_fd);
    filp = dst_fd.file;
    BUG_ON(!filp); /* check run.sh lkvm argv
                        highly likely you don't have enough CPU online */
    vcpu = filp->private_data;
    BUG_ON(!vcpu);
    fdput(dst_fd);

	VHOSTNET_OPTIMIZE_PK("\t %s(): create msg_hdr and inject it START\n", __func__);
	//############################################
	create_msghdr_from_pmsghdr(&kmsghdr, &req->pmsghdr);
	// = create_skb_from_pskb(&req->pskb);
	VHOSTNET_OPTIMIZE_PK("\t %s(): create msg_hdr and inject it DONE\n", __func__);


	{
		int err; //, size = 4096; // TODO
		struct socket *sock = pophype_origin_host_tun_sock; //TODO
		int len = kmsghdr.msg_iter.count;
		BUG_ON(!sock);
		//int ret = tun_sendmsg(sock, kmsghdr, size); // private

		//printk("TODO (major) len %d (should be the same in guest msghdr) "
		//											"sock %p\n", len, sock);
		//printk("[*]self testing bf actually doing\n");
		printk("[*] sk %p [cmp] [msg=kmsghdr] "
					"msg->msg_namelen %d (blocks) msg->msg_controllen %lu msg->msg_flags 0x%x "
					"msg.msg_iter.nr_segs %lu msg.msg_iter.count %lu "
					"msg.msg_iter.iov_offset %lu "
					"msg.msg_iter.type %d "
					"msg.msg_iter.iov %p "
					"msg.msg_iter.iov->iov_base _%p_ "
					"msg.msg_iter.iov->iov_len [[[%lu]]] "
					"\n",
					sock,
					kmsghdr.msg_namelen, kmsghdr.msg_controllen, kmsghdr.msg_flags,
					kmsghdr.msg_iter.nr_segs, kmsghdr.msg_iter.count,
					kmsghdr.msg_iter.iov_offset, kmsghdr.msg_iter.type,
					kmsghdr.msg_iter.iov,
					kmsghdr.msg_iter.iov->iov_base,
					kmsghdr.msg_iter.iov->iov_len);


#if 0
		{
			ssize_t n;
			struct iov_iter *from = &kmsghdr.msg_iter;
			struct virtio_net_hdr gso = { 0 };
			printk("====== [origin (remote) start] ======\n");
			printk("1. (usr) Do the same (copy from user) type %d\n", kmsghdr.msg_iter.type);
			// iov_offset, count, nr_segs, iov fields of the iterator
			n = copy_from_iter(&gso, sizeof(gso), from);
			// iov_offset, count, nr_segs, iov fields of the iterator
			BUG_ON(n != sizeof(gso));
			printk("[ck] copy_from_iter -> "
					"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
											//tun16_to_cpu(tun, gso.hdr_len), len);
											be16_to_cpu((__force __be16)gso.hdr_len),
											le16_to_cpu((__force __le16)gso.hdr_len),
												len);

			printk("2. (usr) memcpy type %d\n", kmsghdr.msg_iter.type);
			memcpy(&gso, from, sizeof(gso));
			printk("[ck] memcpy -> "
					"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
											//tun16_to_cpu(tun, gso.hdr_len), len);
											be16_to_cpu((__force __be16)gso.hdr_len),
											le16_to_cpu((__force __le16)gso.hdr_len),
											len);

			kmsghdr.msg_iter.type = ITER_KVEC; // im in kern // [Pophype]
			printk("3. (kern) Do the same (copy from user) type %d\n", kmsghdr.msg_iter.type);
			n = copy_from_iter(&gso, sizeof(gso), from);
			BUG_ON(n != sizeof(gso));
			printk("[ck] copy_from_iter -> "
					"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
											//tun16_to_cpu(tun, gso.hdr_len), len);
											be16_to_cpu((__force __be16)gso.hdr_len),
											le16_to_cpu((__force __le16)gso.hdr_len),
											len);

			printk("4. (kernel) memcpy type %d\n", kmsghdr.msg_iter.type);
			memcpy(&gso, from, sizeof(gso));
			printk("[ck] memcpy -> "
					"tun16_to_cpu(tun, gso.hdr_len) be %d le %d > len %d (WRONG)\n",
											//tun16_to_cpu(tun, gso.hdr_len), len);
											be16_to_cpu((__force __be16)gso.hdr_len),
											le16_to_cpu((__force __le16)gso.hdr_len),
											len);
			printk("[thought] I think kvaddr may be a problem to copy_from_iter(usr) 3.4.\n");
			printk("=====================================\n");
		}
#endif

		//10/1 check handle_tx() in drivers/vhost/net.c
		//iov_iter_advance(&msg.msg_iter, hdr_size);
		//err = sock->ops->sendmsg(sock, (struct msghdr)&kmsghdr, len);
		err = sock->ops->sendmsg(sock, (struct msghdr*)&kmsghdr, len);
		if (!err)
			printk("DONE (JUST G  O      H  O  M  E!!!!)\n");
		else
			printk("[dbg] CURRENT PROBLEM - here %d (check err #)\n", err);
		/* release */
		kfree(kmsghdr.msg_name);
//		VHOSTNET_OPTIMIZE_PK("\t %s(): free name\n", __func__);
		kfree(kmsghdr.msg_iter.iov->iov_base);
//		VHOSTNET_OPTIMIZE_PK("\t %s(): free iov->iov_base\n", __func__);
		kfree(kmsghdr.msg_iter.iov);
//		VHOSTNET_OPTIMIZE_PK("\t %s(): free iov\n", __func__);
	}
	// check handle tx or tun_send
	//skb = create_skb_from_pskb(&req->pskb);
	//netif_rx_ni(skb); /* Free skb */


	VHOSTNET_OPTIMIZE_PK("%s(): remote this handshaking ->\n\n", __func__);
    res->ret = ret;
    res->from_pid = req->from_pid;
    res->ws = req->ws;
    pcn_kmsg_post(PCN_KMSG_TYPE_DELEGATE_NET_MSG_TX_RESPONSE,
								from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);

}


static int handle_delegate_net_msg_tx_response(struct pcn_kmsg_message *msg)
{
	delegate_net_msg_tx_response_t *res = (delegate_net_msg_tx_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

	VHOSTNET_OPTIMIZE_PK("-> %s(): remote this handshaking\n", __func__);
	ws->private = res;
	complete(&ws->pendings);

    //return res->ret;
	return 0;
}



/****
 * Pophype network optimization
 * Notes:
 *		skb->qlen = how many sk_buff for this network package
 */

struct pophype_skb* guest_skb_to_pophype_skb(struct sk_buff *skb)
{
	struct pophype_skb *pskb;
    int headerlen;
    int head_data_len;
    int pskb_size;

	VHOSTNET_OPTIMIZE_PK("%s(): START\n", __func__);

    headerlen = skb_headroom(skb);
    head_data_len = headerlen + skb->len;
    pskb_size = head_data_len + sizeof(*pskb);

    pskb = kmalloc(pskb_size, GFP_ATOMIC);
	BUG_ON(!pskb);

	VHOSTNET_OPTIMIZE_PK("(guest) %s(): create pophype_skb pskb %p pskb_size %d"
						"[check] skb->len %u ->data_len %u\n",
						__func__, pskb, pskb_size, skb->len, skb->data_len);
	VHOSTNET_OPTIMIZE_PK("\t\t(guest) %s(): BUG_ON{"
			"offset(skb->csum_start %d - (skb->data %lu - skb->head %lu)(%lu))) [[[%d]]]"
			" >= skb_headlen(skb->len %d - skb->data_len %d) [[[%d]]]} "
			"csum_offset %u [[csum=%d]] csum %d\n",
			__func__,
			skb->csum_start, (unsigned long)skb->data, (unsigned long)skb->head,
						(unsigned long)skb->data - (unsigned long)skb->head,
				skb_checksum_start_offset(skb),
			skb->len, skb->data_len,
				skb_headlen(skb),
			skb->csum_offset,
			skb_checksum(skb, skb_checksum_start_offset(skb), skb->len - skb_checksum_start_offset(skb), 0),
			skb->csum);

	pskb->headerlen = headerlen;
    pskb->datalen = skb->len;
    pskb->taillen = skb_end_pointer(skb) - skb_tail_pointer(skb);

    //this should copy both header and data
	// skb ofs to len
	BUG_ON(!skb);
    BUG_ON(skb_copy_bits(skb, -headerlen, &pskb->data, head_data_len));

    /* Code copied from __copy_skb_header */

    pskb->tstamp         = skb->tstamp;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    pskb->transport_header_off   = skb->transport_header - (skb->data - skb->head);
	pskb->network_header_off     = skb->network_header - (skb->data - skb->head);
	pskb->mac_header_off         = skb->mac_header - (skb->data - skb->head);
#else
    pskb->transport_header_off   = skb->transport_header - (skb->data);
	pskb->network_header_off     = skb->network_header - (skb->data);
	pskb->mac_header_off         = skb->mac_header - (skb->data);

#endif

    memcpy(pskb->cb, skb->cb, sizeof(pskb->cb));
    pskb->csum               = skb->csum;
	pskb->pkt_type           = skb->pkt_type;
	pskb->ip_summed          = skb->ip_summed;
    pskb->priority          = skb->priority;
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	pskb->ipvs_property      = skb->ipvs_property;
#endif
	pskb->protocol           = skb->protocol;
	pskb->mark               = skb->mark;
	pskb->skb_iif            = skb->skb_iif;
	/*__nf_copy(new, old);*/
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
	pskb->nf_trace           = skb->nf_trace;
#endif
#ifdef CONFIG_NET_SCHED
	pskb->tc_index           = skb->tc_index;
#ifdef CONFIG_NET_CLS_ACT
	pskb->tc_verd            = skb->tc_verd;
#endif
#endif
	pskb->vlan_tci           = skb->vlan_tci;
#ifdef CONFIG_NETWORK_SECMARK
    pskb->secmark = skb->secmark;
#endif

	return pskb;
}


//#if !POPHYPE_HOST_KERNEL /* TODO: this is for my convinience
/* hypercall at remote */
void delegate_skb_tx_hypercall(struct pophype_skb *pskb, int pskb_size)
{
	VHOSTNET_OPTIMIZE_PK("[(guest) %s()]: START - pskb %p size %d\n",
												__func__, pskb, pskb_size);
	kvm_hypercall2(KVM_HC_POPHYPE_NET_DELEGATE, (unsigned long)pskb, pskb_size);
	VHOSTNET_OPTIMIZE_PK("[(guest) %s()]: END - pskb %p size %d\n",
											__func__, pskb, pskb_size);
	kfree(pskb);
	VHOSTNET_OPTIMIZE_PK("[(guest) %s()]: size %d freed\n",
										__func__, pskb_size);
}
//#endif

/*
 * For coping skb check net/core/skbbuff.c (frome ft-popcorn net/core/ft_filter.c)
 * static int create_rx_skb_copy_msg(struct net_filter_info *filter, long long pckt_id, long long local_tx, struct sk_buff *skb, struct rx_copy_msg **msg, int *msg_size){
 */
/* check __copy_skb_header() at net/core/skbuff.c */
/****
 * At host.
 * skb: a guest ptr
 * pskb_size: from guest (HACK)
 * caller: ./arch/x86/kvm/x86.c
 */
int delegate_skb_tx(struct pophype_skb *pskb_gva, int pskb_size)
{
	delegate_skb_tx_request_t *req;
	delegate_skb_tx_response_t *res;
	struct wait_station *ws;
	struct remote_context *rc = current->mm->remote;
	int r, dst_nid = 0; /* delegation to origin */

	//int headerlen;
    //int head_data_len;
    int req_size;

	unsigned long gpa, gfn, ofs, pskb_hva;
	struct kvm_translation tr;
	//struct pophype_skb *skb; // the name is wrong as well -> pskb
	//struct sk_buff *skb;
	//int my_cpu = 1; // TODO HACK
	int my_cpu = my_nid; // TODO HACK but this is puzzlehype
	int fd = my_cpu + VCPU_FD_BASE;



	VHOSTNET_OPTIMIZE_PK("%s(): START\n", __func__);


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
	/* Convert skb from guest to host first */
	/* gva -> gspa */
	tr.linear_address = (unsigned long)pskb_gva;
	kvm_arch_vcpu_ioctl_translate(
				hype_node_info[my_nid][fd]->vcpu, &tr);
	gpa = tr.physical_address;

	/* host - gpa -> gfn */
    gfn = gpa >> PAGE_SHIFT;
    ofs = gpa % PAGE_SIZE;
    pskb_hva = kvm_vcpu_gfn_to_hva(
                hype_node_info[my_nid][fd]->vcpu, gfn);
	pskb_hva += ofs;

	VHOSTNET_OPTIMIZE_PK("(host requester) %s(): (guest<%d>) START "
			"pskb_gva %p gpa 0x%lx pskb_hva 0x%lx (void*)pskb_hva %p"
			"pskb_size %d in_atomic() %d\n",
			__func__, my_cpu, pskb_gva, gpa, pskb_hva, (void*)pskb_hva,
			pskb_size, in_atomic());

	BUG_ON(pskb_size > PAGE_SIZE); // implement more



//	//if (copy_from_user(out, buf, sizeof(*out)))
//	skb = kmalloc(pskb_size, GFP_KERNEL);
//	BUG_ON(!skb);
//	BUG_ON(copy_from_user(skb, (void*)pskb_hva, pskb_size)); // TODO: HACK


//	/* Copied skb data from skb_hva */
//	headerlen = skb_headroom(skb);
//    head_data_len = headerlen + skb->len;
//    req_size = head_data_len + sizeof(*req); // skb size varies


    req = kmalloc(pskb_size, GFP_KERNEL); // HACK: struct pskb + msg_layer hdr (HACK is outside now)
	// pskb_size + header
    //req = kmalloc(req_size, GFP_KERNEL);

	//#################################
	//#################################
	/* common msg */
	//req = kmalloc(sizeof(*req), GFP_KERNEL);
	ws = get_wait_station(current);
	BUG_ON(!req || !rc);
	req->from_pid = current->pid;
	req->ws = ws->id;
	//req->pskb->;
	/* pophype specifi */
	req->fd = vcpuid_to_fd(my_cpu);
	//#################################
	//#################################

	BUG_ON(copy_from_user(&req->pskb, (void*)pskb_hva, pskb_size)); // TODO: HACK

	req_size = pskb_size;


	VHOSTNET_OPTIMIZE_PK("%s(): =>\n\n", __func__);
    /* common */
    req->remote_pid = rc->remote_tgids[dst_nid];
    pcn_kmsg_send(PCN_KMSG_TYPE_DELEGATE_SKB_TX_REQUEST,
                            dst_nid, req, req_size);
    res = wait_at_station(ws);
    r = res->ret;
    pcn_kmsg_done(res);

    kfree(req);

	return r;
}

#include <linux/ip.h>
#include <net/ip.h>
#include <net/tcp.h>
/* Note: call put_iphdr after using get_iphdr in case
 * of no errors.
 */
static int get_iphdr(struct sk_buff *skb, struct iphdr** ip_header,int *iphdrlen) {
    int res= -EFAULT;
    struct iphdr* network_header= NULL;
    int len;

    skb_reset_network_header(skb);
    skb_reset_transport_header(skb);
    skb_reset_mac_len(skb);

    if (skb->pkt_type == PACKET_OTHERHOST)
        goto out;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        goto out;

    /*if(skb_shared(skb))
        printk("%s: WARNING skb shared\n", __func__);*/

    network_header= ip_hdr(skb);

    if (network_header->ihl < 5 || network_header->version != 4)
        goto out;

    if (!pskb_may_pull(skb, network_header->ihl*4))
        goto out;

    network_header= ip_hdr(skb);

    if (unlikely(ip_fast_csum((u8 *)network_header, network_header->ihl)))
        goto out;

    len = ntohs(network_header->tot_len);
    if (skb->len < len || len < network_header->ihl*4)
        goto out;

    if (pskb_trim_rcsum(skb, len))
        goto out;

    /* Remove any debris in the socket control block */
    memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
    skb_orphan(skb);

    *iphdrlen= ip_hdrlen(skb);
    __skb_pull(skb, *iphdrlen);
    skb_reset_transport_header(skb);

    *ip_header= ip_hdr(skb);

    res= 0;

out:
    return res;
}

static void put_iphdr(struct sk_buff *skb, int iphdrlen){
    __skb_push(skb, iphdrlen);
}

#if 0
extern struct net *pophype_tap0_at_origin;
static void fake_parameters(struct sk_buff *skb)
{
    struct inet_sock *inet;
    //struct inet_request_sock *ireq;
    int res, iphdrlen, datalen, msg_changed;
        struct iphdr *network_header;
    struct tcphdr *tcp_header= NULL;     // tcp header struct
        struct udphdr *udp_header= NULL;     // udp header struct
    __be16 sport;
    __be32 saddr;

	VHOSTNET_OPTIMIZE_PK("\t\t[*] %s(): &init_net %p == "
						"pophype_tap0_at_origin %p\n",
						__func__, &init_net, pophype_tap0_at_origin);
	skb->dev = dev_get_by_name(&init_net, POPHYPE_ORIGIN_TAP_NAME); /* directly mimic ft */
	VHOSTNET_OPTIMIZE_PK("\t\t[*] %s(): replace with origin host dev \"%s\"\n",
													__func__, skb->dev->name);

	/* Jack: this is for sync ack? */
	inet = inet_sk(skb->sk);
//	printk("!skip ip_hdr - inet %p\n", inet);
	if (inet) {
		sport = inet->inet_sport;
		saddr = inet->inet_saddr;
	} else {
//		printk("!skip ip_hdr - SYNC ACK\n");
		/* I don't have a filet->ft_req (struct request_sock *sk) */
		//ireq = inet_rsk(filter->ft_req);
        //if(ireq) {
        //    sport = ireq->loc_port;
		//	saddr = ireq->loc_addr;
        //} else{
        //    printk("%s, ERROR impossible to retrive inet socket\n",__func__);
        //    //return;
        //}
	}

	res = get_iphdr(skb, &network_header, &iphdrlen);
    if (res)
		return;

	//####### Done
    msg_changed = 0;

    /* saddr is the local IP
     * watch out, saddr=0 means any address so do not change it
     * in the packet.
     */
    if(saddr && network_header->daddr != saddr) {
        network_header->daddr = saddr;
        msg_changed = 1;
    }

    if (network_header->protocol == IPPROTO_UDP) {
        udp_header =
			(struct udphdr *) ((char*)network_header + network_header->ihl * 4);
        datalen = skb->len - ip_hdrlen(skb);

        if(udp_header->dest != sport ){
            udp_header->dest= sport;
            msg_changed = 1;
        }
        //inet_iif(skb)

        if(msg_changed) {
			udp_header->check =
				csum_tcpudp_magic(
						network_header->saddr, network_header->daddr,
					   datalen, network_header->protocol,
					   csum_partial((char *)udp_header, datalen, 0));
			ip_send_check(network_header);
		}
    } else {
        if (skb->pkt_type != PACKET_HOST)
            goto out_put;

        if (!pskb_may_pull(skb, sizeof(struct tcphdr))) /* private skb */
            goto out_put;

        tcp_header = tcp_hdr(skb);

        if (tcp_header->doff < sizeof(struct tcphdr) / 4)
            goto out_put;

        if (!pskb_may_pull(skb, tcp_header->doff * 4)) /* private skb */
            goto out_put;

        if(tcp_header->dest != sport) {
			tcp_header->dest = sport;
			msg_changed = 1;
		}

        if(msg_changed) {
			POP_PK("pophype: Jack need your ATTENTION skb->sk %p\n", skb->sk);
			tcp_v4_send_check(skb->sk, skb);
			ip_send_check(network_header);
             //tcp_v4_send_check(filter->ft_sock, skb);
             //            ip_send_check(network_header);
		 }

        //inet_iif(skb)
    }

out_put:
	printk("(bf) skb->data %lx ->len %lx += len %d\n",
				(unsigned long)skb->data, (unsigned long)skb->len, iphdrlen);
	put_iphdr(skb, iphdrlen); // skb->data ->len += len
	printk("(af) skb->data %lx ->len %lx += len %d\n",
				(unsigned long)skb->data, (unsigned long)skb->len, iphdrlen);
}
#endif

static struct sk_buff* create_skb_from_pskb(struct pophype_skb *pskb)
{
    struct sk_buff *skb;

	skb = dev_alloc_skb(pskb->datalen + pskb->headerlen + pskb->taillen);
    BUG_ON(!skb);

//	printk("%s(): Jack skb->csum_start %d ->data %lu ->head %lu (%lu) "
//			"skb->_skb_refdst %lu\n",
//					__func__, skb->csum_start,
//					(unsigned long)skb->data, (unsigned long)skb->head,
//					(unsigned long)skb->data - (unsigned long)skb->head,
//					skb->_skb_refdst);

    /* Set the data pointer */
    skb_reserve(skb, pskb->headerlen);
    /* Set the tail pointer and length */
    skb_put(skb, pskb->datalen);

	/* copy data */
    skb_copy_to_linear_data_offset(skb, -pskb->headerlen,
					&pskb->data, pskb->headerlen + pskb->datalen);

    /* Code copied from __copy_skb_header */
	skb->tstamp     = pskb->tstamp;
	/*new->dev              = old->dev;*/
    skb_set_transport_header(skb,pskb->transport_header_off);
    skb_set_network_header(skb,pskb->network_header_off);
    skb_set_mac_header(skb,pskb->mac_header_off);

	/* skb_dst_copy(new, old); */

	//skb->rxhash             = pskb->rxhash;
	//skb->ooo_okay           = pskb->ooo_okay;
	//skb->l4_rxhash          = pskb->l4_rxhash;
	/*#ifdef CONFIG_XFRM
	new->sp                 = secpath_get(old->sp);
	#endif*/
	memcpy(skb->cb, pskb->cb, sizeof(skb->cb));
	skb->csum               = pskb->csum;
	//skb->local_df           = pskb->local_df; // pophype - new doesn't have
	skb->pkt_type           = pskb->pkt_type;
	skb->ip_summed          = pskb->ip_summed;
	/*skb_copy_queue_mapping(new, old);*/
	skb->priority          = pskb->priority;
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	skb->ipvs_property      = pskb->ipvs_property;
#endif
	skb->protocol           = pskb->protocol;
	skb->mark               = pskb->mark;
	skb->skb_iif            = pskb->skb_iif;
	/*__nf_copy(new, old);*/
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
	skb->nf_trace           = pskb->nf_trace;
#endif
#ifdef CONFIG_NET_SCHED
	skb->tc_index           = pskb->tc_index;
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd            = pskb->tc_verd;
#endif
#endif
	skb->vlan_tci           = pskb->vlan_tci;
#ifdef CONFIG_NETWORK_SECMARK
	skb->secmark        = pskb->secmark;
#endif

//    fake_parameters(skb);
//	VHOSTNET_OPTIMIZE_PK("\t\t[*] %s(): BUG_ON{"
//		"offset(skb->csum_start %d - (skb->data %lu - skb->head %lu)(%lu))) [[[%d]]]"
//		" >= skb_headlen(skb->len %d - skb->data_len %d) [[[%d]]]} "
//		"csum_offset %u [[csum=%d]] csum %d\n",
//		__func__,
//		skb->csum_start, (unsigned long)skb->data, (unsigned long)skb->head,
//						(unsigned long)skb->data-(unsigned long)skb->head,
//			skb_checksum_start_offset(skb),
//		skb->len, skb->data_len,
//			skb_headlen(skb),
//		skb->csum_offset,
//		skb_checksum(skb, skb_checksum_start_offset(skb), skb->len - skb_checksum_start_offset(skb), 0),
//		skb->csum);


    return skb;

};

static void process_delegate_skb_tx_request(struct work_struct *work)
{
    START_KMSG_WORK(delegate_skb_tx_request_t, req, work);
    delegate_skb_tx_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->remote_pid);
	int ret = 0;
	struct fd dst_fd;
	unsigned long v;
	struct file *filp;
	//struct kvm_vcpu *dst_vcpu;
	struct kvm_vcpu *vcpu;
#ifdef CONFIG_POPCORN_STAT_PGFAULTS
	//ktime_t dt, delegate_skb_tx_handle_end, delegate_skb_tx_handle_start = ktime_get();
#endif
#if HPMIGRATION_DEBUG /* debug */
	static int cnt = 0;
#endif

	struct sk_buff *skb;

	BUG_ON(!tsk && "No task exist");
//	VHOSTNET_OPTIMIZE_PK("=> [*] %s():\n", __func__);

    v = fget_light_tsk(tsk, req->fd, FMODE_PATH);
    dst_fd = (struct fd){(struct file *)(v & ~3),v & 3};
//    VHOSTNET_OPTIMIZE_PK("%s(): struct fd & dst_fd %p\n", __func__, (void *)&dst_fd);
    filp = dst_fd.file;
    BUG_ON(!filp); /* check run.sh lkvm argv
                        highly likely you don't have enough CPU online */
    vcpu = filp->private_data;
    BUG_ON(!vcpu);
    fdput(dst_fd);


//	VHOSTNET_OPTIMIZE_PK("\t %s(): create skb and inject it TODO\n", __func__);

	skb = create_skb_from_pskb(&req->pskb);
	//pophype_inject_skb(skb); /* Pophype - TODO */
	netif_rx_ni(skb); /* Free skb */ /* ref: ./drivers/net/tun.c */


//	VHOSTNET_OPTIMIZE_PK("%s(): remote this handshaking ->\n", __func__);
    res->ret = ret;
    res->from_pid = req->from_pid;
    res->ws = req->ws;
    pcn_kmsg_post(PCN_KMSG_TYPE_DELEGATE_SKB_TX_RESPONSE,
							from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
}

static int handle_delegate_skb_tx_response(struct pcn_kmsg_message *msg)
{
	delegate_skb_tx_response_t *res = (delegate_skb_tx_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

	VHOSTNET_OPTIMIZE_PK("-> %s(): remote this handshaking\n", __func__);
	ws->private = res;
	complete(&ws->pendings);

    //return res->ret;
	return 0;
}




/*******************
 * States
 */
void pophype_stat(struct seq_file *seq, void *v)
{
#ifdef CONFIG_POPCORN_STAT
	if (seq) {
		seq_printf(seq, "%6s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
					"regw->", (atomic64_read(&apic_reg_write_ns) / 1000) / MICROSECOND,
							(atomic64_read(&apic_reg_write_ns) / 1000)  % MICROSECOND,
					"cnt", atomic64_read(&apic_reg_write_cnt),
					"per", atomic64_read(&apic_reg_write_cnt) ?
					 atomic64_read(&apic_reg_write_ns) / atomic64_read(&apic_reg_write_cnt) / 1000 : 0);
		seq_printf(seq, "%6s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
					"rwh<-", (atomic64_read(&apic_reg_write_handle_ns) / 1000) / MICROSECOND,
							(atomic64_read(&apic_reg_write_handle_ns) / 1000)  % MICROSECOND,
					"cnt", atomic64_read(&apic_reg_write_handle_cnt),
					"per", atomic64_read(&apic_reg_write_handle_cnt) ?
					 atomic64_read(&apic_reg_write_handle_ns) / atomic64_read(&apic_reg_write_handle_cnt) / 1000 : 0);

		seq_printf(seq, "%6s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
					"ipi->", (atomic64_read(&ipi_ns) / 1000) / MICROSECOND,
							(atomic64_read(&ipi_ns) / 1000)  % MICROSECOND,
					"cnt", atomic64_read(&ipi_cnt),
					"per", atomic64_read(&ipi_cnt) ?
					 atomic64_read(&ipi_ns) / atomic64_read(&ipi_cnt) / 1000 : 0);
		seq_printf(seq, "%6s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
					"ipih<-", (atomic64_read(&ipi_handle_ns) / 1000) / MICROSECOND,
							(atomic64_read(&ipi_handle_ns) / 1000)  % MICROSECOND,
					"cnt", atomic64_read(&ipi_handle_cnt),
					"per", atomic64_read(&ipi_handle_cnt) ?
					 atomic64_read(&ipi_handle_ns) / atomic64_read(&ipi_handle_cnt) / 1000 : 0);

		/* Net - event_signal */
		seq_printf(seq, "%s %lu %s %ld\n",
		                    "eventfd_delegate_cnt", eventfd_delegate_cnt,
		                    "eventfd_delegated_cnt", atomic64_read(&eventfd_delegated_cnt));
	} else { /* clear */
		atomic64_set(&apic_reg_write_cnt, 0);
		atomic64_set(&apic_reg_write_ns, 0);
		atomic64_set(&apic_reg_write_handle_cnt, 0);
		atomic64_set(&apic_reg_write_handle_ns, 0);

		atomic64_set(&ipi_cnt, 0);
		atomic64_set(&ipi_ns, 0);
		atomic64_set(&ipi_handle_cnt, 0);
		atomic64_set(&ipi_handle_ns, 0);

		eventfd_delegate_cnt = 0;
		atomic64_set(&eventfd_delegated_cnt, 0);
	}
#endif
}


/*******************
 *
 */
DEFINE_KMSG_WQ_HANDLER(remote_kvm_create_request);
DEFINE_KMSG_WQ_HANDLER(origin_sipi_request);
DEFINE_KMSG_WQ_HANDLER(origin_broadcast_accept_irq_request);
DEFINE_KMSG_WQ_HANDLER(origin_broadcast_apic_reg_write_request);
DEFINE_KMSG_WQ_HANDLER(origin_broadcast_cpu_table_request);
DEFINE_KMSG_WQ_HANDLER(update_cpu_table_request);
DEFINE_KMSG_WQ_HANDLER(ipi_request);
DEFINE_KMSG_WQ_HANDLER(sig_request);
DEFINE_KMSG_WQ_HANDLER(checkin_vcpu_pid_request);
DEFINE_KMSG_WQ_HANDLER(origin_checkin_vcpu_pid_request);
DEFINE_KMSG_WQ_HANDLER(update_vcpu_request);
DEFINE_KMSG_WQ_HANDLER(delegate_skb_tx_request);
DEFINE_KMSG_WQ_HANDLER(delegate_net_msg_tx_request);
DEFINE_KMSG_WQ_HANDLER(eventfd_delegate_request);
DEFINE_KMSG_WQ_HANDLER(tunfd_delegate_request);
DEFINE_KMSG_WQ_HANDLER(rx_notification_request);
DEFINE_KMSG_WQ_HANDLER(recvmsg_delegate_request);
DEFINE_KMSG_WQ_HANDLER(peek_head_len_request);
int __init popcorn_hype_kvm_init(void)
{
	// reg
    REGISTER_KMSG_WQ_HANDLER(
            PCN_KMSG_TYPE_REMOTE_KVM_CREATE_REQUEST, remote_kvm_create_request);
    REGISTER_KMSG_HANDLER(
            PCN_KMSG_TYPE_REMOTE_KVM_CREATE_RESPONSE, remote_kvm_create_response);

    REGISTER_KMSG_WQ_HANDLER(
            PCN_KMSG_TYPE_ORIGIN_SIPI_REQUEST, origin_sipi_request);
    REGISTER_KMSG_HANDLER(
            PCN_KMSG_TYPE_ORIGIN_SIPI_RESPONSE, origin_sipi_response);
    REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_ORIGIN_BROADCAST_ACCEPT_IRQ_REQUEST,
								origin_broadcast_accept_irq_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_ORIGIN_BROADCAST_ACCEPT_IRQ_RESPONSE,
								origin_broadcast_accept_irq_response);
    REGISTER_KMSG_WQ_HANDLER(
					PCN_KMSG_TYPE_ORIGIN_BROADCAST_APIC_REG_WRITE_REQUEST,
								origin_broadcast_apic_reg_write_request);
    REGISTER_KMSG_HANDLER(
					PCN_KMSG_TYPE_ORIGIN_BROADCAST_APIC_REG_WRITE_RESPONSE,
								origin_broadcast_apic_reg_write_response);

    REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_ORIGIN_BROADCAST_CPU_TABLE_REQUEST,
								origin_broadcast_cpu_table_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_ORIGIN_BROADCAST_CPU_TABLE_RESPONSE,
								origin_broadcast_cpu_table_response);
	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_UPDATE_CPU_TABLE_REQUEST_FIELDS,
								update_cpu_table_request);

	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_IPI_REQUEST, ipi_request); /* For ipi */
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_IPI_RESPONSE, ipi_response);
	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_SIG_REQUEST, sig_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_SIG_RESPONSE, sig_response);
	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_REMOTE_CHECKIN_VCPU_PID_REQUEST,
											checkin_vcpu_pid_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_REMOTE_CHECKIN_VCPU_PID_RESPONSE,
											checkin_vcpu_pid_response);
	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_ORIGIN_CHECKIN_VCPU_PID_REQUEST,
											origin_checkin_vcpu_pid_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_ORIGIN_CHECKIN_VCPU_PID_RESPONSE,
											origin_checkin_vcpu_pid_response);

	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_DELEGATE_EVENTFD_REQUEST,
											eventfd_delegate_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_DELEGATE_EVENTFD_RESPONSE,
										eventfd_delegate_response);

	/* For Pophype migration */
	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_UPDATE_VCPU_REQUEST,
												update_vcpu_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_UPDATE_VCPU_RESPONSE,
												update_vcpu_response);

	/* Network */
	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_DELEGATE_SKB_TX_REQUEST,
											delegate_skb_tx_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_DELEGATE_SKB_TX_RESPONSE,
												delegate_skb_tx_response);

	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_DELEGATE_NET_MSG_TX_REQUEST,
											delegate_net_msg_tx_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_DELEGATE_NET_MSG_TX_RESPONSE,
												delegate_net_msg_tx_response);


       REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_DELEGATE_TUNFD_REQUEST,
												tunfd_delegate_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_DELEGATE_TUNFD_RESPONSE,
												tunfd_delegate_response);

       REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_RX_NOTIFICATION_REQUEST,
                                            rx_notification_request);

       REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_PEEK_HEAD_LEN_REQUEST,
                                            peek_head_len_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_PEEK_HEAD_LEN_RESPONSE,
                                        peek_head_len_response);

       REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_DELEGATE_RECVMSG_REQUEST,
                                            recvmsg_delegate_request);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_DELEGATE_RECVMSG_RESPONSE,
                                        recvmsg_delegate_response);

	/* AP start debugging */
	//hype_callin[1] = false;

	popcorn_hype_check_remote_cpus();

	/* VM stack walk */
	kvaddr = kmalloc(PAGE_SIZE, GFP_KERNEL);
	BUG_ON(!kvaddr);
	//kfree(kvaddr);

	/* */
	spin_lock_init(&phmigrate);

	return 0;
}
