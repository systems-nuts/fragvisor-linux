/*
 * Generic helpers for smp ipi calls
 *
 * (C) Jens Axboe <jens.axboe@oracle.com> 2008
 */
#include <linux/irq_work.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/sched.h>

#include "smpboot.h"

#ifdef CONFIG_POPCORN_HYPE
#include <popcorn/debug.h>
#include <popcorn/bundle.h>
#include <popcorn/hype_kvm.h>
#include <linux/delay.h>
#include <linux/slab.h>
extern pgd_t early_level4_pgt[PTRS_PER_PGD];
#define POPHYPE_SSLEEP 1 /* x2 */
#endif

enum {
	CSD_FLAG_LOCK		= 0x01,
	CSD_FLAG_SYNCHRONOUS	= 0x02,
};

struct call_function_data {
	struct call_single_data	__percpu *csd;
	cpumask_var_t		cpumask;
};

static DEFINE_PER_CPU_SHARED_ALIGNED(struct call_function_data, cfd_data);

static DEFINE_PER_CPU_SHARED_ALIGNED(struct llist_head, call_single_queue);

static void flush_smp_call_function_queue(bool warn_cpu_offline);

static int
hotplug_cfd(struct notifier_block *nfb, unsigned long action, void *hcpu)
{
	long cpu = (long)hcpu;
	struct call_function_data *cfd = &per_cpu(cfd_data, cpu);

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		if (!zalloc_cpumask_var_node(&cfd->cpumask, GFP_KERNEL,
				cpu_to_node(cpu)))
			return notifier_from_errno(-ENOMEM);
		cfd->csd = alloc_percpu(struct call_single_data);
		if (!cfd->csd) {
			free_cpumask_var(cfd->cpumask);
			return notifier_from_errno(-ENOMEM);
		}
		break;

#ifdef CONFIG_HOTPLUG_CPU
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		/* Fall-through to the CPU_DEAD[_FROZEN] case. */

	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		free_cpumask_var(cfd->cpumask);
		free_percpu(cfd->csd);
		break;

	case CPU_DYING:
	case CPU_DYING_FROZEN:
		/*
		 * The IPIs for the smp-call-function callbacks queued by other
		 * CPUs might arrive late, either due to hardware latencies or
		 * because this CPU disabled interrupts (inside stop-machine)
		 * before the IPIs were sent. So flush out any pending callbacks
		 * explicitly (without waiting for the IPIs to arrive), to
		 * ensure that the outgoing CPU doesn't go offline with work
		 * still pending.
		 */
		flush_smp_call_function_queue(false);
		break;
#endif
	};

	return NOTIFY_OK;
}

static struct notifier_block hotplug_cfd_notifier = {
	.notifier_call		= hotplug_cfd,
};

void __init call_function_init(void)
{
	void *cpu = (void *)(long)smp_processor_id();
	int i;
#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	POP_PK("bsp<*>: __init %s() <%d> "
			"list_init(&per_cpu(call_single_queue, all_cpu)\n",
							__func__, cpu ? *(int *)cpu : -99);
#endif

//	for_each_possible_cpu(i)
//		init_llist_head(&per_cpu(call_single_queue, i));

#ifdef CONFIG_POPCORN_HYPE
#if !POPHYPE_HOST_KERNEL
	for_each_possible_cpu(i) {
		struct llist_head *head = &per_cpu(call_single_queue, i);
		POP_PK("bsp<*> %s(): init <%d> bf head %p head->first %p\n",
									__func__, i, head, head->first);
		init_llist_head(&per_cpu(call_single_queue, i));
		POP_PK("bsp<*> %s(): init <%d> af head %p head->first %p\n",
									__func__, i, head, head->first);
	}
#else
	for_each_possible_cpu(i)
		init_llist_head(&per_cpu(call_single_queue, i));
#endif
#else
	for_each_possible_cpu(i)
		init_llist_head(&per_cpu(call_single_queue, i));
#endif


	hotplug_cfd(&hotplug_cfd_notifier, CPU_UP_PREPARE, cpu);
	register_cpu_notifier(&hotplug_cfd_notifier);
}

/*
 * csd_lock/csd_unlock used to serialize access to per-cpu csd resources
 *
 * For non-synchronous ipi calls the csd can still be in use by the
 * previous function call. For multi-cpu calls its even more interesting
 * as we'll have to ensure no other cpu is observing our csd.
 */
static void csd_lock_wait(struct call_single_data *csd)
{
	while (smp_load_acquire(&csd->flags) & CSD_FLAG_LOCK)
		cpu_relax();
}

static void csd_lock(struct call_single_data *csd)
{
	csd_lock_wait(csd);
	csd->flags |= CSD_FLAG_LOCK;

	/*
	 * prevent CPU from reordering the above assignment
	 * to ->flags with any subsequent assignments to other
	 * fields of the specified call_single_data structure:
	 */
	smp_wmb();
}

static void csd_unlock(struct call_single_data *csd)
{
	WARN_ON(!(csd->flags & CSD_FLAG_LOCK));

#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	GSMPPRINTK("<%d> %s(): csd %p\n", smp_processor_id(), __func__, csd);
#endif

	/*
	 * ensure we're all done before releasing data:
	 */
	smp_store_release(&csd->flags, 0);
}

static DEFINE_PER_CPU_SHARED_ALIGNED(struct call_single_data, csd_data);

/*
 * Insert a previously allocated call_single_data element
 * for execution on the given CPU. data must already have
 * ->func, ->info, and ->flags set.
 */
static int generic_exec_single(int cpu, struct call_single_data *csd,
			       smp_call_func_t func, void *info)
{
#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	GBSPIPIPRINTK("<BSP> %s(): check my_cpu %d =? <%d>\n",
						__func__, smp_processor_id(), cpu);
#endif
	if (cpu == smp_processor_id()) {
		unsigned long flags;

		/*
		 * We can unlock early even for the synchronous on-stack case,
		 * since we're doing this from the same CPU..
		 */
		csd_unlock(csd);
		local_irq_save(flags);
		func(info);
		local_irq_restore(flags);
		return 0;
	}


#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	GBSPIPIPRINTK("<BSP> %s(): not the same - 1\n", __func__);
#endif
	if ((unsigned)cpu >= nr_cpu_ids || !cpu_online(cpu)) {
		csd_unlock(csd);
		return -ENXIO;
	}

	csd->func = func;
	csd->info = info;

#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	GBSPIPIPRINTK("<BSP> %s(): not the same &csd->llist %lx "
			"&per_cpu(call_single_queue, cpu) %lx\n",
			__func__, (unsigned long)&csd->llist, (unsigned long)&per_cpu(call_single_queue, cpu));
#endif
	/*
	 * The list addition should be visible before sending the IPI
	 * handler locks the list to pull the entry off it because of
	 * normal cache coherency rules implied by spinlocks.
	 *
	 * If IPIs can go out of order to the cache coherency protocol
	 * in an architecture, sufficient synchronisation should be added
	 * to arch code to make it appear to obey cache coherency WRT
	 * locking and barrier primitives. Generic code isn't really
	 * equipped to do the right thing...
	 */
	if (llist_add(&csd->llist, &per_cpu(call_single_queue, cpu))) {
#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
		/* According to the theory,
			this is for preventing double ipi (check code) */
		GBSPIPIPRINTK("<BSP> %s(): not the same my_cpu %d "
					"*****=ipi>***** <%d>\n",
					__func__, smp_processor_id(), cpu);
#endif
		arch_send_call_function_single_ipi(cpu);
	}

	return 0;
}

/**
 * generic_smp_call_function_single_interrupt - Execute SMP IPI callbacks
 *
 * Invoked by arch to handle an IPI for call function single.
 * Must be called with interrupts disabled.
 */
void generic_smp_call_function_single_interrupt(void)
{
	flush_smp_call_function_queue(true);
}

/**
 * flush_smp_call_function_queue - Flush pending smp-call-function callbacks
 *
 * @warn_cpu_offline: If set to 'true', warn if callbacks were queued on an
 *		      offline CPU. Skip this check if set to 'false'.
 *
 * Flush any pending smp-call-function callbacks queued on this CPU. This is
 * invoked by the generic IPI handler, as well as by a CPU about to go offline,
 * to ensure that all pending IPI callbacks are run before it goes completely
 * offline.
 *
 * Loop through the call_single_queue and run all the queued callbacks.
 * Must be called with interrupts disabled.
 */
static void flush_smp_call_function_queue(bool warn_cpu_offline)
{
	struct llist_head *head;
	struct llist_node *entry;
	struct call_single_data *csd, *csd_next;
	static bool warned;

	WARN_ON(!irqs_disabled());

	head = this_cpu_ptr(&call_single_queue);
	entry = llist_del_all(head);
	entry = llist_reverse_order(entry);

	/* There shouldn't be any pending callbacks on an offline CPU. */
	if (unlikely(warn_cpu_offline && !cpu_online(smp_processor_id()) &&
		     !warned && !llist_empty(head))) {
		warned = true;
		WARN(1, "IPI on offline CPU %d\n", smp_processor_id());

		/*
		 * We don't have to use the _safe() variant here
		 * because we are not invoking the IPI handlers yet.
		 */
		llist_for_each_entry(csd, entry, llist)
			pr_warn("IPI callback %pS sent to offline CPU\n",
				csd->func);
	}

	llist_for_each_entry_safe(csd, csd_next, entry, llist) {
		smp_call_func_t func = csd->func;
		void *info = csd->info;

		/* Do we wait until *after* callback? */
		if (csd->flags & CSD_FLAG_SYNCHRONOUS) {
			func(info);
			csd_unlock(csd);
		} else {
			csd_unlock(csd);
			func(info);
		}
	}

	/*
	 * Handle irq works queued remotely by irq_work_queue_on().
	 * Smp functions above are typically synchronous so they
	 * better run first since some other CPUs may be busy waiting
	 * for them.
	 */
	irq_work_run();
}

/*
 * smp_call_function_single - Run a function on a specific CPU
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait until function has completed on other CPUs.
 *
 * Returns 0 on success, else a negative status code.
 */
int smp_call_function_single(int cpu, smp_call_func_t func, void *info,
			     int wait)
{
	struct call_single_data *csd;
	struct call_single_data csd_stack = { .flags = CSD_FLAG_LOCK | CSD_FLAG_SYNCHRONOUS };
	int this_cpu;
	int err;

	/*
	 * prevent preemption and reschedule on another processor,
	 * as well as CPU removal
	 */
	this_cpu = get_cpu();

	/*
	 * Can deadlock when called with interrupts disabled.
	 * We allow cpu's that are not yet online though, as no one else can
	 * send smp call function interrupt to this cpu and as such deadlocks
	 * can't happen.
	 */
	WARN_ON_ONCE(cpu_online(this_cpu) && irqs_disabled()
		     && !oops_in_progress);

	csd = &csd_stack;
	if (!wait) {
		csd = this_cpu_ptr(&csd_data);
		csd_lock(csd);
	}

#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	GBSPIPIPRINTK("%s(): my_cpu <%d> cpu <%d> > generic_exec_single() %p\n",
					__func__, smp_processor_id(), cpu, csd);
	{
		int i;
		for_each_possible_cpu(i) {
			struct llist_head *_head = &per_cpu(call_single_queue, i);
			GBSPIPIPRINTK("\t\t\tmy_cpu <%d> cpu <%d> %s(): iter <%d> "
							"_head->first %p\n",
					smp_processor_id(), cpu, __func__, i, _head->first);
		}
	}
#endif
	err = generic_exec_single(cpu, csd, func, info);

#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	GBSPIPIPRINTK("%s(): my_cpu <%d> run on cpu <%d> wait=%d\n",
					__func__, smp_processor_id(), cpu, wait);
#if !PERF_EXP
	if (!wait) // ONLY SMP INIT DOES THIS
		dump_stack();
#endif
#endif
	if (wait)
		csd_lock_wait(csd);

	put_cpu();

	return err;
}
EXPORT_SYMBOL(smp_call_function_single);

/**
 * smp_call_function_single_async(): Run an asynchronous function on a
 * 			         specific CPU.
 * @cpu: The CPU to run on.
 * @csd: Pre-allocated and setup data structure
 *
 * Like smp_call_function_single(), but the call is asynchonous and
 * can thus be done from contexts with disabled interrupts.
 *
 * The caller passes his own pre-allocated data structure
 * (ie: embedded in an object) and is responsible for synchronizing it
 * such that the IPIs performed on the @csd are strictly serialized.
 *
 * NOTE: Be careful, there is unfortunately no current debugging facility to
 * validate the correctness of this serialization.
 */
int smp_call_function_single_async(int cpu, struct call_single_data *csd)
{
	int err = 0;

	preempt_disable();

	/* We could deadlock if we have to wait here with interrupts disabled! */
	if (WARN_ON_ONCE(csd->flags & CSD_FLAG_LOCK))
		csd_lock_wait(csd);

	csd->flags = CSD_FLAG_LOCK;
	smp_wmb();

	err = generic_exec_single(cpu, csd, csd->func, csd->info);
	preempt_enable();

	return err;
}
EXPORT_SYMBOL_GPL(smp_call_function_single_async);

/*
 * smp_call_function_any - Run a function on any of the given cpus
 * @mask: The mask of cpus it can run on.
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait until function has completed.
 *
 * Returns 0 on success, else a negative status code (if no cpus were online).
 *
 * Selection preference:
 *	1) current cpu if in @mask
 *	2) any cpu of current node if in @mask
 *	3) any other online cpu in @mask
 */
int smp_call_function_any(const struct cpumask *mask,
			  smp_call_func_t func, void *info, int wait)
{
	unsigned int cpu;
	const struct cpumask *nodemask;
	int ret;

	/* Try for same CPU (cheapest) */
	cpu = get_cpu();
	if (cpumask_test_cpu(cpu, mask))
		goto call;

	/* Try for same node. */
	nodemask = cpumask_of_node(cpu_to_node(cpu));
	for (cpu = cpumask_first_and(nodemask, mask); cpu < nr_cpu_ids;
	     cpu = cpumask_next_and(cpu, nodemask, mask)) {
		if (cpu_online(cpu))
			goto call;
	}

	/* Any online will do: smp_call_function_single handles nr_cpu_ids. */
	cpu = cpumask_any_and(mask, cpu_online_mask);
call:
	ret = smp_call_function_single(cpu, func, info, wait);
	put_cpu();
	return ret;
}
EXPORT_SYMBOL_GPL(smp_call_function_any);

/**
 * smp_call_function_many(): Run a function on a set of other CPUs.
 * @mask: The set of cpus to run on (only runs on online subset).
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait (atomically) until function has completed
 *        on other CPUs.
 *
 * If @wait is true, then returns once @func has returned.
 *
 * You must not call this function with disabled interrupts or from a
 * hardware interrupt handler or from a bottom half handler. Preemption
 * must be disabled when calling this function.
 */
void smp_call_function_many(const struct cpumask *mask,
			    smp_call_func_t func, void *info, bool wait)
{
	struct call_function_data *cfd;
	int cpu, next_cpu, this_cpu = smp_processor_id();

	/*
	 * Can deadlock when called with interrupts disabled.
	 * We allow cpu's that are not yet online though, as no one else can
	 * send smp call function interrupt to this cpu and as such deadlocks
	 * can't happen.
	 */
	WARN_ON_ONCE(cpu_online(this_cpu) && irqs_disabled()
		     && !oops_in_progress && !early_boot_irqs_disabled);

	/* Try to fastpath.  So, what's a CPU they want? Ignoring this one. */
	cpu = cpumask_first_and(mask, cpu_online_mask);
	if (cpu == this_cpu)
		cpu = cpumask_next_and(cpu, mask, cpu_online_mask);

	/* No online cpus?  We're done. */
	if (cpu >= nr_cpu_ids)
		return;

	/* Do we have another CPU which isn't us? */
	next_cpu = cpumask_next_and(cpu, mask, cpu_online_mask);
	if (next_cpu == this_cpu)
		next_cpu = cpumask_next_and(next_cpu, mask, cpu_online_mask);

	/* Fastpath: do that cpu by itself. */
	if (next_cpu >= nr_cpu_ids) {
#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
		GBSPIPIPRINTK("%s(): my_cpu <%d> cpu <%d> > smp_call_function_single()\n",
						__func__, smp_processor_id(), cpu);
#endif
		smp_call_function_single(cpu, func, info, wait);
		return;
	}

	cfd = this_cpu_ptr(&cfd_data);

	cpumask_and(cfd->cpumask, mask, cpu_online_mask);
	cpumask_clear_cpu(this_cpu, cfd->cpumask);

	/* Some callers race with other cpus changing the passed mask */
	if (unlikely(!cpumask_weight(cfd->cpumask)))
		return;

	for_each_cpu(cpu, cfd->cpumask) {
		struct call_single_data *csd = per_cpu_ptr(cfd->csd, cpu);

		csd_lock(csd);
		if (wait)
			csd->flags |= CSD_FLAG_SYNCHRONOUS;
		csd->func = func;
		csd->info = info;
		llist_add(&csd->llist, &per_cpu(call_single_queue, cpu));
	}

#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	GSMPPRINTK("%s(): my_cpu <%d> cpu <%d> > "
				"arch_send_call_function_ipi_mask()\n",
				__func__, smp_processor_id(), cpu);
#endif
	/* Send a message to all CPUs in the map */
	arch_send_call_function_ipi_mask(cfd->cpumask);

	if (wait) {
		for_each_cpu(cpu, cfd->cpumask) {
			struct call_single_data *csd;

			csd = per_cpu_ptr(cfd->csd, cpu);
			csd_lock_wait(csd);
		}
	}
}
EXPORT_SYMBOL(smp_call_function_many);

/**
 * smp_call_function(): Run a function on all other CPUs.
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait (atomically) until function has completed
 *        on other CPUs.
 *
 * Returns 0.
 *
 * If @wait is true, then returns once @func has returned; otherwise
 * it returns just before the target cpu calls @func.
 *
 * You must not call this function with disabled interrupts or from a
 * hardware interrupt handler or from a bottom half handler.
 */
int smp_call_function(smp_call_func_t func, void *info, int wait)
{
	preempt_disable();
	smp_call_function_many(cpu_online_mask, func, info, wait);
	preempt_enable();

	return 0;
}
EXPORT_SYMBOL(smp_call_function);

/* Setup configured maximum number of CPUs to activate */
unsigned int setup_max_cpus = NR_CPUS;
EXPORT_SYMBOL(setup_max_cpus);


/*
 * Setup routine for controlling SMP activation
 *
 * Command-line option of "nosmp" or "maxcpus=0" will disable SMP
 * activation entirely (the MPS table probe still happens, though).
 *
 * Command-line option of "maxcpus=<NUM>", where <NUM> is an integer
 * greater than 0, limits the maximum number of CPUs activated in
 * SMP mode to <NUM>.
 */

void __weak arch_disable_smp_support(void) { }

static int __init nosmp(char *str)
{
	setup_max_cpus = 0;
	arch_disable_smp_support();

	return 0;
}

early_param("nosmp", nosmp);

/* this is hard limit */
static int __init nrcpus(char *str)
{
	int nr_cpus;

	get_option(&str, &nr_cpus);
	if (nr_cpus > 0 && nr_cpus < nr_cpu_ids)
		nr_cpu_ids = nr_cpus;

	return 0;
}

early_param("nr_cpus", nrcpus);

static int __init maxcpus(char *str)
{
	get_option(&str, &setup_max_cpus);
	if (setup_max_cpus == 0)
		arch_disable_smp_support();

	return 0;
}

early_param("maxcpus", maxcpus);

/* Setup number of possible processor ids */
int nr_cpu_ids __read_mostly = NR_CPUS;
EXPORT_SYMBOL(nr_cpu_ids);

/* An arch may set nr_cpu_ids earlier if needed, so this would be redundant */
void __init setup_nr_cpu_ids(void)
{
	nr_cpu_ids = find_last_bit(cpumask_bits(cpu_possible_mask),NR_CPUS) + 1;
}

void __weak smp_announce(void)
{
	printk(KERN_INFO "Brought up %d CPUs\n", num_online_cpus());
}

/* Called by boot processor to activate the rest. */
#ifdef CONFIG_POPCORN_HYPE
void ssleep_at_ap(int seconds)
{
	int i, j,k, loop1 = 100, loop2 = 100000000 / 60;
//	POP_PK(KERN_INFO "\t\t[%d] (sleep %ds...)\n",
//					current ? current->pid : -1, seconds);
	for (k=0; k< seconds; k++)
		for (i = 0; i < loop1; i++)
			for (j = 0; j < loop2; j++)
				cpu_relax();

}

extern bool **hype_callin_dynamic_alloc;
extern bool hype_callin[HYPE_DEBUG_POINT_MAX + 1][MAX_POPCORN_VCPU];
//extern bool **hype_callin;
#if 0
void cpu_sleep_almost_forever(int cpu)
{
    //hype_callin[HYPE_DEBUG_POINT1][1] = true; /* remote guest kernel cannot printk() */
    //wmb(); // DSM has handled it
//    if (cpu == 1) {
        //int ssleep = 999999;
        //ssleep_at_ap(ssleep); /* dont sleep forever */
//    }
}
#endif

void popcorn_hype_faultaddr_test(bool is_bsp)
{
#if 0
	int tmp;
	printk("__START_KERNEL_map %lx (cannot read)\n", __START_KERNEL_map);

	printk("__START_KERNEL %lx\n", __START_KERNEL);
	printk("__START_KERNEL %lx read (%d)\n", __START_KERNEL, *(int*)__START_KERNEL);
	tmp = *(int*)__START_KERNEL;

	printk("__START_KERNEL %lx write back (%d)\n", __START_KERNEL, tmp);
	memset((void*)__START_KERNEL, tmp, sizeof(tmp));
	if (is_bsp) {
		msleep(2000);
	} else {
		ssleep_at_ap(2);
	}

	printk("__PAGE_OFFSET %lx\n", __PAGE_OFFSET);
	printk("__PAGE_OFFSET %lx read (%d)\n", __PAGE_OFFSET, *(int*)__PAGE_OFFSET);
	tmp = *(int*)__PAGE_OFFSET;
	printk("__PAGE_OFFSET %lx write back (%d)\n", __PAGE_OFFSET, *(int*)__PAGE_OFFSET);
	memset((void*)__PAGE_OFFSET, tmp, sizeof(tmp));

	if (is_bsp) {
		msleep(2000);
	} else {
		ssleep_at_ap(2);
	}

	//printk("init_level4_pgt %lx\n", init_level4_pgt);
	printk("early_level4_pgt %p\n", early_level4_pgt);
	printk("&early_level4_pgt[510] %p\n", &early_level4_pgt[510]);
	printk("&early_level4_pgt[511] %p\n", &early_level4_pgt[511]);
	printk("early_level4_pgt[510].pgd %lx\n", early_level4_pgt[510].pgd);
	printk("early_level4_pgt[511].pgd %lx\n", early_level4_pgt[511].pgd);
#endif
}
//ffffffff81000042:   48 01 2d af 1f c1 00    add    %rbp,0xc11faf(%rip)        # ffffffff81c11ff8 <level3_kernel_pgt+0xff8>
#endif
void __init smp_init(void)
{
	unsigned int cpu;
#ifdef CONFIG_POPCORN_HYPE
	int i; //, j;
	//unsigned long cnt = 0; /* 4054000 */
	//struct mm_struct *mm = current->mm;
#endif
	idle_threads_init();
#ifdef CONFIG_POPCORN_HYPE
    HYPEBOOTDBGPRINTK("\n\t\t===== <*> BSP TESTING ZONE ======\n\n");
	HYPEBOOTDBGPRINTK("Move others to here\n");

    HYPEBOOTDBGPRINTK("Popcorn Hype argvs:\n");
    HYPEBOOTDBGPRINTK("DISABLE_WRITABLE_EPT %c\n",
					DISABLE_WRITABLE_EPT ? 'O' : 'X');
    HYPEBOOTDBGPRINTK("HYPE_PERF_CRITICAL_DEBUG %c\n",
					  HYPE_PERF_CRITICAL_DEBUG ? 'O' : 'X');
    HYPEBOOTDBGPRINTK("DISABLE_VANILLA_DIRECT_PTE_PREFETCH %c\n",
					  DISABLE_VANILLA_DIRECT_PTE_PREFETCH ? 'O' : 'X');
	HYPEBOOTDBGPRINTK("RETRY_FIRST_EPT (I don't think this should happen) %c\n",
											RETRY_FIRST_EPT ? 'O' : 'X');
	HYPEBOOTDBGPRINTK("HYPE_DEBUG_POINT_MAX %d\n", HYPE_DEBUG_POINT_MAX);

    HYPEBOOTDBGPRINTK("cpu_initialized_mask passed %p 0x%lx\n",
				cpu_initialized_mask, __pa(cpu_initialized_mask));
	HYPEBOOTDBGPRINTK("***cpu_callout_mask*** %p 0x%lx\n",
				cpu_callout_mask, __pa(cpu_callout_mask));
	HYPEBOOTDBGPRINTK("cpu_online_mask kva %p kpa 0x%lx\n",
				cpu_online_mask, __pa(cpu_online_mask));

#if POPHYPE_HOST_KERNEL
    HYPEBOOTDBGPRINTK("\n\n\t\tI'm a HOST OS BSP !!!!!\n\n");
#else
	HYPEBOOTDBGPRINTK("\n\n\t\tI'm a GUEST OS BSP !atomic sleepable!!!!\n");
    //HYPEBOOTDBGPRINTK("Prepare to start (sleep %ds first...)\n\n",
	//												POPHYPE_SSLEEP);
	//msleep(POPHYPE_SSLEEP * 1000);
#endif

#if 0
	popcorn_hype_faultaddr_test(true);
#endif

#ifdef CONFIG_POPCORN_HYPE
	hype_callin_dynamic_alloc =
			kmalloc((HYPE_DEBUG_POINT_MAX + 1) * sizeof(bool *), GFP_KERNEL);
	BUG_ON(!hype_callin_dynamic_alloc);
	for (i = 0; i < HYPE_DEBUG_POINT_MAX + 1; i++) {
		BUG_ON(!&hype_callin_dynamic_alloc[i]);
		BUG_ON(!(bool *)((hype_callin_dynamic_alloc) + i));
		hype_callin_dynamic_alloc[i] =
				kmalloc(MAX_POPCORN_VCPU * sizeof(bool), GFP_KERNEL);
		BUG_ON(!hype_callin_dynamic_alloc[i]);
	}
	POP_PK("pophype: GOOD ALLOC !!!!!!\n");
    HYPEBOOTDBGPRINTK("Only check <1>\n");
    for (i = HYPE_DEBUG_POINT0; i < HYPE_DEBUG_POINT_MAX; i++) {
		HYPEBOOTDBGPRINTK(KERN_INFO "addr of "
					"&hype_callin_dynamic_alloc[HYPE_DEBUG_POINT%d][1] %p\n",
										i, &hype_callin_dynamic_alloc[i][1]);
    }
#endif

#if !POPHYPE_HOST_KERNEL
    //HYPEBOOTDBGPRINTK("Done!! (sleeping %ds...)\n", POPHYPE_SSLEEP);
	//msleep(POPHYPE_SSLEEP * 1000);
#endif

    HYPEBOOTDBGPRINTK("\n\t\t======= <*> BSP TESTING ZONE DONE ==========\n\n");
#endif
	/* FIXME: This should be done in userspace --RR */
	for_each_present_cpu(cpu) {
		if (num_online_cpus() >= setup_max_cpus)
			break;
		if (!cpu_online(cpu))
			cpu_up(cpu);
	}

#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	for_each_possible_cpu(i) {
		struct llist_head *head = &per_cpu(call_single_queue, i);
		POP_PK("bsp<*> %s(): <%d> late smp_init check "
				"head %p head->first %p\n",
				__func__, i, head, head->first);
		//init_llist_head(&per_cpu(call_single_queue, i));
		//POP_PK("bsp<*> %s(): laste smp_init <%d> af head %p head->first %p\n",
		//							__func__, i, head, head->first);
	}
#endif


	/* Any cleanup work */
	smp_announce();
	smp_cpus_done(setup_max_cpus);
}

/*
 * Call a function on all processors.  May be used during early boot while
 * early_boot_irqs_disabled is set.  Use local_irq_save/restore() instead
 * of local_irq_disable/enable().
 */
int on_each_cpu(void (*func) (void *info), void *info, int wait)
{
	unsigned long flags;
	int ret = 0;

	preempt_disable();
	ret = smp_call_function(func, info, wait);
	local_irq_save(flags);
	func(info);
	local_irq_restore(flags);
	preempt_enable();
	return ret;
}
EXPORT_SYMBOL(on_each_cpu);

/**
 * on_each_cpu_mask(): Run a function on processors specified by
 * cpumask, which may include the local processor.
 * @mask: The set of cpus to run on (only runs on online subset).
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait (atomically) until function has completed
 *        on other CPUs.
 *
 * If @wait is true, then returns once @func has returned.
 *
 * You must not call this function with disabled interrupts or from a
 * hardware interrupt handler or from a bottom half handler.  The
 * exception is that it may be used during early boot while
 * early_boot_irqs_disabled is set.
 */
void on_each_cpu_mask(const struct cpumask *mask, smp_call_func_t func,
			void *info, bool wait)
{
	int cpu = get_cpu();

	smp_call_function_many(mask, func, info, wait);
	if (cpumask_test_cpu(cpu, mask)) {
		unsigned long flags;
		local_irq_save(flags);
		func(info);
		local_irq_restore(flags);
	}
	put_cpu();
}
EXPORT_SYMBOL(on_each_cpu_mask);

/*
 * on_each_cpu_cond(): Call a function on each processor for which
 * the supplied function cond_func returns true, optionally waiting
 * for all the required CPUs to finish. This may include the local
 * processor.
 * @cond_func:	A callback function that is passed a cpu id and
 *		the the info parameter. The function is called
 *		with preemption disabled. The function should
 *		return a blooean value indicating whether to IPI
 *		the specified CPU.
 * @func:	The function to run on all applicable CPUs.
 *		This must be fast and non-blocking.
 * @info:	An arbitrary pointer to pass to both functions.
 * @wait:	If true, wait (atomically) until function has
 *		completed on other CPUs.
 * @gfp_flags:	GFP flags to use when allocating the cpumask
 *		used internally by the function.
 *
 * The function might sleep if the GFP flags indicates a non
 * atomic allocation is allowed.
 *
 * Preemption is disabled to protect against CPUs going offline but not online.
 * CPUs going online during the call will not be seen or sent an IPI.
 *
 * You must not call this function with disabled interrupts or
 * from a hardware interrupt handler or from a bottom half handler.
 */
void on_each_cpu_cond(bool (*cond_func)(int cpu, void *info),
			smp_call_func_t func, void *info, bool wait,
			gfp_t gfp_flags)
{
	cpumask_var_t cpus;
	int cpu, ret;

	might_sleep_if(gfpflags_allow_blocking(gfp_flags));

	if (likely(zalloc_cpumask_var(&cpus, (gfp_flags|__GFP_NOWARN)))) {
		preempt_disable();
		for_each_online_cpu(cpu)
			if (cond_func(cpu, info))
				cpumask_set_cpu(cpu, cpus);
		on_each_cpu_mask(cpus, func, info, wait);
		preempt_enable();
		free_cpumask_var(cpus);
	} else {
		/*
		 * No free cpumask, bother. No matter, we'll
		 * just have to IPI them one by one.
		 */
		preempt_disable();
		for_each_online_cpu(cpu)
			if (cond_func(cpu, info)) {
				ret = smp_call_function_single(cpu, func,
								info, wait);
				WARN_ON_ONCE(ret);
			}
		preempt_enable();
	}
}
EXPORT_SYMBOL(on_each_cpu_cond);

static void do_nothing(void *unused)
{
#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
    GBSPIPIPRINTK("<%d> %s():\n", smp_processor_id(), __func__);
#endif
}

/**
 * kick_all_cpus_sync - Force all cpus out of idle
 *
 * Used to synchronize the update of pm_idle function pointer. It's
 * called after the pointer is updated and returns after the dummy
 * callback function has been executed on all cpus. The execution of
 * the function can only happen on the remote cpus after they have
 * left the idle function which had been called via pm_idle function
 * pointer. So it's guaranteed that nothing uses the previous pointer
 * anymore.
 */
void kick_all_cpus_sync(void)
{
#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
#if HYPE_PERF_CRITICAL_DEBUG
	static u64 cnt = 0;
	cnt++;
	if (my_nid > 0) {
		POP_PK("%s(): debug for remote1 boot die "
				"(potential problematic spot (only remote)) "
				"#%llu\n", __func__, cnt);
	}

#endif
    GBSPIPIPRINTK("<BSP> %s():\n", __func__);
#endif
	/* Make sure the change is visible before we kick the cpus */
	smp_mb();
	smp_call_function(do_nothing, NULL, 1);
}
EXPORT_SYMBOL_GPL(kick_all_cpus_sync);

/**
 * wake_up_all_idle_cpus - break all cpus out of idle
 * wake_up_all_idle_cpus try to break all cpus which is in idle state even
 * including idle polling cpus, for non-idle cpus, we will do nothing
 * for them.
 */
void wake_up_all_idle_cpus(void)
{
	int cpu;

	preempt_disable();
	for_each_online_cpu(cpu) {
		if (cpu == smp_processor_id())
			continue;

		wake_up_if_idle(cpu);
	}
	preempt_enable();
}
EXPORT_SYMBOL_GPL(wake_up_all_idle_cpus);
