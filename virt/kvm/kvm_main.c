/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <kvm/iodev.h>

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/reboot.h>
#include <linux/debugfs.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/syscore_ops.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/anon_inodes.h>
#include <linux/profile.h>
#include <linux/kvm_para.h>
#include <linux/pagemap.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/compat.h>
#include <linux/srcu.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/bsearch.h>

#include <asm/processor.h>
#include <asm/io.h>
#include <asm/ioctl.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>

#include "coalesced_mmio.h"
#include "async_pf.h"
#include "vfio.h"

#ifdef CONFIG_POPCORN_HYPE
//#include <popcorn/hype.h>
#include <popcorn/hype_kvm.h>
#include <popcorn/debug.h>
#define RETRY_LOCALFAULT_MOD 4 // appear 4 times
#define RETRY_LOCALFAULT 100
//#define RETRY_LOCALFAULT 10000
//#define RETRY_LOCALFAULT 10000000 //good
//#define RETRY_LOCALFAULT 100000000 // supper enough time
#include <linux/delay.h>
//#include "../../kernel/popcorn/trace_events.h"
#endif

#define CREATE_TRACE_POINTS
#include <trace/events/kvm.h>

MODULE_AUTHOR("Qumranet");
MODULE_LICENSE("GPL");

/* Architectures should define their poll value according to the halt latency */
static unsigned int halt_poll_ns = KVM_HALT_POLL_NS_DEFAULT;
module_param(halt_poll_ns, uint, S_IRUGO | S_IWUSR);

/* Default doubles per-vcpu halt_poll_ns. */
static unsigned int halt_poll_ns_grow = 2;
module_param(halt_poll_ns_grow, int, S_IRUGO);

/* Default resets per-vcpu halt_poll_ns . */
static unsigned int halt_poll_ns_shrink;
module_param(halt_poll_ns_shrink, int, S_IRUGO);

/*
 * Ordering of locks:
 *
 *	kvm->lock --> kvm->slots_lock --> kvm->irq_lock
 */

DEFINE_SPINLOCK(kvm_lock);
static DEFINE_RAW_SPINLOCK(kvm_count_lock);
LIST_HEAD(vm_list);

static cpumask_var_t cpus_hardware_enabled;
static int kvm_usage_count;
static atomic_t hardware_enable_failed;

struct kmem_cache *kvm_vcpu_cache;
EXPORT_SYMBOL_GPL(kvm_vcpu_cache);

static __read_mostly struct preempt_ops kvm_preempt_ops;

struct dentry *kvm_debugfs_dir;
EXPORT_SYMBOL_GPL(kvm_debugfs_dir);

static long kvm_vcpu_ioctl(struct file *file, unsigned int ioctl,
			   unsigned long arg);
#ifdef CONFIG_KVM_COMPAT
static long kvm_vcpu_compat_ioctl(struct file *file, unsigned int ioctl,
				  unsigned long arg);
#endif
static int hardware_enable_all(void);
static void hardware_disable_all(void);

static void kvm_io_bus_destroy(struct kvm_io_bus *bus);

static void kvm_release_pfn_dirty(pfn_t pfn);
static void mark_page_dirty_in_slot(struct kvm_memory_slot *memslot, gfn_t gfn);

__visible bool kvm_rebooting;
EXPORT_SYMBOL_GPL(kvm_rebooting);

static bool largepages_enabled = true;

bool kvm_is_reserved_pfn(pfn_t pfn)
{
	if (pfn_valid(pfn))
		return PageReserved(pfn_to_page(pfn));

	return true;
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
int vcpu_load(struct kvm_vcpu *vcpu)
{
	int cpu;

	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;
	cpu = get_cpu();
	preempt_notifier_register(&vcpu->preempt_notifier);
	kvm_arch_vcpu_load(vcpu, cpu);
	put_cpu();
	return 0;
}
EXPORT_SYMBOL_GPL(vcpu_load);

void vcpu_put(struct kvm_vcpu *vcpu)
{
	preempt_disable();
	kvm_arch_vcpu_put(vcpu);
	preempt_notifier_unregister(&vcpu->preempt_notifier);
	preempt_enable();
	mutex_unlock(&vcpu->mutex);
}
EXPORT_SYMBOL_GPL(vcpu_put);

static void ack_flush(void *_completed)
{
}

bool kvm_make_all_cpus_request(struct kvm *kvm, unsigned int req)
{
	int i, cpu, me;
	cpumask_var_t cpus;
	bool called = true;
	struct kvm_vcpu *vcpu;

	zalloc_cpumask_var(&cpus, GFP_ATOMIC);

	me = get_cpu();
	kvm_for_each_vcpu(i, vcpu, kvm) {
		kvm_make_request(req, vcpu);
		cpu = vcpu->cpu;

		/* Set ->requests bit before we read ->mode */
		smp_mb();

		if (cpus != NULL && cpu != -1 && cpu != me &&
		      kvm_vcpu_exiting_guest_mode(vcpu) != OUTSIDE_GUEST_MODE)
			cpumask_set_cpu(cpu, cpus);
	}
	if (unlikely(cpus == NULL))
		smp_call_function_many(cpu_online_mask, ack_flush, NULL, 1);
	else if (!cpumask_empty(cpus))
		smp_call_function_many(cpus, ack_flush, NULL, 1);
	else
		called = false;
	put_cpu();
	free_cpumask_var(cpus);
	return called;
}

#ifndef CONFIG_HAVE_KVM_ARCH_TLB_FLUSH_ALL
void kvm_flush_remote_tlbs(struct kvm *kvm)
{
	long dirty_count = kvm->tlbs_dirty;

	smp_mb();
	if (kvm_make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH))
		++kvm->stat.remote_tlb_flush;
	cmpxchg(&kvm->tlbs_dirty, dirty_count, 0);
}
EXPORT_SYMBOL_GPL(kvm_flush_remote_tlbs);
#endif

void kvm_reload_remote_mmus(struct kvm *kvm)
{
	kvm_make_all_cpus_request(kvm, KVM_REQ_MMU_RELOAD);
}

void kvm_make_mclock_inprogress_request(struct kvm *kvm)
{
	kvm_make_all_cpus_request(kvm, KVM_REQ_MCLOCK_INPROGRESS);
}

void kvm_make_scan_ioapic_request(struct kvm *kvm)
{
	kvm_make_all_cpus_request(kvm, KVM_REQ_SCAN_IOAPIC);
}

int kvm_vcpu_init(struct kvm_vcpu *vcpu, struct kvm *kvm, unsigned id)
{
	struct page *page;
	int r;

	mutex_init(&vcpu->mutex);
	vcpu->cpu = -1;
	vcpu->kvm = kvm;
	vcpu->vcpu_id = id;
	vcpu->pid = NULL;
	vcpu->halt_poll_ns = 0;
	init_waitqueue_head(&vcpu->wq);
	kvm_async_pf_vcpu_init(vcpu);

	vcpu->pre_pcpu = -1;
	INIT_LIST_HEAD(&vcpu->blocked_vcpu_list);

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		r = -ENOMEM;
		goto fail;
	}
	vcpu->run = page_address(page);

	kvm_vcpu_set_in_spin_loop(vcpu, false);
	kvm_vcpu_set_dy_eligible(vcpu, false);
	vcpu->preempted = false;

	r = kvm_arch_vcpu_init(vcpu);
	if (r < 0)
		goto fail_free_run;

#ifdef CONFIG_POPCORN_HYPE
	VCPUPRINTK("%s(): vcpu %d (kern)vcpu->run %p created!!\n",
										__func__, id, vcpu->run);
#endif
	return 0;

fail_free_run:
	free_page((unsigned long)vcpu->run);
fail:
	return r;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_init);

void kvm_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	put_pid(vcpu->pid);
	kvm_arch_vcpu_uninit(vcpu);
	free_page((unsigned long)vcpu->run);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_uninit);

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
static inline struct kvm *mmu_notifier_to_kvm(struct mmu_notifier *mn)
{
	return container_of(mn, struct kvm, mmu_notifier);
}

static void kvm_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
					     struct mm_struct *mm,
					     unsigned long address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int need_tlb_flush, idx;
#if defined(CONFIG_POPCORN_HYPE) && defined(CONFIG_POPCORN_STAT)
	/* USED: DSM pg fault ->
		__mmu_notifier_invalidate_page -> kvm_mmu_notifier_invalidate_page */
	//trace_kvm_ept_inv(address);
#endif

	/*
	 * When ->invalidate_page runs, the linux pte has been zapped
	 * already but the page is still allocated until
	 * ->invalidate_page returns. So if we increase the sequence
	 * here the kvm page fault will notice if the spte can't be
	 * established because the page is going to be freed. If
	 * instead the kvm page fault establishes the spte before
	 * ->invalidate_page runs, kvm_unmap_hva will release it
	 * before returning.
	 *
	 * The sequence increase only need to be seen at spin_unlock
	 * time, and not at spin_lock time.
	 *
	 * Increasing the sequence after the spin_unlock would be
	 * unsafe because the kvm page fault could then establish the
	 * pte after kvm_unmap_hva returned, without noticing the page
	 * is going to be freed.
	 */
	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	kvm->mmu_notifier_seq++;
	need_tlb_flush = kvm_unmap_hva(kvm, address) | kvm->tlbs_dirty;
	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);

	kvm_arch_mmu_notifier_invalidate_page(kvm, address);

	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_change_pte(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long address,
					pte_t pte)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	kvm->mmu_notifier_seq++;
	kvm_set_spte_hva(kvm, address, pte);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
						    struct mm_struct *mm,
						    unsigned long start,
						    unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int need_tlb_flush = 0, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	/*
	 * The count increase must become visible at unlock time as no
	 * spte can be established without taking the mmu_lock and
	 * count is also read inside the mmu_lock critical section.
	 */
	kvm->mmu_notifier_count++;
	need_tlb_flush = kvm_unmap_hva_range(kvm, start, end);
	need_tlb_flush |= kvm->tlbs_dirty;
	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);

	spin_lock(&kvm->mmu_lock);
	/*
	 * This sequence increase will notify the kvm page fault that
	 * the page that is going to be mapped in the spte could have
	 * been freed.
	 */
	kvm->mmu_notifier_seq++;
	smp_wmb();
	/*
	 * The above sequence increase must be visible before the
	 * below count decrease, which is ensured by the smp_wmb above
	 * in conjunction with the smp_rmb in mmu_notifier_retry().
	 */
	kvm->mmu_notifier_count--;
	spin_unlock(&kvm->mmu_lock);

	BUG_ON(kvm->mmu_notifier_count < 0);
}

static int kvm_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
					      struct mm_struct *mm,
					      unsigned long start,
					      unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	young = kvm_age_hva(kvm, start, end);
	if (young)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static int kvm_mmu_notifier_clear_young(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long start,
					unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	/*
	 * Even though we do not flush TLB, this will still adversely
	 * affect performance on pre-Haswell Intel EPT, where there is
	 * no EPT Access Bit to clear so that we have to tear down EPT
	 * tables instead. If we find this unacceptable, we can always
	 * add a parameter to kvm_age_hva so that it effectively doesn't
	 * do anything on clear_young.
	 *
	 * Also note that currently we never issue secondary TLB flushes
	 * from clear_young, leaving this job up to the regular system
	 * cadence. If we find this inaccurate, we might come up with a
	 * more sophisticated heuristic later.
	 */
	young = kvm_age_hva(kvm, start, end);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static int kvm_mmu_notifier_test_young(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	young = kvm_test_age_hva(kvm, address);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static void kvm_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	kvm_arch_flush_shadow_all(kvm);
	srcu_read_unlock(&kvm->srcu, idx);
}

static const struct mmu_notifier_ops kvm_mmu_notifier_ops = {
	.invalidate_page	= kvm_mmu_notifier_invalidate_page,
	.invalidate_range_start	= kvm_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= kvm_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= kvm_mmu_notifier_clear_flush_young,
	.clear_young		= kvm_mmu_notifier_clear_young,
	.test_young		= kvm_mmu_notifier_test_young,
	.change_pte		= kvm_mmu_notifier_change_pte,
	.release		= kvm_mmu_notifier_release,
};

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	kvm->mmu_notifier.ops = &kvm_mmu_notifier_ops;
	return mmu_notifier_register(&kvm->mmu_notifier, current->mm);
}

#ifdef CONFIG_POPCORN_HYPE
static int kvm_init_mmu_notifier_tsk(struct task_struct *tsk, struct kvm *kvm)
{
	kvm->mmu_notifier.ops = &kvm_mmu_notifier_ops;
	return mmu_notifier_register(&kvm->mmu_notifier, tsk->mm);
}
#endif

#else  /* !(CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER) */

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	return 0;
}

#endif /* CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER */

static struct kvm_memslots *kvm_alloc_memslots(void)
{
	int i;
	struct kvm_memslots *slots;

	slots = kvm_kvzalloc(sizeof(struct kvm_memslots));
	if (!slots)
		return NULL;

	/*
	 * Init kvm generation close to the maximum to easily test the
	 * code of handling generation number wrap-around.
	 */
	slots->generation = -150;
	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++)
		slots->id_to_index[i] = slots->memslots[i].id = i;

	return slots;
}

static void kvm_destroy_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	if (!memslot->dirty_bitmap)
		return;

	kvfree(memslot->dirty_bitmap);
	memslot->dirty_bitmap = NULL;
}

/*
 * Free any memory in @free but not in @dont.
 */
static void kvm_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free,
			      struct kvm_memory_slot *dont)
{
	if (!dont || free->dirty_bitmap != dont->dirty_bitmap)
		kvm_destroy_dirty_bitmap(free);

	kvm_arch_free_memslot(kvm, free, dont);

	free->npages = 0;
}

static void kvm_free_memslots(struct kvm *kvm, struct kvm_memslots *slots)
{
	struct kvm_memory_slot *memslot;

	if (!slots)
		return;

	kvm_for_each_memslot(memslot, slots)
		kvm_free_memslot(kvm, memslot, NULL);

	kvfree(slots);
}

#ifdef CONFIG_POPCORN_HYPE
static struct kvm *kvm_create_vm_tsk(struct task_struct *tsk, unsigned long type)
{
	int r, i;
	struct kvm *kvm = kvm_arch_alloc_vm();

	if (!kvm)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&kvm->mmu_lock);
	atomic_inc(&tsk->mm->mm_count);
	kvm->mm = tsk->mm;
	kvm_eventfd_init(kvm);
	mutex_init(&kvm->lock);
	mutex_init(&kvm->irq_lock);
	mutex_init(&kvm->slots_lock);
	atomic_set(&kvm->users_count, 1);
	INIT_LIST_HEAD(&kvm->devices);

	r = kvm_arch_init_vm(kvm, type);
	if (r)
		goto out_err_no_disable;

	r = hardware_enable_all();
	if (r)
		goto out_err_no_disable;

#ifdef CONFIG_HAVE_KVM_IRQFD
	INIT_HLIST_HEAD(&kvm->irq_ack_notifier_list);
#endif

	BUILD_BUG_ON(KVM_MEM_SLOTS_NUM > SHRT_MAX);

	r = -ENOMEM;
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		kvm->memslots[i] = kvm_alloc_memslots();
		if (!kvm->memslots[i])
			goto out_err_no_srcu;
	}

	if (init_srcu_struct(&kvm->srcu))
		goto out_err_no_srcu;
	if (init_srcu_struct(&kvm->irq_srcu))
		goto out_err_no_irq_srcu;
	for (i = 0; i < KVM_NR_BUSES; i++) {
		kvm->buses[i] = kzalloc(sizeof(struct kvm_io_bus),
					GFP_KERNEL);
		if (!kvm->buses[i])
			goto out_err;
	}

	r = kvm_init_mmu_notifier_tsk(tsk, kvm);
	if (r)
		goto out_err;

	spin_lock(&kvm_lock);
	list_add(&kvm->vm_list, &vm_list);
	spin_unlock(&kvm_lock);

	preempt_notifier_inc();

	HPPRINTK("%s: Done\n", __func__);
	return kvm;

out_err:
	cleanup_srcu_struct(&kvm->irq_srcu);
out_err_no_irq_srcu:
	cleanup_srcu_struct(&kvm->srcu);
out_err_no_srcu:
	hardware_disable_all();
out_err_no_disable:
	for (i = 0; i < KVM_NR_BUSES; i++)
		kfree(kvm->buses[i]);
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++)
		kvm_free_memslots(kvm, kvm->memslots[i]);
	kvm_arch_free_vm(kvm);
	mmdrop(tsk->mm);
	return ERR_PTR(r);
}
#endif

static struct kvm *kvm_create_vm(unsigned long type)
{
	int r, i;
	struct kvm *kvm = kvm_arch_alloc_vm();

	if (!kvm)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&kvm->mmu_lock);
	atomic_inc(&current->mm->mm_count);
	kvm->mm = current->mm;
	kvm_eventfd_init(kvm);
	mutex_init(&kvm->lock);
	mutex_init(&kvm->irq_lock);
	mutex_init(&kvm->slots_lock);
	atomic_set(&kvm->users_count, 1);
	INIT_LIST_HEAD(&kvm->devices);

	r = kvm_arch_init_vm(kvm, type);
	if (r)
		goto out_err_no_disable;

	r = hardware_enable_all();
	if (r)
		goto out_err_no_disable;

#ifdef CONFIG_HAVE_KVM_IRQFD
	INIT_HLIST_HEAD(&kvm->irq_ack_notifier_list);
#endif

	BUILD_BUG_ON(KVM_MEM_SLOTS_NUM > SHRT_MAX);

	r = -ENOMEM;
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		kvm->memslots[i] = kvm_alloc_memslots();
		if (!kvm->memslots[i])
			goto out_err_no_srcu;
	}

	if (init_srcu_struct(&kvm->srcu))
		goto out_err_no_srcu;
	if (init_srcu_struct(&kvm->irq_srcu))
		goto out_err_no_irq_srcu;
	for (i = 0; i < KVM_NR_BUSES; i++) {
		kvm->buses[i] = kzalloc(sizeof(struct kvm_io_bus),
					GFP_KERNEL);
		if (!kvm->buses[i])
			goto out_err;
	}

	r = kvm_init_mmu_notifier(kvm);
	if (r)
		goto out_err;

	spin_lock(&kvm_lock);
	list_add(&kvm->vm_list, &vm_list);
	spin_unlock(&kvm_lock);

	preempt_notifier_inc();

	return kvm;

out_err:
	cleanup_srcu_struct(&kvm->irq_srcu);
out_err_no_irq_srcu:
	cleanup_srcu_struct(&kvm->srcu);
out_err_no_srcu:
	hardware_disable_all();
out_err_no_disable:
	for (i = 0; i < KVM_NR_BUSES; i++)
		kfree(kvm->buses[i]);
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++)
		kvm_free_memslots(kvm, kvm->memslots[i]);
	kvm_arch_free_vm(kvm);
	mmdrop(current->mm);
	return ERR_PTR(r);
}

/*
 * Avoid using vmalloc for a small buffer.
 * Should not be used when the size is statically known.
 */
void *kvm_kvzalloc(unsigned long size)
{
	if (size > PAGE_SIZE)
		return vzalloc(size);
	else
		return kzalloc(size, GFP_KERNEL);
}

static void kvm_destroy_devices(struct kvm *kvm)
{
	struct list_head *node, *tmp;

	list_for_each_safe(node, tmp, &kvm->devices) {
		struct kvm_device *dev =
			list_entry(node, struct kvm_device, vm_node);

		list_del(node);
		dev->ops->destroy(dev);
	}
}

static void kvm_destroy_vm(struct kvm *kvm)
{
	int i;
	struct mm_struct *mm = kvm->mm;

	kvm_arch_sync_events(kvm);
	spin_lock(&kvm_lock);
	list_del(&kvm->vm_list);
	spin_unlock(&kvm_lock);
	kvm_free_irq_routing(kvm);
	for (i = 0; i < KVM_NR_BUSES; i++) {
		if (kvm->buses[i])
			kvm_io_bus_destroy(kvm->buses[i]);
		kvm->buses[i] = NULL;
	}
	kvm_coalesced_mmio_free(kvm);
#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
	mmu_notifier_unregister(&kvm->mmu_notifier, kvm->mm);
#else
	kvm_arch_flush_shadow_all(kvm);
#endif
	kvm_arch_destroy_vm(kvm);
	kvm_destroy_devices(kvm);
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++)
		kvm_free_memslots(kvm, kvm->memslots[i]);
	cleanup_srcu_struct(&kvm->irq_srcu);
	cleanup_srcu_struct(&kvm->srcu);
	kvm_arch_free_vm(kvm);
	preempt_notifier_dec();
	hardware_disable_all();
	mmdrop(mm);
}

void kvm_get_kvm(struct kvm *kvm)
{
	atomic_inc(&kvm->users_count);
}
EXPORT_SYMBOL_GPL(kvm_get_kvm);

void kvm_put_kvm(struct kvm *kvm)
{
	if (atomic_dec_and_test(&kvm->users_count))
		kvm_destroy_vm(kvm);
}
EXPORT_SYMBOL_GPL(kvm_put_kvm);


static int kvm_vm_release(struct inode *inode, struct file *filp)
{
	struct kvm *kvm = filp->private_data;

	kvm_irqfd_release(kvm);

	kvm_put_kvm(kvm);
	return 0;
}

/*
 * Allocation size is twice as large as the actual dirty bitmap size.
 * See x86's kvm_vm_ioctl_get_dirty_log() why this is needed.
 */
static int kvm_create_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	unsigned long dirty_bytes = 2 * kvm_dirty_bitmap_bytes(memslot);

	memslot->dirty_bitmap = kvm_kvzalloc(dirty_bytes);
	if (!memslot->dirty_bitmap)
		return -ENOMEM;

	return 0;
}

/*
 * Insert memslot and re-sort memslots based on their GFN,
 * so binary search could be used to lookup GFN.
 * Sorting algorithm takes advantage of having initially
 * sorted array and known changed memslot position.
 */
static void update_memslots(struct kvm_memslots *slots,
			    struct kvm_memory_slot *new)
{
	int id = new->id;
	int i = slots->id_to_index[id];
	struct kvm_memory_slot *mslots = slots->memslots;

	WARN_ON(mslots[i].id != id);
	if (!new->npages) {
		WARN_ON(!mslots[i].npages);
		if (mslots[i].npages)
			slots->used_slots--;
	} else {
		if (!mslots[i].npages)
			slots->used_slots++;
	}

	while (i < KVM_MEM_SLOTS_NUM - 1 &&
	       new->base_gfn <= mslots[i + 1].base_gfn) {
		if (!mslots[i + 1].npages)
			break;
		mslots[i] = mslots[i + 1];
		slots->id_to_index[mslots[i].id] = i;
		i++;
	}

	/*
	 * The ">=" is needed when creating a slot with base_gfn == 0,
	 * so that it moves before all those with base_gfn == npages == 0.
	 *
	 * On the other hand, if new->npages is zero, the above loop has
	 * already left i pointing to the beginning of the empty part of
	 * mslots, and the ">=" would move the hole backwards in this
	 * case---which is wrong.  So skip the loop when deleting a slot.
	 */
	if (new->npages) {
		while (i > 0 &&
		       new->base_gfn >= mslots[i - 1].base_gfn) {
			mslots[i] = mslots[i - 1];
			slots->id_to_index[mslots[i].id] = i;
			i--;
		}
	} else
		WARN_ON_ONCE(i != slots->used_slots);

	mslots[i] = *new;
	slots->id_to_index[mslots[i].id] = i;
}

static int check_memory_region_flags(const struct kvm_userspace_memory_region *mem)
{
	u32 valid_flags = KVM_MEM_LOG_DIRTY_PAGES;

#ifdef __KVM_HAVE_READONLY_MEM
	valid_flags |= KVM_MEM_READONLY;
#endif

	if (mem->flags & ~valid_flags)
		return -EINVAL;

	return 0;
}

static struct kvm_memslots *install_new_memslots(struct kvm *kvm,
		int as_id, struct kvm_memslots *slots)
{
	struct kvm_memslots *old_memslots = __kvm_memslots(kvm, as_id);

	/*
	 * Set the low bit in the generation, which disables SPTE caching
	 * until the end of synchronize_srcu_expedited.
	 */
	WARN_ON(old_memslots->generation & 1);
	slots->generation = old_memslots->generation + 1;

	rcu_assign_pointer(kvm->memslots[as_id], slots);
	synchronize_srcu_expedited(&kvm->srcu);

	/*
	 * Increment the new memslot generation a second time. This prevents
	 * vm exits that race with memslot updates from caching a memslot
	 * generation that will (potentially) be valid forever.
	 */
	slots->generation++;

	kvm_arch_memslots_updated(kvm, slots);

	return old_memslots;
}

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding kvm->slots_lock for write.
 */
int __kvm_set_memory_region(struct kvm *kvm,
			    const struct kvm_userspace_memory_region *mem)
{
	int r;
	gfn_t base_gfn;
	unsigned long npages;
	struct kvm_memory_slot *slot;
	struct kvm_memory_slot old, new; /* new: waiting for setup */
	struct kvm_memslots *slots = NULL, *old_memslots;
	int as_id, id;
	enum kvm_mr_change change;

	r = check_memory_region_flags(mem);
	if (r)
		goto out;

	r = -EINVAL;
	as_id = mem->slot >> 16;
	id = (u16)mem->slot;

	/* General sanity checks */
	if (mem->memory_size & (PAGE_SIZE - 1))
		goto out;
	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		goto out;
	/* We can read the guest memory with __xxx_user() later on. */
	if ((id < KVM_USER_MEM_SLOTS) &&
	    ((mem->userspace_addr & (PAGE_SIZE - 1)) ||
	     !access_ok(VERIFY_WRITE,
			(void __user *)(unsigned long)mem->userspace_addr,
			mem->memory_size)))
		goto out;
	if (as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_MEM_SLOTS_NUM)
		goto out;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	slot = id_to_memslot(__kvm_memslots(kvm, as_id), id);
	base_gfn = mem->guest_phys_addr >> PAGE_SHIFT;
	npages = mem->memory_size >> PAGE_SHIFT;

#ifdef CONFIG_POPCORN_HYPE
	DDPRINTK("%s(): from usr - guest_phys_addr %llx size %llx\n",
			__func__, mem->guest_phys_addr, mem->memory_size);
#endif
	if (npages > KVM_MEM_MAX_NR_PAGES)
		goto out;

	new = old = *slot;

	new.id = id;
	new.base_gfn = base_gfn;
	new.npages = npages;
	new.flags = mem->flags;

	/* Determin operation */
	if (npages) { /* !DELETE */
		if (!old.npages) /* Brand new */
			change = KVM_MR_CREATE;
		else { /* Modify an existing slot. */
			if ((mem->userspace_addr != old.userspace_addr) ||
			    (npages != old.npages) ||
			    ((new.flags ^ old.flags) & KVM_MEM_READONLY))
				goto out;

			if (base_gfn != old.base_gfn)
				change = KVM_MR_MOVE;
			else if (new.flags != old.flags)
				change = KVM_MR_FLAGS_ONLY;
			else { /* Nothing to change. */
				r = 0;
				goto out;
			}
		}
	} else {
		if (!old.npages)
			goto out;

		change = KVM_MR_DELETE;
		new.base_gfn = 0;
		new.flags = 0;
	}

	if ((change == KVM_MR_CREATE) || (change == KVM_MR_MOVE)) {
		/* Check for existing memslots overlaps */
		r = -EEXIST;
		kvm_for_each_memslot(slot, __kvm_memslots(kvm, as_id)) {
			if (slot->id == id)
				continue;
			if (!((base_gfn + npages <= slot->base_gfn) ||
			      (base_gfn >= slot->base_gfn + slot->npages)))
				goto out;
		}
	}

	/* Free page dirty bitmap if unneeded */
	if (!(new.flags & KVM_MEM_LOG_DIRTY_PAGES))
		new.dirty_bitmap = NULL;

	r = -ENOMEM;
	if (change == KVM_MR_CREATE) {
		new.userspace_addr = mem->userspace_addr;

		if (kvm_arch_create_memslot(kvm, &new, npages))
			goto out_free;
	}

	/* Allocate page dirty bitmap if needed */
	if ((new.flags & KVM_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap) {
		if (kvm_create_dirty_bitmap(&new) < 0)
			goto out_free;
	}

	slots = kvm_kvzalloc(sizeof(struct kvm_memslots));
	if (!slots)
		goto out_free;
	memcpy(slots, __kvm_memslots(kvm, as_id), sizeof(struct kvm_memslots));

	if ((change == KVM_MR_DELETE) || (change == KVM_MR_MOVE)) {
		slot = id_to_memslot(slots, id);
		slot->flags |= KVM_MEMSLOT_INVALID;

		old_memslots = install_new_memslots(kvm, as_id, slots);

		/* slot was deleted or moved, clear iommu mapping */
		kvm_iommu_unmap_pages(kvm, &old);
		/* From this point no new shadow pages pointing to a deleted,
		 * or moved, memslot will be created.
		 *
		 * validation of sp->gfn happens in:
		 *	- gfn_to_hva (kvm_read_guest, gfn_to_pfn)
		 *	- kvm_is_visible_gfn (mmu_check_roots)
		 */
		kvm_arch_flush_shadow_memslot(kvm, slot);

		/*
		 * We can re-use the old_memslots from above, the only difference
		 * from the currently installed memslots is the invalid flag.  This
		 * will get overwritten by update_memslots anyway.
		 */
		slots = old_memslots;
	}

	r = kvm_arch_prepare_memory_region(kvm, &new, mem, change);
	if (r)
		goto out_slots;

	/* actual memory is freed via old in kvm_free_memslot below */
	if (change == KVM_MR_DELETE) {
		new.dirty_bitmap = NULL;
		memset(&new.arch, 0, sizeof(new.arch));
	}

	update_memslots(slots, &new);
	old_memslots = install_new_memslots(kvm, as_id, slots);

	kvm_arch_commit_memory_region(kvm, mem, &old, &new, change);

	kvm_free_memslot(kvm, &old, &new);
	kvfree(old_memslots);

#ifdef CONFIG_POPCORN_HYPE
	/* From 1. KVM_SET_TSS_ADDR -> vmx_set_tss_addr -> __x86_set_memory_region
			2. KVM_SET_USER_MEMORY_REGION
			3. KVM_CREATE_VCPU					(ordered) */
	DDPRINTK("%s(): as_id %d base_gfn[%d(usr)/%d] "
					"base %llx pgs %lx uaddr %lx\n",
					__func__, as_id, new.id, slots->used_slots - 1, //mem->slot
					new.base_gfn,
					new.npages,
					new.userspace_addr);
	//if (current->at_remote) { dump_stack(); }
#endif

	/*
	 * IOMMU mapping:  New slots need to be mapped.  Old slots need to be
	 * un-mapped and re-mapped if their base changes.  Since base change
	 * unmapping is handled above with slot deletion, mapping alone is
	 * needed here.  Anything else the iommu might care about for existing
	 * slots (size changes, userspace addr changes and read-only flag
	 * changes) is disallowed above, so any other attribute changes getting
	 * here can be skipped.
	 */
	if (as_id == 0 && (change == KVM_MR_CREATE || change == KVM_MR_MOVE)) {
		r = kvm_iommu_map_pages(kvm, &new);
		return r;
	}

	return 0;

out_slots:
	kvfree(slots);
out_free:
	kvm_free_memslot(kvm, &new, &old);
out:
	return r;
}
EXPORT_SYMBOL_GPL(__kvm_set_memory_region);

int kvm_set_memory_region(struct kvm *kvm,
			  const struct kvm_userspace_memory_region *mem)
{
	int r;
	mutex_lock(&kvm->slots_lock);
	r = __kvm_set_memory_region(kvm, mem);
	mutex_unlock(&kvm->slots_lock);
	return r;
}
EXPORT_SYMBOL_GPL(kvm_set_memory_region);

static int kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
					  struct kvm_userspace_memory_region *mem)
{
#ifdef CONFIG_POPCORN_HYPE
	DDPRINTK("%s(): \n", __func__);
#endif
	if ((u16)mem->slot >= KVM_USER_MEM_SLOTS)
		return -EINVAL;

	return kvm_set_memory_region(kvm, mem);
}

int kvm_get_dirty_log(struct kvm *kvm,
			struct kvm_dirty_log *log, int *is_dirty)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int r, i, as_id, id;
	unsigned long n;
	unsigned long any = 0;

	r = -EINVAL;
	as_id = log->slot >> 16;
	id = (u16)log->slot;
	if (as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_USER_MEM_SLOTS)
		goto out;

	slots = __kvm_memslots(kvm, as_id);
	memslot = id_to_memslot(slots, id);
	r = -ENOENT;
	if (!memslot->dirty_bitmap)
		goto out;

	n = kvm_dirty_bitmap_bytes(memslot);

	for (i = 0; !any && i < n/sizeof(long); ++i)
		any = memslot->dirty_bitmap[i];

	r = -EFAULT;
	if (copy_to_user(log->dirty_bitmap, memslot->dirty_bitmap, n))
		goto out;

	if (any)
		*is_dirty = 1;

	r = 0;
out:
	return r;
}
EXPORT_SYMBOL_GPL(kvm_get_dirty_log);

#ifdef CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT
/**
 * kvm_get_dirty_log_protect - get a snapshot of dirty pages, and if any pages
 *	are dirty write protect them for next write.
 * @kvm:	pointer to kvm instance
 * @log:	slot id and address to which we copy the log
 * @is_dirty:	flag set if any page is dirty
 *
 * We need to keep it in mind that VCPU threads can write to the bitmap
 * concurrently. So, to avoid losing track of dirty pages we keep the
 * following order:
 *
 *    1. Take a snapshot of the bit and clear it if needed.
 *    2. Write protect the corresponding page.
 *    3. Copy the snapshot to the userspace.
 *    4. Upon return caller flushes TLB's if needed.
 *
 * Between 2 and 4, the guest may write to the page using the remaining TLB
 * entry.  This is not a problem because the page is reported dirty using
 * the snapshot taken before and step 4 ensures that writes done after
 * exiting to userspace will be logged for the next call.
 *
 */
int kvm_get_dirty_log_protect(struct kvm *kvm,
			struct kvm_dirty_log *log, bool *is_dirty)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int r, i, as_id, id;
	unsigned long n;
	unsigned long *dirty_bitmap;
	unsigned long *dirty_bitmap_buffer;

	r = -EINVAL;
	as_id = log->slot >> 16;
	id = (u16)log->slot;
	if (as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_USER_MEM_SLOTS)
		goto out;

	slots = __kvm_memslots(kvm, as_id);
	memslot = id_to_memslot(slots, id);

	dirty_bitmap = memslot->dirty_bitmap;
	r = -ENOENT;
	if (!dirty_bitmap)
		goto out;

	n = kvm_dirty_bitmap_bytes(memslot);

	dirty_bitmap_buffer = dirty_bitmap + n / sizeof(long);
	memset(dirty_bitmap_buffer, 0, n);

	spin_lock(&kvm->mmu_lock);
	*is_dirty = false;
	for (i = 0; i < n / sizeof(long); i++) {
		unsigned long mask;
		gfn_t offset;

		if (!dirty_bitmap[i])
			continue;

		*is_dirty = true;

		mask = xchg(&dirty_bitmap[i], 0);
		dirty_bitmap_buffer[i] = mask;

		if (mask) {
			offset = i * BITS_PER_LONG;
			kvm_arch_mmu_enable_log_dirty_pt_masked(kvm, memslot,
								offset, mask);
		}
	}

	spin_unlock(&kvm->mmu_lock);

	r = -EFAULT;
	if (copy_to_user(log->dirty_bitmap, dirty_bitmap_buffer, n))
		goto out;

	r = 0;
out:
	return r;
}
EXPORT_SYMBOL_GPL(kvm_get_dirty_log_protect);
#endif

bool kvm_largepages_enabled(void)
{
	return largepages_enabled;
}

void kvm_disable_largepages(void)
{
	largepages_enabled = false;
}
EXPORT_SYMBOL_GPL(kvm_disable_largepages);

struct kvm_memory_slot *gfn_to_memslot(struct kvm *kvm, gfn_t gfn)
{
	return __gfn_to_memslot(kvm_memslots(kvm), gfn);
}
EXPORT_SYMBOL_GPL(gfn_to_memslot);

struct kvm_memory_slot *kvm_vcpu_gfn_to_memslot(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return __gfn_to_memslot(kvm_vcpu_memslots(vcpu), gfn);
}

int kvm_is_visible_gfn(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot = gfn_to_memslot(kvm, gfn);

	if (!memslot || memslot->id >= KVM_USER_MEM_SLOTS ||
	      memslot->flags & KVM_MEMSLOT_INVALID)
		return 0;

	return 1;
}
EXPORT_SYMBOL_GPL(kvm_is_visible_gfn);

unsigned long kvm_host_page_size(struct kvm *kvm, gfn_t gfn)
{
	struct vm_area_struct *vma;
	unsigned long addr, size;

	size = PAGE_SIZE;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return PAGE_SIZE;

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, addr);
	if (!vma)
		goto out;

	size = vma_kernel_pagesize(vma);

out:
#ifdef CONFIG_POPCORN_HYPE
	; /* TODO 0523 */
#endif
	up_read(&current->mm->mmap_sem);
	return size;
}

static bool memslot_is_readonly(struct kvm_memory_slot *slot)
{
	return slot->flags & KVM_MEM_READONLY;
}

static unsigned long __gfn_to_hva_many(struct kvm_memory_slot *slot, gfn_t gfn,
				       gfn_t *nr_pages, bool write)
{
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_STAT
	// even 0x1a0c many forever.........
	//if (gfn == 0x99 || (gfn == 0x1a0c)) {
	if (gfn == 0x99) {
		POP_PK("%s(): [%d] <%s> - gfn %llx 0 REMOTE DIES HERE "
				"(cannot pass this check) [[[[slot %p]]] slot->flags %x\n",
				__func__, current->pid, "?", gfn, slot,slot?slot->flags:0);
	}
#endif
#endif

	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return KVM_HVA_ERR_BAD;
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_STAT
	if (gfn == 0x99) {
		POP_PK("%s(): [%d] <%s> gfn %llx - 1\n", __func__, current->pid, "?", gfn);
	}
#endif
#endif
	if (memslot_is_readonly(slot) && write)
		return KVM_HVA_ERR_RO_BAD;

	if (nr_pages)
		*nr_pages = slot->npages - (gfn - slot->base_gfn);

#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_STAT
	if (gfn == 0x99) {
		POP_PK("%s(): [%d] <%s> nr_pages(dec) %lld slot %p || hva [[[%llx]]] = "
					"->userspace_addr %lx + (gfn %llx ->base_gfn %llx) * %lu\n",
					__func__, current->pid, "?",
					nr_pages ? *nr_pages : -1, slot,
					slot ? slot->userspace_addr +
						(gfn - slot->base_gfn) * PAGE_SIZE : -1,
					slot ? slot->userspace_addr : -1,
					gfn, slot ? slot->base_gfn : -1, PAGE_SIZE);
	}
#endif
#endif
	return __gfn_to_hva_memslot(slot, gfn);
}

unsigned long gfn_to_hva_many_pub(struct kvm_memory_slot *slot, gfn_t gfn,
				       gfn_t *nr_pages, bool write)
{
#ifdef CONFIG_POPCORN_HYPE
	// even 0x1a0c many forever.........
	//if (gfn == 0x99 || (gfn == 0x1a0c)) {
	if (gfn == 0x99) {
		POP_PK("%s(): [%d] <%s> - gfn %llx 0 REMOTE DIES HERE "
				"(cannot pass this check) [[[[slot %p]]] slot->flags %x\n",
				__func__, current->pid, "?", gfn, slot,slot?slot->flags:0);
	}
#endif

	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return KVM_HVA_ERR_BAD;
#ifdef CONFIG_POPCORN_HYPE
	if (gfn == 0x99) {
		POP_PK("%s(): [%d] <%s> gfn %llx - 1\n", __func__, current->pid, "?", gfn);
	}
#endif
	if (memslot_is_readonly(slot) && write)
		return KVM_HVA_ERR_RO_BAD;

	if (nr_pages)
		*nr_pages = slot->npages - (gfn - slot->base_gfn);

#ifdef CONFIG_POPCORN_HYPE
	if (gfn == 0x99) {
		POP_PK("%s(): [%d] <%s> nr_pages(dec) %lld slot %p || hva [[[%llx]]] = "
					"->userspace_addr %lx + (gfn %llx ->base_gfn %llx) * %lu\n",
					__func__, current->pid, "?",
					nr_pages ? *nr_pages : -1, slot,
					slot ? slot->userspace_addr +
						(gfn - slot->base_gfn) * PAGE_SIZE : -1,
					slot ? slot->userspace_addr : -1,
					gfn, slot ? slot->base_gfn : -1, PAGE_SIZE);
	}
#endif
	return __gfn_to_hva_memslot(slot, gfn);
}
//EXPORT_SYMBOL_GPL(gfn_to_hva_many_pub);

#ifdef CONFIG_POPCORN_HYPE /* debug */
unsigned long pop_gfn_to_hva_many(struct kvm_memory_slot *slot, gfn_t gfn,
				       gfn_t *nr_pages, bool write)
{
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return KVM_HVA_ERR_BAD;
	if (memslot_is_readonly(slot) && write)
		return KVM_HVA_ERR_RO_BAD;

	if (nr_pages)
		*nr_pages = slot->npages - (gfn - slot->base_gfn);

	return __gfn_to_hva_memslot(slot, gfn);
}
#endif

static unsigned long gfn_to_hva_many(struct kvm_memory_slot *slot, gfn_t gfn,
				     gfn_t *nr_pages)
{
	return __gfn_to_hva_many(slot, gfn, nr_pages, true);
}

unsigned long gfn_to_hva_memslot(struct kvm_memory_slot *slot,
					gfn_t gfn)
{
	return gfn_to_hva_many(slot, gfn, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_hva_memslot);

unsigned long gfn_to_hva(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_hva_many(gfn_to_memslot(kvm, gfn), gfn, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_hva);

unsigned long kvm_vcpu_gfn_to_hva(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return gfn_to_hva_many(kvm_vcpu_gfn_to_memslot(vcpu, gfn), gfn, NULL);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_gfn_to_hva);

/*
 * If writable is set to false, the hva returned by this function is only
 * allowed to be read.
 */
unsigned long gfn_to_hva_memslot_prot(struct kvm_memory_slot *slot,
				      gfn_t gfn, bool *writable)
{
	unsigned long hva = __gfn_to_hva_many(slot, gfn, NULL, false);

	if (!kvm_is_error_hva(hva) && writable)
		*writable = !memslot_is_readonly(slot);

	return hva;
}

unsigned long gfn_to_hva_prot(struct kvm *kvm, gfn_t gfn, bool *writable)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	return gfn_to_hva_memslot_prot(slot, gfn, writable);
}

unsigned long kvm_vcpu_gfn_to_hva_prot(struct kvm_vcpu *vcpu, gfn_t gfn, bool *writable)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	return gfn_to_hva_memslot_prot(slot, gfn, writable);
}

static int get_user_page_nowait(struct task_struct *tsk, struct mm_struct *mm,
	unsigned long start, int write, struct page **page)
{
	int flags = FOLL_TOUCH | FOLL_NOWAIT | FOLL_HWPOISON | FOLL_GET;
	/* special flag for gup */
#ifdef CONFIG_POPCORN_HYPE
	flags = FOLL_TOUCH | FOLL_HWPOISON | FOLL_GET;
	/* FOLL_NOWAIT will return immediately */
#endif

	if (write)
		flags |= FOLL_WRITE;

	return __get_user_pages(tsk, mm, start, 1, flags, page, NULL, NULL);
}

static inline int check_user_page_hwpoison(unsigned long addr)
{
	int rc, flags = FOLL_TOUCH | FOLL_HWPOISON | FOLL_WRITE;

	rc = __get_user_pages(current, current->mm, addr, 1,
			      flags, NULL, NULL, NULL);
	return rc == -EHWPOISON;
}

/*
 * The atomic path to get the writable pfn which will be stored in @pfn,
 * true indicates success, otherwise false is returned.
 */
static bool hva_to_pfn_fast(unsigned long addr, bool atomic, bool *async,
			    bool write_fault, bool *writable, pfn_t *pfn)
{
	struct page *page[1];
	int npages;

	if (!(async || atomic))
		return false;

	/*
	 * Fast pin a writable pfn only if it is a write fault request
	 * or the caller allows to map a writable pfn for a read fault
	 * request.
	 */
	if (!(write_fault || writable))
		return false;

	/* pophype - all except write_fault = 0 (R fault) + !writable (not a ptr) */
#ifdef CONFIG_POPCORN_HYPE
	// -> __get_user_pages_fast():arch/x86/mm/gup.c
#endif
	npages = __get_user_pages_fast(addr, 1, 1, page);
	if (npages == 1) {
		*pfn = page_to_pfn(page[0]);

		// pophype dbg - count it
		if (writable)
			*writable = true;

#ifdef CONFIG_POPCORN_HYPE
		if ((distributed_process(current) &&
			(current->at_remote || INTERESTED_GVA(addr))) &&
			NOTINTERESTED_GVA(addr)) {
			EPTVPRINTK("\t\t=fast: [%d] DONE %lx (!lock)\n",
											current->pid, addr);
		}
#endif
		return true;
	}

	return false;
}

/*
 * The slow path to get the pfn of the specified host virtual address,
 * 1 indicates success, -errno is returned if error is detected.
 */
static int hva_to_pfn_slow(unsigned long addr, bool *async, bool write_fault,
			   bool *writable, pfn_t *pfn)
{
	struct page *page[1];
	int npages = 0;
#ifdef CONFIG_POPCORN_HYPE
	unsigned long try_lock_cnt = 0; /* try_lock */
	unsigned long retry_cnt = 0;
	if (distributed_process(current) && !writable) {
		EPTVPRINTK("\t\t=slow: [%d] %lx not from eptfault but gfn_to_pfn()\n",
									current->pid, addr);
	}
#endif

	might_sleep();

	if (writable)
		*writable = write_fault;

#ifdef CONFIG_POPCORN_HYPE
#if 0
	//if ((current->at_remote && !async) ||
	if ((INTERESTED_GVA(addr) && !async)) {
		EPTVPRINTK("\t\t=slow: [%d] XXXXX !async(since it's 2nd try) addr %lx\n",
					current->pid, addr);
		//dump_stack();
	}
#endif
#endif

	if (async) {
//#if 0
		//npages = __get_user_pages_unlocked(current, current->mm, addr, 1,
		//				   write_fault, 0, page,
		//				   FOLL_TOUCH|FOLL_HWPOISON); /* !forece */
//#else
retry:
#ifdef CONFIG_POPCORN_HYPE
		if ((current->at_remote || INTERESTED_GVA(addr)) &&
			 NOTINTERESTED_GVA(addr)
			 ) {
			EPTVVPRINTK("\t\t=slow: [%d] before LOCK %lx\n",
									current->pid, addr);
		}
#endif

#ifdef CONFIG_POPCORN_HYPE
		while (!down_read_trylock(&current->mm->mmap_sem)) {
			if ((!(try_lock_cnt % (RETRY_LOCALFAULT / RETRY_LOCALFAULT_MOD))) &&
				NOTINTERESTED_GVA(addr)) {
				EPTVVPRINTK("\t\t=slow: [%d] =1st TRYLOCK %lx "
						"owner [%d] cnt %ld #%lu %s\n",
						current->pid, addr,
						current->mm->mmap_sem.owner ?
							current->mm->mmap_sem.owner->pid :
							REMOTE_CANNOT_DOWN_MMAP_SEM,
						current->mm->mmap_sem.count,
						try_lock_cnt,
						try_lock_cnt >= RETRY_LOCALFAULT ?
									"***FALLBACK***" : "");

				/* Retry is not used becaus
				 * get_user_page_nowait must return 1 pg */
#if 0
				if (try_lock_cnt >= RETRY_LOCALFAULT) {
					*pfn = REMOTE_CANNOT_DOWN_MMAP_SEM;
					/* ret=npages=!1, do botton-half =afslow */
					return REMOTE_CANNOT_DOWN_MMAP_SEM;
					//BUG();
				}
#endif
			}
			try_lock_cnt++;
			io_schedule();
		}

		if ((current->at_remote || INTERESTED_GVA(addr)) &&
			 NOTINTERESTED_GVA(addr)
			 ) {
			EPTVVPRINTK("\t\t=slow: [%d] =1st [[[LOCKed]]] %lx\n",
									current->pid, addr);
		}
#else
		down_read(&current->mm->mmap_sem);
#endif

		/* 1st __gfn_to_pfn_memslot() / hva_to_pfn() */
		npages = get_user_page_nowait(current, current->mm,
					      addr, write_fault, page);
		up_read(&current->mm->mmap_sem);

#ifdef CONFIG_POPCORN_HYPE
		if (distributed_process(current)) {
			if ((current->at_remote ||
				//(((addr >> PAGE_SHIFT) & PAGE_MASK) > 0x1a00 &&
				 //((addr >> PAGE_SHIFT) & PAGE_MASK) < 0x1aff) ||
				 INTERESTED_GVA(addr)) &&
				 NOTINTERESTED_GVA(addr)
				 ) {
				EPTVVPRINTK("\t\t=slow: [%d] [[[UNLOCKed]]] %lx retpg %s%d%s "
									"atomic %s #%lu\n",
									current->pid, addr,
									npages != 1 ? "*****" : "",
									npages,
									npages != 1 ? "***** Jack !RETRY" : "",
									in_atomic() ? "O" : "X", retry_cnt);
			}
		}

#ifdef CONFIG_POPCORN_CHECK_SANITY
		/* Retry is not used becaus
		 * get_user_page_nowait must return 1 pg */
		/* I made/hope get_user_page_nowait() must successful -
			So RETRY_FIRST_EPT is not nessary........
			but this is not ture...... (why??? so far stable)
			BUG BUG BUG */
		/* Jack: popcorn_hype retry dsm failure */
		if (RETRY_FIRST_EPT) {
			/* hacking/fixing for RETRY CASE -
				THIS IS BAD. HERE IS NOT THE PLACE FOR SWAP
				meaning failure is fine */
			if (npages != 1) { // TODO assumming RETY != 1 which is not 100% true
				printk(KERN_ERR "[SYSTEM CORRUPTED] !![%d] I don't think this should happen, I thought "
						"get_user_page_nowait MUST return 1 pg, npages %d\n",
						current->pid, npages);
				BUG_ON(npages < 0 && "system corrupted");
				//schedule();
				retry_cnt++;
				goto retry;
				/* old BUG: retry never get down_read() lock
					meanwhile origin is asking for the same page */
			}
		}
#endif
#endif
//#endif
	} else { /* 2nd __gfn_to_pfn_memslot() (aka hva_to_pfn())  or !!gfn_to_page(1st remote #ept )!!!  */
		/* Have to handle this as well */
		npages = __get_user_pages_unlocked(current, current->mm, addr, 1,
					   write_fault, 0, page,
					   FOLL_TOUCH|FOLL_HWPOISON); /* lkvm interested forece=0 */
#ifdef CONFIG_POPCORN_HYPE
		BUG_ON(distributed_process(current) &&
				npages != 1 && "ifso, handle it");
#endif
	}

	if (npages != 1)
		return npages;

#if !DISABLE_WRITABLE_EPT /* !important */
	/* map read fault as writable if possible */
	/* https://patchwork.kernel.org/patch/10630897/ */
	if (unlikely(!write_fault) && writable) {
		struct page *wpage[1];

		npages = __get_user_pages_fast(addr, 1, 1, wpage);
		if (npages == 1) {
			*writable = true;
			put_page(page[0]);
			page[0] = wpage[0];
		}

		npages = 1;
	}
#endif

	*pfn = page_to_pfn(page[0]);
	return npages;
}

static bool vma_is_valid(struct vm_area_struct *vma, bool write_fault)
{
	if (unlikely(!(vma->vm_flags & VM_READ)))
		return false;

	if (write_fault && (unlikely(!(vma->vm_flags & VM_WRITE))))
		return false;

	return true;
}

/*
 * Pin guest page in memory and return its pfn.
 * @addr: host virtual address which maps memory to the guest
 * @atomic: whether this function can sleep
 * @async: whether this function need to wait IO complete if the
 *         host page is not in the memory
 * @write_fault: whether we should get a writable host page
 * @writable: whether it allows to map a writable host page for !@write_fault
 *
 * The function will map a writable host page for these two cases:
 * 1): @write_fault = true
 * 2): @write_fault = false && @writable, @writable will tell the caller
 *     whether the mapping is writable.
 */
/* from ./arch/x86/kvm/mmu.c try_async_pf() -> __gfn_to_pfn_memslot() */
/* __gfn_to_pfn_memslot() ~= hva_to_pfn = fast + slow
	1st: &async(false)
	2nd: NULL(this hva_to_pfn has changed to true one time before)

	slow: takes different async to get_usr_page
		async!=NULL
		async==NULL
 */
static pfn_t hva_to_pfn(unsigned long addr, bool atomic, bool *async,
			bool write_fault, bool *writable
#ifdef CONFIG_POPCORN_HYPE
			, gfn_t gfn
#endif
)
{
	struct vm_area_struct *vma;
	pfn_t pfn = 0;
	int npages;
#ifdef CONFIG_POPCORN_HYPE
	int cnt = 0;
	static unsigned long hva_pfn_cnt = 0;
	if (((current->at_remote ||
		INTERESTED_GVA(addr))) &&
//		 !( gfn > 0x12a800 && gfn < 0x12ff21) &&
//		 !( gfn > 0xcc013 && gfn < 0xcffeb)) &&
		NOTINTERESTED_GVA(addr)
		) {
//		if (
//			(!(gfn > 0x12a490 && gfn < 0x12fbf3) &&
//			!(gfn > 0xcb9f6 && gfn < 0xcffea)) &&
//			NOTINTERESTED_GVA(gfn)
//			) {
			hva_pfn_cnt++;
			EPTVPRINTK("\t@@ =[%d] <%s> hva_to_pfn/fastslow gfn %llx hva %lx "
					"%s writable %s &async_ptr %s #%lu\n",
					current->pid, "?", gfn, addr,
					write_fault ? "W" : "R",
					writable ? *writable ? "O" : "X" : "-",
					async ? "O (1st)" : "X (2nd)", hva_pfn_cnt);
			//if (((hva_pfn_cnt >= 150 && hva_pfn_cnt <= 180) ||
			//	(hva_pfn_cnt >= 170 && hva_pfn_cnt <= 200) ||
			//	hva_pfn_cnt >= 200) &&
			//	current->at_remote
			//	){
			//	dump_stack();
			//}
//		}
	}
#endif

	/* we can do it either atomically or asynchronously, not both */
	BUG_ON(atomic && async);

#ifdef CONFIG_POPCORN_HYPE
	/* !First touch - !!pte - check TLB cache
		Both fast&slow will do __get_user_pages_fast() */
#endif
	if (hva_to_pfn_fast(addr, atomic, async, write_fault, writable, &pfn))
		return pfn; /* succ */

	if (atomic)
		return KVM_PFN_ERR_FAULT;

#ifdef CONFIG_POPCORN_HYPE
	/* PAGE FAULT */
	// hva_to_pfn_slow() =
	// 		if (async) {
	//			hold mm lock
	//			npages = get_user_page_nowait(current, current->mm,
	//				      addr, write_fault, page);
	//			release mm lock
	// 		} else
	//			__get_user_pages_unlocked(current, current->mm, addr, 1,
	//									write_fault, 0, page,
	//									FOLL_TOUCH|FOLL_HWPOISON); /* !forece *
	/* First touch - !pte */
#endif
	npages = hva_to_pfn_slow(addr, async, write_fault, writable, &pfn);
	if (npages == 1)
		return pfn;



#ifdef CONFIG_POPCORN_HYPE
	/* 0521shold we really need to do afslow?????????? */
	if (npages == REMOTE_CANNOT_DOWN_MMAP_SEM)
		return REMOTE_CANNOT_DOWN_MMAP_SEM; /* no need to retry again */

#ifdef CONFIG_POPCORN_CHECK_SANITY
	if (npages == 0) {
		POP_PK("\t [%d] %lx npages 0 (If, handle it)\n", current->pid, addr);
	}
	BUG_ON(distributed_process(current) && npages > 1);
#endif
	EPTVVPRINTK("\t =afslow: [%d] before LOCK mmap_sem "
				"addr %lx npages %d(0/%d)\n",
				current->pid, addr, npages, REMOTE_CANNOT_DOWN_MMAP_SEM);

	while (!down_read_trylock(&current->mm->mmap_sem)) {
		if (!(cnt % (RETRY_LOCALFAULT / RETRY_LOCALFAULT_MOD))) {
			EPTVVPRINTK("\t =afslow: [%d] try LOCK %lx "
					"owner [%d] cnt %ld #%d %s\n",
					current->pid, addr,
					current->mm->mmap_sem.owner ?
						current->mm->mmap_sem.owner->pid :
						REMOTE_CANNOT_DOWN_MMAP_SEM,
					current->mm->mmap_sem.count,
					cnt, cnt >= RETRY_LOCALFAULT ? "***FALLBACK***" : "");

			/* Jack's modification */
			if (cnt >= RETRY_LOCALFAULT) {
				if (async) {
					//*async = true; /* Jack: TODO take care this */
					/* *async:true - try 2nd IOasyncfault
							:false - dmap()(default) */

					/* Make sure we don't allow *sync=true, which will
												go 2nd (e.g swapping )*/
					/* Jack: NOW I NEED IT GO OUT before dmap()'s -87 checking */
					*async = false;
				}
				return REMOTE_CANNOT_DOWN_MMAP_SEM; /* !1, do botton-half */
				//BUG();
			}
		}
		//schedule();
		cnt++;
	}
#else /* !CONFIG_POPCORN_HYPE */
	down_read(&current->mm->mmap_sem);
#endif /* CONFIG_POPCORN_HYPE end */

#ifdef CONFIG_POPCORN_HYPE
	EPTVVPRINTK("\t=afslow $$[%d] [[[LOCKed]]] mmap_sem "
				"addr %lx npages %d(0)\n", current->pid, addr, npages);
#endif
	if (npages == -EHWPOISON ||
	      (!async && check_user_page_hwpoison(addr))) {
#ifdef CONFIG_POPCORN_HYPE
		EPTVPRINTK("\t=afslow $$[%d] addr %lx "
					"npages %d==-EHWPOISON pfn %llx\n",
					current->pid, addr, npages, KVM_PFN_ERR_HWPOISON);
#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(distributed_remote_process(current));
#endif
#endif
		/* Send signal to user process */
		pfn = KVM_PFN_ERR_HWPOISON;
		goto exit;
	}

	vma = find_vma_intersection(current->mm, addr, addr + 1);

	if (vma == NULL) {
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_CHECK_SANITY
		if (distributed_process(current)) {
			WARN_ON("!vma TODO\n"); BUG();
		}
#endif
#endif
		pfn = KVM_PFN_ERR_FAULT;
	} else if ((vma->vm_flags & VM_PFNMAP)) { /* !struct page - recalculate */
		/* The only good */
		/* Such pages are typically created by device drivers that
								  map the pages into user space.
			  http://man7.org/linux/man-pages/man2/madvise.2.html */
		pfn = ((addr - vma->vm_start) >> PAGE_SHIFT) +
			vma->vm_pgoff;

#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(distributed_process(current));
#endif
#endif
		BUG_ON(!kvm_is_reserved_pfn(pfn));
	} else {
		/* If host page is not here, keep async = false */
		if (async && vma_is_valid(vma, write_fault)) {
			/* fail, go to botton half */
			*async = true; /* async IO is needed (e.g. is swap-out) = skip dmap */
#ifdef CONFIG_POPCORN_HYPE
			if (distributed_remote_process(current) ||
				(distributed_process(current) && INTERESTED_GVA(addr))) {
				EPTVPRINTK("\t=afslow %s(): [%d] <%s> [[[SWAPINing pfn %llx]]] "
								"go to 2nd/asyncIO\n",
								__func__, current->pid, "?", KVM_PFN_ERR_FAULT);
			}
			/* no swap allowed in pophype */
			BUG_ON(distributed_remote_process(current));
#endif
		}
#ifdef CONFIG_POPCORN_HYPE
		if (distributed_process(current)) {
			printk("\t=afslow %s(): ??[%d] <%s> 0x%llx ?????? "
					"host doesn't have the page. what's going on?\n",
					__func__, current->pid, "?", KVM_PFN_ERR_FAULT);
			BUG();
		}
#endif
		pfn = KVM_PFN_ERR_FAULT;
	}
exit:
#ifdef CONFIG_POPCORN_HYPE
	EPTVPRINTK("\t=afslow $$[%d] before UNLOCK mmap_sem "
				"addr %lx ***EMGPATH****\n", current->pid, addr);
#endif
	up_read(&current->mm->mmap_sem);
#ifdef CONFIG_POPCORN_HYPE
	EPTVPRINTK("\t=afslow $$[%d] [[[UNLOCKed]]] mmap_sem "
				"addr %lx ***EMGPATH****\n", current->pid, addr);
#endif
#ifdef CONFIG_POPCORN_HYPE
	/* PAGE FAULT above */
#endif
	return pfn;
}

/* gfn -> hva -> pfn */
pfn_t __gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn, bool atomic,
			   bool *async, bool write_fault, bool *writable)
{
	/*gfn -> hva(addr) */
	unsigned long addr = __gfn_to_hva_many(slot, gfn, NULL, write_fault);

	if (addr == KVM_HVA_ERR_RO_BAD)
		return KVM_PFN_ERR_RO_FAULT;

	if (kvm_is_error_hva(addr))
		return KVM_PFN_NOSLOT;

	/* Do not map writable pfn in the readonly memslot. */
	if (writable && memslot_is_readonly(slot)) {
		*writable = false;
		writable = NULL; /* overwrite writable ptr */
	}

	/* hva(addr) -> pfn */
	return hva_to_pfn(addr, atomic, async, write_fault, writable
#ifdef CONFIG_POPCORN_HYPE
			  ,gfn
#endif
			  );
}
EXPORT_SYMBOL_GPL(__gfn_to_pfn_memslot);

pfn_t gfn_to_pfn_prot(struct kvm *kvm, gfn_t gfn, bool write_fault,
		      bool *writable)
{
	return __gfn_to_pfn_memslot(gfn_to_memslot(kvm, gfn), gfn, false, NULL,
				    write_fault, writable);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_prot);

pfn_t gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn)
{
#ifdef CONFIG_POPCORN_HYPE
#if !POP_CLEAN
	printk_once("%s(): (not used)\n", __func__);
#endif
#endif
	return __gfn_to_pfn_memslot(slot, gfn, false, NULL, true, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_memslot);

pfn_t gfn_to_pfn_memslot_atomic(struct kvm_memory_slot *slot, gfn_t gfn)
{
#ifdef CONFIG_POPCORN_HYPE
#if !POP_CLEAN
	printk_once("%s(): (not used)\n", __func__);
#endif
#endif
	return __gfn_to_pfn_memslot(slot, gfn, true, NULL, true, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_memslot_atomic);

pfn_t gfn_to_pfn_atomic(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_pfn_memslot_atomic(gfn_to_memslot(kvm, gfn), gfn);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_atomic);

pfn_t kvm_vcpu_gfn_to_pfn_atomic(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return gfn_to_pfn_memslot_atomic(kvm_vcpu_gfn_to_memslot(vcpu, gfn), gfn);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_gfn_to_pfn_atomic);

pfn_t gfn_to_pfn(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_pfn_memslot(gfn_to_memslot(kvm, gfn), gfn);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn);

pfn_t kvm_vcpu_gfn_to_pfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return gfn_to_pfn_memslot(kvm_vcpu_gfn_to_memslot(vcpu, gfn), gfn);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_gfn_to_pfn);

int gfn_to_page_many_atomic(struct kvm_memory_slot *slot, gfn_t gfn,
			    struct page **pages, int nr_pages)
{
	unsigned long addr;
	gfn_t entry;

	addr = gfn_to_hva_many(slot, gfn, &entry);
	if (kvm_is_error_hva(addr))
		return -1;

	if (entry < nr_pages)
		return 0;

	return __get_user_pages_fast(addr, nr_pages, 1, pages);
}
EXPORT_SYMBOL_GPL(gfn_to_page_many_atomic);

static struct page *kvm_pfn_to_page(pfn_t pfn)
{
	if (is_error_noslot_pfn(pfn))
		return KVM_ERR_PTR_BAD_PAGE;

	if (kvm_is_reserved_pfn(pfn)) {
		WARN_ON(1);
		return KVM_ERR_PTR_BAD_PAGE;
	}

	return pfn_to_page(pfn);
}

struct page *gfn_to_page(struct kvm *kvm, gfn_t gfn)
{
	pfn_t pfn;

#ifdef CONFIG_POPCORN_HYPE
	if (distributed_process(current)) {
		EPTVPRINTK("\t_memslot: [%d] %s(): pfn 0x%llx\n",
							current->pid, __func__, pfn);
	}
#endif
	pfn = gfn_to_pfn(kvm, gfn);

	return kvm_pfn_to_page(pfn);
}
EXPORT_SYMBOL_GPL(gfn_to_page);

struct page *kvm_vcpu_gfn_to_page(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	pfn_t pfn;

	pfn = kvm_vcpu_gfn_to_pfn(vcpu, gfn);

	return kvm_pfn_to_page(pfn);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_gfn_to_page);

void kvm_release_page_clean(struct page *page)
{
	WARN_ON(is_error_page(page));

	kvm_release_pfn_clean(page_to_pfn(page));
}
EXPORT_SYMBOL_GPL(kvm_release_page_clean);

void kvm_release_pfn_clean(pfn_t pfn)
{
	if (!is_error_noslot_pfn(pfn) && !kvm_is_reserved_pfn(pfn))
		put_page(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(kvm_release_pfn_clean);

void kvm_release_page_dirty(struct page *page)
{
	WARN_ON(is_error_page(page));

	kvm_release_pfn_dirty(page_to_pfn(page));
}
EXPORT_SYMBOL_GPL(kvm_release_page_dirty);

static void kvm_release_pfn_dirty(pfn_t pfn)
{
	kvm_set_pfn_dirty(pfn);
	kvm_release_pfn_clean(pfn);
}

void kvm_set_pfn_dirty(pfn_t pfn)
{
	if (!kvm_is_reserved_pfn(pfn)) {
		struct page *page = pfn_to_page(pfn);

		if (!PageReserved(page))
			SetPageDirty(page);
	}
}
EXPORT_SYMBOL_GPL(kvm_set_pfn_dirty);

void kvm_set_pfn_accessed(pfn_t pfn)
{
	if (!kvm_is_reserved_pfn(pfn))
		mark_page_accessed(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(kvm_set_pfn_accessed);

void kvm_get_pfn(pfn_t pfn)
{
	if (!kvm_is_reserved_pfn(pfn))
		get_page(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(kvm_get_pfn);

static int next_segment(unsigned long len, int offset)
{
	if (len > PAGE_SIZE - offset)
		return PAGE_SIZE - offset;
	else
		return len;
}

static int __kvm_read_guest_page(struct kvm_memory_slot *slot, gfn_t gfn,
				 void *data, int offset, int len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva_memslot_prot(slot, gfn, NULL);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = __copy_from_user(data, (void __user *)addr + offset, len);
	if (r)
		return -EFAULT;
	return 0;
}

int kvm_read_guest_page(struct kvm *kvm, gfn_t gfn, void *data, int offset,
			int len)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	return __kvm_read_guest_page(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_read_guest_page);

int kvm_vcpu_read_guest_page(struct kvm_vcpu *vcpu, gfn_t gfn, void *data,
			     int offset, int len)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	return __kvm_read_guest_page(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_read_guest_page);

int kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_read_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_read_guest);

int kvm_vcpu_read_guest(struct kvm_vcpu *vcpu, gpa_t gpa, void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_vcpu_read_guest_page(vcpu, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_read_guest);

static int __kvm_read_guest_atomic(struct kvm_memory_slot *slot, gfn_t gfn,
			           void *data, int offset, unsigned long len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva_memslot_prot(slot, gfn, NULL);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	pagefault_disable();
	r = __copy_from_user_inatomic(data, (void __user *)addr + offset, len);
	pagefault_enable();
	if (r)
		return -EFAULT;
	return 0;
}

int kvm_read_guest_atomic(struct kvm *kvm, gpa_t gpa, void *data,
			  unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);
	int offset = offset_in_page(gpa);

	return __kvm_read_guest_atomic(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_read_guest_atomic);

int kvm_vcpu_read_guest_atomic(struct kvm_vcpu *vcpu, gpa_t gpa,
			       void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	int offset = offset_in_page(gpa);

	return __kvm_read_guest_atomic(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_read_guest_atomic);

static int __kvm_write_guest_page(struct kvm_memory_slot *memslot, gfn_t gfn,
			          const void *data, int offset, int len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva_memslot(memslot, gfn);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = __copy_to_user((void __user *)addr + offset, data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty_in_slot(memslot, gfn);
	return 0;
}

int kvm_write_guest_page(struct kvm *kvm, gfn_t gfn,
			 const void *data, int offset, int len)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	return __kvm_write_guest_page(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_write_guest_page);

int kvm_vcpu_write_guest_page(struct kvm_vcpu *vcpu, gfn_t gfn,
			      const void *data, int offset, int len)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	return __kvm_write_guest_page(slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_write_guest_page);

int kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data,
		    unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_write_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_write_guest);

int kvm_vcpu_write_guest(struct kvm_vcpu *vcpu, gpa_t gpa, const void *data,
		         unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_vcpu_write_guest_page(vcpu, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_write_guest);

int kvm_gfn_to_hva_cache_init(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			      gpa_t gpa, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int offset = offset_in_page(gpa);
	gfn_t start_gfn = gpa >> PAGE_SHIFT;
	gfn_t end_gfn = (gpa + len - 1) >> PAGE_SHIFT;
	gfn_t nr_pages_needed = end_gfn - start_gfn + 1;
	gfn_t nr_pages_avail;

	ghc->gpa = gpa;
	ghc->generation = slots->generation;
	ghc->len = len;
	ghc->memslot = gfn_to_memslot(kvm, start_gfn);
	ghc->hva = gfn_to_hva_many(ghc->memslot, start_gfn, NULL);
	if (!kvm_is_error_hva(ghc->hva) && nr_pages_needed <= 1) {
		ghc->hva += offset;
	} else {
		/*
		 * If the requested region crosses two memslots, we still
		 * verify that the entire region is valid here.
		 */
		while (start_gfn <= end_gfn) {
			ghc->memslot = gfn_to_memslot(kvm, start_gfn);
			ghc->hva = gfn_to_hva_many(ghc->memslot, start_gfn,
						   &nr_pages_avail);
			if (kvm_is_error_hva(ghc->hva))
				return -EFAULT;
			start_gfn += nr_pages_avail;
		}
		/* Use the slow path for cross page reads and writes. */
		ghc->memslot = NULL;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_gfn_to_hva_cache_init);

int kvm_write_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int r;

	BUG_ON(len > ghc->len);

	if (slots->generation != ghc->generation)
		kvm_gfn_to_hva_cache_init(kvm, ghc, ghc->gpa, ghc->len);

	if (unlikely(!ghc->memslot))
		return kvm_write_guest(kvm, ghc->gpa, data, len);

	if (kvm_is_error_hva(ghc->hva))
		return -EFAULT;

	r = __copy_to_user((void __user *)ghc->hva, data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty_in_slot(ghc->memslot, ghc->gpa >> PAGE_SHIFT);

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_write_guest_cached);

int kvm_read_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int r;

	BUG_ON(len > ghc->len);

	if (slots->generation != ghc->generation)
		kvm_gfn_to_hva_cache_init(kvm, ghc, ghc->gpa, ghc->len);

	if (unlikely(!ghc->memslot))
		return kvm_read_guest(kvm, ghc->gpa, data, len);

	if (kvm_is_error_hva(ghc->hva))
		return -EFAULT;

	r = __copy_from_user(data, (void __user *)ghc->hva, len);
	if (r)
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_read_guest_cached);

int kvm_clear_guest_page(struct kvm *kvm, gfn_t gfn, int offset, int len)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));

	return kvm_write_guest_page(kvm, gfn, zero_page, offset, len);
}
EXPORT_SYMBOL_GPL(kvm_clear_guest_page);

int kvm_clear_guest(struct kvm *kvm, gpa_t gpa, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_clear_guest_page(kvm, gfn, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_clear_guest);

static void mark_page_dirty_in_slot(struct kvm_memory_slot *memslot,
				    gfn_t gfn)
{
	if (memslot && memslot->dirty_bitmap) {
		unsigned long rel_gfn = gfn - memslot->base_gfn;

		set_bit_le(rel_gfn, memslot->dirty_bitmap);
	}
}

void mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	memslot = gfn_to_memslot(kvm, gfn);
	mark_page_dirty_in_slot(memslot, gfn);
}
EXPORT_SYMBOL_GPL(mark_page_dirty);

void kvm_vcpu_mark_page_dirty(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	memslot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	mark_page_dirty_in_slot(memslot, gfn);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_mark_page_dirty);

static void grow_halt_poll_ns(struct kvm_vcpu *vcpu)
{
	int old, val;

	old = val = vcpu->halt_poll_ns;
	/* 10us base */
	if (val == 0 && halt_poll_ns_grow)
		val = 10000;
	else
		val *= halt_poll_ns_grow;

	if (val > halt_poll_ns)
		val = halt_poll_ns;

	vcpu->halt_poll_ns = val;
	trace_kvm_halt_poll_ns_grow(vcpu->vcpu_id, val, old);
}

static void shrink_halt_poll_ns(struct kvm_vcpu *vcpu)
{
	int old, val;

	old = val = vcpu->halt_poll_ns;
	if (halt_poll_ns_shrink == 0)
		val = 0;
	else
		val /= halt_poll_ns_shrink;

	vcpu->halt_poll_ns = val;
	trace_kvm_halt_poll_ns_shrink(vcpu->vcpu_id, val, old);
}

static int kvm_vcpu_check_block(struct kvm_vcpu *vcpu)
{
	if (kvm_arch_vcpu_runnable(vcpu)) {
		kvm_make_request(KVM_REQ_UNHALT, vcpu);
		return -EINTR;
	}
	if (kvm_cpu_has_pending_timer(vcpu))
		return -EINTR;
	if (signal_pending(current))
		return -EINTR;

	return 0;
}

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 */
void kvm_vcpu_block(struct kvm_vcpu *vcpu)
{
	ktime_t start, cur;
	DEFINE_WAIT(wait);
	bool waited = false;
	u64 block_ns;

	start = cur = ktime_get();
	if (vcpu->halt_poll_ns) {
		ktime_t stop = ktime_add_ns(ktime_get(), vcpu->halt_poll_ns);

		++vcpu->stat.halt_attempted_poll;
		do {
			/*
			 * This sets KVM_REQ_UNHALT if an interrupt
			 * arrives.
			 */
			if (kvm_vcpu_check_block(vcpu) < 0) {
				++vcpu->stat.halt_successful_poll;
				goto out;
			}
			cur = ktime_get();
		} while (single_task_running() && ktime_before(cur, stop));
	}

	kvm_arch_vcpu_blocking(vcpu);

	for (;;) {
		prepare_to_wait(&vcpu->wq, &wait, TASK_INTERRUPTIBLE);

		if (kvm_vcpu_check_block(vcpu) < 0)
			break;

		waited = true;
		schedule();
	}

	finish_wait(&vcpu->wq, &wait);
	cur = ktime_get();

	kvm_arch_vcpu_unblocking(vcpu);
out:
	block_ns = ktime_to_ns(cur) - ktime_to_ns(start);

	if (halt_poll_ns) {
		if (block_ns <= vcpu->halt_poll_ns)
			;
		/* we had a long block, shrink polling */
		else if (vcpu->halt_poll_ns && block_ns > halt_poll_ns)
			shrink_halt_poll_ns(vcpu);
		/* we had a short halt and our poll time is too small */
		else if (vcpu->halt_poll_ns < halt_poll_ns &&
			block_ns < halt_poll_ns)
			grow_halt_poll_ns(vcpu);
	} else
		vcpu->halt_poll_ns = 0;

	trace_kvm_vcpu_wakeup(block_ns, waited);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_block);

#ifndef CONFIG_S390
/*
 * Kick a sleeping VCPU, or a guest VCPU in guest mode, into host kernel mode.
 */
void kvm_vcpu_kick(struct kvm_vcpu *vcpu)
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
	if (cpu != me && (unsigned)cpu < nr_cpu_ids && cpu_online(cpu))
		if (kvm_arch_vcpu_should_kick(vcpu))
			smp_send_reschedule(cpu);
	put_cpu();
}
EXPORT_SYMBOL_GPL(kvm_vcpu_kick);
#endif /* !CONFIG_S390 */

int kvm_vcpu_yield_to(struct kvm_vcpu *target)
{
	struct pid *pid;
	struct task_struct *task = NULL;
	int ret = 0;

	rcu_read_lock();
	pid = rcu_dereference(target->pid);
	if (pid)
		task = get_pid_task(pid, PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return ret;
	ret = yield_to(task, 1);
	put_task_struct(task);

	return ret;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_yield_to);

/*
 * Helper that checks whether a VCPU is eligible for directed yield.
 * Most eligible candidate to yield is decided by following heuristics:
 *
 *  (a) VCPU which has not done pl-exit or cpu relax intercepted recently
 *  (preempted lock holder), indicated by @in_spin_loop.
 *  Set at the beiginning and cleared at the end of interception/PLE handler.
 *
 *  (b) VCPU which has done pl-exit/ cpu relax intercepted but did not get
 *  chance last time (mostly it has become eligible now since we have probably
 *  yielded to lockholder in last iteration. This is done by toggling
 *  @dy_eligible each time a VCPU checked for eligibility.)
 *
 *  Yielding to a recently pl-exited/cpu relax intercepted VCPU before yielding
 *  to preempted lock-holder could result in wrong VCPU selection and CPU
 *  burning. Giving priority for a potential lock-holder increases lock
 *  progress.
 *
 *  Since algorithm is based on heuristics, accessing another VCPU data without
 *  locking does not harm. It may result in trying to yield to  same VCPU, fail
 *  and continue with next VCPU and so on.
 */
static bool kvm_vcpu_eligible_for_directed_yield(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT
	bool eligible;

	eligible = !vcpu->spin_loop.in_spin_loop ||
		    vcpu->spin_loop.dy_eligible;

	if (vcpu->spin_loop.in_spin_loop)
		kvm_vcpu_set_dy_eligible(vcpu, !vcpu->spin_loop.dy_eligible);

	return eligible;
#else
	return true;
#endif
}

void kvm_vcpu_on_spin(struct kvm_vcpu *me)
{
	struct kvm *kvm = me->kvm;
	struct kvm_vcpu *vcpu;
	int last_boosted_vcpu = me->kvm->last_boosted_vcpu;
	int yielded = 0;
	int try = 3;
	int pass;
	int i;

	kvm_vcpu_set_in_spin_loop(me, true);
	/*
	 * We boost the priority of a VCPU that is runnable but not
	 * currently running, because it got preempted by something
	 * else and called schedule in __vcpu_run.  Hopefully that
	 * VCPU is holding the lock that we need and will release it.
	 * We approximate round-robin by starting at the last boosted VCPU.
	 */
	for (pass = 0; pass < 2 && !yielded && try; pass++) {
		kvm_for_each_vcpu(i, vcpu, kvm) {
			if (!pass && i <= last_boosted_vcpu) {
				i = last_boosted_vcpu;
				continue;
			} else if (pass && i > last_boosted_vcpu)
				break;
			if (!ACCESS_ONCE(vcpu->preempted))
				continue;
			if (vcpu == me)
				continue;
			if (waitqueue_active(&vcpu->wq) && !kvm_arch_vcpu_runnable(vcpu))
				continue;
			if (!kvm_vcpu_eligible_for_directed_yield(vcpu))
				continue;

			yielded = kvm_vcpu_yield_to(vcpu);
			if (yielded > 0) {
				kvm->last_boosted_vcpu = i;
				break;
			} else if (yielded < 0) {
				try--;
				if (!try)
					break;
			}
		}
	}
	kvm_vcpu_set_in_spin_loop(me, false);

	/* Ensure vcpu is not eligible during next spinloop */
	kvm_vcpu_set_dy_eligible(me, false);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_on_spin);

/* vaddr to kaddr's page
 * vcpu 3 pages
 * vaddr[0] fault and return (kaddr[0])vcpu->run's pages directly (usr: vcpu->kvm_run)
 * vaddr[1]: vcpu->arch.pio_data
 * vaddr[2]: vcpu->kvm->coalesced_mmio_ring
 */
static int kvm_vcpu_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct kvm_vcpu *vcpu = vma->vm_file->private_data;
	struct page *page;

#ifdef CONFIG_POPCORN_HYPE
	static int first = 1;
	if (first) {
		POP_PK("\n=====================================\n");
#if !POP_CLEAN
		dump_stack();
#endif
		POP_PK("=====================================\n");
		first = 0;
	}
	VCPUPRINTK("\t<%d> kvm_vcpu_fault %p + 0x%lx return phy_page\n",
			vcpu->vcpu_id, vmf->virtual_address, vmf->pgoff);
#endif
	if (vmf->pgoff == 0) {
		page = virt_to_page(vcpu->run);
#ifdef CONFIG_X86
	} else if (vmf->pgoff == KVM_PIO_PAGE_OFFSET) {
		page = virt_to_page(vcpu->arch.pio_data);
#endif
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	} else if (vmf->pgoff == KVM_COALESCED_MMIO_PAGE_OFFSET) {
		page = virt_to_page(vcpu->kvm->coalesced_mmio_ring);
#endif
	} else {
		return kvm_arch_vcpu_fault(vcpu, vmf);
	}

#ifdef CONFIG_POPCORN_HYPE
	VCPUPRINTK("\t\t<%d> %p (+ofs %lx) (usr) - (kern) %s %p ret struct page\n",
				vcpu->vcpu_id, vmf->virtual_address, vmf->pgoff,
				vmf->pgoff == 0 ? "vcpu->run" :
					vmf->pgoff == 1 ? "vcpu->arch.pio_data" :
									"vcpu->kvm->coalesced_mmio_ring", /* kvm */
				vmf->pgoff == 0 ? vcpu->run :
					vmf->pgoff == 1 ? vcpu->arch.pio_data :
									vcpu->kvm->coalesced_mmio_ring);
	VCPUPRINTK("\n");
#endif

	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct kvm_vcpu_vm_ops = {
	.fault = kvm_vcpu_fault,
};

#ifdef CONFIG_POPCORN_HYPE
void *popcorn_vcpu_op = NULL;
#endif
static int kvm_vcpu_mmap(struct file *file, struct vm_area_struct *vma)
{
#ifdef CONFIG_POPCORN_HYPE
	struct kvm_vcpu *vcpu = file->private_data;
#endif
	vma->vm_ops = &kvm_vcpu_vm_ops; /*pophype -
										this has to be install on each kernel */
#ifdef CONFIG_POPCORN_HYPE
	popcorn_vcpu_op = (void *)&kvm_vcpu_vm_ops;
	VCPUPRINTK("%s(): fd vcpu <%d> installing vm->vm_ops %p "
				"(kvm_vcpu_vm_ops) for vma %lx - %lx\n",
				__func__, vcpu->vcpu_id, vma->vm_ops,
				vma->vm_start, vma->vm_end);

	if (distributed_process(current)) {
        // I wanna log hype info for vpu. This [0][fd] is sosososososo important.
        // I will record all first. Then see how it works.
        //printk("\n\n");
        //printk("******************************\n");
        //printk("%s(): [%d] <%d> mmap addr %lx\n",
		//		__func__, my_nid, vcpu->vcpu_id, vma->vm_start);
        //printk("******************************\n");
        //printk("\n\n");
        if (vma->vm_start) {
			/* fd is done by pophype */
			int fd = vcpuid_to_fd(vcpu->vcpu_id);
			POP_PK("\n\n");
			POP_PK("*******install pophype vcpu info*************\n");
			POP_PK("%s(): [%d/%d]<%d> mmap addr %lx [my_nid %d][req->fd %d] "
					"vcpu %p tsk %p (INSTALL VCPU)\n",
					__func__, my_nid, current->pid,
					vcpu->vcpu_id, vma->vm_start, my_nid, fd, vcpu, current);
			POP_PK("*********************************************\n");
			POP_PK("\n\n");
            //hype_node_info[my_nid][fd]->run = xxx;
            hype_node_info[my_nid][fd]->vcpu = vcpu;
            hype_node_info[my_nid][fd]->uaddr = vma->vm_start;
            hype_node_info[my_nid][fd]->vcpu_id = vcpu->vcpu_id;
            hype_node_info[my_nid][fd]->tsk = current;
		}
    }
#endif
	return 0;
}

static int kvm_vcpu_release(struct inode *inode, struct file *filp)
{
	struct kvm_vcpu *vcpu = filp->private_data;

	kvm_put_kvm(vcpu->kvm);
	return 0;
}

static struct file_operations kvm_vcpu_fops = {
	.release        = kvm_vcpu_release,
	.unlocked_ioctl = kvm_vcpu_ioctl,
#ifdef CONFIG_KVM_COMPAT
	.compat_ioctl   = kvm_vcpu_compat_ioctl,
#endif
	.mmap           = kvm_vcpu_mmap,
	.llseek		= noop_llseek,
};

/*
 * Allocates an inode for the vcpu.
 */
#define ITOA_MAX_LEN 12
static int create_vcpu_fd(struct kvm_vcpu *vcpu)
{
	char name[8 + 1 + ITOA_MAX_LEN + 1];

	/* TODO name for remote 0? so that both node has only its vcpu's meta */
	snprintf(name, sizeof(name), "kvm-vcpu:%d", vcpu->vcpu_id);
	return anon_inode_getfd(name, &kvm_vcpu_fops, vcpu, O_RDWR | O_CLOEXEC);
//	return anon_inode_getfd("kvm-vcpu", &kvm_vcpu_fops, vcpu, O_RDWR | O_CLOEXEC);
}

/*
 * Creates some virtual cpus.  Good luck creating more than one.
 */
static int kvm_vm_ioctl_create_vcpu(struct kvm *kvm, u32 id)
{
	int r;
	struct kvm_vcpu *vcpu, *v;

	if (id >= KVM_MAX_VCPUS)
		return -EINVAL;

	vcpu = kvm_arch_vcpu_create(kvm, id); /* main */
	if (IS_ERR(vcpu))
		return PTR_ERR(vcpu);

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("%s(): KVM_CREATE_VCPU -> kvm_arch_vcpu_create vcpu %d done\n",
															__func__, id);
#endif

	preempt_notifier_init(&vcpu->preempt_notifier, &kvm_preempt_ops);

	r = kvm_arch_vcpu_setup(vcpu);
	if (r)
		goto vcpu_destroy;

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("%s(): kvm_arch_vcpu_setup vcpu %d done\n", __func__, id);
#endif

	mutex_lock(&kvm->lock);
	if (!kvm_vcpu_compatible(vcpu)) {
		r = -EINVAL;
		goto unlock_vcpu_destroy;
	}
	if (atomic_read(&kvm->online_vcpus) == KVM_MAX_VCPUS) {
		r = -EINVAL;
		goto unlock_vcpu_destroy;
	}

	/* Check if exiting */
	kvm_for_each_vcpu(r, v, kvm)
		if (v->vcpu_id == id) {
			r = -EEXIST;
			goto unlock_vcpu_destroy;
		}

	BUG_ON(kvm->vcpus[atomic_read(&kvm->online_vcpus)]);

	/* Now it's all set up, let userspace reach it */
	kvm_get_kvm(kvm);
	r = create_vcpu_fd(vcpu);
	if (r < 0) {
		kvm_put_kvm(kvm);
		goto unlock_vcpu_destroy;
	}
#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t(inside check id#) vcpu_id %d created\n", vcpu->vcpu_id);
#endif

	kvm->vcpus[atomic_read(&kvm->online_vcpus)] = vcpu;

	/*
	 * Pairs with smp_rmb() in kvm_get_vcpu.  Write kvm->vcpus
	 * before kvm->online_vcpu's incremented value.
	 */
	smp_wmb();
	atomic_inc(&kvm->online_vcpus);

	mutex_unlock(&kvm->lock);
	kvm_arch_vcpu_postcreate(vcpu);
	return r; /* user vcpu_fd */

unlock_vcpu_destroy:
	mutex_unlock(&kvm->lock);
vcpu_destroy:
	kvm_arch_vcpu_destroy(vcpu);
	return r;
}

static int kvm_vcpu_ioctl_set_sigmask(struct kvm_vcpu *vcpu, sigset_t *sigset)
{
	if (sigset) {
		sigdelsetmask(sigset, sigmask(SIGKILL)|sigmask(SIGSTOP));
		vcpu->sigset_active = 1;
		vcpu->sigset = *sigset;
	} else
		vcpu->sigset_active = 0;
	return 0;
}

static long kvm_vcpu_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;
	struct kvm_fpu *fpu = NULL;
	struct kvm_sregs *kvm_sregs = NULL;

	if (vcpu->kvm->mm != current->mm)
		return -EIO;

	if (unlikely(_IOC_TYPE(ioctl) != KVMIO))
		return -EINVAL;

#if defined(CONFIG_S390) || defined(CONFIG_PPC) || defined(CONFIG_MIPS)
	/*
	 * Special cases: vcpu ioctls that are asynchronous to vcpu execution,
	 * so vcpu_load() would break it.
	 */
	if (ioctl == KVM_S390_INTERRUPT || ioctl == KVM_S390_IRQ || ioctl == KVM_INTERRUPT)
		return kvm_arch_vcpu_ioctl(filp, ioctl, arg);
#endif

#ifdef CONFIG_POPCORN_HYPE
	// many
	//PHMIGRATEPRINTK("[%d] %s: going to call vcpu_load "
	//				"vcpu_id <%d> smp_processor_id() %d\n",
	//				current->pid, __func__, vcpu->vcpu_id, smp_processor_id());
#endif

#if defined(CONFIG_POPCORN_HYPE) && POPCORN_DEBUG_FT
	if (ioctl == KVM_GET_SREGS ||
			ioctl == KVM_GET_MP_STATE) { // KVM_GET_MSRS //killme
		int lock_retry_lock = 0;
		PHMIGRATEPRINTK("[%d] <%d> %s: start - 5 (0x%x)\n",
				current->pid, vcpu->vcpu_id, __func__, ioctl);
		PHMIGRATEPRINTK("[%d] <%d> %s: dies between 5 & 6 (0x%x) "
				"KVM_GET_SREGS 0x%lx KVM_GET_MP_STATE 0x%lx\n",
				current->pid, vcpu->vcpu_id, __func__, ioctl,
				KVM_GET_SREGS, KVM_GET_MP_STATE);
		PHMIGRATEPRINTK("[%d] <%d> %s: start - 5.5 (0x%x) [debug] "
				"mutex debug start\n",
				current->pid, vcpu->vcpu_id, __func__, ioctl);

		if (!mutex_trylock(&vcpu->mutex)) { // contention
			PHMIGRATEPRINTK("[%d] <%d> %s: start - 5.6 (0x%x) "
					"[debug] lock contention -  the owner is [[[%d]]]\n",
					current->pid, vcpu->vcpu_id, __func__, ioctl,
					vcpu->mutex.owner->pid);
		} else { // no contention (grabed)
			PHMIGRATEPRINTK("[%d] <%d> %s: start - 5.5 (0x%x) "
					"[debug] lock GOOD no contention\n",
					current->pid, vcpu->vcpu_id, __func__, ioctl);
			mutex_unlock(&vcpu->mutex);
		}

		while (!mutex_trylock(&vcpu->mutex)) {
			lock_retry_lock++;
		};
		mutex_unlock(&vcpu->mutex); // grabed

		//if (mutex_trylock(&vcpu->mutex)) {
		if (!lock_retry_lock) {
			PHMIGRATEPRINTK("[%d] <%d> %s: start - 5.6 (0x%x) "
					"[debug] lock GOOD no contention\n",
					current->pid, vcpu->vcpu_id, __func__, ioctl);
		} else {
			PHMIGRATEPRINTK("[%d] <%d> %s: start - 5.6 (0x%x) "
					"[debug] lock contention #%d time\n",
					current->pid, vcpu->vcpu_id, __func__,
					ioctl, lock_retry_lock);
//			PHMIGRATEPRINTK("[%d] <%d> %s: start - 5.6 (0x%x) "
//					"[debug] the lock owner is [[[%d]]]\n",
//					current->pid, vcpu->vcpu_id, __func__, ioctl,
//					vcpu->mutex.owner->pid);
		}
	}
#endif

	r = vcpu_load(vcpu);
#if defined(CONFIG_POPCORN_HYPE)
	if (r) {
		if (unlikely(signal_pending_state(TASK_KILLABLE, current))) {
			PHMIGRATEPRINTK("[dbg] [%d] <%d> %s: this is the problem r = %d\n",
				current->pid, vcpu->vcpu_id, __func__, r);
		}else{
			PHMIGRATEPRINTK("[dbg] [%d] <%d> %s: this is NOT the problem r = %d\n",
				current->pid, vcpu->vcpu_id, __func__, r);
		}
		PHMIGRATEPRINTK("[%d] <%d> %s: start - 5 fail r = %d "
						"(expect -4 mutex_lock() fails)\n",
						current->pid, vcpu->vcpu_id, __func__, r);
	}
#endif
	if (r)
		return r;

#ifdef CONFIG_POPCORN_HYPE
	if (distributed_remote_process(current)) {
		HPPRINTK("%s: 0x%x\n", __func__, ioctl);
	}
#endif
	switch (ioctl) {
	case KVM_RUN:
		HPPRINTK("<%d> %s: KVM_RUN\n", current->pid, __func__);
		r = -EINVAL;
#ifdef CONFIG_POPCORN_HYPE
		HPPRINTK("[%d] %s: KVM_RUN 1\n", current->pid, __func__);
#endif
		if (arg)
			goto out;
#ifdef CONFIG_POPCORN_HYPE
		HPPRINTK("[%d] %s: KVM_RUN 2\n", current->pid, __func__);
#endif
		if (unlikely(vcpu->pid != current->pids[PIDTYPE_PID].pid)) {
			/* The thread running this VCPU changed. */
			struct pid *oldpid = vcpu->pid;
			struct pid *newpid = get_task_pid(current, PIDTYPE_PID);
#ifdef CONFIG_POPCORN_HYPE
			PHMIGRATEPRINTK("[%d] %s: KVM_RUN pophype migration vcpu->pid "
							"chagned [old %p] [new %p]\n",
							current->pid, __func__, oldpid, newpid);
#endif

			rcu_assign_pointer(vcpu->pid, newpid);
			if (oldpid)
				synchronize_rcu();
			put_pid(oldpid);
		}
		r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
								/* arch/x86/kvm/x86.c */
		trace_kvm_userspace_exit(vcpu->run->exit_reason, r);
#ifdef CONFIG_POPCORN_HYPE
		//if (vcpu->run->exit_reason != KVM_EXIT_IO && current->at_remote) { // 2
		//if (current->at_remote) // 2
		//}
#if 0
		{ /* pophype debug */
			static unsigned int cnt = 0;
			static unsigned int exit_two = 0;
			//if (vcpu->run->exit_reason == KVM_EXIT_INTERNAL_ERROR) {
									//17-3 KVM_INTERNAL_ERROR_DELIVERY_EV
				if (vcpu->run->exit_reason == KVM_EXIT_IO)
					exit_two++;
				if (exit_two > 500 && !current->at_remote) // bug...
					goto outprint;

				cnt++;
				if (cnt < 1150 || current->at_remote) { // bug
					//printk("\t[%d][%d]<%d> vcpu->run [[[%p]]] "
					VMPRINTK("\t[%d/%d] <%d> vcpu->run [[[%p]]] "
							"->run->exit %u-%u r %d %lx #%u reting!\n",
							//current->at_remote ? 1:0, current->pid,
							current->at_remote ? 1:0, current->pid,
							vcpu->vcpu_id, vcpu->run,
							vcpu->run->exit_reason,
							vcpu->run->internal.suberror,
							r, (unsigned long)r, cnt);
				}
				/* a test was done - result: kernel and usr are shareing
												struct vcpu now (999) workd */
			//}
		}
outprint:
#endif
#endif
		break;
	case KVM_GET_REGS: {
		struct kvm_regs *kvm_regs;
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("[%d] <%d> %s: KVM_GET_REGS\n",
				current->pid, vcpu->vcpu_id, __func__);
		PHMIGRATEPRINTK("[%d] <%d> %s: KVM_GET_REGS\n",
				current->pid, vcpu->vcpu_id, __func__);
#endif

		r = -ENOMEM;
		kvm_regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL);
		if (!kvm_regs)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_regs(vcpu, kvm_regs);
		if (r)
			goto out_free1;
		r = -EFAULT;
		if (copy_to_user(argp, kvm_regs, sizeof(struct kvm_regs)))
			goto out_free1;
		r = 0;
out_free1:
		kfree(kvm_regs);
		break;
	}
	case KVM_SET_REGS: {
		struct kvm_regs *kvm_regs;
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("%s: KVM_SET_REGS\n", __func__);
		PHMIGRATEPRINTK("%s: KVM_SET_REGS\n", __func__);
#endif

		r = -ENOMEM;
		kvm_regs = memdup_user(argp, sizeof(*kvm_regs));
		if (IS_ERR(kvm_regs)) {
			r = PTR_ERR(kvm_regs);
			goto out;
		}
		r = kvm_arch_vcpu_ioctl_set_regs(vcpu, kvm_regs);
		kfree(kvm_regs);
		break;
	}
	case KVM_GET_SREGS: {
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("[%d] <%d> %s: KVM_GET_SREGS\n",
					current->pid, vcpu->vcpu_id, __func__);
		PHMIGRATEPRINTK("[%d] <%d> %s: KVM_GET_SREGS\n",
					current->pid, vcpu->vcpu_id, __func__);
		//static int debug = 0;
		//if (debug < 15) {
//			dump_stack(); // kill me
		//}
		//debug = 1;
#endif
		kvm_sregs = kzalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
		r = -ENOMEM;
		if (!kvm_sregs)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_sregs(vcpu, kvm_sregs);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, kvm_sregs, sizeof(struct kvm_sregs)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_SREGS: {
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("[%d] <%d> %s: KVM_SET_SREGS\n",
				current->pid, vcpu->vcpu_id, __func__);
		PHMIGRATEPRINTK("[%d] <%d> %s: KVM_SET_SREGS\n",
					current->pid, vcpu->vcpu_id, __func__);
#endif

		kvm_sregs = memdup_user(argp, sizeof(*kvm_sregs));
		if (IS_ERR(kvm_sregs)) {
			r = PTR_ERR(kvm_sregs);
			kvm_sregs = NULL;
			goto out;
		}
		r = kvm_arch_vcpu_ioctl_set_sregs(vcpu, kvm_sregs);
		break;
	}
	case KVM_GET_MP_STATE: {
		struct kvm_mp_state mp_state;
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("[%d] <%d> %s: KVM_GET_MP_STATE\n\n",
				current->pid, vcpu->vcpu_id, __func__);
		PHMIGRATEPRINTK("[%d] <%d> %s: KVM_GET_MP_STATE\n\n",
						current->pid, vcpu->vcpu_id, __func__);
#endif

		r = kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &mp_state);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &mp_state, sizeof(mp_state)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_MP_STATE: {
		struct kvm_mp_state mp_state;
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("%s: KVM_SET_MP_STATE\n", __func__);
#endif

		r = -EFAULT;
		if (copy_from_user(&mp_state, argp, sizeof(mp_state)))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &mp_state);
		break;
	}
	case KVM_TRANSLATE: {
		struct kvm_translation tr;
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("%s: KVM_TRANSLATE\n", __func__);
#endif

		r = -EFAULT;
		if (copy_from_user(&tr, argp, sizeof(tr)))
			goto out;
		r = kvm_arch_vcpu_ioctl_translate(vcpu, &tr);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &tr, sizeof(tr)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_GUEST_DEBUG: {
		struct kvm_guest_debug dbg;
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("%s: KVM_SET_GUEST_DEBUG\n", __func__);
#endif

		r = -EFAULT;
		if (copy_from_user(&dbg, argp, sizeof(dbg)))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_guest_debug(vcpu, &dbg);
		break;
	}
	case KVM_SET_SIGNAL_MASK: {
		struct kvm_signal_mask __user *sigmask_arg = argp;
		struct kvm_signal_mask kvm_sigmask;
		sigset_t sigset, *p;
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("%s: KVM_SET_SIGNAL_MASK\n", __func__);
#endif

		p = NULL;
		if (argp) {
			r = -EFAULT;
			if (copy_from_user(&kvm_sigmask, argp,
					   sizeof(kvm_sigmask)))
				goto out;
			r = -EINVAL;
			if (kvm_sigmask.len != sizeof(sigset))
				goto out;
			r = -EFAULT;
			if (copy_from_user(&sigset, sigmask_arg->sigset,
					   sizeof(sigset)))
				goto out;
			p = &sigset;
		}
		r = kvm_vcpu_ioctl_set_sigmask(vcpu, p);
		break;
	}
	case KVM_GET_FPU: {
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("<%d> %s: KVM_GET_FPU\n", current->pid, __func__);
#endif

		fpu = kzalloc(sizeof(struct kvm_fpu), GFP_KERNEL);
		r = -ENOMEM;
		if (!fpu)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_fpu(vcpu, fpu);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, fpu, sizeof(struct kvm_fpu)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_FPU: {
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("<%d> %s: KVM_SET_FPU\n", current->pid, __func__);
		PHMIGRATEPRINTK("<%d> %s: KVM_SET_FPU\n", current->pid, __func__);
#endif

		fpu = memdup_user(argp, sizeof(*fpu));
		if (IS_ERR(fpu)) {
			r = PTR_ERR(fpu);
			fpu = NULL;
			goto out;
		}
		r = kvm_arch_vcpu_ioctl_set_fpu(vcpu, fpu);
		break;
	}
	default:
#if defined(CONFIG_POPCORN_HYPE)
		HPPRINTK("<%d> %s: (default) -> kvm_arch_vcpu_ioctl()\n",
											current->pid, __func__);
#endif
		r = kvm_arch_vcpu_ioctl(filp, ioctl, arg);
	}
out:
	HPPRINTK("<%d> %s: vcpu %d return %d\n",
				current->pid, __func__, vcpu->vcpu_id, r);
	vcpu_put(vcpu);
	kfree(fpu);
	kfree(kvm_sregs);
	return r;
}

#ifdef CONFIG_KVM_COMPAT
static long kvm_vcpu_compat_ioctl(struct file *filp,
				  unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = compat_ptr(arg);
	int r;

	if (vcpu->kvm->mm != current->mm)
		return -EIO;

	switch (ioctl) {
	case KVM_SET_SIGNAL_MASK: {
		struct kvm_signal_mask __user *sigmask_arg = argp;
		struct kvm_signal_mask kvm_sigmask;
		compat_sigset_t csigset;
		sigset_t sigset;

		if (argp) {
			r = -EFAULT;
			if (copy_from_user(&kvm_sigmask, argp,
					   sizeof(kvm_sigmask)))
				goto out;
			r = -EINVAL;
			if (kvm_sigmask.len != sizeof(csigset))
				goto out;
			r = -EFAULT;
			if (copy_from_user(&csigset, sigmask_arg->sigset,
					   sizeof(csigset)))
				goto out;
			sigset_from_compat(&sigset, &csigset);
			r = kvm_vcpu_ioctl_set_sigmask(vcpu, &sigset);
		} else
			r = kvm_vcpu_ioctl_set_sigmask(vcpu, NULL);
		break;
	}
	default:
		r = kvm_vcpu_ioctl(filp, ioctl, arg);
	}

out:
	return r;
}
#endif

static int kvm_device_ioctl_attr(struct kvm_device *dev,
				 int (*accessor)(struct kvm_device *dev,
						 struct kvm_device_attr *attr),
				 unsigned long arg)
{
	struct kvm_device_attr attr;

	if (!accessor)
		return -EPERM;

	if (copy_from_user(&attr, (void __user *)arg, sizeof(attr)))
		return -EFAULT;

	return accessor(dev, &attr);
}

static long kvm_device_ioctl(struct file *filp, unsigned int ioctl,
			     unsigned long arg)
{
	struct kvm_device *dev = filp->private_data;

	switch (ioctl) {
	case KVM_SET_DEVICE_ATTR:
		return kvm_device_ioctl_attr(dev, dev->ops->set_attr, arg);
	case KVM_GET_DEVICE_ATTR:
		return kvm_device_ioctl_attr(dev, dev->ops->get_attr, arg);
	case KVM_HAS_DEVICE_ATTR:
		return kvm_device_ioctl_attr(dev, dev->ops->has_attr, arg);
	default:
		if (dev->ops->ioctl)
			return dev->ops->ioctl(dev, ioctl, arg);

		return -ENOTTY;
	}
}

static int kvm_device_release(struct inode *inode, struct file *filp)
{
	struct kvm_device *dev = filp->private_data;
	struct kvm *kvm = dev->kvm;

	kvm_put_kvm(kvm);
	return 0;
}

static const struct file_operations kvm_device_fops = {
	.unlocked_ioctl = kvm_device_ioctl,
#ifdef CONFIG_KVM_COMPAT
	.compat_ioctl = kvm_device_ioctl,
#endif
	.release = kvm_device_release,
};

struct kvm_device *kvm_device_from_filp(struct file *filp)
{
	if (filp->f_op != &kvm_device_fops)
		return NULL;

	return filp->private_data;
}

static struct kvm_device_ops *kvm_device_ops_table[KVM_DEV_TYPE_MAX] = {
#ifdef CONFIG_KVM_MPIC
	[KVM_DEV_TYPE_FSL_MPIC_20]	= &kvm_mpic_ops,
	[KVM_DEV_TYPE_FSL_MPIC_42]	= &kvm_mpic_ops,
#endif

#ifdef CONFIG_KVM_XICS
	[KVM_DEV_TYPE_XICS]		= &kvm_xics_ops,
#endif
};

int kvm_register_device_ops(struct kvm_device_ops *ops, u32 type)
{
	if (type >= ARRAY_SIZE(kvm_device_ops_table))
		return -ENOSPC;

	if (kvm_device_ops_table[type] != NULL)
		return -EEXIST;

	kvm_device_ops_table[type] = ops;
	return 0;
}

void kvm_unregister_device_ops(u32 type)
{
	if (kvm_device_ops_table[type] != NULL)
		kvm_device_ops_table[type] = NULL;
}

static int kvm_ioctl_create_device(struct kvm *kvm,
				   struct kvm_create_device *cd)
{
	struct kvm_device_ops *ops = NULL;
	struct kvm_device *dev;
	bool test = cd->flags & KVM_CREATE_DEVICE_TEST;
	int ret;

	if (cd->type >= ARRAY_SIZE(kvm_device_ops_table))
		return -ENODEV;

	ops = kvm_device_ops_table[cd->type];
	if (ops == NULL)
		return -ENODEV;

	if (test)
		return 0;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->ops = ops;
	dev->kvm = kvm;

	ret = ops->create(dev, cd->type);
	if (ret < 0) {
		kfree(dev);
		return ret;
	}

	ret = anon_inode_getfd(ops->name, &kvm_device_fops, dev, O_RDWR | O_CLOEXEC);
	if (ret < 0) {
		ops->destroy(dev);
		return ret;
	}

	list_add(&dev->vm_node, &kvm->devices);
	kvm_get_kvm(kvm);
	cd->fd = ret;
	return 0;
}

static long kvm_vm_ioctl_check_extension_generic(struct kvm *kvm, long arg)
{
	switch (arg) {
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
	case KVM_CAP_INTERNAL_ERROR_DATA:
#ifdef CONFIG_HAVE_KVM_MSI
	case KVM_CAP_SIGNAL_MSI:
#endif
#ifdef CONFIG_HAVE_KVM_IRQFD
	case KVM_CAP_IRQFD:
	case KVM_CAP_IRQFD_RESAMPLE:
#endif
	case KVM_CAP_IOEVENTFD_ANY_LENGTH:
	case KVM_CAP_CHECK_EXTENSION_VM:
		return 1;
#ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
	case KVM_CAP_IRQ_ROUTING:
		return KVM_MAX_IRQ_ROUTES;
#endif
#if KVM_ADDRESS_SPACE_NUM > 1
	case KVM_CAP_MULTI_ADDRESS_SPACE:
		return KVM_ADDRESS_SPACE_NUM;
#endif
	default:
		break;
	}
	return kvm_vm_ioctl_check_extension(kvm, arg);
}

#include <linux/fdtable.h>
static long kvm_vm_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;

#ifdef CONFIG_POPCORN_HYPE
	HPPRINTK("%s:\n", __func__);
#endif

	if (kvm->mm != current->mm)
		return -EIO;
	switch (ioctl) {
	case KVM_CREATE_VCPU:
		DDPRINTK("======================================\n");
		POP_PK("======================================\n");
		POP_PK("%s: [[KVM_CREATE_VCPU]] vcpu %lu\n", __func__, arg);
		POP_PK("======================================\n");
		DDPRINTK("======================================\n");
		r = kvm_vm_ioctl_create_vcpu(kvm, arg);
#ifdef CONFIG_POPCORN_HYPE
		if (r < 0) {
			POP_PK("\n**********************************\n"
					"**********************************\n"
					"\t\t[[[[[[[vcpu_id %d failed to create ret %d ]]]]]]]\n"
					"**********************************\n"
					"**********************************\n",
					atomic_read(&kvm->online_vcpus), r);
		} else {
			POP_PK("%s(): vcpu_id %d fd %d (#%d) sucessfully created!!\n",
							__func__, atomic_read(&kvm->online_vcpus) - 1,
							popcorn_file_to_fd(current, filp, true),
							atomic_read(&kvm->online_vcpus));
		}
#endif
		break;
	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_userspace_memory_region kvm_userspace_mem;
		POP_PK("%s: KVM_SET_USER_MEMORY_REGION 1 bank\n", __func__);

		r = -EFAULT;
		if (copy_from_user(&kvm_userspace_mem, argp,
						sizeof(kvm_userspace_mem)))
			goto out;

		r = kvm_vm_ioctl_set_memory_region(kvm, &kvm_userspace_mem);
		break;
	}
	case KVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;
		HPPRINTK("%s: KVM_GET_DIRTY_LOG\n", __func__);

		r = -EFAULT;
		if (copy_from_user(&log, argp, sizeof(log)))
			goto out;
		r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
		break;
	}
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;
		POP_PK("%s: KVM_REGISTER_COALESCED_MMIO\n", __func__);

		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof(zone)))
			goto out;
		r = kvm_vm_ioctl_register_coalesced_mmio(kvm, &zone);
		break;
	}
	case KVM_UNREGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;
		POP_PK("%s: KVM_UNREGISTER_COALESCED_MMIO\n", __func__);

		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof(zone)))
			goto out;
		r = kvm_vm_ioctl_unregister_coalesced_mmio(kvm, &zone);
		break;
	}
#endif
	case KVM_IRQFD: {
		struct kvm_irqfd data;
		POP_PK("%s: KVM_IRQFD\n", __func__);
#ifdef CONFIG_POPCORN_HYPE
        POP_PK("\t\tpophype: %s: %s(): KVM_IRQFD e.g. vhost-net\n",
												__FILE__, __func__);
#endif

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof(data)))
			goto out;
		r = kvm_irqfd(kvm, &data);
		break;
	}
	case KVM_IOEVENTFD: {
		struct kvm_ioeventfd data;
		POP_PK("%s: KVM_IOEVENTFD (vhost-net-eventfd)\n", __func__);

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof(data)))
			goto out;
		r = kvm_ioeventfd(kvm, &data);
		break;
	}
#ifdef CONFIG_HAVE_KVM_MSI
	case KVM_SIGNAL_MSI: {
		struct kvm_msi msi;
#if POPHYPE_NET_OPTIMIZE_TMP_DEBUG
		{
			static int cnt = 0;
			cnt++;
			if (cnt < 100 || !(cnt % 100)) {
				POP_PK("%s: KVM_SIGNAL_MSI - "
						"vanilla virtio-host many #%d\n", __func__, cnt);
			}
		}
#endif
		r = -EFAULT;
		if (copy_from_user(&msi, argp, sizeof(msi)))
			goto out;
		r = kvm_send_userspace_msi(kvm, &msi);
		break;
	}
#endif
#ifdef __KVM_HAVE_IRQ_LINE
	case KVM_IRQ_LINE_STATUS:
	case KVM_IRQ_LINE: {
		struct kvm_irq_level irq_event;
		/*if (ioctl == KVM_IRQ_LINE)
			VIRTIOBLKPK("%s: KVM_IRQ_LINE comm=%s\n", __func__, current->comm);*/
		r = -EFAULT;
		if (copy_from_user(&irq_event, argp, sizeof(irq_event)))
			goto out;

		r = kvm_vm_ioctl_irq_line(kvm, &irq_event,
					ioctl == KVM_IRQ_LINE_STATUS);
		/*if (ioctl == KVM_IRQ_LINE)
		            VIRTIOBLKPK("%s: KVM_IRQ_LINE r=%d\n", __func__, r);*/
		if (r)
			goto out;

		r = -EFAULT;
		if (ioctl == KVM_IRQ_LINE_STATUS) {
			if (copy_to_user(argp, &irq_event, sizeof(irq_event)))
				goto out;
		}

		r = 0;
		break;
	}
#endif
#ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
	case KVM_SET_GSI_ROUTING: {
		struct kvm_irq_routing routing;
		struct kvm_irq_routing __user *urouting;
		struct kvm_irq_routing_entry *entries;
		POP_PK("%s: %s(): KVM_SET_GSI_ROUTING from PCI "
				"20VIRTIO_MSI_CONFIG_VECTOR/22VIRTIO_MSI_QUEUE_VECTOR "
				"(vcpu init & vhost-net: first ping)\n",
				__FILE__, __func__);

		r = -EFAULT;
		if (copy_from_user(&routing, argp, sizeof(routing)))
			goto out;
		r = -EINVAL;
		if (routing.nr > KVM_MAX_IRQ_ROUTES)
			goto out;
		if (routing.flags)
			goto out;
		r = -ENOMEM;
		entries = vmalloc(routing.nr * sizeof(*entries));
		if (!entries)
			goto out;
		r = -EFAULT;
		urouting = argp;
		if (copy_from_user(entries, urouting->entries,
				   routing.nr * sizeof(*entries)))
			goto out_free_irq_routing;
		r = kvm_set_irq_routing(kvm, entries, routing.nr,
					routing.flags);
out_free_irq_routing:
		vfree(entries);
		break;
	}
#endif /* CONFIG_HAVE_KVM_IRQ_ROUTING */
	case KVM_CREATE_DEVICE: {
		struct kvm_create_device cd;
		POP_PK("%s: KVM_CREATE_DEVICE\n", __func__);

		r = -EFAULT;
		if (copy_from_user(&cd, argp, sizeof(cd)))
			goto out;

		r = kvm_ioctl_create_device(kvm, &cd);
		if (r)
			goto out;

		r = -EFAULT;
		if (copy_to_user(argp, &cd, sizeof(cd)))
			goto out;

		r = 0;
		break;
	}
	case KVM_CHECK_EXTENSION:
		HPPRINTK("%s: KVM_CHECK_EXTENSION\n", __func__);
		r = kvm_vm_ioctl_check_extension_generic(kvm, arg);
		break;
	default:
#ifdef CONFIG_POPCORN_HYPE
		HPPRINTK("%s: (default) -> kvm_arch_vm_ioctl() 0x%x\n", __func__, ioctl);
#endif
		r = kvm_arch_vm_ioctl(filp, ioctl, arg);
	}
out:
	return r;
}

#ifdef CONFIG_KVM_COMPAT
struct compat_kvm_dirty_log {
	__u32 slot;
	__u32 padding1;
	union {
		compat_uptr_t dirty_bitmap; /* one bit per page */
		__u64 padding2;
	};
};

static long kvm_vm_compat_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	int r;

	if (kvm->mm != current->mm)
		return -EIO;
	switch (ioctl) {
	case KVM_GET_DIRTY_LOG: {
		struct compat_kvm_dirty_log compat_log;
		struct kvm_dirty_log log;

		r = -EFAULT;
		if (copy_from_user(&compat_log, (void __user *)arg,
				   sizeof(compat_log)))
			goto out;
		log.slot	 = compat_log.slot;
		log.padding1	 = compat_log.padding1;
		log.padding2	 = compat_log.padding2;
		log.dirty_bitmap = compat_ptr(compat_log.dirty_bitmap);

		r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
		break;
	}
	default:
		r = kvm_vm_ioctl(filp, ioctl, arg);
	}

out:
	return r;
}
#endif

#ifdef CONFIG_POPCORN_HYPE
static struct file_operations kvm_vm_fops = {
#else
struct file_operations kvm_vm_fops = {
#endif
	.release        = kvm_vm_release,
	.unlocked_ioctl = kvm_vm_ioctl,
#ifdef CONFIG_KVM_COMPAT
	.compat_ioctl   = kvm_vm_compat_ioctl,
#endif
	.llseek		= noop_llseek,
};

#ifdef CONFIG_POPCORN_HYPE
// replay
int replay_kvm_dev_ioctl_create_vm_tsk(struct task_struct *tsk, unsigned long type)
{
	int r;
	struct kvm *kvm;

	kvm = kvm_create_vm_tsk(tsk, type);
	if (IS_ERR(kvm))
		return PTR_ERR(kvm);
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET /* Using */
	r = kvm_coalesced_mmio_init(kvm);
	if (r < 0) {
		kvm_put_kvm(kvm);
		return r;
	}
#endif
	r = anon_inode_getfd_tsk(tsk, "kvm-vm", &kvm_vm_fops, kvm, O_RDWR | O_CLOEXEC);
	if (r < 0)
		kvm_put_kvm(kvm);

	return r;
}
EXPORT_SYMBOL_GPL(replay_kvm_dev_ioctl_create_vm_tsk);
#endif

static int kvm_dev_ioctl_create_vm(unsigned long type)
{
	int r;
	struct kvm *kvm;

#ifdef CONFIG_POPCORN_HYPE
	if (distributed_remote_process(current)) { /* remote */
		HPPRINTK("%s: do nothing now\n", __func__);
		//return popcorn_kvm_dev_ioctl_create_vm_tsk(type);
	}
#endif

	kvm = kvm_create_vm(type);
	if (IS_ERR(kvm))
		return PTR_ERR(kvm);
#ifdef CONFIG_POPCORN_HYPE
	HPPRINTK("%s: struct kvm %p\n", __func__, kvm);
#endif
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	HPPRINTK("[arch] %s: KVM_COALESCED_MMIO_PAGE_OFFSET ON\n", __func__);
	r = kvm_coalesced_mmio_init(kvm);
	if (r < 0) {
		kvm_put_kvm(kvm);
		return r;
	}
#endif
	r = anon_inode_getfd("kvm-vm", &kvm_vm_fops, kvm, O_RDWR | O_CLOEXEC);
	if (r < 0)
		kvm_put_kvm(kvm);

	return r;
}

/* from vcpu->kvm->sys_fd */
static long kvm_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	long r = -EINVAL;

	HPPRINTK("%s:\n", __func__);
	switch (ioctl) {
	case KVM_GET_API_VERSION:
		HPPRINTK("%s: KVM_GET_API_VERSION\n", __func__);
		if (arg)
			goto out;
		r = KVM_API_VERSION;
		break;
	case KVM_CREATE_VM:
		HPPRINTK("%s: KVM_CREATE_VM\n", __func__);
		r = kvm_dev_ioctl_create_vm(arg);
		break;
	case KVM_CHECK_EXTENSION:
		HPPRINTK("%s: KVM_CHECK_EXTENSION\n", __func__);
		r = kvm_vm_ioctl_check_extension_generic(NULL, arg);
		break;
	case KVM_GET_VCPU_MMAP_SIZE:
		HPPRINTK("%s: KVM_GET_VCPU_MMAP_SIZE\n", __func__);
		if (arg)
			goto out;
		r = PAGE_SIZE;     /* struct kvm_run */
#ifdef CONFIG_X86
		r += PAGE_SIZE;    /* pio data page */
#endif
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
		r += PAGE_SIZE;    /* coalesced mmio ring page */
#endif
		HPPRINTK("%s: KVM_GET_VCPU_MMAP_SIZE ret %ld\n", __func__, r);
		break;
	case KVM_TRACE_ENABLE:
	case KVM_TRACE_PAUSE:
	case KVM_TRACE_DISABLE:
		r = -EOPNOTSUPP;
		break;
	default:
		HPPRINTK("%s: (default) -> kvm_arch_dev_ioctl()\n", __func__);
		return kvm_arch_dev_ioctl(filp, ioctl, arg);
	}
out:
	return r;
}

static struct file_operations kvm_chardev_ops = {
	.unlocked_ioctl = kvm_dev_ioctl,
	.compat_ioctl   = kvm_dev_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice kvm_dev = {
	KVM_MINOR,
	"kvm",
	&kvm_chardev_ops,
};

static void hardware_enable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();
	int r;

	if (cpumask_test_cpu(cpu, cpus_hardware_enabled))
		return;

	cpumask_set_cpu(cpu, cpus_hardware_enabled);

	r = kvm_arch_hardware_enable();

	if (r) {
		cpumask_clear_cpu(cpu, cpus_hardware_enabled);
		atomic_inc(&hardware_enable_failed);
		pr_info("kvm: enabling virtualization on CPU%d failed\n", cpu);
	}
}

static void hardware_enable(void)
{
	raw_spin_lock(&kvm_count_lock);
	if (kvm_usage_count)
		hardware_enable_nolock(NULL);
	raw_spin_unlock(&kvm_count_lock);
}

static void hardware_disable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();

	if (!cpumask_test_cpu(cpu, cpus_hardware_enabled))
		return;
	cpumask_clear_cpu(cpu, cpus_hardware_enabled);
	kvm_arch_hardware_disable();
}

static void hardware_disable(void)
{
	raw_spin_lock(&kvm_count_lock);
	if (kvm_usage_count)
		hardware_disable_nolock(NULL);
	raw_spin_unlock(&kvm_count_lock);
}

static void hardware_disable_all_nolock(void)
{
	BUG_ON(!kvm_usage_count);

	kvm_usage_count--;
	if (!kvm_usage_count)
		on_each_cpu(hardware_disable_nolock, NULL, 1);
}

static void hardware_disable_all(void)
{
	raw_spin_lock(&kvm_count_lock);
	hardware_disable_all_nolock();
	raw_spin_unlock(&kvm_count_lock);
}

static int hardware_enable_all(void)
{
	int r = 0;

	raw_spin_lock(&kvm_count_lock);

	kvm_usage_count++;
	if (kvm_usage_count == 1) {
		atomic_set(&hardware_enable_failed, 0);
		on_each_cpu(hardware_enable_nolock, NULL, 1);

		if (atomic_read(&hardware_enable_failed)) {
			hardware_disable_all_nolock();
			r = -EBUSY;
		}
	}

	raw_spin_unlock(&kvm_count_lock);

	return r;
}

static int kvm_cpu_hotplug(struct notifier_block *notifier, unsigned long val,
			   void *v)
{
	val &= ~CPU_TASKS_FROZEN;
	switch (val) {
	case CPU_DYING:
		hardware_disable();
		break;
	case CPU_STARTING:
		hardware_enable();
		break;
	}
	return NOTIFY_OK;
}

static int kvm_reboot(struct notifier_block *notifier, unsigned long val,
		      void *v)
{
	/*
	 * Some (well, at least mine) BIOSes hang on reboot if
	 * in vmx root mode.
	 *
	 * And Intel TXT required VMX off for all cpu when system shutdown.
	 */
	pr_info("kvm: exiting hardware virtualization\n");
	kvm_rebooting = true;
	on_each_cpu(hardware_disable_nolock, NULL, 1);
	return NOTIFY_OK;
}

static struct notifier_block kvm_reboot_notifier = {
	.notifier_call = kvm_reboot,
	.priority = 0,
};

static void kvm_io_bus_destroy(struct kvm_io_bus *bus)
{
	int i;

	for (i = 0; i < bus->dev_count; i++) {
		struct kvm_io_device *pos = bus->range[i].dev;

		kvm_iodevice_destructor(pos);
	}
	kfree(bus);
}

static inline int kvm_io_bus_cmp(const struct kvm_io_range *r1,
				 const struct kvm_io_range *r2)
{
	gpa_t addr1 = r1->addr;
	gpa_t addr2 = r2->addr;

	if (addr1 < addr2)
		return -1;

	/* If r2->len == 0, match the exact address.  If r2->len != 0,
	 * accept any overlapping write.  Any order is acceptable for
	 * overlapping ranges, because kvm_io_bus_get_first_dev ensures
	 * we process all of them.
	 */
	if (r2->len) {
		addr1 += r1->len;
		addr2 += r2->len;
	}

	if (addr1 > addr2)
		return 1;

	return 0;
}

static int kvm_io_bus_sort_cmp(const void *p1, const void *p2)
{
	return kvm_io_bus_cmp(p1, p2);
}

static int kvm_io_bus_insert_dev(struct kvm_io_bus *bus, struct kvm_io_device *dev,
			  gpa_t addr, int len)
{
	bus->range[bus->dev_count++] = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
		.dev = dev,
	};

	sort(bus->range, bus->dev_count, sizeof(struct kvm_io_range),
		kvm_io_bus_sort_cmp, NULL);

	return 0;
}

static int kvm_io_bus_get_first_dev(struct kvm_io_bus *bus,
			     gpa_t addr, int len)
{
	struct kvm_io_range *range, key;
	int off;

	key = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	range = bsearch(&key, bus->range, bus->dev_count,
			sizeof(struct kvm_io_range), kvm_io_bus_sort_cmp);
	if (range == NULL)
		return -ENOENT;

	off = range - bus->range;

	while (off > 0 && kvm_io_bus_cmp(&key, &bus->range[off-1]) == 0)
		off--;

	return off;
}

static int __kvm_io_bus_write(struct kvm_vcpu *vcpu, struct kvm_io_bus *bus,
			      struct kvm_io_range *range, const void *val)
{
	int idx;

	idx = kvm_io_bus_get_first_dev(bus, range->addr, range->len);
	if (idx < 0)
		return -EOPNOTSUPP;

	while (idx < bus->dev_count &&
		kvm_io_bus_cmp(range, &bus->range[idx]) == 0) {
		if (!kvm_iodevice_write(vcpu, bus->range[idx].dev, range->addr,
					range->len, val)) {
#ifdef CONFIG_POPCORN_HYPE
			/* matching bus */
			static unsigned long cnt = 0;
			static unsigned long no_print_cnt = 0;
			cnt++;
			//if (cnt > 0 && (cnt < 10000 || idx > 2) ) {
			if (idx > 0) {
				/* This is not only for critical net debugging... */
				CRITICALNETPK("\t\t|| %s(): <%d> bus->dev_count %d "
						"->ioeventfd_count %d idx %d "
						"gpa 0x%llx (input) gpa 0x%llx #%lu (#%lu)\n",
						__func__, vcpu->vcpu_id,
						bus->dev_count, bus->ioeventfd_count, idx,
						bus->range[idx].addr, range->addr, cnt, no_print_cnt);
			} else {
				no_print_cnt++;
			}
#endif
			return idx;
		}
		idx++;
	}

	return -EOPNOTSUPP;
}

/* kvm_io_bus_write - called under kvm->slots_lock */
int kvm_io_bus_write(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx, gpa_t addr,
		     int len, const void *val)
{
	struct kvm_io_bus *bus;
	struct kvm_io_range range;
	int r;
#ifdef CONFIG_POPCORN_HYPE
    //static unsigned long cnt = 0;
#endif

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(vcpu->kvm->buses[bus_idx], &vcpu->kvm->srcu);
	if (!bus)
		return -ENOMEM;

#ifdef CONFIG_POPCORN_HYPE
    // many
	//cnt++;
    //if (cnt > 0) {
	//	printk("\t\t|| %s(): <%d> bus->ioeventfd_count %d #%lu\n",
	//			__func__, vcpu->vcpu_id, bus->ioeventfd_count, cnt);
	//}
#endif
	r = __kvm_io_bus_write(vcpu, bus, &range, val);
	return r < 0 ? r : 0;
}

/* kvm_io_bus_write_cookie - called under kvm->slots_lock */
int kvm_io_bus_write_cookie(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx,
			    gpa_t addr, int len, const void *val, long cookie)
{
	struct kvm_io_bus *bus;
	struct kvm_io_range range;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(vcpu->kvm->buses[bus_idx], &vcpu->kvm->srcu);
	if (!bus)
		return -ENOMEM;

	/* First try the device referenced by cookie. */
	if ((cookie >= 0) && (cookie < bus->dev_count) &&
	    (kvm_io_bus_cmp(&range, &bus->range[cookie]) == 0)) {

		if (!kvm_iodevice_write(vcpu, bus->range[cookie].dev, addr, len,
					val))
			return cookie;
	}

	/*
	 * cookie contained garbage; fall back to search and return the
	 * correct cookie value.
	 */
	return __kvm_io_bus_write(vcpu, bus, &range, val);
}

static int __kvm_io_bus_read(struct kvm_vcpu *vcpu, struct kvm_io_bus *bus,
			     struct kvm_io_range *range, void *val)
{
	int idx;

	idx = kvm_io_bus_get_first_dev(bus, range->addr, range->len);
	if (idx < 0)
		return -EOPNOTSUPP;

	while (idx < bus->dev_count &&
		kvm_io_bus_cmp(range, &bus->range[idx]) == 0) {
		if (!kvm_iodevice_read(vcpu, bus->range[idx].dev, range->addr,
				       range->len, val))
			return idx;
		idx++;
	}

	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(kvm_io_bus_write);

/* kvm_io_bus_read - called under kvm->slots_lock */
int kvm_io_bus_read(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx, gpa_t addr,
		    int len, void *val)
{
	struct kvm_io_bus *bus;
	struct kvm_io_range range;
	int r;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(vcpu->kvm->buses[bus_idx], &vcpu->kvm->srcu);
	if (!bus)
		return -ENOMEM;
	r = __kvm_io_bus_read(vcpu, bus, &range, val);
	return r < 0 ? r : 0;
}


/* Caller must hold slots_lock. */
int kvm_io_bus_register_dev(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
			    int len, struct kvm_io_device *dev)
{
	struct kvm_io_bus *new_bus, *bus;

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t\tpophype: vhost-net-evenfd: %s(): "
			"register gpa_t 0x%llx bus_idx %d dev %p\n",
			__func__, addr, bus_idx, dev);
#endif
	bus = kvm->buses[bus_idx];
	if (!bus)
		return -ENOMEM;

	/* exclude ioeventfd which is limited by maximum fd */
	if (bus->dev_count - bus->ioeventfd_count > NR_IOBUS_DEVS - 1)
		return -ENOSPC;

	new_bus = kmalloc(sizeof(*bus) + ((bus->dev_count + 1) *
			  sizeof(struct kvm_io_range)), GFP_KERNEL);
	if (!new_bus)
		return -ENOMEM;
	memcpy(new_bus, bus, sizeof(*bus) + (bus->dev_count *
	       sizeof(struct kvm_io_range)));
	kvm_io_bus_insert_dev(new_bus, dev, addr, len);
	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
	kfree(bus);

	return 0;
}

/* Caller must hold slots_lock. */
void kvm_io_bus_unregister_dev(struct kvm *kvm, enum kvm_bus bus_idx,
			       struct kvm_io_device *dev)
{
	int i;
	struct kvm_io_bus *new_bus, *bus;

	bus = kvm->buses[bus_idx];
	if (!bus)
		return;

	for (i = 0; i < bus->dev_count; i++)
		if (bus->range[i].dev == dev) {
			break;
		}

	if (i == bus->dev_count)
		return;

	new_bus = kmalloc(sizeof(*bus) + ((bus->dev_count - 1) *
			  sizeof(struct kvm_io_range)), GFP_KERNEL);
	if (!new_bus)  {
		pr_err("kvm: failed to shrink bus, removing it completely\n");
		goto broken;
	}

	memcpy(new_bus, bus, sizeof(*bus) + i * sizeof(struct kvm_io_range));
	new_bus->dev_count--;
	memcpy(new_bus->range + i, bus->range + i + 1,
	       (new_bus->dev_count - i) * sizeof(struct kvm_io_range));

broken:
	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
	kfree(bus);
	return;
}

static struct notifier_block kvm_cpu_notifier = {
	.notifier_call = kvm_cpu_hotplug,
};

static int vm_stat_get(void *_offset, u64 *val)
{
	unsigned offset = (long)_offset;
	struct kvm *kvm;

	*val = 0;
	spin_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list)
		*val += *(u32 *)((void *)kvm + offset);
	spin_unlock(&kvm_lock);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(vm_stat_fops, vm_stat_get, NULL, "%llu\n");

static int vcpu_stat_get(void *_offset, u64 *val)
{
	unsigned offset = (long)_offset;
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
	int i;

	*val = 0;
	spin_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list)
		kvm_for_each_vcpu(i, vcpu, kvm)
			*val += *(u32 *)((void *)vcpu + offset);

	spin_unlock(&kvm_lock);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(vcpu_stat_fops, vcpu_stat_get, NULL, "%llu\n");

static const struct file_operations *stat_fops[] = {
	[KVM_STAT_VCPU] = &vcpu_stat_fops,
	[KVM_STAT_VM]   = &vm_stat_fops,
};

static int kvm_init_debug(void)
{
	int r = -EEXIST;
	struct kvm_stats_debugfs_item *p;

	kvm_debugfs_dir = debugfs_create_dir("kvm", NULL);
	if (kvm_debugfs_dir == NULL)
		goto out;

	for (p = debugfs_entries; p->name; ++p) {
		p->dentry = debugfs_create_file(p->name, 0444, kvm_debugfs_dir,
						(void *)(long)p->offset,
						stat_fops[p->kind]);
		if (p->dentry == NULL)
			goto out_dir;
	}

	return 0;

out_dir:
	debugfs_remove_recursive(kvm_debugfs_dir);
out:
	return r;
}

static void kvm_exit_debug(void)
{
	struct kvm_stats_debugfs_item *p;

	for (p = debugfs_entries; p->name; ++p)
		debugfs_remove(p->dentry);
	debugfs_remove(kvm_debugfs_dir);
}

static int kvm_suspend(void)
{
	if (kvm_usage_count)
		hardware_disable_nolock(NULL);
	return 0;
}

static void kvm_resume(void)
{
	if (kvm_usage_count) {
		WARN_ON(raw_spin_is_locked(&kvm_count_lock));
		hardware_enable_nolock(NULL);
	}
}

static struct syscore_ops kvm_syscore_ops = {
	.suspend = kvm_suspend,
	.resume = kvm_resume,
};

static inline
struct kvm_vcpu *preempt_notifier_to_vcpu(struct preempt_notifier *pn)
{
	return container_of(pn, struct kvm_vcpu, preempt_notifier);
}

static void kvm_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct kvm_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	if (vcpu->preempted)
		vcpu->preempted = false;

	kvm_arch_sched_in(vcpu, cpu);

#if defined(CONFIG_POPCORN_HYPE) && HYPEBOOTDEBUG && POPHYPE_MIGRATE_VERBOSE_DEBUG
	{
		static int cnt = 0;
		if (!(cnt % 10000)) {
			PHMIGRATEVPRINTK("------- %s(): <%d> host cpu %d ------- #%d\n",
										__func__, vcpu->vcpu_id, cpu, cnt);
		}
		if ((cnt++ % 10000) == 0) {
			/* From ...
				kvm_arch_vcpu_load()
				vmx_vcpu_load() */
			//dump_stack(); /* turn on to debug why this happens in default */
		}
	}
#endif
	kvm_arch_vcpu_load(vcpu, cpu);
}

static void kvm_sched_out(struct preempt_notifier *pn,
			  struct task_struct *next)
{
	struct kvm_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	if (current->state == TASK_RUNNING)
		vcpu->preempted = true;
	kvm_arch_vcpu_put(vcpu);
}

int kvm_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align,
		  struct module *module)
{
	int r;
	int cpu;

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t%s():\n", __func__);
#endif

	r = kvm_arch_init(opaque);
	if (r)
		goto out_fail;

	/*
	 * kvm_arch_init makes sure there's at most one caller
	 * for architectures that support multiple implementations,
	 * like intel and amd on x86.
	 * kvm_arch_init must be called before kvm_irqfd_init to avoid creating
	 * conflicts in case kvm is already setup for another implementation.
	 */
	r = kvm_irqfd_init();
	if (r)
		goto out_irqfd;

	if (!zalloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out_free_0;
	}

	r = kvm_arch_hardware_setup();
	if (r < 0)
		goto out_free_0a;

	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu,
				kvm_arch_check_processor_compat,
				&r, 1);
		if (r < 0)
			goto out_free_1;
	}

	r = register_cpu_notifier(&kvm_cpu_notifier);
	if (r)
		goto out_free_2;
	register_reboot_notifier(&kvm_reboot_notifier);

	/* A kmem cache lets us meet the alignment requirements of fx_save. */
	if (!vcpu_align)
		vcpu_align = __alignof__(struct kvm_vcpu);
	kvm_vcpu_cache = kmem_cache_create("kvm_vcpu", vcpu_size, vcpu_align,
					   0, NULL);
	if (!kvm_vcpu_cache) {
		r = -ENOMEM;
		goto out_free_3;
	}

	r = kvm_async_pf_init();
	if (r)
		goto out_free;

	kvm_chardev_ops.owner = module;
	kvm_vm_fops.owner = module;
	kvm_vcpu_fops.owner = module;

	r = misc_register(&kvm_dev);
	if (r) {
		pr_err("kvm: misc device register failed\n");
		goto out_unreg;
	}

	register_syscore_ops(&kvm_syscore_ops);

	kvm_preempt_ops.sched_in = kvm_sched_in;
	kvm_preempt_ops.sched_out = kvm_sched_out;

	r = kvm_init_debug();
	if (r) {
		pr_err("kvm: create debugfs files failed\n");
		goto out_undebugfs;
	}

	r = kvm_vfio_ops_init();
	WARN_ON(r);

	return 0;

out_undebugfs:
	unregister_syscore_ops(&kvm_syscore_ops);
	misc_deregister(&kvm_dev);
out_unreg:
	kvm_async_pf_deinit();
out_free:
	kmem_cache_destroy(kvm_vcpu_cache);
out_free_3:
	unregister_reboot_notifier(&kvm_reboot_notifier);
	unregister_cpu_notifier(&kvm_cpu_notifier);
out_free_2:
out_free_1:
	kvm_arch_hardware_unsetup();
out_free_0a:
	free_cpumask_var(cpus_hardware_enabled);
out_free_0:
	kvm_irqfd_exit();
out_irqfd:
	kvm_arch_exit();
out_fail:
	return r;
}
EXPORT_SYMBOL_GPL(kvm_init);

void kvm_exit(void)
{
	kvm_exit_debug();
	misc_deregister(&kvm_dev);
	kmem_cache_destroy(kvm_vcpu_cache);
	kvm_async_pf_deinit();
	unregister_syscore_ops(&kvm_syscore_ops);
	unregister_reboot_notifier(&kvm_reboot_notifier);
	unregister_cpu_notifier(&kvm_cpu_notifier);
	on_each_cpu(hardware_disable_nolock, NULL, 1);
	kvm_arch_hardware_unsetup();
	kvm_arch_exit();
	kvm_irqfd_exit();
	free_cpumask_var(cpus_hardware_enabled);
	kvm_vfio_ops_exit();
}
EXPORT_SYMBOL_GPL(kvm_exit);
