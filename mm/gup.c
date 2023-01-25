#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/spinlock.h>

#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/swapops.h>

#include <linux/sched.h>
#include <linux/rwsem.h>
#include <linux/hugetlb.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_POPCORN
#define HYPE_GUP_RETRY 1 // BUG......
#include <popcorn/process_server.h>
#include <popcorn/vma_server.h>
#include <popcorn/page_server.h>
#include <popcorn/debug.h>
#include <linux/delay.h>
#endif

#include "internal.h"

static struct page *no_page_table(struct vm_area_struct *vma,
		unsigned int flags)
{
	/*
	 * When core dumping an enormous anonymous area that nobody
	 * has touched so far, we don't want to allocate unnecessary pages or
	 * page tables.  Return error instead of NULL to skip handle_mm_fault,
	 * then get_dump_page() will return NULL to leave a hole in the dump.
	 * But we can only make this optimization where a hole would surely
	 * be zero-filled if handle_mm_fault() actually did handle it.
	 */
	if ((flags & FOLL_DUMP) && (!vma->vm_ops || !vma->vm_ops->fault))
		return ERR_PTR(-EFAULT);
	return NULL;
}

static int follow_pfn_pte(struct vm_area_struct *vma, unsigned long address,
		pte_t *pte, unsigned int flags)
{
	/* No page to get reference */
	if (flags & FOLL_GET)
		return -EFAULT;

	if (flags & FOLL_TOUCH) {
		pte_t entry = *pte;

		if (flags & FOLL_WRITE)
			entry = pte_mkdirty(entry);
		entry = pte_mkyoung(entry);

		if (!pte_same(*pte, entry)) {
			set_pte_at(vma->vm_mm, address, pte, entry);
			update_mmu_cache(vma, address, pte);
		}
	}

	/* Proper page table entry exists, but no corresponding struct page */
	return -EEXIST;
}

/*
 * FOLL_FORCE can write to even unwritable pte's, but only
 * after we've gone through a COW cycle and they are dirty.
 */
static inline bool can_follow_write_pte(pte_t pte, unsigned int flags)
{
	return pte_write(pte) ||
		((flags & FOLL_FORCE) && (flags & FOLL_COW) && pte_dirty(pte));
}

static struct page *follow_page_pte(struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd, unsigned int flags)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page *page;
	spinlock_t *ptl;
	pte_t *ptep, pte;

retry:
	if (unlikely(pmd_bad(*pmd)))
		return no_page_table(vma, flags);

	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	pte = *ptep;
	if (!pte_present(pte)) {
		swp_entry_t entry;
		/*
		 * KSM's break_ksm() relies upon recognizing a ksm page
		 * even while it is being migrated, so for that case we
		 * need migration_entry_wait().
		 */
		if (likely(!(flags & FOLL_MIGRATION)))
			goto no_page;
		if (pte_none(pte))
			goto no_page;
		entry = pte_to_swp_entry(pte);
		if (!is_migration_entry(entry))
			goto no_page;
		pte_unmap_unlock(ptep, ptl);
		migration_entry_wait(mm, pmd, address);
		goto retry;
	}
	if ((flags & FOLL_NUMA) && pte_protnone(pte))
		goto no_page;
	if ((flags & FOLL_WRITE) && !can_follow_write_pte(pte, flags)) {
		pte_unmap_unlock(ptep, ptl);
		return NULL;
	}

	page = vm_normal_page(vma, address, pte);
	if (unlikely(!page)) {
		if (flags & FOLL_DUMP) {
			/* Avoid special (like zero) pages in core dumps */
			page = ERR_PTR(-EFAULT);
			goto out;
		}

		if (is_zero_pfn(pte_pfn(pte))) {
			page = pte_page(pte);
		} else {
			int ret;

			ret = follow_pfn_pte(vma, address, ptep, flags);
			page = ERR_PTR(ret);
			goto out;
		}
	}

	if (flags & FOLL_GET)
		get_page_foll(page);
	if (flags & FOLL_TOUCH) {
		if ((flags & FOLL_WRITE) &&
		    !pte_dirty(pte) && !PageDirty(page))
			set_page_dirty(page);
		/*
		 * pte_mkyoung() would be more correct here, but atomic care
		 * is needed to avoid losing the dirty bit: it is easier to use
		 * mark_page_accessed().
		 */
		mark_page_accessed(page);
	}
	if ((flags & FOLL_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
		/*
		 * The preliminary mapping check is mainly to avoid the
		 * pointless overhead of lock_page on the ZERO_PAGE
		 * which might bounce very badly if there is contention.
		 *
		 * If the page is already locked, we don't need to
		 * handle it now - vmscan will handle it later if and
		 * when it attempts to reclaim the page.
		 */
		if (page->mapping && trylock_page(page)) {
			lru_add_drain();  /* push cached pages to LRU */
			/*
			 * Because we lock page here, and migration is
			 * blocked by the pte's page reference, and we
			 * know the page is still mapped, we don't even
			 * need to check for file-cache page truncation.
			 */
			mlock_vma_page(page);
			unlock_page(page);
		}
	}
out:
	pte_unmap_unlock(ptep, ptl);
	return page;
no_page:
	pte_unmap_unlock(ptep, ptl);
	if (!pte_none(pte))
		return NULL;
	return no_page_table(vma, flags);
}

/**
 * follow_page_mask - look up a page descriptor from a user-virtual address
 * @vma: vm_area_struct mapping @address
 * @address: virtual address to look up
 * @flags: flags modifying lookup behaviour
 * @page_mask: on output, *page_mask is set according to the size of the page
 *
 * @flags can have FOLL_ flags set, defined in <linux/mm.h>
 *
 * Returns the mapped (struct page *), %NULL if no mapping exists, or
 * an error pointer if there is a mapping to something not represented
 * by a page descriptor (see also vm_normal_page()).
 */
struct page *follow_page_mask(struct vm_area_struct *vma,
			      unsigned long address, unsigned int flags,
			      unsigned int *page_mask)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

	*page_mask = 0;

	page = follow_huge_addr(mm, address, flags & FOLL_WRITE);
	if (!IS_ERR(page)) {
		BUG_ON(flags & FOLL_GET);
		return page;
	}

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return no_page_table(vma, flags);

	pud = pud_offset(pgd, address);
	if (pud_none(*pud))
		return no_page_table(vma, flags);
	if (pud_huge(*pud) && vma->vm_flags & VM_HUGETLB) {
		page = follow_huge_pud(mm, address, pud, flags);
		if (page)
			return page;
		return no_page_table(vma, flags);
	}
	if (unlikely(pud_bad(*pud)))
		return no_page_table(vma, flags);

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return no_page_table(vma, flags);
	if (pmd_huge(*pmd) && vma->vm_flags & VM_HUGETLB) {
		page = follow_huge_pmd(mm, address, pmd, flags);
		if (page)
			return page;
		return no_page_table(vma, flags);
	}
	if ((flags & FOLL_NUMA) && pmd_protnone(*pmd))
		return no_page_table(vma, flags);
	if (pmd_trans_huge(*pmd)) {
		if (flags & FOLL_SPLIT) {
			split_huge_page_pmd(vma, address, pmd);
			return follow_page_pte(vma, address, pmd, flags);
		}
		ptl = pmd_lock(mm, pmd);
		if (likely(pmd_trans_huge(*pmd))) {
			if (unlikely(pmd_trans_splitting(*pmd))) {
				spin_unlock(ptl);
				wait_split_huge_page(vma->anon_vma, pmd);
			} else {
				page = follow_trans_huge_pmd(vma, address,
							     pmd, flags);
				spin_unlock(ptl);
				*page_mask = HPAGE_PMD_NR - 1;
				return page;
			}
		} else
			spin_unlock(ptl);
	}
	return follow_page_pte(vma, address, pmd, flags);
}

static int get_gate_page(struct mm_struct *mm, unsigned long address,
		unsigned int gup_flags, struct vm_area_struct **vma,
		struct page **page)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret = -EFAULT;

	/* user gate pages are read-only */
	if (gup_flags & FOLL_WRITE)
		return -EFAULT;
	if (address > TASK_SIZE)
		pgd = pgd_offset_k(address);
	else
		pgd = pgd_offset_gate(mm, address);
	BUG_ON(pgd_none(*pgd));
	pud = pud_offset(pgd, address);
	BUG_ON(pud_none(*pud));
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return -EFAULT;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	pte = pte_offset_map(pmd, address);
	if (pte_none(*pte))
		goto unmap;
	*vma = get_gate_vma(mm);
	if (!page)
		goto out;
	*page = vm_normal_page(*vma, address, *pte);
	if (!*page) {
		if ((gup_flags & FOLL_DUMP) || !is_zero_pfn(pte_pfn(*pte)))
			goto unmap;
		*page = pte_page(*pte);
	}
	get_page(*page);
out:
	ret = 0;
unmap:
	pte_unmap(pte);
	return ret;
}

/*
 * mmap_sem must be held on entry.  If @nonblocking != NULL and
 * *@flags does not include FOLL_NOWAIT, the mmap_sem may be released.
 * If it is, *@nonblocking will be set to 0 and -EBUSY returned.
 */
static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
		unsigned long address, unsigned int *flags, int *nonblocking)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned int fault_flags = 0;
	int ret;

#ifdef CONFIG_POPCORN_HYPE
	/* lkvm interested cases
		1st __gfn_to_pfn_memslot/ hva_to_pfn path:
			vmas: NULL, nonblocking(locked): NULL
				gup_flags: FOLL_TOUCH | FOLL_NOWAIT |
							FOLL_HWPOISON | FOLL_GET | (FOLL_WRITE)

		2nd __gfn_to_pfn_memslot/ hva_to_pfn path:
					vmas: NULL, *nonblocking(*locked): 1
					gup_flags = FOLL_TOUCH | FOLL_HWPOISON (from the topest)
								FOLL_GET | (FOLL_WRITE)

		Diff: 1st is FOLL_NOWAIT, 2nd is !FOLL_NOWAIT
			1st nonblocking(locked): NULL 2nd *nonblocking(*locked): 1
	*/
#endif

	/* mlock all present pages, but do not fault in new pages */
	if ((*flags & (FOLL_POPULATE | FOLL_MLOCK)) == FOLL_MLOCK)
		return -ENOENT;
	if (*flags & FOLL_WRITE)
		fault_flags |= FAULT_FLAG_WRITE;
	if (nonblocking) {
#ifdef CONFIG_POPCORN_HYPE
		/* 1st NULL 2nd *nonblocking 1 2nd-2 NULL*/
#endif
		fault_flags |= FAULT_FLAG_ALLOW_RETRY;
	}
	if (*flags & FOLL_NOWAIT)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	if (*flags & FOLL_TRIED) {
#ifdef CONFIG_POPCORN_HYPE
		/* 2nd-2 case meaning 2nd failed....and now retrying */
#endif
		VM_WARN_ON_ONCE(fault_flags & FAULT_FLAG_ALLOW_RETRY);
		fault_flags |= FAULT_FLAG_TRIED;
	}

#ifdef CONFIG_POPCORN_HYPE
	/* aka handle_pte_fault(dsm) return directly */
	/* HOOK WITH DSM */
	// __get_user_pages -> (faultin_page) -> __handle_mm_fault ->
	//		handle_pte_fault -> page_server_handle_pte_fault
#endif
	ret = handle_mm_fault(mm, vma, address, fault_flags);
#ifdef CONFIG_POPCORN_HYPE
	if (tsk) {
		if (distributed_process(tsk)) {
			//if ((address & 0xffff000) == 0x1c75 ||
			//	(address & 0xffff000) == 0x1f1b) {
			if (INTERESTED_GVA(address)) {
				//printk("\t\t\t%s(): pophype %lx ret %lx\n",
				//				__func__, address, (long)ret);
			}
		}
	}
#endif
	if (ret & VM_FAULT_ERROR) {
#ifdef CONFIG_POPCORN_HYPE
		if (tsk) {
			if (distributed_process(tsk)) {
				printk("%s(): !![%d] %lx VM_FAULT_ERROR ret %x (THINK ABOUT IT)\n",
								__func__, tsk->pid, address, ret);
			}
		}
#endif
		if (ret & VM_FAULT_OOM)
			return -ENOMEM;
		if (ret & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
			return *flags & FOLL_HWPOISON ? -EHWPOISON : -EFAULT;
		if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			return -EFAULT;
		BUG();
	}

	if (tsk) {
		if (ret & VM_FAULT_MAJOR)
			tsk->maj_flt++;
		else
			tsk->min_flt++;
	}

	if (ret & VM_FAULT_RETRY) {
#ifdef CONFIG_POPCORN_HYPE
		/* Can be local RETRY=(DSM CONTINU + local RETRY) or DSM RETRY */
#endif
		if (nonblocking) {
#ifdef CONFIG_POPCORN_HYPE
			/* 1st NULL 2nd *nonblocking 1 2nd-2 NULL*/
			BUG_ON(distributed_process(tsk));
			/* =*locked */
			/* TODO 0526 not sure but testing */
			*nonblocking = 0;
#else
			*nonblocking = 0;
#endif
		}
#ifdef CONFIG_POPCORN_HYPE
		if (tsk) {
			if (distributed_process(tsk)) {
				EPTVVPRINTK("%s(): @@ [%d] %lx HYPE_RETRY (for debug)\n",
											__func__, tsk->pid, address);
				/* POPCRON DSM RETRY ALSO SHARE THIS (*locked|*nonblocking=0) */

				/* if from caller, defaultly *nonblocking(locked)=1 or
														!nonblocking */

				/* debuggin fore reasons */
				if (!(ret & VM_FAULT_HYPE_RETRY) && (ret & VM_FAULT_RETRY)) {
					printk("%s(): @@ $$[%d] %lx $$VM_FAULT_RETRY$$ locally$$$$$ "
										"r 0x%x (for debug)\n",
										__func__, tsk->pid, address, ret);
				}
//				else if ((ret & VM_FAULT_HYPE_RETRY) &&
//							(ret & VM_FAULT_RETRY)) {
//					printk("%s(): @@ [%d] %lx "
//							//"VM_FAULT_HYPE_RETRY a super set of VM_FAULT_RETRY "
//							"r 0x%x from DSM RETRY\n",
//							__func__, tsk->pid, address, ret);
//				}
#ifdef CONFIG_POPCORN_CHECK_SANITY
				/* impossible */
				BUG_ON((ret & VM_FAULT_HYPE_RETRY) && !(ret & VM_FAULT_RETRY));
#endif

				// DEBUG
				if (ret & VM_FAULT_LOCKED) {
					printk("%s(): @@ !![%d] %lx $$VM_FAULT_LOCKED$$ "
										"r 0x%x (for debug)\n",
										__func__, tsk->pid, address, ret);
				}
				if (ret & VM_FAULT_NOPAGE) {
					printk("%s(): @@ !![%d] %lx $$VM_FAULT_NOPAGE$$ "
											"r 0x%x (for debug)\n",
											__func__, tsk->pid, address, ret);
				}
				if (ret & VM_FAULT_KILLED) {
					printk("%s(): @@ !![%d] %lx $$VM_FAULT_KILLED$$ "
											"r 0x%x (for debug)\n",
											__func__, tsk->pid, address, ret);
				}

				/*****************************************
				 *	Pophype - obey PTE fault/DSM sematics to retry -
				 *											throw to upper
				 *	check the discription of handle_mm_fault()
				 *									in __do_page_fault().
				 *	"if we get VM_FAULT_RETRY back,
				 *		the mmap_sem has been unlocked."
				 *
				 *	So, we unlock here now.
				 *****************************************/
				//goto retry; // throw to upper level don't retry here
				if (ret & VM_FAULT_HYPE_RETRY) {
					//printk("%s(): @@ [%d] %lx HYPE RETRY #%lu\n"
					//	__func__, tsk->pid, address, pophype_dsm_retry++);
					down_read(&tsk->mm->mmap_sem);
				}

			}
		} else { BUG(); }
#endif

		return -EBUSY;
	}
#ifdef CONFIG_POPCORN_HYPE
	else {
		if (tsk->backoff_weight &&
			NOTINTERESTED_GVA(address)
			) {
			EPTPRINTK("@@ %s(): [%d] %lx HYPE_RETRYed/backoffed #%d(+0/1)\n",
					__func__, tsk->pid, address, tsk->backoff_weight * 2);
		}
	}

	if (ret & VM_FAULT_CONTINUE) {
		printk("@@ %s(): !![%d] %lx TODO VM_FAULT_CONTINUE "
								"r 0x%x (for debug)\n",
								__func__, tsk->pid, address, ret);
	}
#endif

	/*
	 * The VM_FAULT_WRITE bit tells us that do_wp_page has broken COW when
	 * necessary, even if maybe_mkwrite decided not to set pte_write. We
	 * can thus safely do subsequent page lookups as if they were reads.
	 * But only do so when looping for pte_write is futile: in some cases
	 * userspace may also be wanting to write to the gotten user page,
	 * which a read fault here might prevent (a readonly page might get
	 * reCOWed by userspace write).
	 */
	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE)) {
		*flags |= FOLL_COW;
#ifdef CONFIG_POPCORN_HYPE
		/* seems dirtycow patvh */
		if (distributed_remote_process(tsk)) {
			printk(KERN_ERR "[%d] %lx XXX COW AT REMOTE XXX\n",
											tsk->pid, address);
			BUG(); /* IF, HANDLE IT */
		}
#endif
	}
	return 0;
}

static int check_vma_flags(struct vm_area_struct *vma, unsigned long gup_flags)
{
	vm_flags_t vm_flags = vma->vm_flags;

	if (vm_flags & (VM_IO | VM_PFNMAP))
		return -EFAULT;

	if (gup_flags & FOLL_WRITE) {
		if (!(vm_flags & VM_WRITE)) {
			if (!(gup_flags & FOLL_FORCE))
				return -EFAULT;
			/*
			 * We used to let the write,force case do COW in a
			 * VM_MAYWRITE VM_SHARED !VM_WRITE vma, so ptrace could
			 * set a breakpoint in a read-only mapping of an
			 * executable, without corrupting the file (yet only
			 * when that file had been opened for writing!).
			 * Anon pages in shared mappings are surprising: now
			 * just reject it.
			 */
			if (!is_cow_mapping(vm_flags)) {
				WARN_ON_ONCE(vm_flags & VM_MAYWRITE);
				return -EFAULT;
			}
		}
	} else if (!(vm_flags & VM_READ)) {
		if (!(gup_flags & FOLL_FORCE))
			return -EFAULT;
		/*
		 * Is there actually any vma we can reach here which does not
		 * have VM_MAYREAD set?
		 */
		if (!(vm_flags & VM_MAYREAD))
			return -EFAULT;
	}
	return 0;
}

/**
 * __get_user_pages() - pin user pages in memory
 * @tsk:	task_struct of target task
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying pin behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @vmas:	array of pointers to vmas corresponding to each page.
 *		Or NULL if the caller does not require them.
 * @nonblocking: whether waiting for disk IO or mmap_sem contention
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with. vmas will only
 * remain valid while mmap_sem is held.
 *
 * Must be called with mmap_sem held.  It may be released.  See below.
 *
 * __get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * This does not guarantee that the page exists in the user mappings when
 * __get_user_pages returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If @gup_flags & FOLL_WRITE == 0, the page must not be written to. If
 * the page is written to, set_page_dirty (or set_page_dirty_lock, as
 * appropriate) must be called after the page is finished with, and
 * before put_page is called.
 *
 * If @nonblocking != NULL, __get_user_pages will not wait for disk IO
 * or mmap_sem contention, and if waiting is needed to pin all pages,
 * *@nonblocking will be set to 0.  Further, if @gup_flags does not
 * include FOLL_NOWAIT, the mmap_sem will be released via up_read() in
 * this case.
 *
 * A caller using such a combination of @nonblocking and @gup_flags
 * must therefore hold the mmap_sem for reading only, and recognize
 * when it's been released.  Otherwise, it must be held for either
 * reading or writing and will not be released.
 *
 * In most cases, get_user_pages or get_user_pages_fast should be used
 * instead of __get_user_pages. __get_user_pages should be used only if
 * you need some special @gup_flags.
 */
long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		struct vm_area_struct **vmas, int *nonblocking)
{
	long i = 0;
	unsigned int page_mask;
	struct vm_area_struct *vma = NULL;

#ifdef CONFIG_POPCORN_HYPE
	int iter = 0;
	unsigned long gup_retry = 0;
	unsigned long retry_itself = 0;
//	unsigned long pophype_dsm_retry = 0;
#ifdef CONFIG_POPCORN_CHECK_SANITY
	unsigned long old_start = start;
#endif
	/* lkvm interested cases
		1st __gfn_to_pfn_memslot/ hva_to_pfn path:
			vmas: NULL, nonblocking(locked): NULL
				gup_flags: FOLL_TOUCH | FOLL_NOWAIT |
							FOLL_HWPOISON | FOLL_GET | (FOLL_WRITE)

		2nd __gfn_to_pfn_memslot/ hva_to_pfn path:
					vmas: NULL, *nonblocking(*locked): 1
					gup_flags = FOLL_TOUCH | FOLL_HWPOISON (from the topest)
								FOLL_GET | (FOLL_WRITE)

		Diff 1st FOLL_NOWAIT 2nd !FOLL_NOWAIT
			1st nonblocking(locked): NULL 2nd *nonblocking(*locked): 1

		!!!!!2nd-2 (similar to 1 but flag)
				vmas: NULL nonblocking: NULL *gup_flags | FOLL_TRIED*
	*/
#endif

	if (!nr_pages)
		return 0;

	VM_BUG_ON(!!pages != !!(gup_flags & FOLL_GET));

#ifdef CONFIG_POPCORN_HYPE
	if (tsk)
		if (distributed_process(tsk)) {
			//BUG_ON(nr_pages > 1);
			WARN_ON(nr_pages > 1); /* happens when memcached - concurrent large -reqs */
		}
#endif
	/*
	 * If FOLL_FORCE is set then do not force a full fault as the hinting
	 * fault information is unrelated to the reference behaviour of a task
	 * using the address space
	 */
	if (!(gup_flags & FOLL_FORCE))
		gup_flags |= FOLL_NUMA;

	do {
		struct page *page;
		unsigned int foll_flags = gup_flags;
		unsigned int page_increm;

		/* first iteration or cross vma bound */
		if (!vma || start >= vma->vm_end) {
			/* find rbtree - property = priv/share */
			vma = find_extend_vma(mm, start);
#ifdef CONFIG_POPCORN
#ifdef CONFIG_POPCORN_HYPE
			if(tsk) {
				//if (distributed_remote_process(tsk)) {
				if (distributed_process(tsk)) {
					///* vma worker should not fault */
					BUG_ON(tsk->is_worker);
					if (!vma || start < vma->vm_start) {
					//if (!vma || vma->vm_start > address)  //
#ifdef CONFIG_POPCORN_STAT
						printk(" $$[%d] %lx TODO - remote never touch vma - "
								"no chance to test yet\n", tsk->pid, start);
						WARN_ON("Maybe BAD");
#endif
						/* If origin doesn't populate mem (enforce touch),
							this will happen at remote.
									(My sol for this is not tested yet) */
						if (vma_server_fetch_vma(tsk, start) == 0) {
							/* Replace with updated VMA */
#ifdef CONFIG_POPCORN_STAT
							printk(" $$[%d] %lx TODO - "
									"origin doesn't have it as well, "
									"alloc by myself - "
									"no chance to test yet\n", tsk->pid, start);
#endif
							vma = find_extend_vma(mm, start);
							//vma = find_vma(mm, address); //
						}
						/* Check again */
						if (!vma || start < vma->vm_start)
							BUG();
							//return -EFAULT;
					}
				}
			}
#endif
#endif

			if (!vma && in_gate_area(mm, start)) { // whether this addr is in page
				int ret;
				ret = get_gate_page(mm, start & PAGE_MASK,
						gup_flags, &vma,
						pages ? &pages[i] : NULL);
#ifdef CONFIG_POPCORN_HYPE
				printk(" $$[%d] %lx TODO - not in page\n", tsk->pid, start);
#endif
				if (ret)
					return i ? : ret;
				page_mask = 0;
				goto next_page;
			}

			if (!vma || check_vma_flags(vma, gup_flags)) {
#ifdef CONFIG_POPCORN_HYPE
				BUG_ON(distributed_process(tsk));
#endif
				return i ? : -EFAULT;
			}
			if (is_vm_hugetlb_page(vma)) {
#ifdef CONFIG_POPCORN_HYPE
				/* pophype - our dsm doesn't support hugepg */
				BUG_ON(distributed_process(tsk));
#endif
				i = follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &nr_pages, i,
						gup_flags);
				continue;
			}
		}
retry:
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_CHECK_SANITY
		if (tsk) {
			if (distributed_process(tsk)) {
				BUG_ON(i != 0); // we don't handle more than 1 fault
				//BUG_ON(i != 0 || i != 1); // i will
				BUG_ON(old_start != start);
			}
		}
#endif
#endif
		/*
		 * If we have a pending SIGKILL, don't keep faulting pages and
		 * potentially allocating memory.
		 */
		if (unlikely(fatal_signal_pending(current))) {
#ifdef CONFIG_POPCORN_HYPE
			/* ATTENTION current vs tsk */
			if (tsk) {
				if (distributed_process(tsk))
					printk(" !![%d] %lx TODO - is_signal ret/i %ld\n",
													tsk->pid, start, i);
			} else {
				printk(" !![%s] %lx pending signal while faulting ret/i %ld\n",
														"no task", start, i);
			}
#endif
			return i ? i : -ERESTARTSYS;
		}
		cond_resched();
		/* get pte */
		page = follow_page_mask(vma, start, foll_flags, &page_mask);
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_STAT
		if (tsk) {
			if (distributed_process(tsk) && gup_retry) {
				if (page) {
					/* 0603 is_page - doesn't mean is_permission */
					DSMRETRYPRINTK(" !![%d] %lx ***WATCHOUT*** "
								"solved !page #%lu MINE %s\n",
								tsk->pid, start, gup_retry,
								page_is_mine_pub(tsk->mm, start) ? "O" : "X");
					if (!page_is_mine_pub(tsk->mm, start)) {
						DSMRETRYPRINTK(" !![%d] %lx **WATCHOUT** "
										"will triger EPT_RETRY\n",
										tsk->pid, start);
					}
					BUG_ON(i);
					/* origin */
				} else {
					if (retry_itself > 0) {
						/* see this when mm_fault returns !RETRY but page is not mine.... */
						DSMRETRYPRINTK(" !![%d] %lx **MINE %s** !page imm "
								"autofix localgood#%lu gupdsmretry #%lu\n",
								tsk->pid, start,
								page_is_mine_pub(tsk->mm, start) ? "O" : "X",
								retry_itself, gup_retry);
					} /* remote */
				}
			}
#ifdef CONFIG_POPCORN_CHECK_SANITY
			if (distributed_process(tsk)) {
				if (tsk != current) {
					printk(KERN_ERR " !![%d] %lx WATCHOUT current != tsk\n",
															tsk->pid, start);
					BUG();
				}
			}
#endif
		}
#endif
#endif

		if (!page) {
			int ret;
#ifdef CONFIG_POPCORN_HYPE
//dsm_path:
//#ifdef CONFIG_POPCORN_CHECK_SANITY
//			if (tsk) {
//				if (distributed_process(tsk)) {
//					if (tsk != current) {
//						printk(KERN_ERR " !![%d] %lx WATCHOUT current != tsk\n",
//																tsk->pid, start);
//						BUG();
//					}
//				}
//			}
//#endif
			/* VM_FAULT_HYPE_RETRY debug info point */
			if (tsk) {
				if ((distributed_process(tsk) &&
					//(INTERESTED_GVA(start) || tsk->at_remote)) &&
					(INTERESTED_GVA(start))) &&
					NOTINTERESTED_GVA(start)) {
					/* 1 memslot 2 memslot both call it
						asyn is not delivered to here so
						use nonblocking to determin */
					EPTVPRINTK("\t\t=slow: (lked) __gups() %s [%d] %lx "
							"faultin_pg nrpg(remain) %lu mine %s\n",
							!nonblocking ?
								(!(gup_flags & FOLL_TRIED) ? "=1st" : "=2nd-2")
															: "=2nd",
							tsk->pid, start, nr_pages,
							page_is_mine_pub(tsk->mm, start) ? "O" : "X");
				}
			}

			// (__get_user_pages) -> faultin_page -> __handle_mm_fault ->
			//				handle_pte_fault -> page_server_handle_pte_fault
#endif
			ret = faultin_page(tsk, vma, start, &foll_flags,
					nonblocking);
#ifdef CONFIG_POPCORN_HYPE
			if (tsk) {
				if (distributed_process(tsk)) {
					//if ((start & 0xffff000) == 0x1c75 ||
					//	(start & 0xffff000) == 0x1f1b) {
					if (INTERESTED_GVA(start)) {
						//printk("\t\t\t%s(): pophype %lx ret %lx\n",
						//				__func__, start, (long)ret);
					}
				}
			}
#endif
			switch (ret) {
			case 0:
#ifdef CONFIG_POPCORN_HYPE
				/* 0: good */
				if (tsk) {
					if (distributed_process(tsk)) {
						if (retry_itself > 0) {
							if (INTERESTED_GVA(start) &&
								NOTINTERESTED_GVA(start)) {
									DSMRETRYPRINTK(" $$[%d] %lx local good #%lu"
										"\n", tsk->pid, start, retry_itself);
							}
						}
						retry_itself++;
					}
				}
#endif
				goto retry;
			case -EFAULT:
			case -ENOMEM:
			case -EHWPOISON:
#ifdef CONFIG_POPCORN_HYPE
				if (tsk)
					if (distributed_process(tsk))
						printk("!![%d] %lx TODO -EHWPOISON\n", tsk->pid, start);
#endif
				return i ? i : ret;
			case -EBUSY:
#ifdef CONFIG_POPCORN_HYPE
				/* 1st: immediately return
					2nd: *nonblocking = 0; (set by VM_FAULT_RETRY) */
				//if ((tsk && INTERESTED_GVA(start)) &&
				if (tsk) {
					if (distributed_process(tsk)) {
						if (
							INTERESTED_GVA(start)
							//(INTERESTED_GVA(start) && NOTINTERESTED_GVA(start)) ||
							//(start & 0xffff0000) == 0x1c75 ||
							//(start & 0xffff0000) == 0x1f1b
							) {
							EPTVPRINTK("\t=__gups() [%d] %s %lx ret RETRY "
								"i(succpgs) %ld HYPE_GUP_RETRY(%s) #%lu\n",
									tsk->pid,
									!nonblocking ?
										(!(gup_flags & FOLL_TRIED) ?
											"=1st(imme return)" :
											"=2nd-2 (TODO!)") :
												"=2nd(by DSM RETRY "
												"*nonblocking = 0)",
									start, i,
									HYPE_GUP_RETRY ? "O" : "X",
									gup_retry); /* i=0 */
						}
					}
				}

				/* hype retry - faultin_page has unlocked
						and VM_FAULT_HYPE_RETRY -> -EBUSY */
				if (HYPE_GUP_RETRY) {
					//if (distributed_remote_process(tsk) && // BUG
					if (distributed_process(tsk) &&
						/* retry for 1st - don't only retry for 2nd-1 */
						!nonblocking &&  (!(gup_flags & FOLL_TRIED))) {
						// =1st
						io_schedule();
						gup_retry++;
						goto retry;
						//goto dsm_path;
					} else if (distributed_process(tsk)) {
						printk(KERN_ERR "nonblocking %p gup_flags %x\n",
												nonblocking, gup_flags);
						BUG();
					}
				} else {
					printk(" !![%d] %lx need attention!\n", tsk->pid, start);
				}
#endif
				return i;
			case -ENOENT:
				goto next_page;
			}
			BUG();
		} else if (PTR_ERR(page) == -EEXIST) {
			/*
			 * Proper page table entry exists, but no corresponding
			 * struct page.
			 */
#ifdef CONFIG_POPCORN_HYPE
			if (tsk)
				if (distributed_process(tsk))
					printk(" !![%d] %lx TODO - pte but !page\n", tsk->pid, start);
#endif
			goto next_page;
		} else if (IS_ERR(page)) {
#ifdef CONFIG_POPCORN_HYPE
			if (tsk)
				if (distributed_process(tsk))
					printk(" !![%d] %lx TODO - IS_ERR(page)\n", tsk->pid, start);
#endif
			return i ? i : PTR_ERR(page);
		}

		if (pages) { /* flush cache coressponded to the page */
			pages[i] = page;
			flush_anon_page(vma, page, start);
			flush_dcache_page(page);
			page_mask = 0;
		}

next_page:
		if (vmas) {
#ifdef CONFIG_POPCORN_HYPE
			if (tsk) {
				BUG_ON(distributed_process(tsk)); /* not seen yet */
			}
#endif
			vmas[i] = vma;
			page_mask = 0;
		}
		page_increm = 1 + (~(start >> PAGE_SHIFT) & page_mask);
		if (page_increm > nr_pages)
			page_increm = nr_pages;
		i += page_increm;
		start += page_increm * PAGE_SIZE;
		nr_pages -= page_increm;
#ifdef CONFIG_POPCORN_HYPE
		iter++;
#ifdef CONFIG_POPCORN_CHECK_SANITY
		if (tsk)
			if (distributed_process(tsk))
				BUG_ON(page_increm > 1);
#endif
#endif
	} while (nr_pages);

#ifdef CONFIG_POPCORN_HYPE
	/* If !i, start has been shifted */
	if (tsk) {
		if (distributed_process(tsk)) {
			if (i != 1 || gup_retry > 0)
				DSMRETRYPRINTK(" !![%d] %lx CHECK ret/i %ld(%s) dsm_retry #%lu "
								"MINE %s\n",
						tsk->pid, start - (iter * PAGE_SIZE),
						i, i == 1 ? "GOOD" : "BAD", gup_retry,
						page_is_mine_pub(tsk->mm, start - (iter * PAGE_SIZE)) ?
																	"O" : "X");
				// origin
		}
	}
#endif

	return i;
}
EXPORT_SYMBOL(__get_user_pages);

/*
 * fixup_user_fault() - manually resolve a user page fault
 * @tsk:	the task_struct to use for page fault accounting, or
 *		NULL if faults are not to be recorded.
 * @mm:		mm_struct of target mm
 * @address:	user address
 * @fault_flags:flags to pass down to handle_mm_fault()
 *
 * This is meant to be called in the specific scenario where for locking reasons
 * we try to access user memory in atomic context (within a pagefault_disable()
 * section), this returns -EFAULT, and we want to resolve the user fault before
 * trying again.
 *
 * Typically this is meant to be used by the futex code.
 *
 * The main difference with get_user_pages() is that this function will
 * unconditionally call handle_mm_fault() which will in turn perform all the
 * necessary SW fixup of the dirty and young bits in the PTE, while
 * handle_mm_fault() only guarantees to update these in the struct page.
 *
 * This is important for some architectures where those bits also gate the
 * access permission to the page because they are maintained in software.  On
 * such architectures, gup() will not be enough to make a subsequent access
 * succeed.
 *
 * This has the same semantics wrt the @mm->mmap_sem as does filemap_fault().
 */
int fixup_user_fault(struct task_struct *tsk, struct mm_struct *mm,
		     unsigned long address, unsigned int fault_flags)
{
	struct vm_area_struct *vma;
	vm_flags_t vm_flags;
	int ret;

	vma = find_extend_vma(mm, address);
#ifdef CONFIG_POPCORN
	if (distributed_remote_process(tsk)) {
		if (!vma || address < vma->vm_start) {
			if (vma_server_fetch_vma(tsk, address) == 0) {
				/* Replace with updated VMA */
				vma = find_extend_vma(mm, address);
			}
		}
	}
#endif
	if (!vma || address < vma->vm_start)
		return -EFAULT;

	vm_flags = (fault_flags & FAULT_FLAG_WRITE) ? VM_WRITE : VM_READ;
	if (!(vm_flags & vma->vm_flags))
		return -EFAULT;

	ret = handle_mm_fault(mm, vma, address, fault_flags);
	if (ret & VM_FAULT_ERROR) {
		if (ret & VM_FAULT_OOM)
			return -ENOMEM;
		if (ret & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
			return -EHWPOISON;
		if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			return -EFAULT;
		BUG();
	}
	if (tsk) {
		if (ret & VM_FAULT_MAJOR)
			tsk->maj_flt++;
		else
			tsk->min_flt++;
	}
	return 0;
}

static __always_inline long __get_user_pages_locked(struct task_struct *tsk,
						struct mm_struct *mm,
						unsigned long start,
						unsigned long nr_pages,
						int write, int force,
						struct page **pages,
						struct vm_area_struct **vmas,
						int *locked, bool notify_drop,
						unsigned int flags)
{
	long ret, pages_done;
	bool lock_dropped;

#ifdef CONFIG_POPCORN_HYPE
	/* lkvm interested cases = vmas: NULL notify_drop: NULL forece: 0
				2nd __gfn_to_pfn_memslot/ hva_to_pfn path:
					vmas: NULL, *nonblocking(*locked): 1
					gup_flags = FOLL_TOUCH | FOLL_HWPOISON (from the topest)
								FOLL_GET | (FOLL_WRITE)
	*/
#endif

	if (locked) {
		/* if VM_FAULT_RETRY can be returned, vmas become invalid */
		BUG_ON(vmas);
		/* check caller initialized locked */
		BUG_ON(*locked != 1);
	}

	if (pages)
		flags |= FOLL_GET;
	if (write)
		flags |= FOLL_WRITE;
	if (force)
		flags |= FOLL_FORCE;

	pages_done = 0;
	lock_dropped = false;
	for (;;) {
		ret = __get_user_pages(tsk, mm, start, nr_pages, flags, pages,
				       vmas, locked);
#ifdef CONFIG_POPCORN_HYPE
		/* faultin_page may have change locked */
#endif
		if (!locked) {
#ifdef CONFIG_POPCORN_HYPE
			if (tsk) {
				BUG_ON(distributed_process(tsk));
			}
#endif
			/* VM_FAULT_RETRY couldn't trigger, bypass */
			return ret;
		}

		/* VM_FAULT_RETRY cannot return errors */
		if (!*locked) {
#ifdef CONFIG_POPCORN_HYPE
			/* nice check for us */
#endif
			BUG_ON(ret < 0);
			BUG_ON(ret >= nr_pages);
		}

		if (!pages) {
#ifdef CONFIG_POPCORN_HYPE
			if (tsk) {
				if (distributed_process(tsk)) {
					EPTVPRINTK("\t=__gups() $$[%d] =2nd -1 %lx "
								" mine %s nr_pages %ld pages_done %ld\n",
								tsk->pid, start,
								page_is_mine_pub(tsk->mm, start) ? "O" : "X",
								nr_pages, pages_done);
				}
			}
#endif
			/* If it's a prefault don't insist harder */
			return ret;
		}

		if (ret > 0) {
			nr_pages -= ret;
			pages_done += ret;
			if (!nr_pages) {
#ifdef CONFIG_POPCORN_HYPE
				if (tsk) {
					if (distributed_process(tsk)) {
						EPTVPRINTK("\t=__gups() $$[%d] =2nd -2 %lx "
									" mine %s nr_pages %ld pages_done %ld\n",
									tsk->pid, start,
									page_is_mine_pub(tsk->mm, start) ? "O" : "X",
									nr_pages, pages_done);
					}
				}
#endif
				break;
			}
		}
		if (*locked) {
			/* VM_FAULT_RETRY didn't trigger */
			if (!pages_done)
				pages_done = ret;
			break;
		}
#ifdef CONFIG_POPCORN_HYPE
		/* POPCRON DSM RETRY ALSO SHARE THIS (*locked|*nonblocking=0)
		 * VM_FAULT_RETRY will set *locked = 0 and then come to here
		 * here we lock again (*locked=1 + down_read())
		 * (notice: 2nd is not properly handled (todo hype retry))
		 */
		/* (notice: 2nd is not properly handled (todo hype retry)) */
		if (tsk) {
			BUG_ON(distributed_process(tsk));
			//BUG_ON(distributed_remote_process(tsk));
		}
#endif
		/* VM_FAULT_RETRY triggered, so seek to the faulting offset */
		pages += ret;
		start += ret << PAGE_SHIFT;

		/*
		 * Repeat on the address that fired VM_FAULT_RETRY
		 * without FAULT_FLAG_ALLOW_RETRY but with
		 * FAULT_FLAG_TRIED.
		 */
		*locked = 1;
		lock_dropped = true;
		down_read(&mm->mmap_sem);
#ifdef CONFIG_POPCORN_HYPE
		if (tsk) {
			if (distributed_process(tsk)) {
				BUG_ON(ret); /* we only support 1 page */
				//if ((tsk &&
					//INTERESTED_GVA(start)) &&
					//NOTINTERESTED_GVA(start) {
				EPTVPRINTK("\t=__gups() $$[%d] =2nd-2 [[LOCKED]] %lx faultin_pg "
						"nrpg(remain) %lu mine %s (TODO) pages_done %ld\n",
						tsk->pid, start, nr_pages,
						page_is_mine_pub(tsk->mm, start) ? "O" : "X",
						pages_done);
				//}
			}
		}
#endif
		ret = __get_user_pages(tsk, mm, start, 1, flags | FOLL_TRIED,
				       pages, NULL, NULL);
		if (ret != 1) {
			BUG_ON(ret > 1);
#ifdef CONFIG_POPCORN_HYPE
			/* Jack have a look */
			/* ret = 0 because of RETRY */
			/* I guess pages_done is 0 ret is 0 so return 0 */
			if (distributed_process(tsk)) {
				EPTVPRINTK("\t=__gups() $$[%d] =2nd-2 %lx why dsm fail?\n",
														tsk->pid, start);
			}
#endif
			if (!pages_done)
				pages_done = ret;
			break;
		}
		nr_pages--;
		pages_done++;
		if (!nr_pages)
			break;
		pages++;
		start += PAGE_SIZE;
	}
#ifdef CONFIG_POPCORN_HYPE
	/* I guess pages_done is 0 ret is 0 so return 0 now back to 2nd argvs
			notify_drop: false,
			lock_dropped: true (sinde 2nd-2), *locked: 1 (sinde 2nd-2)
								so this lock will be unlocked outside */
#endif
	if (notify_drop && lock_dropped && *locked) {
		/*
		 * We must let the caller know we temporarily dropped the lock
		 * and so the critical section protected by it was lost.
		 */
		up_read(&mm->mmap_sem);
		*locked = 0;
#ifdef CONFIG_POPCORN_HYPE
		if (distributed_process(tsk)) {
			//if ((tsk && (INTERESTED_GVA(start) || tsk->at_remote)) &&
			if ((tsk && (INTERESTED_GVA(start))) &&
				NOTINTERESTED_GVA(start)) {
				EPTVPRINTK("\t=__gups() $$[%d] =2nd [[UNLOCKED]] %lx faultin_pg "
							"nrpg(remain) %lu mine %s "
							"(BUG: should not reach)\n",
							tsk->pid, start, nr_pages,
							page_is_mine_pub(tsk->mm, start) ? "O" : "X");
			}
		}
#endif
	}
	return pages_done;
}

/*
 * We can leverage the VM_FAULT_RETRY functionality in the page fault
 * paths better by using either get_user_pages_locked() or
 * get_user_pages_unlocked().
 *
 * get_user_pages_locked() is suitable to replace the form:
 *
 *      down_read(&mm->mmap_sem);
 *      do_something()
 *      get_user_pages(tsk, mm, ..., pages, NULL);
 *      up_read(&mm->mmap_sem);
 *
 *  to:
 *
 *      int locked = 1;
 *      down_read(&mm->mmap_sem);
 *      do_something()
 *      get_user_pages_locked(tsk, mm, ..., pages, &locked);
 *      if (locked)
 *          up_read(&mm->mmap_sem);
 */
long get_user_pages_locked(struct task_struct *tsk, struct mm_struct *mm,
			   unsigned long start, unsigned long nr_pages,
			   int write, int force, struct page **pages,
			   int *locked)
{
	return __get_user_pages_locked(tsk, mm, start, nr_pages, write, force,
				       pages, NULL, locked, true, FOLL_TOUCH);
}
EXPORT_SYMBOL(get_user_pages_locked);

/*
 * Same as get_user_pages_unlocked(...., FOLL_TOUCH) but it allows to
 * pass additional gup_flags as last parameter (like FOLL_HWPOISON).
 *
 * NOTE: here FOLL_TOUCH is not set implicitly and must be set by the
 * caller if required (just like with __get_user_pages). "FOLL_GET",
 * "FOLL_WRITE" and "FOLL_FORCE" are set implicitly as needed
 * according to the parameters "pages", "write", "force"
 * respectively.
 */
__always_inline long __get_user_pages_unlocked(struct task_struct *tsk, struct mm_struct *mm,
					       unsigned long start, unsigned long nr_pages,
					       int write, int force, struct page **pages,
					       unsigned int gup_flags)
{
	long ret;
	int locked = 1; /* lkvm interested */
	down_read(&mm->mmap_sem);
#ifdef CONFIG_POPCORN_HYPE
	if (distributed_process(tsk)) {
		//if ((tsk && (INTERESTED_GVA(start) || tsk->at_remote)) &&
		//	NOTINTERESTED_GVA(start)) {
			EPTVPRINTK("\t=__gups() [%d] =2nd async(NULL) [[[LOCKed]]] "
												"addr %lx locked 1\n",
													tsk->pid, start);
		//}
	}
#endif
	ret = __get_user_pages_locked(tsk, mm, start, nr_pages, write, force,
				      pages, NULL, &locked, false, gup_flags);
#ifdef CONFIG_POPCORN_HYPE
	if (distributed_process(tsk) && ret != 1) {
		/* if so, handle it (double up_read probkem (1 loc above and below) */
		printk("[%d] DIE DIE DIE locked [[[[[[%d]]]]]] ret %ld\n",
											tsk->pid, locked, ret);
		WARN_ON(1); /* happens when memcachedlarg regs & more conn */
	}
#endif
	if (locked) {
		up_read(&mm->mmap_sem);
#ifdef CONFIG_POPCORN_HYPE
		if (distributed_process(tsk)) {
			//if ((tsk && (INTERESTED_GVA(start) || tsk->at_remote)) &&
			//	NOTINTERESTED_GVA(start)) {
//				EPTVPRINTK("\t=__gups() [%d] =2nd UNLOCKED %lx faultin_pg "
//							"nrpg(remain) %lu mine %s\n",
//							tsk->pid, start, nr_pages,
//							page_is_mine_pub(tsk->mm, start) ? "O" : "X");
				/* 0519 someone up_read again */
				/* right after got sipi 7ffff4fe400 from kvm_vcpu_reload_apic_access_page() */
				EPTVPRINTK("\t=__gups() $$[%d] =2nd async(NULL) "
						"locked %d %s [[[UNLOCKed]]] addr %lx ret %ld\n",
						tsk->pid, locked, locked ? "=>" : "!=>", start, ret);
				//dump_stack();
			//}
			BUG_ON(ret != 1 && "if so, handle it"); /* This is another general
										place to solve pophype dsm shortage */
		}
#endif
	}
//#ifdef CONFIG_POPCORN_HYPE
//	if (tsk->at_remote) {
//		EPTVPRINTK("%s(): [%d] no async [[[UNLOCKed]]] mmap_sem addr %lx locked %d\n",
//							__func__, tsk->pid, start, locked);
//	}
//#endif
	return ret;
}

/*
 * get_user_pages_unlocked() is suitable to replace the form:
 *
 *      down_read(&mm->mmap_sem);
 *      get_user_pages(tsk, mm, ..., pages, NULL);
 *      up_read(&mm->mmap_sem);
 *
 *  with:
 *
 *      get_user_pages_unlocked(tsk, mm, ..., pages);
 *
 * It is functionally equivalent to get_user_pages_fast so
 * get_user_pages_fast should be used instead, if the two parameters
 * "tsk" and "mm" are respectively equal to current and current->mm,
 * or if "force" shall be set to 1 (get_user_pages_fast misses the
 * "force" parameter).
 */
long get_user_pages_unlocked(struct task_struct *tsk, struct mm_struct *mm,
			     unsigned long start, unsigned long nr_pages,
			     int write, int force, struct page **pages)
{
	return __get_user_pages_unlocked(tsk, mm, start, nr_pages, write,
					 force, pages, FOLL_TOUCH);
}
EXPORT_SYMBOL(get_user_pages_unlocked);

/*
 * get_user_pages() - pin user pages in memory
 * @tsk:	the task_struct to use for page fault accounting, or
 *		NULL if faults are not to be recorded.
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @write:	whether pages will be written to by the caller
 * @force:	whether to force access even when user mapping is currently
 *		protected (but never forces write access to shared mapping).
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @vmas:	array of pointers to vmas corresponding to each page.
 *		Or NULL if the caller does not require them.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with. vmas will only
 * remain valid while mmap_sem is held.
 *
 * Must be called with mmap_sem held for read or write.
 *
 * get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * This does not guarantee that the page exists in the user mappings when
 * get_user_pages returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If write=0, the page must not be written to. If the page is written to,
 * set_page_dirty (or set_page_dirty_lock, as appropriate) must be called
 * after the page is finished with, and before put_page is called.
 *
 * get_user_pages is typically used for fewer-copy IO operations, to get a
 * handle on the memory by some means other than accesses via the user virtual
 * addresses. The pages may be submitted for DMA to devices or accessed via
 * their kernel linear mapping (via the kmap APIs). Care should be taken to
 * use the correct cache flushing APIs.
 *
 * See also get_user_pages_fast, for performance critical applications.
 *
 * get_user_pages should be phased out in favor of
 * get_user_pages_locked|unlocked or get_user_pages_fast. Nothing
 * should use get_user_pages because it cannot pass
 * FAULT_FLAG_ALLOW_RETRY to handle_mm_fault.
 */
long get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages, int write,
		int force, struct page **pages, struct vm_area_struct **vmas)
{
	return __get_user_pages_locked(tsk, mm, start, nr_pages, write, force,
				       pages, vmas, NULL, false, FOLL_TOUCH);
}
EXPORT_SYMBOL(get_user_pages);

/**
 * populate_vma_page_range() -  populate a range of pages in the vma.
 * @vma:   target vma
 * @start: start address
 * @end:   end address
 * @nonblocking:
 *
 * This takes care of mlocking the pages too if VM_LOCKED is set.
 *
 * return 0 on success, negative error code on error.
 *
 * vma->vm_mm->mmap_sem must be held.
 *
 * If @nonblocking is NULL, it may be held for read or write and will
 * be unperturbed.
 *
 * If @nonblocking is non-NULL, it must held for read only and may be
 * released.  If it's released, *@nonblocking will be set to 0.
 */
long populate_vma_page_range(struct vm_area_struct *vma,
		unsigned long start, unsigned long end, int *nonblocking)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long nr_pages = (end - start) / PAGE_SIZE;
	int gup_flags;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end   & ~PAGE_MASK);
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end   > vma->vm_end, vma);
	VM_BUG_ON_MM(!rwsem_is_locked(&mm->mmap_sem), mm);

	gup_flags = FOLL_TOUCH | FOLL_POPULATE | FOLL_MLOCK;
	if (vma->vm_flags & VM_LOCKONFAULT)
		gup_flags &= ~FOLL_POPULATE;

	/*
	 * We want to touch writable mappings with a write fault in order
	 * to break COW, except for shared mappings because these don't COW
	 * and we would not want to dirty them for nothing.
	 */
	if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
		gup_flags |= FOLL_WRITE;

	/*
	 * We want mlock to succeed for regions that have any permissions
	 * other than PROT_NONE.
	 */
	if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))
		gup_flags |= FOLL_FORCE;

	/*
	 * We made sure addr is within a VMA, so the following will
	 * not result in a stack expansion that recurses back here.
	 */
	return __get_user_pages(current, mm, start, nr_pages, gup_flags,
				NULL, NULL, nonblocking);
}

/*
 * __mm_populate - populate and/or mlock pages within a range of address space.
 *
 * This is used to implement mlock() and the MAP_POPULATE / MAP_LOCKED mmap
 * flags. VMAs must be already marked with the desired vm_flags, and
 * mmap_sem must not be held.
 */
int __mm_populate(unsigned long start, unsigned long len, int ignore_errors)
{
	struct mm_struct *mm = current->mm;
	unsigned long end, nstart, nend;
	struct vm_area_struct *vma = NULL;
	int locked = 0;
	long ret = 0;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(len != PAGE_ALIGN(len));
	end = start + len;

	for (nstart = start; nstart < end; nstart = nend) {
		/*
		 * We want to fault in pages for [nstart; end) address range.
		 * Find first corresponding VMA.
		 */
		if (!locked) {
			locked = 1;
			down_read(&mm->mmap_sem);
			vma = find_vma(mm, nstart);
		} else if (nstart >= vma->vm_end)
			vma = vma->vm_next;
		if (!vma || vma->vm_start >= end)
			break;
		/*
		 * Set [nstart; nend) to intersection of desired address
		 * range with the first VMA. Also, skip undesirable VMA types.
		 */
		nend = min(end, vma->vm_end);
		if (vma->vm_flags & (VM_IO | VM_PFNMAP))
			continue;
		if (nstart < vma->vm_start)
			nstart = vma->vm_start;
		/*
		 * Now fault in a range of pages. populate_vma_page_range()
		 * double checks the vma flags, so that it won't mlock pages
		 * if the vma was already munlocked.
		 */
		ret = populate_vma_page_range(vma, nstart, nend, &locked);
		if (ret < 0) {
			if (ignore_errors) {
				ret = 0;
				continue;	/* continue at next VMA */
			}
			break;
		}
		nend = nstart + ret * PAGE_SIZE;
		ret = 0;
	}
	if (locked)
		up_read(&mm->mmap_sem);
	return ret;	/* 0 or negative error code */
}

/**
 * get_dump_page() - pin user page in memory while writing it to core dump
 * @addr: user address
 *
 * Returns struct page pointer of user page pinned for dump,
 * to be freed afterwards by page_cache_release() or put_page().
 *
 * Returns NULL on any kind of failure - a hole must then be inserted into
 * the corefile, to preserve alignment with its headers; and also returns
 * NULL wherever the ZERO_PAGE, or an anonymous pte_none, has been found -
 * allowing a hole to be left in the corefile to save diskspace.
 *
 * Called without mmap_sem, but after all other threads have been killed.
 */
#ifdef CONFIG_ELF_CORE
struct page *get_dump_page(unsigned long addr)
{
	struct vm_area_struct *vma;
	struct page *page;

	if (__get_user_pages(current, current->mm, addr, 1,
			     FOLL_FORCE | FOLL_DUMP | FOLL_GET, &page, &vma,
			     NULL) < 1)
		return NULL;
	flush_cache_page(vma, addr, page_to_pfn(page));
	return page;
}
#endif /* CONFIG_ELF_CORE */

/*
 * Generic RCU Fast GUP
 *
 * get_user_pages_fast attempts to pin user pages by walking the page
 * tables directly and avoids taking locks. Thus the walker needs to be
 * protected from page table pages being freed from under it, and should
 * block any THP splits.
 *
 * One way to achieve this is to have the walker disable interrupts, and
 * rely on IPIs from the TLB flushing code blocking before the page table
 * pages are freed. This is unsuitable for architectures that do not need
 * to broadcast an IPI when invalidating TLBs.
 *
 * Another way to achieve this is to batch up page table containing pages
 * belonging to more than one mm_user, then rcu_sched a callback to free those
 * pages. Disabling interrupts will allow the fast_gup walker to both block
 * the rcu_sched callback, and an IPI that we broadcast for splitting THPs
 * (which is a relatively rare event). The code below adopts this strategy.
 *
 * Before activating this code, please be aware that the following assumptions
 * are currently made:
 *
 *  *) HAVE_RCU_TABLE_FREE is enabled, and tlb_remove_table is used to free
 *      pages containing page tables.
 *
 *  *) THP splits will broadcast an IPI, this can be achieved by overriding
 *      pmdp_splitting_flush.
 *
 *  *) ptes can be read atomically by the architecture.
 *
 *  *) access_ok is sufficient to validate userspace address ranges.
 *
 * The last two assumptions can be relaxed by the addition of helper functions.
 *
 * This code is based heavily on the PowerPC implementation by Nick Piggin.
 */
#ifdef CONFIG_HAVE_GENERIC_RCU_GUP

#ifdef __HAVE_ARCH_PTE_SPECIAL
static int gup_pte_range(pmd_t pmd, unsigned long addr, unsigned long end,
			 int write, struct page **pages, int *nr)
{
	pte_t *ptep, *ptem;
	int ret = 0;

	ptem = ptep = pte_offset_map(&pmd, addr);
	do {
		/*
		 * In the line below we are assuming that the pte can be read
		 * atomically. If this is not the case for your architecture,
		 * please wrap this in a helper function!
		 *
		 * for an example see gup_get_pte in arch/x86/mm/gup.c
		 */
		pte_t pte = READ_ONCE(*ptep);
		struct page *page;

		/*
		 * Similar to the PMD case below, NUMA hinting must take slow
		 * path using the pte_protnone check.
		 */
		if (!pte_present(pte) || pte_special(pte) ||
			pte_protnone(pte) || (write && !pte_write(pte)))
			goto pte_unmap;

		VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
		page = pte_page(pte);

		if (!page_cache_get_speculative(page))
			goto pte_unmap;

		if (unlikely(pte_val(pte) != pte_val(*ptep))) {
			put_page(page);
			goto pte_unmap;
		}

		pages[*nr] = page;
		(*nr)++;

	} while (ptep++, addr += PAGE_SIZE, addr != end);

	ret = 1;

pte_unmap:
	pte_unmap(ptem);
	return ret;
}
#else

/*
 * If we can't determine whether or not a pte is special, then fail immediately
 * for ptes. Note, we can still pin HugeTLB and THP as these are guaranteed not
 * to be special.
 *
 * For a futex to be placed on a THP tail page, get_futex_key requires a
 * __get_user_pages_fast implementation that can pin pages. Thus it's still
 * useful to have gup_huge_pmd even if we can't operate on ptes.
 */
static int gup_pte_range(pmd_t pmd, unsigned long addr, unsigned long end,
			 int write, struct page **pages, int *nr)
{
	return 0;
}
#endif /* __HAVE_ARCH_PTE_SPECIAL */

static int gup_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page, *tail;
	int refs;

	if (write && !pmd_write(orig))
		return 0;

	refs = 0;
	head = pmd_page(orig);
	page = head + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	tail = page;
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	if (!page_cache_add_speculative(head, refs)) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	/*
	 * Any tail pages need their mapcount reference taken before we
	 * return. (This allows the THP code to bump their ref count when
	 * they are split into base pages).
	 */
	while (refs--) {
		if (PageTail(tail))
			get_huge_page_tail(tail);
		tail++;
	}

	return 1;
}

static int gup_huge_pud(pud_t orig, pud_t *pudp, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page, *tail;
	int refs;

	if (write && !pud_write(orig))
		return 0;

	refs = 0;
	head = pud_page(orig);
	page = head + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	tail = page;
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	if (!page_cache_add_speculative(head, refs)) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pud_val(orig) != pud_val(*pudp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	while (refs--) {
		if (PageTail(tail))
			get_huge_page_tail(tail);
		tail++;
	}

	return 1;
}

static int gup_huge_pgd(pgd_t orig, pgd_t *pgdp, unsigned long addr,
			unsigned long end, int write,
			struct page **pages, int *nr)
{
	int refs;
	struct page *head, *page, *tail;

	if (write && !pgd_write(orig))
		return 0;

	refs = 0;
	head = pgd_page(orig);
	page = head + ((addr & ~PGDIR_MASK) >> PAGE_SHIFT);
	tail = page;
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	if (!page_cache_add_speculative(head, refs)) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pgd_val(orig) != pgd_val(*pgdp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	while (refs--) {
		if (PageTail(tail))
			get_huge_page_tail(tail);
		tail++;
	}

	return 1;
}

static int gup_pmd_range(pud_t pud, unsigned long addr, unsigned long end,
		int write, struct page **pages, int *nr)
{
	unsigned long next;
	pmd_t *pmdp;

	pmdp = pmd_offset(&pud, addr);
	do {
		pmd_t pmd = READ_ONCE(*pmdp);

		next = pmd_addr_end(addr, end);
		if (pmd_none(pmd) || pmd_trans_splitting(pmd))
			return 0;

		if (unlikely(pmd_trans_huge(pmd) || pmd_huge(pmd))) {
			/*
			 * NUMA hinting faults need to be handled in the GUP
			 * slowpath for accounting purposes and so that they
			 * can be serialised against THP migration.
			 */
			if (pmd_protnone(pmd))
				return 0;

			if (!gup_huge_pmd(pmd, pmdp, addr, next, write,
				pages, nr))
				return 0;

		} else if (unlikely(is_hugepd(__hugepd(pmd_val(pmd))))) {
			/*
			 * architecture have different format for hugetlbfs
			 * pmd format and THP pmd format
			 */
			if (!gup_huge_pd(__hugepd(pmd_val(pmd)), addr,
					 PMD_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!gup_pte_range(pmd, addr, next, write, pages, nr))
				return 0;
	} while (pmdp++, addr = next, addr != end);

	return 1;
}

static int gup_pud_range(pgd_t pgd, unsigned long addr, unsigned long end,
			 int write, struct page **pages, int *nr)
{
	unsigned long next;
	pud_t *pudp;

	pudp = pud_offset(&pgd, addr);
	do {
		pud_t pud = READ_ONCE(*pudp);

		next = pud_addr_end(addr, end);
		if (pud_none(pud))
			return 0;
		if (unlikely(pud_huge(pud))) {
			if (!gup_huge_pud(pud, pudp, addr, next, write,
					  pages, nr))
				return 0;
		} else if (unlikely(is_hugepd(__hugepd(pud_val(pud))))) {
			if (!gup_huge_pd(__hugepd(pud_val(pud)), addr,
					 PUD_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!gup_pmd_range(pud, addr, next, write, pages, nr))
			return 0;
	} while (pudp++, addr = next, addr != end);

	return 1;
}

/*
 * Like get_user_pages_fast() except it's IRQ-safe in that it won't fall back to
 * the regular GUP. It will only return non-negative values.
 */
int __get_user_pages_fast(unsigned long start, int nr_pages, int write,
			  struct page **pages)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr, len, end;
	unsigned long next, flags;
	pgd_t *pgdp;
	int nr = 0;

	start &= PAGE_MASK;
	addr = start;
	len = (unsigned long) nr_pages << PAGE_SHIFT;
	end = start + len;

	if (unlikely(!access_ok(write ? VERIFY_WRITE : VERIFY_READ,
					start, len)))
		return 0;

#ifdef CONFIG_POPCORN_HYPE
	if (distributed_process(current) && INTERESTED_GVA(start)) {
		printk(" fast[%d] %lx mm/gup.c\n", current->pid, start);
	}
#endif

	/*
	 * Disable interrupts.  We use the nested form as we can already have
	 * interrupts disabled by get_futex_key.
	 *
	 * With interrupts disabled, we block page table pages from being
	 * freed from under us. See mmu_gather_tlb in asm-generic/tlb.h
	 * for more details.
	 *
	 * We do not adopt an rcu_read_lock(.) here as we also want to
	 * block IPIs that come from THPs splitting.
	 */
	/* If !!pte, gup_pud_rang() going to next level (pmd)
								and next next level (pte) */

	local_irq_save(flags);
	pgdp = pgd_offset(mm, addr);
	do {
		pgd_t pgd = READ_ONCE(*pgdp);

		next = pgd_addr_end(addr, end);
		if (pgd_none(pgd))
			break;	/* !pte goto slow path */
		if (unlikely(pgd_huge(pgd))) {
			if (!gup_huge_pgd(pgd, pgdp, addr, next, write,
					  pages, &nr))
				break;
		} else if (unlikely(is_hugepd(__hugepd(pgd_val(pgd))))) {
			if (!gup_huge_pd(__hugepd(pgd_val(pgd)), addr,
					 PGDIR_SHIFT, next, write, pages, &nr))
				break;
		} else if (!gup_pud_range(pgd, addr, next, write, pages, &nr))
			break;
	} while (pgdp++, addr = next, addr != end);
	local_irq_restore(flags);

	return nr;
}

/**
 * get_user_pages_fast() - pin user pages in memory
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @write:	whether pages will be written to
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long.
 *
 * Attempt to pin user pages in memory without taking mm->mmap_sem.
 * If not successful, it will fall back to taking the lock and
 * calling get_user_pages().
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno.
 */
int get_user_pages_fast(unsigned long start, int nr_pages, int write,
			struct page **pages)
{
	struct mm_struct *mm = current->mm;
	int nr, ret;

	start &= PAGE_MASK;
	nr = __get_user_pages_fast(start, nr_pages, write, pages);
	ret = nr;

	if (nr < nr_pages) {
		/* Try to get the remaining pages with get_user_pages */
		start += nr << PAGE_SHIFT;
		pages += nr;

#ifdef CONFIG_POPCORN_HYPE
		/* pophype: currently, memcached tx problem happens in another
						get_user_pages_fast() located arch/x86/mm/gup.c.
			If this happens, we need to solve
					solving dsm shortage/problem here */
		WARN_ON("should never happen");
		POP_PK("pophype: dsm shortage - nr (done) %d < nr_pages (req) %d\n",
																nr, nr_pages);
		if (nr_pages - nr) { /* multi-page but pophype doesn't support so */
			/*break it down to be individual */
			int cnt = nr_pages - nr;
			while (cnt) {
				POP_PK("pophype: my sol %d/%d\n", cnt, nr_pages - nr);
				ret = get_user_pages_unlocked(current, mm, start,
												  1, write, 0, pages);
				/* TODO: what should I do for ret and nr_pages & nr !!!! TODO */
				cnt--;
			}

		} else { /* normal single page */
			ret = get_user_pages_unlocked(current, mm, start,
							  nr_pages - nr, write, 0, pages);
		}
#else
		ret = get_user_pages_unlocked(current, mm, start,
					      nr_pages - nr, write, 0, pages);
#endif

		/* Have to be a bit careful with return values */
		if (nr > 0) {
			if (ret < 0)
				ret = nr;
			else
				ret += nr;
		}
	}

	return ret;
}

#endif /* CONFIG_HAVE_GENERIC_RCU_GUP */
