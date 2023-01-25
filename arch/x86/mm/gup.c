/*
 * Lockless get_user_pages_fast for x86
 *
 * Copyright (C) 2008 Nick Piggin
 * Copyright (C) 2008 Novell Inc.
 */
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/highmem.h>
#include <linux/swap.h>

#include <asm/pgtable.h>

#ifdef CONFIG_POPCORN_HYPE
#include <popcorn/types.h>
int io_gup_cnt = 0;
int dsm_shortage_cnt = 0;
int nr_pages_mismatch_cnt = 0;

#ifdef CONFIG_POPCORN_STAT
atomic64_t iogup_ns = ATOMIC64_INIT(0);
atomic64_t iogup_cnt = ATOMIC64_INIT(0);
atomic64_t kvm_eptrefault_ns = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
atomic64_t kvm_eptrefault_cnt = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
atomic64_t kvm_eptreinv_ns = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
atomic64_t kvm_eptreinv_cnt = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
atomic64_t kvm_eptreinv_fast_cnt = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
#endif
#if POPHYPE_HOST_KERNEL
int is_host_kernel = 1;
#else
int is_host_kernel = 0;
#endif

#else // CONFIG_POPCORN_HYPE
/* */
#include <popcorn/types.h>
int is_host_kernel = 1;
int io_gup_cnt = 0;
int dsm_shortage_cnt = 0;
int nr_pages_mismatch_cnt = 0;
atomic64_t iogup_ns = ATOMIC64_INIT(0);
atomic64_t iogup_cnt = ATOMIC64_INIT(0);
atomic64_t kvm_eptrefault_ns = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
atomic64_t kvm_eptrefault_cnt = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
atomic64_t kvm_eptreinv_ns = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
atomic64_t kvm_eptreinv_cnt = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
atomic64_t kvm_eptreinv_fast_cnt = ATOMIC64_INIT(0); /* arch/x86/kvm/mmu.c */
#endif


static inline pte_t gup_get_pte(pte_t *ptep)
{
#ifndef CONFIG_X86_PAE
	return READ_ONCE(*ptep);
#else
	/*
	 * With get_user_pages_fast, we walk down the pagetables without taking
	 * any locks.  For this we would like to load the pointers atomically,
	 * but that is not possible (without expensive cmpxchg8b) on PAE.  What
	 * we do have is the guarantee that a pte will only either go from not
	 * present to present, or present to not present or both -- it will not
	 * switch to a completely different present page without a TLB flush in
	 * between; something that we are blocking by holding interrupts off.
	 *
	 * Setting ptes from not present to present goes:
	 * ptep->pte_high = h;
	 * smp_wmb();
	 * ptep->pte_low = l;
	 *
	 * And present to not present goes:
	 * ptep->pte_low = 0;
	 * smp_wmb();
	 * ptep->pte_high = 0;
	 *
	 * We must ensure here that the load of pte_low sees l iff pte_high
	 * sees h. We load pte_high *after* loading pte_low, which ensures we
	 * don't see an older value of pte_high.  *Then* we recheck pte_low,
	 * which ensures that we haven't picked up a changed pte high. We might
	 * have got rubbish values from pte_low and pte_high, but we are
	 * guaranteed that pte_low will not have the present bit set *unless*
	 * it is 'l'. And get_user_pages_fast only operates on present ptes, so
	 * we're safe.
	 *
	 * gup_get_pte should not be used or copied outside gup.c without being
	 * very careful -- it does not atomically load the pte or anything that
	 * is likely to be useful for you.
	 */
	pte_t pte;

retry:
	pte.pte_low = ptep->pte_low;
	smp_rmb();
	pte.pte_high = ptep->pte_high;
	smp_rmb();
	if (unlikely(pte.pte_low != ptep->pte_low))
		goto retry;

	return pte;
#endif
}

/*
 * The performance critical leaf functions are made noinline otherwise gcc
 * inlines everything into a single function which results in too much
 * register pressure.
 */
static noinline int gup_pte_range(pmd_t pmd, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	unsigned long mask;
	pte_t *ptep;

	mask = _PAGE_PRESENT|_PAGE_USER;
	if (write)
		mask |= _PAGE_RW;

	ptep = pte_offset_map(&pmd, addr);
	do {
		pte_t pte = gup_get_pte(ptep);
		struct page *page;

		/* Similar to the PMD case, NUMA hinting must take slow path */
		if (pte_protnone(pte)) {
			pte_unmap(ptep);
			return 0;
		}

		if ((pte_flags(pte) & (mask | _PAGE_SPECIAL)) != mask) {
			pte_unmap(ptep);
			return 0;
		}
		VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
		page = pte_page(pte);
		get_page(page);
		SetPageReferenced(page);
		pages[*nr] = page;
		(*nr)++;

	} while (ptep++, addr += PAGE_SIZE, addr != end);
	pte_unmap(ptep - 1);

	return 1;
}

static inline void get_head_page_multiple(struct page *page, int nr)
{
	VM_BUG_ON_PAGE(page != compound_head(page), page);
	VM_BUG_ON_PAGE(page_count(page) == 0, page);
	atomic_add(nr, &page->_count);
	SetPageReferenced(page);
}

static noinline int gup_huge_pmd(pmd_t pmd, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	unsigned long mask;
	struct page *head, *page;
	int refs;

	mask = _PAGE_PRESENT|_PAGE_USER;
	if (write)
		mask |= _PAGE_RW;
	if ((pmd_flags(pmd) & mask) != mask)
		return 0;
	/* hugepages are never "special" */
	VM_BUG_ON(pmd_flags(pmd) & _PAGE_SPECIAL);
	VM_BUG_ON(!pfn_valid(pmd_pfn(pmd)));

	refs = 0;
	head = pmd_page(pmd);
	page = head + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		if (PageTail(page))
			get_huge_page_tail(page);
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);
	get_head_page_multiple(head, refs);

	return 1;
}

static int gup_pmd_range(pud_t pud, unsigned long addr, unsigned long end,
		int write, struct page **pages, int *nr)
{
	unsigned long next;
	pmd_t *pmdp;

	pmdp = pmd_offset(&pud, addr);
	do {
		pmd_t pmd = *pmdp;

		next = pmd_addr_end(addr, end);
		/*
		 * The pmd_trans_splitting() check below explains why
		 * pmdp_splitting_flush has to flush the tlb, to stop
		 * this gup-fast code from running while we set the
		 * splitting bit in the pmd. Returning zero will take
		 * the slow path that will call wait_split_huge_page()
		 * if the pmd is still in splitting state. gup-fast
		 * can't because it has irq disabled and
		 * wait_split_huge_page() would never return as the
		 * tlb flush IPI wouldn't run.
		 */
		if (pmd_none(pmd) || pmd_trans_splitting(pmd))
			return 0;
		if (unlikely(pmd_large(pmd) || !pmd_present(pmd))) {
			/*
			 * NUMA hinting faults need to be handled in the GUP
			 * slowpath for accounting purposes and so that they
			 * can be serialised against THP migration.
			 */
			if (pmd_protnone(pmd))
				return 0;
			if (!gup_huge_pmd(pmd, addr, next, write, pages, nr))
				return 0;
		} else {
			if (!gup_pte_range(pmd, addr, next, write, pages, nr))
				return 0;
		}
	} while (pmdp++, addr = next, addr != end);

	return 1;
}

static noinline int gup_huge_pud(pud_t pud, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	unsigned long mask;
	struct page *head, *page;
	int refs;

	mask = _PAGE_PRESENT|_PAGE_USER;
	if (write)
		mask |= _PAGE_RW;
	if ((pud_flags(pud) & mask) != mask)
		return 0;
	/* hugepages are never "special" */
	VM_BUG_ON(pud_flags(pud) & _PAGE_SPECIAL);
	VM_BUG_ON(!pfn_valid(pud_pfn(pud)));

	refs = 0;
	head = pud_page(pud);
	page = head + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		if (PageTail(page))
			get_huge_page_tail(page);
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);
	get_head_page_multiple(head, refs);

	return 1;
}

static int gup_pud_range(pgd_t pgd, unsigned long addr, unsigned long end,
			int write, struct page **pages, int *nr)
{
	unsigned long next;
	pud_t *pudp;

	pudp = pud_offset(&pgd, addr);
	do {
		pud_t pud = *pudp;

		next = pud_addr_end(addr, end);
		if (pud_none(pud))
			return 0;
		if (unlikely(pud_large(pud))) {
			if (!gup_huge_pud(pud, addr, next, write, pages, nr))
				return 0;
		} else {
			if (!gup_pmd_range(pud, addr, next, write, pages, nr))
				return 0;
		}
	} while (pudp++, addr = next, addr != end);

	return 1;
}

/*
 * Like get_user_pages_fast() except its IRQ-safe in that it won't fall
 * back to the regular GUP.
 */
int __get_user_pages_fast(unsigned long start, int nr_pages, int write,
			  struct page **pages)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr, len, end;
	unsigned long next;
	unsigned long flags;
	pgd_t *pgdp;
	int nr = 0;

	start &= PAGE_MASK;
	addr = start;
	len = (unsigned long) nr_pages << PAGE_SHIFT;
	end = start + len;
	if (unlikely(!access_ok(write ? VERIFY_WRITE : VERIFY_READ,
					(void __user *)start, len)))
		return 0;

#ifdef CONFIG_POPCORN_HYPE
    if (distributed_process(current) && INTERESTED_GVA(start)) {
        GUPFASTPRINTK(" fast[%d] %lx arch/x86/mm/gup.c\n", current->pid, start);
    }
#endif

	/*
	 * XXX: batch / limit 'nr', to avoid large irq off latency
	 * needs some instrumenting to determine the common sizes used by
	 * important workloads (eg. DB2), and whether limiting the batch size
	 * will decrease performance.
	 *
	 * It seems like we're in the clear for the moment. Direct-IO is
	 * the main guy that batches up lots of get_user_pages, and even
	 * they are limited to 64-at-a-time which is not so many.
	 */
	/*
	 * This doesn't prevent pagetable teardown, but does prevent
	 * the pagetables and pages from being freed on x86.
	 *
	 * So long as we atomically load page table pointers versus teardown
	 * (which we do on x86, with the above PAE exception), we can follow the
	 * address down to the the page and take a ref on it.
	 */
	local_irq_save(flags);
	pgdp = pgd_offset(mm, addr);
	do {
		pgd_t pgd = *pgdp;

		next = pgd_addr_end(addr, end);
		if (pgd_none(pgd))
			break;
		if (!gup_pud_range(pgd, addr, next, write, pages, &nr))
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
 * 		Should be at least nr_pages long.
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
#ifdef CONFIG_POPCORN_HYPE
	/* Never happen in pophype */
	static int cnt = 0;
#endif
	struct mm_struct *mm = current->mm;
	unsigned long addr, len, end;
	unsigned long next;
	pgd_t *pgdp;
	int nr = 0;

	start &= PAGE_MASK;
	addr = start;
	len = (unsigned long) nr_pages << PAGE_SHIFT;

	end = start + len;
	if (end < start)
		goto slow_irqon;

#ifdef CONFIG_X86_64
	if (end >> __VIRTUAL_MASK_SHIFT)
		goto slow_irqon;
#endif

	/*
	 * XXX: batch / limit 'nr', to avoid large irq off latency
	 * needs some instrumenting to determine the common sizes used by
	 * important workloads (eg. DB2), and whether limiting the batch size
	 * will decrease performance.
	 *
	 * It seems like we're in the clear for the moment. Direct-IO is
	 * the main guy that batches up lots of get_user_pages, and even
	 * they are limited to 64-at-a-time which is not so many.
	 */
	/*
	 * This doesn't prevent pagetable teardown, but does prevent
	 * the pagetables and pages from being freed on x86.
	 *
	 * So long as we atomically load page table pointers versus teardown
	 * (which we do on x86, with the above PAE exception), we can follow the
	 * address down to the the page and take a ref on it.
	 */
	local_irq_disable();
	pgdp = pgd_offset(mm, addr);
	do {
		pgd_t pgd = *pgdp;

		next = pgd_addr_end(addr, end);
		if (pgd_none(pgd))
			goto slow;
		if (!gup_pud_range(pgd, addr, next, write, pages, &nr))
			goto slow;
	} while (pgdp++, addr = next, addr != end);
	local_irq_enable();

	VM_BUG_ON(nr != (end - start) >> PAGE_SHIFT);
	return nr;

	{
		int ret;

slow:
		local_irq_enable();
slow_irqon:
		/* Try to get the remaining pages with get_user_pages */
		start += nr << PAGE_SHIFT;
		pages += nr;

#ifdef CONFIG_POPCORN_HYPE
		/* since both this func get_user_pages_fast() and
			get_user_pages_unlocked() return pages_done,
			we can implment here or outside of this func (iov_iter_get_pages()).

			Here I'm checking where should I do it, if there are too many here,
			I can implemente here for general. Otherwise, I just implement
			outside because only tx uses it. This will also make code more
			easy to read.

			It turns out only iov_iter_get_pages() use it. I will move the code
			to iov_iter_get_pages;

			Note the sentence above: "Direct-IO is the main guy that
										batches up lots of get_user_pages."
		*/
		cnt++;
		if (distributed_process(current)) { /* from tx */
			/* pophype io_gup_single_page */
			unsigned long new_nr_pages = (end - start) >> PAGE_SHIFT;
#ifdef CONFIG_POPCORN_STAT
			ktime_t dt, iogup_end, iogup_start = ktime_get();
#endif
#ifdef CONFIG_POPCORN_STAT
			io_gup_cnt += new_nr_pages;
#endif
			/* Attention: nr_pages (func input) new_nr_pages (calced in func) */
			DSMPATCHPK("%s %s(): nr_pages %d (func in) new_nr_pages %lu #%d\n",
							__FILE__, __func__, nr_pages, new_nr_pages, cnt);
			if (nr_pages != new_nr_pages) {
				/* This happens but I believe new_nr_pages is correct */
				//WARN_ON(-1);
#ifdef CONFIG_POPCORN_STAT
				/* real fetch - who's input? */
				nr_pages_mismatch_cnt += new_nr_pages - nr_pages;
#endif
				DSMPATCHPK("\n\nnr_pages (%d) != new_nr_pages (%lu)\n\n",
													nr_pages, new_nr_pages);
			}
#define POPHYPE_TX_MULTIPAGE_BUT_PATCH 1
#if POPHYPE_TX_MULTIPAGE_BUT_PATCH
			if (new_nr_pages > 1) { // multi-page but pophype doesn't support so
								// break it down to be individual
				int pg_left = new_nr_pages;
#ifdef CONFIG_POPCORN_STAT
				dsm_shortage_cnt += pg_left;
#endif
				while (pg_left) {
					DSMPATCHPK("pophype %s %s(): my patch for dsm shortage "
						"%d/%lu\n", __FILE__, __func__, pg_left, new_nr_pages);
					ret = get_user_pages_unlocked(current, mm, start, 1,
									  write, 0, pages);
					// TODO: what should I do for ret and new_nr_pages & nr !!!!
					// 1. check ret
					// 2. ret eventually return ret so ret = new_nr_pages
					// 3. nr
					BUG_ON(ret != 1); /* dsm shortage + error (-) detection */

					pg_left--;

					/* next - ptr/value moves on */
					start += PAGE_SIZE; // = addr
					pages++; // struct page *pages[MAX_SKB_FRAGS];
				}
				DSMPATCHPK("pophype %s %s(): my patch DONE!\n",
											__FILE__, __func__);
				// 2
				// 3 nr is a vanilla product
				ret = new_nr_pages + nr; /* new_nr_pages = vanilla ret. nr =  */
				return ret; /* my own path */
			} else { // normal single page
				ret = get_user_pages_unlocked(current, mm, start,
							  (end - start) >> PAGE_SHIFT, /* pophype: <= 1 */
							  write, 0, pages);
				/* fall through */
			}
#endif

#if !POPHYPE_TX_MULTIPAGE_BUT_PATCH
		/* need to remove */
		ret = get_user_pages_unlocked(current, mm, start,
					      (end - start) >> PAGE_SHIFT,
					      write, 0, pages);
#endif
#ifdef CONFIG_POPCORN_STAT
		iogup_end = ktime_get();
		dt = ktime_sub(iogup_end, iogup_start);
		atomic64_add(ktime_to_ns(dt), &iogup_ns);
		//atomic64_inc(&iogup_cnt);
		atomic64_add(new_nr_pages, &iogup_cnt); /* 0515 - iogup_cnt=0 */
#endif
		} else {
			ret = get_user_pages_unlocked(current, mm, start,
							  (end - start) >> PAGE_SHIFT,
							  write, 0, pages);

		}
#else /* vanilla io_gup_pages*/
#if defined(CONFIG_POPCORN_STAT)
		if (!is_host_kernel) {
			atomic64_add((end - start) >> PAGE_SHIFT, &iogup_cnt);
		}
#endif
		ret = get_user_pages_unlocked(current, mm, start,
					      (end - start) >> PAGE_SHIFT,
					      write, 0, pages);
#endif

		/* Have to be a bit careful with return values */
		if (nr > 0) {
			if (ret < 0)
				ret = nr;
			else
				ret += nr;
		}

		return ret; /* succ: return pages_done */
	}
}

/***
 * Pophype
 */
void pophype_net_gup(struct seq_file *seq, void *v)
{
#ifdef CONFIG_POPCORN_STAT
    if (seq) {
		/* memcached only */
		seq_printf(seq, "%s %d (test - redundant)\n", /* # of single page fault from net */
					"io_gup_cnt (total)", io_gup_cnt);
		/* in ./arch/x86/kvm/mmu.c */
		seq_printf(seq, "%10s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
                    "iogup", (atomic64_read(&iogup_ns) / 1000) / MICROSECOND,
                            (atomic64_read(&iogup_ns) / 1000)  % MICROSECOND,
                    "cnt", atomic64_read(&iogup_cnt),
                    "per", atomic64_read(&iogup_cnt) ?
								 atomic64_read(&iogup_ns) /
									atomic64_read(&iogup_cnt) / 1000 : 0);
		/* ept retry info in ./arch/x86/kvm/mmu.c */
		seq_printf(seq, "%10s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
					"eptrefault", (atomic64_read(&kvm_eptrefault_ns) / 1000) / MICROSECOND,
							(atomic64_read(&kvm_eptrefault_ns) / 1000)  % MICROSECOND,
					"cnt", atomic64_read(&kvm_eptrefault_cnt),
					"per", atomic64_read(&kvm_eptrefault_cnt) ?
					 atomic64_read(&kvm_eptrefault_ns) / atomic64_read(&kvm_eptrefault_cnt) / 1000 : 0);
		seq_printf(seq, "%10s  %10ld.%06ld (s)  %3s %-10ld   %3s %-6ld (us)\n",
					"eptreinv", (atomic64_read(&kvm_eptreinv_ns) / 1000) / MICROSECOND,
							(atomic64_read(&kvm_eptreinv_ns) / 1000)  % MICROSECOND,
					"cnt", atomic64_read(&kvm_eptreinv_cnt),
					"per", atomic64_read(&kvm_eptreinv_cnt) ?
					 atomic64_read(&kvm_eptreinv_ns) / atomic64_read(&kvm_eptreinv_cnt) / 1000 : 0);
		seq_printf(seq, "%12s  %10d.%06d (s)  %3s %-10ld   %3s %-6d (us)\n",
					"eptreinvfast", 0, 0,
					"cnt", atomic64_read(&kvm_eptreinv_fast_cnt),
					"per", 0);



		seq_printf(seq, "%s %d\n", /* These # of pages are handled by pophype */
					"dsm_shortage_cnt", dsm_shortage_cnt);
		seq_printf(seq, "%s %d\n",
					"nr_pages_mismatch_cnt", nr_pages_mismatch_cnt);
	} else { /* clear */
		io_gup_cnt = 0;
		//seq_printf(seq, "is_host_kernel (%c)", is_host_kernel ? 'O' : 'X');
		atomic64_set(&iogup_cnt, 0);
        atomic64_set(&iogup_ns, 0);

		atomic64_set(&kvm_eptrefault_ns, 0);
		atomic64_set(&kvm_eptrefault_cnt, 0);
		atomic64_set(&kvm_eptreinv_ns, 0);
		atomic64_set(&kvm_eptreinv_cnt, 0);
		atomic64_set(&kvm_eptreinv_fast_cnt, 0);

		dsm_shortage_cnt = 0;
		nr_pages_mismatch_cnt = 0;
	}
#endif
}
