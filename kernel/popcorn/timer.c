/**
 * @file timer.c
 *
 *
 * @author Ho-Ren (Jack) Chuang, SSRG Virginia Tech 2019
 *
 * Distributed under terms of the MIT license.
 */
#include <linux/kernel.h>
#include <linux/timer.h>

#include <asm/pgtable.h>
#include <popcorn/hype_kvm.h>

#include <linux/highmem.h>

extern bool pophype_debug;
#if defined(CONFIG_POPCORN_STAT) && POPHYPE_HOST_KERNEL
static struct timer_list my_timer;
#endif

static unsigned char *paddr;
static unsigned char _paddr[PAGE_SIZE];
//static char kvaddr[PAGE_SIZE];
static char kvmaddr_hex_str[PAGE_SIZE * 10];

//static int cnt = 0;

void my_timer_callback(unsigned long data)
{
#if defined(CONFIG_POPCORN_STAT) && POPHYPE_HOST_KERNEL
	/* do your timer stuff here */
	//if (++cnt < 10 || !(cnt % 10))
	//	printk("%s(): timer 10s pophype_debug %d #%d\n",
	//						__func__, pophype_debug, cnt);
	if (pophype_debug) {


		/* TODO bh.......... otherwise __get_user_pages_unlocked() cannot work */


		int i, found = 0;
		for (i = 0; i < MAX_POPCORN_VCPU; i++) {
			if (my_nid == popcorn_vcpuid_to_nid(i)) {
				int fd = i + VCPU_FD_BASE;
				if (hype_node_info[my_nid][fd]->vcpu) { /* found vcpu */
					struct kvm_vcpu *vcpu = hype_node_info[my_nid][fd]->vcpu;
					unsigned long gpa = __pa(level3_kernel_pgt);
					unsigned long gfn, hva;
					int j, ofs = 0;

					struct task_struct *tsk = hype_node_info[my_nid][fd]->tsk;
					struct page *page[1];
					int write_fault = 0;
					int npages;

					struct vm_area_struct *vma;

					found = 1;
					// level3_kernel_pgt
					// 		gva = ffffffff81e0d000
					//		gpa = 		   1e0d000
					//		hva =

					// show page contain

					///* guest pgt walk */
					//tr.linear_address = next_rbp_gva;
					//kvm_arch_vcpu_ioctl_translate(
					//            hype_node_info[my_nid][fd]->vcpu, &tr);
					//gpa = tr.physical_address;

					//if (gpa == 0UL - 1)
					//    goto __err;

					//int cnt = 0, i;
					//int err_cnt = 0;
					//struct kvm_translation tr;
					//unsigned long *frame;
					//unsigned long next_rbp_gva = kvm_regs->rbp;

					/* host - gpa -> gfn */
					gfn = gpa >> PAGE_SHIFT;
					hva = kvm_vcpu_gfn_to_hva(vcpu, gfn);

					// BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG
					// BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG
					//// how to get the right address space???
					//// how to feed to copy_from_user.....
					//if (copy_from_user(kvaddr,
					//			(const void __user *)hva, PAGE_SIZE)) {
					//	printk(KERN_ERR "%s(): BUG() "
					//			"kvaddr %p gpa %lx gfn %lx hva %p\n",
					//				__func__, kvaddr, gpa, gfn, hva);
					//	BUG();
					//}
					// BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG
					// BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG BUG

					// case 2
					// get mm vma

		goto out; // remote out origin stay
		goto out; // remote out origin stay
		goto out; // remote out origin stay
		goto out; // remote out origin stay
		goto out; // remote out origin stay
		goto out; // remote out origin stay
		goto out; // remote out origin stay
		goto out; // remote out origin stay
		goto out; // remote out origin stay

					if (my_nid) goto out; // remote out origin stay
					printk("show level3_kernel_pgt %p %lx page data "
							"(dbg - fd %d) hva %lx "
							"tsk %p [pid %d's address space]\n",
							level3_kernel_pgt, __pa(level3_kernel_pgt),
							fd, hva, tsk, tsk ? tsk->pid : -78);
					/* remote tsk already released so pid is -XXXXXXXXXXX */
					if (!tsk->mm) goto out; // remote out origin stay

					// get_user_pages
					//		like virt/kvm/kvm_main.c
					//		ref get_user_page_nowait()
					//struct task_struct *tsk, struct mm_struct *mm,
					//		unsigned long start, int write, struct page **page
					//int read_flags = FOLL_TOUCH | FOLL_HWPOISON | FOLL_GET;
					//int a = __get_user_pages(tsk, mm, start,
					//						1, read_flags, page, NULL, NULL);
					//long get_user_pages_unlocked(
					//		struct task_struct *tsk, struct mm_struct *mm,
					//		unsigned long start, unsigned long nr_pages,
					//		int write, int force, struct page **pages) {
					//	__get_user_pages_unlocked(tsk, mm, start, nr_pages,
					//						write, force, pages, FOLL_TOUCH);
					//}
					npages = __get_user_pages_unlocked(tsk, tsk->mm,
										hva, 1, write_fault, 0, page,
											FOLL_TOUCH|FOLL_HWPOISON);
					BUG_ON(npages != 1);

					//paddr = kmap(page);
					vma = find_vma(tsk->mm, hva);
					BUG_ON (!vma || vma->vm_start > hva);

					paddr = kmap_atomic(*page);
					copy_from_user_page(vma, *page, hva, _paddr, paddr, PAGE_SIZE); // !!!! retry
					kunmap_atomic(paddr);
					// TODO hex to string and then print
					//for (j = 0; j < PAGE_SIZE; j += sizeof(long)) {
					for (j = 0; j < PAGE_SIZE; j += sizeof(char)) { // 0xff (*4096)
						ofs += sprintf(kvmaddr_hex_str + ofs,
										"%02hhx ", *(_paddr + j));
					}

					kvmaddr_hex_str[ofs] = '\0';
					printk("ofs %d: %s\n",
								ofs, kvmaddr_hex_str);
				}
			}
		}
		BUG_ON(!found);
	}
out:
	mod_timer(&my_timer, jiffies + msecs_to_jiffies(1000));
#endif
}

int __init vm_dsm_debug_timer_init(void)
{
#if defined(CONFIG_POPCORN_STAT) && POPHYPE_HOST_KERNEL
	/* setup your timer to call my_timer_callback */
	setup_timer(&my_timer, my_timer_callback, 0);
	/* setup timer interval to 1000 msecs */
	mod_timer(&my_timer, jiffies + msecs_to_jiffies(1000));
	printk("%s(): __init\n", __func__);
#endif
	return 0;
}

void __exit cleanup_vm_dsm_debug_timer(void)
{
#if defined(CONFIG_POPCORN_STAT) && POPHYPE_HOST_KERNEL
	del_timer(&my_timer);
	printk("%s(): __exit\n", __func__);
#endif
	return;
}
