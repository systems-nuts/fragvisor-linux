/**
 * @file vma_server.c
 *
 * Popcorn Linux VMA handler implementation
 * This work was an extension of David Katz MS Thesis, but totally rewritten
 * by Sang-Hoon to support multithread environment.
 *
 * @author Sang-Hoon Kim, SSRG Virginia Tech 2016-2017
 * @author Vincent Legout, Antonio Barbalace, SSRG Virginia Tech 2016
 * @author Ajith Saya, Sharath Bhat, SSRG Virginia Tech 2015
 * @author Marina Sadini, Antonio Barbalace, SSRG Virginia Tech 2014
 * @author Marina Sadini, SSRG Virginia Tech 2013
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/kthread.h>

#include <linux/mman.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>

#include <linux/elf.h>

#include <popcorn/types.h>
#include <popcorn/bundle.h>
#include <popcorn/hype_kvm.h>
#include <popcorn/debug.h>

#include "types.h"
#include "util.h"
#include "vma_server.h"
#include "page_server.h"
#include "wait_station.h"

enum vma_op_code {
	VMA_OP_NOP = -1,
	VMA_OP_MMAP,
	VMA_OP_MUNMAP,
	VMA_OP_MPROTECT,
	VMA_OP_MREMAP,
	VMA_OP_MADVISE,
	VMA_OP_BRK,
	VMA_OP_MAX,
};

const char *vma_op_code_sz[] = {
	"mmap", "munmap", "mprotect", "mremap", "madvise", "brk"
};

/* remap */
static unsigned long map_difference(struct mm_struct *mm, struct file *file,
		unsigned long start, unsigned long end,
		unsigned long prot, unsigned long flags, unsigned long pgoff)
{
	unsigned long ret = start;
	unsigned long error;
	unsigned long populate = 0;
	struct vm_area_struct* vma;

	/**
	 * Go through ALL VMAs, looking for overlapping with this space.
	 */
	VSPRINTK("  [%d] map+ %lx %lx\n", current->pid, start, end);
	for (vma = current->mm->mmap; start < end; vma = vma->vm_next) {
		/*
		VSPRINTK("  [%d] vma  %lx -- %lx\n", current->pid,
				vma ? vma->vm_start : 0, vma ? vma->vm_end : 0);
		*/
		if (vma == NULL || end <= vma->vm_start) {
			/**
			 * We've reached the end of the list, or the VMA is fully
			 * above the region of interest
			 */
			VSPRINTK("  [%d] map0 %lx -- %lx @ %lx, %lx\n", current->pid,
					start, end, pgoff, prot);
#ifndef CONFIG_POPCORN_HYPE
			flags |= MAP_FIXED; /* pophype - WE MUST REPLAY THE SAME ADDR */
#endif
			error = do_mmap_pgoff(file, start, end - start,
					prot, flags, pgoff, &populate);
			if (error != start) {
				ret = VM_FAULT_SIGBUS;
			}
			break;
		} else if (start >= vma->vm_start && end <= vma->vm_end) {
			/**
			 * VMA fully encompases the region of interest. nothing to do
			 */
			break;
		} else if (start >= vma->vm_start
				&& start < vma->vm_end && end > vma->vm_end) {
			/**
			 * VMA includes the start of the region of interest
			 * but not the end. advance start (no mapping to do)
			 */
			pgoff += ((vma->vm_end - start) >> PAGE_SHIFT);
			start = vma->vm_end;
		} else if (start < vma->vm_start
				&& vma->vm_start < end && end <= vma->vm_end) {
			/**
			 * VMA includes the end of the region of interest
			 * but not the start
			 */
			VSPRINTK("  [%d] map1 %lx -- %lx @ %lx\n", current->pid,
					start, vma->vm_start, pgoff);
			error = do_mmap_pgoff(file, start, vma->vm_start - start,
					prot, flags, pgoff, &populate);
			if (error != start) {
				ret = VM_FAULT_SIGBUS;;
			}
			break;
		} else if (start <= vma->vm_start && vma->vm_end <= end) {
			/* VMA is fully within the region of interest */
			VSPRINTK("  [%d] map2 %lx -- %lx @ %lx\n", current->pid,
					start, vma->vm_start, pgoff);
			error = do_mmap_pgoff(file, start, vma->vm_start - start,
					prot, flags, pgoff, &populate);
			if (error != start) {
				ret = VM_FAULT_SIGBUS;
				break;
			}

			/**
			 * Then advance to the end of this VMA
			 */
			pgoff += ((vma->vm_end - start) >> PAGE_SHIFT);
			start = vma->vm_end;
		}
	}
	BUG_ON(populate); /* we dont handle it */
	return ret;
}


#if 0
/**
 * Heterogeneous binary support
 *
 * Handle misaligned ELF sections in the heterogeneous binary.
 * However, recent alignment tool updates makes ELF sections aligned,
 * so this is not required anymore
 * Should be paried to fs/binfmt_elf.c
 */
static unsigned long __get_file_offset(struct file *file, unsigned long vm_start)
{
	struct elfhdr elf_ex;
	struct elf_phdr *elf_eppnt = NULL, *elf_eppnt_start = NULL;
	int size, retval, i;

	retval = kernel_read(file, 0, (char *)&elf_ex, sizeof(elf_ex));
	if (retval != sizeof(elf_ex)) {
		printk("%s: ERROR in Kernel read of ELF file\n", __func__);
		retval = -1;
		goto out;
	}

	size = elf_ex.e_phnum * sizeof(struct elf_phdr);

	elf_eppnt = kmalloc(size, GFP_KERNEL);
	if (elf_eppnt == NULL) {
		printk("%s: ERROR: kmalloc failed in\n", __func__);
		retval = -1;
		goto out;
	}

	elf_eppnt_start = elf_eppnt;
	retval = kernel_read(file, elf_ex.e_phoff, (char *)elf_eppnt, size);
	if (retval != size) {
		printk("%s: ERROR: during kernel read of ELF file\n", __func__);
		retval = -1;
		goto out;
	}
	retval = 0;
	for (i = 0; i < elf_ex.e_phnum; i++, elf_eppnt++) {
		if (elf_eppnt->p_type != PT_LOAD) continue;

		if ((vm_start >= elf_eppnt->p_vaddr) &&
				(vm_start <= (elf_eppnt->p_vaddr + elf_eppnt->p_memsz))) {
			retval = elf_eppnt->p_offset +
				(vm_start & PAGE_MASK) - (elf_eppnt->p_vaddr & PAGE_MASK);
			retval >>= PAGE_SHIFT;
			break;
		}
	}

out:
	if (elf_eppnt_start != NULL)
		kfree(elf_eppnt_start);

	return retval;
}
#endif


/**
 * VMA operation delegators at remotes
 */
static vma_op_request_t *__alloc_vma_op_request(enum vma_op_code opcode)
{
	vma_op_request_t *req = kmalloc(sizeof(*req), GFP_KERNEL);

	req->origin_pid = current->origin_pid,
	req->remote_pid = current->pid,
	req->operation = opcode;

	return req;
}

static int __delegate_vma_op(vma_op_request_t *req, vma_op_response_t **resp)
{
	vma_op_response_t *res;
	struct wait_station *ws = get_wait_station(current);

	req->remote_ws = ws->id;

	pcn_kmsg_send(PCN_KMSG_TYPE_VMA_OP_REQUEST,
			current->origin_nid, req, sizeof(*req));
	res = wait_at_station(ws);
	BUG_ON(res->operation != req->operation);

	*resp = res;
	return res->ret;
}

static int handle_vma_op_response(struct pcn_kmsg_message *msg)
{
	vma_op_response_t *res = (vma_op_response_t *)msg;
	struct wait_station *ws = wait_station(res->remote_ws);

	ws->private = res;
	complete(&ws->pendings);

	return 0;
}

#include <linux/fdtable.h>
extern unsigned long vm_mmap_pgoff(struct file *, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
unsigned long vma_server_mmap_remote(struct file *file,
		unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flags, unsigned long pgoff)
{
	unsigned long ret = 0;
	vma_op_request_t *req = __alloc_vma_op_request(VMA_OP_MMAP);
	vma_op_response_t *res;

	req->addr = addr;
	req->len = len;
	req->prot = prot;
	req->flags = flags;
	req->pgoff = pgoff;
	req->fd = -1;
	get_file_path(file, req->path, sizeof(req->path));

	VSPRINTK("\n## VMA mmap [%d] %lx - %lx, %lx %lx\n", current->pid,
			addr, addr + len, prot, flags);
	if (req->path[0] != '\0') {
#ifdef CONFIG_POPCORN_HYPE
		/* pophype handle files (mmaped vcpu region)*/
		int i;
		struct fdtable *fdt;
		spin_lock(&current->files->file_lock);
		fdt = files_fdtable(current->files);
		spin_unlock(&current->files->file_lock);
		/* *file to fd for vcpu requestes */
		for (i = 3; i < fdt->max_fds; i++) { /* any MACRO to leverage? */
			if (fdt->fd[i] == file) {
				POP_PK("\t*file %p to fd %d\n\n", file, i);
				req->fd = i;
				break;
			} //else { printk("\tnot found %p\n", i, file); }
		}
#endif
		VSPRINTK("  [%d] %s\n", current->pid, req->path);
	}

	ret = __delegate_vma_op(req, &res);

#ifdef CONFIG_POPCORN_HYPE
    if (file) {
		/* pophype handle files (mmaped vcpu region) */
        //char path[512];
        //get_file_path(file, path, sizeof(path)); /* file to path */
		/* check path */
        //if (!strncmp("anon_inode:kvm-vcpu:", path,
        if (!strncmp("anon_inode:kvm-vcpu:", req->path,
                sizeof("anon_inode:kvm-vcpu:") - 1 )) {
			/* save to pophype table */
			hype_node_info[my_nid][req->fd]->vcpu =
						(struct kvm_vcpu *)file->private_data;
			hype_node_info[my_nid][req->fd]->run =
						((struct kvm_vcpu *)file->private_data)->run;
			hype_node_info[my_nid][req->fd]->vcpu_id =
						((struct kvm_vcpu *)file->private_data)->vcpu_id;
			hype_node_info[my_nid][req->fd]->uaddr = res->addr; // done by delegation
			//hype_node_info[my_nid][req->fd]->tsk = current; // ./drivers/vhost/vhost.c
			POP_PK("--------------------------------------------\n");
            POP_PK("%s(): ATTENTION this is a mmap(\"%s\") "
					"req->addr %lx [deleg] res->addr 0x%lx len %lx "
					"prot %lx flags %lx pgoff %lx\n", __func__,
					req->path, req->addr, addr, len, prot, flags, pgoff);
			POP_PK("[%d] rem (INSTALL VCPU) [%d][fd %d] vcpu_id %d vcpu %p "
					"(kern)*vcpu->run [[[%p]]] "
					"uaddr [[[0x%lx]]] *tsk [[%p]] (2nd usr cpu->kvm_run)\n",
						current->pid, my_nid, req->fd,
						hype_node_info[my_nid][req->fd]->vcpu_id,
						hype_node_info[my_nid][req->fd]->vcpu,
						hype_node_info[my_nid][req->fd]->run,
						hype_node_info[my_nid][req->fd]->uaddr,
						hype_node_info[my_nid][req->fd]->tsk);
			POP_PK("--------------------------------------------\n\n");
        }
    }
#endif

	VSPRINTK("  [%d] %ld %lx -- %lx\n", current->pid,
			ret, res->addr, res->addr + res->len);

	if (ret) {
		/* origin cannot handle, do it at remote */
		unsigned long __addr;
		__addr  = vm_mmap_pgoff(file, addr, len, prot, flags, pgoff);
		VSPRINTK("  [%d] rollback 0x%lx\n", current->pid, __addr);
		goto out_free;
	}

#if defined(CONFIG_POPCORN_HYPE) && defined(CONFIG_POPCORN_STAT)
	if (INTERESTED_GVA(addr)) {
		POP_PK("%s(): [%d] %lx $$$\n", __func__, current->pid, addr);
	}
#endif
	while (!down_write_trylock(&current->mm->mmap_sem)) {
		schedule();
	}
	ret = map_difference(current->mm, file, res->addr, res->addr + res->len,
			prot, flags, pgoff);
	up_write(&current->mm->mmap_sem);

#if 0
	/* TODO bebug  addr to vma vma->file */
#endif
out_free:
	kfree(req);
	pcn_kmsg_done(res);

#ifdef CONFIG_POPCORN_HYPE
#if HYPE_PERF_CRITICAL_DEBUG
    if (file) { /* dbg */
        char path[512];
        get_file_path(file, path, sizeof(path));
        if (!strncmp("anon_inode:kvm-vcpu:", path,
                sizeof("anon_inode:kvm-vcpu:") - 1 )) {
			VCPUPRINTK("map_difference(): [[[%lx]]] (usr cpu->kvm_run)\n\n\n\n", ret);
		}
	}
#endif
#endif
	return ret;
}

int vma_server_munmap_remote(unsigned long start, size_t len)
{
	int ret;
	vma_op_request_t *req;
	vma_op_response_t *res;

	VSPRINTK("\n## VMA munmap [%d] %lx %lx\n", current->pid, start, len);

	ret = vm_munmap(start, len);
	if (ret) return ret;

	req = __alloc_vma_op_request(VMA_OP_MUNMAP);
	req->addr = start;
	req->len = len;

	ret = __delegate_vma_op(req, &res);

	VSPRINTK("  [%d] %d %lx -- %lx\n", current->pid,
			ret, res->addr, res->addr + res->len);

	kfree(req);
	pcn_kmsg_done(res);

	return ret;
}

int vma_server_brk_remote(unsigned long oldbrk, unsigned long brk)
{
	int ret;
	vma_op_request_t *req = __alloc_vma_op_request(VMA_OP_BRK);
	vma_op_response_t *res;

	req->brk = brk;

	VSPRINTK("\n## VMA brk-ed [%d] %lx --> %lx\n", current->pid, oldbrk, brk);

	ret = __delegate_vma_op(req, &res);

	VSPRINTK("  [%d] %d %lx\n", current->pid, ret, res->brk);

	kfree(req);
	pcn_kmsg_done(res);

	return ret;
}

int vma_server_madvise_remote(unsigned long start, size_t len, int behavior)
{
	int ret;
	vma_op_request_t *req = __alloc_vma_op_request(VMA_OP_MADVISE);
	vma_op_response_t *res;

	req->addr = start;
	req->len = len;
	req->behavior = behavior;

	VSPRINTK("\n## VMA madvise-d [%d] %lx %lx %d\n", current->pid,
			start, len, behavior);

	ret = __delegate_vma_op(req, &res);

	VSPRINTK("  [%d] %d %lx -- %lx %d\n", current->pid,
			ret, res->addr, res->addr + res->len, behavior);

	kfree(req);
	pcn_kmsg_done(res);

	return ret;
}

int vma_server_mprotect_remote(unsigned long start, size_t len, unsigned long prot)
{
	int ret;
	vma_op_request_t *req = __alloc_vma_op_request(VMA_OP_MPROTECT);
	vma_op_response_t *res;

	req->start = start;
	req->len = len;
	req->prot = prot;

	VSPRINTK("\nVMA mprotect [%d] %lx %lx %lx\n", current->pid,
			start, len, prot);

	ret = __delegate_vma_op(req, &res);

	VSPRINTK("  [%d] %d %lx -- %lx %lx\n", current->pid,
			ret, res->start, res->start + res->len, prot);

	kfree(req);
	pcn_kmsg_done(res);

	return ret;
}

int vma_server_mremap_remote(unsigned long addr, unsigned long old_len,
		unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
	WARN_ON_ONCE("Does not support remote mremap yet");
	VSPRINTK("\nVMA mremap [%d] %lx %lx %lx %lx %lx\n", current->pid,
			addr, old_len, new_len, flags, new_addr);
	return -EINVAL;
}


/**
 * VMA handlers for origin
 */
int vma_server_munmap_origin(unsigned long start, size_t len, int nid_except)
{
	int nid;
	vma_op_request_t *req = __alloc_vma_op_request(VMA_OP_MUNMAP);
	struct remote_context *rc = get_task_remote(current);

	req->start = start;
	req->len = len;
	req->fd = -1;

	for (nid = 0; nid < MAX_POPCORN_NODES; nid++) {
		struct wait_station *ws;
		vma_op_response_t *res;

		if (!get_popcorn_node_online(nid) || !rc->remote_tgids[nid]) continue;

		if (nid == my_nid || nid == nid_except) continue;

		ws = get_wait_station(current);
		req->remote_ws = ws->id;
		req->origin_pid = rc->remote_tgids[nid];

		VSPRINTK("  [%d] ->munmap [%d/%d] %lx+%lx (%lx)\n", current->pid,
				req->origin_pid, nid, start, len,
				instruction_pointer(current_pt_regs()));
		pcn_kmsg_send(PCN_KMSG_TYPE_VMA_OP_REQUEST, nid, req, sizeof(*req));
		res = wait_at_station(ws);
		pcn_kmsg_done(res);
	}
	put_task_remote(current);
	kfree(req);

	vm_munmap(start, len);
	return 0;
}

/* Not used */
unsigned long pophype_vm_mmap_anon(unsigned long size, unsigned long prot, unsigned long flags)
{
	unsigned long hva = 0;
	// 1. check nodes
	//int __x86_set_memory_region(struct kvm *kvm, int id, gpa_t gpa, u32 size)

	struct remote_context *rc = get_task_remote(current);
	/*======================= TODO =======================*/
	BUG();
	/*======================= TODO =======================*/
	if (!rc) { // !migrated at all
		BUG_ON(my_nid);
		hva = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
				  MAP_SHARED | MAP_ANONYMOUS, 0);
	} else {
		if (!my_nid) { // origin
			int nid;
			// 2. origin: ->
				//check nodes
			for (nid = 1; nid < MAX_POPCORN_NODES; nid++) {
				if (!get_popcorn_node_online(nid) || !rc->remote_tgids[nid])
					continue; /* !msg || !migrated to the node */

				// TODO(): send hva -> rc->hva ()
			}
		} else { // remote
			// 3. remote: wait origin to reach (3 objs in rc)


			// TODO: spin on ec->hva
			// TODO: mimic  vma_server_mmap_remot's map_difference()
		}
	}
//done:
	HPPRINTK("%s: kvm alloates user-cannot-see hva address 0x%lx\n",
														__func__, hva);
	return hva;
}

/**
 * VMA worker
 *
 * We do this stupid thing because functions related to meomry mapping operate
 * on "current". Thus, we need mmap/munmap/madvise in our process
 */
static void __reply_vma_op(vma_op_request_t *req, long ret)
{
	vma_op_response_t *res = pcn_kmsg_get(sizeof(*res));

	res->origin_pid = current->pid;
	res->remote_pid = req->remote_pid;
	res->remote_ws = req->remote_ws;

	res->operation = req->operation;
	res->ret = ret;
	res->addr = req->addr;
	res->len = req->len;

	pcn_kmsg_post(PCN_KMSG_TYPE_VMA_OP_RESPONSE,
			PCN_KMSG_FROM_NID(req), res, sizeof(*res));
}


/**
 * Handle delegated VMA operations
 * Currently, the remote worker only handles munmap VMA operations.
 */
static long __process_vma_op_at_remote(vma_op_request_t *req)
{
	long ret = -EPERM;

	switch (req->operation) {
	case VMA_OP_MUNMAP:
		ret = vm_munmap(req->addr, req->len);
		break;
	case VMA_OP_MMAP:
	case VMA_OP_MPROTECT:
	case VMA_OP_MREMAP:
	case VMA_OP_BRK:
	case VMA_OP_MADVISE:
		BUG_ON("Not implemented yet");
		break;
	default:
		BUG_ON("unreachable");

	}
	return ret;
}

#ifdef CONFIG_POPCORN_HYPE
extern struct file_operations kvm_vm_fops;
//extern struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);
extern int anon_inode_getfd(const char *name, const struct file_operations *fops, void *priv, int flags);
extern struct filename *getname_kernel(const char * filename);
#endif
#include <linux/file.h>
static long __process_vma_op_at_origin(vma_op_request_t *req)
{
	long ret = -EPERM;
	int from_nid = PCN_KMSG_FROM_NID(req);
#ifdef CONFIG_POPCORN_HYPE
	int hype_filp = 0;
#endif

	switch (req->operation) {
	case VMA_OP_MMAP: {
		unsigned long populate = 0;
		unsigned long raddr, req_addr;
		struct file *f = NULL;
		struct mm_struct *mm = get_task_mm(current);

		if (req->path[0] != '\0')
			f = filp_open(req->path, O_RDONLY | O_LARGEFILE, 0);

		if (IS_ERR(f)) {
#ifdef CONFIG_POPCORN_HYPE
			/* POPCORN cannot open vcpu (no sysfs) - if vcpu, retry */
			char *path = req->path;
			if (!strncmp("anon_inode:kvm-vcpu:", path,
					sizeof("anon_inode:kvm-vcpu:") - 1 )) {
				int i, fd = req->fd;
				struct fd __fd = fdget(fd);
				/* Let origin go first and remote overwrite vaddr */
				/* vcpu fd -> kernel *vcpu (f->private_data) */
				VCPUPRINTK(" [%d]: => remapping/overwriting \"%s\" use fd %d "
							"to get struct &__fd %p __fd.file %p (matched???)\n\n",
								from_nid, path, req->fd, (void *)&__fd, __fd.file);
				BUG_ON(!__fd.file);
				f = __fd.file;
				BUG_ON(!f);
				fdput(__fd);
				hype_filp = 1; /* skip close since we never opened */

				POP_PK("\n======================\n"
						"\t\tPOPHYPE LOOKUP VCPU\n"
						"=======================\n");
				//for (i = 0; i < 8; i++) {
				for (i = 0; i < MAX_POPCORN_NODES; i++) {
					POP_PK("hype_node_info[%d][%d]->uaddr %lx\n",
							i, req->fd, hype_node_info[i][req->fd]->uaddr);
					POP_PK("hype_node_info[%d][%d]->uaddr %lx\n",
							i, req->fd + 1, hype_node_info[i][req->fd + 1]->uaddr);
					POP_PK("hype_node_info[%d][%d]->uaddr %lx\n",
							i, req->fd + 2, hype_node_info[i][req->fd + 2]->uaddr);
					if (hype_node_info[i][req->fd]->uaddr) {
						req_addr = req->addr;
						req->addr = raddr = hype_node_info[i][req->fd]->uaddr;
						ret = IS_ERR_VALUE(req->addr) ? req->addr : 0;
						VSPRINTK("  [%d] %lx req %lx ack [[[%lx]]] "
									"-- %lx %lx %lx\n",
									current->pid, ret, req_addr, raddr,
									raddr + req->len, req->prot, req->flags);
						POP_PK("\n");
						goto pophype_got_addr;
					} else {
						POP_PK(KERN_ERR "\n\n"
								"mynid %d=%d req->fd %d uaddr 0x%lx\n\n\n",
										my_nid, i, req->fd,
										hype_node_info[i][req->fd]->uaddr);
						BUG();
					}
				}
				POP_PK("\n");

				goto pophype_resume;
#if 0
				/* 2. Cannot get the path from sysfs */
				get_file_path(file, path, sizeof(path)); /* user space */
				printk("%s(): \"%s\" selected got *file %p "
								"at origin (O)\n", __func__, path, file);
				/* 3. Treat vcpu op as a normal region at origin */
				printk("  [%d] (using) treat as /dev/zero\n", current->pid);
				f = NULL;
#endif
			}
#endif
			ret = PTR_ERR(f);
			POP_PK("  [%d] Cannot open %s %ld\n", current->pid, req->path, ret);
			mmput(mm);
			break;
		}
pophype_resume:
		down_write(&mm->mmap_sem);
		raddr = do_mmap_pgoff(f, req->addr, req->len, req->prot,
				req->flags, req->pgoff, &populate);
		if (populate) mm_populate(raddr, populate);

		ret = IS_ERR_VALUE(raddr) ? raddr : 0;
		up_write(&mm->mmap_sem);
		req_addr = req->addr;
		req->addr = raddr; /* will copy to res */
		VSPRINTK("  [%d] %lx req %lx ack [[[%lx]]] -- %lx %lx %lx\n", current->pid,
				ret, req_addr, raddr, raddr + req->len, req->prot, req->flags);
#ifndef CONFIG_POPCORN_HYPE
		if (f)
			filp_close(f, NULL);
#else
		if (hype_filp && f) { /* more info - dbg - origin save debug info */
			/* Not used - check "(INSTALL VCPU)" at ./virt/kvm/kvm_main.c */
			hype_node_info[my_nid][req->fd]->vcpu =
							(struct kvm_vcpu *)f->private_data;
			hype_node_info[my_nid][req->fd]->run =
							((struct kvm_vcpu *)f->private_data)->run;
			hype_node_info[my_nid][req->fd]->vcpu_id =
							((struct kvm_vcpu *)f->private_data)->vcpu_id;
			hype_node_info[my_nid][req->fd]->uaddr = raddr;
			//hype_node_info[my_nid][req->fd]->tsk = current; ./drivers/vhost/vhost.c
			VCPUPRINTK("--------------------------------------------\n");
            VCPUPRINTK("%s(): ATTENTION this is a mmap(\"%s\") "
					"delegated at origin\n", __func__, req->path);
			//VCPUPRINTK("[%d] ori (INSTALL VCPU) [%d] fd %d vcpu_id %d "
			POP_PK("[%d] ori (INSTALL VCPU) [%d][fd %d] vcpu_id %d "
					"(kern)*vcpu->run [[[%p]]] uaddr [[[0x%lx]]] "
						"*tsk [[%p]] (2nd usr cpu->kvm_run)\n",
						current->pid, my_nid, req->fd,
						hype_node_info[my_nid][req->fd]->vcpu_id,
						hype_node_info[my_nid][req->fd]->run,
						hype_node_info[my_nid][req->fd]->uaddr,
						hype_node_info[my_nid][req->fd]->tsk);
			VCPUPRINTK("--------------------------------------------\n\n");
#if 0
			/* TODO bebug  addr to vma vma->file */
#endif
		} else if (f && !hype_filp) {
			filp_close(f, NULL);
		}
#endif

pophype_got_addr: /* Don't reinstall hype_node_info[][] */
		mmput(mm);
		break;
	}
	case VMA_OP_BRK: {
		unsigned long brk = req->brk;
		req->brk = sys_brk(req->brk);
		ret = brk != req->brk;
		break;
	}
	case VMA_OP_MUNMAP:
		ret = vma_server_munmap_origin(req->addr, req->len, from_nid);
		break;
	case VMA_OP_MPROTECT:
		ret = sys_mprotect(req->addr, req->len, req->prot);
		break;
	case VMA_OP_MREMAP:
		ret = sys_mremap(req->addr, req->old_len, req->new_len,
			req->flags, req->new_addr);
		break;
	case VMA_OP_MADVISE:
		if (req->behavior == MADV_RELEASE) {
			ret = process_madvise_release_from_remote(
					from_nid, req->start, req->start + req->len);
		} else {
			ret = sys_madvise(req->start, req->len, req->behavior);
		}
		break;
	default:
		BUG_ON("unreachable");
	}

	return ret;
}

void process_vma_op_request(vma_op_request_t *req)
{
	long ret = 0;
	VSPRINTK("\nVMA_OP_REQUEST [%d] %s %lx %lx %lx\n", current->pid,
			vma_op_code_sz[req->operation], req->addr, req->len,
			instruction_pointer(current_pt_regs()));

	if (current->at_remote) {
		ret = __process_vma_op_at_remote(req);
	} else {
		ret = __process_vma_op_at_origin(req);
	}

	VSPRINTK("  [%d] ->%s %ld\n", current->pid,
			vma_op_code_sz[req->operation], ret);

	__reply_vma_op(req, ret);
	pcn_kmsg_done(req);
}


/**
 * Response for remote VMA request and handling the response
 */
struct vma_info {
	struct list_head list;
	unsigned long addr;
	atomic_t pendings;
	struct completion complete;
	wait_queue_head_t pendings_wait;

	volatile int ret;
	volatile vma_info_response_t *response;
};

static struct vma_info *__lookup_pending_vma_request(struct remote_context *rc, unsigned long addr)
{
	struct vma_info *vi;

	list_for_each_entry(vi, &rc->vmas, list) {
		if (vi->addr == addr) return vi;
	}
	return NULL;
}

static int handle_vma_info_response(struct pcn_kmsg_message *msg)
{
	vma_info_response_t *res = (vma_info_response_t *)msg;
	struct task_struct *tsk;
	unsigned long flags;
	struct vma_info *vi;
	struct remote_context *rc;

	tsk = __get_task_struct(res->remote_pid);
	if (WARN_ON(!tsk)) {
		goto out_free;
	}
	rc = get_task_remote(tsk);

	spin_lock_irqsave(&rc->vmas_lock, flags);
	vi = __lookup_pending_vma_request(rc, res->addr);
	spin_unlock_irqrestore(&rc->vmas_lock, flags);
	put_task_remote(tsk);
	put_task_struct(tsk);

	if (WARN_ON(!vi)) {
		goto out_free;
	}

	vi->response = res;
	complete(&vi->complete);
	return 0;

out_free:
	pcn_kmsg_done(res);
	return 0;
}


/**
 * Handle VMA info requests at the origin.
 * This is invoked through the remote work delegation.
 */
void process_vma_info_request(vma_info_request_t *req)
{
	vma_info_response_t *res = NULL;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long addr = req->addr;

	might_sleep();

	while (!res) {
		res = kmalloc(sizeof(*res), GFP_KERNEL);
	}
	res->addr = addr;

retry:
	mm = get_task_mm(current);
	down_read(&mm->mmap_sem);

	vma = find_vma(mm, addr);

#ifdef CONFIG_POPCORN_HYPE
	/* pophype debug */
	POP_PK("vma_info: %lx, %lx - %lx\n",
			addr, vma->vm_start, vma->vm_end);
#endif
	if (unlikely(!vma)) {
		up_read(&mm->mmap_sem);
		mmput(mm);
		printk(KERN_WARNING "vma_info: vma not exist at %lx "
							"(retrying)\n", addr);
		msleep(1000);
		goto retry;
		res->result = -ENOENT;
		goto out_up;
	}
	if (likely(vma->vm_start <= addr)) {
		goto good;
	}
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		up_read(&mm->mmap_sem);
		mmput(mm);
		printk(KERN_WARNING "vma_info: vma not really exist "
					"(GROWSDOWN) at %lx > vm_start %lx (retrying)\n",
												addr, vma->vm_start);
		msleep(1000);
		goto retry;
		res->result = -ENOENT;
		goto out_up;
	}

good:
	res->vm_start = vma->vm_start;
	res->vm_end = vma->vm_end;
	res->vm_flags = vma->vm_flags;
	res->vm_pgoff = vma->vm_pgoff;

	get_file_path(vma->vm_file, res->vm_file_path, sizeof(res->vm_file_path));
	res->result = 0;

out_up:
	up_read(&mm->mmap_sem);
	mmput(mm);

	if (res->result == 0) {
		VSPRINTK("\n## VMA_INFO [%d] %lx -- %lx %lx\n", current->pid,
				res->vm_start, res->vm_end, res->vm_flags);
		if (!vma_info_anon(res)) {
			VSPRINTK("  [%d] %s + %lx\n", current->pid,
					res->vm_file_path, res->vm_pgoff);
		}
	}

	res->remote_pid = req->remote_pid;
	pcn_kmsg_send(PCN_KMSG_TYPE_VMA_INFO_RESPONSE,
			PCN_KMSG_FROM_NID(req), res, sizeof(*res));

	pcn_kmsg_done(req);
	kfree(res);
	return;
}


static struct vma_info *__alloc_vma_info_request(struct task_struct *tsk, unsigned long addr, vma_info_request_t **preq)
{
	struct vma_info *vi = kmalloc(sizeof(*vi), GFP_KERNEL);
	vma_info_request_t *req = kmalloc(sizeof(*req), GFP_KERNEL);

	BUG_ON(!vi || !req);

	/* vma_info */
	INIT_LIST_HEAD(&vi->list);
	vi->addr = addr;
	vi->response = (volatile vma_info_response_t *)0xdeadbeaf; /* poision */
	atomic_set(&vi->pendings, 0);
	init_completion(&vi->complete);
	init_waitqueue_head(&vi->pendings_wait);

	/* req */
	req->origin_pid = tsk->origin_pid;
	req->remote_pid = tsk->pid;
	req->addr = addr;

	*preq = req;

	return vi;
}


static int __update_vma(struct task_struct *tsk, vma_info_response_t *res)
{
	struct mm_struct *mm = tsk->mm;
	struct vm_area_struct *vma;
	unsigned long prot;
	unsigned flags = MAP_FIXED;
	struct file *f = NULL;
	unsigned long err = 0;
	int ret = 0;
	unsigned long addr = res->addr;

	if (res->result) {
		down_read(&mm->mmap_sem);
		return res->result;
	}

	while (!down_write_trylock(&mm->mmap_sem)) {
		schedule();
	}
	vma = find_vma(mm, addr);
	VSPRINTK("  [%d] %lx %lx\n", tsk->pid, vma ? vma->vm_start : 0, addr);
	if (vma && vma->vm_start <= addr) {
		/* somebody already done for me. */
		goto out;
	}

	/* Pophype VMFAULT has solved by origin. Now unstall */
	if (vma_info_anon(res)) {
		flags |= MAP_ANONYMOUS;
	} else {
#ifdef CONFIG_POPCORN_HYPE
		POP_PK("%s: fetched from ORIGIN now replay on my node \"%s\" "
				"res-> vm_addr 0x%lx - 0x%lx, vm_pgoff 0x%lx\n",
				__func__, res->vm_file_path,
				res->vm_start, res->vm_end, res->vm_pgoff);
		/***********************************************/
		/*** popcorn open file succ (e.g. lkvm file) ***/
		/***********************************************/
#endif
		f = filp_open(res->vm_file_path, O_RDONLY | O_LARGEFILE, 0);
		if (IS_ERR(f)) {
			printk(KERN_ERR"%s: cannot find backing file %s\n",
					__func__, res->vm_file_path);
			ret = -EIO;
#ifdef CONFIG_POPCORN_HYPE
            /****************************************/
            /*** popcorn open file fail -
				 pophype kick in (e.g. vcpu file) ***/
            /****************************************/
			dump_stack();
			printk(KERN_ERR"%s: POPHYPE FALLTHROUGH %s (popcorn cannot open)\n",
					__func__, res->vm_file_path);
			goto pophype_fall_through;
#endif
			goto out;
		}
#ifdef CONFIG_POPCORN_HYPE
pophype_fall_through:
#endif
		/*
		unsigned long orig_pgoff = res->vm_pgoff;
		res->vm_pgoff = __get_file_offset(f, res->vm_start);
		BUG_ON(res->vm_pgoff == -1);
		*/
		VSPRINTK("  [%d] %s + %lx\n", tsk->pid,
				res->vm_file_path, res->vm_pgoff);
	}

	prot  = ((res->vm_flags & VM_READ) ? PROT_READ : 0)
			| ((res->vm_flags & VM_WRITE) ? PROT_WRITE : 0)
			| ((res->vm_flags & VM_EXEC) ? PROT_EXEC : 0);

	flags = flags
			| ((res->vm_flags & VM_DENYWRITE) ? MAP_DENYWRITE : 0)
			| ((res->vm_flags & VM_SHARED) ? MAP_SHARED : MAP_PRIVATE)
			| ((res->vm_flags & VM_GROWSDOWN) ? MAP_GROWSDOWN : 0);

	/* remap */
	err = map_difference(mm, f, res->vm_start, res->vm_end,
				prot, flags, res->vm_pgoff);

	if (f) filp_close(f, NULL);

	/*
	vma = find_vma(mm, addr);
	BUG_ON(!vma || vma->vm_start > addr);
	if (res->vm_flags & VM_FETCH_LOCAL) vma->vm_flags |= VM_FETCH_LOCAL;
	*/
out:
	downgrade_write(&mm->mmap_sem);
	return ret;
}


/**
 * Fetch VMA information from the origin.
 * mm->mmap_sem is down_read() at this point and should be downed upon return.
 */
int vma_server_fetch_vma(struct task_struct *tsk, unsigned long address)
{
	struct vma_info *vi;
	unsigned long flags;
	DEFINE_WAIT(wait);
	int ret = 0;
	unsigned long addr = address & PAGE_MASK;
	vma_info_request_t *req = NULL;
	struct remote_context *rc = get_task_remote(tsk);

	might_sleep();

	VSPRINTK("\n## VMAFAULT [%d] %lx %lx\n", current->pid,
			address, instruction_pointer(current_pt_regs()));

	spin_lock_irqsave(&rc->vmas_lock, flags);
	vi = __lookup_pending_vma_request(rc, addr);
	if (!vi) {
		struct vma_info *v;
		spin_unlock_irqrestore(&rc->vmas_lock, flags);

		vi = __alloc_vma_info_request(tsk, addr, &req);

		spin_lock_irqsave(&rc->vmas_lock, flags);
		v = __lookup_pending_vma_request(rc, addr);
		if (!v) {
			list_add(&vi->list, &rc->vmas);
		} else {
			kfree(vi);
			vi = v;
			kfree(req);
			req = NULL;
		}
	}
	up_read(&tsk->mm->mmap_sem);

	if (req) {
		spin_unlock_irqrestore(&rc->vmas_lock, flags);

		VSPRINTK("  [%d] %lx ->[%d/%d]\n", current->pid,
				addr, tsk->origin_pid, tsk->origin_nid);
#ifdef CONFIG_POPCORN_HYPE
		/* pophype (dex) limitation -
		 * if address < 0x7ffff0000000 && address > heap,
		 * mir cannot malloc at remote - found caused by mpx.
		 * Current solution: disable intel mpx */
#endif
		pcn_kmsg_send(PCN_KMSG_TYPE_VMA_INFO_REQUEST,
				tsk->origin_nid, req, sizeof(*req));
		wait_for_completion(&vi->complete);

		ret = vi->ret =
			__update_vma(tsk, (vma_info_response_t *)vi->response);

		spin_lock_irqsave(&rc->vmas_lock, flags);
		list_del(&vi->list);
		spin_unlock_irqrestore(&rc->vmas_lock, flags);

		pcn_kmsg_done((void *)vi->response);
		wake_up_all(&vi->pendings_wait);

		kfree(req);
	} else {
		VSPRINTK("  [%d] %lx already pended\n", current->pid, addr);
		atomic_inc(&vi->pendings);
		prepare_to_wait(&vi->pendings_wait, &wait, TASK_UNINTERRUPTIBLE);
		spin_unlock_irqrestore(&rc->vmas_lock, flags);

		io_schedule();
		finish_wait(&vi->pendings_wait, &wait);

		smp_rmb();
		ret = vi->ret;
		if (atomic_dec_and_test(&vi->pendings)) {
			kfree(vi);
		}
		down_read(&tsk->mm->mmap_sem);
	}

	put_task_remote(tsk);
	return ret;
}


DEFINE_KMSG_RW_HANDLER(vma_info_request, vma_info_request_t, origin_pid);
DEFINE_KMSG_RW_HANDLER(vma_op_request, vma_op_request_t, origin_pid);

extern int first[]; // from arch/x86/kvm/x86.c
int vma_server_init(void)
{
	int i, j;
	REGISTER_KMSG_HANDLER(
			PCN_KMSG_TYPE_VMA_INFO_REQUEST, vma_info_request);
	REGISTER_KMSG_HANDLER(
			PCN_KMSG_TYPE_VMA_INFO_RESPONSE, vma_info_response);

	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_VMA_OP_REQUEST, vma_op_request);
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_VMA_OP_RESPONSE, vma_op_response);

#ifdef CONFIG_POPCORN_HYPE
//	hype_node_info = kmalloc(sizeof(struct hype_node_info_t) *
//							MAX_POPCORN_NODES * MAX_POPCORN_FD, GFP_KERNEL);
	SIGVPRINTK("%s(): init vma_server_init[][]\n", __func__);
	for (i = 0; i < MAX_POPCORN_NODES; i++)
		for (j = 0; j < MAX_POPCORN_VCPU; j++) {
			hype_node_info[i][j] =
					kmalloc(sizeof(struct hype_node_info_t), GFP_KERNEL);
			BUG_ON(!hype_node_info[i][j]);
			memset(hype_node_info[i][j], 0, sizeof(struct hype_node_info_t));
		}

	for (i = 0; i < MAX_POPCORN_NODES; i++) {
		first[i] = 1;
	}
#endif
	return 0;
}
