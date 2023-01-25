/**
 * @file util.c
 *
 *
 * @author Ho-Ren (Jack) Chuang, SSRG Virginia Tech 2019
 *
 * Distributed under terms of the MIT license.
 */
#include <linux/mm.h>
#include <linux/slab.h>

#include <popcorn/bundle.h>

/* vm dsm debug */
volatile long false_share[PAGE_SIZE];
volatile long true_share[PAGE_SIZE];
volatile long no_share_first[PAGE_SIZE];
volatile long no_share_second[PAGE_SIZE];

void print_page_data(unsigned char *addr)
{
	int i;
	for (i = 0; i < PAGE_SIZE; i++) {
		if (i % 16 == 0) {
			printk(KERN_INFO"%08lx:", (unsigned long)(addr + i));
		}
		if (i % 4 == 0) {
			printk(" ");
		}
		printk("%02x", *(addr + i));
	}
	printk("\n");
}

void print_page_signature(unsigned char *addr)
{
	unsigned char *p = addr;
	int i, j;
	for (i = 0; i < PAGE_SIZE / 128; i++) {
		unsigned char signature = 0;
		for (j = 0; j < 32; j++) {
			signature = (signature + *p++) & 0xff;
		}
		printk("%02x", signature);
	}
	printk("\n");
}

void print_page_signature_pid(pid_t pid, unsigned char *addr)
{
	printk("  [%d] ", pid);
	print_page_signature(addr);
}

static DEFINE_SPINLOCK(__print_lock);
static char *__print_buffer = NULL;

void print_page_owner(unsigned long addr, unsigned long *owners, pid_t pid)
{
	if (unlikely(!__print_buffer)) {
		__print_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	}
	spin_lock(&__print_lock);
	bitmap_print_to_pagebuf(
			true, __print_buffer, owners, MAX_POPCORN_NODES);
	printk("  [%d] %lx %s", pid, addr, __print_buffer);
	spin_unlock(&__print_lock);
}

#include <linux/fs.h>

static DEFINE_SPINLOCK(__file_path_lock);
static char *__file_path_buffer = NULL;

int get_file_path(struct file *file, char *sz, size_t size)
{
	char *ppath;
	int retval = 0;

	if (!file) {
		BUG_ON(size < 1);
		sz[0] = '\0';
		return -EINVAL;
	}

	if (unlikely(!__file_path_buffer)) {
		__file_path_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	}

	spin_lock(&__file_path_lock);
	ppath = file_path(file, __file_path_buffer, PAGE_SIZE);
	if (IS_ERR(ppath)) {
		retval = -ESRCH;
		goto out_unlock;
	}

	strncpy(sz, ppath, size);

out_unlock:
	spin_unlock(&__file_path_lock);
	return 0;
}


static const char *__comm_to_trace[] = {
};

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>

void trace_task_status(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(__comm_to_trace); i++) {
		const char *comm = __comm_to_trace[i];
		if (memcmp(current->comm, comm, strlen(comm)) == 0) {
			printk("@@[%d] %s %lx\n", current->pid,
					current->comm, instruction_pointer(current_pt_regs()));
			break;
		}
	}
}

/********
 *
 */
#include <linux/syscalls.h>
#define OP_FALSE_SHARE_FIRST 0
#define OP_FALSE_SHARE_SECOND 1
#define OP_TRUE_SHARE 2
#define OP_NO_SHARE_FIRST 3
#define OP_NO_SHARE_SECOND 4

long noinline level4_stack(int op)
{
	int i, j, k;
	ktime_t dt, invh_end, invh_start = ktime_get();
	for (i = 0; i < 100; i++) {
		for (j = 0; j < 100000000; j++) {
	//for (i = 0; i < 10000000; i++) {
	//	for (j = 0; j < 1000; j++) {
			for (k = 0; k < 1; k++) {
				if (op == OP_FALSE_SHARE_FIRST) {
					*(false_share + 0) += 1;
				} else if (op == OP_FALSE_SHARE_SECOND) {
					*(false_share + 10) += 1;
				} else if (op == OP_TRUE_SHARE) {
					*(true_share + 0) += 1;
				} else if (op == OP_NO_SHARE_FIRST) {
					*(no_share_first + 0) += 1;
				} else if (op == OP_NO_SHARE_SECOND) {
					*(no_share_second + 0) += 1;
				} else {
					BUG();
				}
			}
		}
		schedule();
	}
	invh_end = ktime_get();
	dt = ktime_sub(invh_end, invh_start);
	printk("Took %lld s\n", ktime_to_ns(dt) / 1000 / 1000 / 1000);
	return 0;
}

long noinline level3_stack(int op) { return level4_stack(op); }
long noinline level2_stack(int op) { return level3_stack(op); }
long noinline level1_stack(int op) { return level2_stack(op); }

SYSCALL_DEFINE1(popcorn_false_share, int __user, notused)
{
	printk("[%d] %s(): %d [START]\n", current->pid, __func__, notused);
	if (notused == 1) {
		return level1_stack(OP_FALSE_SHARE_FIRST);
	} else if (notused == 2) {
		return level1_stack(OP_FALSE_SHARE_SECOND);
	} else {
		printk("[%d] %s() not support\n", current->pid, __func__);
	}
	printk("[%d] %s(): %d [DONE]\n\n", current->pid, __func__, notused);
	return 0;
}

/* notused: NULL since always the same */
SYSCALL_DEFINE1(popcorn_true_share, int __user *, notused)
{
	printk("%s(): [START]\n", __func__);
	level1_stack(OP_TRUE_SHARE);
	printk("%s(): [DONE]\n\n", __func__);
	return 0;
}

SYSCALL_DEFINE1(popcorn_no_share, int __user, notused)
{
	printk("%s(): %d [START]\n", __func__, notused);
	if (notused == 1) {
		return level1_stack(OP_NO_SHARE_FIRST);
	} else if (notused == 2) {
		return level1_stack(OP_NO_SHARE_SECOND);
	} else {
		printk("%s() not support\n", __func__);
	}
	printk("%s(): %d [DONE]\n\n", __func__, notused);
	return 0;
}

int __init vm_dsm_debug_init(void)
{
	/* todo - move to global to see it in objdumped file */
	//volatile long *false_share;
	//volatile long *true_share;
	//volatile long *no_share_first;
	//volatile long *no_share_second;
	//false_share = kmalloc(PAGE_SIZE, GFP_KERNEL);
	//true_share = kmalloc(PAGE_SIZE, GFP_KERNEL);
	//no_share_first = kmalloc(PAGE_SIZE, GFP_KERNEL);
	//no_share_second = kmalloc(PAGE_SIZE, GFP_KERNEL);
	POP_PK("false_share: %p true_share: %p "
			"no_share_first: %p no_share_second: %p\n",
			false_share, true_share, no_share_first, no_share_second);
	return 0;
}
