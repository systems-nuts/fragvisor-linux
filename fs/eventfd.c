/*
 *  fs/eventfd.c
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#include <linux/file.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/anon_inodes.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/kref.h>
#include <linux/eventfd.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#ifdef CONFIG_POPCORN_HYPE
#include <popcorn/types.h>
#include <popcorn/hype_kvm.h>
#endif

struct eventfd_ctx {
	struct kref kref;
	wait_queue_head_t wqh;
	/*
	 * Every time that a write(2) is performed on an eventfd, the
	 * value of the __u64 being written is added to "count" and a
	 * wakeup is performed on "wqh". A read(2) will return the "count"
	 * value to userspace, and will reset "count" to zero. The kernel
	 * side eventfd_signal() also, adds to the "count" counter and
	 * issue a wakeup.
	 */
	__u64 count;
	unsigned int flags;
};

/**
 * eventfd_signal - Adds @n to the eventfd counter.
 * @ctx: [in] Pointer to the eventfd context.
 * @n: [in] Value of the counter to be added to the eventfd internal counter.
 *          The value cannot be negative.
 *
 * This function is supposed to be called by the kernel in paths that do not
 * allow sleeping. In this function we allow the counter to reach the ULLONG_MAX
 * value, and we signal this as overflow condition by returining a POLLERR
 * to poll(2).
 *
 * Returns the amount by which the counter was incrememnted.  This will be less
 * than @n if the counter has overflowed.
 */
__u64 eventfd_signal(struct eventfd_ctx *ctx, __u64 n)
{
	unsigned long flags;

//#ifdef CONFIG_POPCORN_HYPE
#if 0
    static u64 cnt = 0;
    cnt++;
	//if (cnt < 10000) {
	CRITICALNETPK("\tpophype: vhost-net: <%d> %s: %s(): -> #%llu\n",
						smp_processor_id(), __FILE__, __func__, cnt);
	//}

	/* pophype prepares to delegate */
	CRITICALNETPK("\tpophype: vhost-net: <%d> %s: %s(): "
			"delegate event ctx %p ->count %llu ->flags %u "
			"&ctx->kref.refcount %d => #%llu\n",
			smp_processor_id(), __FILE__, __func__, ctx, ctx->count,
			ctx->flags, atomic_read(&ctx->kref.refcount), cnt);
	/* how can I get the wqh at remote (I need to record) */
	/* What I'm doing now is to just wake up
		the corresponding vhost_wq (I assume there is only one Q) */

	/* pophype - ioeventfd delegation */
	/* ctx to fd or file */
	if (distributed_remote_process(current)) {
		int fd = eventfd_ctx_to_fd(ctx);
		__u64 res_n = pophype_eventfd_delegate(fd, n);
		CRITICALNETPK("%s(): [DELEGATED] SKIP LOCAL\n", __func__);
		//
		//msg->fd = fd;
		//pcnkmsg_send(msg);

		/* Don't update local ctx->count at remote */
		/* and return directly */
		return res_n;
/*
		if (res_n == n)
			fine
		else
			printk("ctx wqh ";);
		spin_lock_irqsave(&ctx->wqh.lock, flags);
		ctx->count += n;
		spin_unlock_irqrestore(&ctx->wqh.lock, flags);
*/
	}
	/* 2019/11/05 (remove above) change to nonblocking */

	/* delegate */
	/* ctx to fd or file */
#endif

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	if (ULLONG_MAX - ctx->count < n)
		n = ULLONG_MAX - ctx->count;
	ctx->count += n;
	VIRTIOBLKPK("%s(): comm=%s (%d), count=%d\n",
		__func__, current->comm, current->pid, ctx->count);
	if (waitqueue_active(&ctx->wqh)) {
		wake_up_locked_poll(&ctx->wqh, POLLIN);
		VIRTIOBLKPK("%s(): comm=%s (%d), waking up the waiter, count=%d\n",
			__func__, current->comm, current->pid, ctx->count);
	}
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);

	return n;
}
EXPORT_SYMBOL_GPL(eventfd_signal);

/* Delegation work */
__u64 pophype_eventfd_signal(struct eventfd_ctx *ctx, __u64 n)
{
	unsigned long flags;

	BUG_ON(current->at_remote);

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	if (ULLONG_MAX - ctx->count < n)
		n = ULLONG_MAX - ctx->count;
	ctx->count += n;
	if (waitqueue_active(&ctx->wqh))
		wake_up_locked_poll(&ctx->wqh, POLLIN);
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);

	return n;
}
//EXPORT_SYMBOL_GPL(pophype_eventfd_signal);

static void eventfd_free_ctx(struct eventfd_ctx *ctx)
{
	kfree(ctx);
}

static void eventfd_free(struct kref *kref)
{
	struct eventfd_ctx *ctx = container_of(kref, struct eventfd_ctx, kref);

	eventfd_free_ctx(ctx);
}

/**
 * eventfd_ctx_get - Acquires a reference to the internal eventfd context.
 * @ctx: [in] Pointer to the eventfd context.
 *
 * Returns: In case of success, returns a pointer to the eventfd context.
 */
struct eventfd_ctx *eventfd_ctx_get(struct eventfd_ctx *ctx)
{
	kref_get(&ctx->kref);
	return ctx;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_get);

/**
 * eventfd_ctx_put - Releases a reference to the internal eventfd context.
 * @ctx: [in] Pointer to eventfd context.
 *
 * The eventfd context reference must have been previously acquired either
 * with eventfd_ctx_get() or eventfd_ctx_fdget().
 */
void eventfd_ctx_put(struct eventfd_ctx *ctx)
{
	kref_put(&ctx->kref, eventfd_free);
}
EXPORT_SYMBOL_GPL(eventfd_ctx_put);

static int eventfd_release(struct inode *inode, struct file *file)
{
	struct eventfd_ctx *ctx = file->private_data;

	wake_up_poll(&ctx->wqh, POLLHUP);
	eventfd_ctx_put(ctx);
	return 0;
}

static unsigned int eventfd_poll(struct file *file, poll_table *wait)
{
	struct eventfd_ctx *ctx = file->private_data;
	unsigned int events = 0;
	u64 count;

#ifdef CONFIG_POPCORN_HYPE
	if (distributed_process(current)) {
		POP_PK("%s(): file %p *eventfd_ctx = file->private_data fd %d\n",
				__func__, file, popcorn_file_to_fd(current, file, false));
		//dump_stack();
	}
#endif

	poll_wait(file, &ctx->wqh, wait);
	smp_rmb();
	count = ctx->count;

	if (count > 0)
		events |= POLLIN;
	if (count == ULLONG_MAX)
		events |= POLLERR;
	if (ULLONG_MAX - 1 > count)
		events |= POLLOUT;

	return events;
}

static void eventfd_ctx_do_read(struct eventfd_ctx *ctx, __u64 *cnt)
{
	*cnt = (ctx->flags & EFD_SEMAPHORE) ? 1 : ctx->count;
	ctx->count -= *cnt;
}

/**
 * eventfd_ctx_remove_wait_queue - Read the current counter and removes wait queue.
 * @ctx: [in] Pointer to eventfd context.
 * @wait: [in] Wait queue to be removed.
 * @cnt: [out] Pointer to the 64-bit counter value.
 *
 * Returns %0 if successful, or the following error codes:
 *
 * -EAGAIN      : The operation would have blocked.
 *
 * This is used to atomically remove a wait queue entry from the eventfd wait
 * queue head, and read/reset the counter value.
 */
int eventfd_ctx_remove_wait_queue(struct eventfd_ctx *ctx, wait_queue_t *wait,
				  __u64 *cnt)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	eventfd_ctx_do_read(ctx, cnt);
	__remove_wait_queue(&ctx->wqh, wait);
	if (*cnt != 0 && waitqueue_active(&ctx->wqh))
		wake_up_locked_poll(&ctx->wqh, POLLOUT);
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);

	return *cnt != 0 ? 0 : -EAGAIN;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_remove_wait_queue);

/**
 * eventfd_ctx_read - Reads the eventfd counter or wait if it is zero.
 * @ctx: [in] Pointer to eventfd context.
 * @no_wait: [in] Different from zero if the operation should not block.
 * @cnt: [out] Pointer to the 64-bit counter value.
 *
 * Returns %0 if successful, or the following error codes:
 *
 * -EAGAIN      : The operation would have blocked but @no_wait was non-zero.
 * -ERESTARTSYS : A signal interrupted the wait operation.
 *
 * If @no_wait is zero, the function might sleep until the eventfd internal
 * counter becomes greater than zero.
 */
ssize_t eventfd_ctx_read(struct eventfd_ctx *ctx, int no_wait, __u64 *cnt)
{
	ssize_t res;
	DECLARE_WAITQUEUE(wait, current);

	spin_lock_irq(&ctx->wqh.lock);
	*cnt = 0;
	res = -EAGAIN;
	VIRTIOBLKPK("%s(): comm=%s (%d), count=%d\n",
				 __func__, current->comm, current->pid, ctx->count);
	if (ctx->count > 0)
		res = 0;
	else if (!no_wait) {
		__add_wait_queue(&ctx->wqh, &wait);
		for (;;) {
			set_current_state(TASK_INTERRUPTIBLE);
			if (ctx->count > 0) {
				res = 0;
				break;
			}
			if (signal_pending(current)) {
				res = -ERESTARTSYS;
				break;
			}
			spin_unlock_irq(&ctx->wqh.lock);
			VIRTIOBLKPK("%s(): comm=%s (%d), going to sleep! count=%d\n",
						 __func__, current->comm, current->pid, ctx->count);
			schedule();
			spin_lock_irq(&ctx->wqh.lock);
			VIRTIOBLKPK("%s(): comm=%s (%d), woke up! count=%d\n",
						 __func__, current->comm, current->pid, ctx->count);
		}
		__remove_wait_queue(&ctx->wqh, &wait);
		__set_current_state(TASK_RUNNING);
	}
	if (likely(res == 0)) {
		eventfd_ctx_do_read(ctx, cnt);
		if (waitqueue_active(&ctx->wqh))
			wake_up_locked_poll(&ctx->wqh, POLLOUT);
	}

	VIRTIOBLKPK("%s(): comm=%s (%d) did it! leaving! count=%d cnt=%d\n",
				 __func__, current->comm, current->pid, ctx->count, *cnt);
	spin_unlock_irq(&ctx->wqh.lock);

	return res;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_read);

static ssize_t eventfd_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	struct eventfd_ctx *ctx = file->private_data;
	ssize_t res;
	__u64 cnt;

#ifdef CONFIG_POPCORN_HYPE
	if (distributed_process(current)) {
		int fd = popcorn_file_to_fd(current, file, false);
		POP_PK("\t\t[%d] %s: [R] fd %d file %p count %lu ppos %lld\n\n",
							current->pid, __func__, fd, file, count, *ppos);
		//dump_stack();
		/* Happens when using net-mq (fd 28) */
	}
#endif

	if (count < sizeof(cnt))
		return -EINVAL;
	res = eventfd_ctx_read(ctx, file->f_flags & O_NONBLOCK, &cnt);
	if (res < 0)
		return res;

	return put_user(cnt, (__u64 __user *) buf) ? -EFAULT : sizeof(cnt);
}

static ssize_t eventfd_write(struct file *file, const char __user *buf, size_t count,
			     loff_t *ppos)
{
	struct eventfd_ctx *ctx = file->private_data;
	ssize_t res;
	__u64 ucnt;
	DECLARE_WAITQUEUE(wait, current);

#ifdef CONFIG_POPCORN_HYPE
	if (distributed_process(current)) {
		int fd = popcorn_file_to_fd(current, file, false);
		POP_PK("\t\t[%d] %s: [W] fd %d file %p count %lu ppos %lld\n\n",
							current->pid, __func__, fd, file, count, *ppos);
	}
#endif

	if (count < sizeof(ucnt))
		return -EINVAL;
	if (copy_from_user(&ucnt, buf, sizeof(ucnt)))
		return -EFAULT;
	if (ucnt == ULLONG_MAX)
		return -EINVAL;
	spin_lock_irq(&ctx->wqh.lock);
	res = -EAGAIN;
	if (ULLONG_MAX - ctx->count > ucnt)
		res = sizeof(ucnt);
	else if (!(file->f_flags & O_NONBLOCK)) {
		__add_wait_queue(&ctx->wqh, &wait);
		for (res = 0;;) {
			set_current_state(TASK_INTERRUPTIBLE);
			if (ULLONG_MAX - ctx->count > ucnt) {
				res = sizeof(ucnt);
				break;
			}
			if (signal_pending(current)) {
				res = -ERESTARTSYS;
				break;
			}
			spin_unlock_irq(&ctx->wqh.lock);
			schedule();
			spin_lock_irq(&ctx->wqh.lock);
		}
		__remove_wait_queue(&ctx->wqh, &wait);
		__set_current_state(TASK_RUNNING);
	}
	if (likely(res > 0)) {
		ctx->count += ucnt;
		if (waitqueue_active(&ctx->wqh))
			wake_up_locked_poll(&ctx->wqh, POLLIN);
	}
	spin_unlock_irq(&ctx->wqh.lock);

	return res;
}

#ifdef CONFIG_PROC_FS
static void eventfd_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct eventfd_ctx *ctx = f->private_data;

	spin_lock_irq(&ctx->wqh.lock);
	seq_printf(m, "eventfd-count: %16llx\n",
		   (unsigned long long)ctx->count);
	spin_unlock_irq(&ctx->wqh.lock);
}
#endif

static const struct file_operations eventfd_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= eventfd_show_fdinfo,
#endif
	.release	= eventfd_release,
	.poll		= eventfd_poll,
	.read		= eventfd_read,
	.write		= eventfd_write,
	.llseek		= noop_llseek,
};

/**
 * eventfd_fget - Acquire a reference of an eventfd file descriptor.
 * @fd: [in] Eventfd file descriptor.
 *
 * Returns a pointer to the eventfd file structure in case of success, or the
 * following error pointer:
 *
 * -EBADF    : Invalid @fd file descriptor.
 * -EINVAL   : The @fd file descriptor is not an eventfd file.
 */
struct file *eventfd_fget(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &eventfd_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}

	return file;
}
EXPORT_SYMBOL_GPL(eventfd_fget);

/**
 * eventfd_ctx_fdget - Acquires a reference to the internal eventfd context.
 * @fd: [in] Eventfd file descriptor.
 *
 * Returns a pointer to the internal eventfd context, otherwise the error
 * pointers returned by the following functions:
 *
 * eventfd_fget
 */
struct eventfd_ctx *eventfd_ctx_fdget(int fd)
{
	struct eventfd_ctx *ctx;
	struct fd f = fdget(fd);
	if (!f.file)
		return ERR_PTR(-EBADF);
	ctx = eventfd_ctx_fileget(f.file);
	fdput(f);
	return ctx;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_fdget);

/**
 * eventfd_ctx_fileget - Acquires a reference to the internal eventfd context.
 * @file: [in] Eventfd file pointer.
 *
 * Returns a pointer to the internal eventfd context, otherwise the error
 * pointer:
 *
 * -EINVAL   : The @fd file descriptor is not an eventfd file.
 */
struct eventfd_ctx *eventfd_ctx_fileget(struct file *file)
{
	if (file->f_op != &eventfd_fops)
		return ERR_PTR(-EINVAL);

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t\tpophype: vhost-net: <%d> %s(): use file to get ctx\n",
										smp_processor_id(), __func__);
#endif

	return eventfd_ctx_get(file->private_data);
}
EXPORT_SYMBOL_GPL(eventfd_ctx_fileget);

/**
 * eventfd_file_create - Creates an eventfd file pointer.
 * @count: Initial eventfd counter value.
 * @flags: Flags for the eventfd file.
 *
 * This function creates an eventfd file pointer, w/out installing it into
 * the fd table. This is useful when the eventfd file is used during the
 * initialization of data structures that require extra setup after the eventfd
 * creation. So the eventfd creation is split into the file pointer creation
 * phase, and the file descriptor installation phase.
 * In this way races with userspace closing the newly installed file descriptor
 * can be avoided.
 * Returns an eventfd file pointer, or a proper error pointer.
 */
struct file *eventfd_file_create(unsigned int count, int flags)
{
	struct file *file;
	struct eventfd_ctx *ctx;
#ifdef CONFIG_POPCORN_HYPE
	static int cnt = 0;
#endif
	/* Check the EFD_* constants for consistency.  */
	BUILD_BUG_ON(EFD_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON(EFD_NONBLOCK != O_NONBLOCK);

	if (flags & ~EFD_FLAGS_SET)
		return ERR_PTR(-EINVAL);

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	kref_init(&ctx->kref);
	init_waitqueue_head(&ctx->wqh);
	ctx->count = count;
	ctx->flags = flags;

	file = anon_inode_getfile("[eventfd]", &eventfd_fops, ctx,
				  O_RDWR | (flags & EFD_SHARED_FCNTL_FLAGS));
	if (IS_ERR(file))
		eventfd_free_ctx(ctx);

#ifdef CONFIG_POPCORN_HYPE
	cnt++;
	/* pophype: memcached requires libevent and uses ebentfd a lot!!! */
	CRITICALNETPK("\n\tpophype: vhost-net: <%d> %s(): [eventfd] ctx %p "
			"I need this info to delegaten. "
			"TODO RECORD mapping with "
			"struct file %p <-priv data-> ctx %p #%d\n",
			smp_processor_id(), __func__, ctx, file, ctx, cnt);
	/* record it inside anon_inode_getfile() */
	// event_ctx is from here............. not from 22
#endif

	return file;
}

SYSCALL_DEFINE2(eventfd2, unsigned int, count, int, flags)
{
	int fd, error;
	struct file *file;

	error = get_unused_fd_flags(flags & EFD_SHARED_FCNTL_FLAGS);
	if (error < 0)
		return error;
	fd = error;

	file = eventfd_file_create(count, flags);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto err_put_unused_fd;
	}
	fd_install(fd, file);

//#ifdef CONFIG_POPCORN_HYPE
#if 0
    if (distributed_process(current)) {
        POP_PK("\t[%d] %s() %s: *** eventfd fd %d *** <-> file %p "
				"count %d flags %x rip 0x%lx\n",
				current->pid, __func__, __FILE__,
				fd, file, count, flags,
				instruction_pointer(current_pt_regs()));

		/* only here I can get fd!!!
			This is the right place for vhost-net eventfd not from 22 */
		if (!hype_eventfd_info[fd]) { /* new - install ctx */
//			struct fd f = fdget(fd);
//			struct file *file;
//			struct eventfd_ctx *eventfd_ctx;
			/* Attension eventfd_ctx != file->private_data but containerof() */

			struct eventfd_ctx *eventfd_ctx = eventfd_ctx_fdget(fd);
//			eventfd_ctx = eventfd_ctx_fileget(file);
//			if (file)
//				eventfd_ctx = eventfd_ctx_get(file->private_data);

			hype_eventfd_info[fd] =
				kmalloc(sizeof(**hype_eventfd_info), GFP_ATOMIC);
			BUG_ON(!hype_eventfd_info[fd]);
			if (eventfd_ctx < 0) {
				POP_PK("\n\t\t%s: %s(): hype_eventfd_info[%d] BAD "
						"don't install eventfd_ctx %p %d\n\n",
						__FILE__, __func__, fd, eventfd_ctx, (int)eventfd_ctx);
			} else if (eventfd_ctx) {
				hype_eventfd_info[fd]->eventfd_ctx = eventfd_ctx;
				//hype_eventfd_info[fd]->irqfd = irqfd;
				POP_PK("\n\t\t%s %s(): [ADD] hype_eventfd_info[%d] "
						"eventfd_ctx %p\n\n",
						__FILE__, __func__, fd, eventfd_ctx);
				/* optimize - record the smallest fd for faster lookup */
			} else { // happens
				POP_PK("\n\t\t%s %s(): [ADD] hype_eventfd_info[%d] BUT "
					"this fd doesn't have a private_data (not eventfd_ctx) - "
					"debug file %p file->private_data %p eventfd_ctx %p %d\n\n",
					__FILE__, __func__,
					fd, file, file->private_data, eventfd_ctx, (int)eventfd_ctx);
			}
		} else {
			POP_PK("\n\t\t%s %s(): [ADD] hype_eventfd_info[%d] "
					"eventfd_ctx %p already exitst\n\n",
					__FILE__, __func__, fd, hype_eventfd_info[fd]->eventfd_ctx);
		}
    }
#endif
	// printk(KERN_INFO "virtio-blk: eventfd(%d, %d): return fd=%d\n", count, flags, fd);
	return fd;

err_put_unused_fd:
	put_unused_fd(fd);

	return error;
}

SYSCALL_DEFINE1(eventfd, unsigned int, count)
{
	return sys_eventfd2(count, 0);
}

