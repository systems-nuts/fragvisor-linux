/**
 * @file process_server.c
 *
 * Popcorn Linux thread migration implementation
 * This work was an extension of David Katz MS Thesis, but totally rewritten
 * by Sang-Hoon to support multithread environment.
 *
 * @author Sang-Hoon Kim, SSRG Virginia Tech 2017
 * @author Antonio Barbalace, SSRG Virginia Tech 2014-2016
 * @author Vincent Legout, Sharat Kumar Bath, Ajithchandra Saya, SSRG Virginia Tech 2014-2015
 * @author David Katz, Marina Sadini, SSRG Virginia 2013
 */

#include <linux/sched.h>
#include <linux/threads.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/ptrace.h>
#include <linux/mmu_context.h>
#include <linux/fs.h>
#include <linux/futex.h>

#include <asm/mmu_context.h>
#include <asm/kdebug.h>
#include <asm/uaccess.h>

#include <popcorn/types.h>
#include <popcorn/bundle.h>
#include <popcorn/cpuinfo.h>
#include <popcorn/debug.h>

#include <linux/file.h>

#include "types.h"
#include "process_server.h"
#include "vma_server.h"
#include "page_server.h"
#include "wait_station.h"
#include "util.h"

#ifdef CONFIG_POPCORN_HYPE
#include <popcorn/hype_kvm.h>
#endif
static struct list_head remote_contexts[2];
static spinlock_t remote_contexts_lock[2];

static void popcorn_ask_remote_tgid(int nid, struct remote_context *rc);

enum {
	INDEX_OUTBOUND = 0,
	INDEX_INBOUND = 1,
};

/* Hold the correnponding remote_contexts_lock */
static struct remote_context *__lookup_remote_contexts_in(int nid, int tgid)
{
	struct remote_context *rc;

	list_for_each_entry(rc, remote_contexts + INDEX_INBOUND, list) {
		if (rc->remote_tgids[nid] == tgid) {
			return rc;
		}
	}
	return NULL;
}

#define __lock_remote_contexts(index) \
	spin_lock(remote_contexts_lock + index)
#define __lock_remote_contexts_in(nid) \
	__lock_remote_contexts(INDEX_INBOUND)
#define __lock_remote_contexts_out(nid) \
	__lock_remote_contexts(INDEX_OUTBOUND)

#define __unlock_remote_contexts(index) \
	spin_unlock(remote_contexts_lock + index)
#define __unlock_remote_contexts_in(nid) \
	__unlock_remote_contexts(INDEX_INBOUND)
#define __unlock_remote_contexts_out(nid) \
	__unlock_remote_contexts(INDEX_OUTBOUND)

#define __remote_contexts_in() remote_contexts[INDEX_INBOUND]
#define __remote_contexts_out() remote_contexts[INDEX_OUTBOUND]


inline struct remote_context *__get_mm_remote(struct mm_struct *mm)
{
	struct remote_context *rc = mm->remote;
	atomic_inc(&rc->count);
	return rc;
}

inline struct remote_context *get_task_remote(struct task_struct *tsk)
{
	return __get_mm_remote(tsk->mm);
}

inline bool __put_task_remote(struct remote_context *rc)
{
	if (!atomic_dec_and_test(&rc->count)) return false;

	__lock_remote_contexts(rc->for_remote);
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(atomic_read(&rc->count));
#endif
	list_del(&rc->list);
	__unlock_remote_contexts(rc->for_remote);

	free_remote_context_pages(rc);
	kfree(rc);
	return true;
}

inline bool put_task_remote(struct task_struct *tsk)
{
	return __put_task_remote(tsk->mm->remote);
}

void free_remote_context(struct remote_context *rc)
{
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(atomic_read(&rc->count) != 1 && atomic_read(&rc->count) != 2);
#endif
	__put_task_remote(rc);
}

static struct remote_context *__alloc_remote_context(int nid, int tgid, bool remote)
{
	struct remote_context *rc = kmalloc(sizeof(*rc), GFP_KERNEL);
	int i;

	if (!rc) return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rc->list);
	atomic_set(&rc->count, 1); /* Account for mm->remote in a near future */
	rc->mm = NULL;

	rc->tgid = tgid;
	rc->for_remote = remote;

	for (i = 0; i < FAULTS_HASH; i++) {
		INIT_HLIST_HEAD(&rc->faults[i]);
		spin_lock_init(&rc->faults_lock[i]);
	}

	INIT_LIST_HEAD(&rc->vmas);
	spin_lock_init(&rc->vmas_lock);

	rc->stop_remote_worker = false;

	rc->remote_worker = NULL;
	INIT_LIST_HEAD(&rc->remote_works);
	spin_lock_init(&rc->remote_works_lock);
	init_completion(&rc->remote_works_ready);

	memset(rc->remote_tgids, 0x00, sizeof(rc->remote_tgids));

	INIT_RADIX_TREE(&rc->pages, GFP_ATOMIC);

	return rc;
}

static void __build_task_comm(char *buffer, char *path)
{
	int i, ch;
	for (i = 0; (ch = *(path++)) != '\0';) {
		if (ch == '/')
			i = 0;
		else if (i < (TASK_COMM_LEN - 1))
			buffer[i++] = ch;
	}
	buffer[i] = '\0';
}


///////////////////////////////////////////////////////////////////////////////
// Distributed mutex
///////////////////////////////////////////////////////////////////////////////
#define ORIGIN_FUTEX_SKIP (0)
#define REMOTE_FUTEX_SKIP (0)
long process_server_do_futex_at_remote(u32 __user *uaddr, int op, u32 val,
		bool valid_ts, struct timespec *ts,
		u32 __user *uaddr2,u32 val2, u32 val3)
{
	struct wait_station *ws = get_wait_station(current);
	remote_futex_request req = {
		.origin_pid = current->origin_pid,
		.remote_ws = ws->id,
		.op = op,
		.val = val,
		.ts = {
			.tv_sec = -1,
		},
		.uaddr = uaddr,
		.uaddr2 = uaddr2,
		.val2 = val2,
		.val3 = val3,
	};
	remote_futex_response *res;
	long ret;
#ifdef CONFIG_POPCORN_HYPE
	static unsigned long futex_at_remote_cnt = 0;
	unsigned long futex_at_remote_thre;
	unsigned long addr;
	if (uaddr) {
		BUG_ON(copy_from_user(&addr, uaddr, sizeof(unsigned long)));
	}
#endif

	if (valid_ts) {
		req.ts = *ts;
	}

#ifdef CONFIG_POPCORN_HYPE
	BUG_ON(!current->at_remote);
	futex_at_remote_thre = REMOTE_FUTEX_SKIP;
	futex_at_remote_cnt++;
	if (uaddr &&
		(futex_at_remote_cnt > futex_at_remote_thre ||
		INTERESTED_GVA(addr))) {
		FUTEXPRINTK(" f[%d] =>[%d/%d] 0x%x %p 0x%x #%lu\n", current->pid,
				current->origin_pid, current->origin_nid,
				op, uaddr, val, futex_at_remote_cnt);
	}
#else
	/*
	printk(" f[%d] ->[%d/%d] 0x%x %p 0x%x\n", current->pid,
			current->origin_pid, current->origin_nid,
			op, uaddr, val);
	*/
#endif
	pcn_kmsg_send(PCN_KMSG_TYPE_FUTEX_REQUEST,
			current->origin_nid, &req, sizeof(req));
	res = wait_at_station(ws);
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(!res);
#ifdef CONFIG_POPCORN_HYPE
	if (res == ERR_PTR(-ETIMEDOUT)) {
		PCNPRINTK_ERR("Not !res but time out\n");
		WARN_ON(res == ERR_PTR(-ETIMEDOUT));
	}
#endif
#endif
	ret = res->ret;
#ifdef CONFIG_POPCORN_HYPE
	if (uaddr &&
		(futex_at_remote_cnt > futex_at_remote_thre ||
		INTERESTED_GVA(addr))) {
		FUTEXPRINTK(" >>f[%d] <=[%d/%d] 0x%x %p 0x%x #%lu\n", current->pid,
				current->origin_pid, current->origin_nid,
				op, uaddr, val, futex_at_remote_cnt);
	}
#else
	/*
	printk(" f[%d] <-[%d/%d] 0x%x %p %ld\n", current->pid,
			current->origin_pid, current->origin_nid,
			op, uaddr, ret);
	*/
#endif

	pcn_kmsg_done(res);
	return ret;
}

static int handle_remote_futex_response(struct pcn_kmsg_message *msg)
{
	remote_futex_response *res = (remote_futex_response *)msg;
	struct wait_station *ws = wait_station(res->remote_ws);

	ws->private = res;
	complete(&ws->pendings);
	return 0;
}

static void process_remote_futex_request(remote_futex_request *req)
{
	int ret;
	remote_futex_response *res;
	ktime_t t, *tp = NULL;
#ifdef CONFIG_POPCORN_HYPE
	static unsigned long process_futex_at_origin_cnt = 0;
	unsigned long process_futex_at_origin_thre;
	unsigned long addr;
	if (req->uaddr) {
		BUG_ON(copy_from_user(&addr, req->uaddr, sizeof(unsigned long)));
	}
#endif

	if (timespec_valid(&req->ts)) {
		t = timespec_to_ktime(req->ts);
		t = ktime_add_safe(ktime_get(), t);
		tp = &t;
	}

#ifdef CONFIG_POPCORN_HYPE
	BUG_ON(current->at_remote);
	process_futex_at_origin_thre = ORIGIN_FUTEX_SKIP;
	process_futex_at_origin_cnt++;

	FUTEXPRINTK(" f[%d] <-[%d/%d] 0x%x %p 0x%x #%lu\n", current->pid,
			current->remote_pid, current->remote_nid,
			req->op, req->uaddr, req->val, process_futex_at_origin_cnt);
#else
	/*
	printk(" f[%d] <-[%d/%d] 0x%x %p 0x%x\n", current->pid,
			current->remote_pid, current->remote_nid,
			req->op, req->uaddr, req->val);
	*/
#endif
	ret = do_futex(req->uaddr, req->op, req->val,
			tp, req->uaddr2, req->val2, req->val3);

#ifdef CONFIG_POPCORN_HYPE
	FUTEXPRINTK(" f[%d] ->[%d/%d] 0x%x %p %d #%lu\n", current->pid,
			current->remote_pid, current->remote_nid,
			req->op, req->uaddr, ret, process_futex_at_origin_cnt);
#else
	/*
	printk(" f[%d] ->[%d/%d] 0x%x %p %d\n", current->pid,
			current->remote_pid, current->remote_nid,
			req->op, req->uaddr, ret);
	*/
#endif
	res = pcn_kmsg_get(sizeof(*res));
	res->remote_ws = req->remote_ws;
	res->ret = ret;

	pcn_kmsg_post(PCN_KMSG_TYPE_FUTEX_RESPONSE,
			current->remote_nid, res, sizeof(*res));
	pcn_kmsg_done(req);
}


///////////////////////////////////////////////////////////////////////////////
// Handle process/task exit
///////////////////////////////////////////////////////////////////////////////
static void __terminate_remotes(struct remote_context *rc)
{
	int nid;
	origin_task_exit_t req = {
		.origin_pid = current->pid,
		.exit_code = current->exit_code,
	};

	/* Take down peer vma workers */
	for (nid = 0; nid < MAX_POPCORN_NODES; nid++) {
		if (nid == my_nid || rc->remote_tgids[nid] == 0) continue;
		PSPRINTK("TERMINATE [%d/%d] with 0x%d\n",
				rc->remote_tgids[nid], nid, req.exit_code);

		req.remote_pid = rc->remote_tgids[nid];
		pcn_kmsg_send(PCN_KMSG_TYPE_TASK_EXIT_ORIGIN, nid, &req, sizeof(req));
	}
}

static int __exit_origin_task(struct task_struct *tsk)
{
	struct remote_context *rc = tsk->mm->remote;

	if (tsk->remote) {
		put_task_remote(tsk);
	}
	tsk->remote = NULL;
	tsk->origin_nid = tsk->origin_pid = -1;

	/**
	 * Trigger peer termination if this is the last user thread
	 * referring to this mm.
	 */
	if (atomic_read(&tsk->mm->mm_users) == 1) {
		__terminate_remotes(rc);
	}

	return 0;
}

static int __exit_remote_task(struct task_struct *tsk)
{
	if (tsk->exit_code == TASK_PARKED) {
		/* Skip notifying for back-migrated threads */
	} else {
		/* Something went south. Notify the origin. */
		if (!get_task_remote(tsk)->stop_remote_worker) {
			remote_task_exit_t req = {
				.origin_pid = tsk->origin_pid,
				.remote_pid = tsk->pid,
				.exit_code = tsk->exit_code,
			};
			pcn_kmsg_send(PCN_KMSG_TYPE_TASK_EXIT_REMOTE,
					tsk->origin_nid, &req, sizeof(req));
		}
		put_task_remote(tsk);
	}

	put_task_remote(tsk);
	tsk->remote = NULL;
	tsk->origin_nid = tsk->origin_pid = -1;

	return 0;
}

int process_server_task_exit(struct task_struct *tsk)
{
	WARN_ON(tsk != current);

	if (!distributed_process(tsk)) return -ESRCH;

	PSPRINTK("EXITED [%d] %s%s / 0x%x\n", tsk->pid,
			tsk->at_remote ? "remote" : "local",
			tsk->is_worker ? " worker": "",
			tsk->exit_code);

	// show_regs(task_pt_regs(tsk));

	if (tsk->is_worker) return 0;

	if (tsk->at_remote) {
		return __exit_remote_task(tsk);
	} else {
		return __exit_origin_task(tsk);
	}
}


/**
 * Handle the notification of the task kill at the remote.
 */
static void process_remote_task_exit(remote_task_exit_t *req)
{
	struct task_struct *tsk = current;
	int exit_code = req->exit_code;

	if (tsk->remote_pid != req->remote_pid) {
		printk(KERN_INFO"%s: pid mismatch %d != %d\n", __func__,
				tsk->remote_pid, req->remote_pid);
		pcn_kmsg_done(req);
		return;
	}

	PSPRINTK("%s [%d] 0x%x\n", __func__, tsk->pid, req->exit_code);

	tsk->remote = NULL;
	tsk->remote_nid = -1;
	tsk->remote_pid = -1;
	put_task_remote(tsk);

	exit_code = req->exit_code;
	pcn_kmsg_done(req);

	if (exit_code & CSIGNAL) {
		force_sig(exit_code & CSIGNAL, tsk);
	}
	do_exit(exit_code);
}

static void process_origin_task_exit(struct remote_context *rc, origin_task_exit_t *req)
{
	BUG_ON(!current->is_worker);

	PSPRINTK("\nTERMINATE [%d] with 0x%x\n", current->pid, req->exit_code);
	current->exit_code = req->exit_code;
	rc->stop_remote_worker = true;

	pcn_kmsg_done(req);
}


///////////////////////////////////////////////////////////////////////////////
// handling back migration
///////////////////////////////////////////////////////////////////////////////
static void process_back_migration(back_migration_request_t *req)
{
	if (current->remote_pid != req->remote_pid) {
		printk(KERN_INFO"%s: pid mismatch during back migration (%d != %d)\n",
				__func__, current->remote_pid, req->remote_pid);
		goto out_free;
	}

	PSPRINTK("### BACKMIG [%d] from [%d/%d]\n",
			current->pid, req->remote_pid, req->remote_nid);

	/* Welcome home */

	current->remote = NULL;
	current->remote_nid = -1;
	current->remote_pid = -1;
	put_task_remote(current);

	current->personality = req->personality;

	/* XXX signals */

	/* mm is not updated here; has been synchronized through vma operations */

	restore_thread_info(&req->arch, true);

out_free:
	pcn_kmsg_done(req);
}


/*
 * Send a message to <dst_nid> for migrating back a task <task>.
 * This is a back migration
 *  => <task> must already been migrated to <dst_nid>.
 * It returns -1 in error case.
 */
static int __do_back_migration(struct task_struct *tsk, int dst_nid, void __user *uregs)
{
	back_migration_request_t *req;
	int ret;

	might_sleep();

	BUG_ON(tsk->origin_nid == -1 && tsk->origin_pid == -1);

	req = pcn_kmsg_get(sizeof(*req));

	req->origin_pid = tsk->origin_pid;
	req->remote_nid = my_nid;
	req->remote_pid = tsk->pid;

	req->personality = tsk->personality;

	/*
	req->remote_blocked = tsk->blocked;
	req->remote_real_blocked = tsk->real_blocked;
	req->remote_saved_sigmask = tsk->saved_sigmask;
	req->remote_pending = tsk->pending;
	req->sas_ss_sp = tsk->sas_ss_sp;
	req->sas_ss_size = tsk->sas_ss_size;
	memcpy(req->action, tsk->sighand->action, sizeof(req->action));
	*/

	ret = copy_from_user(&req->arch.regsets, uregs,
			regset_size(get_popcorn_node_arch(dst_nid)));
	BUG_ON(ret != 0);

	save_thread_info(&req->arch);

	ret = pcn_kmsg_post(
			PCN_KMSG_TYPE_TASK_MIGRATE_BACK, dst_nid, req, sizeof(*req));

	do_exit(TASK_PARKED);
}


///////////////////////////////////////////////////////////////////////////////
// Remote thread
///////////////////////////////////////////////////////////////////////////////
static int handle_remote_task_pairing(struct pcn_kmsg_message *msg)
{
	remote_task_pairing_t *req = (remote_task_pairing_t *)msg;
	struct task_struct *tsk;
	int from_nid = PCN_KMSG_FROM_NID(req);
	int ret = 0;

	tsk = __get_task_struct(req->your_pid);
	if (!tsk) {
		ret = -ESRCH;
		goto out;
	}
#if defined(CONFIG_POPCORN_HYPE) && defined(CONFIG_POPCORN_CHECK_SANITY)
	if (tsk->at_remote) {
		printk(KERN_ERR "from a remote remote_thread_main() => "
				"from_nid [%d/%d]\n", from_nid, req->my_pid);
	}
#endif
	BUG_ON(tsk->at_remote);
	BUG_ON(!tsk->remote);

	tsk->remote_nid = from_nid;
	tsk->remote_pid = req->my_pid;
	tsk->remote->remote_tgids[from_nid] = req->my_tgid;

	put_task_struct(tsk);
out:
	pcn_kmsg_done(req);
	return 0;
}

static int __pair_remote_task(void)
{
	remote_task_pairing_t req = {
		.my_tgid = current->tgid,
		.my_pid = current->pid,
		.your_pid = current->origin_pid,
	};
	return pcn_kmsg_send(
			PCN_KMSG_TYPE_TASK_PAIRING, current->origin_nid, &req, sizeof(req));
}


struct remote_thread_params {
	clone_request_t *req;
};

static int remote_thread_main(void *_args)
{
	struct remote_thread_params *params = _args;
	clone_request_t *req = params->req;

#ifdef CONFIG_POPCORN_DEBUG_VERBOSE
	PSPRINTK("%s [%d] started for [%d/%d]\n", __func__,
			current->pid, req->origin_pid, PCN_KMSG_FROM_NID(req));
#endif

	current->flags &= ~PF_KTHREAD;	/* Demote from temporary priviledge */
	current->origin_nid = PCN_KMSG_FROM_NID(req);
	current->origin_pid = req->origin_pid;
	current->remote = get_task_remote(current);

	set_fs(USER_DS);

	/* Inject thread info here */
	restore_thread_info(&req->arch, true);

	/* XXX: Skip restoring signals and handlers for now
	sigorsets(&current->blocked, &current->blocked, &req->remote_blocked);
	sigorsets(&current->real_blocked,
			&current->real_blocked, &req->remote_real_blocked);
	sigorsets(&current->saved_sigmask,
			&current->saved_sigmask, &req->remote_saved_sigmask);
	current->pending = req->remote_pending;
	current->sas_ss_sp = req->sas_ss_sp;
	current->sas_ss_size = req->sas_ss_size;
	memcpy(current->sighand->action, req->action, sizeof(req->action));
	*/

#ifdef CONFIG_POPCORN_HYPE
	/* No need to restore fds */
	FDPRINTK("[%d] current->files [[%p]] skip fd establishing\n",
									current->pid, current->files);
#endif

	__pair_remote_task();

	PSPRINTK("\n####### MIGRATED - [%d/%d] from [%d/%d]\n",
			current->pid, my_nid, current->origin_pid, current->origin_nid);

	kfree(params);
	pcn_kmsg_done(req);

	return 0;
	/* Returning from here makes this thread jump into the user-space */
}

static int __fork_remote_thread(clone_request_t *req)
{
	struct remote_thread_params *params;
	params = kmalloc(sizeof(*params), GFP_KERNEL);
	params->req = req;

	/* The loop deals with signals between concurrent migration */
	while (kernel_thread(remote_thread_main, params,
					CLONE_FILES | CLONE_THREAD | CLONE_SIGHAND | SIGCHLD) < 0) {
		schedule();
	}
	return 0;
}

static int __construct_mm(clone_request_t *req, struct remote_context *rc)
{
	struct mm_struct *mm;
	struct file *f;

	mm = mm_alloc();
	if (!mm) {
		return -ENOMEM;
	}

	arch_pick_mmap_layout(mm);

	f = filp_open(req->exe_path, O_RDONLY | O_LARGEFILE | O_EXCL, 0);
	if (IS_ERR(f)) {
		PCNPRINTK_ERR("cannot open executable from %s\n", req->exe_path);
		mmdrop(mm);
		return -EINVAL;
	}
	set_mm_exe_file(mm, f);
	filp_close(f, NULL);

	mm->task_size = req->task_size;
	mm->start_stack = req->stack_start;
	mm->start_brk = req->start_brk;
	mm->brk = req->brk;
	mm->env_start = req->env_start;
	mm->env_end = req->env_end;
	mm->arg_start = req->arg_start;
	mm->arg_end = req->arg_end;
	mm->start_code = req->start_code;
	mm->end_code = req->end_code;
	mm->start_data = req->start_data;
	mm->end_data = req->end_data;
	mm->def_flags = req->def_flags;

	use_mm(mm);

	rc->mm = mm;  /* No need to increase mm_users due to mm_alloc() */
	mm->remote = rc;

	return 0;
}


static void __terminate_remote_threads(struct remote_context *rc)
{
	struct task_struct *tsk;

	/* Terminate userspace threads. Tried to use do_group_exit() but it
	 * didn't work */
	rcu_read_lock();
	for_each_thread(current, tsk) {
		if (tsk->is_worker) continue;
		force_sig(current->exit_code, tsk);
	}
	rcu_read_unlock();
}

static void __run_remote_worker(struct remote_context *rc)
{
	while (!rc->stop_remote_worker) {
		struct work_struct *work = NULL;
		struct pcn_kmsg_message *msg;
		int ret;
		unsigned long flags;

		ret = wait_for_completion_interruptible_timeout(
					&rc->remote_works_ready, HZ);
		if (ret == 0) continue;

		spin_lock_irqsave(&rc->remote_works_lock, flags);
		if (!list_empty(&rc->remote_works)) {
			work = list_first_entry(
					&rc->remote_works, struct work_struct, entry);
			list_del(&work->entry);
		}
		spin_unlock_irqrestore(&rc->remote_works_lock, flags);
		if (!work) continue;

		msg = ((struct pcn_kmsg_work *)work)->msg;

		switch (msg->header.type) {
		case PCN_KMSG_TYPE_TASK_MIGRATE:
			__fork_remote_thread((clone_request_t *)msg);
			break;
		case PCN_KMSG_TYPE_VMA_OP_REQUEST:
			process_vma_op_request((vma_op_request_t *)msg);
			break;
		case PCN_KMSG_TYPE_TASK_EXIT_ORIGIN:
			process_origin_task_exit(rc, (origin_task_exit_t *)msg);
			break;
		default:
			printk("Unknown remote work type %d\n", msg->header.type);
			break;
		}

		/* msg is released (pcn_kmsg_done()) in each handler */
		kfree(work);
	}
}


struct remote_worker_params {
	clone_request_t *req;
	struct remote_context *rc;
	char comm[TASK_COMM_LEN];
};

#include <linux/fdtable.h>
extern int sys_close(unsigned int fd);
static int remote_worker_main(void *data)
{
	struct remote_worker_params *params = (struct remote_worker_params *)data;
	struct remote_context *rc = params->rc;
	clone_request_t *req = params->req;
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_TERMINAL_MIGRATION
	int fd1, fd2, fd3;
#endif
#endif

	might_sleep();
	kfree(params);

	PSPRINTK("%s: [%d] for [%d/%d]\n", __func__,
			current->pid, req->origin_tgid, PCN_KMSG_FROM_NID(req));
	PSPRINTK("%s: [%d] %s\n", __func__,
			current->pid, req->exe_path);

	current->flags &= ~PF_RANDOMIZE;	/* Disable ASLR for now*/
	current->flags &= ~PF_KTHREAD;	/* Demote to a user thread */

	current->personality = req->personality;
	current->is_worker = true;
	current->at_remote = true;
	current->origin_nid = PCN_KMSG_FROM_NID(req);
	current->origin_pid = req->origin_pid;

	set_user_nice(current, 0);

	/* meaningless for now */
	/*
	struct cred *new;
	new = prepare_kernel_cred(NULL);
	commit_creds(new);
	*/

	if (__construct_mm(req, rc)) {
		BUG();
		return -EINVAL;
	}

	get_task_remote(current);
	rc->tgid = current->tgid;

#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_TERMINAL_MIGRATION
	/* fd migration support */
	/* There is a permission BUG - e.g. pts/6 can open others' pts */
	{
		int flags = O_CREAT | O_RDWR;

		fd1 = do_sys_open(AT_FDCWD , "/dev/pts/0", flags, 0);
		fd2 = do_sys_open(AT_FDCWD , "/dev/pts/0", flags, 0);
		fd3 = do_sys_open(AT_FDCWD , "/dev/pts/0", flags, 0);

		//int fd1 = do_sys_open(AT_FDCWD , "/dev/null", flags, 0);
		POP_PK("/dev/pts/ %d %d %d\n", fd1, fd2, fd3);
		if (fd1 >= 0 && fd2 >= 0 && fd3 >= 0) { /* All good */
			PSPRINTK("fd Recreated /dev/pts/ %d %d %d\n", fd1, fd2, fd3);
		} else {
			fd1 = do_sys_open(AT_FDCWD , "/dev/pts/1", flags, 0);
			fd2 = do_sys_open(AT_FDCWD , "/dev/pts/1", flags, 0);
			fd3 = do_sys_open(AT_FDCWD , "/dev/pts/1", flags, 0);
			POP_PK("%d %d %d\n", fd1, fd2, fd3);
			if (fd1 == 0 && fd2 == 1 && fd3 == 2) {
				PSPRINTK("fd Recreated %d %d %d (ALL GOOD)\n", fd1, fd2, fd3);
			} else {
				BUG();
			}
		}
	}
#endif
#endif

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("%s(): at remote first worker thread migration [%d/%d]\n",
		__func__, POPCORN_HOST_NID, rc->remote_tgids[POPCORN_HOST_NID]);
	{
		int nid;
		for (nid = 1; nid < get_popcorn_nodes() && nid < my_nid; nid++) {
			/* how can I be sure remote has created the worker thread. */
			POP_PK("%s(): ASK [%d(/%d)] for tgid\n",
				__func__, nid, get_popcorn_nodes() - 1);
			popcorn_ask_remote_tgid(nid, rc);
		}
	}
	POP_PK("\n");
#endif

	__run_remote_worker(rc);

	__terminate_remote_threads(rc);
#ifdef CONFIG_POPCORN_HYPE
#ifdef CONFIG_POPCORN_TERMINAL_MIGRATION
	PSPRINTK("remote main worker frees dummy files/fds\n");
	if (fd1 == 0 && fd2 == 1 && fd3 == 2) { /* All good */
		PSPRINTK("Close fd %d %d %d\n", fd1, fd2, fd3);
		sys_close(fd1);
		sys_close(fd2);
		sys_close(fd3);
	} else {
		BUG();
	}
#endif
#endif

	put_task_remote(current);
	return current->exit_code;
}



static void __schedule_remote_work(struct remote_context *rc, struct pcn_kmsg_work *work)
{
	/* Exploit the list_head in work_struct */
	struct list_head *entry = &((struct work_struct *)work)->entry;
	unsigned long flags;

	INIT_LIST_HEAD(entry);
	spin_lock_irqsave(&rc->remote_works_lock, flags);
	list_add(entry, &rc->remote_works);
	spin_unlock_irqrestore(&rc->remote_works_lock, flags);

	complete(&rc->remote_works_ready);
}

static void clone_remote_thread(struct work_struct *_work)
{
	struct pcn_kmsg_work *work = (struct pcn_kmsg_work *)_work;
	clone_request_t *req = work->msg;
	int nid_from = PCN_KMSG_FROM_NID(req);
	int tgid_from = req->origin_tgid;
	struct remote_context *rc;
	struct remote_context *rc_new =
			__alloc_remote_context(nid_from, tgid_from, true);

	BUG_ON(!rc_new);

	__lock_remote_contexts_in(nid_from);
	rc = __lookup_remote_contexts_in(nid_from, tgid_from);
	if (!rc) {
		struct remote_worker_params *params;

		rc = rc_new;
		rc->remote_tgids[nid_from] = tgid_from;
		list_add(&rc->list, &__remote_contexts_in());
		__unlock_remote_contexts_in(nid_from);

		params = kmalloc(sizeof(*params), GFP_KERNEL);
		BUG_ON(!params);

		params->rc = rc;
		params->req = req;
		__build_task_comm(params->comm, req->exe_path);
		smp_wmb();

		rc->remote_worker =
				kthread_run(remote_worker_main, params, params->comm);
	} else {
		__unlock_remote_contexts_in(nid_from);
		kfree(rc_new);
	}

	/* Schedule this fork request */
	__schedule_remote_work(rc, work);
	return;
}

static int handle_clone_request(struct pcn_kmsg_message *msg)
{
	clone_request_t *req = (clone_request_t *)msg;
	struct pcn_kmsg_work *work = kmalloc(sizeof(*work), GFP_ATOMIC);
	BUG_ON(!work);

	work->msg = req;
	INIT_WORK((struct work_struct *)work, clone_remote_thread);
	queue_work(popcorn_wq, (struct work_struct *)work);

	return 0;
}


///////////////////////////////////////////////////////////////////////////////
// Handle remote works at the origin
///////////////////////////////////////////////////////////////////////////////
int request_remote_work(pid_t pid, struct pcn_kmsg_message *req)
{
	struct task_struct *tsk = __get_task_struct(pid);
	int ret = -ESRCH;
	if (!tsk) {
		int i = 0;
		POP_PK(KERN_INFO"%s: invalid origin task %d for remote work %d\n",
				__func__, pid, req->header.type);
		WARN_ON("trying to fix");
		while (!tsk) {
			if (++i > 1000000) {
				POP_PK(KERN_INFO"%s: invalid origin task %d for remote work %d\n",
						__func__, pid, req->header.type);
				BUG();
			}
			io_schedule();
			tsk = __get_task_struct(pid);
		}
		POP_PK(KERN_INFO"%s: fixed origin task %d for remote work %d\n",
										__func__, pid, req->header.type);
	}

	/**
	 * Origin-initiated remote works are node-wide operations, thus, enqueue
	 * such requests into the remote work queue.
	 * On the other hand, remote-initated remote works are thread-wise requests.
	 * So, pending the requests to the per-thread work queue.
	 */
	if (tsk->at_remote) {
		struct remote_context *rc = get_task_remote(tsk);
		struct pcn_kmsg_work *work = kmalloc(sizeof(*work), GFP_ATOMIC);

		BUG_ON(!tsk->is_worker);
		work->msg = req;

		__schedule_remote_work(rc, work);

		__put_task_remote(rc);
	} else {
		WARN_ON(tsk->remote_work);
		while (tsk->remote_work)
			;
		tsk->remote_work = req;
		complete(&tsk->remote_work_pended); /* implicit memory barrier */
	}

	put_task_struct(tsk);
	return 0;
}

static void __process_remote_works(void)
{
	bool run = true;
	if (current->at_remote) {
		dump_stack();
	}
	BUG_ON(current->at_remote);

	while (run) {
		struct pcn_kmsg_message *req;
		long ret;
		ret = wait_for_completion_interruptible_timeout(
				&current->remote_work_pended, HZ);
		if (ret == 0) continue; /* timeout */

		req = (struct pcn_kmsg_message *)current->remote_work;
		current->remote_work = NULL;
		smp_wmb();

		if (!req) continue;

		switch (req->header.type) {
		case PCN_KMSG_TYPE_REMOTE_PAGE_REQUEST:
			WARN_ON_ONCE("Not implemented yet!");
			break;
		case PCN_KMSG_TYPE_VMA_OP_REQUEST: // DEFINE_KMSG_RW_HANDLER in vma_server.c
			process_vma_op_request((vma_op_request_t *)req);
			break;
		case PCN_KMSG_TYPE_VMA_INFO_REQUEST: // DEFINE_KMSG_RW_HANDLER in vma_server.c
			process_vma_info_request((vma_info_request_t *)req);
			break;
		case PCN_KMSG_TYPE_FUTEX_REQUEST: // DEFINE_KMSG_RW_HANDLER
			process_remote_futex_request((remote_futex_request *)req);
			break;
		case PCN_KMSG_TYPE_TASK_EXIT_REMOTE: // DEFINE_KMSG_RW_HANDLER
			process_remote_task_exit((remote_task_exit_t *)req);
			run = false;
			break;
		case PCN_KMSG_TYPE_TASK_MIGRATE_BACK: // DEFINE_KMSG_RW_HANDLER
			process_back_migration((back_migration_request_t *)req);
			run = false;
			break;
		default:
			if (WARN_ON("Received unsupported remote work")) {
				POP_PK("  type: %d\n", req->header.type);
			}
		}
	}
}


/**
 * Send a message to <dst_nid> for migrating a task <task>.
 * This function will ask the remote node to create a thread to host the task.
 * It returns <0 in error case.
 */
static int __request_clone_remote(int dst_nid, struct task_struct *tsk, void __user *uregs)
{
	struct mm_struct *mm = get_task_mm(tsk);
	clone_request_t *req;
	int ret;

	req = pcn_kmsg_get(sizeof(*req));
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}

	/* struct mm_struct */
	if (get_file_path(mm->exe_file, req->exe_path, sizeof(req->exe_path))) {
		printk("%s: cannot get path to exe binary\n", __func__);
		ret = -ESRCH;
		pcn_kmsg_put(req);
		goto out;
	}

	req->task_size = mm->task_size;
	req->stack_start = mm->start_stack;
	req->start_brk = mm->start_brk;
	req->brk = mm->brk;
	req->env_start = mm->env_start;
	req->env_end = mm->env_end;
	req->arg_start = mm->arg_start;
	req->arg_end = mm->arg_end;
	req->start_code = mm->start_code;
	req->end_code = mm->end_code;
	req->start_data = mm->start_data;
	req->end_data = mm->end_data;
	req->def_flags = mm->def_flags;

	/* struct tsk_struct */
	req->origin_tgid = tsk->tgid;
	req->origin_pid = tsk->pid;

	req->personality = tsk->personality;

	/* Signals and handlers
	req->remote_blocked = tsk->blocked;
	req->remote_real_blocked = tsk->real_blocked;
	req->remote_saved_sigmask = tsk->saved_sigmask;
	req->remote_pending = tsk->pending;
	req->sas_ss_sp = tsk->sas_ss_sp;
	req->sas_ss_size = tsk->sas_ss_size;
	memcpy(req->action, tsk->sighand->action, sizeof(req->action));
	*/

	/* Register sets from userspace */
	ret = copy_from_user(&req->arch.regsets, uregs,
			regset_size(get_popcorn_node_arch(dst_nid)));
	BUG_ON(ret != 0);
	save_thread_info(&req->arch);

	ret = pcn_kmsg_post(PCN_KMSG_TYPE_TASK_MIGRATE, dst_nid, req, sizeof(*req));

out:
	mmput(mm);
	return ret;
}

static int __do_migration(struct task_struct *tsk, int dst_nid, void __user *uregs)
{
	int ret;
	struct remote_context *rc;

	/* Won't to allocate this object in a spinlock-ed area */
	rc = __alloc_remote_context(my_nid, tsk->tgid, false);
	if (IS_ERR(rc)) return PTR_ERR(rc);

	if (cmpxchg(&tsk->mm->remote, 0, rc)) {
		kfree(rc);
	} else {
		/*
		 * This process is becoming a distributed one if it was not yet.
		 * The first thread gets migrated attaches the remote context to
		 * mm->remote, which indicates some threads in this process is
		 * distributed.
		 */
		rc->mm = tsk->mm;
		rc->remote_tgids[my_nid] = tsk->tgid;
#ifdef CONFIG_POPCORN_HYPE
		POP_PK("%s() myself [%d/%d]\n",
				__func__, my_nid, tsk->tgid);
#endif

		__lock_remote_contexts_out(dst_nid);
		list_add(&rc->list, &__remote_contexts_out());
		__unlock_remote_contexts_out(dst_nid);

		/* First migration from origin */
		{
			int cur_total_files_cnt = jack_traverse_thread_files(current, 1, 1);
			cur_total_files_cnt += 0; // fixing compilterwarning
			PSPRINTK("do_migrate: cur total file cnt %d\n", cur_total_files_cnt);
		}
		jack_do_file_migration(current);
	}
	/*
	 * tsk->remote != NULL implies this thread is distributed (migrated away).
	 */
	tsk->remote = get_task_remote(tsk);

	ret = __request_clone_remote(dst_nid, tsk, uregs);
	if (ret) return ret;

	__process_remote_works();
	return 0;
}



#ifdef CONFIG_POPCORN_HYPE
/***********
 * Hype
 */

/* Workitem: This has to be in user:
 * hypercall -> return to user with vm_exit=xxx
 *  (user) syscall pophype_migration_flag on
 *  (user) syscall flush_dsm (when should I do this) (search destroy rc)
 *  (user) syscall migration (rely on pophype_migration_flag to know it should do optimized migration)
 *  (user) syscall pophype_migration_flag off
 */
/* pophype migration request from guest VM */
/* only sync kernel data. user needs to perform migration */
static int __pophype_do_migrate(int dst_nid, int dst_vcpu)
{
    int ret = 0; /* good */

    PHMIGRATEPRINTK("[%d] <%d> %s(%d, %d): at \"%s\"\n",
            current->pid, smp_processor_id(), __func__,
			dst_nid, dst_vcpu,
            distributed_remote_process(current) ? "REMOTE" : "ORIGIN");

	popcorn_update_remote_vcpu(dst_nid, dst_vcpu);

    return ret; /* let userspace to do back_migration() */
}
#endif

/**
 * Migrate the specified task <task> to node <dst_nid>
 * Currently, this function will put the specified task to sleep,
 * and push its info over to the remote node.
 * The remote node will then create a new thread and import that
 * info into its new context.
 */
int process_server_do_migration(struct task_struct *tsk, unsigned int dst_nid, void __user *uregs)
{
	int ret = 0,a0;

	if (tsk->origin_nid == dst_nid) {
		ret = __do_back_migration(tsk, dst_nid, uregs);
#ifdef CONFIG_POPCORN_HYPE
	} else if (dst_nid >= MAX_POPCORN_VCPU
				&& dst_nid < 2 * MAX_POPCORN_VCPU) {
		PHMIGRATEPRINTK("syscall input dst_nid %d\n", dst_nid);
		BUG_ON(!my_nid);
		dst_nid -= MAX_POPCORN_VCPU; /* assumption: 1 vcpu on 1 node - restore */
		/* Node N -> Node 0 */
		__pophype_do_migrate(0, dst_nid);

		BUG_ON(dst_nid >= MAX_POPCORN_VCPU);
		ret = __do_back_migration(tsk, 0, uregs);
	} else if (dst_nid >= 2 * MAX_POPCORN_VCPU
				&& dst_nid < 3 * MAX_POPCORN_VCPU) {
		PHMIGRATEPRINTK("syscall input dst_nid %d\n", dst_nid);
		BUG_ON(my_nid);
		dst_nid -= MAX_POPCORN_VCPU * 2; /* assumption: 1 vcpu on 1 node - restore */
		__pophype_do_migrate(dst_nid, dst_nid);

		BUG_ON(dst_nid >= MAX_POPCORN_VCPU);
		ret = __do_migration(tsk, dst_nid, uregs);
		BUG_ON(ret);
	} else if (dst_nid >= 100 && dst_nid < 1000) {
		a0 = dst_nid / 100; // a0, target nid, 1,2,3 for example
		dst_nid -= a0 * 100;
		__pophype_do_migrate(a0, dst_nid);
		BUG_ON(dst_nid >= MAX_POPCORN_VCPU);
        ret = __do_migration(tsk, a0, uregs);
        BUG_ON(ret);

#endif
	} else {
		ret = __do_migration(tsk, dst_nid, uregs);
		if (ret) {
			tsk->remote = NULL;
			tsk->remote_pid = tsk->remote_nid = -1;
			put_task_remote(tsk);
		}
	}

	return ret;
}



/* Ask origin for tgid table
 * //Remote registers vcpu to original's list.
 * [remote] -> origin -fwd> remote
 */
static void popcorn_ask_remote_tgid(int nid, struct remote_context *rc)
{
	remote_ask_origin_tgid_request_t *req = kmalloc(sizeof(*req), GFP_KERNEL);
	struct wait_station *ws = get_wait_station(current);
	remote_ask_origin_tgid_response_t *res;
	//struct remote_context *rc = current->mm->remote;

	BUG_ON(!current->at_remote);
	BUG_ON(!rc || !req);
	req->from_pid = current->pid;
	req->ws = ws->id;

	BUG_ON(!rc->remote_tgids[0]);
	req->origin_pid = rc->remote_tgids[0];

	req->src_tgid = current->tgid;
	req->dst_nid = nid;

	POP_PK("pair: [%d/%d] src_pid %d => [%d/%d]\n",
			my_nid, current->pid, current->tgid, my_nid, req->origin_pid);
	pcn_kmsg_send(PCN_KMSG_TYPE_REMOTE_ASK_ORIGIN_TGID_REQUEST,
							POPCORN_HOST_NID, req, sizeof(*req));
	res = wait_at_station(ws);

	POP_PK("\t\tpair: [%d] install [%d/%d]\n", current->pid, nid, res->dst_tgid);
	rc->remote_tgids[nid] = res->dst_tgid;
	BUG_ON(res->dst_tgid < 0);

	kfree(req);
	pcn_kmsg_done(res);
}

#define FOWARD_PID 123456
/* remote -> origin [-fwd>] remote */
void send_tgid_to_remote_at_origin(int src_nid, int dst_nid, int remote_pid, int forward_src_tgid)
{
	origin_ask_remote_tgid_request_t *req =
			kmalloc(sizeof(*req), GFP_KERNEL);
	req->src_tgid = forward_src_tgid;
	req->remote_pid = remote_pid;
	req->src_nid= src_nid;
	req->from_pid = FOWARD_PID;
	pcn_kmsg_send(PCN_KMSG_TYPE_ORIGIN_ASK_REMOTE_TGID_REQUEST,
									dst_nid, req, sizeof(*req));
	kfree(req);
}

/* remote -> [origin] -fwd> remote */
static void process_remote_ask_origin_tgid_request(struct work_struct *work)
{
    START_KMSG_WORK(remote_ask_origin_tgid_request_t, req, work);
    remote_ask_origin_tgid_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req), dst_tgid = -1;
    struct task_struct *tsk = __get_task_struct(req->origin_pid);
	struct remote_context *rc;

    POP_PK("pair: [from%d/%d] => [origin%d] [[rr pair]] at origin\n",
						from_nid, req->from_pid, req->origin_pid);
    BUG_ON(!tsk && "No task exist");
    BUG_ON(tsk->at_remote);

	/* Get from original + forward to remote /
		redirect to another remote (NOT IMPLEMENTED) */
	/* Cache */
	rc = tsk->mm->remote;
	BUG_ON(!rc->remote_tgids[req->dst_nid]);
	BUG_ON(rc->remote_tgids[req->dst_nid] < 0);
	dst_tgid = rc->remote_tgids[req->dst_nid];

	/* Forward */
	{
		int forward_src_tgid = req->src_tgid;
		int dst_nid = req->dst_nid;
		int remote_pid = rc->remote_tgids[dst_nid];
		//int remote_pid = req->remote_pid;
		POP_PK("\t\t pair: fwd [from%d/%d] => [origin%d] [[rr pair]]\n",
							from_nid, req->from_pid, req->remote_pid);
		send_tgid_to_remote_at_origin(from_nid, dst_nid, remote_pid, forward_src_tgid);
	}
	/* Redirect (all) done */

	res->dst_tgid = dst_tgid;
    res->from_pid = req->from_pid;
    res->ws = req->ws;

    POP_PK("pair: [from%d/%d] => [origin%d] [[rr pair]] ret %d\n",
			from_nid, req->from_pid, req->origin_pid, dst_tgid);
    pcn_kmsg_post(PCN_KMSG_TYPE_REMOTE_ASK_ORIGIN_TGID_RESPONSE,
									from_nid, res, sizeof(*res));
    END_KMSG_WORK(req);
}

/* remote -> origin -fwd> [remote] */
static void process_origin_ask_remote_tgid_request(struct work_struct *work)
{
    START_KMSG_WORK(origin_ask_remote_tgid_request_t, req, work);
    struct task_struct *tsk = __get_task_struct(req->remote_pid);
	struct remote_context *rc;

    POP_PK("pair: [from(?->%d)/%d] => [remote%d] "
			"[[rr notice (not ask) pair]]\n",
			PCN_KMSG_FROM_NID(req), req->from_pid, req->remote_pid);
    BUG_ON(!tsk && "No task exist");
    BUG_ON(!tsk->at_remote);

	/* rr installs */
	rc = tsk->mm->remote;
	rc->remote_tgids[req->src_nid] = req->src_tgid;
    POP_PK("\t\tpair: [%d] install [%d/%d]\n",
				tsk->pid, req->src_nid, req->src_tgid);

	END_KMSG_WORK(req);
}

static int handle_remote_ask_origin_tgid_response(struct pcn_kmsg_message *msg)
{
	remote_ask_origin_tgid_response_t *res =
		(remote_ask_origin_tgid_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;

    complete(&ws->pendings);
    return 0;
}

DEFINE_KMSG_RW_HANDLER(origin_task_exit, origin_task_exit_t, remote_pid);
DEFINE_KMSG_RW_HANDLER(remote_task_exit, remote_task_exit_t, origin_pid);
DEFINE_KMSG_RW_HANDLER(back_migration, back_migration_request_t, origin_pid);
DEFINE_KMSG_RW_HANDLER(remote_futex_request, remote_futex_request, origin_pid);
DEFINE_KMSG_WQ_HANDLER(remote_ask_origin_tgid_request);
DEFINE_KMSG_WQ_HANDLER(origin_ask_remote_tgid_request);
/**
 * Initialize the process server.
 */
int __init process_server_init(void)
{
	INIT_LIST_HEAD(&remote_contexts[0]);
	INIT_LIST_HEAD(&remote_contexts[1]);

	spin_lock_init(&remote_contexts_lock[0]);
	spin_lock_init(&remote_contexts_lock[1]);

	/* Register handlers */
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_TASK_MIGRATE, clone_request);
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_TASK_MIGRATE_BACK, back_migration);
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_TASK_PAIRING, remote_task_pairing);

	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_TASK_EXIT_REMOTE, remote_task_exit);
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_TASK_EXIT_ORIGIN, origin_task_exit);

	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_FUTEX_REQUEST, remote_futex_request);
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_FUTEX_RESPONSE, remote_futex_response);

	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_REMOTE_ASK_ORIGIN_TGID_REQUEST,
										remote_ask_origin_tgid_request);
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_ORIGIN_ASK_REMOTE_TGID_REQUEST,
										origin_ask_remote_tgid_request);
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_REMOTE_ASK_ORIGIN_TGID_RESPONSE,
										remote_ask_origin_tgid_response);


	return 0;
}
