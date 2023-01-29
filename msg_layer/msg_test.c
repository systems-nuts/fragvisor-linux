/*
 * Copyright (C) 2017-2018
 *
 *  Ho-Ren (Jack) Chuang <horenc@vt.edu>
 *  Sang-Hoon Kim <sanghoon@vt.edu>
 */

#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "../../kernel/popcorn/types.h"
#include "common.h"

#define MAX_THREADS 288


#define DEFAULT_PAYLOAD_SIZE_KB	4
#define DEFAULT_NR_ITERATIONS 1

static int cnt = 0; /* 4's remote info */
#define REMOTE_HANDLE_WRITE_TIME 0
#define LOCAL_RR_PAGE_TIME 0


enum TEST_REQUEST_FLAG {
	TEST_REQUEST_FLAG_REPLY = 0,
	TEST_REQUEST_FLAG_RDMA_WRITE = 1,
};

#define TEST_REQUEST_FIELDS \
	unsigned long flags; \
	unsigned long done; \
	char msg[PCN_KMSG_MAX_PAYLOAD_SIZE -  \
		sizeof(unsigned long) * 2 \
	];
DEFINE_PCN_KMSG(test_request_t, TEST_REQUEST_FIELDS);

#define TEST_RDMA_REQUEST_FIELDS \
	dma_addr_t rdma_addr; \
	u32 rdma_key; \
	size_t size; \
	unsigned long done; \
	unsigned long flags;
DEFINE_PCN_KMSG(test_rdma_request_t, TEST_RDMA_REQUEST_FIELDS);

#define TEST_RDMA_DSMRR_REQUEST_FIELDS \
	dma_addr_t rdma_addr; \
	u32 rdma_key; \
	size_t size; \
	int id; \
	unsigned long done; \
	unsigned long flags;
DEFINE_PCN_KMSG(test_dsmrr_request_t, TEST_RDMA_DSMRR_REQUEST_FIELDS);

#define TEST_RESPONSE_FIELDS \
	unsigned long done;
DEFINE_PCN_KMSG(test_response_t, TEST_RESPONSE_FIELDS);

#define TEST_PAGE_RESPONSE_FIELDS \
	unsigned long done; \
	int id;
DEFINE_PCN_KMSG(test_page_response_t, TEST_PAGE_RESPONSE_FIELDS);

enum test_action {
	TEST_ACTION_SEND = 0,
	TEST_ACTION_POST,
	TEST_ACTION_RDMA_WRITE,
	TEST_ACTION_RDMA_READ,
	TEST_ACTION_DSM_RR,
	TEST_ACTION_CLEAR = 9,
	TEST_ACTION_MAX,
};

struct test_params {
	int tid;
	enum test_action action;

	unsigned int nr_threads;
	unsigned long nr_iterations;
	size_t payload_size;

	struct test_barrier *barrier;
	void *private;
};


/**
 * Barrier to synchronize test threads
 */
struct test_barrier {
	spinlock_t lock;
	atomic_t count;
	unsigned int _count;
	wait_queue_head_t waiters;
};

static inline void __barrier_init(struct test_barrier *barrier, unsigned int nr)
{
	spin_lock_init(&barrier->lock);
	atomic_set(&barrier->count, nr);
	barrier->_count = nr;
	init_waitqueue_head(&barrier->waiters);
}

static inline void __barrier_wait(struct test_barrier *barrier)
{
	unsigned long flags;
	DEFINE_WAIT(wait);

	spin_lock_irqsave(&barrier->lock, flags);
	if (atomic_dec_and_test(&barrier->count)) {
		atomic_set(&barrier->count, barrier->_count);
		spin_unlock_irqrestore(&barrier->lock, flags);
		wake_up_all(&barrier->waiters);
	} else {
		prepare_to_wait(&barrier->waiters, &wait, TASK_INTERRUPTIBLE);
		spin_unlock_irqrestore(&barrier->lock, flags);

		schedule();
		finish_wait(&barrier->waiters, &wait);
	}
}

/**
 * Fundamental performance tests
 */
char per_t_buf[MAX_THREADS][PCN_KMSG_MAX_SIZE];
static int test_send(void *arg)
{
	struct test_params *param = arg;
	DECLARE_COMPLETION_ONSTACK(done);
	test_request_t *req = (void *)per_t_buf[param->tid];
	int i;
	size_t msg_size = PCN_KMSG_SIZE(param->payload_size);

	printk("pid: %d\n", current->pid);

	__barrier_wait(param->barrier);
	for (i = 0; i < param->nr_iterations; i++) {
		req->flags = 1;
		req->done = (unsigned long)&done;
		*(unsigned long *)req->msg = 0xcafe00dead00beef;

		pcn_kmsg_send(PCN_KMSG_TYPE_TEST_REQUEST, !my_nid, req, msg_size);

		wait_for_completion(&done);
	}
	__barrier_wait(param->barrier);
	return 0;
}

static int test_post(void *arg)
{
	struct test_params *param = arg;
	DECLARE_COMPLETION_ONSTACK(done);
	test_request_t *req;
	int i;

	__barrier_wait(param->barrier);
	for (i = 0; i < param->nr_iterations; i++) {
		req = pcn_kmsg_get(PCN_KMSG_SIZE(param->payload_size));

		req->flags = 1;
		req->done = (unsigned long)&done;
		*(unsigned long *)req->msg = 0xcafe00dead00beef;

		pcn_kmsg_post(PCN_KMSG_TYPE_TEST_REQUEST,
				!my_nid, req, PCN_KMSG_SIZE(param->payload_size));

		wait_for_completion(&done);
	}
	__barrier_wait(param->barrier);
	return 0;
}

static void process_test_send_request(struct work_struct *work)
{
	START_KMSG_WORK(test_request_t, req, work);
	if (test_bit(TEST_REQUEST_FLAG_REPLY, &req->flags)) {
		test_response_t *res = pcn_kmsg_get(sizeof(*res));
		res->done = req->done;

		pcn_kmsg_post(PCN_KMSG_TYPE_TEST_RESPONSE,
				PCN_KMSG_FROM_NID(req), res, sizeof(*res));
	}
	END_KMSG_WORK(req);
}

static int handle_test_send_response(struct pcn_kmsg_message *msg)
{
	test_response_t *res = (test_response_t *)msg;
	if (res->done) {
		complete((struct completion *)res->done);
	}

	pcn_kmsg_done(res);
	return 0;
}


/**
 * Test RDMA features
 */
static int test_rdma_write(void *arg)
{
	struct test_params *param = arg;
	int i;

	__barrier_wait(param->barrier);
	for (i = 0; i < param->nr_iterations; i++) {
		DECLARE_COMPLETION_ONSTACK(done);
		struct pcn_kmsg_rdma_handle *rh =
				pcn_kmsg_pin_rdma_buffer(NULL, PAGE_SIZE);
		test_rdma_request_t req = {
			.rdma_addr = rh->dma_addr,
			.rdma_key = rh->rkey,
			.size = param->payload_size,
			.done = (unsigned long)&done,
		};

		*(unsigned long *)rh->addr = 0xcafecaf00eadcafe;

		pcn_kmsg_send(PCN_KMSG_TYPE_TEST_RDMA_REQUEST,
				!my_nid, &req, sizeof(req));
		wait_for_completion(&done);

		pcn_kmsg_unpin_rdma_buffer(rh);
	}
	__barrier_wait(param->barrier);
	return 0;
}

static int test_rdma_read(void *arg)
{
	struct test_params *param = arg;

	__barrier_wait(param->barrier);
	__barrier_wait(param->barrier);
	return 0;
}

static int test_rdma_dsm_rr(void *arg)
{
	int i, my_id;
	struct test_params *param = arg;

#if LOCAL_RR_PAGE_TIME
	/* Workitem per t */
	ktime_t dt1, t1e, t1s;
	ktime_t t2e, t2s;
	ktime_t t3e, t3s;
	ktime_t t4e, t4s;
	ktime_t t5e, t5s;
	long long t2 = 0, t3 = 0, t4 = 0, t5 = 0;
#endif

	/* write */
	DECLARE_COMPLETION_ONSTACK(done);
	test_dsmrr_request_t *req;
	struct pcn_kmsg_rdma_handle *rh;

	/* Warm up */
	req = pcn_kmsg_get(sizeof(*req));
	rh = pcn_kmsg_pin_rdma_buffer(NULL, PAGE_SIZE); /* max write size */
	BUG_ON(!rh || !req);
	req->rdma_addr = rh->dma_addr;
	req->id = param->tid;
	req->rdma_key = rh->rkey;
	req->size = param->payload_size;
	req->done = (unsigned long)&done;
	*(unsigned long *)rh->addr = 0xcafecaf00eadcafe;
	pcn_kmsg_post(PCN_KMSG_TYPE_TEST_RDMA_DSMRR_REQUEST,
							!my_nid, req, sizeof(*req));
	wait_for_completion(&done);
	pcn_kmsg_unpin_rdma_buffer(rh);

	__barrier_wait(param->barrier);
#if LOCAL_RR_PAGE_TIME
	t1s = ktime_get();
#endif
	for (i = 0; i < param->nr_iterations; i++) {
#if LOCAL_RR_PAGE_TIME
		t2s = ktime_get();
#endif
		req = pcn_kmsg_get(sizeof(*req));
		rh = pcn_kmsg_pin_rdma_buffer(NULL, PAGE_SIZE);
		req->rdma_addr = rh->dma_addr;
		req->rdma_key = rh->rkey;
		req->size = param->payload_size;
		req->done = (unsigned long)&done;
		req->id = my_id;
#if LOCAL_RR_PAGE_TIME
		t2e = ktime_get();
		t2 += ktime_to_ns(ktime_sub(t2e, t2s));
#endif

#if LOCAL_RR_PAGE_TIME
		t3s = ktime_get();
#endif
		pcn_kmsg_post(PCN_KMSG_TYPE_TEST_RDMA_DSMRR_REQUEST,
								!my_nid, req, sizeof(*req));
#if LOCAL_RR_PAGE_TIME
		t3e = ktime_get();
		t3 += ktime_to_ns(ktime_sub(t3e, t3s));
#endif

#if LOCAL_RR_PAGE_TIME
		t4s = ktime_get();
#endif
		wait_for_completion(&done);
#if LOCAL_RR_PAGE_TIME
		t4e = ktime_get();
		t4 += ktime_to_ns(ktime_sub(t4e, t4s));
#endif

#if LOCAL_RR_PAGE_TIME
		t5s = ktime_get();
#endif
		pcn_kmsg_unpin_rdma_buffer(rh);
#if LOCAL_RR_PAGE_TIME
		t5e = ktime_get();
		t5 += ktime_to_ns(ktime_sub(t5e, t5s));
#endif
	}
#if LOCAL_RR_PAGE_TIME
	t1e = ktime_get();
	dt1 = ktime_sub(t1e, t1s);
	/* Workitem per t */
	printk("%s(): dsm rr lat done %lld ns %lld us!!!\n",
					__func__, ktime_to_ns(dt1) / param->nr_iterations,
					ktime_to_ns(dt1) / param->nr_iterations / 1000);
	printk("t2 %lld ns %lld us!!!\n",
					t2 / param->nr_iterations,
					t2 / param->nr_iterations / 1000);
	printk("t3 %lld ns %lld us!!!\n",
					t3 / param->nr_iterations,
					t3 / param->nr_iterations / 1000);
	printk("t4 %lld ns %lld us!!!\n",
					t4 / param->nr_iterations,
					t4 / param->nr_iterations / 1000);
	printk("t5 %lld ns %lld us!!!\n",
					t5 / param->nr_iterations,
					t5 / param->nr_iterations / 1000);


	printk("\n\n");
#endif

	__barrier_wait(param->barrier);
	return 0;
}

static int test_clear_all(void *arg)
{
	cnt = 0;
	return 0;
}

void *_buffer[MAX_POPCORN_THREADS] = {NULL}; /* For RDMA write */
/* For remote handling time */
#define ITER 1000001
#define ONE_M 1000000
static void process_test_dsmrr_request(struct work_struct *work)
{
	int ret;
	START_KMSG_WORK(test_dsmrr_request_t, req, work);
	test_page_response_t *res;
#if REMOTE_HANDLE_WRITE_TIME
	ktime_t t2e, t2s;
	ktime_t t3e, t3s;
	ktime_t t4e, t4s;
	ktime_t t5e, t5s;
	static long long t2 = 0, t3 = 0, t4 = 0, t5 = 0;
#endif

#if REMOTE_HANDLE_WRITE_TIME
	t2s = ktime_get();
#endif
	res = pcn_kmsg_get(sizeof(*res));
	res->done = req->done;
	res->id = req->id;
#if REMOTE_HANDLE_WRITE_TIME
	t2e = ktime_get();
#endif

#if REMOTE_HANDLE_WRITE_TIME
	t3s = ktime_get();
#endif
	ret = pcn_kmsg_rdma_write(PCN_KMSG_FROM_NID(req),
			req->rdma_addr, _buffer[req->id], req->size, req->rdma_key);
#if REMOTE_HANDLE_WRITE_TIME
	t3e = ktime_get();
#endif

#if REMOTE_HANDLE_WRITE_TIME
	t4s = ktime_get();
#endif
	pcn_kmsg_post(PCN_KMSG_TYPE_TEST_RDMA_DSMRR_RESPONSE,
					PCN_KMSG_FROM_NID(req), res, sizeof(*res));
#if REMOTE_HANDLE_WRITE_TIME
	t4e = ktime_get();
#endif

#if REMOTE_HANDLE_WRITE_TIME
	t5s = ktime_get();
#endif
	END_KMSG_WORK(req);
#if REMOTE_HANDLE_WRITE_TIME
	t5e = ktime_get();
#endif

#if REMOTE_HANDLE_WRITE_TIME
	t2 += ktime_to_ns(ktime_sub(t2e, t2s));
	t3 += ktime_to_ns(ktime_sub(t3e, t3s));
	t4 += ktime_to_ns(ktime_sub(t4e, t4s));
	t5 += ktime_to_ns(ktime_sub(t5e, t5s));

	cnt++;
	if (cnt <= 1) {
		t2 = 0, t3 = 0, t4 = 0, t5 = 0;
	}

	if (cnt >= ITER) {
        printk("%s(): t2 %lld ns %lld us!!!\n",
                        __func__,
                        t2 / ONE_M,
                        t2 / ONE_M / 1000);
        printk("%s(): t3 %lld ns %lld us!!!\n",
                        __func__,
                        t3 / ONE_M,
                        t3 / ONE_M / 1000);
        printk("%s(): t4 %lld ns %lld us!!!\n",
                        __func__,
                        t4 / ONE_M,
                        t4 / ONE_M / 1000);
        printk("%s(): t5 %lld ns %lld us!!!\n",
                        __func__,
                        t5 / ONE_M,
                        t5 / ONE_M / 1000);
	}
#endif
}

static int handle_test_dsmrr_response(struct pcn_kmsg_message *msg)
{
	test_page_response_t *res = (test_page_response_t *)msg;
	if (res->done) {
		complete((struct completion *)res->done);
	}
	pcn_kmsg_done(res);
	return 0;
}

static void process_test_rdma_request(struct work_struct *work)
{
	START_KMSG_WORK(test_rdma_request_t, req, work);
	void *buffer = (void *)__get_free_page(GFP_KERNEL);
	test_response_t *res = kmalloc(sizeof(*res), GFP_KERNEL);
	int ret;

	if (req->flags & TEST_REQUEST_FLAG_RDMA_WRITE) {
		*(unsigned long *)buffer = 0xbaffdeafbeefface;

		ret = pcn_kmsg_rdma_write(PCN_KMSG_FROM_NID(req),
				req->rdma_addr, buffer, req->size, req->rdma_key);
	} else {
		ret = pcn_kmsg_rdma_read(PCN_KMSG_FROM_NID(req),
				buffer, req->rdma_addr, req->size, req->rdma_key);
	}
	res->done = req->done;
	pcn_kmsg_send(PCN_KMSG_TYPE_TEST_RESPONSE,
				PCN_KMSG_FROM_NID(req), res, sizeof(*res));

	free_page((unsigned long)buffer);
	END_KMSG_WORK(req);
}

/**
 * Run tests!
 */
struct test_desc {
	int (*test_fn)(void *);
	char *description;
};

static struct test_desc tests[] = {
	[TEST_ACTION_SEND]			= { test_send, "synchronous send"  },
	[TEST_ACTION_POST]			= { test_post, "synchronous post" },
	[TEST_ACTION_RDMA_WRITE]	= { test_rdma_write, "RDMA write" },
	[TEST_ACTION_RDMA_READ]		= { test_rdma_read, "RDMA read" },
	[TEST_ACTION_DSM_RR]		= { test_rdma_dsm_rr, "RDMA RR" }, /* 4 */
	[TEST_ACTION_CLEAR]			= { test_clear_all, "CLEAR ALL" }, /* 9 */
};

static void __run_test(enum test_action action, struct test_params *param)
{
	/* Stack frame over 4k */
	struct test_params *thread_params; /* test_params thread_params[MAX_THREADS] */
	struct task_struct **tsks; /* task_struct *tsks[MAX_THREADS] */
	struct test_barrier barrier;
	ktime_t t_start, t_end;
	DECLARE_COMPLETION_ONSTACK(done);
	unsigned long elapsed;
	int i;

	thread_params = kzalloc(sizeof(*thread_params) * MAX_THREADS, GFP_KERNEL);
	tsks = kzalloc(sizeof(struct task_struct*) * MAX_THREADS, GFP_KERNEL);
	printk("%s: %d %lu %u %lu\n",
			tests[action].description, action,
			param->payload_size,
			param->nr_threads,
			param->nr_iterations);

	__barrier_init(&barrier, param->nr_threads + 1);
	param->barrier = &barrier;

	for (i = 0; i < param->nr_threads; i++) {
		struct test_params *thr_param = thread_params + i;

		*thr_param = *param;
		thr_param->tid = i;

		tsks[i] = kthread_run(tests[action].test_fn, thr_param, "test_%d", i);
	}

	__barrier_wait(&barrier);
	t_start = ktime_get();
	/* run the test */
	__barrier_wait(&barrier);
	t_end = ktime_get();

	kfree(thread_params);
	kfree(tsks);

	elapsed = ktime_to_ns(ktime_sub(t_end, t_start));

	printk("  %9lu ns in total\n", elapsed);
	printk("lat: %3lu.%05lu us per operation\n",
		elapsed / param->nr_iterations / 1000,
		((elapsed % param->nr_iterations) * 1000 * 1000) /
									(param->nr_iterations));

	printk("tps: %lu MB/s\n",
			((param->nr_iterations * param->payload_size * param->nr_threads)
									* (1000 * 1000) /
											(elapsed / 1000)) // 1/ns * 1000 => 1/us (GB)
													/ 1000 / 1000);
}


static int __parse_cmd(const char __user *buffer, size_t count, struct test_params *params)
{
	int args;
	int action;
	char *cmd;
	unsigned long payload_size, iter, nr_threads;

	cmd = kmalloc(count, GFP_KERNEL);
	if (!cmd) {
		printk(KERN_ERR "kmalloc failure\n");
		return -ENOMEM;
	}
	if (copy_from_user(cmd, buffer, count)) {
		kfree(cmd);
		return -EFAULT;
	}

	args = sscanf(cmd, "%d %lu %lu %lu",
			&action, &payload_size, &nr_threads, &iter);
	if (args <= 0) {
		printk(KERN_ERR "Wrong command\n");
		kfree(cmd);
		return -EINVAL;
	}

	params->action = action;

	if (args >= 2) {
		if (payload_size < sizeof(unsigned long) * 2) {
			printk(KERN_ERR "Payload should be larger than %ld\n",
					sizeof(unsigned long) * 2);
			kfree(cmd);
			return -EINVAL;
		}
		if (payload_size > PCN_KMSG_MAX_SIZE) {
			printk(KERN_ERR "Payload should be less than %lu KB\n",
					PCN_KMSG_MAX_SIZE >> 10);
			kfree(cmd);
			return -EINVAL;
		}
		params->payload_size = payload_size;
	}
	if (args >= 3) {
		if (nr_threads > MAX_THREADS) {
			printk(KERN_ERR "# of threads cannot be larger than %d\n",
					MAX_THREADS);
			params->payload_size = 24;
			kfree(cmd);
			//return -EINVAL;
			return 0;
		}
		params->nr_threads = nr_threads;
	}
	if (args >= 4)
		params->nr_iterations = iter;

	kfree(cmd);
	return 0;
}

static ssize_t start_test(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	int ret;
	int action;
	struct test_params params = {
		.payload_size = DEFAULT_PAYLOAD_SIZE_KB << 10,
		.nr_threads = 1,
		.nr_iterations = DEFAULT_NR_ITERATIONS,
	};

	if ((ret = __parse_cmd(buffer, count, &params))) {
		return ret;
	}
	action = params.action;

	if (!try_module_get(THIS_MODULE))
		return -EPERM;

	if (params.nr_threads > MAX_THREADS) {
		printk("action %d thread exceed %d threads.\n", action, MAX_THREADS);
		return 0; /* For simplifying script */
	}

	/* do the coresponding work */
	switch(action) {
	case TEST_ACTION_SEND:
	case TEST_ACTION_POST:
		__run_test(action, &params);
		break;
	case TEST_ACTION_RDMA_WRITE:
	case TEST_ACTION_RDMA_READ:
	case TEST_ACTION_DSM_RR:
		if (pcn_kmsg_has_features(PCN_KMSG_FEATURE_RDMA)) {
			if (params.payload_size == PAGE_SIZE)
				__run_test(action, &params);
			else
				printk("action %d only support page size %lu.\n",
												action, PAGE_SIZE);
		} else {
			printk(KERN_ERR "Transport does not support RDMA.\n");
		}
		break;
	case TEST_ACTION_CLEAR:
		test_clear_all(NULL);
		break;
	default:
		printk("Unknown test no #%d\n", action);
	}

	module_put(THIS_MODULE);
	return count;
}

static void __show_usage(void)
{
	int i;
	printk(" Usage: echo [action] {payload size in byte} {# of threads} \\\n");
	printk("                      {# of iterations} > /proc/msg_test\n");
	printk(" Default: %d KB payload, iterate %d time%s, single thread\n",
			DEFAULT_PAYLOAD_SIZE_KB,
			DEFAULT_NR_ITERATIONS, DEFAULT_NR_ITERATIONS == 1 ? "" : "s");
	printk("echo 0 4096 16 50000 > /proc/msg_test\n");
	printk("echo 0 24 1 50000 > /proc/msg_test\n");
	printk("echo 0 65536 16 50000 > /proc/msg_test\n");
	printk(" Tests:\n");
	for (i = 0; i < TEST_ACTION_MAX; i++) {
		if (!tests[i].test_fn) continue;
		printk("  %d: %s\n", i, tests[i].description);
	}
	printk("\n");
}

static int kmsg_test_read_proc(struct seq_file *seq, void *v)
{
	return 0;
}

static int kmsg_test_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, kmsg_test_read_proc, inode->i_private);
}

static struct file_operations kmsg_test_ops = {
	.owner = THIS_MODULE,
	.open = kmsg_test_read_open,
	.llseek  = seq_lseek,
	.release = single_release,
	.write = start_test,
};


DEFINE_KMSG_WQ_HANDLER(test_send_request);
DEFINE_KMSG_WQ_HANDLER(test_rdma_request);
DEFINE_KMSG_WQ_HANDLER(test_dsmrr_request);

static struct proc_dir_entry *kmsg_test_proc = NULL;

static int __init msg_test_init(void)
{
	int i;
	printk("\nLoading Popcorn messaging layer tester...\n");

	for (i = 0; i < MAX_POPCORN_THREADS; i++) {
		_buffer[i] = (void *)__get_free_page(GFP_KERNEL); // move to global
		BUG_ON(!_buffer[i]);
	}

#ifdef CONFIG_POPCORN_STAT
	printk(KERN_WARNING " * You are collecting statistics "
			"and may get inaccurate performance data now *\n");
#endif

	/* register a proc fs entry */
	kmsg_test_proc = proc_create("msg_test", 0666, NULL, &kmsg_test_ops);
	if (!kmsg_test_proc) {
		printk(KERN_ERR " Cannot create /proc/msg_test\n");
		return -EPERM;
	}

	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_TEST_REQUEST, test_send_request);
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_TEST_RESPONSE, test_send_response);
	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_TEST_RDMA_REQUEST, test_rdma_request);
	REGISTER_KMSG_WQ_HANDLER(PCN_KMSG_TYPE_TEST_RDMA_DSMRR_REQUEST,
												test_dsmrr_request);
	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_TEST_RDMA_DSMRR_RESPONSE,
												test_dsmrr_response);

	__show_usage();
	return 0;
}

static void __exit msg_test_exit(void)
{
	int i;
	if (kmsg_test_proc) proc_remove(kmsg_test_proc);

	for (i = 0;i < MAX_POPCORN_THREADS; i++)
		free_page((unsigned long)_buffer[i]);

	printk("Unloaded Popcorn messaging layer tester. Good bye!\n");
}

module_init(msg_test_init);
module_exit(msg_test_exit);
MODULE_LICENSE("GPL");
