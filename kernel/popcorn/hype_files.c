/*
 * hype_files.c
 * Copyright (C) 2019 Ho-Ren (Jack) Chuang <horenc@vt.edu>
 *
 * Distributed under terms of the MIT license.
 */

#include <popcorn/hype_files.h>



/******************************************************************************
 * File operations -
 * 		origin: origin has opened
 * 		remote: skipped open
 */
int popcorn_open(const char __user *filename, int flags, umode_t mode, int fd)
{
	if (!current->at_remote) { // origin - broadcast
		printk("TODO: implement\n");
		BUG();
	} else { // remote - delegation and reply
		remote_open_request_t *req = kmalloc(sizeof(*req), GFP_KERNEL);
		struct wait_station *ws = get_wait_station(current);
		remote_open_response_t *res;
		struct remote_context *rc = current->mm->remote;
		BUG_ON(!rc);

		// wait ws
		BUG_ON(!req);
		req->from_pid = current->pid;
		req->origin_pid = rc->remote_tgids[0];
		req->ws = ws->id;
		req->flags = flags;
		req->mode = mode;
		fd = -1;
		req->fd = fd;

        if (copy_from_user(req->filename, filename, MAX_PCN_NAME_LEN) != 0)
			return -EFAULT;
		//memcpy(req->filename, filename, MAX_PCN_NAME_LEN - 1);
		printk("[%d] #working# [[open]]- delegating to origin "
								"\"%s\" flags %d mode %d fd %d\n",
								current->pid, req->filename, flags, mode, fd);

        pcn_kmsg_send(PCN_KMSG_TYPE_REMOTE_OPEN_REQUEST,
									0, req, sizeof(*req));
		res = wait_at_station(ws);
		BUG_ON(res->ret);

		// mapping using
		printk("working open - replaying and matching "
						"fd %d with struct file* at remote\n", res->fd);
		// do open
		// but use res->fd; to map with file_struct

		kfree(req);
		pcn_kmsg_done(res);
	}
	return 0;
}


/******************************************************************************
 * MSG handlers -
 * 		open
 *
 *
 */
// from remote
static void process_remote_open_request(struct work_struct *work)
{
    START_KMSG_WORK(remote_open_request_t, req, work);
    remote_open_response_t *res = pcn_kmsg_get(sizeof(*res));
    int from_nid = PCN_KMSG_FROM_NID(req);
    struct task_struct *tsk = __get_task_struct(req->origin_pid);
//    struct mm_struct *mm;
	int dfd = AT_FDCWD;
	int flags = req->flags; //
	int mode = req->mode; //
	int fd = req->fd; //
	char *filename = req->filename; //

	printk("[from%d/origin%d]#working# [[open]] at origin \"%s\" "
								"flags %d mode %d fd %d\n",
						req->from_pid, req->origin_pid, filename, flags, mode, fd);

	BUG_ON(!tsk);
	BUG_ON(!tsk && "No task exist");
	BUG_ON(tsk->at_remote);

	printk("[from%d/origin%d]#working# [[open]] at origin "
							"\"%s\" flags %d mode %d fd %d\n",
						req->from_pid, tsk->pid, filename, flags, mode, fd);

	// do_sys_open()
    res->fd = do_sys_open_tsk_req_at_origin(tsk, dfd, filename, flags, mode); // TODO still using lots ""current""

    res->from_pid = req->from_pid;
	res->ws = req->ws;
    //res->ret = ret;

    pcn_kmsg_post(PCN_KMSG_TYPE_REMOTE_OPEN_RESPONSE,
							from_nid, res, sizeof(*res));
	printk("#working# [[open]] at origin DONE fd %d \"%s\" ->\n", res->fd, filename);
    END_KMSG_WORK(req);
}

static int handle_remote_open_response(struct pcn_kmsg_message *msg)
{
    remote_open_response_t *res = (remote_open_response_t *)msg;
    struct wait_station *ws = wait_station(res->ws);

    ws->private = res;

	complete(&ws->pendings);
    return 0;
}
#if 0
// just wakeup example, not passing res back to the wait_station()
static int handle_remote_page_flush_ack(struct pcn_kmsg_message *msg)
{
    remote_page_flush_ack_t *req = (remote_page_flush_ack_t *)msg;
    struct wait_station *ws = wait_station(req->remote_ws);

    complete(&ws->pendings);

    pcn_kmsg_done(req);
    return 0;
}
#endif



/******************************************************************************
 *
 *
 */
DEFINE_KMSG_WQ_HANDLER(remote_open_request);
int __init popcorn_hype_files_init(void)
{
	// reg
    REGISTER_KMSG_WQ_HANDLER(
            PCN_KMSG_TYPE_REMOTE_OPEN_REQUEST, remote_open_request);
    REGISTER_KMSG_HANDLER(
            PCN_KMSG_TYPE_REMOTE_OPEN_RESPONSE, remote_open_response);
	return 0;
}

#if 0
int vma_server_munmap_origin(unsigned long start, size_t len, int nid_except)
{
    int nid;
    vma_op_request_t *req = __alloc_vma_op_request(VMA_OP_MUNMAP);
    struct remote_context *rc = get_task_remote(current);

    req->start = start;
    req->len = len;

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
#endif
