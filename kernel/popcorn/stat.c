#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>

#include <popcorn/pcn_kmsg.h>
#include <popcorn/stat.h>

static unsigned long long sent_stats[PCN_KMSG_TYPE_MAX] = {0};
static unsigned long long recv_stats[PCN_KMSG_TYPE_MAX] = {0};

static DEFINE_PER_CPU(unsigned long long, bytes_sent) = 0;
static DEFINE_PER_CPU(unsigned long long, bytes_recv) = 0;
static DEFINE_PER_CPU(unsigned long long, bytes_rdma_written) = 0;
static DEFINE_PER_CPU(unsigned long long, bytes_rdma_read) = 0;

static unsigned long long last_bytes_sent = 0;
static unsigned long long last_bytes_recv = 0;
static unsigned long long last_bytes_rdma_written = 0;
static unsigned long long last_bytes_rdma_read = 0;
static struct timeval last_stat = {};

const char *pcn_kmsg_type_name[PCN_KMSG_TYPE_MAX] = {
	[PCN_KMSG_TYPE_TASK_MIGRATE] = "migration",
	[PCN_KMSG_TYPE_VMA_INFO_REQUEST] = "VMA info",
	[PCN_KMSG_TYPE_VMA_OP_REQUEST] = "VMA op",
	[PCN_KMSG_TYPE_REMOTE_PAGE_REQUEST] = "remote page",
	[PCN_KMSG_TYPE_REMOTE_PAGE_RESPONSE] = "w/ page",
	[PCN_KMSG_TYPE_REMOTE_PAGE_RESPONSE_SHORT] = "w/o page",
	[PCN_KMSG_TYPE_PAGE_INVALIDATE_REQUEST] = "invalidate",
	[PCN_KMSG_TYPE_FUTEX_REQUEST] = "futex",
};

void account_pcn_message_sent(struct pcn_kmsg_message *msg)
{
	struct pcn_kmsg_hdr *h = (struct pcn_kmsg_hdr *)msg;
	this_cpu_add(bytes_sent, h->size);
#ifdef CONFIG_POPCORN_STAT
	sent_stats[h->type]++;
#endif
}

void account_pcn_message_recv(struct pcn_kmsg_message *msg)
{
	struct pcn_kmsg_hdr *h = (struct pcn_kmsg_hdr *)msg;
	this_cpu_add(bytes_recv, h->size);
#ifdef CONFIG_POPCORN_STAT
	recv_stats[h->type]++;
#endif
}

void account_pcn_rdma_write(size_t size)
{
	this_cpu_add(bytes_rdma_written, size);
}

void account_pcn_rdma_read(size_t size)
{
	this_cpu_add(bytes_rdma_read, size);
}

void fh_action_stat(struct seq_file *seq, void *);
extern void pf_time_stat(struct seq_file *seq, void *v);
extern void pophype_stat(struct seq_file *seq, void *v);
extern void dsm_traffic_stat(struct seq_file *seq, void *v);
extern void pophype_net_gup(struct seq_file *seq, void *v);

static int __show_stats(struct seq_file *seq, void *v)
{
	int i;
	unsigned long long sent = 0;
	unsigned long long recv = 0;
	struct timeval now;
	unsigned long long rate_sent, rate_recv;
	unsigned long elapsed;

	do_gettimeofday(&now);
	elapsed = (now.tv_sec * 1000000 + now.tv_usec) -
			(last_stat.tv_sec * 1000000 + last_stat.tv_usec);
	last_stat = now;

	for_each_present_cpu(i) {
		sent += per_cpu(bytes_sent, i);
		recv += per_cpu(bytes_recv, i);
	}
	seq_printf(seq, POPCORN_STAT_FMT, sent, recv, "Total network I/O");

	rate_sent = (sent - last_bytes_sent);
	rate_recv = (recv - last_bytes_recv);
	seq_printf(seq, POPCORN_STAT_FMT2,
			rate_sent / elapsed, (rate_sent % elapsed) * 1000 / elapsed,
			rate_recv / elapsed, (rate_recv % elapsed) * 1000 / elapsed,
			"MB/s");
	last_bytes_sent = sent;
	last_bytes_recv = recv;

	if (pcn_kmsg_has_features(PCN_KMSG_FEATURE_RDMA) && elapsed) {
		recv = sent = 0;
		for_each_present_cpu(i) {
			sent += per_cpu(bytes_rdma_written, i);
			recv += per_cpu(bytes_rdma_read, i);
		}
		seq_printf(seq, POPCORN_STAT_FMT, sent, recv, "RDMA");

		rate_sent = (sent - last_bytes_rdma_written);
		rate_recv = (recv - last_bytes_rdma_read);
		seq_printf(seq, POPCORN_STAT_FMT2,
				rate_sent / elapsed, (rate_sent % elapsed) * 1000 / elapsed,
				rate_recv / elapsed, (rate_recv % elapsed) * 1000 / elapsed,
				"MB/s");
		last_bytes_rdma_written = sent;
		last_bytes_rdma_read = recv;
	}

	pcn_kmsg_stat(seq, NULL);

#ifdef CONFIG_POPCORN_STAT
	seq_printf(seq, "-----------------------------------------------\n");
	//for (i = PCN_KMSG_TYPE_STAT_START + 1; i < PCN_KMSG_TYPE_STAT_END; i++) {
	for (i = PCN_KMSG_TYPE_REMOTE_PAGE_REQUEST; i < PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH; i++) {
		seq_printf(seq, POPCORN_STAT_FMT,
				sent_stats[i], recv_stats[i], pcn_kmsg_type_name[i] ? : "");
	}
	seq_printf(seq, "---------------------------------------------------------------------------\n");

	//fh_action_stat(seq, v);
	pf_time_stat(seq, v);
#endif
	return 0;
}

static ssize_t __write_stats(struct file *file, const char __user *buffer, size_t size, loff_t *offset)
{
	int i;
	for_each_present_cpu(i) {
		per_cpu(bytes_sent, i) = 0;
		per_cpu(bytes_recv, i) = 0;
		per_cpu(bytes_rdma_written, i) = 0;
		per_cpu(bytes_rdma_read, i) = 0;
	}
	pcn_kmsg_stat(NULL, NULL);

	for (i = 0 ; i < PCN_KMSG_TYPE_MAX; i++) {
		sent_stats[i] = 0;
		recv_stats[i] = 0;
	}
	fh_action_stat(NULL, NULL);

#ifdef CONFIG_POPCORN_STAT
	pf_time_stat(NULL, NULL);
#endif

	return size;
}

static int __open_stats(struct inode *inode, struct file *file)
{
	return single_open(file, __show_stats, inode->i_private);
}

static struct file_operations stats_ops = {
	.owner = THIS_MODULE,
	.open = __open_stats,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write = __write_stats,
};

static int __show_pophype_stats(struct seq_file *seq, void *v)
{
#if 0
	int i;
	unsigned long long sent = 0;
	unsigned long long recv = 0;
	unsigned long long rate_sent, rate_recv;
	unsigned long elapsed;
	struct timeval now;

	/* Between two cat */
	do_gettimeofday(&now);
	elapsed = (now.tv_sec * 1000000 + now.tv_usec) -
			(last_stat.tv_sec * 1000000 + last_stat.tv_usec);
	last_stat = now;

	/* Per cpu msg */
	for_each_present_cpu(i) {
		sent += per_cpu(bytes_sent, i);
		recv += per_cpu(bytes_recv, i);
	}
	seq_printf(seq, POPCORN_STAT_FMT, sent, recv, "Total network I/O");

	rate_sent = (sent - last_bytes_sent);
	rate_recv = (recv - last_bytes_recv);
	seq_printf(seq, POPCORN_STAT_FMT2,
			rate_sent / elapsed, (rate_sent % elapsed) * 1000 / elapsed,
			rate_recv / elapsed, (rate_recv % elapsed) * 1000 / elapsed,
			"MB/s");
	last_bytes_sent = sent;
	last_bytes_recv = recv;

	if (pcn_kmsg_has_features(PCN_KMSG_FEATURE_RDMA) && elapsed) {
		recv = sent = 0;
		for_each_present_cpu(i) {
			sent += per_cpu(bytes_rdma_written, i);
			recv += per_cpu(bytes_rdma_read, i);
		}
		seq_printf(seq, POPCORN_STAT_FMT, sent, recv, "RDMA");

		rate_sent = (sent - last_bytes_rdma_written);
		rate_recv = (recv - last_bytes_rdma_read);
		seq_printf(seq, POPCORN_STAT_FMT2,
				rate_sent / elapsed, (rate_sent % elapsed) * 1000 / elapsed,
				rate_recv / elapsed, (rate_recv % elapsed) * 1000 / elapsed,
				"MB/s");
		last_bytes_rdma_written = sent;
		last_bytes_rdma_read = recv;
	}

	pcn_kmsg_stat(seq, NULL);
#endif

#ifdef CONFIG_POPCORN_STAT
#if 0
	seq_printf(seq, "-----------------------------------------------\n");
	//for (i = PCN_KMSG_TYPE_STAT_START + 1; i < PCN_KMSG_TYPE_STAT_END; i++) {
	for (i = PCN_KMSG_TYPE_REMOTE_PAGE_REQUEST; i < PCN_KMSG_TYPE_REMOTE_PAGE_FLUSH; i++) {
		seq_printf(seq, POPCORN_STAT_FMT,
				sent_stats[i], recv_stats[i], pcn_kmsg_type_name[i] ? : "");
	}
	seq_printf(seq, "---------------------------------------------------------------------------\n");
#endif
#endif

	//fh_action_stat(seq, v);
	//pf_time_stat(seq, v);
	pophype_stat(seq, v); /* kernel/popcorn/hype_kvm.c */
	//file_stat(seq, v); /* kernel/popcorn/hype_file.c */
	seq_printf(seq, "\n");
	pophype_net_gup(seq, v); /* arch/x86/mm/gup.c (no time for me to move) */

	return 0;
}

static ssize_t __write_pophype_stats(struct file *file, const char __user *buffer, size_t size, loff_t *offset)
{
#if 0
	int i;

	/* Msg */
	for_each_present_cpu(i) {
		per_cpu(bytes_sent, i) = 0;
		per_cpu(bytes_recv, i) = 0;
		per_cpu(bytes_rdma_written, i) = 0;
		per_cpu(bytes_rdma_read, i) = 0;
	}

	pcn_kmsg_stat(NULL, NULL);

	for (i = 0 ; i < PCN_KMSG_TYPE_MAX; i++) {
		sent_stats[i] = 0;
		recv_stats[i] = 0;
	}

	fh_action_stat(NULL, NULL);
#endif

	//pf_time_stat(NULL, NULL);
	pophype_stat(NULL, NULL); /* kernel/popcorn/hype_kvm.c */
	//file_stat(NULL, NULL); /* kernel/popcorn/hype_file.c */
	pophype_net_gup(NULL, NULL); /* arch/x86/mm/gup.c (no time for me to move) */

	return size;
}

static int __open_pophype_stats(struct inode *inode, struct file *file)
{
	return single_open(file, __show_pophype_stats, inode->i_private);
}

static struct file_operations pophype_stats_ops = {
	.owner = THIS_MODULE,
	.open = __open_pophype_stats,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write = __write_pophype_stats,
};

extern bool pophype_debug;

static int __show_pophype_debug(struct seq_file *seq, void *v)
{
	if (seq) { /* show */
		seq_printf(seq, "Pophype debug %s (current)\n",
							pophype_debug ? "ON" : "OFF");
		printk("Pophype debug %s (current)\n", pophype_debug ? "ON" : "OFF");
		dsm_traffic_stat(seq, v);
	} else { /* change */
		printk("never happen\n");
	}
	return 0;
}

static ssize_t __write_pophype_debug(struct file *file, const char __user *buffer, size_t size, loff_t *offset)
{
	/* toggle */
	if (pophype_debug)
		pophype_debug = false;
	else
		pophype_debug = true;
	//pophype_debug = ~pophype_debug;

	/* show */
	//seq_printf(seq, "Pophype debug %s (current)\n",
	//					pophype_debug ? "ON" : "OFF");
	printk("Pophype debug %s (current)\n", pophype_debug ? "ON" : "OFF");
	printk("Clean all the info\n");
	dsm_traffic_stat(NULL, NULL);
	return size;
}

static int __open_pophype_debug(struct inode *inode, struct file *file)
{
	return single_open(file, __show_pophype_debug, inode->i_private);
}

static struct file_operations pophype_debug_ops = {
	.owner = THIS_MODULE,
	.open = __open_pophype_debug,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write = __write_pophype_debug,
};

#if POPCORN_STAT_MQ_INFO
extern void pophype_mq_tx_stat(struct seq_file *seq, void *v); /* net/core/dev.c */
extern void pophype_mq_rx_stat(struct seq_file *seq, void *v); /* net/core/dev.c */
static int __show_pophype_mq(struct seq_file *seq, void *v)
{
	pophype_mq_tx_stat(seq, v);
	pophype_mq_rx_stat(seq, v);
	return 0;
}

static ssize_t __write_pophype_mq(struct file *file, const char __user *buffer, size_t size, loff_t *offset)
{
	pophype_mq_tx_stat(NULL, NULL);
	pophype_mq_rx_stat(NULL, NULL);
	return 0;
}

static int __open_pophype_mq(struct inode *inode, struct file *file)
{
	return single_open(file, __show_pophype_mq, inode->i_private);
}

static struct file_operations pophype_mq_ops = {
	.owner = THIS_MODULE,
	.open = __open_pophype_mq,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write = __write_pophype_mq,
};
#endif

int statistics_init(void)
{
	struct proc_dir_entry *proc_entry = NULL;
	proc_entry = proc_create("popcorn_stat", S_IRUGO | S_IWUGO, NULL, &stats_ops);
	if (proc_entry == NULL) {
		printk(KERN_ERR"cannot create proc_fs entry for popcorn stats\n");
		return -ENOMEM;
	}
	proc_entry = proc_create("popcorn_hype", S_IRUGO | S_IWUGO, NULL, &pophype_stats_ops);
	if (proc_entry == NULL) {
		printk(KERN_ERR"cannot create proc_fs entry for popcorn_hype stats\n");
		return -ENOMEM;
	}
	proc_entry = proc_create("popcorn_debug", S_IRUGO | S_IWUGO, NULL, &pophype_debug_ops);
	if (proc_entry == NULL) {
		printk(KERN_ERR"cannot create proc_fs entry for popcorn_hype stats\n");
		return -ENOMEM;
	}
#if POPCORN_STAT_MQ_INFO
	proc_entry = proc_create("popcorn_mq", S_IRUGO | S_IWUGO, NULL, &pophype_mq_ops);
	if (proc_entry == NULL) {
		printk(KERN_ERR"cannot create proc_fs entry for popcorn_mq stats\n");
		return -ENOMEM;
	}
#endif
	return 0;
}
