/*
 * linux/kernel/irq/proc.c
 *
 * Copyright (C) 1992, 1998-2004 Linus Torvalds, Ingo Molnar
 *
 * This file contains the /proc/irq/ handling code.
 */

#include <linux/irq.h>
#include <linux/gfp.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/mutex.h>

#ifdef CONFIG_POPCORN_HYPE
#include <popcorn/bundle.h>
#include <popcorn/debug.h>
#else /* Support for vanilla*/
#include <popcorn/debug.h>
#endif

#include "internals.h"
/*
 * Access rules:
 *
 * procfs protects read/write of /proc/irq/N/ files against a
 * concurrent free of the interrupt descriptor. remove_proc_entry()
 * immediately prevents new read/writes to happen and waits for
 * already running read/write functions to complete.
 *
 * We remove the proc entries first and then delete the interrupt
 * descriptor from the radix tree and free it. So it is guaranteed
 * that irq_to_desc(N) is valid as long as the read/writes are
 * permitted by procfs.
 *
 * The read from /proc/interrupts is a different problem because there
 * is no protection. So the lookup and the access to irqdesc
 * information must be protected by sparse_irq_lock.
 */
static struct proc_dir_entry *root_irq_dir;

#ifdef CONFIG_SMP

static int show_irq_affinity(int type, struct seq_file *m, void *v)
{
	struct irq_desc *desc = irq_to_desc((long)m->private);
	const struct cpumask *mask = desc->irq_common_data.affinity;

#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL
	//unsigned int irq = desc->irq_data.irq;
	IRQPROCPRINTK("\t\t[%d] %s(): read/show/open type %d "
			"(irq_desc is the meta data for irq in kernel)\n",
								current->pid, __func__, type);
#endif
#ifdef CONFIG_GENERIC_PENDING_IRQ
	if (irqd_is_setaffinity_pending(&desc->irq_data)) {
		mask = desc->pending_mask;
#if !POPHYPE_HOST_KERNEL
		IRQPROCPRINTK("irq affinity overwritten by desc->pending_mask %*pb\n",
										cpumask_pr_args(desc->pending_mask));
#endif
	}
#endif
	if (type)
		seq_printf(m, "%*pbl\n", cpumask_pr_args(mask)); /* irq/<>/smp_affinity_list */
	else
		seq_printf(m, "%*pb\n", cpumask_pr_args(mask)); /* irq/<>/smp_affinity */
	return 0;
}

static int irq_affinity_hint_proc_show(struct seq_file *m, void *v)
{
	struct irq_desc *desc = irq_to_desc((long)m->private);
	unsigned long flags;
	cpumask_var_t mask;
#if !POPHYPE_HOST_KERNEL
	unsigned int irq = desc->irq_data.irq;
	if (irq == HOST_X86_UART || irq == GUEST_X86_UART || irq == GUEST_X86_NET)
		IRQPROCPRINTK("%s(): pop_irqproc irq %u (no hope)\n",
										__func__, irq);
#endif

	if (!zalloc_cpumask_var(&mask, GFP_KERNEL))
		return -ENOMEM;

	raw_spin_lock_irqsave(&desc->lock, flags);
	if (desc->affinity_hint) {
#if !POPHYPE_HOST_KERNEL
		if (irq == HOST_X86_UART || irq == GUEST_X86_UART ||
			irq == GUEST_X86_NET) { /* not used */
			IRQPROCPRINTK("%s(): pop_irqproc irq %u "
						"uses affinity_hint (no hope)\n", __func__, irq);
		}
#endif
		cpumask_copy(mask, desc->affinity_hint);
	}
	raw_spin_unlock_irqrestore(&desc->lock, flags);

#if !POPHYPE_HOST_KERNEL
	IRQPROCPRINTK("%s(): preparing to overwrit irq %u\n", __func__, irq);
	if (irq == GUEST_X86_NET) {
		if (irq_can_set_affinity(irq)) {
			//desc->irq_common_data.affinity
			//(irq_common_data.affinity, );
			//IRQPROCPRINTK("%s(): don't care hint, overwriting irq %u to 1\n",
			//													__func__, irq);
			IRQPROCPRINTK("%s(): overwriting irq %u "
						"hint & affinity to 1 (hardcoded)\n", __func__, irq);

			IRQPROCPRINTK("%s(): check: bf: affinity cpu %*pbl %*pb\n",
					__func__, cpumask_pr_args(desc->irq_common_data.affinity),
					cpumask_pr_args(desc->irq_common_data.affinity));
			irq_set_affinity(irq, cpumask_of(1));
			IRQPROCPRINTK("%s(): check: af1: affinity cpu %*pbl %*pb\n",
					__func__, cpumask_pr_args(desc->irq_common_data.affinity),
					cpumask_pr_args(desc->irq_common_data.affinity));

			cpumask_copy(desc->irq_common_data.affinity, cpumask_of(1));
			IRQPROCPRINTK("%s(): check: af2: affinity cpu %*pbl %*pb\n",
					__func__, cpumask_pr_args(desc->irq_common_data.affinity),
					cpumask_pr_args(desc->irq_common_data.affinity));

			//cpumask_copy(desc->affinity_hint, cpumask_of(1));
			//IRQPROCPRINTK("%s(): do this at least 2 times "
			//			"BUT hint is const........\n", __func__);
			if (desc->affinity_notify) {
				IRQPROCPRINTK("%s(): check desc->affinity_notify->notify %p\n",
									__func__, desc->affinity_notify->notify);
			} else {
				IRQPROCPRINTK("%s(): check "
					"!desc->affinity_notify(->notify) %p\n", __func__, NULL);
			}
			IRQPROCPRINTK("%s(): try irq balance disable but how?\n", __func__);
		} else {
			IRQPROCPRINTK("%s(): CANNOT set irq affinity\n", __func__);
		}
	}
#endif

	seq_printf(m, "%*pb\n", cpumask_pr_args(mask));
	free_cpumask_var(mask);

	return 0;
}

#ifndef is_affinity_mask_valid
#define is_affinity_mask_valid(val) 1
#endif

int no_irq_affinity;
static int irq_affinity_proc_show(struct seq_file *m, void *v)
{
	return show_irq_affinity(0, m, v);
}

static int irq_affinity_list_proc_show(struct seq_file *m, void *v)
{
	return show_irq_affinity(1, m, v);
}


static ssize_t write_irq_affinity(int type, struct file *file,
		const char __user *buffer, size_t count, loff_t *pos)
{
	unsigned int irq = (int)(long)PDE_DATA(file_inode(file));
	cpumask_var_t new_value;
	int err;

#if !POPHYPE_HOST_KERNEL
	IRQPROCPRINTK("\t\t[%d] %s(): set irq %u as ??? type %d\n",
							current->pid, __func__, irq, type);
#endif
	if (!irq_can_set_affinity(irq) || no_irq_affinity) {
//#if !POPHYPE_HOST_KERNEL
#ifdef CONFIG_POPCORN_HYPE
#if 0
		/* patch: echo "" > /proc/irq/ && no set_affinity callback func */
		/* echo */
		if (irq == HOST_X86_UART || irq == GUEST_X86_UART) {
			int count = 1;
			cpumask_var_t tmpmask;
			struct irq_desc *desc = irq_to_desc(irq);
			IRQPROCPRINTK("\t\t[%d] %s(): irq %d return 1 cannot set %d "
					"no affi %d \n\t\t\t\t"
					"irqd_can_balance() ret %d   "
					"1 %d 2 %d 3 %d 4 %d (1problem)\n",
					current->pid, __func__, irq,
					!irq_can_set_affinity(irq), no_irq_affinity,
						!desc || !irqd_can_balance(&desc->irq_data) ||
							!desc->irq_data.chip ||
								!desc->irq_data.chip->irq_set_affinity ? 0 : 1,
					!desc, !irqd_can_balance(&desc->irq_data),
					!desc->irq_data.chip,
					!desc->irq_data.chip->irq_set_affinity);
			// ...... no call back function...
			IRQPROCPRINTK("\t\t[%d] %s(): irq %u no callback -> rollback\n",
										current->pid, __func__, irq);

			if (!alloc_cpumask_var(&tmpmask, GFP_KERNEL))
				return -ENOMEM;
			cpumask_clear(tmpmask);
			if (cpumask_parse_user(buffer, count, tmpmask))
			//err = cpumask_parse(buffer, tmpmask);
				return -ENOMEM;

			/* hardcoded */
			//cpumask_set_cpu(0, tmpmask); // pin the irq on cpu0. cpumask = 1
			//cpumask_set_cpu(1, tmpmask);

			IRQPROCPRINTK("\tpop_irqproc get a irq affinity from usr: %*pb "
							"test nr_cpumask_bits %d\n",
							cpumask_pr_args(tmpmask), nr_cpumask_bits);

			/* default*/
			// mask = desc->irq_common_data.affinity
			// cpumask_var_t irq_default_affinity; /* global in kernel/irq/manage.c and used for default_affinity_show */

			/* now. write it */
			if (desc->affinity_hint)
				cpumask_copy(desc->affinity_hint,
						(const struct cpumask *)tmpmask); // update aff_hint
			else
				IRQPROCPRINTK("\tpop_irqproc CANNOT SET desc-> "
									"irq_common_data.affinity\n");

			/* write/set desc->irq_common_data.affinity  */
			//cpumask_copy(mask, tmpmask); // update mask // cannot write directly so write indrectly
			cpumask_copy(desc->irq_common_data.affinity, tmpmask); // update mask // cannot write directly so write indrectly
			IRQPROCPRINTK("\tpop_irqproc set irq affinity ->.aff: %*pb\n",
								cpumask_pr_args(desc->irq_common_data.affinity));
			//IRQPROCPRINTK("\tpop_irqproc set irq affinity mask: %*pb\n",
			//										cpumask_pr_args(mask));
			IRQPROCPRINTK("\n");

			free_cpumask_var(tmpmask);
		}
#endif
#endif
		return -EIO;
	}

#ifdef CONFIG_POPCORN_HYPE
	//debug
	{
		struct irq_desc *desc = irq_to_desc(irq);
		if (desc) {
			if (desc->irq_data.chip) {
				if (desc->irq_data.chip->irq_set_affinity) {
					AFFPRINTK("%s() check: smp_irq_set_affinity_callback() %p name %s\n",
							__func__, desc->irq_data.chip->irq_set_affinity,
										desc->irq_data.chip->name);
				} else {
					AFFPRINTK("%s() check: !smp_irq_set_affinity_callback() \n", __func__);
				}
			} else {
				AFFPRINTK("%s() check: !desc->irq_data.chip case\n", __func__);
			}
		} else {
			AFFPRINTK("%s() check: !desc case\n", __func__);
		}
	}
#endif

	if (!alloc_cpumask_var(&new_value, GFP_KERNEL)) {
#if !POPHYPE_HOST_KERNEL
		IRQPROCPRINTK("\t\t[%d] %s(): irq %d return 1\n",
							current->pid, __func__, irq);
#endif
		return -ENOMEM;
	}

	if (type)
		err = cpumask_parselist_user(buffer, count, new_value);
	else
		err = cpumask_parse_user(buffer, count, new_value);
	if (err)
		goto free_cpumask;

	if (!is_affinity_mask_valid(new_value)) {
#if !POPHYPE_HOST_KERNEL
		IRQPROCPRINTK("\t\t[%d] %s(): irq %d return 1\n",
							current->pid, __func__, irq);
#endif
		err = -EINVAL;
		goto free_cpumask;
	}

	/*
	 * Do not allow disabling IRQs completely - it's a too easy
	 * way to make the system unusable accidentally :-) At least
	 * one online CPU still has to be targeted.
	 */
	if (!cpumask_intersects(new_value, cpu_online_mask)) {
		/* Special case for empty set - allow the architecture
		   code to set default SMP affinity. */
		err = irq_select_affinity_usr(irq, new_value) ? -EINVAL : count;
	} else {
#if !POPHYPE_HOST_KERNEL
#if 0
		/* x86: ioapic_set_affinity */
		int ret = irq_set_affinity(irq, new_value);
		IRQPROCPRINTK("\t\t[%d] %s(): set irq %d as ??? ret %d\n",
								current->pid, __func__, irq, ret);
#else
		irq_set_affinity(irq, new_value);
#endif
#else
		irq_set_affinity(irq, new_value);
#endif
		err = count;
	}

free_cpumask:
	free_cpumask_var(new_value);
	return err;
}

static ssize_t irq_affinity_proc_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *pos)
{
	return write_irq_affinity(0, file, buffer, count, pos);
}

static ssize_t irq_affinity_list_proc_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *pos)
{
	return write_irq_affinity(1, file, buffer, count, pos);
}

static int irq_affinity_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, irq_affinity_proc_show, PDE_DATA(inode));
}

static int irq_affinity_list_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, irq_affinity_list_proc_show, PDE_DATA(inode));
}

static int irq_affinity_hint_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, irq_affinity_hint_proc_show, PDE_DATA(inode));
}

static const struct file_operations irq_affinity_proc_fops = {
	.open		= irq_affinity_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= irq_affinity_proc_write,
};

static const struct file_operations irq_affinity_hint_proc_fops = {
	.open		= irq_affinity_hint_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations irq_affinity_list_proc_fops = {
	.open		= irq_affinity_list_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= irq_affinity_list_proc_write,
};

static int default_affinity_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%*pb\n", cpumask_pr_args(irq_default_affinity));
	return 0;
}

static ssize_t default_affinity_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{
	cpumask_var_t new_value;
	int err;

	if (!alloc_cpumask_var(&new_value, GFP_KERNEL))
		return -ENOMEM;

	err = cpumask_parse_user(buffer, count, new_value);
	if (err)
		goto out;

	if (!is_affinity_mask_valid(new_value)) {
		err = -EINVAL;
		goto out;
	}

	/*
	 * Do not allow disabling IRQs completely - it's a too easy
	 * way to make the system unusable accidentally :-) At least
	 * one online CPU still has to be targeted.
	 */
	if (!cpumask_intersects(new_value, cpu_online_mask)) {
		err = -EINVAL;
		goto out;
	}

	cpumask_copy(irq_default_affinity, new_value);
	err = count;

out:
	free_cpumask_var(new_value);
	return err;
}

static int default_affinity_open(struct inode *inode, struct file *file)
{
	return single_open(file, default_affinity_show, PDE_DATA(inode));
}

static const struct file_operations default_affinity_proc_fops = {
	.open		= default_affinity_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= default_affinity_write,
};

static int irq_node_proc_show(struct seq_file *m, void *v)
{
	struct irq_desc *desc = irq_to_desc((long) m->private);

	seq_printf(m, "%d\n", irq_desc_get_node(desc));
	return 0;
}

static int irq_node_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, irq_node_proc_show, PDE_DATA(inode));
}

static const struct file_operations irq_node_proc_fops = {
	.open		= irq_node_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

static int irq_spurious_proc_show(struct seq_file *m, void *v)
{
	struct irq_desc *desc = irq_to_desc((long) m->private);

	seq_printf(m, "count %u\n" "unhandled %u\n" "last_unhandled %u ms\n",
		   desc->irq_count, desc->irqs_unhandled,
		   jiffies_to_msecs(desc->last_unhandled));
	return 0;
}

static int irq_spurious_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, irq_spurious_proc_show, PDE_DATA(inode));
}

static const struct file_operations irq_spurious_proc_fops = {
	.open		= irq_spurious_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#define MAX_NAMELEN 128

static int name_unique(unsigned int irq, struct irqaction *new_action)
{
	struct irq_desc *desc = irq_to_desc(irq);
	struct irqaction *action;
	unsigned long flags;
	int ret = 1;

	raw_spin_lock_irqsave(&desc->lock, flags);
	for (action = desc->action ; action; action = action->next) {
		if ((action != new_action) && action->name &&
				!strcmp(new_action->name, action->name)) {
			ret = 0;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&desc->lock, flags);
	return ret;
}

void register_handler_proc(unsigned int irq, struct irqaction *action)
{
	char name [MAX_NAMELEN];
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc->dir || action->dir || !action->name ||
					!name_unique(irq, action))
		return;

	memset(name, 0, MAX_NAMELEN);
	snprintf(name, MAX_NAMELEN, "%s", action->name);

	/* create /proc/irq/1234/handler/ */
	action->dir = proc_mkdir(name, desc->dir);
}

#undef MAX_NAMELEN

#define MAX_NAMELEN 10

void register_irq_proc(unsigned int irq, struct irq_desc *desc)
{
	static DEFINE_MUTEX(register_lock);
	char name [MAX_NAMELEN];

	if (!root_irq_dir || (desc->irq_data.chip == &no_irq_chip))
		return;

	/*
	 * irq directories are registered only when a handler is
	 * added, not when the descriptor is created, so multiple
	 * tasks might try to register at the same time.
	 */
	mutex_lock(&register_lock);

	if (desc->dir)
		goto out_unlock;

	memset(name, 0, MAX_NAMELEN);
	sprintf(name, "%d", irq);

	/* create /proc/irq/1234 */
	desc->dir = proc_mkdir(name, root_irq_dir);
	if (!desc->dir)
		goto out_unlock;

#ifdef CONFIG_SMP
	/* create /proc/irq/<irq>/smp_affinity */
	proc_create_data("smp_affinity", 0644, desc->dir,
			 &irq_affinity_proc_fops, (void *)(long)irq);

	/* create /proc/irq/<irq>/affinity_hint */
	proc_create_data("affinity_hint", 0444, desc->dir,
			 &irq_affinity_hint_proc_fops, (void *)(long)irq);

	/* create /proc/irq/<irq>/smp_affinity_list */
	proc_create_data("smp_affinity_list", 0644, desc->dir,
			 &irq_affinity_list_proc_fops, (void *)(long)irq);

	proc_create_data("node", 0444, desc->dir,
			 &irq_node_proc_fops, (void *)(long)irq);
#ifdef CONFIG_POPCORN_HYPE
	if (irq == HOST_X86_UART || irq == GUEST_X86_UART || irq == GUEST_X86_NET)
		IRQPROCPRINTK("\t%s(): pop_irqproc irq %u create irq/affinity_hint!\n", __func__, irq);
#endif
#endif

	proc_create_data("spurious", 0444, desc->dir,
			 &irq_spurious_proc_fops, (void *)(long)irq);

out_unlock:
	mutex_unlock(&register_lock);
}

void unregister_irq_proc(unsigned int irq, struct irq_desc *desc)
{
	char name [MAX_NAMELEN];

	if (!root_irq_dir || !desc->dir)
		return;
#ifdef CONFIG_SMP
	remove_proc_entry("smp_affinity", desc->dir);
	remove_proc_entry("affinity_hint", desc->dir);
	remove_proc_entry("smp_affinity_list", desc->dir);
	remove_proc_entry("node", desc->dir);
#endif
	remove_proc_entry("spurious", desc->dir);

	memset(name, 0, MAX_NAMELEN);
	sprintf(name, "%u", irq);
	remove_proc_entry(name, root_irq_dir);
}

#undef MAX_NAMELEN

void unregister_handler_proc(unsigned int irq, struct irqaction *action)
{
	proc_remove(action->dir);
}

static void register_default_affinity_proc(void)
{
#ifdef CONFIG_SMP
	proc_create("irq/default_smp_affinity", 0644, NULL,
		    &default_affinity_proc_fops);
#endif
}

void init_irq_proc(void)
{
	unsigned int irq;
	struct irq_desc *desc;

	/* create /proc/irq */
	root_irq_dir = proc_mkdir("irq", NULL);
	if (!root_irq_dir)
		return;

	register_default_affinity_proc();

	/*
	 * Create entries for all existing IRQs.
	 */
	for_each_irq_desc(irq, desc) {
		if (!desc)
			continue;

		register_irq_proc(irq, desc);
	}
}

#ifdef CONFIG_GENERIC_IRQ_SHOW

int __weak arch_show_interrupts(struct seq_file *p, int prec)
{
	return 0;
}

#ifndef ACTUAL_NR_IRQS
# define ACTUAL_NR_IRQS nr_irqs
#endif

int show_interrupts(struct seq_file *p, void *v)
{
	static int prec;

	unsigned long flags, any_count = 0;
	int i = *(loff_t *) v, j;
	struct irqaction *action;
	struct irq_desc *desc;

	if (i > ACTUAL_NR_IRQS)
		return 0;

	if (i == ACTUAL_NR_IRQS)
		return arch_show_interrupts(p, prec);

	/* print header and calculate the width of the first column */
	if (i == 0) {
		for (prec = 3, j = 1000; prec < 10 && j <= nr_irqs; ++prec)
			j *= 10;

		seq_printf(p, "%*s", prec + 8, "");
		for_each_online_cpu(j)
			seq_printf(p, "CPU%-8d", j);
		seq_putc(p, '\n');
	}

	irq_lock_sparse();
	desc = irq_to_desc(i);
	if (!desc)
		goto outsparse;

	raw_spin_lock_irqsave(&desc->lock, flags);
	for_each_online_cpu(j)
		any_count |= kstat_irqs_cpu(i, j);
	action = desc->action;
	if ((!action || irq_desc_is_chained(desc)) && !any_count)
		goto out;

	seq_printf(p, "%*d: ", prec, i);
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", kstat_irqs_cpu(i, j));

	if (desc->irq_data.chip) {
		if (desc->irq_data.chip->irq_print_chip)
			desc->irq_data.chip->irq_print_chip(&desc->irq_data, p);
		else if (desc->irq_data.chip->name)
			seq_printf(p, " %8s", desc->irq_data.chip->name);
		else
			seq_printf(p, " %8s", "-");
	} else {
		seq_printf(p, " %8s", "None");
	}
	if (desc->irq_data.domain)
		seq_printf(p, " %*d", prec, (int) desc->irq_data.hwirq);
#ifdef CONFIG_GENERIC_IRQ_SHOW_LEVEL
	seq_printf(p, " %-8s", irqd_is_level_type(&desc->irq_data) ? "Level" : "Edge");
#endif
	if (desc->name)
		seq_printf(p, "-%-8s", desc->name);

	if (action) {
		seq_printf(p, "  %s", action->name);
		while ((action = action->next) != NULL)
			seq_printf(p, ", %s", action->name);
	}

	seq_putc(p, '\n');
out:
	raw_spin_unlock_irqrestore(&desc->lock, flags);
outsparse:
	irq_unlock_sparse();
	return 0;
}
#endif
