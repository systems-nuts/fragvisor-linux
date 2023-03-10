/*
 *  include/linux/anon_inodes.h
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#ifndef _LINUX_ANON_INODES_H
#define _LINUX_ANON_INODES_H

struct file_operations;

struct file *anon_inode_getfile(const char *name,
				const struct file_operations *fops,
				void *priv, int flags);
int anon_inode_getfd(const char *name, const struct file_operations *fops,
		     void *priv, int flags);
#ifdef CONFIG_POPCORN_HYPE
int anon_inode_getfd_tsk(struct task_struct *tsk, const char *name,
				const struct file_operations *fops, void *priv, int flags);
#endif
#endif /* _LINUX_ANON_INODES_H */

