/*
 *  fs/anon_inodes.c
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 *  Thanks to Arnd Bergmann for code review and suggestions.
 *  More changes for Thomas Gleixner suggestions.
 *
 */

#include <linux/cred.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/anon_inodes.h>

#include <asm/uaccess.h>

#ifdef CONFIG_POPCORN_HYPE
#include <popcorn/debug.h>
#include <popcorn/types.h>
#endif

static struct vfsmount *anon_inode_mnt __read_mostly;
static struct inode *anon_inode_inode;

/*
 * anon_inodefs_dname() is called from d_path().
 */
static char *anon_inodefs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return dynamic_dname(dentry, buffer, buflen, "anon_inode:%s",
				dentry->d_name.name);
}

static const struct dentry_operations anon_inodefs_dentry_operations = {
	.d_dname	= anon_inodefs_dname,
};

static struct dentry *anon_inodefs_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name, void *data)
{
	return mount_pseudo(fs_type, "anon_inode:", NULL,
			&anon_inodefs_dentry_operations, ANON_INODE_FS_MAGIC);
}

static struct file_system_type anon_inode_fs_type = {
	.name		= "anon_inodefs",
	.mount		= anon_inodefs_mount,
	.kill_sb	= kill_anon_super,
};

/**
 * anon_inode_getfile - creates a new file instance by hooking it up to an
 *                      anonymous inode, and a dentry that describe the "class"
 *                      of the file
 *
 * @name:    [in]    name of the "class" of the new file
 * @fops:    [in]    file operations for the new file
 * @priv:    [in]    private data for the new file (will be file's private_data)
 * @flags:   [in]    flags
 *
 * Creates a new file by hooking it on a single inode. This is useful for files
 * that do not need to have a full-fledged inode in order to operate correctly.
 * All the files created with anon_inode_getfile() will share a single inode,
 * hence saving memory and avoiding code duplication for the file/inode/dentry
 * setup.  Returns the newly created file* or an error pointer.
 */
struct file *anon_inode_getfile(const char *name,
				const struct file_operations *fops,
				void *priv, int flags)
{
	struct qstr this;
	struct path path;
	struct file *file;

	if (IS_ERR(anon_inode_inode))
		return ERR_PTR(-ENODEV);

	if (fops->owner && !try_module_get(fops->owner))
		return ERR_PTR(-ENOENT);

	/*
	 * Link the inode to a directory entry by creating a unique name
	 * using the inode sequence number.
	 */
	file = ERR_PTR(-ENOMEM);
	this.name = name;
	this.len = strlen(name);
	this.hash = 0;
	path.dentry = d_alloc_pseudo(anon_inode_mnt->mnt_sb, &this);
	if (!path.dentry)
		goto err_module;

	path.mnt = mntget(anon_inode_mnt);
	/*
	 * We know the anon_inode inode count is always greater than zero,
	 * so ihold() is safe.
	 */
	ihold(anon_inode_inode);

	d_instantiate(path.dentry, anon_inode_inode);

	file = alloc_file(&path, OPEN_FMODE(flags), fops);
	if (IS_ERR(file))
		goto err_dput;
	file->f_mapping = anon_inode_inode->i_mapping;

	file->f_flags = flags & (O_ACCMODE | O_NONBLOCK);
	file->private_data = priv;

#ifdef CONFIG_POPCORN_HYPE
	/* More details outside. vpcu and vhost-net eventfd both use this!! */
	HPPRINTK("%s(): \"%s\"\n", __func__, this.name);
	/* event_signal for vhost for delegation */
	if (distributed_process(current)) {
		POP_PK("%s(): \"%s\"\n", __func__, this.name);
	}
#endif

	return file;

err_dput:
	path_put(&path);
err_module:
	module_put(fops->owner);
	return file;
}
EXPORT_SYMBOL_GPL(anon_inode_getfile);

/**
 * anon_inode_getfd - creates a new file instance by hooking it up to an
 *                    anonymous inode, and a dentry that describe the "class"
 *                    of the file
 *
 * @name:    [in]    name of the "class" of the new file
 * @fops:    [in]    file operations for the new file
 * @priv:    [in]    private data for the new file (will be file's private_data)
 * @flags:   [in]    flags
 *
 * Creates a new file by hooking it on a single inode. This is useful for files
 * that do not need to have a full-fledged inode in order to operate correctly.
 * All the files created with anon_inode_getfd() will share a single inode,
 * hence saving memory and avoiding code duplication for the file/inode/dentry
 * setup.  Returns new descriptor or an error code.
 */
#ifdef CONFIG_POPCORN_HYPE
#include <linux/kvm_host.h>
#endif
extern int get_file_path(struct file *file, char *sz, size_t size); /////////////
int anon_inode_getfd(const char *name, const struct file_operations *fops,
		     void *priv, int flags)
{
	int error, fd;
	struct file *file;

	error = get_unused_fd_flags(flags);
	if (error < 0)
		return error;
	fd = error;

	file = anon_inode_getfile(name, fops, priv, flags);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto err_put_unused_fd;
	}
	fd_install(fd, file);

#ifdef CONFIG_POPCORN_HYPE
    if (file) {
        char path[512];
		HPPRINTK("%s(): \"%s\"\n", __func__, name);
        get_file_path(file, path, sizeof(path));
        if (!strncmp("anon_inode:kvm-vcpu:", path,
                sizeof("anon_inode:kvm-vcpu:") - 1 ))
		{
			struct kvm_vcpu *vcpu = file->private_data;
			POP_PK("   ================\n");
			POP_PK("%s(): GT. fd %d <-> *file %p vcpu %p run %p TODO construct table here\n",
														__func__, fd, file, vcpu, vcpu->run);
			POP_PK("   ================\n\n");
			/* MAKE VCPU FILE FD table here */
#if 0
			struct file *f = NULL;
			f = filp_open(path, O_RDONLY | O_LARGEFILE | O_TMPFILE, 0);
			if (IS_ERR(f)) {
				printk("%s(): (try) filp open diectly (((FAIL)))\n", __func__);
			} else {
				printk("%s(): (test) filp open \"%s\" f %p O_TMPFILE (((O)))\n", __func__, path, f);
				filp_close(f, NULL);
			}
#endif

#if 0
			{
				struct fd __fd = fdget(fd);
				printk("%s(): (try) use fd to get struct __fd.file %p "
									"(matched???)\n", __func__, __fd.file);
				if(__fd.file)
					fdput(__fd);
			}
#endif
        } else {
            //printk("%s(): This is not our target. May try if no idea\n", __func__);
		}
    }
#endif
////////////////


	return fd;

err_put_unused_fd:
	put_unused_fd(fd);
	return error;
}
EXPORT_SYMBOL_GPL(anon_inode_getfd);

#ifdef CONFIG_POPCORN_HYPE
int anon_inode_getfd_tsk(struct task_struct *tsk, const char *name, const struct file_operations *fops, void *priv, int flags)
{
	int error, fd;
	struct file *file;

	error = get_unused_fd_flags_tsk(tsk, flags);
	if (error < 0)
		return error;
	fd = error;

	HPPRINTK("%s(): check moredetails\n", __func__);
	file = anon_inode_getfile(name, fops, priv, flags);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto err_put_unused_fd;
	}
	fd_install_tsk(tsk, fd, file);

	return fd;

err_put_unused_fd:
	put_unused_fd_tsk(tsk, fd);
	return error;
}
EXPORT_SYMBOL_GPL(anon_inode_getfd_tsk);
#endif

static int __init anon_inode_init(void)
{
	anon_inode_mnt = kern_mount(&anon_inode_fs_type);
	if (IS_ERR(anon_inode_mnt))
		panic("anon_inode_init() kernel mount failed (%ld)\n", PTR_ERR(anon_inode_mnt));

	anon_inode_inode = alloc_anon_inode(anon_inode_mnt->mnt_sb);
	if (IS_ERR(anon_inode_inode))
		panic("anon_inode_init() inode allocation failed (%ld)\n", PTR_ERR(anon_inode_inode));

	return 0;
}

fs_initcall(anon_inode_init);

