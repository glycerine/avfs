#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define REDIR2_VERSION "0.0"

#define AVFS_MAGIC_CHAR '#'
#define OVERLAY_DIR "/overlay"
#define OVERLAY_DIR_LEN 8

#define FUSE_MAGIC 0x65735546

static struct dentry *(*orig_lookup)(struct inode *, struct dentry *,
				     struct nameidata *);

static struct dentry *(**orig_lookup_ptr)(struct inode *, struct dentry *,
				     struct nameidata *);


static struct vfsmount *orig_mount;
static struct semaphore redir2_sem;
static int mount_pid = -1;
static int lookup_pid = -1;
static LIST_HEAD(redir2_mounts);
static struct proc_dir_entry *redir2_proc_dir;



struct redir2_mount {
	struct list_head list;
	struct vfsmount *mnt;
};

static struct super_operations redir2_dummy_super_operations;
static struct super_block redir2_dummy_sb = {
	.s_op = &redir2_dummy_super_operations,
};


static int is_avfs(const unsigned char *name, unsigned int len)
{
	for (; len--; name++)
		if (*name == AVFS_MAGIC_CHAR)
			return 1;
	return 0;
}

static char * my_d_path( struct dentry *dentry, struct vfsmount *vfsmnt,
			struct dentry *root, struct vfsmount *rootmnt,
			char *buffer, int buflen)
{
	char * end = buffer+buflen;
	char * retval;
	int namelen;

	*--end = '\0';
	buflen--;
	if (!IS_ROOT(dentry) && d_unhashed(dentry)) 
		return ERR_PTR(-ENOENT);

	if (buflen < 1)
		goto Elong;
	/* Get '/' right */
	retval = end-1;
	*retval = '/';

	for (;;) {
		struct dentry * parent;

		if (dentry == root && vfsmnt == rootmnt)
			break;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
			spin_lock(&vfsmount_lock);
			if (vfsmnt->mnt_parent == vfsmnt) {
				spin_unlock(&vfsmount_lock);
				goto global_root;
			}
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			spin_unlock(&vfsmount_lock);
			continue;
		}
		parent = dentry->d_parent;
		prefetch(parent);
		namelen = dentry->d_name.len;
		buflen -= namelen + 1;
		if (buflen < 0)
			goto Elong;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		retval = end;
		dentry = parent;
	}

	return retval;

global_root:
	namelen = dentry->d_name.len;
	buflen -= namelen;
	if (buflen < 0)
		goto Elong;
	retval -= namelen-1;	/* hit the slash */
	memcpy(retval, dentry->d_name.name, namelen);
	return retval;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}

static int redir2_permission(struct inode *inode, int mask,
			     struct nameidata *nd)
{
	return -ENOENT;
}

static int redir2_getattr(struct vfsmount *mnt, struct dentry *entry,
			  struct kstat *stat)
{
	return -ENOENT;
}

static struct dentry *redir2_dummy_lookup(struct inode *dir, struct dentry *entry,
				   struct nameidata *nd)
{
	return ERR_PTR(-ENOENT);
}


static struct inode_operations redir2_inode_operations = {
	.permission	= redir2_permission,
	.getattr	= redir2_getattr,
	.lookup		= redir2_dummy_lookup,
};

static int mount_avfs(struct dentry *dentry, struct vfsmount *mnt,
		      char *path, int mode)
{
	struct inode *inode;
	struct redir2_mount *newmnt;

	newmnt = kmalloc(sizeof(struct redir2_mount), GFP_KERNEL);
	if (!newmnt)
		return -ENOMEM;
	
	inode = new_inode(&redir2_dummy_sb);
	if (!inode) {
		kfree(newmnt);
		return -ENOMEM;
	}

	inode->i_mode = mode;
	inode->i_op = &redir2_inode_operations;
	d_instantiate(dentry, inode);
	
	char *argv[] = { "/usr/local/bin/redir2mount",
			 path, path + OVERLAY_DIR_LEN, NULL };
	char *envp[] = { NULL };
	int ret;
	ret = call_usermodehelper(argv[0], argv, envp, 1);
	printk("mount ret: %i\n", ret);
	if (ret) {
		kfree(newmnt);
		return -EINVAL;
	}
	newmnt->mnt = lookup_mnt(mnt, dentry);
	if (!newmnt->mnt) {
		printk("not mounted\n");
		kfree(newmnt);
		return -EINVAL;
	}

	__module_get(THIS_MODULE);
	list_add(&newmnt->list, &redir2_mounts);
	printk("new mount: %p\n", newmnt->mnt);

	return 0;
}

static int exists_avfs(char *path, int *modep)
{
	int err;
	struct nameidata avfsnd;

	printk("lookup_avfs: '%s'\n", path);

	avfsnd.last_type = LAST_ROOT;
	avfsnd.flags = 0;
	avfsnd.mnt = mntget(orig_mount);
	avfsnd.dentry = dget(orig_mount->mnt_sb->s_root);
	err = path_walk(path, &avfsnd);
	if (err)
		return 0;

	if(!avfsnd.dentry->d_inode) {
		path_release(&avfsnd);
		return 0;
	}
	*modep = avfsnd.dentry->d_inode->i_mode;
	path_release(&avfsnd);
	return 1;
}

static int lookup_avfs(struct dentry *dentry, struct vfsmount *mnt)
{
	char *page;
	char *path;
	int err;
	
	err = -ENOMEM;
	page = (char *) __get_free_page(GFP_KERNEL);
	if (page) {
		spin_lock(&dcache_lock);
		path = my_d_path(dentry, mnt, mnt->mnt_sb->s_root, mnt, page, PAGE_SIZE);
		spin_unlock(&dcache_lock);
		err = -ENAMETOOLONG;
		if (!IS_ERR(path) && page + OVERLAY_DIR_LEN < path) {
			int mode;
			path -= OVERLAY_DIR_LEN;
			memcpy(path, OVERLAY_DIR, OVERLAY_DIR_LEN);
			
			if (exists_avfs(path, &mode))
				err = mount_avfs(dentry, mnt, path, mode);
			else
				err = -ENOENT;
		}
		free_page((unsigned long) page);
	}
	return err;
}

static int redir2_dentry_revalidate(struct dentry *dentry,
				    struct nameidata *nd)
{
	//printk("redir2_dentry_revalidate\n");
	if (dentry->d_flags & DCACHE_AUTOFS_PENDING) {
		if (current->pid == mount_pid)
			return 1;

		printk("redir2_dentry_revalidate: still pending\n");
		down(&redir2_sem);
		printk("redir2_dentry_revalidate: OK\n");
		up(&redir2_sem);
	}
	if (dentry->d_flags & DCACHE_AUTOFS_PENDING)
		BUG();
	if (!dentry->d_inode || d_unhashed(dentry))
		return 0;
	return 1;
}

static int redir2_dentry_delete(struct dentry *dentry)
{
	printk("redir2_dentry_delete %p '%.*s'\n", dentry,
	       dentry->d_name.len, dentry->d_name.name);
	
	module_put(THIS_MODULE);
	return 1;
}

static struct dentry_operations redir2_dentry_operations = {
	.d_revalidate	= redir2_dentry_revalidate,
	.d_delete	= redir2_dentry_delete,
};

static inline int is_create(struct nameidata *nd)
{
	if (!nd)
		return 1;
	if ((nd->flags & LOOKUP_CREATE) && !(nd->flags & LOOKUP_CONTINUE))
		return 1;
	return 0;
}

static int lookup_maybeavfs(struct inode *dir, struct dentry *dentry,
			    struct nameidata *nd)
{
	int err;

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	down(&redir2_sem);
	lookup_pid = current->pid;
	printk("redir2_dentry_add %p '%.*s'\n", dentry,
	       dentry->d_name.len, dentry->d_name.name);
	mount_pid = -1;
	dentry->d_op = &redir2_dentry_operations;
	dentry->d_flags |= DCACHE_AUTOFS_PENDING;
	d_add(dentry, NULL);
	up(&dir->i_sem);
	err = lookup_avfs(dentry, nd->mnt);
	if (err)
		d_drop(dentry);
	dentry->d_flags &= ~DCACHE_AUTOFS_PENDING;
	lookup_pid = -1;
	up(&redir2_sem);
	down(&dir->i_sem);
	return err;
}

static struct dentry *redir2_lookup(struct inode *dir, struct dentry *dentry,
				    struct nameidata *nd)
{
	int err;
	//printk("lookup %.*s\n", dentry->d_name.len, dentry->d_name.name);

	if (current->pid == lookup_pid || is_create(nd) || 
	    !is_avfs(dentry->d_name.name, dentry->d_name.len))
		return orig_lookup(dir, dentry, nd);

	err = lookup_maybeavfs(dir, dentry, nd);
	if (err)
		return ERR_PTR(err);
	return NULL;
}

static void redir2_release_mount(struct redir2_mount *mnt)
{
	printk("releasing mount: %p\n", mnt->mnt);
	mntput(mnt->mnt);
	list_del(&mnt->list);
	kfree(mnt);
	module_put(THIS_MODULE);
}

static int umount_avfs(struct redir2_mount *mnt, char *path)
{
	char *argv[] = { "/usr/local/bin/redir2mount", "-", path, NULL };
	char *envp[] = { NULL };
	int ret;
	redir2_release_mount(mnt);
	printk("umount\n");
	ret = call_usermodehelper(argv[0], argv, envp, 1);
	printk("umount ret: %i\n", ret);
	if (ret)
		return -EINVAL;

	return 0;
}

static void redir2_try_umount(struct redir2_mount *mnt)
{
	char *page;
	char *path;
	struct dentry *dentry;
	struct vfsmount *pmnt;

	page = (char *) __get_free_page(GFP_KERNEL);
	if (!page)
		return;

	spin_lock(&vfsmount_lock);
	if (mnt->mnt->mnt_parent == mnt->mnt) {
		/* Already unmounted */
		spin_unlock(&vfsmount_lock);
		redir2_release_mount(mnt);
		free_page((unsigned long) page);
		return;
	}
	pmnt = mntget(mnt->mnt->mnt_parent);
	dentry = dget(mnt->mnt->mnt_mountpoint);
	spin_unlock(&vfsmount_lock);

	spin_lock(&dcache_lock);
	path = my_d_path(dentry, pmnt, pmnt->mnt_sb->s_root, pmnt, page, PAGE_SIZE);
	spin_unlock(&dcache_lock);
	if (!IS_ERR(path))
		umount_avfs(mnt, path);
	free_page((unsigned long) page);
	dput(dentry);
	mntput(pmnt);
}

static int redir2_flush(struct file *file, const char __user *buffer,
			unsigned long count, void *data)
{
	struct redir2_mount *mnt;
	struct redir2_mount *next;
	printk("redir2_flush (%i)\n", current->pid);
	down(&redir2_sem);
	list_for_each_entry_safe (mnt, next, &redir2_mounts, list) {
		int cnt = atomic_read(&mnt->mnt->mnt_count);
		printk("mount %p has count %u\n", mnt->mnt, cnt);
		if (cnt <= 2) {
			redir2_try_umount(mnt);
//			break;
		}
	}
	up(&redir2_sem);
	return count;
}

static int mount_pid_write(struct file *file, const char __user *buffer,
			unsigned long count, void *data)
{
	char buf[32];
	if(count > sizeof(buf))
		return -EINVAL;
        if(copy_from_user(buf, buffer, count))
                return -EFAULT;
        mount_pid = simple_strtol(buf, NULL, 10);
        return count;

}

static void redir2_init_proc(void)
{
	redir2_proc_dir = proc_mkdir("redir2", proc_root_fs);
	if (redir2_proc_dir) {
		struct proc_dir_entry *e;
		redir2_proc_dir->owner = THIS_MODULE;
		e = create_proc_entry("mount_pid", S_IFREG | 0200, redir2_proc_dir);
		if (e) {
			e->owner = THIS_MODULE;
			e->write_proc = mount_pid_write;
		}
		e = create_proc_entry("flush", S_IFREG | 0200, redir2_proc_dir);
		if (e) {
			e->owner = THIS_MODULE;
			e->write_proc = redir2_flush;
		}
	}
}

static int __init init_redir2(void)
{
	printk(KERN_INFO "redir2 init (version %s)\n", REDIR2_VERSION);

	sema_init(&redir2_sem, 1);
	redir2_init_proc();
	read_lock(&current->fs->lock);
	orig_mount = mntget(current->fs->rootmnt);
	orig_lookup_ptr = &current->fs->root->d_inode->i_op->lookup;
	orig_lookup = *orig_lookup_ptr;
	*orig_lookup_ptr = redir2_lookup;
	read_unlock(&current->fs->lock);

	/* FIXME: This is a bit too brutal approach */
	printk("shrinking dcache...\n");
	shrink_dcache_sb(orig_mount->mnt_sb);
	printk("done\n");

	return 0;
}

static void __exit exit_redir2(void)
{
	printk(KERN_INFO "redir2 cleanup\n");

	if (orig_lookup_ptr)
		*orig_lookup_ptr = orig_lookup;
	mntput(orig_mount);
	if (redir2_proc_dir) {
		remove_proc_entry("mount_pid", redir2_proc_dir);
		remove_proc_entry("flush", redir2_proc_dir);
		remove_proc_entry("redir2", proc_root_fs);
	}
}


module_init(init_redir2)
module_exit(exit_redir2)


MODULE_LICENSE("GPL");

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
