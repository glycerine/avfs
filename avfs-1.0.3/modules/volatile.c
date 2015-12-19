/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "avfs.h"
#include "version.h"

/* a generic information node */
/* analogous to the "on-disk inode" in a disk filesystem */
struct volnode {
    struct avstat st;
    struct volentry *subdir;  /* only dir */
    struct volentry *parent;  /* only dir */
    char *content;            /* only regular & symlink */
};

/* our ventry.data handle */
/* represents a named reference to a volnode */
struct volentry {
    char *name;
    struct volnode *node;
    struct volentry *next;
    struct volentry **prevp;
    struct volentry *parent;
};

/* our vmount.data handle */
struct volfs {
    struct volentry *root;
    struct avfs *avfs;
};

/* av_obj.destr for volentry */
static void vol_unlink_entry(struct volentry *ent)
{
    if(ent->prevp != NULL)
        *ent->prevp = ent->next;
    if(ent->next != NULL)
        ent->next->prevp = ent->prevp;
    av_unref_obj(ent->parent);
    av_free(ent->name);

    ent->prevp = NULL;
    ent->next = NULL;
    ent->parent = NULL;
    ent->name = NULL;
}

/* constructor for volentry */
static struct volentry *vol_new_entry(const char *name)
{
    struct volentry *ent;

    AV_NEW_OBJ(ent, vol_unlink_entry);

    ent->node = NULL;
    ent->next = NULL;
    ent->prevp = NULL;
    ent->parent = NULL;
    ent->name = av_strdup(name);

    return ent;
}

/* av_obj.destr for volnode */
static void vol_free_node(struct volnode *nod)
{
    av_free(nod->content);
}

/* constructor for volnode */
static struct volnode *vol_new_node(struct avstat *initstat)
{
    struct volnode *nod;

    AV_NEW_OBJ(nod, vol_free_node);

    nod->st = *initstat;
    nod->subdir = NULL;
    nod->parent = NULL;
    nod->content = NULL;

    return nod;
}

/* link ent to nod */
static void vol_link_node(struct volentry *ent, struct volnode *nod)
{
    av_ref_obj(ent);
    av_ref_obj(nod);
    ent->node = nod;
    
    if(AV_ISDIR(nod->st.mode)) {
        nod->st.nlink = 2;
        if(ent->parent != NULL) {
            nod->parent = ent->parent;
            ent->parent->node->st.nlink ++;
        }
        else 
            nod->parent = ent;
    }
    else
        nod->st.nlink ++;

    if(ent->parent != NULL)
        ent->parent->node->st.size ++;    
}

static void vol_unlink_node(struct volentry *ent)
{
    struct volnode *nod = ent->node;
    
    if(AV_ISDIR(nod->st.mode)) {
        nod->st.nlink = 0;
        if(nod->parent != NULL)
            nod->parent->node->st.nlink --;
    }
    else
        nod->st.nlink --;

    if(ent->parent != NULL)
        ent->parent->node->st.size --;


    ent->node = NULL;
    av_unref_obj(nod);
    av_unref_obj(ent);
}

/* called by vol_destroy */
static void vol_free_tree(struct volentry *ent)
{
    struct volnode *nod = ent->node;

    if(nod != NULL) {
        while(nod->subdir != NULL)
            vol_free_tree(nod->subdir);
        
        vol_unlink_entry(ent);
        vol_unlink_node(ent);
    }
}

static int vol_make_node(struct volfs *fs, struct volentry *ent, avmode_t mode)
{
    struct volnode *nod;
    struct avstat initstat;

    if(ent->name == NULL)
        return -ENOENT;

    av_default_stat(&initstat);
    
    initstat.dev = fs->avfs->dev;
    initstat.ino = av_new_ino(fs->avfs);

    nod = vol_new_node(&initstat);
    nod->st.mode = mode;
    
    vol_link_node(ent, nod);
    av_unref_obj(nod);

    return 0;
}

static struct volentry *vol_ventry_volentry(ventry *ve)
{
    return (struct volentry *) ve->data;
}

static struct volnode *vol_vfile_volnode(vfile *vf)
{
    return (struct volnode *) vf->data;
}

static struct volfs *vol_ventry_volfs(ventry *ve)
{
    return (struct volfs *) ve->mnt->avfs->data;
}

/****************************************************************/
/* start of avfs ops                                            */

/* called by vol_do_lookup */
static struct volentry *vol_get_entry(struct volentry *parent,
                                      const char *name)
{
    struct volentry **entp;
    struct volentry *ent;

    if(strcmp(name, ".") == 0) {
        ent = parent;
	av_ref_obj(ent);
	return ent;
    }
    if(strcmp(name, "..") == 0) {
        ent = parent->parent;
	av_ref_obj(ent);
	return ent;
    }
    for(entp = &parent->node->subdir; *entp != NULL; entp = &(*entp)->next)
	if(strcmp(name, (*entp)->name) == 0) {
	    ent = *entp;
	    av_ref_obj(ent);
	    return ent;
	}

    /* lookup failed, so create a new entry and add it to the
       directory list temporarily */
 
    ent = vol_new_entry(name);
    
    *entp = ent;
    ent->prevp = entp;
    ent->parent = parent;
    av_ref_obj(parent);

    return ent;
}

/* called by vol_lookup */
static int vol_do_lookup(struct volentry *parent, const char *name,
                         struct volentry **entp)
{
    if(parent->node == NULL)
        return -ENOENT;

    if(name == NULL) {
        *entp = parent->parent;
        av_ref_obj(*entp);
        return 0;
    }

    if(!AV_ISDIR(parent->node->st.mode))
        return -ENOTDIR;

    *entp = vol_get_entry(parent, name);
    
    return 0;
}

/* called by vol_lookup */
static struct volentry *vol_get_root(ventry *ve)
{
    struct volfs *fs = vol_ventry_volfs(ve);
    struct volentry *root = fs->root;

    av_ref_obj(root);

    return root;
}

static int vol_lookup(ventry *ve, const char *name, void **newp)
{
    int res = 0;
    struct volentry *parent = vol_ventry_volentry(ve);
    struct volentry *ent;
    
    if(parent == NULL) {
        if(name[0] != '\0' || ve->mnt->opts[0] != '\0')
            return -ENOENT;

        ent = vol_get_root(ve);
    }
    else {
        res = vol_do_lookup(parent, name, &ent);
        if(res < 0)
            return res;
        
        av_unref_obj(parent);
    }

    *newp = ent;

    if(ent != NULL && ent->node != NULL)
        return AV_TYPE(ent->node->st.mode);
    else
        return 0;
}

/* called by vol_getpath */
static char *vol_create_path(struct volentry *ent)
{
    char *path;
    
    if(ent->parent == NULL)
        return av_strdup("");
    
    path = vol_create_path(ent->parent);

    return av_stradd(path, "/", ent->name, NULL);
}

static int vol_getpath(ventry *ve, char **resp)
{
    struct volentry *ent = vol_ventry_volentry(ve);

    *resp = vol_create_path(ent);

    return 0;
}

static void vol_putent(ventry *ve)
{
    struct volentry *ent = vol_ventry_volentry(ve);

    av_unref_obj(ent);
}

static int vol_copyent(ventry *ve, void **resp)
{
    struct volentry *ent = vol_ventry_volentry(ve);
    
    av_ref_obj(ent);

    *resp = (void *) ent;

    return 0;
}

/* called by vol_open and vol_truncate */
static void vol_truncate_node(struct volnode *nod, avoff_t length)
{
    nod->st.size = length;
    nod->st.blocks = AV_DIV(nod->st.size, 512);
    av_curr_time(&nod->st.mtime);
}

/* called by vol_open_check_type */
static int vol_need_write(int flags)
{
    if((flags & AVO_ACCMODE) == AVO_WRONLY ||
       (flags & AVO_ACCMODE) == AVO_RDWR ||
       (flags & AVO_TRUNC) != 0)
        return 1;
    
    return 0;
}

/* called by vol_open_check */
static int vol_open_check_type(avmode_t mode, int flags)
{
    if((flags & AVO_DIRECTORY) != 0 && !AV_ISDIR(mode))
        return -ENOTDIR;
    
    switch(mode & AV_IFMT) {
    case AV_IFREG:
        return 0;
        
    case AV_IFDIR:
        if(vol_need_write(flags))
            return -EISDIR;
        return 0;

    case AV_IFLNK:
        if((flags & AVO_ACCMODE) != AVO_NOPERM || !(flags & AVO_NOFOLLOW))
            return -ENOENT;
        return 0;

    default:
        /* FIFO, char/bockdev, socket */
        if((flags & AVO_ACCMODE) != AVO_NOPERM)
            return -ENXIO;
        return 0;
    }
}

/* called by vol_open */
static int vol_open_check(struct volnode *nod, int flags)
{
    if(nod == NULL) {
        if(!(flags & AVO_CREAT))
            return -ENOENT;
        return 0;
    }

    if((flags & AVO_EXCL) != 0)
        return -EEXIST;

    return vol_open_check_type(nod->st.mode, flags);
}

static int vol_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    struct volfs *fs = vol_ventry_volfs(ve);
    struct volentry *ent = vol_ventry_volentry(ve);
    
    /* check permissions */
    res = vol_open_check(ent->node, flags);
    if(res < 0)
        return res;

    /* create the file if it doesn't exist yet */
    if(ent->node == NULL) {
        res = vol_make_node(fs, ent, mode | AV_IFREG);
        if(res < 0)
            return res;
    }
    else if((flags & AVO_TRUNC) != 0)
        vol_truncate_node(ent->node, 0);

    av_ref_obj(ent->node);
    
    *resp = ent->node;

    return 0;
}

static int vol_close(vfile *vf)
{
    struct volnode *nod = vol_vfile_volnode(vf);

    av_unref_obj(nod);

    return 0;
}

static avssize_t vol_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avoff_t nact;
    struct volnode *nod = vol_vfile_volnode(vf);

    if(AV_ISDIR(nod->st.mode))
        return -EISDIR;
    
    if(vf->ptr >= nod->st.size)
	return 0;
    
    nact = AV_MIN(nbyte, (avsize_t) (nod->st.size - vf->ptr));
    
    memcpy(buf, nod->content + vf->ptr, nact);
    
    vf->ptr += nact;
    
    return nact;
}

static avssize_t vol_write(vfile *vf, const char *buf, avsize_t nbyte)
{
    avoff_t end;
    struct volnode *nod = vol_vfile_volnode(vf);

    if((vf->flags & AVO_APPEND) != 0)
        vf->ptr = nod->st.size;

    end = vf->ptr + nbyte;
    if(end > nod->st.size) {
        nod->content = av_realloc(nod->content, end);
        nod->st.size = end;
        nod->st.blocks = AV_DIV(nod->st.size, 512);
    }

    memcpy(nod->content + vf->ptr, buf, nbyte);

    av_curr_time(&nod->st.mtime);

    vf->ptr = end;

    return nbyte;
}

static int vol_truncate(vfile *vf, avoff_t length)
{
    struct volnode *nod = vol_vfile_volnode(vf);

    if(length < nod->st.size)
        vol_truncate_node(nod, length);

    return 0;
}

/* called by vol_nth_entry */
static struct volnode *vol_special_entry(int n, struct volnode *nod,
                                      const char **namep)
{
    if(n == 0) {
        *namep = ".";
        return nod;
    }
    else {
        *namep = "..";
        return nod->parent->node;
    }
}

/* called by vol_readdir */
static struct volnode *vol_nth_entry(int n, struct volnode *nod,
                                     const char **namep)
{
    struct volentry *ent;
    int i;

    if(nod->parent != NULL) {
        if(n  < 2)
            return vol_special_entry(n, nod, namep);

        n -= 2;
    }

    ent = nod->subdir;
    for(i = 0; i < n && ent != NULL; i++)
        ent = ent->next;
    
    if(ent == NULL)
        return NULL;

    *namep = ent->name;
    return ent->node;
}

static int vol_readdir(vfile *vf, struct avdirent *buf)
{
    struct volnode *parent = vol_vfile_volnode(vf);
    struct volnode *nod;
    const char *name;
    
    if(!AV_ISDIR(parent->st.mode))
        return -ENOTDIR;
    
    nod = vol_nth_entry(vf->ptr, parent, &name);
    if(nod == NULL)
        return 0;

    buf->name = av_strdup(name);
    buf->ino = nod->st.ino;
    buf->type = AV_TYPE(nod->st.mode);
    
    vf->ptr ++;
    
    return 1;
}

static int vol_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    struct volnode *nod = vol_vfile_volnode(vf);

    *buf = nod->st;

    return 0;
}

static void vol_set_attributes(struct avstat *dest, const struct avstat *src,
                               int attrmask)
{
    if((attrmask & AVA_ATIME) != 0)
        dest->atime = src->atime;
    if((attrmask & AVA_MTIME) != 0)
        dest->mtime = src->mtime;
    if((attrmask & AVA_MODE) != 0)
        dest->mode = (dest->mode & AV_IFMT) | src->mode;
    if((attrmask & AVA_UID) != 0)
        dest->uid = src->uid;
    if((attrmask & AVA_GID) != 0)
        dest->gid = src->gid;
}

static int vol_setattr(vfile *vf, struct avstat *buf, int attrmask)
{
    struct volnode *nod = vol_vfile_volnode(vf);

    vol_set_attributes(&nod->st, buf, attrmask);
    
    return 0;
}

static int vol_access(ventry *ve, int amode)
{
    struct volnode *nod = vol_ventry_volentry(ve)->node;

    if(nod == NULL) 
        return -ENOENT;
    
    return 0;
}

static int vol_readlink(ventry *ve, char **bufp)
{
    struct volnode *nod = vol_ventry_volentry(ve)->node;

    if(nod == NULL)
        return -ENOENT;

    if(!AV_ISLNK(nod->st.mode))
        return -EINVAL;

    *bufp = av_strdup(nod->content);

    return 0;
}

static int vol_unlink(ventry *ve)
{
    struct volentry *ent = vol_ventry_volentry(ve);

    if(ent->node == NULL)
        return -ENOENT;

    if(AV_ISDIR(ent->node->st.mode))
        return -EISDIR;
    
    vol_unlink_node(ent);

    return 0;
}

/* called by vol_rmdir */
static int vol_check_rmdir(struct volentry *ent)
{
    struct volnode *nod = ent->node;

    if(nod == NULL)
        return -ENOENT;

    if(!AV_ISDIR(nod->st.mode)) 
        return -ENOTDIR;

    if(nod->subdir != NULL)
        return -ENOTEMPTY;

    if(ent->parent == NULL)
        return -EBUSY;

    return 0;
}

static int vol_rmdir(ventry *ve)
{
    int res;
    struct volentry *ent = vol_ventry_volentry(ve);

    res = vol_check_rmdir(ent);
    if(res < 0) 
        return res;

    vol_unlink_node(ent);
    
    return 0;
}

static int vol_mkdir(ventry *ve, avmode_t mode)
{
    int res;
    struct volfs *fs = vol_ventry_volfs(ve);
    struct volentry *ent = vol_ventry_volentry(ve);
    
    if(ent->node != NULL)
        return -EEXIST;
    
    res = vol_make_node(fs, ent, mode | AV_IFDIR);
    if(res < 0)
        return res;

    return 0;
}

static int vol_mknod(ventry *ve, avmode_t mode, avdev_t dev)
{
    int res;
    struct volfs *fs = vol_ventry_volfs(ve);
    struct volentry *ent = vol_ventry_volentry(ve);
    
    if(ent->node != NULL)
        return -EEXIST;
    
    res = vol_make_node(fs, ent, mode);
    if(res < 0)
        return res;

    ent->node->st.rdev = dev;

    return 0;
}

/* called by vol_check_rename */
static int vol_is_subdir(struct volentry *dir, struct volentry *basedir)
{
    while(1) {
        if(dir == basedir)
            return 1;

        if(dir->parent == NULL)
            break;

        dir = dir->parent;
    }

    return 0;
}

/* called by vol_rename */
static int vol_check_rename(struct volentry *ent, struct volentry *newent)
{
    if(ent->node == NULL)
        return -ENOENT;

    if(newent->name == NULL)
        return -ENOENT;

    if(AV_ISDIR(ent->node->st.mode) && vol_is_subdir(newent, ent))
        return -EINVAL;

    if(newent->node != NULL) {
        if(AV_ISDIR(ent->node->st.mode)) {
            if(!AV_ISDIR(newent->node->st.mode))
                return -ENOTDIR;

            if(newent->node->subdir != NULL)
                return -ENOTEMPTY;
        }
        else {
            if(AV_ISDIR(newent->node->st.mode))
               return -EISDIR;
        }
        vol_unlink_node(newent);
    }

    return 0;
}

static int vol_rename(ventry *ve, ventry *newve)
{
    int res;
    struct volentry *ent = vol_ventry_volentry(ve);
    struct volentry *newent = vol_ventry_volentry(newve);

    if(ent->node != NULL && ent == newent)
        return 0;

    res = vol_check_rename(ent, newent);
    if(res < 0)
        return res;

    vol_link_node(newent, ent->node);
    vol_unlink_node(ent);

    return 0;
}

/* called by vol_link */
static int vol_check_link(struct volentry *ent, struct volentry *newent)
{
    if(ent->node == NULL)
        return -ENOENT;

    if(newent->name == NULL)
        return -ENOENT;

    if(AV_ISDIR(ent->node->st.mode))
        return -EPERM;
    
    if(newent->node != NULL)
        return -EEXIST;
    
    return 0;
}

static int vol_link(ventry *ve, ventry *newve)
{
    int res;
    struct volentry *ent = vol_ventry_volentry(ve);
    struct volentry *newent = vol_ventry_volentry(newve);
    
    res = vol_check_link(ent, newent);
    if(res < 0)
        return res;

    vol_link_node(newent, ent->node);
    
    return 0;
}

static int vol_symlink(const char *path, ventry *newve)
{
    int res;
    struct volfs *fs = vol_ventry_volfs(newve);
    struct volentry *ent = vol_ventry_volentry(newve);
    
    if(ent->node != NULL)
        return -EEXIST;

    res = vol_make_node(fs, ent, 0777 | AV_IFLNK);
    if(res < 0)
        return res;
    
    ent->node->content = av_strdup(path);
    ent->node->st.size = strlen(path);

    return 0;
}

static void vol_destroy(struct avfs *avfs)
{
    struct volfs *fs = (struct volfs *) avfs->data;

    vol_free_tree(fs->root);
    av_unref_obj(fs->root);
    av_free(fs);
}

/* end of avfs ops                                              */
/****************************************************************/

extern int av_init_module_volatile(struct vmodule *module);

int av_init_module_volatile(struct vmodule *module)
{
    int res;
    struct avfs *avfs;
    struct volfs *fs;

    res = av_new_avfs("volatile", NULL, AV_VER, AVF_ONLYROOT, module, &avfs);
    if(res < 0)
        return res;

    avfs->destroy = vol_destroy;

    AV_NEW(fs);

    avfs->data = (void *) fs;

    fs->root = vol_new_entry("/");
    fs->avfs = avfs;

    vol_make_node(fs, fs->root, 0755 | AV_IFDIR);

    avfs->lookup    = vol_lookup;
    avfs->putent    = vol_putent;
    avfs->copyent   = vol_copyent;
    avfs->getpath   = vol_getpath;
    
    avfs->open      = vol_open;
    avfs->close     = vol_close;
    avfs->read      = vol_read;
    avfs->write     = vol_write;
    avfs->readdir   = vol_readdir;
    avfs->getattr   = vol_getattr;
    avfs->setattr   = vol_setattr;
    avfs->truncate  = vol_truncate;

    avfs->access    = vol_access;
    avfs->readlink  = vol_readlink;
    avfs->unlink    = vol_unlink;
    avfs->rmdir     = vol_rmdir;
    avfs->mkdir     = vol_mkdir;
    avfs->mknod     = vol_mknod;
    avfs->rename    = vol_rename;
    avfs->link      = vol_link;
    avfs->symlink   = vol_symlink;

    av_add_avfs(avfs);
    
    return 0;
}
