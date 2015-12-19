/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "internal.h"

static void default_destroy(struct avfs *avfs)
{
}

static int default_lookup(ventry *ve, const char *name, void **newp)
{
    char *path = (char *) ve->data;
    
    if(path == NULL)
	path = av_strdup(name);
    else if(name == NULL || strcmp(name, "..") == 0) {
	char *s;
	s = strrchr(path, AV_DIR_SEP_CHAR);
	if(s == NULL) {
	    av_free(path);
	    path = NULL;
	}
	else 
	    *s = '\0';
    }
    else if(strcmp(name, ".") != 0)
	path = av_stradd(path, AV_DIR_SEP_STR, name, NULL);
    
    *newp = path;

    return 0;
}

static void default_putent(ventry *ve)
{
    char *path = (char *) ve->data;

    av_free(path);
}

static int default_copyent(ventry *ve, void **resp)
{
    char *path = (char *) ve->data;
    
    *resp =  (void *) av_strdup(path);
    
    return 0;
}

static int default_getpath(ventry *ve, char **resp)
{
    char *path = (char *) ve->data;
    
    *resp =  av_strdup(path);

    return 0;
}

static int default_access(ventry *ve, int amode)
{
    return -EINVAL;
}

static int default_readlink(ventry *ve, char **bufp)
{
    return -EINVAL;
}

static int default_symlink(const char *path, ventry *newve)
{
    return -ENOSYS;
}

static int default_unlink(ventry *ve)
{
    return -ENOSYS;
}

static int default_rmdir(ventry *ve)
{
    return -ENOSYS;
}

static int default_mknod(ventry *ve, avmode_t mode, avdev_t dev)
{
    return -ENOSYS;
}

static int default_mkdir(ventry *ve, avmode_t mode)
{
    return -ENOSYS;
}

static int default_rename(ventry *ve, ventry *newve)
{
    return -ENOSYS;
}

static int default_link(ventry *ve, ventry *newve)
{
    return -ENOSYS;
}

static int default_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    return -ENOSYS;
}

static int default_close(vfile *vf)
{
    return 0;
}

static avssize_t default_read(vfile *vf, char *buf, avsize_t nbyte)
{
    return -ENOSYS;
}

static avssize_t default_write(vfile *vf, const char *buf,
			       avsize_t nbyte)
{
    return -ENOSYS;
}

static int default_readdir(vfile *vf, struct avdirent *buf)
{
    return -ENOSYS;
}

static int default_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    return -ENOSYS;
}

static int default_setattr(vfile *vf, struct avstat *buf, int attrmask)
{
    return -ENOSYS;
}

static int default_truncate(vfile *vf, avoff_t length)
{
    return -ENOSYS;
}

static avoff_t get_size(vfile *vf)
{
    int res;
    struct avfs *avfs = vf->mnt->avfs;
    struct avstat stbuf;

    res = avfs->getattr(vf, &stbuf, AVA_SIZE);
    if(res < 0)
	return res;

    return stbuf.size;
}

static avoff_t default_lseek(vfile *vf, avoff_t offset, int whence)
{
    avoff_t res;

    switch(whence) {
    case AVSEEK_SET:
	res = offset;
	break;
	
    case AVSEEK_CUR:
	res = vf->ptr + offset;
	break;
	
    case AVSEEK_END:
	res = get_size(vf);
	if(res < 0)
	    return res;

	res = res + offset;
	break;
	
    default:
        return -EINVAL;
    }

    if(res < 0)
        return -EINVAL;

    vf->ptr = res;

    return res;
}

void av_default_avfs(struct avfs *avfs)
{
    avfs->destroy    = default_destroy;

    avfs->lookup     = default_lookup;
    avfs->putent     = default_putent;
    avfs->copyent    = default_copyent;
    avfs->getpath    = default_getpath;

    avfs->access     = default_access;
    avfs->readlink   = default_readlink;
    avfs->symlink    = default_symlink;
    avfs->unlink     = default_unlink;
    avfs->rmdir      = default_rmdir;
    avfs->mknod      = default_mknod;
    avfs->mkdir      = default_mkdir;
    avfs->rename     = default_rename;
    avfs->link       = default_link;

    avfs->open       = default_open;
    avfs->close      = default_close;
    avfs->read       = default_read;
    avfs->write      = default_write;
    avfs->readdir    = default_readdir;
    avfs->getattr    = default_getattr;
    avfs->setattr    = default_setattr;
    avfs->truncate   = default_truncate;
    avfs->lseek      = default_lseek;
}

