/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "local.h"
#include "version.h"

#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

struct localfile {
    int fd;
    DIR *dirp;
    avoff_t entctr;
    char *path;
};

static struct localfile *local_vfile_file(vfile *vf)
{
    return (struct localfile *) vf->data;
}

static int avoflags_to_oflags(int avflags)
{
    int flags;
  
    flags = avflags & AVO_ACCMODE;
    if(avflags & AVO_CREAT)    flags |= O_CREAT;
    if(avflags & AVO_EXCL)     flags |= O_EXCL;
    if(avflags & AVO_TRUNC)    flags |= O_TRUNC;
    if(avflags & AVO_APPEND)   flags |= O_APPEND;
    if(avflags & AVO_NONBLOCK) flags |= O_NONBLOCK;
#ifdef O_SYNC
    if(avflags & AVO_SYNC)     flags |= O_SYNC;
#endif

    return flags;
}

static int local_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    struct localfile *fi;
    const char *path = (char *) ve->data;
    int fd;
    DIR *dirp;
    
    fd = -1;
    dirp = NULL;
    if((flags & AVO_ACCMODE) != AVO_NOPERM) {
        if(!(flags & AVO_DIRECTORY))
            fd = open(path, avoflags_to_oflags(flags), mode);
        else
            dirp = opendir(path);

        if(fd == -1 && dirp == NULL)
            return -errno;
        
        if(fd != -1)
            av_registerfd(fd);
    }
    
    AV_NEW(fi);

    fi->fd = fd;
    fi->dirp = dirp;
    fi->entctr = 0;
    fi->path = av_strdup(path);

    *resp = fi;

    return 0;
}

static int local_close(vfile *vf)
{
    int res = 0;
    struct localfile *fi = local_vfile_file(vf);

    if(fi->fd != -1)
        res = close(fi->fd);
    if(fi->dirp != NULL)
        res = closedir(fi->dirp);
    
    if(res == -1)
        res = -errno;

    av_free(fi->path);
    av_free(fi);

    return res;
}


static avssize_t local_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct localfile *fi = local_vfile_file(vf);

    res = read(fi->fd, buf, nbyte);
    if(res == -1)
        return -errno;

    vf->ptr += res;
    
    return res;
}

static avssize_t local_write(vfile *vf, const char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct localfile *fi = local_vfile_file(vf);

    res = write(fi->fd, buf, nbyte);
    if(res == -1)
        return -errno;

    /* NOTE: ptr will go astray if file is opened with O_APPEND */
    vf->ptr += res;

    return res;
}

static avoff_t local_lseek(vfile *vf, avoff_t offset, int whence)
{
    avoff_t res;
    struct localfile *fi = local_vfile_file(vf);

    res = lseek(fi->fd, offset, whence);
    if(res == -1)
        return -errno;
    
    vf->ptr = res;

    return res;
}

static int local_readdir(vfile *vf, struct avdirent *buf)
{
    struct dirent *de;
    struct localfile *fi = local_vfile_file(vf);

    if(vf->ptr < fi->entctr) {
	rewinddir(fi->dirp);
	fi->entctr = 0;
    }

    do {
	errno = 0;
	de = readdir(fi->dirp);
	if(de == NULL)
            return -errno;

	fi->entctr ++;
    } while(vf->ptr >= fi->entctr);

    buf->name = av_strdup(de->d_name);
    buf->ino = de->d_ino;
#ifdef HAVE_D_TYPE
    buf->type = de->d_type;
#else
    buf->type = 0;
#endif
    vf->ptr ++;

    return 1;
}

static int local_truncate(vfile *vf, avoff_t length)
{
    int res;
    struct localfile *fi = local_vfile_file(vf);
    
    if(fi->fd != -1)
        res = ftruncate(fi->fd, length);
    else
        res = truncate(fi->path, length);

    if(res == -1)
        return -errno;

    return 0;
}

static void stat_to_avstat(struct avstat *vbuf, struct stat *lbuf)
{
    vbuf->dev        = lbuf->st_dev;
    vbuf->ino        = lbuf->st_ino;
    vbuf->mode       = lbuf->st_mode;
    vbuf->nlink      = lbuf->st_nlink;
    vbuf->uid        = lbuf->st_uid;
    vbuf->gid        = lbuf->st_gid;
    vbuf->rdev       = lbuf->st_rdev;
    vbuf->size       = lbuf->st_size;
    vbuf->blksize    = lbuf->st_blksize;
    vbuf->blocks     = lbuf->st_blocks;
    vbuf->atime.sec  = lbuf->st_atime;
    vbuf->atime.nsec = 0;
    vbuf->mtime.sec  = lbuf->st_mtime;
    vbuf->mtime.nsec = 0;
    vbuf->ctime.sec  = lbuf->st_ctime;
    vbuf->ctime.nsec = 0;
}


static int local_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    int res;
    struct stat stbuf;
    struct localfile *fi = local_vfile_file(vf);

    if(fi->fd != -1)
        res = fstat(fi->fd, &stbuf);
    else if((vf->flags & AVO_NOFOLLOW) != 0)
        res = lstat(fi->path, &stbuf);
    else
        res = stat(fi->path, &stbuf);

    if(res == -1)
        return -errno;
    
    stat_to_avstat(buf, &stbuf);
    return 0;
}

static int local_set_time(struct localfile *fi, const struct avstat *buf,
                          int attrmask)
{
    struct utimbuf utbuf;
    
    utbuf.actime = buf->atime.sec;
    utbuf.modtime  = buf->mtime.sec;
    
    if(!(attrmask & AVA_ATIME))
        utbuf.actime = utbuf.modtime;
    if(!(attrmask & AVA_MTIME))
        utbuf.modtime = utbuf.actime;
    
    return utime(fi->path, &utbuf);
}

static int local_set_mode(struct localfile *fi, avmode_t mode)
{
    if(fi->fd != -1)
        return  fchmod(fi->fd, mode);
    else
        return chmod(fi->path, mode);
}

static int local_set_ugid(struct localfile *fi, const struct avstat *buf,
                          int attrmask, int flags)
{
    uid_t uid = (uid_t) -1;
    gid_t gid = (gid_t) -1;
    
    if((attrmask & AVA_UID) != 0)
        uid = buf->uid;
    if((attrmask & AVA_GID) != 0)
        gid = buf->gid;
    
    if(fi->fd != -1)
        return fchown(fi->fd, uid, gid);
    else if((flags & AVO_NOFOLLOW) != 0)
        return lchown(fi->path, uid, gid);
    else
        return chown(fi->path, uid, gid);
}

static int local_setattr(vfile *vf, struct avstat *buf, int attrmask)
{
    int res = 0;
    struct localfile *fi = local_vfile_file(vf);

    if((attrmask & (AVA_ATIME | AVA_MTIME)) != 0) 
        res = local_set_time(fi, buf, attrmask);
    if((attrmask & AVA_MODE) != 0)
        res = local_set_mode(fi, buf->mode);
    if((attrmask & (AVA_UID | AVA_GID)) != 0)
        res = local_set_ugid(fi, buf, attrmask, vf->flags);

    if(res == -1)
        return -errno;

    return 0;
}

static int local_access(ventry *ve, int amode)
{
    int res;
    const char *path = (char *) ve->data;
    
    res = access(path, amode);
    if(res == -1)
        return -errno;

    return 0;
}

static int local_readlink(ventry *ve, char **bufp)
{
    int res;
    unsigned int bufsize;
    char *buf;
    const char *path = (char *) ve->data;
    
    bufsize = 0;
    buf = NULL;
    do {
        bufsize += 1024;
        buf = av_realloc(buf, bufsize + 1);
        res = readlink(path, buf, bufsize);
        if(res == -1) {
            av_free(buf);
            return -errno;
        }
    } while(res >= bufsize);
    
    buf[res] = '\0';
    *bufp = buf;

    return 0;
}

static int local_unlink(ventry *ve)
{
    int res;
    char *path = (char *) ve->data;

    res = unlink(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int local_rmdir(ventry *ve)
{
    int res;
    char *path = (char *) ve->data;

    res = rmdir(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int local_mkdir(ventry *ve, avmode_t mode)
{
    int res;
    char *path = (char *) ve->data;

    res = mkdir(path, mode);
    if(res == -1)
        return -errno;

    return 0;
}

static int local_mknod(ventry *ve, avmode_t mode, avdev_t dev)
{
    int res;
    char *path = (char *) ve->data;

    res = mknod(path, mode, dev);
    if(res == -1)
        return -errno;

    return 0;
}

static int local_rename(ventry *ve, ventry *newve)
{
    int res;
    char *path = (char *) ve->data;
    char *newpath = (char *) newve->data;

    res = rename(path, newpath);
    if(res == -1)
        return -errno;

    return 0;
}

static int local_link(ventry *ve, ventry *newve)
{
    int res;
    char *path = (char *) ve->data;
    char *newpath = (char *) newve->data;

    res = link(path, newpath);
    if(res == -1)
        return -errno;

    return 0;
}

static int local_symlink(const char *path, ventry *newve)
{
    int res;
    char *newpath = (char *) newve->data;

    res = symlink(path, newpath);
    if(res == -1)
        return -errno;

    return 0;
}

static int local_lookup(ventry *ve, const char *name, void **newp)
{
    char *path = (char *) ve->data;

    
    if(path == NULL) {
        /* You can't access the local handler directly*/
        return -ENOENT;
    }
    else if(name != NULL) {
        if(path[0] == '/' && path[1] == '\0' && name[0] == '/')
            path[0] = '\0';
        path = av_stradd(path, name, NULL);
    }
    else {
        char *s;
        s = strrchr(path, AV_DIR_SEP_CHAR);
        if(s == NULL) {
            path[0] = '\0';
            path = av_stradd(path, ".", NULL);
        }
        else if(s != path)
            s[0] = '\0';
        else
            s[1] = '\0';
    }

    *newp = path;
    
    return 0;
}

int av_init_module_local()
{
    int res;
    int flags = AVF_NEEDSLASH | AVF_NOLOCK;
    struct avfs *avfs;

    res = av_new_avfs("local", NULL, AV_VER, flags, NULL, &avfs);
    if(res < 0)
        return res;

    avfs->lookup     = local_lookup;

    avfs->open       = local_open;
    avfs->close      = local_close;
    avfs->read       = local_read;
    avfs->write      = local_write;
    avfs->lseek      = local_lseek;
    avfs->readdir    = local_readdir;
    avfs->access     = local_access;
    avfs->getattr    = local_getattr;
    avfs->setattr    = local_setattr;
    avfs->readlink   = local_readlink;
    avfs->unlink     = local_unlink;
    avfs->rmdir      = local_rmdir;
    avfs->mkdir      = local_mkdir;
    avfs->mknod      = local_mknod;
    avfs->rename     = local_rename;
    avfs->link       = local_link;
    avfs->symlink    = local_symlink;
    avfs->truncate   = local_truncate;

    av_add_avfs(avfs);
    
    return 0;
}
