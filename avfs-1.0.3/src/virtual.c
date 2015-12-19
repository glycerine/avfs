/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "virtual.h"
#include "operutil.h"
#include "oper.h"
#include "internal.h"

#include <dirent.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/types.h>
#include <sys/stat.h>

static int oflags_to_avfs(int flags)
{
    int avflags;
  
    avflags = flags & O_ACCMODE;
    if(avflags == AVO_NOPERM)
	avflags = AVO_RDWR;

    if(flags & O_CREAT)    avflags |= AVO_CREAT;
    if(flags & O_EXCL)     avflags |= AVO_EXCL;
    if(flags & O_TRUNC)    avflags |= AVO_TRUNC;
    if(flags & O_APPEND)   avflags |= AVO_APPEND;
    if(flags & O_NONBLOCK) avflags |= AVO_NONBLOCK;
#ifdef O_SYNC
    if(flags & O_SYNC)     avflags |= AVO_SYNC;
#endif

    return avflags;
}

int virt_open(const char *path, int flags, mode_t mode)
{
    int res;
    int errno_save = errno;

    res = av_fd_open(path, oflags_to_avfs(flags), mode & 07777);
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return res;
}

int virt_close(int fd)
{
    int res;
    int errno_save = errno;

    res = av_fd_close(fd);
    if(res < 0) {
        errno = -res;
        return -1;
    }
    
    errno = errno_save;
    return 0;
}


ssize_t virt_write(int fd, const void *buf, size_t nbyte)
{
    ssize_t res;
    int errno_save = errno;

    res = av_fd_write(fd, buf, nbyte);
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return res;
}

ssize_t virt_read(int fd, void *buf, size_t nbyte)
{
    ssize_t res;
    int errno_save = errno;

    res = av_fd_read(fd, buf, nbyte);
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return res;
}

off_t virt_lseek(int fd, off_t offset, int whence)
{
    off_t res;
    int errno_save = errno;

    res = av_fd_lseek(fd, offset, whence);
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return res;
}

static void avstat_to_stat(struct stat *buf, struct avstat *avbuf)
{
    buf->st_dev     = avbuf->dev;
    buf->st_ino     = avbuf->ino;
    buf->st_mode    = avbuf->mode;
    buf->st_nlink   = avbuf->nlink;
    buf->st_uid     = avbuf->uid;
    buf->st_gid     = avbuf->gid;
    buf->st_rdev    = avbuf->rdev;
    buf->st_size    = avbuf->size;
    buf->st_blksize = avbuf->blksize;
    buf->st_blocks  = avbuf->blocks;
    buf->st_atime   = avbuf->atime.sec;
    buf->st_mtime   = avbuf->mtime.sec;
    buf->st_ctime   = avbuf->ctime.sec;
}

int virt_fstat(int fd, struct stat *buf)
{
    int res;
    struct avstat avbuf;
    int errno_save = errno;

    res = av_fd_getattr(fd, &avbuf, AVA_ALL);
    if(res < 0) {
        errno = -res;
        return -1;
    }
    avstat_to_stat(buf, &avbuf);

    errno = errno_save;
    return 0;
}

static int open_path(vfile *vf, const char *path, int flags, avmode_t mode)
{
    int res;
    ventry *ve;

    res = av_get_ventry(path, !(flags & AVO_NOFOLLOW), &ve);
    if(res < 0)
        return res;

    res = av_file_open(vf, ve, flags, mode);
    av_free_ventry(ve);

    return res;
}


static int common_stat(const char *path, struct stat *buf, int flags)
{
    int res;
    vfile vf;
    struct avstat avbuf;
    int errno_save = errno;

    res = open_path(&vf, path, AVO_NOPERM | flags, 0);
    if(res == 0) {
        res = av_file_getattr(&vf, &avbuf, AVA_ALL);
        av_file_close(&vf);
	if(res == 0)
	    avstat_to_stat(buf, &avbuf);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }
    
    errno = errno_save;
    return 0;
}

int virt_stat(const char *path, struct stat *buf)
{
    return common_stat(path, buf, 0); 
}

int virt_lstat(const char *path, struct stat *buf)
{
    return common_stat(path, buf, AVO_NOFOLLOW); 
}


#ifndef NAME_MAX
#define NAME_MAX 255
#endif

typedef struct {
    int fd;
    struct dirent entry;
    char _trail[NAME_MAX + 1];
} AVDIR;

DIR *virt_opendir(const char *path)
{
    AVDIR *dp;
    int res;
    int errno_save = errno;

    res = av_fd_open(path, AVO_DIRECTORY, 0);
    if(res < 0) {
        errno = -res;
        return NULL;
    }

    AV_NEW(dp);
    dp->fd = res;

    errno = errno_save;
    return (DIR *) dp;
}

int virt_closedir(DIR *dirp)
{
    int res;
    AVDIR *dp = (AVDIR *) dirp;
    int errno_save = errno;
    int fd;

    if(dp == NULL) {
	errno = EINVAL;
	return -1;
    }
    
    fd = dp->fd;
    av_free(dp);
    res = av_fd_close(fd);
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return 0;
}

void virt_rewinddir(DIR *dirp)
{
    int res;
    AVDIR *dp = (AVDIR *) dirp;
    int errno_save = errno;

    if(dp == NULL) {
	errno = EINVAL;
	return;
    }

    res = av_fd_lseek(dp->fd, 0, AVSEEK_SET);
    if(res < 0)
        errno = -res;

    errno = errno_save;
}

#define AVFS_DIR_RECLEN 256 /* just an arbitary number */

static void avdirent_to_dirent(struct dirent *ent, struct avdirent *avent,
			       avoff_t n)
{
    ent->d_ino = avent->ino;
#ifdef HAVE_D_OFF
    ent->d_off = n * AVFS_DIR_RECLEN; 
#endif
    ent->d_reclen = AVFS_DIR_RECLEN;
#ifdef HAVE_D_TYPE
    ent->d_type = avent->type;
#endif
    strncpy(ent->d_name, avent->name, NAME_MAX);
    ent->d_name[NAME_MAX] = '\0';
}

struct dirent *virt_readdir(DIR *dirp)
{
    int res;
    struct avdirent buf;
    avoff_t n;
    AVDIR *dp = (AVDIR *) dirp;
    int errno_save = errno;

    if(dp == NULL) {
	errno = EINVAL;
	return NULL;
    }
    res = av_fd_readdir(dp->fd, &buf, &n);
    if(res <= 0) {
        if(res < 0)
            errno = -res;
        else
            errno = errno_save;
        return NULL;
    }

    avdirent_to_dirent(&dp->entry, &buf, n);
    av_free(buf.name);

    errno = errno_save;
    return &dp->entry;
}


int virt_truncate(const char *path, off_t length)
{
    int res;
    vfile vf;
    int errno_save = errno;

    res = open_path(&vf, path, AVO_WRONLY, 0);
    if(res == 0) {
        av_file_truncate(&vf, length);
        av_file_close(&vf);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return 0;
}

static int common_setattr(const char *path, struct avstat *buf, int attrmask,
			  int flags)
{
    int res;
    int errno_save = errno;
    vfile vf;

    res = open_path(&vf, path, AVO_NOPERM | flags, 0);
    if(res == 0) {
        res = av_file_setattr(&vf, buf, attrmask);
	av_file_close(&vf);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return 0;
}

int virt_utime(const char *path, struct utimbuf *buf)
{
    struct avstat stbuf;

    if(buf == NULL) {
        int errno_save = errno;
	av_curr_time(&stbuf.mtime);
        errno = errno_save;
	stbuf.atime = stbuf.mtime;
    }
    else {
	stbuf.mtime.sec = buf->modtime;
	stbuf.mtime.nsec = 0;
	stbuf.atime.sec = buf->actime;
	stbuf.atime.nsec = 0;
    }
    
    return common_setattr(path, &stbuf, AVA_MTIME | AVA_ATIME, 0);
}

int virt_chmod(const char *path, mode_t mode)
{
    struct avstat stbuf;

    stbuf.mode = mode & 07777;

    return common_setattr(path, &stbuf, AVA_MODE, 0);
}

static int common_chown(const char *path, uid_t owner, gid_t grp, int flags)
{
    struct avstat stbuf;
    int attrmask = 0;
    
    stbuf.uid = owner;
    stbuf.gid = grp;

    if(owner != (uid_t) -1)
	attrmask |= AVA_UID;
    if(grp != (gid_t) -1)
	attrmask |= AVA_GID;

    return common_setattr(path, &stbuf, attrmask, flags);
}

int virt_chown(const char *path, uid_t owner, gid_t grp)
{
    return common_chown(path, owner, grp, 0);
}

int virt_lchown(const char *path, uid_t owner, gid_t grp)
{
    return common_chown(path, owner, grp, AVO_NOFOLLOW);
}

int virt_ftruncate(int fd, off_t length)
{
    int res;
    int errno_save = errno;
    
    res = av_fd_truncate(fd, length);
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return 0;
}

static int common_fsetattr(int fd, struct avstat *stbuf, int attrmask)
{
    int res;
    int errno_save = errno;
    
    res = av_fd_setattr(fd, stbuf, attrmask);
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return 0;
}

int virt_fchmod(int fd, mode_t mode)
{
    struct avstat stbuf;
    
    stbuf.mode = mode & 07777;

    return common_fsetattr(fd, &stbuf, AVA_MODE);
}

int virt_fchown(int fd, uid_t owner, gid_t grp)
{
    struct avstat stbuf;
    int attrmask = 0;
        
    stbuf.uid = owner;
    stbuf.gid = grp;

    if(owner != (uid_t) -1)
	attrmask |= AVA_UID;
    if(grp != (gid_t) -1)
	attrmask |= AVA_GID;

    return common_fsetattr(fd, &stbuf, attrmask);
}

int virt_access(const char *path, int amode)
{
    int res;
    ventry *ve;
    int errno_save = errno;

    res = av_get_ventry(path, 1, &ve);
    if(res == 0) {
	res = av_access(ve, amode);
	av_free_ventry(ve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return 0;
}

static int copy_readlink(char *buf, size_t bsiz, const char *avbuf)
{
    size_t nact;

    nact = strlen(avbuf);
    nact = AV_MIN(nact, bsiz);

    strncpy(buf, avbuf, nact);

    return (int) nact;
}

int virt_readlink(const char *path, char *buf, size_t bsiz)
{
    int res;
    ventry *ve;
    char *avbuf;
    int errno_save = errno;
   
    res = av_get_ventry(path, 0, &ve);
    if(res == 0) {
        res = av_readlink(ve, &avbuf);
	if(res == 0) {
	    res = copy_readlink(buf, bsiz, avbuf);
	    av_free(avbuf);
	}
	av_free_ventry(ve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return res;
}

int virt_unlink(const char *path)
{
    int res;
    ventry *ve;
    int errno_save = errno;

    res = av_get_ventry(path, 0, &ve);
    if(res == 0) {
        res = av_unlink(ve);
	av_free_ventry(ve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }
    
    errno = errno_save;
    return 0;
}

int virt_rmdir(const char *path)
{
    int res;
    ventry *ve;
    int errno_save = errno;

    res = av_get_ventry(path, 0, &ve);
    if(res == 0) {
        res = av_rmdir(ve);
	av_free_ventry(ve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }
    
    errno = errno_save;
    return 0;
}

int virt_mkdir(const char *path, mode_t mode)
{
    int res;
    ventry *ve;
    int errno_save = errno;

    res = av_get_ventry(path, 0, &ve);
    if(res == 0) {
        res = av_mkdir(ve, mode);
        av_free_ventry(ve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }
    
    errno = errno_save;
    return 0;
}

int virt_mknod(const char *path, mode_t mode, dev_t dev)
{
    int res;
    ventry *ve;
    int errno_save = errno;

    res = av_get_ventry(path, 0, &ve);
    if(res == 0) {
        res = av_mknod(ve, mode, dev);
	av_free_ventry(ve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }
    
    errno = errno_save;
    return 0;
}

int virt_symlink(const char *path, const char *newpath)
{
    int res;
    ventry *newve;
    int errno_save = errno;

    res = av_get_ventry(newpath, 0, &newve);
    if(res == 0) {
        res = av_symlink(path, newve);
	av_free_ventry(newve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }
    
    errno = errno_save;
    return 0;
}

int virt_rename(const char *path, const char *newpath)
{
    int res;
    ventry *ve;
    ventry *newve;
    int errno_save = errno;

    res = av_get_ventry(path, 0, &ve);
    if(res == 0) {
	res = av_get_ventry(newpath, 0, &newve);
	if(res == 0) {
            res = av_rename(ve, newve);
	    av_free_ventry(newve);
	}
	av_free_ventry(ve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }
    
    errno = errno_save;
    return 0;
}

int virt_link(const char *path, const char *newpath)
{
    int res;
    ventry *ve;
    ventry *newve;
    int errno_save = errno;

    res = av_get_ventry(path, 0, &ve);
    if(res == 0) {
	res = av_get_ventry(newpath, 0, &newve);
	if(res == 0) {
            res = av_link(ve, newve);
	    av_free_ventry(newve);
	}
	av_free_ventry(ve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }
    
    errno = errno_save;
    return 0;
}

int virt_remove(const char *path)
{
    struct stat stbuf;

    if(path != NULL) {
        if(virt_lstat(path, &stbuf) == 0) {
            if(S_ISDIR(stbuf.st_mode)) {
                return virt_rmdir(path);
            } else {
                return virt_unlink(path);
            }
        }
    }

    errno = EFAULT;
    return -1;
}

int virt_islocal(const char *path)
{
    int res;
    ventry *ve;
    int errno_save = errno;
    int erg = 0;

    res = av_get_ventry(path, 0, &ve);
    if(res == 0) {
        if(ve->mnt->base == NULL)
            erg = 1;
        else
            erg = 0;
        av_free_ventry(ve);
    }
    if(res < 0) {
        errno = -res;
        return -1;
    }

    errno = errno_save;
    return erg;
}
