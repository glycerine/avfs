/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "utils.h"
#include "config.h"

#include <dirent.h>


#ifdef HAVE_LSEEK64
static off64_t real_lseek64(int fd, off64_t offset, int whence, int undersc)
{
    if(undersc == 0) {
        static off64_t (*prev)(int, off64_t, int);
        
        if(!prev)
            prev = (off64_t (*)(int, off64_t, int)) __av_get_real("lseek64");
        
        return prev(fd, offset, whence);
    }
    else {
        static off64_t (*prev)(int, off64_t, int);
        
        if(!prev)
            prev = (off64_t (*)(int, off64_t, int)) __av_get_real("_lseek64");
        
        return prev(fd, offset, whence);
    }
}
#endif

static off_t real_lseek(int fd, off_t offset, int whence, int undersc)
{
    if(undersc == 0) {
        static off_t (*prev)(int, off_t, int);
        
        if(!prev)
            prev = (off_t (*)(int, off_t, int)) __av_get_real("lseek");
        
        return prev(fd, offset, whence);
    }
    else {
        static off_t (*prev)(int, off_t, int);
        
        if(!prev)
            prev = (off_t (*)(int, off_t, int)) __av_get_real("_lseek");
        
        return prev(fd, offset, whence);
    }
}


static ssize_t real_read(int fd, void *buf, size_t nbyte, int undersc)
{
    if(undersc == 0) {
        static ssize_t (*prev)(int, void *, size_t);
        
        if(!prev)
            prev = (ssize_t (*)(int, void *, size_t)) __av_get_real("read");
        
        return prev(fd, buf, nbyte);
    }
    else {
        static ssize_t (*prev)(int, void *, size_t);
        
        if(!prev)
            prev = (ssize_t (*)(int, void *, size_t)) __av_get_real("_read");
        
        return prev(fd, buf, nbyte);

    }
}

static ssize_t real_write(int fd, const void *buf, size_t nbyte, int undersc)
{
    if(undersc == 0) {
        static ssize_t (*prev)(int, const void *, size_t);
        
        if(!prev)
            prev = (ssize_t (*)(int, const void *, size_t))
                __av_get_real("write");
        
        return prev(fd, buf, nbyte);
    }
    else {
        static ssize_t (*prev)(int, const void *, size_t);
        
        if(!prev)
            prev = (ssize_t (*)(int, const void *, size_t))
                __av_get_real("_write");
        
        return prev(fd, buf, nbyte);

    }
}

#ifdef HAVE_GETDENTS64
static int real_getdents64(int fd, struct dirent64 *buf, size_t nbyte,
                           int undersc)
{
    if(undersc == 0) {
        static int (*prev)(int, struct dirent64 *, size_t);
        
        if(!prev)
            prev = (int (*)(int, struct dirent64 *, size_t)) 
                __av_get_real("getdents64");
        
        return prev(fd, buf, nbyte);
    }
    else {
        static int (*prev)(int, struct dirent64 *, size_t);
        
        if(!prev)
            prev = (int (*)(int, struct dirent64 *, size_t)) 
                __av_get_real("_getdents64");
        
        return prev(fd, buf, nbyte);
    }
}
#endif

static int real_getdents(int fd, struct dirent *buf, size_t nbyte,
                           int undersc)
{
    if(undersc == 0) {
        static int (*prev)(int, struct dirent *, size_t);
        
        if(!prev)
            prev = (int (*)(int, struct dirent *, size_t)) 
                __av_get_real("getdents");
        
        return prev(fd, buf, nbyte);
    }
    else {
        static int (*prev)(int, struct dirent *, size_t);
        
        if(!prev)
            prev = (int (*)(int, struct dirent *, size_t)) 
                __av_get_real("_getdents");
        
        return prev(fd, buf, nbyte);
    }
}

static avoff_t cmd_lseek(int serverfh, avoff_t offset, int whence)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
    struct avfs_result result;

    cmd.type = CMD_LSEEK;
    cmd.u.lseek.serverfh = serverfh;
    cmd.u.lseek.offset = offset;
    cmd.u.lseek.whence = whence;
    
    outmsg.num = 1;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;

    inmsg.seg[0].buf = &result;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    return result.u.lseek.offset;
}

static ssize_t cmd_read(int serverfh, void *buf, size_t nbyte)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
    struct avfs_result result;

    cmd.type = CMD_READ;
    cmd.u.readwrite.serverfh = serverfh;
    cmd.u.readwrite.nbyte = nbyte;
    
    outmsg.num = 1;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;

    inmsg.seg[0].buf = &result;
    inmsg.seg[1].buf = buf;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    return result.result;
}

static ssize_t cmd_write(int serverfh, const void *buf, size_t nbyte)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
    struct avfs_result result;

    cmd.type = CMD_WRITE;
    cmd.u.readwrite.serverfh = serverfh;
    cmd.u.readwrite.nbyte = nbyte;
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;
    outmsg.seg[1].len = nbyte;
    outmsg.seg[1].buf = buf;

    inmsg.seg[0].buf = &result;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    return result.result;
}

#ifdef HAVE_LSEEK64
static off64_t virt_lseek64(int fd, off64_t offset, int whence, int undersc)
{
    off64_t res;

    if(!FD_OK(fd) || !ISVIRTUAL(fd))
        res = real_lseek64(fd, offset, whence, undersc);
    else {
        int errnosave = errno;

        res = cmd_lseek(SERVERFH(fd), offset, whence);
        if(res < 0)
            errno = -res, res = -1;
        else
            errno = errnosave;
    }

    return res;
}
#endif

static off_t virt_lseek(int fd, off_t offset, int whence, int undersc)
{
    off_t res;

    if(!FD_OK(fd) || !ISVIRTUAL(fd))
        res = real_lseek(fd, offset, whence, undersc);
    else {
        int errnosave = errno;

        res = cmd_lseek(SERVERFH(fd), offset, whence);
        if(res < 0)
            errno = -res, res = -1;
        else
            errno = errnosave;
    }

    return res;
}

static ssize_t virt_read(int fd, void *buf, size_t nbyte, int undersc)
{
    ssize_t res;

    if(!FD_OK(fd) || !ISVIRTUAL(fd))
        res = real_read(fd, buf, nbyte, undersc);
    else {
        int errnosave = errno;

        res = cmd_read(SERVERFH(fd), buf, nbyte);
        if(res < 0)
            errno = -res, res = -1;
        else
            errno = errnosave;
    }

    return res;
}

static ssize_t virt_write(int fd, const void *buf, size_t nbyte, int undersc)
{
    ssize_t res;

    if(!FD_OK(fd) || !ISVIRTUAL(fd))
        res = real_write(fd, buf, nbyte, undersc);
    else {
        int errnosave = errno;

        res = cmd_write(SERVERFH(fd), buf, nbyte);
        if(res < 0)
            errno = -res, res = -1;
        else
            errno = errnosave;
    }

    return res;
}


static int cmd_readdir(int serverfh, struct avfs_direntry *de, char *name)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
    struct avfs_result result;

    cmd.type = CMD_READDIR;
    cmd.u.fdops.serverfh = serverfh;
    
    outmsg.num = 1;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;

    inmsg.seg[0].buf = &result;
    inmsg.seg[1].buf = de;
    inmsg.seg[2].buf = name;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    return result.result;
}

#ifdef HAVE_GETDENTS64
#define AVFS_DIR_RECLEN64 ((size_t)(((struct dirent64 *)0)->d_name)+NAME_MAX+1)

static void avfs_direntry_to_dirent64(struct dirent64 *ent,
                                 struct avfs_direntry *avent)
{
    ent->d_ino = avent->ino;
    ent->d_off = avent->n * AVFS_DIR_RECLEN64; 
    ent->d_reclen = AVFS_DIR_RECLEN64;
}

static int virt_getdents64(int fd, struct dirent64 *buf, size_t nbyte,
                           int undersc)
{
    int res;

    if(!FD_OK(fd) || !ISVIRTUAL(fd))
        res =  real_getdents64(fd, buf, nbyte, undersc);
    else {
        struct avfs_direntry de;
        int errnosave;

        if(nbyte < AVFS_DIR_RECLEN64) {
            errno = EINVAL;
            return -1;
        }

        errnosave = errno;
        res = cmd_readdir(SERVERFH(fd), &de, buf->d_name);
        errno = errnosave;
        if(res < 0) 
            errno = -res, res = -1;
        else if(res > 0) {
            avfs_direntry_to_dirent64(buf, &de);
            res = AVFS_DIR_RECLEN64;
        }
    }

    return res;
}
#endif

#define AVFS_DIR_RECLEN ((size_t)(((struct dirent *)0)->d_name)+NAME_MAX+1)

static void avfs_direntry_to_dirent(struct dirent *ent,
                                 struct avfs_direntry *avent)
{
    ent->d_ino = avent->ino;
    ent->d_off = avent->n * AVFS_DIR_RECLEN; 
    ent->d_reclen = AVFS_DIR_RECLEN;
}

static int virt_getdents(int fd, struct dirent *buf, size_t nbyte,
                           int undersc)
{
    int res;

    if(!FD_OK(fd) || !ISVIRTUAL(fd))
        res =  real_getdents(fd, buf, nbyte, undersc);
    else {
        struct avfs_direntry de;
        int errnosave;

        if(nbyte < AVFS_DIR_RECLEN) {
            errno = EINVAL;
            return -1;
        }

        errnosave = errno;
        res = cmd_readdir(SERVERFH(fd), &de, buf->d_name);
        errno = errnosave;
        if(res < 0) 
            errno = -res, res = -1;
        else if(res > 0) {
            avfs_direntry_to_dirent(buf, &de);
            res = AVFS_DIR_RECLEN;
        }
    }

    return res;
}


#ifdef HAVE_LSEEK64
off64_t lseek64(int fd, off64_t offset, int whence)
{
    return virt_lseek64(fd, offset, whence, 0);
}

off64_t _lseek64(int fd, off64_t offset, int whence)
{
    return virt_lseek64(fd, offset, whence, 1);
}
#endif

off_t lseek(int fd, off_t offset, int whence)
{
    return virt_lseek(fd, offset, whence, 0);
}

off_t _lseek(int fd, off_t offset, int whence)
{
    return virt_lseek(fd, offset, whence, 1);
}


ssize_t read(int fd, void *buf, size_t nbyte)
{
    return virt_read(fd, buf, nbyte, 0);
}

ssize_t _read(int fd, void *buf, size_t nbyte)
{
    return virt_read(fd, buf, nbyte, 1);
}

ssize_t write(int fd, const void *buf, size_t nbyte)
{
    return virt_write(fd, buf, nbyte, 0);
}

ssize_t _write(int fd, const void *buf, size_t nbyte)
{
    return virt_write(fd, buf, nbyte, 1);
}

#ifdef HAVE_GETDENTS64
int getdents64(int fd, struct dirent64 *buf, size_t nbyte)
{
    return virt_getdents64(fd, buf, nbyte, 0);
}

int _getdents64(int fd, struct dirent64 *buf, size_t nbyte)
{
    return virt_getdents64(fd, buf, nbyte, 1);
}
#endif

int getdents(int fd, struct dirent *buf, size_t nbyte)
{
    return virt_getdents(fd, buf, nbyte, 0);
}

int _getdents(int fd, struct dirent *buf, size_t nbyte)
{
    return virt_getdents(fd, buf, nbyte, 1);
}
