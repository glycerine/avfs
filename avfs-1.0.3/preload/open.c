/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "utils.h"
#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>

#define CREATFLAGS (O_WRONLY | O_CREAT | O_TRUNC)

#ifdef HAVE_OPEN64
static int real_open64(const char *path, int flags, mode_t mode, int undersc)
{
    int res;

    if(undersc == 0) {
        static int (*prev)(const char *, int, mode_t);
        if(!prev)
            prev = (int (*)(const char *, int, mode_t))
                __av_get_real("open64");
        
        res = prev(path, flags, mode);
    }
    else {
        static int (*prev)(const char *, int, mode_t);
        if(!prev)
            prev = (int (*)(const char *, int, mode_t))
                __av_get_real("_open64");

        res = prev(path, flags, mode);

    }

    return res;
}
#endif

static int real_open32(const char *path, int flags, mode_t mode, int undersc)
{
    int res;

    if(undersc == 0) {
        static int (*prev)(const char *, int, mode_t);
        if(!prev)
            prev = (int (*)(const char *, int, mode_t))
                __av_get_real("open");
        
        res = prev(path, flags, mode);
    }
    else {
        static int (*prev)(const char *, int, mode_t);
        if(!prev)
            prev = (int (*)(const char *, int, mode_t))
                __av_get_real("_open");

        res = prev(path, flags, mode);

    }

    return res;
}

#ifdef HAVE_CREAT64
static int real_creat64(const char *path, mode_t mode, int undersc)
{
    int res;

    if(undersc == 0) {
        static int (*prev)(const char *, mode_t);
        if(!prev)
            prev = (int (*)(const char *, mode_t))
                __av_get_real("creat64");
        
        res = prev(path, mode);
    }
    else {
        static int (*prev)(const char *, mode_t);
        if(!prev)
            prev = (int (*)(const char *, mode_t))
                __av_get_real("_creat64");
        
        res = prev(path, mode);
    }

    return res;
}
#endif

static int real_creat32(const char *path, mode_t mode, int undersc)
{
    int res;

    if(undersc == 0) {
        static int (*prev)(const char *, mode_t);
        if(!prev)
            prev = (int (*)(const char *, mode_t))
                __av_get_real("creat");
        
        res = prev(path, mode);
    }
    else {
        static int (*prev)(const char *, mode_t);
        if(!prev)
            prev = (int (*)(const char *, mode_t))
                __av_get_real("_creat");
        
        res = prev(path, mode);
    }

    return res;
}

static int real_open(const char *path, int flags, mode_t mode, int undersc,
                       int is64, int creat)
{
    int res;
    
    is64 = is64; /* Possibly unused arg */

    if(creat) {
#ifdef HAVE_CREAT64            
        if(is64)
            res = real_creat64(path, mode, undersc);
        else
#endif
            res = real_creat32(path, mode, undersc);
    }
    else {
#ifdef HAVE_OPEN64
        if(is64)
            res = real_open64(path, flags, mode, undersc);
        else
#endif
            res = real_open32(path, flags, mode, undersc);
    }
    
    return res;
}


static int real_close(int fd, int undersc)
{
    if(undersc == 0) {
        static int (*prev)(int);
        
        if(!prev)
            prev = (int (*)(int)) __av_get_real("close");
        
        return prev(fd);
    }
    else {
        static int (*prev)(int);
        
        if(!prev)
            prev = (int (*)(int)) __av_get_real("_close");
        
        return prev(fd);
    }
}

static int real_unlink(const char *path)
{
    return unlink(path);
}

static int get_handle()
{
    int fh = -1;
    char dummyfile[64];
    int numtries;
    
    for(numtries = 0; numtries < 10; numtries++) {
        strcpy(dummyfile, "/tmp/.avfs_dummyfile_XXXXXX");
        mktemp(dummyfile);
        if(dummyfile[0] != '\0') {
            fh = real_open(dummyfile, O_RDONLY | O_CREAT | O_EXCL, 0600, 1,
                           1, 0);
            real_unlink(dummyfile);
        }
        if(fh != -1)
            break;
    }

    if(fh == -1)
        return -EIO;
  
    if(!FD_OK(fh)) {
        real_close(fh, 1);
        return -EIO;
    }

    if(ISVIRTUAL(fh)) {
        real_close(fh, 1);
        __av_dtable[fh].isvirtual = 0;
        return -EFAULT;
    }

    fcntl(fh, F_SETFD, FD_CLOEXEC); 

    __av_dtable[fh].isvirtual = 1;

    return fh;
}

static void free_handle(int fh)
{
    if(FD_OK(fh)) 
        __av_dtable[fh].isvirtual = 0;

    real_close(fh, 1);
}

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
    if(flags & O_SYNC)     avflags |= AVO_SYNC;

    return avflags;
}


static int cmd_open(const char *path, int flags, mode_t mode, char *pathbuf,
                    int *holderfd)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
    struct avfs_result result;
    const char *abspath;

    res = __av_get_abs_path(path, pathbuf, &abspath);
    if(res < 0)
        return res;

    cmd.type = CMD_OPEN;
    cmd.u.open.flags = oflags_to_avfs(flags);
    cmd.u.open.mode = mode;
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;
    outmsg.seg[1].len = strlen(abspath) + 1;
    outmsg.seg[1].buf = abspath;

    inmsg.seg[0].buf = &result;
    inmsg.seg[1].buf = pathbuf;

    res = __av_send_message(&outmsg, &inmsg, 1);
    if(res == -1)
        return -EIO;

    *holderfd = res;

    if(inmsg.seg[1].len == 0)
        pathbuf[0] = '\0';

    return result.result;
}

static int cmd_close(int serverfh)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
    struct avfs_result result;

    cmd.type = CMD_CLOSE;
    cmd.u.fdops.serverfh = serverfh;
    
    outmsg.num = 1;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;

    inmsg.seg[0].buf = &result;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    return result.result;
}


static int do_open(const char *path, int flags, mode_t mode, char *pathbuf)
{
    int serverfh;
    int holderfd;
    int fh;

    serverfh = cmd_open(path, flags, mode, pathbuf, &holderfd);
    if(serverfh < 0) {
        real_close(holderfd, 1);
        return serverfh;
    }

    fh = get_handle();
    if(fh < 0) {
        cmd_close(serverfh);
        real_close(holderfd, 1);
        return fh;
    }
    
    fcntl(holderfd, F_SETFD, FD_CLOEXEC);

    __av_dtable[fh].serverfh = serverfh;
    __av_dtable[fh].holderfd = holderfd;

    return fh;
}

static int virt_open(const char *path, int flags, mode_t mode, int undersc,
                     int is64, int creat)
{
    int res = 0;
    int local = 0;

    if(__av_maybe_local(path)) {
        res = real_open(path, flags, mode, undersc, is64, creat);
        local = __av_is_local(res, path);
    }
    
    if(!local) {
        int errnosave;
        char pathbuf[PATHBUF_LEN];

        errnosave = errno;
        res = do_open(path, flags, mode, pathbuf);
        errno = errnosave;
        if(pathbuf[0])
            res = real_open(pathbuf, flags, mode, undersc, is64, creat);
        else if(res < 0)
            errno = -res, res = -1;
    }

    return res;
}

static int virt_close(int fd, int undersc)
{
    int res;

    if(!FD_OK(fd) || !ISVIRTUAL(fd))
        res =  real_close(fd, undersc);
    else {
        int errnosave = errno;
        res = cmd_close(SERVERFH(fd));
        real_close(__av_dtable[fd].holderfd, 1);
        free_handle(fd);
        if(res < 0) 
            errno = -res, res = -1;
        else
            errno = errnosave;
    }

    return res;
}

#ifdef HAVE_OPEN64
int open64(const char *path, int flags, ...)
{
    va_list ap;
    mode_t mode;
    
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);

    return virt_open(path, flags, mode, 0, 1, 0);
}

int _open64(const char *path, int flags, mode_t mode)
{
    return virt_open(path, flags, mode, 1, 1, 0);
}
#endif

int open(const char *path, int flags, ...)
{
    va_list ap;
    mode_t mode;
    
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);

    return virt_open(path, flags, mode, 0, 0, 0);
}

int _open(const char *path, int flags, mode_t mode)
{
    return virt_open(path, flags, mode, 1, 0, 0);
}

#ifdef HAVE_CREAT64
int creat64(const char *path, mode_t mode)
{
    return virt_open(path, CREATFLAGS, mode, 0, 1, 1);
}

int _creat64(const char *path, mode_t mode)
{
    return virt_open(path, CREATFLAGS, mode, 1, 1, 1);
}
#endif

int creat(const char *path, mode_t mode)
{
    return virt_open(path, CREATFLAGS, mode, 0, 0, 1);
}

int _creat(const char *path, mode_t mode)
{
    return virt_open(path, CREATFLAGS, mode, 1, 0, 1);
}

int close(int fd)
{
    return virt_close(fd, 0);
}

int _close(int fd)
{
    return virt_close(fd, 1);
}

