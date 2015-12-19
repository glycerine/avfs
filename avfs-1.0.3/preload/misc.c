/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "utils.h"
#include <stdlib.h>

static int real_chdir(const char *path, int undersc)
{
    if(undersc == 0) {
        static int (*prev)(const char *);
        
        if(!prev)
            prev = (int (*)(const char *)) 
                __av_get_real("chdir");
        
        return prev(path);
    }
    else {
        static int (*prev)(const char *);
        
        if(!prev)
            prev = (int (*)(const char *)) 
                __av_get_real("_chdir");
        
        return prev(path);
    }
}

static char *real_getcwd(char *buf, size_t size, int undersc)
{
    if(undersc == 0) {
        static char *(*prev)(char *, size_t);
        
        if(!prev)
            prev = (char *(*)(char *, size_t)) 
                __av_get_real("getcwd");
        
        return prev(buf, size);
    }
    else {
        static char *(*prev)(char *, size_t);
        
        if(!prev)
            prev = (char *(*)(char *, size_t)) 
                __av_get_real("_getcwd");
        
        return prev(buf, size);
    }    
}

static int real_readlink(const char *path, char *buf, size_t bufsiz,
                           int undersc)
{
    if(undersc == 0) {
        static int (*prev)(const char *, char *, size_t);
        
        if(!prev)
            prev = (int (*)(const char *, char *, size_t))
                __av_get_real("readlink");
        
        return prev(path, buf, bufsiz);
    }
    else {
        static int (*prev)(const char *, char *, size_t);
        
        if(!prev)
            prev = (int (*)(const char *, char *, size_t))
                __av_get_real("_readlink");
        
        return prev(path, buf, bufsiz);
    }
}

static int cmd_resolve(const char *path, char *pathbuf, int *isvirtualp)
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
    
    cmd.type = CMD_RESOLVE;
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;
    outmsg.seg[1].len = strlen(abspath) + 1;
    outmsg.seg[1].buf = abspath;

    inmsg.seg[0].buf = &result;
    inmsg.seg[1].buf = pathbuf;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    *isvirtualp = result.u.resolve.isvirtual;

    return result.result;
}

static void set_avfs_cwd(const char *cwd, int isvirtual)
{
    pthread_mutex_lock(&__av_cwdlock);
    strcpy(__av_cwd, cwd);
    __av_virtcwd = isvirtual;
    pthread_mutex_unlock(&__av_cwdlock);
}

static int virt_chdir(const char *path, int undersc)
{
    int res = 0;
    int local = 0;

    if(__av_maybe_local(path)) {
        res = real_chdir(path, undersc);
        if(res == 0)
            set_avfs_cwd("", 0);
        local = __av_is_local(res, path);
    }
    
    if(!local) {
        int errnosave;
        char pathbuf[PATHBUF_LEN];
        int isvirtual;

        errnosave = errno;
        res = cmd_resolve(path, pathbuf, &isvirtual);
        errno = errnosave;
        if(res < 0)
            errno = -res, res = -1;
        else if(!isvirtual) {
            res = real_chdir(pathbuf, undersc);
            if(res == 0)
                set_avfs_cwd("", 0);
        }
        else {
            res = real_chdir("/", undersc);
            if(res == 0)
                set_avfs_cwd(pathbuf, 1);
        }
    }

    return res;
}

static char *getcwd_virt(char *buf, size_t size)
{
    if(size == 0) {
        errno = EINVAL;
        return NULL;
    }

    if(size < strlen(__av_cwd) + 1) {
        errno = ERANGE;
        return NULL;
    }

    if(buf == NULL) {
        buf = malloc(size);
        if(buf == NULL)
            return NULL;
    }
    
    strcpy(buf, __av_cwd);
    
    return buf;
}

static char *virt_getcwd(char *buf, size_t size, int undersc)
{
    char *cwd;

    pthread_mutex_lock(&__av_cwdlock);
    if(!__av_virtcwd) {
        pthread_mutex_unlock(&__av_cwdlock);
        return real_getcwd(buf, size, undersc);
    }
    
    cwd = getcwd_virt(buf, size);
    pthread_mutex_unlock(&__av_cwdlock);

    return cwd;
}

static int cmd_readlink(const char *path, char *buf, size_t bufsiz,
                        char *pathbuf)
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
    
    cmd.type = CMD_READLINK;
    cmd.u.readlink.bufsize = bufsiz;
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;
    outmsg.seg[1].len = strlen(abspath) + 1;
    outmsg.seg[1].buf = abspath;

    inmsg.seg[0].buf = &result;
    inmsg.seg[1].buf = pathbuf;
    inmsg.seg[2].buf = buf;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    if(inmsg.seg[1].len == 0)
        pathbuf[0] = '\0';

    return result.result;
}

static int virt_readlink(const char *path, char *buf, size_t bufsiz,
                         int undersc)
{
    int res = 0;
    int local = 0;

    if(__av_maybe_local(path)) {
        res = real_readlink(path, buf, bufsiz, undersc);
        local = __av_is_local(res, path);
    }
    
    if(!local) {
        int errnosave;
        char pathbuf[PATHBUF_LEN];

        errnosave = errno;
        res = cmd_readlink(path, buf, bufsiz, pathbuf);
        errno = errnosave;
        if(pathbuf[0])
            res = real_readlink(pathbuf, buf, bufsiz, undersc);
        else if(res < 0)
            errno = -res, res = -1;
    }

    return res;
}


int chdir(const char *path)
{
    return virt_chdir(path, 0);
}

int _chdir(const char *path)
{
    return virt_chdir(path, 1);
}

char *getcwd(char *buf, size_t size)
{
    return virt_getcwd(buf, size, 0);
}

char *_getcwd(char *buf, size_t size)
{
    return virt_getcwd(buf, size, 1);
}

int readlink(const char *path, char *buf, size_t bufsiz)
{
    return virt_readlink(path, buf, bufsiz, 0);
}

int _readlink(const char *path, char *buf, size_t bufsiz)
{
    return virt_readlink(path, buf, bufsiz, 1);
}
