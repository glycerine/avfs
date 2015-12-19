/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#define _GNU_SOURCE /* necessary to get definition of RTLD_NEXT */

#include "cmd.h"
#include "client.h"
#include <dlfcn.h>
#include <pthread.h>

#define AVFS_DTABLE_SIZE 1024

struct fileinfo {
    int isvirtual;
    int serverfh;
    int holderfd;
};

extern struct fileinfo __av_dtable[AVFS_DTABLE_SIZE];
extern char __av_cwd[PATHBUF_LEN];
extern pthread_mutex_t __av_cwdlock;
extern int __av_virtcwd;

#define ISVIRTUAL(fd)    (__av_dtable[fd].isvirtual)
#define FD_OK(fd)        ((fd) >= 0 && (fd) < AVFS_DTABLE_SIZE)
#define SERVERFH(fd)     (__av_dtable[fd].serverfh)

int __av_get_abs_path(const char *path, char *pathbuf, const char **resp);
int __av_path_local(const char *path);

static inline void *__av_get_real(const char *name)
{
    void *res;
    int errnosave = errno;
    
    res = dlsym(RTLD_NEXT, name);
    errno = errnosave;

    return res;
}

static inline int __av_maybe_local(const char *path)
{
    int isvirtual;
    
    pthread_mutex_lock(&__av_cwdlock);
    isvirtual = __av_virtcwd;
    pthread_mutex_unlock(&__av_cwdlock);

    if(!isvirtual || path == NULL || path[0] == '/')
        return 1;
    else
        return 0;
}

static inline int __av_is_local(int res, const char *path)
{
    if(res != -1 || errno != ENOENT || __av_path_local(path))
        return 1;
    else
        return 0;
}
