/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define VDEV_SEP_CHAR '#'

struct fileinfo __av_dtable[AVFS_DTABLE_SIZE];
char __av_cwd[PATHBUF_LEN];
pthread_mutex_t __av_cwdlock;
int __av_virtcwd;

static int path_valid_virtual(const char *path)
{
    const char *s = path;

    while(*s == '/')
        s++;
    
    for(; *s != '\0'; s++) {
        if(*s == '/')
            return 0;
        if(*s == ':')
            return 1;
    }
    
    return 0;
}

int __av_path_local(const char *path)
{
    if(strchr(path, VDEV_SEP_CHAR) == NULL) {
        if(strchr(path, ':') == NULL)
            return 1;
        else if(path_valid_virtual(path))
            return 0;
        else
            return 1;
    }
    else
        return 0;
}


static int make_abs_path(const char *path, char *pathbuf)
{
    unsigned int len;

    if(__av_cwd[0] == '\0') {
        if(getcwd(__av_cwd, PATHBUF_LEN) == NULL)
            return -errno;
    }

    len = strlen(__av_cwd) + 1 + strlen(path);
    if(len >= PATHBUF_LEN)
        return -ENAMETOOLONG;

    sprintf(pathbuf, "%s/%s", __av_cwd, path);

    return 0;
}

static int try_convert_path(const char *path, char *pathbuf)
{
    const char *s;
    const char *prefixenv;

    if(strlen(path) + 32 > PATHBUF_LEN)
        return 0;
    
    for(s = path; *s != '\0'; s++) {
        if(*s == ':')
            break;

        if(!isalpha((int) *s) && !isdigit((int) *s) && *s != '-' && *s != '.')
            return 0;
    }

    if(s == path || *s == '\0' || (s[1] != '/' && s[1] != '\0'))
        return 0;
    
    prefixenv = getenv("AVFS_HOST_PREFIX");
    if(prefixenv == NULL)
        prefixenv = "rsh:";

    if(strlen(path) + strlen(prefixenv) + 32 > PATHBUF_LEN)
        return 0;

    sprintf(pathbuf, "/%c%s%.*s%s", VDEV_SEP_CHAR, prefixenv,
            s - path, path, s + 1);
    
    return 1;
}

int __av_get_abs_path(const char *path, char *pathbuf, const char **resp)
{
    int res;

    if(path[0] == '/') {
        if(strchr(path, ':') != NULL) {
            const char *s;

            for(s = path; *s == '/'; s++);
            if(try_convert_path(s, pathbuf)) {
                *resp = pathbuf;
                return 0;
            }
        }
        *resp = path;
        return 0;
    }

    if(strchr(path, ':') != NULL) {
        if(try_convert_path(path, pathbuf)) {
            *resp = pathbuf;
            return 0;
        }
    }

    pthread_mutex_lock(&__av_cwdlock);
    res = make_abs_path(path, pathbuf);
    pthread_mutex_unlock(&__av_cwdlock);
    if(res == 0)
        *resp = pathbuf;

    return res;
}

