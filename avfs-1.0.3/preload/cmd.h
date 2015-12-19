/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed either under the terms of the GNU
    GPL or under the terms of the GNU LGPL.  See the files COPYING and
    COPYING.LIB.
*/

#include "avfs.h"
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>

enum avfs_cmd_type {
    CMD_GETATTR,
    CMD_OPEN,
    CMD_CLOSE,
    CMD_FSTAT,
    CMD_READDIR,
    CMD_LSEEK,
    CMD_READ,
    CMD_WRITE,
    CMD_RESOLVE,
    CMD_READLINK,
    CMD_ACCESS
};

struct avfs_cmd {
    enum avfs_cmd_type type;
    union {
        struct {
            int flags;
            int attrmask;
        } getattr;

        struct {
            int flags;
            avmode_t mode;
        } open;

        struct {
            int serverfh;
        } fdops;

        struct {
            int serverfh;
            avoff_t offset;
            int whence;
        } lseek;

        struct {
            int serverfh;
            avsize_t nbyte;
        } readwrite;

        struct {
            avsize_t bufsize;
        } readlink;

        struct {
            int amode;
        } access;
    } u;
};

struct avfs_result {
    int result;
    union {
        struct {
            avoff_t offset;
        } lseek;
        struct {
            int isvirtual;
        } resolve;
    } u;    
};

struct avfs_direntry {
    avino_t ino;
    int type;
    int n;
};

#define PATHBUF_LEN (PATH_MAX + 1)

#ifndef NAME_MAX
#define NAME_MAX 255
#endif
