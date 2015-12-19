/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <sys/types.h>

struct child_message {
    int reqsize;
    int path1size;
    int path2size;
};


extern void run(int cfs, const char *codadir, int dm);
extern void child_process(int infd, int outfd);

extern int mount_coda(const char *dev, const char *dir, int devfd, int quiet);
extern int unmount_coda(const char *dir, int quiet);

extern void set_signal_handlers();
extern void clean_exit(int status);
extern void run_exit();
extern void user_child(pid_t pid);
