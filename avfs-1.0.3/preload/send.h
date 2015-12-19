/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed either under the terms of the GNU
    GPL or under the terms of the GNU LGPL.  See the files COPYING and
    COPYING.LIB.
*/

#define MAXSEG 10

struct avfs_out_message_segment {
    unsigned int len;
    const void *buf;
};

struct avfs_out_message {
    unsigned int num;
    struct avfs_out_message_segment seg[MAXSEG];
};

struct avfs_in_message_segment {
    unsigned int len;
    void *buf;
};

struct avfs_in_message {
    unsigned int num;
    struct avfs_in_message_segment seg[MAXSEG];
};

int __av_read_message(int sock, struct avfs_in_message *msg);
int __av_write_message(int sock, struct avfs_out_message *msg);

