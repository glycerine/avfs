/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed either under the terms of the GNU
    GPL or under the terms of the GNU LGPL.  See the files COPYING and
    COPYING.LIB.
*/

#include "send.h"

#include <stdlib.h>
#include <unistd.h>

#define BUFLEN 1024
struct buffer {
    int fd;
    char buf[BUFLEN];
    unsigned int ptr;
    unsigned int len;
    int error;
};

static int sock_write(int sock, const char *msg, unsigned int len)
{
    int res;

    while(len > 0) {
        res = write(sock, msg, len);
        if(res == -1)
            return -1;

        len -= res;
        msg += res;
    }

    return 0;
}

static void init_buffer(struct buffer *buf, int fd)
{
    buf->fd = fd;
    buf->ptr = 0;
    buf->len = 0;
    buf->error = 0;
}


static void read_buffer(struct buffer *buf, char *msg, unsigned int len)
{
    int res;

    while(len > 0) {
        if(buf->error != 0)
            return;

        if(buf->len == 0 && len > BUFLEN) {
            res = read(buf->fd, msg, len);
            if(res <= 0) {
                buf->error = -1;
                return;
            }
            
            len -= res;
            msg += res;
        }
        else if(len <= buf->len) {
            memcpy(msg, buf->buf + buf->ptr, len);
            buf->len -= len;
            buf->ptr += len;
            return;
        }
        else {
            memcpy(msg, buf->buf + buf->ptr, buf->len);
            msg += buf->len;
            len -= buf->len;
            buf->ptr = 0;

            res = read(buf->fd, buf->buf, BUFLEN);
            if(res <= 0)
                buf->error = -1;
            else
                buf->len = res;
        }
    }
}

static void write_buffer(struct buffer *buf, const char *msg, unsigned int len)
{
    unsigned int rem;

    while(len > 0) {
        if(buf->error != 0)
            return;

        if(buf->ptr == 0 && len > BUFLEN) {
            buf->error = sock_write(buf->fd, msg, len);
            return;
        }

        rem = BUFLEN - buf->ptr;
        if(len < rem) {
            memcpy(buf->buf + buf->ptr, msg, len);
            buf->ptr += len;
            return;
        }
        
        memcpy(buf->buf + buf->ptr, msg, rem);
        len -= rem;
        msg += rem;
        buf->error = sock_write(buf->fd, buf->buf, BUFLEN);
        buf->ptr = 0;
    }
}

static void flush_buffer(struct buffer *buf)
{
    if(buf->error != 0)
        return;
    
    buf->error = sock_write(buf->fd, buf->buf, buf->ptr);
}

int __av_read_message(int sock, struct avfs_in_message *msg)
{
    unsigned int lengths[MAXSEG];
    struct buffer buf;
    int i;

    init_buffer(&buf, sock);
    read_buffer(&buf, (void *) lengths, sizeof(int) * MAXSEG);

    for(i = 0; i < MAXSEG; i++) {
        msg->seg[i].len = lengths[i];
        if(lengths[i] != 0) {
            if(msg->seg[i].buf == NULL)
                msg->seg[i].buf = malloc(lengths[i]);
            
            read_buffer(&buf, msg->seg[i].buf, msg->seg[i].len);
        }
    }
    
    return buf.error;
}


int __av_write_message(int sock, struct avfs_out_message *msg)
{
    int i;
    unsigned int lengths[MAXSEG];
    struct buffer buf;

    for(i = 0; i < MAXSEG; i++) {
        if(i < msg->num)
            lengths[i] = msg->seg[i].len;
        else
            lengths[i] = 0;
    }

    init_buffer(&buf, sock);

    write_buffer(&buf, (void *) lengths, sizeof(int) * MAXSEG);
    
    for(i = 0; i < msg->num; i++)
        write_buffer(&buf, msg->seg[i].buf, msg->seg[i].len);

    flush_buffer(&buf);

    return buf.error;
}

