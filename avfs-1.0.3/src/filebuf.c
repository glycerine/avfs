/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
/* filebuf.c
   
   Implements buffered i/o with avfs fs functions. Includes facilities
   for i/o multiplexing as well.
*/

#include "filebuf.h"

#include <fcntl.h>
#include <unistd.h>
#include <poll.h>

struct filebuf {
    int flags;
    int fd;
    avsize_t size;
    avsize_t ptr;
    avsize_t nbytes;
    char *buf;
    int eof;
    int avail;
};

static void free_filebuf(struct filebuf *fb)
{
    av_free(fb->buf);
    close(fb->fd);
}

struct filebuf *av_filebuf_new(int fd, int flags)
{
    struct filebuf *fb;
    int oflags;

    AV_NEW_OBJ(fb, free_filebuf);

    if(flags & FILEBUF_NONBLOCK) {
        oflags = fcntl(fd, F_GETFL);
        oflags = oflags == -1 ? 0 : oflags;
        fcntl(fd, F_SETFL, oflags | O_NONBLOCK);
    }

    fb->flags = flags;
    fb->fd = fd;
    fb->size = 0;
    fb->nbytes = 0;
    fb->ptr = 0;
    fb->buf = NULL;
    fb->eof = 0;
    fb->avail = 0;

    return fb;
}

int av_filebuf_eof(struct filebuf *fb)
{
    return fb->eof;
}

static void filebuf_fill_poll(struct filebuf *fbs[], struct pollfd *pf,
                              int numfbs)
{
    int i;

    for(i = 0; i < numfbs; i++) {
        pf[i].fd = -1;
        pf[i].events = 0;
        if(fbs[i] != NULL && !fbs[i]->eof) {
            pf[i].fd = fbs[i]->fd;
            if((fbs[i]->flags & FILEBUF_WRITE) != 0)
                pf[i].events = POLLOUT;
            else
                pf[i].events = POLLIN;
        }
    }
}

static void filebuf_check_poll(struct filebuf *fbs[], struct pollfd *pf,
                               int numfbs)
{
    int i;

    for(i = 0; i < numfbs; i++) {
        if(fbs[i] != NULL && !fbs[i]->eof) {
            if(pf[i].revents != 0)
                fbs[i]->avail = 1;
            else
                fbs[i]->avail = 0;
        }
    }
}
                               
int av_filebuf_check(struct filebuf *fbs[], unsigned int numfbs,
                       long timeoutms)
{
    int res;
    struct pollfd *pf;

    pf = (struct pollfd *) av_malloc(sizeof(*pf) * numfbs);
    filebuf_fill_poll(fbs, pf, numfbs);
    res = poll(pf, numfbs, timeoutms);
    if(res == -1) {
        av_log(AVLOG_ERROR, "filebuf: poll error: %s", strerror(errno));
        res = -EIO;
    }
    else if(res > 0) {
        filebuf_check_poll(fbs, pf, numfbs);
        res = 1;
    }
    av_free(pf);

    return res;
}

static avssize_t filebuf_real_read(struct filebuf *fb, char *buf,
                                   avsize_t nbytes)
{
    avssize_t res;

    if(!fb->avail)
        return 0;

    fb->avail = 0;
    res = read(fb->fd, buf, nbytes);
    if(res < 0) {
        av_log(AVLOG_ERROR, "filebuf: read error: %s", strerror(errno));
        return -EIO;
    }
    if(res == 0)
        fb->eof = 1;

    return res;
}

avssize_t av_filebuf_read(struct filebuf *fb, char *buf, avsize_t nbytes)
{
    if(fb->nbytes > 0) {
        avsize_t nact = AV_MIN(fb->nbytes, nbytes);
        
        memcpy(buf, fb->buf + fb->ptr, nact);
        fb->ptr += nact;
        fb->nbytes -= nact;

        return nact;
    }

    return  filebuf_real_read(fb, buf, nbytes);
}

avssize_t av_filebuf_write(struct filebuf *fb, const char *buf,
                             avsize_t nbytes)
{
    avssize_t res;

    if(!fb->avail)
        return 0;

    fb->avail = 0;
    res = write(fb->fd, buf, nbytes);
    if(res < 0) {
        av_log(AVLOG_ERROR, "filebuf: write error: %s", strerror(errno));
        return -EIO;
    }

    return res;
}

static avssize_t read_data(struct filebuf *fb)
{
    avssize_t res;
    const int readsize = 256;
    avsize_t newsize;

    if(fb->ptr != 0 && fb->nbytes != 0)
        memmove(fb->buf, fb->buf + fb->ptr, fb->nbytes);
        
    fb->ptr = 0;
    
    newsize = fb->nbytes + readsize;
    if(newsize > fb->size) {
        fb->buf = av_realloc(fb->buf, newsize);
        fb->size = newsize;
    }
    
    res = filebuf_real_read(fb, fb->buf + fb->nbytes, readsize);
    if(res > 0)
        fb->nbytes += res;

    return res;
}

static avssize_t filebuf_lineend(struct filebuf *fb)
{
    avssize_t res;
    char *start;
    char *s;

    do {
        start = fb->buf + fb->ptr;
        if(fb->nbytes > 0) {
            s = memchr(start, '\n', fb->nbytes);
            if(s != NULL)
                return (s + 1) - start;
        }

        if(fb->eof)
            return fb->nbytes;
        
        res = read_data(fb);
    } while(res > 0);

    return res;
}

int av_filebuf_readline(struct filebuf *fb, char **resp)
{
    avssize_t nbytes;

    *resp = NULL;

    nbytes = filebuf_lineend(fb);
    if(nbytes <= 0)
        return nbytes;
    
    *resp = av_strndup(fb->buf + fb->ptr, nbytes);

    fb->ptr += nbytes;
    fb->nbytes -= nbytes;

    return 1;
}

int av_filebuf_getline(struct filebuf *fb, char **linep, long timeoutms)
{
    int res;
    char *line;

    *linep = NULL;
    while(1) {
        res = av_filebuf_readline(fb, &line);
        if(res < 0)
            return res;
        if(res == 1)
            break;

        if(av_filebuf_eof(fb))
            return 1;

        res = av_filebuf_check(&fb, 1, timeoutms);
        if(res < 0)
            return res;

        if(res == 0) 
            return 0;
    }

    *linep = line;

    return 1;
}
