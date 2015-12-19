/*
    AVFS: A Virtual File System Library
    Copyright (C) 2010  Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    based on bzread.c
*/

#include "config.h"
#include "xzfile.h"
#include "lzma.h"
#include "oper.h"
#include "exit.h"

#include <stdlib.h>
#include <fcntl.h>


#define INBUFSIZE 16384
#define OUTBUFSIZE 32768
#define INITIAL_MEMLIMIT (100<<20)

struct xzstreamcache {
    int id;
    lzma_stream *s;
};

/* FIXME: the streamcache should be cleaned up after a short timeout
   because it uses a LOT of memory */

static struct xzstreamcache xzscache;
static int xzread_nextid;
static AV_LOCK_DECL(xzread_lock);

struct xzcache {
    int id;
    avoff_t size;
};

struct xzfile {
    lzma_stream *s;
    int iseof;
    int iserror;
    int id; /* The id of the last used xzcache */
    
    vfile *infile;
    char inbuf[INBUFSIZE];
};

void xz_internal_error(int errorcode)
{
    av_log(AVLOG_ERROR, "XZ: internal error %i", errorcode);
}

static avoff_t xz_total_in(lzma_stream *s)
{
    return (avoff_t) s->total_in;
}

static avoff_t xz_total_out(lzma_stream *s)
{
    return (avoff_t) s->total_out;
}

static void xz_delete_stream(lzma_stream *s)
{
    if(s != NULL) {
        lzma_end(s);
        
        av_free(s);
    }
}

static int xz_new_stream(lzma_stream **resp)
{
    int res;
    lzma_stream *s;
    lzma_stream tmp = LZMA_STREAM_INIT;

    AV_NEW(s);
    *s = tmp;

    /* TODO: choose good memory limit */
    res = lzma_auto_decoder(s, INITIAL_MEMLIMIT, 0);
    if(res != LZMA_OK) {
        *resp = NULL;
        av_log(AVLOG_ERROR, "XZ: decompress init error: %i", res);
        return -EIO;
    }

    *resp = s;
    return 0;
}

static void xzfile_scache_delete()
{
    AV_LOCK(xzread_lock);
    if(xzscache.id != 0) {
        xz_delete_stream(xzscache.s);
        xzscache.id = 0;
    }
    AV_UNLOCK(xzread_lock);
}

static void xzfile_scache_save(int id, lzma_stream *s)
{
    static int regdestroy = 0;
    if(!regdestroy) {
        regdestroy = 1;
        av_add_exithandler(xzfile_scache_delete);
    }

    if(id == 0 || s == NULL) {
        xz_delete_stream(s);
        return;
    }
    
    if(xzscache.id != 0)
        xz_delete_stream(xzscache.s);

    xzscache.id = id;
    xzscache.s = s;
}

static int xzfile_reset(struct xzfile *fil)
{
    /* FIXME: Is it a good idea to save the previous state or not? */
    if (fil->iseof || fil->iserror)
        xz_delete_stream(fil->s);
    else
        xzfile_scache_save(fil->id, fil->s);

    fil->iseof = 0;
    fil->iserror = 0;
    return xz_new_stream(&fil->s);
}

static int xzfile_fill_inbuf(struct xzfile *fil)
{
    avssize_t res;
    avoff_t inoff = xz_total_in(fil->s);

    res = av_pread(fil->infile, fil->inbuf, INBUFSIZE, inoff);
    if(res < 0)
        return res;
    
    fil->s->next_in = (uint8_t*)fil->inbuf;
    fil->s->avail_in = res;

    return 0;
}

static int xzfile_decompress(struct xzfile *fil, struct xzcache *zc)
{
    int res;
    unsigned char *start;

    if(fil->s->avail_in == 0) {
        res = xzfile_fill_inbuf(fil);
        if(res < 0)
            return res;
	if(fil->s->avail_in == 0) {
	  /* still no byte available */
	  av_log(AVLOG_ERROR, "XZ: decompress error");
	  return -EIO;
	}
    }
    
    start = (unsigned char*)( fil->s->next_out );

    res = lzma_code(fil->s, LZMA_RUN);
    if(res == LZMA_STREAM_END) {
        fil->iseof = 1;
        AV_LOCK(xzread_lock);
        zc->size = xz_total_out(fil->s);
        AV_UNLOCK(xzread_lock);
        return 0;
    }
    /*TODO handle LZMA_MEMLIMIT_ERROR */
    if(res != LZMA_OK) {
        av_log(AVLOG_ERROR, "XZ: decompress error: %i", res);
        return -EIO;
    }
    /*TODO what if avail_in is not 0? */
    
    return 0;
}


static int xzfile_read(struct xzfile *fil, struct xzcache *zc, char *buf,
                      avsize_t nbyte)
{
    int res;

    fil->s->next_out = (uint8_t*)buf;
    fil->s->avail_out = nbyte;
    while(fil->s->avail_out != 0 && !fil->iseof) {
        res = xzfile_decompress(fil, zc);
        if(res < 0)
            return res;
    }

    return nbyte - fil->s->avail_out;
}

static int xzfile_skip_to(struct xzfile *fil, struct xzcache *zc,
                          avoff_t offset)
{
    int res;
    uint8_t outbuf[OUTBUFSIZE];
    
    while(!fil->iseof) {
        avoff_t curroff = xz_total_out(fil->s);

        if(curroff == offset)
            break;

        /* FIXME: Maybe cache some data as well */
        fil->s->next_out = outbuf;
        fil->s->avail_out = AV_MIN(OUTBUFSIZE, offset - curroff);

        res = xzfile_decompress(fil, zc);
        if(res < 0)
            return res;
    }

    return 0;
}

static avssize_t av_xzfile_do_pread(struct xzfile *fil, struct xzcache *zc,
                                   char *buf, avsize_t nbyte, avoff_t offset)
{
    avssize_t res;
    avoff_t curroff;

    fil->id = zc->id;

    curroff = xz_total_out(fil->s);
    if(offset != curroff) {
        AV_LOCK(xzread_lock);
        if ( curroff > offset ) {
            res = xzfile_reset( fil );
        } else {
            res = 0;
        }
        AV_UNLOCK(xzread_lock);
        if(res < 0)
            return res;

        res = xzfile_skip_to(fil, zc, offset);
        if(res < 0)
            return res;
    }

    res = xzfile_read(fil, zc, buf, nbyte);
    
    return res;
}

avssize_t av_xzfile_pread(struct xzfile *fil, struct xzcache *zc, char *buf,
                         avsize_t nbyte, avoff_t offset)
{
    avssize_t res;

    if(fil->iserror)
        return -EIO;

    res = av_xzfile_do_pread(fil, zc, buf, nbyte, offset);
    if(res < 0)
        fil->iserror = 1;

    return res;
}

int av_xzfile_size(struct xzfile *fil, struct xzcache *zc, avoff_t *sizep)
{
    int res;
    avoff_t size;

    AV_LOCK(xzread_lock);
    size = zc->size;
    AV_UNLOCK(xzread_lock);

    if(size != -1 || fil == NULL) {
        *sizep = size;
        return 0;
    }

    fil->id = zc->id;

    AV_LOCK(xzread_lock);
    res = xzfile_reset( fil );
    AV_UNLOCK(xzread_lock);
    if(res < 0)
        return res;

    res = xzfile_skip_to(fil, zc, AV_MAXOFF);
    if(res < 0)
        return res;
    
    AV_LOCK(xzread_lock);
    size = zc->size;
    AV_UNLOCK(xzread_lock);
    
    if(size == -1) {
        av_log(AVLOG_ERROR, "XZ: Internal error: could not find size");
        return -EIO;
    }
    
    *sizep = size;
    return 0;
}

static void xzfile_destroy(struct xzfile *fil)
{
    AV_LOCK(xzread_lock);
    xzfile_scache_save(fil->id, fil->s);
    AV_UNLOCK(xzread_lock);
}

struct xzfile *av_xzfile_new(vfile *vf)
{
    int res;
    struct xzfile *fil;

    AV_NEW_OBJ(fil, xzfile_destroy);
    fil->iseof = 0;
    fil->iserror = 0;
    fil->infile = vf;
    fil->id = 0;

    res = xz_new_stream(&fil->s);
    if(res < 0)
        fil->iserror = 1;

    return fil;
}

static void xzcache_destroy(struct xzcache *zc)
{
}

struct xzcache *av_xzcache_new()
{
    struct xzcache *zc;

    AV_NEW_OBJ(zc, xzcache_destroy);
    zc->size = -1;

    AV_LOCK(xzread_lock);
    if(xzread_nextid == 0)
        xzread_nextid = 1;

    zc->id = xzread_nextid ++;
    AV_UNLOCK(xzread_lock);
    
    return zc;
}
