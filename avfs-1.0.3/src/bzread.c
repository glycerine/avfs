/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "config.h"
#include "bzfile.h"
#include "bzlib.h"
#include "oper.h"
#include "exit.h"

#include <stdlib.h>
#include <fcntl.h>


#define INBUFSIZE 16384
#define OUTBUFSIZE 32768

struct bzstreamcache {
    int id;
    bz_stream *s;
};

/* FIXME: the streamcache should be cleaned up after a short timeout
   because it uses a LOT of memory */

static struct bzstreamcache bzscache;
static int bzread_nextid;
static AV_LOCK_DECL(bzread_lock);

struct bzindex {
    avoff_t offset;          /* The number of output bytes */
    avoff_t inbits;          /* The number of input bits */
    avuint crc;              /* The cumulative CRC up to this point */
    avbyte blocksize;        /* the blocksize in 100k (1 .. 9) */
    avbyte startbits;        /* the bits at the start of the block */
};

struct bzcache {
    int id;
    avoff_t size;
    unsigned int numindex;
    struct bzindex *indexes;
};

struct bzfile {
    bz_stream *s;
    int iseof;
    int iserror;
    int id; /* The id of the last used bzcache */
    
    vfile *infile;
    char inbuf[INBUFSIZE];
};

void bz_internal_error(int errorcode)
{
    av_log(AVLOG_ERROR, "BZLIB: internal error %i", errorcode);
}

static avoff_t bz_total_in(bz_stream *s)
{
    return (avoff_t) s->total_in_lo32 + ((avoff_t) s->total_in_hi32 << 32);
}

static avoff_t bz_total_out(bz_stream *s)
{
    return (avoff_t) s->total_out_lo32 + ((avoff_t) s->total_out_hi32 << 32);
}

static void bz_delete_stream(bz_stream *s)
{
    int res;

    if(s != NULL) {
        res = BZ2_bzDecompressEnd(s);
        if(res != BZ_OK)
            av_log(AVLOG_ERROR, "BZFILE: decompress end error: %i", res);
        
        av_free(s);
    }
}

static int bz_new_stream(bz_stream **resp)
{
    int res;
    bz_stream *s;

    AV_NEW(s);
    memset(s, 0, sizeof(*s));
    res = BZ2_bzDecompressInit(s, 0, 0);
    if(res != BZ_OK) {
        *resp = NULL;
        av_log(AVLOG_ERROR, "BZFILE: decompress init error: %i", res);
        return -EIO;
    }

    *resp = s;
    return 0;
}

static void bzfile_scache_delete()
{
    AV_LOCK(bzread_lock);
    if(bzscache.id != 0) {
        bz_delete_stream(bzscache.s);
        bzscache.id = 0;
    }
    AV_UNLOCK(bzread_lock);
}

static void bzfile_scache_save(int id, bz_stream *s)
{
    static int regdestroy = 0;
    if(!regdestroy) {
        regdestroy = 1;
        av_add_exithandler(bzfile_scache_delete);
    }

    if(id == 0 || s == NULL) {
        bz_delete_stream(s);
        return;
    }
    
    if(bzscache.id != 0)
        bz_delete_stream(bzscache.s);

    bzscache.id = id;
    bzscache.s = s;
}

static int bzfile_reset(struct bzfile *fil)
{
    /* FIXME: Is it a good idea to save the previous state or not? */
    if (fil->iseof || fil->iserror)
        bz_delete_stream(fil->s);
    else
        bzfile_scache_save(fil->id, fil->s);

    fil->iseof = 0;
    fil->iserror = 0;
    return bz_new_stream(&fil->s);
}

#ifndef USE_SYSTEM_BZLIB
static int bzfile_seek_index(struct bzfile *fil, struct bzindex *zi)
{
    int res;
    unsigned int bitsrem;
    avoff_t total_in;
    unsigned int val;
    
    /* FIXME: Is it a good idea to save the previous state or not? */
    bzfile_scache_save(fil->id, fil->s);
    res = bz_new_stream(&fil->s);
    if(res < 0)
        return res;

    total_in = (zi->inbits + 7) >> 3;
    bitsrem = (total_in << 3) - zi->inbits;
    total_in -= 4;
    
    fil->s->next_in = fil->inbuf;
    fil->s->avail_in = 4;

    fil->s->total_in_lo32 = total_in & 0xFFFFFFFF;
    fil->s->total_in_hi32 = (total_in >> 32) & 0xFFFFFFFF;
    fil->s->total_out_lo32 = zi->offset & 0xFFFFFFFF;
    fil->s->total_out_hi32 = (zi->offset >> 32) & 0xFFFFFFFF;
    
    val = ('B' << 24) + ('Z' << 16) + ('h' << 8) + (zi->blocksize + '0');
    val <<= bitsrem;
    val += zi->startbits;

    fil->inbuf[0] = (val >> 24) & 0xFF;
    fil->inbuf[1] = (val >> 16) & 0xFF;
    fil->inbuf[2] = (val >> 8) & 0xFF;
    fil->inbuf[3] = val & 0xFF;

    av_log(AVLOG_DEBUG, "BZFILE: restore: %lli %lli/%i %08x %i",
           bz_total_out(fil->s), bz_total_in(fil->s), bitsrem,
           zi->crc, zi->blocksize);
        
    BZ2_bzRestoreBlockEnd(fil->s, bitsrem, zi->crc);

    return 0;
}

static struct bzindex *bzcache_find_index(struct bzcache *zc, avoff_t offset)
{
    unsigned int i;

    for(i = 0; i < zc->numindex; i++) {
        if(zc->indexes[i].offset > offset)
            break;
    }
    if(i == 0)
        return NULL;
    
    return &zc->indexes[i-1];
}
#endif

static int bzfile_fill_inbuf(struct bzfile *fil)
{
    avssize_t res;
    avoff_t inoff = bz_total_in(fil->s);

    res = av_pread(fil->infile, fil->inbuf, INBUFSIZE, inoff);
    if(res < 0)
        return res;
    
    fil->s->next_in = fil->inbuf;
    fil->s->avail_in = res;

    return 0;
}

#ifndef USE_SYSTEM_BZLIB
static void bzfile_save_state(struct bzcache *zc, bz_stream *s,
                              unsigned int bitsrem, unsigned int bits,
                              unsigned int crc, unsigned int blocksize)
{
    struct bzindex *zi;
    avoff_t offset = bz_total_out(s);
    int i;
    
    for(i = 0; i < zc->numindex; i++) {
        if(zc->indexes[i].offset >= offset)
            return;
    }

    zc->numindex ++;
    zc->indexes = (struct bzindex *)
        av_realloc(zc->indexes, sizeof(*zc->indexes) * zc->numindex);
    
    zi = &zc->indexes[i];
    zi->offset = offset;
    zi->inbits = (bz_total_in(s) << 3) - bitsrem;
    zi->startbits = bits & ((1 << bitsrem) - 1);
    zi->crc = crc;
    zi->blocksize = blocksize;

    av_log(AVLOG_DEBUG, "BZFILE: new block end: %lli %lli/%i %08x %i",
           zi->offset, bz_total_in(s), bitsrem, zi->crc, zi->blocksize);

}

static void bz_block_end(void *data, bz_stream *s, unsigned int bitsrem,
                         unsigned int bits, unsigned int crc,
                         unsigned int blocksize)
{
    struct bzcache *zc = (struct bzcache *) data;

    AV_LOCK(bzread_lock);
    bzfile_save_state(zc, s, bitsrem, bits, crc, blocksize);
    AV_UNLOCK(bzread_lock);
}
#endif

static int bzfile_decompress(struct bzfile *fil, struct bzcache *zc)
{
    int res;
    unsigned char *start;

    if(fil->s->avail_in == 0) {
        res = bzfile_fill_inbuf(fil);
        if(res < 0)
            return res;
	if(fil->s->avail_in == 0) {
	  /* still no byte available */
	  av_log(AVLOG_ERROR, "BZFILE: decompress error");
	  return -EIO;
	}
    }
    
    start = (unsigned char*)( fil->s->next_out );
#ifndef USE_SYSTEM_BZLIB
    BZ2_bzSetBlockEndHandler(fil->s, bz_block_end, zc);
#endif
    res = BZ2_bzDecompress(fil->s);
    if(res == BZ_STREAM_END) {
        fil->iseof = 1;
        AV_LOCK(bzread_lock);
        zc->size = bz_total_out(fil->s);
        AV_UNLOCK(bzread_lock);
        return 0;
    }
    if(res != BZ_OK) {
        av_log(AVLOG_ERROR, "BZFILE: decompress error: %i", res);
        return -EIO;
    }
    
    return 0;
}


static int bzfile_read(struct bzfile *fil, struct bzcache *zc, char *buf,
                      avsize_t nbyte)
{
    int res;

    fil->s->next_out = buf;
    fil->s->avail_out = nbyte;
    while(fil->s->avail_out != 0 && !fil->iseof) {
        res = bzfile_decompress(fil, zc);
        if(res < 0)
            return res;
    }

    return nbyte - fil->s->avail_out;
}

static int bzfile_skip_to(struct bzfile *fil, struct bzcache *zc,
                          avoff_t offset)
{
    int res;
    char outbuf[OUTBUFSIZE];
    
    while(!fil->iseof) {
        avoff_t curroff = bz_total_out(fil->s);

        if(curroff == offset)
            break;

        /* FIXME: Maybe cache some data as well */
        fil->s->next_out = outbuf;
        fil->s->avail_out = AV_MIN(OUTBUFSIZE, offset - curroff);

        res = bzfile_decompress(fil, zc);
        if(res < 0)
            return res;
    }

    return 0;
}

#ifndef USE_SYSTEM_BZLIB
static int bzfile_seek(struct bzfile *fil, struct bzcache *zc, avoff_t offset)
{
    struct bzindex *zi;
    avoff_t curroff = bz_total_out(fil->s);
    avoff_t zcdist;
    avoff_t scdist;
    avoff_t dist;

    if(offset >= curroff)
        dist = offset - curroff;
    else
        dist = -1;

    zi = bzcache_find_index(zc, offset);
    if(zi != NULL)
        zcdist = offset - zi->offset;
    else
        zcdist = offset;

    if(bzscache.id == zc->id) {
        avoff_t scacheoff = bz_total_out(bzscache.s);

        if(offset >= scacheoff) {
            scdist = offset - scacheoff;
            if((dist == -1 || scdist < dist) && scdist < zcdist) {
                bz_stream *tmp = fil->s;
                fil->s = bzscache.s;
                fil->s->avail_in = 0;
                bzscache.s = tmp;
                return 0;
            }
        }
    }

    if(dist == -1 || zcdist < dist) {
        if(zi == NULL)
            return bzfile_reset(fil);
        else
            return bzfile_seek_index(fil, zi);
    }

    return 0;
}
#endif

static avssize_t av_bzfile_do_pread(struct bzfile *fil, struct bzcache *zc,
                                   char *buf, avsize_t nbyte, avoff_t offset)
{
    avssize_t res;
    avoff_t curroff;

    fil->id = zc->id;

    curroff = bz_total_out(fil->s);
    if(offset != curroff) {
        AV_LOCK(bzread_lock);
#ifndef USE_SYSTEM_BZLIB
        res = bzfile_seek(fil, zc, offset);
#else
        if ( curroff > offset ) {
            res = bzfile_reset( fil );
        } else {
            res = 0;
        }
#endif
        AV_UNLOCK(bzread_lock);
        if(res < 0)
            return res;

        res = bzfile_skip_to(fil, zc, offset);
        if(res < 0)
            return res;
    }

    res = bzfile_read(fil, zc, buf, nbyte);
    
    return res;
}

avssize_t av_bzfile_pread(struct bzfile *fil, struct bzcache *zc, char *buf,
                         avsize_t nbyte, avoff_t offset)
{
    avssize_t res;

    if(fil->iserror)
        return -EIO;

    res = av_bzfile_do_pread(fil, zc, buf, nbyte, offset);
    if(res < 0)
        fil->iserror = 1;

    return res;
}

int av_bzfile_size(struct bzfile *fil, struct bzcache *zc, avoff_t *sizep)
{
    int res;
    avoff_t size;

    AV_LOCK(bzread_lock);
    size = zc->size;
    AV_UNLOCK(bzread_lock);

    if(size != -1 || fil == NULL) {
        *sizep = size;
        return 0;
    }

    fil->id = zc->id;

    AV_LOCK(bzread_lock);
#ifndef USE_SYSTEM_BZLIB
    res = bzfile_seek(fil, zc, AV_MAXOFF);
#else
    res = bzfile_reset( fil );
#endif
    AV_UNLOCK(bzread_lock);
    if(res < 0)
        return res;

    res = bzfile_skip_to(fil, zc, AV_MAXOFF);
    if(res < 0)
        return res;
    
    AV_LOCK(bzread_lock);
    size = zc->size;
    AV_UNLOCK(bzread_lock);
    
    if(size == -1) {
        av_log(AVLOG_ERROR, "BZFILE: Internal error: could not find size");
        return -EIO;
    }
    
    *sizep = size;
    return 0;
}

static void bzfile_destroy(struct bzfile *fil)
{
    AV_LOCK(bzread_lock);
    bzfile_scache_save(fil->id, fil->s);
    AV_UNLOCK(bzread_lock);
}

struct bzfile *av_bzfile_new(vfile *vf)
{
    int res;
    struct bzfile *fil;

    AV_NEW_OBJ(fil, bzfile_destroy);
    fil->iseof = 0;
    fil->iserror = 0;
    fil->infile = vf;
    fil->id = 0;

    res = bz_new_stream(&fil->s);
    if(res < 0)
        fil->iserror = 1;

    return fil;
}

static void bzcache_destroy(struct bzcache *zc)
{
    av_free(zc->indexes);
}

struct bzcache *av_bzcache_new()
{
    struct bzcache *zc;

    AV_NEW_OBJ(zc, bzcache_destroy);
    zc->numindex = 0;
    zc->indexes = NULL;
    zc->size = -1;

    AV_LOCK(bzread_lock);
    if(bzread_nextid == 0)
        bzread_nextid = 1;

    zc->id = bzread_nextid ++;
    AV_UNLOCK(bzread_lock);
    
    return zc;
}
