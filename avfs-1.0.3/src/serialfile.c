/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include "serialfile.h"
#include "cache.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

struct sfile {
    const struct sfilefuncs *func;
    void *data;
    int flags;
    void *conndata;
    char *localfile;
    avoff_t numbytes;
    int fd;
    int dirty;
    enum { SF_BEGIN, SF_READ, SF_FINI } state;
};

static void sfile_init(struct sfile *fil)
{
    fil->conndata = NULL;
    fil->localfile = NULL;
    fil->numbytes = 0;
    fil->fd = -1;
    fil->state = SF_BEGIN;
    fil->dirty = 0;
}

static void sfile_end(struct sfile *fil)
{
    close(fil->fd);
    av_del_tmpfile(fil->localfile);
    av_unref_obj(fil->conndata);
}

static void sfile_reset(struct sfile *fil)
{
    sfile_end(fil);
    sfile_init(fil);
}

static void sfile_reset_usecache(struct sfile *fil)
{
    fil->flags &= ~SFILE_NOCACHE;
    sfile_reset(fil);
}

static void sfile_delete(struct sfile *fil)
{
    sfile_end(fil);
    av_unref_obj(fil->data);
}

struct sfile *av_sfile_new(const struct sfilefuncs *func,
			   void *data, int flags)
{
    struct sfile *fil;

    AV_NEW_OBJ(fil, sfile_delete);
    fil->func = func;
    fil->data = data;
    fil->flags = flags;

    sfile_init(fil);

    return fil;
}

static int sfile_open_localfile(struct sfile *fil)
{
    int res;
    int openfl;

    res = av_get_tmpfile(&fil->localfile);
    if(res < 0)
        return res;
    
    openfl = O_RDWR | O_CREAT | O_TRUNC;
    fil->fd = open(fil->localfile, openfl, 0600);
    if(fil->fd == -1) {
        av_log(AVLOG_ERROR, "Error opening file %s: %s", fil->localfile,
                 strerror(errno));
        return -EIO;
    }
    
    return 0;
}

static int sfile_startget(struct sfile *fil)
{
    int res;

    if(!(fil->flags & SFILE_NOCACHE)) {
        res = sfile_open_localfile(fil);
        if(res < 0)
            return res;
    }
    
    res = fil->func->startget(fil->data, &fil->conndata);
    if(res < 0)
        return res;

    fil->state = SF_READ;
    
    return 0;
}


static avssize_t sfile_do_read(struct sfile *fil, char *buf, avssize_t nbyte)
{
    avsize_t numbytes;

    numbytes = 0;
    while(nbyte > 0) {
        avssize_t res;

        res = fil->func->read(fil->conndata, buf, nbyte);
        if(res < 0)
            return res;
        
        if(res == 0) {
            av_unref_obj(fil->conndata);
            fil->conndata = NULL;
            fil->state = SF_FINI;
            break;
        }
        
        nbyte -= res;
        buf += res;
        numbytes += res;
    }

    return numbytes;
}

static avssize_t sfile_cached_pwrite(struct sfile *fil, const char *buf,
                                     avssize_t nbyte, avoff_t offset)
{
    avssize_t res;

    res = pwrite(fil->fd, buf, nbyte, offset);
    if(res == -1 && (errno == ENOSPC || errno == EDQUOT)) {
        av_cache_diskfull();
        res = pwrite(fil->fd, buf, nbyte, offset);
    }
    if(res == -1) {
        av_log(AVLOG_ERROR, "Error writing file %s: %s", fil->localfile,
                 strerror(errno));
        return -EIO;
    }
    if(res != nbyte) {
        av_log(AVLOG_ERROR, "Error writing file %s: short write",
                 fil->localfile);
        return -EIO;
    }

    /* FIXME: Checking free space is expensive. This should be done in
       a more clever way */
    if(offset + nbyte > fil->numbytes)
        av_cache_checkspace();

    return res;
}

static avssize_t sfile_read(struct sfile *fil, char *buf, avssize_t nbyte)
{
    avssize_t res;

    res = sfile_do_read(fil, buf, nbyte);
    if(res <= 0)
        return res;

    if(!(fil->flags & SFILE_NOCACHE))
        res = sfile_cached_pwrite(fil, buf, res, fil->numbytes);

    if(res > 0)
        fil->numbytes += res;

    return res;
}

static int sfile_dummy_read(struct sfile *fil, avoff_t offset)
{
    avssize_t res;
    avsize_t nact;
    const int tmpbufsize = 8192;
    char tmpbuf[tmpbufsize];

    if((fil->flags & SFILE_NOCACHE) != 0)
        nact = AV_MIN(tmpbufsize, offset - fil->numbytes);
    else
        nact = tmpbufsize;

    res = sfile_read(fil, tmpbuf, tmpbufsize);
    
    if(res < 0)
        return res;
    
    return 0;
}

static avssize_t sfile_cached_pread(struct sfile *fil, char *buf,
                                   avssize_t nbyte, avoff_t offset)
{
    avssize_t res;

    if(nbyte == 0)
        return 0;

    res = pread(fil->fd, buf, nbyte, offset);
    if(res < 0) {
        av_log(AVLOG_ERROR, "Error reading file %s: %s", fil->localfile,
                 strerror(errno));
        return -EIO;
    }
    if(res != nbyte) {
        av_log(AVLOG_ERROR, "Error reading file %s: short read",
                 fil->localfile);
        return -EIO;
    }

    return res;
}

static avssize_t sfile_finished_read(struct sfile *fil, char *buf,
                                     avsize_t nbyte, avoff_t offset)
{
    avsize_t nact;
    
    if(offset >= fil->numbytes)
        return 0;
        
    nact = AV_MIN(nbyte, fil->numbytes - offset);

    return sfile_cached_pread(fil, buf, nact, offset);
}

static avssize_t sfile_pread(struct sfile *fil, char *buf, avsize_t nbyte,
                             avoff_t offset)
{
    int res;

    while(fil->state == SF_READ) {
        if(offset + nbyte <= fil->numbytes)
            return sfile_cached_pread(fil, buf, nbyte, offset);
        
        if(offset == fil->numbytes)
            return sfile_read(fil, buf, nbyte);
        
        res = sfile_dummy_read(fil, offset);
        if(res < 0)
            return res;
    }

    return sfile_finished_read(fil, buf, nbyte, offset);
}

static avssize_t sfile_pread_start(struct sfile *fil, char *buf,
                                   avsize_t nbyte, avoff_t offset)
{
    int res;

    if((fil->flags & SFILE_NOCACHE) != 0 && offset < fil->numbytes)
        sfile_reset_usecache(fil);

    if(fil->state == SF_BEGIN) {
        res = sfile_startget(fil);
        if(res < 0)
            return res;
    }

    return sfile_pread(fil, buf, nbyte, offset);
}

static avssize_t sfile_pread_force(struct sfile *fil, char *buf,
                                   avsize_t nbyte, avoff_t offset)
{
    avssize_t res;

    res = sfile_pread_start(fil, buf, nbyte, offset);
    if(res < 0) {
        if(res == -EAGAIN && fil->numbytes > 0) {
            sfile_reset(fil);
            res = sfile_pread_start(fil, buf, nbyte, offset);
        }
        if(res < 0) {
            if(res == -EAGAIN)
                res = -EIO;
            
            sfile_reset(fil);
        }
    }

    return res;
}

avssize_t av_sfile_pread(struct sfile *fil, char *buf, avsize_t nbyte,
                           avoff_t offset)
{
    if(nbyte == 0)
        return 0;
    
    return sfile_pread_force(fil, buf, nbyte, offset);
}


static int sfile_read_until(struct sfile *fil, avoff_t offset, int finish)
{
    avssize_t res;

    if(finish && (fil->flags & SFILE_NOCACHE) != 0)
        sfile_reset_usecache(fil);
    else if(fil->state == SF_FINI)
        return 0;

    res = sfile_pread_force(fil, NULL, 0, offset);
    if(res < 0)
        return res;

    if(finish && fil->state != SF_FINI) {
        av_unref_obj(fil->conndata);
        fil->conndata = NULL;
        fil->state = SF_FINI;
    }

    return 0;
}

avoff_t av_sfile_size(struct sfile *fil)
{
    avssize_t res;

    res = sfile_read_until(fil, AV_MAXOFF, 0);
    if(res < 0)
        return res;

    return fil->numbytes;
}

int av_sfile_startget(struct sfile *fil)
{
    return sfile_read_until(fil, 0, 0);
}

int av_sfile_truncate(struct sfile *fil, avoff_t length)
{
    int res;

    if(length == 0) {
        if(fil->state == SF_FINI && fil->numbytes == 0)
            return 0;

        sfile_reset_usecache(fil);
        res = sfile_open_localfile(fil);
        if(res < 0)
            return res;

        fil->state = SF_FINI;
        fil->dirty = 1;
        return 0;
    }
    
    res = sfile_read_until(fil, length, 1);
    if(res < 0)
        return res;

    if(fil->numbytes > length) {
        ftruncate(fil->fd, length);
        fil->numbytes = length;
        fil->dirty = 1;
    }
    
    return 0;
}

avssize_t av_sfile_pwrite(struct sfile *fil, const char *buf, avsize_t nbyte,
                            avoff_t offset)
{
    avssize_t res;
    avoff_t end;

    if(nbyte == 0)
        return 0;

    res = sfile_read_until(fil, AV_MAXOFF, 1);
    if(res < 0)
        return res;
    
    res = sfile_cached_pwrite(fil, buf, nbyte, offset);
    if(res < 0) {
        sfile_reset(fil);
        return res;
    }

    end = offset + nbyte; 
    if(end > fil->numbytes)
        fil->numbytes = end;

    fil->dirty = 1;
    return res;
}

static int sfile_writeout(struct sfile *fil, void *conndata)
{
    avssize_t res;
    const int tmpbufsize = 8192;
    char tmpbuf[tmpbufsize];
    avoff_t offset;

    for(offset = 0; offset < fil->numbytes;) {
        avsize_t nact = AV_MIN(tmpbufsize, fil->numbytes - offset);

        res = sfile_cached_pread(fil, tmpbuf, nact, offset);
        if(res < 0)
            return res;
        
        res = fil->func->write(conndata, tmpbuf, nact);
        if(res < 0)
            return res;

        offset += res;
    }
    
    return 0;
}

int av_sfile_flush(struct sfile *fil)
{
    int res;
    void *conndata;

    if(!fil->dirty)
        return 0;
    
    res = fil->func->startput(fil->data, &conndata);
    if(res == 0) {
        res = sfile_writeout(fil, conndata);
        if(res == 0)
            res = fil->func->endput(conndata);
    }
    av_unref_obj(conndata);
    if(res < 0)
        sfile_reset(fil);

    fil->dirty = 0;

    return res;
}

void *av_sfile_getdata(struct sfile *fil)
{
    return fil->data;
}

avoff_t av_sfile_diskusage(struct sfile *fil)
{
    int res;
    struct stat buf;

    if(fil->fd == -1)
        return 0;
    
    res = fstat(fil->fd, &buf);
    if(res == -1) {
        av_log(AVLOG_ERROR, "Error in fstat() for %s: %s", fil->localfile,
               strerror(errno));
        return -EIO;
    }
    
    return buf.st_blocks * 512;
}
