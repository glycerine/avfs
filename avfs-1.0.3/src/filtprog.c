/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "filtprog.h"
#include "filebuf.h"
#include "prog.h"
#include "oper.h"

#include <unistd.h>
#include <sys/time.h>

struct filtprog {
    vfile *vf;
    struct filtdata *filtdat;
};

#define cbufsize 16384

struct filtconn {
    struct filtprog *fp;
    struct filebuf *fbs[3];
    struct proginfo pri;
    int cbufat;
    int cbuflen;
    char cbuf[cbufsize];
};

static int filtprog_fill_cbuf(struct filtconn *fc)
{
    avssize_t res;

    res = av_read(fc->fp->vf, fc->cbuf, cbufsize);
    if(res < 0)
        return res;

    if(res == 0) {
        av_unref_obj(fc->fbs[0]);
        fc->fbs[0] = NULL;
    }
    else {
        fc->cbuflen = res;
        fc->cbufat = 0;
    }

    return 0;
}

static int filtprog_check_error(struct filtconn *fc)
{
    char *line;
    int res;
    int gotsome = 0;

    do {
        res = av_filebuf_readline(fc->fbs[2], &line);
        if(res < 0)
            return res;

        if(res == 1) {
            av_log(AVLOG_ERROR, "%s stderr: %s", fc->fp->filtdat->prog[0],
                     line);
            av_free(line);
            gotsome = 1;
        }
    } while(res == 1);

    return gotsome;
}

static int filtprog_write_input(struct filtconn *fc)
{
    int res;

    if(fc->cbuflen == 0) {
        res = filtprog_fill_cbuf(fc);
        if(res < 0)
            return res;

        if(fc->fbs[0] == NULL)
            return 0;
    }
    
    res = av_filebuf_write(fc->fbs[0], fc->cbuf + fc->cbufat,
                             fc->cbuflen);
    if(res < 0)
        return res;
    
    fc->cbufat += res;
    fc->cbuflen -= res;

    return 0;
}

static avssize_t filtprog_read(void *data, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct filtconn *fc = (struct filtconn *) data;

    while(1) {
        res = filtprog_check_error(fc);
        if(res < 0)
            return res;

        if(res == 0) {
            res = av_filebuf_read(fc->fbs[1], buf, nbyte);
            if(res != 0)
                return res;
            
            if(av_filebuf_eof(fc->fbs[1])) {
                res = av_wait_prog(&fc->pri, 0, 0);
                if(res < 0)
                    return res;

                return 0;
            }
            
            if(fc->fbs[0] != NULL) {
                res = filtprog_write_input(fc);
                if(res < 0)
                    return res;
            }
        }

        res = av_filebuf_check(fc->fbs, 3, -1);
        if(res < 0)
            return res;
    }
}

static int filtprog_read_input(struct filtconn *fc)
{
    avssize_t res;

    res  = av_filebuf_read(fc->fbs[1], fc->cbuf + fc->cbufat,
                             cbufsize - fc->cbufat);
    
    if(res > 0) {
        fc->cbufat += res;
        if(fc->cbufat == cbufsize) {
            res = av_write(fc->fp->vf, fc->cbuf, fc->cbufat);
            fc->cbufat = 0;
        }
    }

    return res;
}

static avssize_t filtprog_write(void *data, const char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct filtconn *fc = (struct filtconn *) data;

    while(1) {
        res = filtprog_check_error(fc);
        if(res < 0)
            return res;

        if(res == 0) {
            res = av_filebuf_write(fc->fbs[0], buf, nbyte);
            if(res != 0)
                return res;
            
            res = filtprog_read_input(fc);
            if(res < 0)
                return res;
        }

        res = av_filebuf_check(fc->fbs, 3, -1);
        if(res < 0)
            return res;
    }
}

static int filtprog_endput(void *data)
{
    int res;
    struct filtconn *fc = (struct filtconn *) data;
    
    av_unref_obj(fc->fbs[0]);
    fc->fbs[0] = NULL;

    while(1) {
        res = filtprog_check_error(fc);
        if(res < 0)
            return res;

        if(res == 0) {
            res = filtprog_read_input(fc);
            if(res < 0)
                return res;

            if(av_filebuf_eof(fc->fbs[1]))
                break;
        }

        res = av_filebuf_check(fc->fbs, 3, -1);
        if(res < 0)
            return res;        
    }

    res = av_write(fc->fp->vf, fc->cbuf, fc->cbufat);
    if(res < 0)
        return res;

    res = av_wait_prog(&fc->pri, 0, 0);
    if(res < 0)
        return res;

    return 0;
}

static void filtprog_stop(struct filtconn *fc)
{
    av_unref_obj(fc->fbs[0]);
    av_unref_obj(fc->fbs[1]);   
    av_unref_obj(fc->fbs[2]);
    av_wait_prog(&fc->pri, 1, 0);
    av_lseek(fc->fp->vf, 0, AVSEEK_SET);
}

static int filtprog_init_pipes(int pipein[2], int pipeout[2], int pipeerr[2])
{
    int res;

    pipein[0] = -1,  pipein[1] = -1;
    pipeout[0] = -1, pipeout[1] = -1;
    pipeerr[0] = -1, pipeerr[1] = -1;

    if(pipe(pipein) == -1 || pipe(pipeout) == -1 || pipe(pipeerr) == -1) {
        res = -errno;
        close(pipein[0]), close(pipein[1]);
        close(pipeout[0]), close(pipeout[1]);
        return res;
    }

    av_registerfd(pipein[1]);
    av_registerfd(pipeout[0]);
    av_registerfd(pipeerr[0]);

    return 0;
}

static int filtprog_start(struct filtprog *fp, char **prog,
                          struct filtconn **resp)
{
    struct filtconn *fc;
    int res;
    int pipein[2];
    int pipeout[2];
    int pipeerr[2];
    struct proginfo pri;

    res = filtprog_init_pipes(pipein, pipeout, pipeerr);
    if(res < 0)
        return res;

    av_init_proginfo(&pri);
    
    pri.prog = (const char **) prog;
    pri.ifd = pipein[0];
    pri.ofd = pipeout[1];
    pri.efd = pipeerr[1];

    res = av_start_prog(&pri);
    close(pri.ifd);
    close(pri.ofd);
    close(pri.efd);

    if(res < 0) {
       close(pipein[1]);
       close(pipeout[0]);
       close(pipeerr[0]);
       return res;
    }

    AV_NEW_OBJ(fc, filtprog_stop);
    
    fc->fp = fp;
    fc->fbs[0] = av_filebuf_new(pipein[1], FILEBUF_NONBLOCK | FILEBUF_WRITE);
    fc->fbs[1] = av_filebuf_new(pipeout[0], FILEBUF_NONBLOCK);
    fc->fbs[2] = av_filebuf_new(pipeerr[0], FILEBUF_NONBLOCK);
    fc->pri = pri;
    fc->cbufat = 0;
    fc->cbuflen = 0;

    *resp = fc;
    return 0;
}

static int filtprog_startget(void *data, void **resp)
{
    int res;
    struct filtprog *fp = (struct filtprog *) data;
    struct filtconn *fc;

    res = filtprog_start(fp, fp->filtdat->prog, &fc);
    if(res < 0)
        return res;

    *resp = fc;

    return 0;
}

static int filtprog_startput(void *data, void **resp)
{
    int res;
    struct filtprog *fp = (struct filtprog *) data;
    struct filtconn *fc;

    res = av_ftruncate(fp->vf, 0);
    if(res < 0)
        return res;

    res = filtprog_start(fp, fp->filtdat->revprog, &fc);
    if(res < 0)
        return res;

    *resp = fc;

    return 0;
}

struct sfile *av_filtprog_new(vfile *vf, struct filtdata *filtdat)
{
    struct filtprog *fp;
    struct sfile *sf;
    static const struct sfilefuncs func = {
        filtprog_startget,
        filtprog_read,
        filtprog_startput,
        filtprog_write,
        filtprog_endput
    };

    AV_NEW_OBJ(fp, NULL);
    fp->vf = vf;
    fp->filtdat = filtdat;

    sf = av_sfile_new(&func, fp, 0);

    return sf;
}

void av_filtprog_change(struct sfile *sf, vfile *newvf)
{
    struct filtprog *fp = (struct filtprog *) av_sfile_getdata(sf);
    
    fp->vf = newvf;
}
