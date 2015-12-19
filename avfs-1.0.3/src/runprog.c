/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "runprog.h"
#include "prog.h"
#include "filebuf.h"

#include <unistd.h>
#include <fcntl.h>

struct program {
    char **prog;
    struct proginfo pri;
    struct filebuf *fbs[2];
};


static char **copy_prog(const char **prog)
{
    unsigned int len;
    unsigned int i;
    const char **p;
    char **cp;

    for(len = 0, p = prog; *p != NULL; p++, len++);
    cp = av_malloc(sizeof(*cp) * (len + 1));
    for(i = 0; i < len; i++)
        cp[i] = av_strdup(prog[i]);

    cp[len] = NULL;
    return cp;
}

static void free_prog(char **prog)
{
    unsigned int i;
    for(i = 0; prog[i] != NULL; i++)
        av_free(prog[i]);
    av_free(prog);
}

static void program_delete(struct program *pr)
{
    av_wait_prog(&pr->pri, 1, 0);
    free_prog(pr->prog);
    av_unref_obj(pr->fbs[0]);
    av_unref_obj(pr->fbs[1]);
}

int av_start_program(const char **prog, struct program **resp)
{
    int res;
    int pipeout[2];
    int pipeerr[2];
    struct program *pr;

    pipeout[0] = -1;
    pipeout[1] = -1;
    if(pipe(pipeout) == -1 || pipe(pipeerr) == -1) {
        res = -errno;
        av_log(AVLOG_ERROR, "RUNPROG: unable to create pipe: %s",
               strerror(errno));
        close(pipeout[0]);
        close(pipeout[1]);
        return res;
    }
    av_registerfd(pipeout[0]);
    av_registerfd(pipeerr[0]);

    AV_NEW_OBJ(pr, program_delete);
    av_init_proginfo(&pr->pri);
    pr->fbs[0] = NULL;
    pr->fbs[1] = NULL;
    pr->prog = copy_prog(prog);

    pr->pri.prog = (const char **) pr->prog;
    pr->pri.ifd = open("/dev/null", O_RDONLY);
    if(pr->pri.ifd == -1) {
        res = -errno;
        av_log(AVLOG_ERROR, "RUNPROG: unable to open '/dev/null': %s",
               strerror(errno));
        close(pipeout[0]);
        close(pipeout[1]);
        close(pipeerr[0]);
        close(pipeerr[1]);
        av_unref_obj(pr);
        return res;
    }
    pr->pri.ofd = pipeout[1];
    pr->pri.efd = pipeerr[1];

    res = av_start_prog(&pr->pri);
    close(pr->pri.ifd);
    close(pr->pri.ofd);
    close(pr->pri.efd);

    if(res < 0) {
        close(pipeout[0]);
        close(pipeerr[0]);
        av_unref_obj(pr);
        return res;
    }
    
    pr->fbs[0] = av_filebuf_new(pipeout[0], FILEBUF_NONBLOCK);
    pr->fbs[1] = av_filebuf_new(pipeerr[0], FILEBUF_NONBLOCK);

    *resp = pr;
    return 0;
}

static int flush_error(struct program *pr)
{
    int res;
    char *line;

    while((res = av_filebuf_readline(pr->fbs[1], &line)) == 1) {
        av_log(AVLOG_WARNING, "%s: stderr: %s", pr->pri.prog[0], line);
        av_free(line);
    }

    return res;
}

static int flush_output(struct program *pr)
{
    int res;
    char *line;

    while((res = av_filebuf_readline(pr->fbs[0], &line)) == 1) {
        av_log(AVLOG_WARNING, "%s: stdout: %s", pr->pri.prog[0], line);
        av_free(line);
    }

    return res;
}

int av_program_getline(struct program *pr, char **linep, long timeoutms)
{
    int res;
    char *line;

    *linep = NULL;
    while(1) {
        res = flush_error(pr);
        if(res < 0)
            return res;
        
        res = av_filebuf_readline(pr->fbs[0], &line);
        if(res < 0)
            return res;
        if(res == 1)
            break;

        if(av_filebuf_eof(pr->fbs[0]) && av_filebuf_eof(pr->fbs[1])) {
            res = av_wait_prog(&pr->pri, 0, 0);
            if(res < 0)
                return res;

            return 1;
        }

        res = av_filebuf_check(pr->fbs, 2, timeoutms);
        if(res <= 0)
            return res;
    }

    *linep = line;
    return 1;
}

int av_program_log_output(struct program *pr)
{
    int res;

    res = av_wait_prog(&pr->pri, 0, 1);
    if(res < 0)
        return res;
    
    if(res == 1)
        return 0;

    return 1;
}

static int av_process_program(struct program *pr)
{
    int res;

    while(!av_filebuf_eof(pr->fbs[0]) || !av_filebuf_eof(pr->fbs[1])) {
        res = av_filebuf_check(pr->fbs, 2, 0);
        if(res < 0)
            return res;
        
        if(res == 1) {
            res = flush_error(pr);
            if(res < 0)
                return res;
            res = flush_output(pr);
            if(res < 0)
                return res;
        }
    }
    
    res = av_wait_prog(&pr->pri, 0, 0);
    if(res < 0)
        return res;

    return 0;
}

int av_run_program(const char **prog)
{
    int res;
    struct program *pr;

    res = av_start_program(prog, &pr);
    if(res < 0)
        return res;


    res = av_process_program(pr);
    av_unref_obj(pr);

    return res;
}
