/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "realfile.h"
#include "oper.h"
#include "cache.h"

#include <unistd.h>
#include <fcntl.h>

#define COPY_BUFSIZE 16384

static int copy_file(ventry *ve, const char *destpath)
{
    int res;
    avssize_t num;
    char buf[COPY_BUFSIZE];
    int ctr;
    vfile *vf;
    int destfd;

    res = av_open(ve, AVO_RDONLY, 0, &vf);
    if(res < 0)
        return res;
    
    destfd = open(destpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(destfd == -1) {
        res = -errno;
        av_close(vf);
        av_log(AVLOG_ERROR, "Error opening file %s: %s", destpath,
               strerror(errno));
        return res;
    }

    ctr = 0;
    while(1) {
        res = av_read(vf, buf, COPY_BUFSIZE);
        if(res <= 0)
            break;

        num = res;
        res = write(destfd, buf, num);
        if(res == -1 && (errno == ENOSPC || errno == EDQUOT)) {
            av_cache_diskfull();
            res = write(destfd, buf, num);
        }
        if(res == -1) {
            res = -errno;
            av_log(AVLOG_ERROR, "Error writing file %s: %s", destpath,
                   strerror(errno));
            break;
        }

        /* Check free space after each Meg */
        if((ctr++ % 64) == 0)
            av_cache_checkspace();
    }

    close(destfd);
    if(res == 0)
        res = av_close(vf);
    else
        av_close(vf);

    return res;
}

static void realfile_delete(struct realfile *rf)
{
    if(!rf->is_tmp) 
        av_free(rf->name);
    else 
        av_del_tmpfile(rf->name);
}

int av_get_realfile(ventry *ve, struct realfile **resp)
{
    int res;
    struct realfile *rf;

    AV_NEW_OBJ(rf, realfile_delete);
    rf->is_tmp = 0;
    rf->name = NULL;

    if(ve->mnt->base == NULL) {
        rf->name = av_strdup((char *) ve->data);
        rf->is_tmp = 0;

        *resp = rf;
        return 0;
    }

    res = av_get_tmpfile(&rf->name);
    if(res < 0) {
        av_unref_obj(rf);
        return res;
    }

    rf->is_tmp = 1;

    res = copy_file(ve, rf->name);
    if(res < 0) {
        av_unref_obj(rf);
        return res;
    }

    *resp = rf;
    return 0;
}

