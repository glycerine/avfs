/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>
    Copyright (C) 2006       Ralf Hoffmann (ralf@boomerangsworld.de)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "internal.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif

struct tmpdir {
    char *path;
    int ctr;
};

static AV_LOCK_DECL(tmplock);
static struct tmpdir *tmpdir;

static int unlink_recursive(const char *file)
{
    int res;
    DIR *dirp;
    struct dirent *ent;
    char *name;

    res = unlink(file);
    if(res == 0)
        return 0;

    res = rmdir(file);
    if(res == 0)
        return 0;

    dirp = opendir(file);
    if(dirp == NULL)
        return -1;

    while((ent = readdir(dirp)) != NULL) {
        name = ent->d_name;
    
        if(name[0] != '.' || (name[1] && (name[1] != '.' || name[2]))) {
            char *newname;

            newname = av_stradd(NULL, file, "/", name, NULL);
            unlink_recursive(newname);
            av_free(newname);
        }
    }
    closedir(dirp);

    return rmdir(file);
}


void av_delete_tmpdir()
{
    AV_LOCK(tmplock);
    if(tmpdir != NULL) {
        unlink_recursive(tmpdir->path);
        av_free(tmpdir->path);
        av_free(tmpdir);
        tmpdir = NULL;
    }
    AV_UNLOCK(tmplock);
}

#ifdef HAVE_MKDTEMP

static int make_tmp_dir(char *path)
{
    char *res;

    res = mkdtemp(path);
    if(res == NULL) {
        av_log(AVLOG_ERROR, "mkdtemp failed: %s", strerror(errno));
        return -EIO;
    }
    return 0;
}

#else /* HAVE_MKDTEMP */

static int make_tmp_dir(char *path)
{
    int res;

    mktemp(path);
    if(path[0] == '\0') {
        av_log(AVLOG_ERROR, "mktemp failed for temporary directory");
        return -EIO;
    }
    res = mkdir(path, 0700);
    if(res == -1) {
        av_log(AVLOG_ERROR, "mkdir(%s) failed: %s", path, strerror(errno));
        return -EIO;
    }
    return 0;
}

#endif /* HAVE_MKDTEMP */

int av_get_tmpfile(char **retp)
{
    int res = 0;
    char buf[64];
  
    AV_LOCK(tmplock);
    if(tmpdir == NULL) {
        char *path;

        path = av_strdup("/tmp/.avfs_tmp_XXXXXX");
        res = make_tmp_dir(path);
        if(res < 0)
            av_free(path);
        else {
	    AV_NEW(tmpdir);
	    tmpdir->path = path;
	    tmpdir->ctr = 0;
	}
    }
    if(tmpdir != NULL) {
	sprintf(buf, "/atmp%06i", tmpdir->ctr++);
	*retp = av_stradd(NULL, tmpdir->path, buf, NULL);
    }
    AV_UNLOCK(tmplock);

    return res;
}

void av_del_tmpfile(char *tmpf)
{
    if(tmpf != NULL) {
	if(unlink(tmpf) == -1)
	    rmdir(tmpf);
	
	av_free(tmpf);
    }
}

avoff_t av_tmp_free()
{
#ifdef HAVE_SYS_STATVFS_H
    int res;
    struct statvfs stbuf;
#endif
    avoff_t freebytes = -1;

#ifdef HAVE_SYS_STATVFS_H
    AV_LOCK(tmplock);
    if(tmpdir != NULL) {
        /* Check if fs supports df info (ramfs doesn't) */
        res = statvfs(tmpdir->path, &stbuf);
        if(res != -1 && stbuf.f_blocks != 0)
            freebytes = (avoff_t) stbuf.f_bavail * (avoff_t) stbuf.f_frsize;
    }
    AV_UNLOCK(tmplock);
#endif

#if 0    
    if(freebytes != -1)
        av_log(AVLOG_DEBUG, "free bytes in tmp directory: %lli", freebytes);
#endif

    return freebytes;
}

avoff_t av_tmpfile_blksize(const char *tmpf)
{
    int res;
    struct stat stbuf;
    
    if(tmpf == NULL)
        return -1;

    res = stat(tmpf, &stbuf);
    if(res == 0) {
        /* Ramfs returns 0 diskusage */
        if(stbuf.st_blocks == 0)
            return stbuf.st_size;
        else
            return stbuf.st_blocks * 512;
    } else
        return -1;
}
