/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "operutil.h"
#include "internal.h"

static vfile **file_table;
static unsigned int file_table_size;
static AV_LOCK_DECL(files_lock);

static int find_unused()
{
    int i;
    int newsize;

    for(i = 0; i < file_table_size; i++)
	if(file_table[i] == NULL)
	    return i;

    newsize = file_table_size + 16;
    file_table = av_realloc(file_table, sizeof(*file_table) * newsize);
    for(i = file_table_size; i < newsize; i++)
	file_table[i] = NULL;
    
    i = file_table_size;
    file_table_size = newsize;
    
    return i;
}


static void put_file(vfile *vf)
{
    AV_UNLOCK(vf->lock);
    av_unref_obj(vf);
}

static int get_file(int fd, vfile **resp)
{
    vfile *vf = NULL;

    AV_LOCK(files_lock);
    if(fd >= 0 && fd < file_table_size) {
        vf = file_table[fd];
        if(vf != NULL)
            av_ref_obj(vf);
    }
    AV_UNLOCK(files_lock);

    if(vf == NULL)
        return -EBADF;

    AV_LOCK(vf->lock);
    if(vf->mnt == NULL) {
        put_file(vf);
        return -EBADF;
    }
    
    *resp = vf;
    
    return 0;
}

static void free_vfile(vfile *vf)
{
    AV_FREELOCK(vf->lock);
}

int av_fd_open_entry(ventry *ve, int flags, avmode_t mode)
{
    int res;
    int fd;
    vfile *vf;

    AV_NEW_OBJ(vf, free_vfile);
    AV_INITLOCK(vf->lock);
    res = av_file_open(vf, ve, flags, mode);
    if(res < 0) {
        av_unref_obj(vf);
        return res;
    }

    AV_LOCK(files_lock);
    fd = find_unused();
    file_table[fd] = vf;
    AV_UNLOCK(files_lock);

    return fd;
}

int av_fd_open(const char *path, int flags, avmode_t mode)
{
    int res;
    ventry *ve;
    
    res = av_get_ventry(path, !(flags & AVO_NOFOLLOW), &ve);
    if(res < 0)
        return res;

    res = av_fd_open_entry(ve, flags, mode);
    av_free_ventry(ve);

    return res;
}

int av_fd_close(int fd)
{
    int res;
    vfile *vf;

    res = get_file(fd, &vf);
    if(res == 0) {
        res = av_file_close(vf);
        put_file(vf);

        AV_LOCK(files_lock);
        file_table[fd] = NULL;
        AV_UNLOCK(files_lock);

        av_unref_obj(vf);
    }

    return res;
}

avssize_t av_fd_read(int fd, void *buf, avsize_t nbyte)
{
    avssize_t res;
    vfile *vf;

    res = get_file(fd, &vf);
    if(res == 0) {
        res = av_file_read(vf, buf, nbyte);
        put_file(vf);
    }

    return res;
}

avssize_t av_fd_write(int fd, const char *buf, avsize_t nbyte)
{
    avssize_t res;
    vfile *vf;

    res = get_file(fd, &vf);
    if(res == 0) {
        res = av_file_write(vf, buf, nbyte);
        put_file(vf);
    }

    return res;
}

static avoff_t dir_lseek(vfile *vf, avoff_t offset, int whence)
{
    switch(whence) {
    case AVSEEK_SET:
        if(offset < 0)
            return -EINVAL;

        vf->ptr = offset;
        break;
        
    case AVSEEK_CUR:
        if(offset != 0)
            return -EINVAL;
        break;
        
    default:
        return -EINVAL;
    }

    return vf->ptr;
}

avoff_t av_fd_lseek(int fd, avoff_t offset, int whence)
{
    avoff_t res;
    vfile *vf;

    res = get_file(fd, &vf);
    if(res == 0) {
        if((vf->flags & AVO_DIRECTORY) != 0)
            res = dir_lseek(vf, offset, whence);
        else
            res = av_file_lseek(vf, offset, whence);
	put_file(vf);
    }

    return res;
}

int av_fd_readdir(int fd, struct avdirent *buf, avoff_t *posp)
{
    int res;
    vfile *vf;

    res = get_file(fd, &vf);
    if(res == 0) {
        struct avfs *avfs = vf->mnt->avfs;

	*posp = vf->ptr;
        AVFS_LOCK(avfs);
	res = avfs->readdir(vf, buf);
        AVFS_UNLOCK(avfs);


	put_file(vf);
    }

    return res;
}

int av_fd_getattr(int fd, struct avstat *buf, int attrmask)
{
    int res;
    vfile *vf;

    res = get_file(fd, &vf);
    if(res == 0) {
        res = av_file_getattr(vf, buf, attrmask);
	put_file(vf);
    }

    return res;
}

int av_fd_setattr(int fd, struct avstat *buf, int attrmask)
{
    int res;
    vfile *vf;

    res = get_file(fd, &vf);
    if(res == 0) {
        res = av_file_setattr(vf, buf, attrmask);
	put_file(vf);
    }

    return res;
}

int av_fd_truncate(int fd, avoff_t length)
{
    int res;
    vfile *vf;

    res = get_file(fd, &vf);
    if(res == 0) {
        res = av_file_truncate(vf, length);
	put_file(vf);
    }

    return res;
}

void av_close_all_files()
{
    int fd;
    vfile *vf;
    
    AV_LOCK(files_lock);
    for(fd = 0; fd < file_table_size; fd++) {
        vf = file_table[fd];
        if(vf != NULL) {
            av_log(AVLOG_WARNING, "File handle still in use: %i", fd);
            av_file_close(vf);
            av_unref_obj(vf);
        }
    }
    av_free(file_table);
    file_table = NULL;
    AV_UNLOCK(files_lock);
}
