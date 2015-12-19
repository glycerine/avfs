/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "filter.h"
#include "version.h"
#include "filtprog.h"
#include "filecache.h"
#include "cache.h"
#include "internal.h"
#include "oper.h"

/* FIXME: If there was an error in read, this shouldn't be kept in cache */

struct filtid {
    avino_t ino;
    avdev_t dev;
};

struct filtmod {
    avoff_t size;
    avtimestruc_t mtime;
};

struct filtnode {
    avmutex lock;
    vfile *vf;
    struct sfile *sf;
    struct filtid id;
    struct filtmod mod;
    avino_t ino;
    unsigned int writers;
};

struct filtfile {
    struct filtnode *nod;
    struct cacheobj *cobj;
    int iswrite;
};

static char **filt_copy_prog(const char *prog[])
{
    int num;
    const char **curr;
    char **copyprog;
    int i;

    if(prog == NULL)
        return NULL;

    for(num = 0, curr = prog; *curr != NULL; curr++, num++);
    
    copyprog = (char **) av_malloc(sizeof(char *) * (num + 1));

    for(i = 0; i < num; i++)
        copyprog[i] = av_strdup(prog[i]);

    copyprog[i] = NULL;

    return copyprog;
}

static void filt_free_prog(char **prog)
{
    if(prog != NULL) {
        char **curr;

        for(curr = prog; *curr != NULL; curr++)
            av_free(*curr);
        
        av_free(prog);
    }
}

static int filt_lookup(ventry *ve, const char *name, void **newp)
{
    char *path = (char *) ve->data;
    
    if(path == NULL) {
        if(name[0] != '\0')
            return -ENOENT;
	if(ve->mnt->opts[0] != '\0')
            return -ENOENT;
        path = av_strdup(name);
    }
    else if(name == NULL) {
        av_free(path);
        path = NULL;
    }
    else 
        return -ENOENT;
    
    *newp = path;

    return 0;
}

static void filtnode_free(struct filtnode *nod)
{
    av_unref_obj(nod->sf);
    av_close(nod->vf);
    AV_FREELOCK(nod->lock)
}


static int filt_same_file(struct filtid *id, struct avstat *stbuf)
{
    if(id->ino == stbuf->ino && id->dev == stbuf->dev)
        return 1;
    else
        return 0;
}

static int filt_unmodif_file(struct filtmod *mod, struct avstat *stbuf)
{
    if(mod->size == stbuf->size && mod->mtime.sec == stbuf->mtime.sec &&
       mod->mtime.nsec == stbuf->mtime.nsec)
        return 1;
    else
        return 0;
}

static void filt_id_set(struct filtid *id, struct avstat *stbuf)
{
    id->ino = stbuf->ino;
    id->dev = stbuf->dev;
}

static void filt_mod_set(struct filtmod *mod, struct avstat *stbuf)
{
    mod->size = stbuf->size;
    mod->mtime = stbuf->mtime;
}


static void filt_newnode(struct filtfile *ff, ventry *ve, vfile *vf,
                         const char *key, struct avstat *buf)
{
    struct filtnode *nod;
    struct filtdata *filtdat = (struct filtdata *) ve->mnt->avfs->data;

    AV_NEW_OBJ(nod, filtnode_free);
    AV_INITLOCK(nod->lock);
    nod->vf = vf;
    nod->sf = av_filtprog_new(vf, filtdat);
    filt_id_set(&nod->id, buf);
    filt_mod_set(&nod->mod, buf);
    nod->ino = av_new_ino(ve->mnt->avfs);
    nod->writers = 0;

    AV_LOCK(nod->lock);

    ff->cobj = av_cacheobj_new(nod, key);
    ff->nod = nod;
    av_filecache_set(key, ff->cobj);
}

static int filt_validate_file(struct filtnode *nod, ventry *ve, vfile *vf,
                              struct avstat *buf, int iswrite)
{
    if(nod->writers == 0 && !filt_unmodif_file(&nod->mod, buf)) {
        struct filtdata *filtdat = (struct filtdata *) ve->mnt->avfs->data;
        
        av_unref_obj(nod->sf);
        av_close(nod->vf);
        nod->sf = av_filtprog_new(vf, filtdat);
        nod->vf = vf;
        filt_mod_set(&nod->mod, buf);
    }
    else if(nod->writers == 0 && iswrite) {
        avoff_t pos = av_lseek(nod->vf, 0, AVSEEK_CUR);

        if(pos > 0)
            pos = av_lseek(vf, pos, AVSEEK_SET);
        
        if(pos < 0)
            return pos;
        
        av_filtprog_change(nod->sf, vf);
        av_close(nod->vf);
        nod->vf = vf;
    }
    else
        av_close(vf);

    return 0;
}

static int filt_getfile(struct filtfile *ff, ventry *ve, vfile *vf,
                        const char *key)
{
    int res;
    struct avstat buf;
    int attrmask = AVA_INO | AVA_DEV | AVA_SIZE | AVA_MTIME;

    res = av_fgetattr(vf, &buf, attrmask);
    if(res < 0)
        return res;

    ff->cobj = (struct cacheobj *) av_filecache_get(key);
    if(ff->cobj != NULL)
        ff->nod = (struct filtnode *) av_cacheobj_get(ff->cobj);

    if(ff->nod == NULL || !filt_same_file(&ff->nod->id, &buf)) {
        av_unref_obj(ff->nod);
        av_unref_obj(ff->cobj);
        filt_newnode(ff, ve, vf, key, &buf);
        return 0;
    }

    AV_LOCK(ff->nod->lock);
    res = filt_validate_file(ff->nod, ve, vf, &buf, ff->iswrite);
    if(res < 0) {
        AV_UNLOCK(ff->nod->lock);
        av_unref_obj(ff->nod);
        av_unref_obj(ff->cobj);
        return res;
    }

    return 0;
}

static int filt_get_baseflags(int flags, int *maybecrp)
{
    int baseflags;
    int maybecreat = 0;

    if(AV_ISWRITE(flags))
        baseflags = AVO_RDWR;
    else
        baseflags = AVO_RDONLY;
    
    if((flags & AVO_TRUNC) != 0)
        baseflags |= AVO_TRUNC;

    if((flags & AVO_CREAT) != 0) {
        if(flags & AVO_EXCL)
            baseflags = AVO_RDWR | AVO_CREAT | AVO_EXCL | AVO_TRUNC;
        else if(flags & AVO_TRUNC)
            baseflags = AVO_RDWR | AVO_CREAT | AVO_TRUNC;
        else
            maybecreat = 1;
    }

    *maybecrp = maybecreat;
    return baseflags;
}

static int filt_open_base(ventry *ve, int flags, avmode_t mode, vfile **vfp,
                          int *bfresp)
{
    int res;
    int maybecreat;
    int baseflags;

    baseflags = filt_get_baseflags(flags, &maybecreat);

    res = av_open(ve->mnt->base, baseflags, mode, vfp);
    if(res == -ENOENT && maybecreat) {
        baseflags = AVO_RDWR | AVO_CREAT | AVO_TRUNC;
        res = av_open(ve->mnt->base, baseflags, mode, vfp);
    }

    *bfresp = baseflags;
    return res;
}

static int filt_open_file(struct filtfile *ff, ventry *ve, int flags,
                          avmode_t mode)
{
    int res;
    vfile *vf;
    char *key;
    int baseflags;
    
    res = filt_open_base(ve, flags, mode, &vf, &baseflags);
    if(res < 0)
        return res;

    res = av_filecache_getkey(ve, &key);
    if(res == 0) {
        if((baseflags & AVO_ACCMODE) == AVO_RDWR)
            ff->iswrite = 1;

        res = filt_getfile(ff, ve, vf, key);
        if(res == 0) {
            if((baseflags & AVO_TRUNC) != 0)
                av_sfile_truncate(ff->nod->sf, 0);

            if(ff->iswrite)
                ff->nod->writers ++;

            AV_UNLOCK(ff->nod->lock);
        }

        av_free(key);
    }
    if(res < 0) {
        av_close(vf);
        return res;
    }

    return 0;
}

static int filt_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    struct filtfile *ff;
    
    if(flags & AVO_DIRECTORY)
        return -ENOTDIR;

    AV_NEW(ff);
    ff->nod = NULL;
    ff->cobj = NULL;
    ff->iswrite = 0;

    res = filt_open_file(ff, ve, flags, mode);
    if(res < 0) {
        av_free(ff);
        return res;
    }

    *resp = ff;

    return 0;
}

static avssize_t filt_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct filtfile *ff = (struct filtfile *) vf->data;
    struct filtnode *nod = ff->nod;
    
    AV_LOCK(nod->lock);
    res = av_sfile_pread(nod->sf, buf, nbyte, vf->ptr);
    AV_UNLOCK(nod->lock);

    if(res > 0)
        vf->ptr += res;

    return res;
}

static avssize_t filt_write(vfile *vf, const char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct filtfile *ff = (struct filtfile *) vf->data;
    struct filtnode *nod = ff->nod;
    
    AV_LOCK(nod->lock);
    if((vf->flags & AVO_APPEND) != 0) {
        avoff_t pos;

        pos = av_sfile_size(nod->sf);
        if(pos < 0) {
            AV_UNLOCK(nod->lock);
            return pos;
        }
        
        vf->ptr = pos;
    }
    res = av_sfile_pwrite(nod->sf, buf, nbyte, vf->ptr);
    if(res >= 0)
        av_curr_time(&nod->mod.mtime);
    AV_UNLOCK(nod->lock);
        
    if(res > 0)
        vf->ptr += res;

    return res;
}

static int filt_truncate(vfile *vf, avoff_t length)
{
    int res;
    struct filtfile *ff = (struct filtfile *) vf->data;
    struct filtnode *nod = ff->nod;
    
    AV_LOCK(nod->lock);
    res = av_sfile_truncate(nod->sf, length);
    AV_UNLOCK(nod->lock);

    return res;
}

static void filt_afterflush(vfile *vf, struct filtnode *nod)
{
    int res;
    struct avstat stbuf;
    int attrmask = AVA_INO | AVA_DEV | AVA_SIZE | AVA_MTIME;
    avoff_t size = -1;
    vfile *bvf;

    res = av_fgetattr(nod->vf, &stbuf, AVA_SIZE);
    if(res == 0)
        size = stbuf.size;

    av_close(nod->vf);
    nod->vf = NULL;
    nod->mod.size = -1;

    res = av_open(vf->mnt->base, AVO_NOPERM, 0, &bvf);
    if(res < 0)
        return;

    res = av_fgetattr(bvf, &stbuf, attrmask);
    if(res == 0 && filt_same_file(&nod->id, &stbuf) && stbuf.size == size)
        filt_mod_set(&nod->mod, &stbuf);
        
    av_close(bvf);
}

static int filt_close(vfile *vf)
{
    int res = 0;
    struct filtfile *ff = (struct filtfile *) vf->data;
    struct filtnode *nod = ff->nod;
    avoff_t du;

    AV_LOCK(nod->lock);
    if(ff->iswrite) {
        nod->writers --;

        if(nod->writers == 0) {
            res = av_sfile_flush(nod->sf);
            filt_afterflush(vf, nod);
        }
    }
    du = av_sfile_diskusage(nod->sf);
    if(du >= 0)
        av_cacheobj_setsize(ff->cobj, du);
    AV_UNLOCK(nod->lock);

    av_unref_obj(nod);
    av_unref_obj(ff->cobj);
    av_free(ff);

    return res;
}

static int filt_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    struct filtfile *ff = (struct filtfile *) vf->data;
    struct filtnode *nod = ff->nod;
    struct avstat origbuf;
    int res;
    avoff_t size = -1;
    avino_t ino;
    avtimestruc_t mtime;

    AV_LOCK(nod->lock);
    ino = nod->ino;
    res = av_fgetattr(nod->vf, &origbuf, AVA_ALL & ~AVA_SIZE);
    if(res == 0) { 
        size = av_sfile_size(nod->sf);
        if(size < 0)
            res = size;
    }
    if(nod->writers != 0)
        mtime = nod->mod.mtime;
    else
        mtime = origbuf.mtime;
    AV_UNLOCK(nod->lock);

    if(res < 0)
        return res;

    *buf = origbuf;
    buf->mode &= ~(07000);
    buf->blksize = 4096;
    buf->dev = vf->mnt->avfs->dev;
    buf->ino = ino;
    buf->size = size;
    buf->blocks = AV_BLOCKS(size);
    buf->mtime = mtime;
    
    return 0;
}

static int filt_setattr(vfile *vf, struct avstat *buf, int attrmask)
{
    int res;
    struct filtfile *ff = (struct filtfile *) vf->data;
    struct filtnode *nod = ff->nod;

    AV_LOCK(nod->lock);
    res = av_fsetattr(nod->vf, buf, attrmask);
    AV_UNLOCK(nod->lock);

    return res;    
}

static int filt_access(ventry *ve, int amode)
{
    return av_access(ve->mnt->base, amode);
}

static int filt_rename(ventry *ve, ventry *newve)
{
    return -EXDEV;
}

static int filt_unlink(ventry *ve)
{
    return av_unlink(ve->mnt->base);
}

static void filt_destroy(struct avfs *avfs)
{
    struct filtdata *filtdat = (struct filtdata *) avfs->data;

    filt_free_prog(filtdat->prog);
    filt_free_prog(filtdat->revprog);
    av_free(filtdat);
}

int av_init_filt(struct vmodule *module, int version, const char *name,
                 const char *prog[], const char *revprog[],
                 struct ext_info *exts, struct avfs **resp)
{
    int res;
    struct avfs *avfs;
    struct filtdata *filtdat;
    
    res = av_new_avfs(name, exts, version, AVF_NOLOCK, module, &avfs);
    if(res < 0)
        return res;

    AV_NEW(filtdat);
    filtdat->prog = filt_copy_prog(prog);
    filtdat->revprog = filt_copy_prog(revprog);

    avfs->data = filtdat;

    avfs->destroy  = filt_destroy;
    avfs->lookup   = filt_lookup;
    avfs->access   = filt_access;
    avfs->unlink   = filt_unlink;
    avfs->rename   = filt_rename;  
    avfs->open     = filt_open;
    avfs->close    = filt_close; 
    avfs->read     = filt_read;
    avfs->write    = filt_write;
    avfs->getattr  = filt_getattr;
    avfs->setattr  = filt_setattr;
    avfs->truncate = filt_truncate;

    av_add_avfs(avfs);
    
    *resp = avfs;

    return 0;
}
