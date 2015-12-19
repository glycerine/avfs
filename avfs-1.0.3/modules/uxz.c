/*  
    AVFS: A Virtual File System Library
    Copyright (C) 2010  Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    UXZ module (based on UBZ2 module)
*/

#include "version.h"

#include "xzfile.h"
#include "filecache.h"
#include "oper.h"
#include "version.h"

struct xznode {
    struct avstat sig;
    struct xzcache *cache;
    avino_t ino;
};

struct xzhandle {
    struct xzfile *zfil;
    vfile *base;
    struct xznode *node;
};


static void xznode_destroy(struct xznode *nod)
{
    av_unref_obj(nod->cache);
}

static struct xznode *xz_new_node(ventry *ve, struct avstat *stbuf)
{
    struct xznode *nod;

    AV_NEW_OBJ(nod, xznode_destroy);
    nod->sig = *stbuf;
    nod->cache = av_xzcache_new();
    nod->ino = av_new_ino(ve->mnt->avfs);
    
    return nod;
}

static int xz_same(struct xznode *nod, struct avstat *stbuf)
{
    if(nod->sig.ino == stbuf->ino &&
       nod->sig.dev == stbuf->dev &&
       nod->sig.size == stbuf->size &&
       AV_TIME_EQ(nod->sig.mtime, stbuf->mtime))
        return 1;
    else
        return 0;
}

static struct xznode *xz_do_get_node(ventry *ve, const char *key,
                                     struct avstat *stbuf)
{
    static AV_LOCK_DECL(lock);
    struct xznode *nod;

    AV_LOCK(lock);
    nod = (struct xznode *) av_filecache_get(key);
    if(nod != NULL) {
        if(!xz_same(nod, stbuf)) {
            av_unref_obj(nod);
            nod = NULL;
        }
    }
    
    if(nod == NULL) {
        nod =  xz_new_node(ve, stbuf);
        av_filecache_set(key, nod);
    }
    AV_UNLOCK(lock);

    return nod;
}

static int xz_getnode(ventry *ve, vfile *base, struct xznode **resp)
{
    int res;
    struct avstat stbuf;
    const int attrmask = AVA_INO | AVA_DEV | AVA_SIZE | AVA_MTIME;
    struct xznode *nod;
    char *key;

    res = av_fgetattr(base, &stbuf, attrmask);
    if(res < 0)
        return res;

    res = av_filecache_getkey(ve, &key);
    if(res < 0)
        return res;

    nod = xz_do_get_node(ve, key, &stbuf);

    av_free(key);

    *resp = nod;
    return 0;
}

static int xz_lookup(ventry *ve, const char *name, void **newp)
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

static int xz_access(ventry *ve, int amode)
{
    return av_access(ve->mnt->base, amode);
}

static int xz_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    vfile *base;
    struct xznode *nod;
    struct xzhandle *fil;

    if(flags & AVO_DIRECTORY)
        return -ENOTDIR;

    if(AV_ISWRITE(flags))
        return -EROFS;

    res = av_open(ve->mnt->base, AVO_RDONLY, 0, &base);
    if(res < 0)
        return res;

    res = xz_getnode(ve, base, &nod);
    if(res < 0) {
        av_close(base);
        return res;
    }

    AV_NEW(fil);
    if((flags & AVO_ACCMODE) != AVO_NOPERM)
        fil->zfil = av_xzfile_new(base);
    else
        fil->zfil = NULL;

    fil->base = base;
    fil->node = nod;
    
    *resp = fil;
    return 0;
}

static int xz_close(vfile *vf)
{
    struct xzhandle *fil = (struct xzhandle *) vf->data;

    av_unref_obj(fil->zfil);
    av_unref_obj(fil->node);
    av_close(fil->base);
    av_free(fil);

    return 0;
}

static avssize_t xz_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct xzhandle *fil = (struct xzhandle *) vf->data;
 
    res = av_xzfile_pread(fil->zfil, fil->node->cache, buf, nbyte, vf->ptr);
    if(res > 0)
        vf->ptr += res;

    return res;
}

static int xz_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    int res;
    struct xzhandle *fil = (struct xzhandle *) vf->data;
    struct xznode *nod = fil->node;
    avoff_t size;
    const int basemask = AVA_MODE | AVA_UID | AVA_GID | AVA_MTIME | AVA_ATIME | AVA_CTIME;

    res = av_fgetattr(fil->base, buf, basemask);
    if(res < 0)
        return res;

    if((attrmask & (AVA_SIZE | AVA_BLKCNT)) != 0) {
        res = av_xzfile_size(fil->zfil, fil->node->cache, &size);
        if(res == 0 && size == -1) {
            fil->zfil = av_xzfile_new(fil->base);
            res = av_xzfile_size(fil->zfil, fil->node->cache, &size);
        }
        if(res < 0)
            return res;

        buf->size = size;
        buf->blocks = AV_BLOCKS(buf->size);
    }

    buf->mode &= ~(07000);
    buf->blksize = 4096;
    buf->dev = vf->mnt->avfs->dev;
    buf->ino = nod->ino;
    buf->nlink = 1;
    
    return 0;
}

extern int av_init_module_uxz(struct vmodule *module);

int av_init_module_uxz(struct vmodule *module)
{
    int res;
    struct avfs *avfs;
    struct ext_info uxz_exts[5];

    uxz_exts[0].from = ".tar.xz",  uxz_exts[0].to = ".tar";
    uxz_exts[1].from = ".txz",  uxz_exts[1].to = ".tar";
    uxz_exts[2].from = ".xz",  uxz_exts[2].to = NULL;
    uxz_exts[3].from = ".lzma",  uxz_exts[3].to = NULL;
    uxz_exts[4].from = NULL;

    res = av_new_avfs("uxz", uxz_exts, AV_VER, AVF_NOLOCK, module, &avfs);
    if(res < 0)
        return res;

    avfs->lookup   = xz_lookup;
    avfs->access   = xz_access;
    avfs->open     = xz_open;
    avfs->close    = xz_close; 
    avfs->read     = xz_read;
    avfs->getattr  = xz_getattr;

    av_add_avfs(avfs);

    return 0;
}
