/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "archint.h"
#include "namespace.h"
#include "filecache.h"
#include "internal.h"
#include "oper.h"

static struct archent *arch_ventry_entry(ventry *ve)
{
    return (struct archent *) ve->data;
}

static void arch_free_tree(struct entry *parent)
{
    struct entry *ent;
    struct archnode *nod;

    ent = av_namespace_subdir(NULL, parent);
    while(ent != NULL) {
        struct entry *next;
        
        arch_free_tree(ent);
        next = av_namespace_next(ent);
        av_unref_obj(ent);
        ent = next;
    }
    
    nod = (struct archnode *) av_namespace_get(parent);
    av_unref_obj(nod);
    av_unref_obj(parent);
}

static void arch_delete(struct archive *arch)
{
    struct entry *root;

    if(arch->ns != NULL) {
        root = av_namespace_subdir(arch->ns, NULL);
        arch_free_tree(root);
        av_unref_obj(root);
        av_unref_obj(arch->ns);
    }

    AV_FREELOCK(arch->lock);
}

static int arch_same(struct archive *arch, struct avstat *stbuf)
{
    if(arch->st.ino == stbuf->ino &&
       arch->st.dev == stbuf->dev &&
       arch->st.size == stbuf->size &&
       AV_TIME_EQ(arch->st.mtime, stbuf->mtime))
        return 1;
    else
        return 0;
}

static int new_archive(ventry *ve, struct archive *arch)
{
    int res;
    struct archparams *ap = (struct archparams *) ve->mnt->avfs->data;
    struct entry *root;
    struct avstat stbuf;

    arch->avfs = ve->mnt->avfs;

    if(!(ap->flags & ARF_NOBASE)) {
        res = av_getattr(ve->mnt->base, &arch->st, AVA_ALL & ~AVA_SIZE, 0);
        if(res < 0)
            return res;
    }
    
    arch->ns = av_namespace_new();
    root = av_namespace_lookup(arch->ns, NULL, "");
    av_arch_default_dir(arch, root);
    av_unref_obj(root);

    res = ap->parse(ap->data, ve, arch);
    if(res < 0)
        return res;

    if(!(ap->flags & ARF_NOBASE)) {
        /* The size is only requested _after_ the parse, so bzip2 &
           al. won't suffer. */
        res = av_getattr(ve->mnt->base, &stbuf, AVA_SIZE, 0);
        if(res < 0)
            return res;
    }

    arch->st.size = stbuf.size;

    arch->flags |= ARCHF_READY;

    return 0;
}

static int check_archive(ventry *ve, struct archive *arch, int *neednew)
{
    int res;
    struct archparams *ap = (struct archparams *) ve->mnt->avfs->data;
    struct avstat stbuf;
    int attrmask = AVA_INO | AVA_DEV | AVA_SIZE | AVA_MTIME;
    
    if((ap->flags & ARF_NOBASE) != 0)
        return 0;

    res = av_getattr(ve->mnt->base, &stbuf, attrmask, 0);
    if(res < 0)
        return res;

    if(!arch_same(arch, &stbuf))
        *neednew = 1;

    return 0;
}

static struct archive *find_archive(const char *key)
{
    struct archive *arch;
    static AV_LOCK_DECL(lock);

    AV_LOCK(lock);
    arch = (struct archive *) av_filecache_get(key);
    if(arch == NULL) {
        AV_NEW_OBJ(arch, arch_delete);
        AV_INITLOCK(arch->lock);
        arch->flags = 0;
        arch->ns = NULL;
        arch->numread = 0;
        av_filecache_set(key, arch);
    }
    AV_UNLOCK(lock);

    return arch;
}

static int get_archive(ventry *ve, struct archive **archp)
{
    int res;
    char *key;
    struct archive *arch = NULL;
    int neednew;
    int tries;

    res = av_filecache_getkey(ve, &key);
    if(res < 0)
        return res;

    tries = 0;
    do {
        if(tries > 5) {
            av_log(AVLOG_ERROR, "ARCH: Giving up trying to create archive");
            res = -EIO;
            break;
        }
        arch = find_archive(key);

        neednew = 0;
        AV_LOCK(arch->lock);
        if(!(arch->flags & ARCHF_READY))
            res = new_archive(ve, arch);
        else
            res = check_archive(ve, arch, &neednew);
        if(res < 0 || neednew) {
            AV_UNLOCK(arch->lock);
            av_unref_obj(arch);
            av_filecache_set(key, NULL);
        }
        tries ++;
    } while(neednew);

    av_free(key);
    if(res < 0)
        return res;

    *archp = arch;
    return 0;
}

static int lookup_check_node(struct entry *ent, const char *name)
{
    struct archnode *nod = (struct archnode *) av_namespace_get(ent);
    
    if(nod == NULL)
        return -ENOENT;
    
    if(name != NULL && !AV_ISDIR(nod->st.mode))
        return -ENOTDIR;

    return 0;
}

static int arch_lookup(ventry *ve, const char *name, void **newp)
{
    int res;
    int type;
    struct archent *ae = arch_ventry_entry(ve);
    struct entry *ent;
    struct archive *arch;
 
    if(ae == NULL) {
        if(name[0] != '\0')
            return -ENOENT;

        AV_NEW(ae);
        ae->ent = NULL;
        res = get_archive(ve, &arch);
        if(res < 0) {
            av_free(ae);
            return res;
        }
        ae->arch = arch;
    }
    else {
        arch = ae->arch;
        AV_LOCK(arch->lock);
        res = lookup_check_node(ae->ent, name);
        if(res < 0) {
            AV_UNLOCK(arch->lock);
            return res;
        }
    }

    ent = av_namespace_lookup_all(arch->ns, ae->ent, name);
    av_unref_obj(ae->ent);
    if(ent == NULL) {
        av_unref_obj(ae->arch);
        av_free(ae);
        ae = NULL;
        type = 0;
    }
    else {
        struct archnode *nod = (struct archnode *) av_namespace_get(ent);

        if(nod != NULL)
            type = AV_TYPE(nod->st.mode);
        else
            type = 0;

        ae->ent = ent;        
    }
    AV_UNLOCK(arch->lock);

    *newp = ae;
    return type;
}

static void arch_putent(ventry *ve)
{
    struct archent *ae = arch_ventry_entry(ve);

    av_unref_obj(ae->ent);
    av_unref_obj(ae->arch);

    av_free(ae);
}

static int arch_copyent(ventry *ve, void **resp)
{
    struct archent *ae = arch_ventry_entry(ve);
    struct archent *nae;

    AV_NEW(nae);
    nae->ent = ae->ent;
    nae->arch = ae->arch;
    
    av_ref_obj(nae->ent);
    av_ref_obj(nae->arch);

    *resp = nae;
    return 0;
}

static int arch_getpath(ventry *ve, char **resp)
{
    struct archent *ae = arch_ventry_entry(ve);
    
    *resp = av_namespace_getpath(ae->ent);

    return 0;
}
static int arch_real_open(int flags)
{
    if((flags & AVO_DIRECTORY) == 0 && (flags & AVO_ACCMODE) != AVO_NOPERM)
        return 1;
    else
        return 0;
}

static void arch_do_close(struct archfile *fil, int realopen)
{
    struct archive *arch = fil->arch;
    struct archparams *ap = (struct archparams *) arch->avfs->data;

    if(realopen) {
        if(fil->basefile != NULL) {
            arch->numread --;
            if(arch->numread == 0) {
                av_close(arch->basefile);
                arch->basefile = NULL;
            }
        }

        fil->nod->numopen --;
        if(fil->nod->numopen == 0 && ap->release != NULL)
            ap->release(arch, fil->nod);
    }

    av_unref_obj(fil->arch);
    av_unref_obj(fil->nod);
    av_unref_obj(fil->ent);
    av_unref_obj(fil->curr);
    av_free(fil);
}

static int arch_do_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    struct archent *ae = arch_ventry_entry(ve);
    struct archfile *fil;
    struct archnode *nod = (struct archnode *) av_namespace_get(ae->ent);
    struct archive *arch = ae->arch;
    struct archparams *ap = (struct archparams *) ve->mnt->avfs->data;
    vfile *basefile = NULL;
    int realopen;
   
    if(nod == NULL)
        return -ENOENT;

    if(AV_ISWRITE(flags))
        return -EROFS;

    if((flags & AVO_DIRECTORY) != 0 && !AV_ISDIR(nod->st.mode))
        return -ENOTDIR;
    
    realopen = arch_real_open(flags);
    if(realopen) {
        if(!(ap->flags & ARF_NOBASE)) {
            if(arch->basefile == NULL) {
                res = av_open(ve->mnt->base, AVO_RDONLY, 0, &arch->basefile);
                if(res < 0)
                    return res;
            }

            arch->numread ++;
            basefile = arch->basefile;
        }

        nod->numopen ++;
    }
    
    AV_NEW(fil);
    fil->basefile = basefile;
    fil->arch = arch;
    fil->nod = nod;
    fil->data = NULL;
    
    if((flags & AVO_DIRECTORY))
        fil->ent = ae->ent;
    else
        fil->ent = NULL;

    fil->curr = NULL;
    fil->currn = -1;

    av_ref_obj(fil->arch);
    av_ref_obj(fil->nod);
    av_ref_obj(fil->ent);

    if(realopen && ap->open != NULL) {
        res = ap->open(ve, fil);
        if(res < 0) {
            arch_do_close(fil, realopen);
            return res;
        }
    }

    *resp = fil;
    return 0;
}


static int arch_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    struct archent *ae = arch_ventry_entry(ve);
    struct archive *arch = ae->arch;
 
    AV_LOCK(arch->lock);
    res = arch_do_open(ve, flags, mode, resp);
    AV_UNLOCK(arch->lock);
    
    return res;
}


static int arch_close(vfile *vf)
{
    int res;
    struct archfile *fil = arch_vfile_file(vf);
    struct archive *arch = fil->arch;
    struct archparams *ap = (struct archparams *) vf->mnt->avfs->data;
    int realopen = arch_real_open(vf->flags);

    AV_LOCK(arch->lock);
    if(realopen && ap->close != NULL)
        res = ap->close(fil);
    else
        res = 0;
    arch_do_close(fil, realopen);
    AV_UNLOCK(arch->lock);

    return res;
}

avssize_t av_arch_read(vfile *vf, char *buf, avsize_t nbyte)
{
    int res;
    avoff_t realoff;
    struct archfile *fil = arch_vfile_file(vf);
    struct archnode *nod = fil->nod;
    avoff_t nact;

    if(AV_ISDIR(nod->st.mode))
        return -EISDIR;

    if(nbyte == 0 || vf->ptr >= nod->realsize)
        return 0;

    realoff = vf->ptr + nod->offset;
    nact = AV_MIN((avoff_t)nbyte, (avoff_t) (nod->realsize - vf->ptr));

    // due to the MIN, nact is not larger than the range of avsize_t
    res = av_pread(fil->basefile, buf, (avsize_t)nact, realoff);
    if(res > 0)
        vf->ptr += res;

    return res;
}

static avssize_t arch_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct archfile *fil = arch_vfile_file(vf);
    struct archive *arch = fil->arch;
    struct archparams *ap = (struct archparams *) vf->mnt->avfs->data;
    
    AV_LOCK(arch->lock);
    if(AV_ISDIR(fil->nod->st.mode))
	res = -EISDIR;
    else
	res =  ap->read(vf, buf, nbyte);
    AV_UNLOCK(arch->lock);

    return res;
}

static struct archnode *arch_special_entry(int n, struct entry *ent,
                                           char **namep)
{
    struct archnode *nod;

    if(n == 0) {
        *namep = av_strdup(".");
        nod = (struct archnode *) av_namespace_get(ent);
        return nod;
    }
    else {
        struct entry *parent;

        *namep = av_strdup("..");
        parent = av_namespace_parent(ent);
        if(parent != NULL)
            nod = (struct archnode *) av_namespace_get(parent);
        else
            nod = (struct archnode *) av_namespace_get(ent);

        av_unref_obj(parent);
        return nod;
    }
}

static struct archnode *arch_nth_entry(int n, struct archfile *fil,
				       char **namep)
{
    struct entry *ent;
    struct archnode *nod;

    if(n  < 2)
        return arch_special_entry(n, fil->ent, namep);
    
    n -= 2;
    if(n == 0 || fil->currn != n - 1)
	ent = av_namespace_nth(NULL, fil->ent, n);
    else
	ent = av_namespace_next(fil->curr);

    av_unref_obj(fil->curr);
    fil->curr = ent;
    fil->currn = n;

    if(ent == NULL)
        return NULL;

    *namep = av_namespace_name(ent);
    nod = (struct archnode *) av_namespace_get(ent);

    return nod;
}

static int arch_readdir(vfile *vf, struct avdirent *buf)
{
    int res;
    struct archfile *fil = arch_vfile_file(vf);
    struct archive *arch = fil->arch;
    struct archnode *nod;
    char *name;

    AV_LOCK(arch->lock);
    nod = arch_nth_entry(vf->ptr, fil, &name);
    if(nod == NULL)
        res = 0;
    else {
        buf->name = name;
        buf->ino = nod->st.ino;
        buf->type = AV_TYPE(nod->st.mode);
        
        vf->ptr ++;
        res = 1;
    }
    AV_UNLOCK(arch->lock);

    return res;
}

static int arch_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
     struct archfile *fil = arch_vfile_file(vf);
     struct archnode *nod = fil->nod;
     struct archive *arch = fil->arch;
    
     AV_LOCK(arch->lock);
     *buf = nod->st;
     AV_UNLOCK(arch->lock);

     return 0;
}

static int arch_access(ventry *ve, int amode)
{
    if((amode & AVW_OK) != 0)
        return -EACCES;

    return 0;
}

static int arch_readlink(ventry *ve, char **bufp)
{
    int res;
    struct archent *ae = arch_ventry_entry(ve);
    struct archnode *nod;
    struct archive *arch = ae->arch;

    AV_LOCK(arch->lock);
    nod = (struct archnode *) av_namespace_get(ae->ent);
    if(nod == NULL)
        res = -ENOENT;
    else if(!AV_ISLNK(nod->st.mode))
        res = -EINVAL;
    else if(nod->linkname == NULL) {
	av_log(AVLOG_ERROR, "ARCH: linkname is NULL");
	res = -EIO;
    }
    else {
        *bufp = av_strdup(nod->linkname);
        res = 0;
    }
    AV_UNLOCK(arch->lock);    

    return res;
}

static void arch_destroy(struct avfs *avfs)
{
    struct archparams *ap = (struct archparams *) avfs->data;

    av_unref_obj(ap->data);
    av_free(ap);
}


int av_archive_init(const char *name, struct ext_info *exts, int version,
                    struct vmodule *module, struct avfs **avfsp)
{
    int res;
    struct avfs *avfs;
    struct archparams *ap;

    res = av_new_avfs(name, exts, version, AVF_NOLOCK, module, &avfs);
    if(res < 0)
        return res;

    avfs->lookup    = arch_lookup;
    avfs->putent    = arch_putent;
    avfs->copyent   = arch_copyent;
    avfs->getpath   = arch_getpath;
    avfs->open      = arch_open;
    avfs->close     = arch_close;
    avfs->read      = arch_read;
    avfs->readdir   = arch_readdir;
    avfs->getattr   = arch_getattr;
    avfs->access    = arch_access;
    avfs->readlink  = arch_readlink;
    avfs->destroy   = arch_destroy;

    AV_NEW(ap);
    ap->data = NULL;
    ap->flags = 0;
    ap->parse = NULL;
    ap->open = NULL;
    ap->close = NULL;
    ap->read = av_arch_read;
    ap->release = NULL;

    avfs->data = ap;

    *avfsp = avfs;
    
    return 0;
}

