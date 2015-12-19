/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "state.h"
#include "version.h"

struct stentry {
    char *param;
    struct entry *ent; /* namespace.h */
};

struct stfile {
    struct stentry *stent;
    char *contents;
    int modif;
};

static struct stentry *state_ventry_stentry(ventry *ve)
{
    return (struct stentry *) ve->data;
}

static struct namespace *state_ventry_namespace(ventry *ve)
{
    return (struct namespace *) ve->mnt->avfs->data;
}

static struct stfile *state_vfile_stfile(vfile *vf)
{
    return (struct stfile *) vf->data;
}

static struct namespace *state_vfile_namespace(vfile *vf)
{
    return (struct namespace *) vf->mnt->avfs->data;
}

static void state_free_stentry(struct stentry *stent)
{
    av_free(stent->param);
    av_unref_obj(stent->ent);
}

static int state_lookup(ventry *ve, const char *name, void **newp)
{
    struct stentry *stent = state_ventry_stentry(ve);
    struct namespace *ns = state_ventry_namespace(ve);
    struct stentry *newent;
 
    if(stent != NULL) {
        if(stent->ent == NULL && (name == NULL || strcmp(name, "..") == 0))
            newent = NULL;
        else {
            AV_NEW_OBJ(newent, state_free_stentry);
            newent->ent = av_namespace_lookup_all(ns, stent->ent, name);
            newent->param = av_strdup(stent->param);
        }
    }
    else {
        AV_NEW_OBJ(newent, state_free_stentry);
        newent->ent = NULL;
        newent->param = av_strdup(name);
    }
    av_unref_obj(stent);
    
    *newp = newent;

    return 0;
}

static int state_getpath(ventry *ve, char **resp)
{
    char *path;
    char *nspath;
    struct stentry *stent = state_ventry_stentry(ve);

    path = av_strdup(stent->param);
    if(stent->ent != NULL) {
        nspath = av_namespace_getpath(stent->ent);
        path = av_stradd(path, "/", nspath, NULL);
        av_free(nspath);
    }

    *resp = path;

    return 0;
}

static void state_putent(ventry *ve)
{
    struct stentry *stent = state_ventry_stentry(ve);

    av_unref_obj(stent);
}

static int state_copyent(ventry *ve, void **resp)
{
    struct stentry *stent = state_ventry_stentry(ve);

    av_ref_obj(stent);
    *resp = stent;

    return 0;
}

static int state_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    struct stentry *stent = state_ventry_stentry(ve);
    struct namespace *ns = state_ventry_namespace(ve);
    struct stfile *sf;
    struct entry *subdir;
    struct statefile *stf;
    char *contents;

    subdir = av_namespace_subdir(ns, stent->ent);
    if(stent->ent != NULL)
        stf = (struct statefile *) av_namespace_get(stent->ent);
    else
        stf = NULL;
    
    if(subdir == NULL && (stf == NULL || (flags & AVO_DIRECTORY) != 0))
        return -ENOENT;

    av_unref_obj(subdir);

    contents = NULL;
    if(!(flags & AVO_DIRECTORY) && stf != NULL) {
        if(AV_ISWRITE(flags) && stf->set == NULL)
            return -EACCES;
            
        if((flags & AVO_TRUNC) != 0 || stf->get == NULL)
            contents = av_strdup("");
        else {
            res = stf->get(stent->ent, stent->param, &contents);
            if(res < 0)
                return res;
        }
    }

    AV_NEW(sf);
    sf->stent = stent;
    sf->contents = contents;
    sf->modif = 0;
    av_ref_obj(stent);

    if((flags & AVO_TRUNC) != 0)
        sf->modif = 1;

    *resp = sf;
    
    return 0;
}


static int state_close(vfile *vf)
{
    struct stfile *sf = state_vfile_stfile(vf);
    int res = 0;

    if(sf->modif && sf->stent->ent != NULL) {
        struct statefile *stf;

        stf = (struct statefile *) av_namespace_get(sf->stent->ent);

        res = stf->set(sf->stent->ent, sf->stent->param, sf->contents);
    }

    av_unref_obj(sf->stent);
    av_free(sf->contents);
    av_free(sf);

    return res;
}

static avssize_t state_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avoff_t nact;
    avoff_t size;
    struct stfile *sf = state_vfile_stfile(vf);

    if(sf->contents == NULL)
        return -EISDIR;

    size = strlen(sf->contents);
    if(vf->ptr >= size)
	return 0;
    
    // since nbyte is avsize_t, the min will not be larger than that datatype
    nact = AV_MIN((avoff_t)nbyte, (avoff_t) (size - vf->ptr));
    
    memcpy(buf, sf->contents + vf->ptr, nact);
    
    vf->ptr += nact;
    
    return nact;
}

static avssize_t state_write(vfile *vf, const char *buf, avsize_t nbyte)
{
    avoff_t end;
    struct stfile *sf = state_vfile_stfile(vf);
    avoff_t size;

    size = strlen(sf->contents);
    if((vf->flags & AVO_APPEND) != 0)
        vf->ptr = size;

    end = vf->ptr + nbyte;
    if(end > size) {
        sf->contents = av_realloc(sf->contents, end + 1);
        sf->contents[end] = '\0';
    }

    memcpy(sf->contents + vf->ptr, buf, nbyte);

    vf->ptr = end;
    sf->modif = 1;

    return nbyte;
}

static int state_truncate(vfile *vf, avoff_t length)
{
    struct stfile *sf = state_vfile_stfile(vf);
    avoff_t size;

    size = strlen(sf->contents);

    if(length < size)
        sf->contents[length] = '\0';

    sf->modif = 1;

    return 0;
}

static unsigned int state_paramhash(const char *param)
{
    unsigned long hash = 0;

    for(; *param; param++) {
        unsigned long c = *(const unsigned char *) param;
        hash = (hash + (c << 4) + (c >> 4)) * 11;
    }
    return hash;
}

static int state_readdir(vfile *vf, struct avdirent *buf)
{
    struct stfile *sf = state_vfile_stfile(vf);
    struct namespace *ns = state_vfile_namespace(vf);
    struct statefile *stf;
    struct entry *ent;
    int n;

    ent = av_namespace_subdir(ns, sf->stent->ent);
    for(n = vf->ptr; n > 0 && ent != NULL; n--) {
        struct entry *next;
        next = av_namespace_next(ent);
        av_unref_obj(ent);
        ent = next;
    }
    if(ent == NULL)
        return 0;
    
    buf->name = av_namespace_name(ent);
    stf = av_namespace_get(ent);

    /* FIXME: Make ino be some hash function of param and entry */
    buf->ino = (long) stf + state_paramhash(sf->stent->param);
    /* add hash of entry name to hash */
    buf->ino += state_paramhash( buf->name );
    /* make sure ino is not 0 or 1 */
    buf->ino = (avino_t)((((unsigned int)buf->ino) % (~0U - 1)) + 2);
    
    buf->type = 0;
    av_unref_obj(ent);
    
    vf->ptr ++;
    
    return 1;
}

static int state_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    struct stfile *sf = state_vfile_stfile(vf);
    struct statefile *stf;
    char *ent_name;

    if(sf->stent->ent != NULL)
        stf = (struct statefile *) av_namespace_get(sf->stent->ent);
    else
        stf = NULL;

    av_default_stat(buf);
    /* This isn't perfect, but... */
    buf->ino = (long) stf + state_paramhash(sf->stent->param);

    /* add hash of entry name to hash */
    if( sf->stent->ent != NULL ) {
      ent_name = av_namespace_name( sf->stent->ent );
      buf->ino += state_paramhash( ent_name );
      av_free( ent_name );
    }
    /* make sure ino is not 0 or 1 */
    buf->ino = (avino_t)((((unsigned int)buf->ino) % (~0U - 1)) + 2);
    
    buf->dev = vf->mnt->avfs->dev;
    if(stf != NULL) {
        if(stf->set != NULL)
            buf->mode = AV_IFREG | 0644;
        else
            buf->mode = AV_IFREG | 0444;
    }
    else
        buf->mode = AV_IFDIR | 0755;

    if(sf->contents != NULL) {
        buf->size = strlen(sf->contents);
        buf->blocks = AV_DIV(buf->size, 512);
    }
    buf->nlink = 1;

    return 0;
}

static int state_access(ventry *ve, int amode)
{
    struct stentry *stent = state_ventry_stentry(ve);
    struct namespace *ns = state_ventry_namespace(ve);
    struct entry *subdir;
    struct statefile *stf;

    subdir = av_namespace_subdir(ns, stent->ent);
    if(stent->ent != NULL)
        stf = (struct statefile *) av_namespace_get(stent->ent);
    else
        stf = NULL;
    
    if(subdir == NULL && stf == NULL)
        return -ENOENT;

    if((amode & AVW_OK) != 0 && stf != NULL && stf->set == NULL)
        return -EACCES;

    av_unref_obj(subdir);

    return 0;
}

static void state_free_tree(struct namespace *ns, struct entry *ent)
{
    struct entry *next;
    void *data;

    ent = av_namespace_subdir(ns, ent);
    while(ent != NULL) {
        state_free_tree(ns, ent);
        data = av_namespace_get(ent);
        if(data != NULL) {
            av_free(data);
            av_unref_obj(ent);
        }
        next = av_namespace_next(ent);
        av_unref_obj(ent);
        ent = next;
    }
}


static void state_destroy(struct avfs *avfs)
{
    struct namespace *ns = (struct namespace *) avfs->data;

    state_free_tree(ns, NULL);

    av_unref_obj(ns);
}

int av_state_new(struct vmodule *module, const char *name,
                   struct namespace **resp, struct avfs **avfsp)
{
    int res;
    struct avfs *avfs;
    struct namespace *ns;

    res = av_new_avfs(name, NULL, AV_VER, AVF_ONLYROOT, module, &avfs);
    if(res < 0)
        return res;

    ns = av_namespace_new();

    av_ref_obj(ns);
    avfs->data = ns;
    avfs->destroy = state_destroy;

    avfs->lookup    = state_lookup;
    avfs->putent    = state_putent;
    avfs->copyent   = state_copyent;
    avfs->getpath   = state_getpath;

    avfs->open      = state_open;
    avfs->close     = state_close;
    avfs->read      = state_read;
    avfs->write     = state_write;
    avfs->truncate  = state_truncate;
    avfs->readdir   = state_readdir;
    avfs->getattr   = state_getattr;
    avfs->access    = state_access;

    av_add_avfs(avfs);

    *resp = ns;
    *avfsp = avfs;
    
    return 0;
}
