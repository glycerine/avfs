/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "filecache.h"
#include "internal.h"
#include "exit.h"

struct filecache {
    struct filecache *next;
    struct filecache *prev;
    
    char *key;
    void *obj;
};

static struct filecache fclist;
static AV_LOCK_DECL(fclock);

static void filecache_remove(struct filecache *fc)
{
    struct filecache *prev = fc->prev;
    struct filecache *next = fc->next;

    prev->next = next;
    next->prev = prev;
}

static void filecache_insert(struct filecache *fc)
{
    struct filecache *prev = &fclist;
    struct filecache *next = fclist.next;
    
    prev->next = fc;
    next->prev = fc;
    fc->prev = prev;
    fc->next = next;
}

static void filecache_delete(struct filecache *fc)
{
    av_log(AVLOG_DEBUG, "FILECACHE: delete <%s>", fc->key);
    filecache_remove(fc);

    av_unref_obj(fc->obj);
    av_free(fc->key);
    av_free(fc);
}

static struct filecache *filecache_find(const char *key)
{
    struct filecache *fc;
    
    for(fc = fclist.next; fc != &fclist; fc = fc->next) {
        if(strcmp(fc->key, key) == 0)
            break;
    }

    if(fc->obj == NULL)
        return NULL;

    return fc;
}

void *av_filecache_get(const char *key)
{
    struct filecache *fc;
    void *obj = NULL;
    
    AV_LOCK(fclock);
    fc = filecache_find(key);
    if(fc != NULL) {
        filecache_remove(fc);
        filecache_insert(fc);
        obj = fc->obj;
        av_ref_obj(obj);
    }
    AV_UNLOCK(fclock);

    return obj;
}

void av_filecache_set(const char *key, void *obj)
{
    struct filecache *oldfc;
    struct filecache *fc;

    if(obj != NULL) {
        AV_NEW(fc);
        fc->key = av_strdup(key);
        fc->obj = obj;
        av_ref_obj(obj);
    }
    else
        fc = NULL;

    AV_LOCK(fclock);
    oldfc = filecache_find(key);
    if(oldfc != NULL)
        filecache_delete(oldfc);
    if(fc != NULL) {
        av_log(AVLOG_DEBUG, "FILECACHE: insert <%s>", key);
        filecache_insert(fc);
    }
    AV_UNLOCK(fclock);
}

static void destroy_filecache()
{
    AV_LOCK(fclock);
    while(fclist.next != &fclist)
        filecache_delete(fclist.next);
    AV_UNLOCK(fclock);
}

void av_init_filecache()
{
    fclist.next = &fclist;
    fclist.prev = &fclist;
    fclist.obj = NULL;
    fclist.key = NULL;
    
    av_add_exithandler(destroy_filecache);
}


int av_filecache_getkey(ventry *ve, char **resp)
{
    int res;
    char *key;

    res = av_generate_path(ve->mnt->base, &key);
    if(res < 0)
        return res;

    key = av_stradd(key, AVFS_SEP_STR, ve->mnt->avfs->name, NULL);

    *resp = key;
    return 0;
}
