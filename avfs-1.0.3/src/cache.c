/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>
    Copyright (C) 2006       Ralf Hoffmann (ralf@boomerangsworld.de)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

/* 
   TODO:
   
   Virtual filesystem where all the cached files can be found.

   There are two interfaces available:
   The av_cacheobj* functions are built around the cacheobj structure.
     The user holds the reference to it and can use it to access the
     stored object. The cache itself creates the cacheobj but doesn't
     hold a reference to it so it doesn't destroy the cacheobj but
     will unref the object stored in the cacheobj struct if the space
     is needed.
   The av_cache2* functions are built around the name as a key for
     stored object. The cacheobj is not return and the cache holds the
     only reference to it and will destroy it at some point.

*/

#include "cache.h"
#include "internal.h"
#include "exit.h"

#include <stdio.h>
#include <stdlib.h>

struct cacheobj {
    void *obj;
    avoff_t diskusage;
    char *name;

    struct cacheobj *next;
    struct cacheobj *prev;

    int internal_obj;
};

#define MBYTE (1024 * 1024)

static AV_LOCK_DECL(cachelock);
static struct cacheobj cachelist;
static avoff_t disk_cache_limit = 100 * MBYTE;
static avoff_t disk_keep_free = 10 * MBYTE;
static avoff_t disk_usage = 0;

static int cache_clear();

static int cache_getfunc(struct entry *ent, const char *param, char **retp)
{
    *retp = av_strdup("");
    return 0;
}

static int cache_setfunc(struct entry *ent, const char *param, const char *val)
{
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    int (*func)() = (int (*)()) sf->data;
    
    if(strlen(val) > 0)
        return func();

    return 0;
}

static int cache_getoff(struct entry *ent, const char *param, char **retp)
{
    char buf[64];
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    avoff_t *offp = (avoff_t *)  sf->data;

    AV_LOCK(cachelock);
    sprintf(buf, "%llu\n", *offp);
    AV_UNLOCK(cachelock);

    *retp = av_strdup(buf);
    return 0;
}

static int cache_setoff(struct entry *ent, const char *param, const char *val)
{
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    avoff_t *offp = (avoff_t *) sf->data;
    avoff_t offval;
    char *end;
    
    /* Make truncate work with fuse */
    if(!val[0])
        offval = 0;
    else {
        offval = strtoll(val, &end, 0);
        if(end == val)
            return -EINVAL;
        if(*end == '\n')
            end ++;
        if(*end != '\0')
            return -EINVAL;
        if(offval < 0)
            return -EINVAL;
    }

    AV_LOCK(cachelock);
    *offp = offval;
    AV_UNLOCK(cachelock);

    return 0;
}

/**
 * This is the exit handler to remove all temporary file stored
 * using the V2 interface
 */
static void destroy_cache()
{
    struct cacheobj *cobj;

    AV_LOCK(cachelock);
    for(cobj = &cachelist; cobj->next != &cachelist; ) {
        if(cobj->next->internal_obj) {
            /* unref the internal objects which will remove it */
            av_unref_obj(cobj->next);
        } else {
            /* this shouldn't happen, there shouldn't be
             * any external object left at exit */
            cobj = cobj->next;
        }
    }
    AV_UNLOCK(cachelock);
}

void av_init_cache()
{
    struct statefile statf;

    cachelist.next = &cachelist;
    cachelist.prev = &cachelist;

    statf.get = cache_getoff;
    statf.set = cache_setoff;
 
    statf.data = &disk_cache_limit;
    av_avfsstat_register("cache/limit", &statf);
    
    statf.data = &disk_keep_free;
    av_avfsstat_register("cache/keep_free", &statf);

    statf.set = NULL;
    statf.data = &disk_usage;
    av_avfsstat_register("cache/usage", &statf);

    statf.set = cache_setfunc;
    statf.get = cache_getfunc;
    statf.data = cache_clear;
    av_avfsstat_register("cache/clear", &statf);
    
    av_add_exithandler(destroy_cache);
}

static void cacheobj_remove(struct cacheobj *cobj)
{
    struct cacheobj *next;
    struct cacheobj *prev;
    
    next = cobj->next;
    prev = cobj->prev;
    next->prev = prev;
    prev->next = next;
}

static void cacheobj_insert(struct cacheobj *cobj)
{
    struct cacheobj *next;
    struct cacheobj *prev;

    next = cachelist.next;
    prev = &cachelist;
    next->prev = cobj;
    prev->next = cobj;
    cobj->next = next;
    cobj->prev = prev;
}

static void cacheobj_free(struct cacheobj *cobj)
{
    av_unref_obj(cobj->obj);
    av_log(AVLOG_DEBUG, "got rid of cached object <%s> size %lli",
             cobj->name != NULL ? cobj->name : "?", cobj->diskusage);
    av_free(cobj->name);
}

/**
 * This is the destructor for external cacheobj's created
 * using the V1 interface
 */
static void cacheobj_delete(struct cacheobj *cobj)
{
    AV_LOCK(cachelock);
    if(cobj->obj != NULL) {
        cacheobj_remove(cobj);
        disk_usage -= cobj->diskusage;
    }
    AV_UNLOCK(cachelock);

    if(cobj->obj != NULL)
        cacheobj_free(cobj);
}

/**
 * This is the destructor for internal cacheobj's created
 * using the V2 interface
 * Because of possible race conditions the object can only
 * by destroyed when holding the lock
 */
static void cacheobj_internal_delete(struct cacheobj *cobj)
{
    if(cobj->obj != NULL) {
        cacheobj_remove(cobj);
        disk_usage -= cobj->diskusage;
    }

    AV_UNLOCK(cachelock);
    if(cobj->obj != NULL)
        cacheobj_free(cobj);
    AV_LOCK(cachelock);
}

struct cacheobj *av_cacheobj_new(void *obj, const char *name)
{
    struct cacheobj *cobj;

    if(obj == NULL)
        return NULL;

    AV_NEW_OBJ(cobj, cacheobj_delete);
    cobj->obj = obj;
    cobj->diskusage = 0;
    cobj->name = av_strdup(name);
    cobj->internal_obj = 0;
    av_ref_obj(obj);

    AV_LOCK(cachelock);
    cacheobj_insert(cobj);
    AV_UNLOCK(cachelock);

    return cobj;
}

static int cache_free_one(struct cacheobj *skip_entry)
{
    struct cacheobj *cobj;
    struct cacheobj tmpcobj;

    cobj = cachelist.prev;
    if(cobj == skip_entry)
	cobj = cobj->prev;
    if(cobj == &cachelist)
        return 0;

    if(cobj->internal_obj) {
        av_unref_obj(cobj);
    } else {
        cacheobj_remove(cobj);
        disk_usage -= cobj->diskusage;
        tmpcobj = *cobj;
        cobj->obj = NULL;
        AV_UNLOCK(cachelock);
        cacheobj_free(&tmpcobj);
        AV_LOCK(cachelock);
    }

    return 1;
}

static int cache_clear()
{
    AV_LOCK(cachelock);
    while(cache_free_one(NULL));
    AV_UNLOCK(cachelock);
    
    return 0;
}

static void cache_checkspace(int full, struct cacheobj *skip_entry)
{
    avoff_t tmpfree;
    avoff_t limit;
    avoff_t keepfree;
    
    if(full)
        tmpfree = 0;
    else
        tmpfree = av_tmp_free();

    /* If free space can't be determined, then it is taken to be infinite */
    if(tmpfree == -1)
        tmpfree = AV_MAXOFF;
    
    keepfree = disk_keep_free;
    if(keepfree < 100 * 1024)
        keepfree = 100 * 1024;

    limit = disk_usage - disk_keep_free + tmpfree;
    if(disk_cache_limit < limit)
        limit = disk_cache_limit;
    
    while(disk_usage > limit)
        if(!cache_free_one(skip_entry))
            break;        
}


void av_cache_checkspace()
{
    AV_LOCK(cachelock);
    cache_checkspace(0,NULL);
    AV_UNLOCK(cachelock);
}

void av_cache_diskfull()
{
    AV_LOCK(cachelock);
    cache_checkspace(1,NULL);
    AV_UNLOCK(cachelock);
}


void av_cacheobj_setsize(struct cacheobj *cobj, avoff_t diskusage)
{
    AV_LOCK(cachelock);
    if(cobj->obj != NULL && cobj->diskusage != diskusage) {
        disk_usage -= cobj->diskusage;
        cobj->diskusage = diskusage;
        disk_usage += cobj->diskusage;
        
        cache_checkspace(0, cobj);
    }
    AV_UNLOCK(cachelock);
}

void *av_cacheobj_get(struct cacheobj *cobj)
{
    void *obj;

    if(cobj == NULL)
        return NULL;

    AV_LOCK(cachelock);
    obj = cobj->obj;
    if(obj != NULL) {
        cacheobj_remove(cobj);
        cacheobj_insert(cobj);
        av_ref_obj(obj);
    }
    AV_UNLOCK(cachelock);

    return obj;
}

static struct cacheobj *cacheobj2_find(const char *name)
{
    struct cacheobj *cobj;
    
    for(cobj = cachelist.next; cobj != &cachelist; cobj = cobj->next) {
        if(cobj->internal_obj == 1)
            if(strcmp(cobj->name, name) == 0)
                break;
    }

    if(cobj->obj == NULL)
        return NULL;

    return cobj;
}

int av_cache2_set(void *obj, const char *name)
{
    struct cacheobj *cobj, *oldcobj;

    if(obj != NULL) {
        AV_NEW_OBJ(cobj, cacheobj_internal_delete);
        cobj->obj = obj;
        cobj->diskusage = 0;
        cobj->name = av_strdup(name);
        cobj->internal_obj = 1;
        av_ref_obj(obj);
    } else {
        cobj = NULL;
    }

    AV_LOCK(cachelock);
    oldcobj = cacheobj2_find(name);

    if(oldcobj != NULL )
        av_unref_obj(oldcobj);

    if(cobj != NULL)
        cacheobj_insert(cobj);

    AV_UNLOCK(cachelock);

    return 0;
}

void *av_cache2_get(const char *name)
{
    struct cacheobj *cobj;
    void *obj = NULL;
    
    AV_LOCK(cachelock);
    cobj = cacheobj2_find(name);
    if(cobj != NULL) {
        cacheobj_remove(cobj);
        cacheobj_insert(cobj);
        obj = cobj->obj;
        av_ref_obj(obj);
    }
    AV_UNLOCK(cachelock);

    return obj;
}

void av_cache2_setsize(const char *name, avoff_t diskusage)
{
    struct cacheobj *cobj;

    AV_LOCK(cachelock);
    cobj = cacheobj2_find(name);
    if(cobj->obj != NULL && cobj->diskusage != diskusage) {
        disk_usage -= cobj->diskusage;
        cobj->diskusage = diskusage;
        disk_usage += cobj->diskusage;
        
        cache_checkspace(0, cobj);
    }
    AV_UNLOCK(cachelock);
}
