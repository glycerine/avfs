/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "internal.h"
#include "version.h"
#include "oper.h"
#include <stdarg.h>
#include <string.h>

#define NEED_VER    90

/* FIXME: This is just a random value */
#define AVFS_MAJOR 0xa5f

static struct namespace *avfsstat_ns;

struct av_obj {
    int refctr;
    void (*destr)(void *);
    avmutex *ref_lock;
    void (*destr_locked)(void *);
};

static AV_LOCK_DECL(objlock);

int av_check_version(const char *modname, const char *name,
                       int version, int need_ver, int provide_ver)
{
    if(version < need_ver || version > provide_ver) {
        if(version < need_ver) 
            av_log(AVLOG_WARNING, 
                     "%s: %s has version %i. Needs to be at least %i.",
                     modname, name, version, need_ver);
        else
            av_log(AVLOG_WARNING, 
                     "%s: %s has version %i. Cannot handle above %i.",
                     modname, name, version, provide_ver);
    
        return -ENODEV;
    }
  
    return 0;
}

static struct ext_info *copy_exts(struct ext_info *exts)
{
    int i, num, len;
    struct ext_info *newexts;
    char *pp;

    if(exts == NULL)
        return NULL;

    len = 0;
    for(i = 0; exts[i].from != NULL; i++) {
        len += (strlen(exts[i].from) + 1);
        if(exts[i].to != NULL) len += (strlen(exts[i].to) + 1);
    }
    num = i;

    newexts = av_malloc((num + 1) * sizeof(*newexts) + len);

    pp = (char *) (&newexts[num + 1]);
  
    for(i = 0; i < num; i++) {
        strcpy(pp, exts[i].from);
        newexts[i].from = pp;
        pp += (strlen(pp) + 1);
        if(exts[i].to != NULL) {
            strcpy(pp, exts[i].to);
            newexts[i].to = pp;
            pp += (strlen(pp) + 1);
        }
        else newexts[i].to = NULL;
    }
    newexts[i].from = NULL;
    newexts[i].to = NULL;

    return newexts;
}

static void free_avfs(struct avfs *avfs)
{
    AVFS_LOCK(avfs);
    avfs->destroy(avfs);
    AVFS_UNLOCK(avfs);
    
    av_free(avfs->name);
    av_free(avfs->exts);

    av_unref_obj(avfs->module);
    AV_FREELOCK(avfs->lock);
}

static int new_minor()
{
    static AV_LOCK_DECL(lock);
    static int minor = 1;
    int res;

    AV_LOCK(lock);
    res = minor;
    minor++;
    AV_UNLOCK(lock);

    return res;
}

avino_t av_new_ino(struct avfs *avfs)
{
    static AV_LOCK_DECL(lock);
    avino_t res;

    AV_LOCK(lock);
    res = avfs->inoctr;
    avfs->inoctr++;
    AV_UNLOCK(lock);

    return res;
}

int av_new_avfs(const char *name, struct ext_info *exts, int version,
                  int flags, struct vmodule *module, struct avfs **retp)
{
    int ret;
    struct avfs *avfs;

    ret = av_check_version("CoreLib", name, version, NEED_VER, AV_VER);
    if(ret < 0)
        return ret;

    AV_NEW_OBJ(avfs, free_avfs);
    AV_INITLOCK(avfs->lock);

    avfs->name = av_strdup(name);

    avfs->exts = copy_exts(exts);
    avfs->data = NULL;
    avfs->version = version;
    avfs->flags = flags;
    avfs->module = module;
    avfs->dev = av_mkdev(AVFS_MAJOR, new_minor());
    avfs->inoctr = 2;

    av_ref_obj(module);
    
    av_default_avfs(avfs);

    *retp = avfs;
    return 0;
}

void av_init_avfsstat()
{
    struct avfs *avfs;

    av_state_new(NULL, "avfsstat", &avfsstat_ns, &avfs);
    av_unref_obj(avfsstat_ns);
}

void av_avfsstat_register(const char *path, struct statefile *func)
{
    struct entry *ent;
    struct statefile *stf;

    ent = av_namespace_resolve(avfsstat_ns, path);
    AV_NEW(stf);

    *stf = *func;
    av_namespace_set(ent, stf);
}

char *av_strdup(const char *s)
{
    char *ns;

    if(s == NULL)
        return NULL;
  
    ns = (char *) av_malloc(strlen(s) + 1);
    strcpy(ns, s);

    return ns;
}

char *av_strndup(const char *s, avsize_t len)
{
    char *ns;

    if(s == NULL)
        return NULL;
  
    ns = (char *) av_malloc(len + 1);
    strncpy(ns, s, len);
    
    ns[len] = '\0';

    return ns;
}

char *av_stradd(char *str, ...)
{
    va_list ap;
    unsigned int origlen;
    unsigned int len;
    char *s, *ns;

    origlen = 0;
    if(str != NULL)
        origlen = strlen(str);

    len = origlen;
    va_start(ap, str);
    while((s = va_arg(ap, char*)) != NULL)
        len += strlen(s);
    va_end(ap);
  
    str = av_realloc(str, len + 1);
    ns = str + origlen;
    ns[0] = '\0';
    va_start(ap, str);
    while((s = va_arg(ap, char*)) != NULL) {
        strcpy(ns, s);
        ns += strlen(ns);
    }
    va_end(ap);
  
    return str;
}

void *av_new_obj(avsize_t nbyte, void (*destr)(void *))
{
    struct av_obj *ao;

    ao = (struct av_obj *) av_calloc(sizeof(*ao) + nbyte);
    ao->refctr = 1;
    ao->destr = destr;
    ao->ref_lock = NULL;
    ao->destr_locked = NULL;
    
    return (void *) (ao + 1);
}

void av_obj_set_ref_lock(void *obj, avmutex *lock)
{
    if(obj != NULL) {
        struct av_obj *ao = ((struct av_obj *) obj) - 1;

        ao->ref_lock = lock;
    }
}

void av_obj_set_destr_locked(void *obj, void (*destr_locked)(void *))
{
    if(obj != NULL) {
        struct av_obj *ao = ((struct av_obj *) obj) - 1;

        ao->destr_locked = destr_locked;
    }
}

void av_ref_obj(void *obj)
{
    if(obj != NULL) {
        struct av_obj *ao = ((struct av_obj *) obj) - 1;
        int refctr;
        
        if(ao->ref_lock != NULL) {
            AV_LOCK(*ao->ref_lock);
        } else {
            AV_LOCK(objlock);
        }

        if(ao->refctr > 0)
            ao->refctr ++;
        refctr = ao->refctr;

        if(ao->ref_lock != NULL) {
            AV_UNLOCK(*ao->ref_lock);
        } else {
            AV_UNLOCK(objlock);
        }

        if(refctr <= 0)
            av_log(AVLOG_ERROR, "Referencing deleted object (%p)", obj);
    }
}

void av_unref_obj(void *obj)
{
    if(obj != NULL) {
        struct av_obj *ao = ((struct av_obj *) obj) - 1;
        int refctr;

        if(ao->ref_lock != NULL) {
            AV_LOCK(*ao->ref_lock);
        } else {
            AV_LOCK(objlock);
        }

        if(ao->refctr >= 0)
            ao->refctr --;
        refctr = ao->refctr;
        
        if(refctr == 0) {
            if(ao->destr_locked != NULL)
                ao->destr_locked(obj);
        }

        if(ao->ref_lock != NULL) {
            AV_UNLOCK(*ao->ref_lock);
        } else {
            AV_UNLOCK(objlock);
        }

        if(refctr == 0) {
            if(ao->destr != NULL)
                ao->destr(obj);

            av_free(ao);
            return;
        }
        else if(refctr < 0)
            av_log(AVLOG_ERROR, "Unreferencing deleted object (%p)", obj);
    }
}

avssize_t av_pread_all(vfile *vf, char *buf, avsize_t nbyte, avoff_t offset)
{
    avssize_t res;
    
    res = av_pread(vf, buf, nbyte, offset);
    if(res < 0)
        return res;
    
    if(res != nbyte) {
        av_log(AVLOG_ERROR, "Premature end of file");
        return -EIO;
    }

    return res;
}

avssize_t av_read_all(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    
    res = av_read(vf, buf, nbyte);
    if(res < 0)
        return res;
    
    if(res != nbyte) {
        av_log(AVLOG_ERROR, "Premature end of file");
        return -EIO;
    }

    return res;
}
