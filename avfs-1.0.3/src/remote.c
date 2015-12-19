/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "remote.h"
#include "version.h"
#include "namespace.h"
#include "cache.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define REM_ST_VALID 20
#define REM_DIR_VALID 10

struct remsig {
    avtimestruc_t modif;
    avoff_t size;
};

struct rementry {
    char *name;
    int type;
    struct rementry *next;
};

struct remdir {
    avtime_t valid;
    struct rementry *dirlist;
};

struct remattr {
    avtime_t valid;
    int negative;
    struct avstat st;
    char *linkname;
};

struct remfile {
    struct remsig sig;
    char *localname;
    void *data;
};

struct remnode {
    avmutex lock;
    avmutex filelock;
    struct remnode *next;
    struct remnode *prev;
    struct entry *ent;
    avino_t ino;
    struct remattr attr;
    struct remdir dir;
    struct cacheobj *file;
};

struct remfs {
    struct namespace *ns;
    struct remnode list;
    struct remote *rem;
    struct avfs *avfs;
};

static AV_LOCK_DECL(rem_lock);

static void rem_free_dir(struct remdir *dir)
{
    struct rementry *re;
    
    while((re = dir->dirlist) != NULL) {
        dir->dirlist = re->next;
        av_free(re->name);
        av_free(re);
    }
}

static void rem_free_node(struct remnode *nod)
{
    av_namespace_set(nod->ent, NULL);
    av_unref_obj(nod->ent);
    rem_free_dir(&nod->dir);
    av_free(nod->attr.linkname);
    av_unref_obj(nod->file);

    AV_FREELOCK(nod->lock);
    AV_FREELOCK(nod->filelock);
}

static struct remnode *rem_new_node(struct remfs *fs)
{
    struct remnode *nod;

    AV_NEW_OBJ(nod, rem_free_node);
    AV_INITLOCK(nod->lock);
    AV_INITLOCK(nod->filelock);
    nod->ino = av_new_ino(fs->avfs);
    nod->attr.valid = 0;
    nod->attr.linkname = NULL;
    nod->dir.valid = 0;
    nod->file = NULL;

    return nod;
}

static void rem_remove_node(struct remnode *nod)
{
    struct remnode *next = nod->next;
    struct remnode *prev = nod->prev;
    
    next->prev = prev;
    prev->next = next;
}

static void rem_insert_node(struct remfs *fs, struct remnode *nod)
{
    struct remnode *next = fs->list.next;
    struct remnode *prev = &fs->list;
    
    next->prev = nod;
    prev->next = nod;
    nod->prev = prev;
    nod->next = next;
}

static struct remnode *rem_get_node(struct remfs *fs, struct entry *ent)
{
    struct remnode *nod;

    AV_LOCK(rem_lock);
    nod = (struct remnode *) av_namespace_get(ent);
    if(nod != NULL)
        rem_remove_node(nod);
    else {
        nod = rem_new_node(fs);
        nod->ent = ent;
        av_namespace_set(ent, nod);
        if((fs->rem->flags & REM_NOCASE) != 0)
            av_namespace_setflags(ent, NSF_NOCASE, 0);
        av_ref_obj(ent);
    }
    rem_insert_node(fs, nod);
    av_ref_obj(nod);
    AV_UNLOCK(rem_lock);

    return nod;
}

static void rem_get_locked_node(struct remfs *fs, struct entry *ent,
                                struct remnode **nodep,
                                struct remnode **parentp)
{
    struct remnode *nod;
    struct remnode *parent;
    struct entry *pent;

    pent = av_namespace_lookup(fs->ns, ent, NULL);
    if(pent != NULL) {
        parent = rem_get_node(fs, pent);
        av_unref_obj(pent);
    }
    else
        parent = NULL;

    nod = rem_get_node(fs, ent);

    if(parent != NULL)
        AV_LOCK(parent->lock);
    AV_LOCK(nod->lock);

    *nodep = nod;
    *parentp = parent;
}

static void rem_put_locked_node(struct remnode *nod, struct remnode *parent)
{
    AV_UNLOCK(nod->lock);
    if(parent != NULL)
        AV_UNLOCK(parent->lock);

    av_unref_obj(nod);
    av_unref_obj(parent);
}


static void rem_free_dirlist(struct remdirlist *dl)
{
    int i;

    for(i = 0; i < dl->num; i++) {
        av_free(dl->ents[i].name);
        av_free(dl->ents[i].linkname);
    }

    av_free(dl->ents);
    av_free(dl->hostpath.host);
    av_free(dl->hostpath.path);
}

static void rem_fill_attr(struct remfs *fs, struct remnode *nod,
                          struct remdirent *de, avtime_t now)
{
    struct remattr *attr = &nod->attr;

    attr->valid = now + REM_ST_VALID;
    attr->negative = 0;
    attr->st = de->attr;
    attr->st.ino = nod->ino;
    attr->st.dev = fs->avfs->dev;
    av_free(attr->linkname);
    attr->linkname = av_strdup(de->linkname);
}

static void rem_fill_root(struct remfs *fs, struct remnode *nod)
{
    struct remattr *attr = &nod->attr;
    
    attr->valid = AV_MAXTIME;
    attr->negative = 0;
    attr->st.ino = nod->ino;
    attr->st.dev = fs->avfs->dev;
    attr->st.mode = AV_IFDIR | 0777;
    attr->st.nlink = 2;
    attr->st.uid = 0;
    attr->st.gid = 0;
    attr->st.size = 0;
    attr->st.blksize = 512;
    attr->st.blocks = 0;
    attr->st.atime.sec = 0;
    attr->st.atime.nsec = 0;
    attr->st.mtime = attr->st.atime;
    attr->st.ctime = attr->st.atime;
}

static int rem_list_single(struct remfs *fs, struct remnode *nod,
                           struct remdirlist *dl)
{
    int i;

    for(i = 0; i < dl->num; i++) {
        struct remdirent *de = &dl->ents[i];

        if(strcmp(de->name, dl->hostpath.path) == 0) {
            rem_fill_attr(fs, nod, de, av_time());
            return 0;
        }
    }

    return -ENOENT;
}

static void rem_dir_add(struct remdir *dir, struct remdirent *de)
{
    struct rementry **rep;
    struct rementry *re;
    
    for(rep = &dir->dirlist; *rep != NULL; rep = &(*rep)->next);
    
    AV_NEW(re);
    re->name = av_strdup(de->name);
    re->type = AV_TYPE(de->attr.mode);
    re->next = NULL;
    
    *rep = re;
}

static void rem_dir_add_beg(struct remdir *dir, const char *name, int type)
{
    struct rementry *re;

    AV_NEW(re);
    re->name = av_strdup(name);
    re->type = type;
    re->next = dir->dirlist;

    dir->dirlist = re;
}

static int rem_list_dir(struct remfs *fs, struct remnode *nod,
                         struct remnode *child,  struct remdirlist *dl,
                         struct remnode *need)
{
    int i;
    avtime_t now = av_time();
    int found = 0;
    int gotdots = 0;

    rem_free_dir(&nod->dir);
    for(i = 0; i < dl->num; i++) {
        struct remdirent *de = &dl->ents[i];
        
        rem_dir_add(&nod->dir, de);
        if(strcmp(de->name, ".") == 0) {
            rem_fill_attr(fs, nod, de, now);
            if(nod == need)
                found = 1;

            gotdots = 1;
        }
        else if(strcmp(de->name, "..") == 0)
            gotdots = 1;
        else {
            struct entry *cent;
            struct remnode *cnod;

            cent = av_namespace_lookup(fs->ns, nod->ent, de->name);
            cnod = rem_get_node(fs, cent);
            av_unref_obj(cent);
            if(cnod != child) {
                AV_LOCK(cnod->lock);
                rem_fill_attr(fs, cnod, de, now);
                AV_UNLOCK(cnod->lock);
            }
            else
                rem_fill_attr(fs, cnod, de, now);

            if(cnod == need)
                found = 1;

            av_unref_obj(cnod);
        }
    }
    
    if(!gotdots) {
        rem_dir_add_beg(&nod->dir, "..", AV_TYPE(AV_IFDIR));
        rem_dir_add_beg(&nod->dir, ".", AV_TYPE(AV_IFDIR));
    }

    nod->dir.valid = now + REM_DIR_VALID;

    if(found)
        return 0;
    else
        return -ENOENT;
}

static void rem_get_hostpath(struct entry *ent, struct remhostpath *hp)
{
    char *hostpath = av_namespace_getpath(ent);
    char *s;

    s = strchr(hostpath, '/');
    if(s == NULL) {
        hp->host = av_strdup(hostpath);
        hp->path = av_strdup("/");
    }
    else {
        *s = '\0';
        hp->host = av_strdup(hostpath);
        *s = '/';
        hp->path = av_strdup(s);
    }
    av_free(hostpath);
}

static void rem_dir_only(struct remdirlist *dl)
{
    if((dl->flags & REM_LIST_SINGLE) != 0) {
        char *dir = dl->hostpath.path;
        if(strcmp(dir, "/") == 0)
            dl->flags = 0;
        else {
            char *s;
            s = strrchr(dir, '/');
            if(s == dir)
                s++;
            *s = '\0';
            dl->flags = REM_LIST_PARENT;
        }
    }
}

static int rem_get_attr(struct remfs *fs, struct remnode *nod,
                        struct remnode *parent)
{
    int res;
    struct remote *rem = fs->rem;
    struct remdirlist dl;
    
    dl.flags = REM_LIST_SINGLE;
    dl.num = 0;
    dl.ents = NULL;
    rem_get_hostpath(nod->ent, &dl.hostpath);
    if((rem->flags & REM_DIR_ONLY) != 0)
        rem_dir_only(&dl);

    res = rem->list(rem, &dl);
    if(res == 0) {
        if((dl.flags & REM_LIST_SINGLE) != 0)
            res = rem_list_single(fs, nod, &dl);
        else if((dl.flags & REM_LIST_PARENT) != 0)
            res = rem_list_dir(fs, parent, nod, &dl, nod);
        else
            res = rem_list_dir(fs, nod, NULL, &dl, nod);

        /* It can happen, that the root directory cannot be listed */
        if(parent == NULL && res == -ENOENT) {
            rem_fill_root(fs, nod);
            res = 0;
        }
    }

    rem_free_dirlist(&dl);
    
    if(res == -ENOENT) {
        nod->attr.valid = av_time() + REM_ST_VALID;
        nod->attr.negative = 1;
    }

    return res;
}

static int rem_check_node(struct remfs *fs, struct remnode *nod,
                          struct remnode *parent)
{
    int res;
    avtime_t now = av_time();

    if(now < nod->attr.valid) {
        if(nod->attr.negative)
            res = -ENOENT;
        else
            res = 0;
    }
    else {
        nod->attr.valid = 0;
        res = rem_get_attr(fs, nod, parent);
    }
    
    return res;
}

static int rem_signature_valid(struct remsig *sig, struct avstat *stbuf)
{
    if(sig->modif.sec != stbuf->mtime.sec ||
       sig->modif.nsec != stbuf->mtime.nsec ||
       sig->size != stbuf->size)
        return 0;
    else
        return 1;
}

static int rem_get_dir(struct remfs *fs, struct remnode *nod)
{
    int res;
    struct remote *rem = fs->rem;
    struct remdirlist dl;
    
    dl.flags = 0;
    dl.num = 0;
    dl.ents = NULL;
    rem_get_hostpath(nod->ent, &dl.hostpath);
    
    res = rem->list(rem, &dl);
    if(res == 0)
        rem_list_dir(fs, nod, NULL, &dl, NULL);

    rem_free_dirlist(&dl);

    return res;
}

static int rem_check_dir(struct remfs *fs, struct remnode *nod)
{
    int res;
    avtime_t now = av_time();

    if(now < nod->dir.valid)
        res = 0;
    else
        res = rem_get_dir(fs, nod);
    
    return res;
}

static int rem_node_type(struct remfs *fs, struct entry *ent)
{
    int res;
    struct remnode *nod;
    struct remnode *parent;

    rem_get_locked_node(fs, ent, &nod, &parent);
    if(nod->attr.valid != 0 && !nod->attr.negative)
        res = 0;
    else 
        res = rem_check_node(fs, nod, parent);

    if(res == 0)
        res = AV_TYPE(nod->attr.st.mode);
    rem_put_locked_node(nod, parent);

    return res;
}

static struct entry *rem_ventry_entry(ventry *ve)
{
    return (struct entry *) ve->data;
}

static struct entry *rem_vfile_entry(vfile *vf)
{
    return (struct entry *) vf->data;
}

static struct remfs *rem_ventry_filesys(ventry *ve)
{
    return (struct remfs *) ve->mnt->avfs->data;
}

static struct remfs *rem_vfile_filesys(vfile *vf)
{
    return (struct remfs *) vf->mnt->avfs->data;
}

static int rem_lookup(ventry *ve, const char *name, void **newp)
{
    int res;
    int type;
    struct entry *prev = rem_ventry_entry(ve);
    struct remfs *fs = rem_ventry_filesys(ve);
    struct entry *ent;
 
    if(prev != NULL) {
        res = rem_node_type(fs, prev);
        if(res < 0)
            return res;
        
        if(name != NULL && res != AV_TYPE(AV_IFDIR))
            return -ENOTDIR;
    }

    ent = av_namespace_lookup_all(fs->ns, prev, name);
    
    if(ent == NULL)
        type = 0;
    else {
        type = rem_node_type(fs, ent);
        if(type < 0) {
            av_unref_obj(ent);
            return type;
        }
    }
    av_unref_obj(prev);
    
    *newp = ent;
    return type;
}

static int rem_getpath(ventry *ve, char **resp)
{
    struct entry *ent = rem_ventry_entry(ve);

    *resp = av_namespace_getpath(ent);

    return 0;
}

static void rem_putent(ventry *ve)
{
    struct entry *ent = rem_ventry_entry(ve);

    av_unref_obj(ent);
}

static int rem_copyent(ventry *ve, void **resp)
{
    struct entry *ent = rem_ventry_entry(ve);
    
    av_ref_obj(ent);
    *resp =  (void *) ent;

    return 0;
}

static void rem_check_file(struct remfs * fs, struct entry *ent)
{
    int res;
    struct remnode *nod;
    struct remnode *parent;
    struct remfile *fil;

    rem_get_locked_node(fs, ent, &nod, &parent);
    fil = av_cacheobj_get(nod->file);
    if(fil != NULL) {
        res = rem_check_node(fs, nod, parent);
        if(res < 0 || !rem_signature_valid(&fil->sig, &nod->attr.st)) {
            av_unref_obj(nod->file);
            nod->file = NULL;
        }
        av_unref_obj(fil);
    }
    rem_put_locked_node(nod, parent);
}

static int rem_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    struct entry *ent = rem_ventry_entry(ve);
    struct remfs *fs = rem_ventry_filesys(ve);
    int accmode = (flags & AVO_ACCMODE);

    res = rem_node_type(fs, ent);
    if(res < 0)
        return res;

    if((flags & AVO_DIRECTORY) != 0) {
        if(res != AV_TYPE(AV_IFDIR))
            return -ENOTDIR;
    }
    else {
        if(accmode == AVO_WRONLY || accmode == AVO_RDWR)
            return -EROFS;

        rem_check_file(fs, ent);
    }

    av_ref_obj(ent);

    *resp = (void *) ent;
    return 0;
}

static struct entry *rem_dirent_lookup(struct namespace *ns,
                                       struct entry *parent, const char *name)
{
    struct entry *ent;

    ent = av_namespace_lookup_all(ns, parent, name);
    if(ent == NULL) {
        ent = parent;
        av_ref_obj(ent);
    }

    return ent;
}

static struct rementry *rem_nth_entry(struct remdir *dir, int n)
{
    struct rementry *re;
    int i;

    re = dir->dirlist;
    for(i = 0; i < n && re != NULL; i++)
        re = re->next;
    
    return re;
}

static int rem_get_direntry(struct remfs *fs, struct remnode *nod,
                            vfile *vf, struct avdirent *buf)
{
    struct rementry *re;
    struct entry *cent;
    struct remnode *cnod;

    re = rem_nth_entry(&nod->dir, vf->ptr);
    if(re == NULL)
        return 0;
    
    cent = rem_dirent_lookup(fs->ns, nod->ent, re->name);
    cnod = rem_get_node(fs, cent);
    av_unref_obj(cent);
    
    buf->name = av_strdup(re->name);
    buf->type = re->type;
    buf->ino = cnod->ino;
    av_unref_obj(cnod);
    
    vf->ptr ++;

    return 1;
}

static int rem_readdir(vfile *vf, struct avdirent *buf)
{
    int res;
    struct entry *ent = rem_vfile_entry(vf);
    struct remfs *fs = rem_vfile_filesys(vf);
    struct remnode *nod;

    nod = rem_get_node(fs, ent);
    AV_LOCK(nod->lock);
    res = rem_check_dir(fs, nod);
    if(res == 0)
        res = rem_get_direntry(fs, nod, vf, buf);
    AV_UNLOCK(nod->lock);
    av_unref_obj(nod);

    return res;
}

static int rem_close(vfile *vf)
{
    struct entry *ent = rem_vfile_entry(vf);

    av_unref_obj(ent);

    return 0;
}

static void rem_get_signature(struct remfs *fs, struct entry *ent,
                              struct remsig *sig)
{
    int res;
    struct remnode *nod;
    struct remnode *parent;

    rem_get_locked_node(fs, ent, &nod, &parent);
    res = rem_check_node(fs, nod, parent);
    if(res == 0) {
        sig->modif = nod->attr.st.mtime;
        sig->size = nod->attr.st.size;
    }
    else
        sig->size = -1;
    rem_put_locked_node(nod, parent);
}

static void rem_delete_file(struct remfile *fil)
{
    av_del_tmpfile(fil->localname);
    av_unref_obj(fil->data);
}

static avoff_t rem_local_size(const char *localname)
{
    int res;
    struct stat stbuf;
    
    res = stat(localname, &stbuf);
    if(res == 0) {
        /* Ramfs returns 0 diskusage */
        if(stbuf.st_blocks == 0)
            return stbuf.st_size;
        else
            return stbuf.st_blocks * 512;
    }
    else
        return -1;
    
}

static int rem_get_file(struct remfs *fs, struct remnode *nod,
                        struct remfile **resp)
{
    int res;
    struct remfile *fil;
    struct remote *rem = fs->rem;
    struct remgetparam gp;
    char *objname;
    
    fil = (struct remfile *) av_cacheobj_get(nod->file);
    if(fil != NULL) {
        *resp = fil;
        return 0;
    }

    rem_get_hostpath(nod->ent, &gp.hostpath);
    objname = av_stradd(NULL, rem->name, ":", gp.hostpath.host,
                          gp.hostpath.path, NULL);
    
    if(rem->get != NULL) 
        res = rem->get(rem, &gp);
    else
        res = -ENOENT;
    av_free(gp.hostpath.host);
    av_free(gp.hostpath.path);

    if(res < 0) {
        av_free(objname);
        return res;
    }

    AV_NEW_OBJ(fil, rem_delete_file);
    fil->localname = gp.localname;
    fil->data = gp.data;
    rem_get_signature(fs, nod->ent, &fil->sig);

    av_unref_obj(nod->file);
    nod->file = av_cacheobj_new(fil, objname);
    av_free(objname);

    if(res == 0)
        av_cacheobj_setsize(nod->file, rem_local_size(fil->localname));

    *resp = fil;

    return 0;
}

static int rem_wait_data(struct remfs *fs, struct remnode *nod,
                         struct remfile *fil, avoff_t end)
{
    int res;
    struct remote *rem = fs->rem;
    
    if(fil->data == NULL)
        return 0;

    res = rem->wait(rem, fil->data, end);
    if(res < 0)
        return res;

    if(res == 0) {
        av_unref_obj(fil->data);
        fil->data = NULL;
        av_cacheobj_setsize(nod->file, rem_local_size(fil->localname));
    }

    return 0;
}

static avssize_t rem_real_read(struct remfile *fil, vfile *vf, char *buf,
                               avsize_t nbyte)
{
    avssize_t res;
    avoff_t sres;
    int fd;

    fd = open(fil->localname, O_RDONLY);
    if(fd == -1)
        return -errno;
    
    sres = lseek(fd, vf->ptr, SEEK_SET);
    if(sres == -1)
        res = -errno;
    else {
	res = read(fd, buf, nbyte);
        if(res == -1)
            res = -errno;
        else 
            vf->ptr += res;
    }
    close(fd);

    return res;
}

static avssize_t rem_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct remfs *fs = rem_vfile_filesys(vf);
    struct entry *ent = rem_vfile_entry(vf);
    struct remnode *nod;
    struct remfile *fil = NULL;

    nod = rem_get_node(fs, ent);
    AV_LOCK(nod->filelock);
    res = rem_get_file(fs, nod, &fil);
    if(res == 0) {
        res = rem_wait_data(fs, nod, fil, vf->ptr + nbyte);
        if(res == 0)
            res = rem_real_read(fil, vf, buf, nbyte);

        if(res < 0) {
            av_unref_obj(nod->file);
            nod->file = NULL;
        }
        av_unref_obj(fil);
    }
    AV_UNLOCK(nod->filelock);
    av_unref_obj(nod);

    return res;
}


static int rem_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    int res;
    struct remfs *fs = rem_vfile_filesys(vf);
    struct entry *ent = rem_vfile_entry(vf);
    struct remnode *nod;
    struct remnode *parent;

    rem_get_locked_node(fs, ent, &nod, &parent);
    res = rem_check_node(fs, nod, parent);
    if(res == 0)
        *buf = nod->attr.st;
    rem_put_locked_node(nod, parent);
    
    return res;
}

static int rem_access(ventry *ve, int amode)
{
    int res;
    struct remfs *fs = rem_ventry_filesys(ve);
    struct entry *ent = rem_ventry_entry(ve);

    res = rem_node_type(fs, ent);
    if(res < 0)
        return res;

    if((amode & AVW_OK) != 0)
        return -EACCES;

    return 0;
}


static int rem_readlink(ventry *ve, char **bufp)
{
    int res;
    struct remfs *fs = rem_ventry_filesys(ve);
    struct entry *ent = rem_ventry_entry(ve);
    struct remnode *nod;
    struct remnode *parent;

    rem_get_locked_node(fs, ent, &nod, &parent);
    res = rem_check_node(fs, nod, parent);
    if(res == 0) {
        if(!AV_ISLNK(nod->attr.st.mode))
            res = -EINVAL;
        else
            *bufp = av_strdup(nod->attr.linkname);
    }
    rem_put_locked_node(nod, parent);

    return res;
}

static void rem_log_tree(struct namespace *ns, struct entry *ent)
{
    char *path;
    struct entry *next;

    while(ent != NULL) {
        path = av_namespace_getpath(ent);
        av_log(AVLOG_ERROR, "    %s", path);
        av_free(path);
        rem_log_tree(ns, av_namespace_subdir(ns, ent));
        next = av_namespace_next(ent);
        av_unref_obj(ent);
        ent = next;
    }
}

static void rem_destroy(struct avfs *avfs)
{
    struct remfs *fs = (struct remfs *) avfs->data;
    struct remote *rem = fs->rem;
    struct remnode *nod;
    struct entry *root;

    AV_LOCK(rem_lock);
    nod = fs->list.next;
    while(nod != &fs->list) {
        struct remnode *next = nod->next;
        
        av_unref_obj(nod);
        nod = next;
    }
    AV_UNLOCK(rem_lock);
    
    root = av_namespace_subdir(fs->ns, NULL);
    if(root != NULL) {
        av_log(AVLOG_ERROR, "%s: busy entries after destroy:", avfs->name);
        rem_log_tree(fs->ns, root);
    }
    av_unref_obj(fs->ns);

    rem->destroy(rem);
    av_free(fs);
}

void av_remote_add(struct remdirlist *dl, const char *name,
                     const char *linkname, struct avstat *attr)
{
    struct remdirent *de;

    dl->ents = av_realloc(dl->ents, sizeof(*dl->ents) * (dl->num + 1));
    de = &dl->ents[dl->num];
    dl->num++;

    de->name = av_strdup(name);
    de->linkname = av_strdup(linkname);
    de->attr = *attr;
}


int av_remote_init(struct vmodule *module, struct remote *rem,
                     struct avfs **resp)
{
    int res;
    struct avfs *avfs;
    struct remfs *fs;

    res = av_new_avfs(rem->name, NULL, AV_VER, AVF_ONLYROOT | AVF_NOLOCK,
                        module, &avfs);
    if(res < 0) {
        rem->destroy(rem);
        return res;
    }

    AV_NEW(fs);
    fs->ns = av_namespace_new();
    fs->list.next = fs->list.prev = &fs->list;
    fs->rem = rem;
    fs->avfs = avfs;

    avfs->data = fs;
    avfs->destroy = rem_destroy;

    avfs->lookup    = rem_lookup;
    avfs->putent    = rem_putent;
    avfs->copyent   = rem_copyent;
    avfs->getpath   = rem_getpath;

    avfs->open      = rem_open;

    avfs->close     = rem_close;
    avfs->read      = rem_read;
    avfs->readdir   = rem_readdir;
    avfs->getattr   = rem_getattr;

    avfs->access    = rem_access;
    avfs->readlink  = rem_readlink;

    av_add_avfs(avfs);
    
    *resp = avfs;

    return 0;
}
