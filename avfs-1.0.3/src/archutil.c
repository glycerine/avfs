/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "archint.h"

static void archnode_destroy(struct archnode *nod)
{
    av_free(nod->linkname);
    av_unref_obj(nod->data);
}

struct archnode *av_arch_new_node(struct archive *arch, struct entry *ent,
                                  int isdir)
{
    struct archnode *nod;

    nod = (struct archnode *) av_namespace_get(ent);
    if(nod != NULL) {
        av_unref_obj(nod);
        av_unref_obj(ent);
    }

    AV_NEW_OBJ(nod, archnode_destroy);

    av_default_stat(&nod->st);
    nod->linkname = NULL;
    nod->offset = 0;
    nod->realsize = 0;
    nod->data = NULL;
    nod->flags = 0;
    nod->numopen = 0;

    /* FIXME: This scheme will allocate the same device to a tar file
       inside a tarfile. While this is not fatal, 'find -xdev' would not do
       what is expected.  */

    nod->st.dev = arch->avfs->dev;
    nod->st.ino = av_new_ino(arch->avfs);

    nod->st.mode = 0644 | AV_IFREG;
    nod->st.uid = arch->st.uid;
    nod->st.gid = arch->st.gid;
    nod->st.mtime = arch->st.mtime;
    nod->st.atime = nod->st.mtime;
    nod->st.ctime = nod->st.mtime;
    if(!isdir)
        nod->st.nlink = 1;
    else {
        struct entry *parent;
        struct archnode *parnod;

        nod->st.nlink = 2;        
        parent = av_namespace_parent(ent);
        if(parent != NULL) {
            parnod = (struct archnode *) av_namespace_get(parent);
            if(parnod != NULL) 
                parnod->st.nlink ++;

            av_unref_obj(parent);
        }
    }

    av_namespace_set(ent, nod);
    av_ref_obj(ent);

    return nod;
}

void av_arch_del_node(struct entry *ent)
{
    struct archnode *nod;

    nod = (struct archnode *) av_namespace_get(ent);
    av_namespace_set(ent, NULL);
    av_unref_obj(nod);
    av_unref_obj(ent);
}

struct archnode *av_arch_default_dir(struct archive *arch, struct entry *ent)
{
    struct archnode *nod;
    avmode_t mode;

    nod = av_arch_new_node(arch, ent, 1);

    mode = (arch->st.mode & 0777) | AV_IFDIR;
    if (mode & 0400) mode |= 0100;
    if (mode & 0040) mode |= 0010;
    if (mode & 0004) mode |= 0001;

    nod->st.mode = mode;
    nod->flags |= ANOF_AUTODIR;

    return nod;
}

struct entry *av_arch_resolve(struct archive *arch, const char *path,
                              int create, int flags)
{
    struct entry *ent;
    char *s, *p;
    char *pathdup = av_strdup(path);

    p = pathdup;
    ent = av_namespace_subdir(arch->ns, NULL);
    while(1) {
        struct entry *next;
        struct archnode *nod;
        char c;

        for(;*p == '/'; p++);
        for(s = p; *s && *s != '/'; s++);
        c = *s;
        *s = '\0';
        if(!*p)
            break;

        nod = (struct archnode *) av_namespace_get(ent);
        if(nod == NULL) {
            if(!create) {
                av_unref_obj(ent);
                ent = NULL;
                break;
            }
            av_arch_default_dir(arch, ent);
            av_namespace_setflags(ent, flags, 0);
        }
        else if(!AV_ISDIR(nod->st.mode)) {
            if(create) 
                av_log(AVLOG_WARNING,
                       "ARCH: cannot create %s: Not a directory", path);
            av_unref_obj(ent);
            ent = NULL;
            break;
        }
        
        next = av_namespace_lookup_all(arch->ns, ent, p);
        if(next != NULL) {
            av_unref_obj(ent);
            ent = next;
        }
        
        *s = c;
        p = s;
    }

    av_free(pathdup);

    return ent;
}

int av_arch_isroot(struct archive *arch, struct entry *ent)
{
    int res;
    struct entry *root;
    
    root = av_namespace_subdir(arch->ns, NULL);
    if(root == ent)
        res = 1;
    else
        res = 0;

    av_unref_obj(root);
    
    return res;
}

struct entry *av_arch_create(struct archive *arch, const char *path, int flags)
{
    struct archnode *nod;
    struct entry *ent;

    ent = av_arch_resolve(arch, path, 1, flags);
    if(ent == NULL)
        return NULL;

    if(av_arch_isroot(arch, ent)) {
        av_log(AVLOG_WARNING, "Empty filename");
        av_unref_obj(ent);
        return NULL;
    }
    
    nod = (struct archnode *) av_namespace_get(ent);
    if(nod != NULL) {
        av_log(AVLOG_WARNING, "Entry for %s already exists", path);
        av_unref_obj(ent);
        return NULL;
    }

    av_namespace_setflags(ent, flags, 0);

    return ent;
}
