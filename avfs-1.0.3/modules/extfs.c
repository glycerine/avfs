/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    Copyright (C) 2006  Ralf Hoffmann (ralf@boomerangsworld.de)
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    EXTFS module

    This module is partly based on the 'extfs.c' module of 
    Midnight Commander VFS, by Jakub Jelinek and Pavel Machek.
*/

#include "archive.h"
#include "version.h"
#include "filebuf.h"
#include "parsels.h"
#include "realfile.h"
#include "runprog.h"
#include "filecache.h"
#include "cache.h"
#include "exit.h"
#include "tmpfile.h"

#include <unistd.h>
#include <fcntl.h>

struct extfsdata {
    int needbase;
    char *progpath;
};

struct extfsnode {
    char *fullpath;
    avmutex lock;
};

struct extfscacheentry {
    char *tmpfile;
};

struct extfsfile {
    struct extfscacheentry *cent;
    int fd;
};

static void extfscacheentry_delete(struct extfscacheentry *cent)
{
    if( cent->tmpfile != NULL ) {
        av_del_tmpfile(cent->tmpfile);
    }
}

static void fill_extfs_link(struct archive *arch, struct entry *ent,
                           char *linkname)
{
    struct entry *link;
    struct archnode *nod = NULL;

    link = av_arch_resolve(arch, linkname, 0, 0);
    if(link != NULL)
        nod = (struct archnode *) av_namespace_get(link);

    if(nod == NULL || AV_ISDIR(nod->st.mode))
        av_log(AVLOG_WARNING, "EXTFS: Illegal hard link");
    else {
        nod->st.nlink ++;
        av_namespace_set(ent, nod);
        av_ref_obj(ent);
        av_ref_obj(nod);
    }

    av_unref_obj(link);
}

static void extfsnode_delete(struct extfsnode *enod)
{
    av_free(enod->fullpath);
    AV_FREELOCK(enod->lock);
}

static void fill_extfs_node(struct archive *arch, struct entry *ent, 
                            struct avstat *stbuf, char *path, char *linkname)
{
    struct archnode *nod;
    struct extfsnode *enod;
    char *s;

    nod = av_arch_new_node(arch, ent, AV_ISDIR(stbuf->mode));
        
    stbuf->dev = nod->st.dev;
    stbuf->ino = nod->st.ino;
    stbuf->nlink = nod->st.nlink;

    nod->st = *stbuf;
    nod->offset = 0;
    nod->realsize = 0;

    AV_NEW_OBJ(enod, extfsnode_delete);

    AV_INITLOCK(enod->lock);

    nod->data = enod;

    /* Fullpath should be without leading slashes */
    for(s = path; *s && *s == '/'; s++);
    enod->fullpath = av_strdup(s);

    if(AV_ISLNK(stbuf->mode))
        nod->linkname = av_strdup(linkname);
}


static void insert_extfs_entry(struct archive *arch, struct avstat *stbuf,
			      char *path, char *linkname)
{
    struct entry *ent;

    if(!path[0])
        return;

    ent = av_arch_create(arch, path, 0);
    if(ent == NULL)
        return;

    /* if linkname is not null but mode is not a link
       then this should be a hard link */
    if(linkname != NULL && !AV_ISLNK(stbuf->mode)) 
        fill_extfs_link(arch, ent, linkname);
    else
        fill_extfs_node(arch, ent, stbuf, path, linkname);

    av_unref_obj(ent);
}

static void parse_extfs_line(struct lscache *lc, char *line,
                             struct archive *arch)
{
    int res;
    char *filename;
    char *linkname;
    struct avstat stbuf;
    
    res = av_parse_ls(lc, line, &stbuf, &filename, &linkname);
    if(res != 1)
        return;
    
    insert_extfs_entry(arch, &stbuf, filename, linkname);
    av_free(filename);
    av_free(linkname);
}

static int read_extfs_list(struct program *pr, struct lscache *lc,
                           struct archive *arch)
{
    int res;

    while(1) {
        char *line;

        res = av_program_getline(pr, &line, -1);
        if(res <= 0)
            return res;
        if(line == NULL)
            return 0;
        parse_extfs_line(lc, line, arch);
        av_free(line);
    }
}

static int extfs_list(void *data, ventry *ve, struct archive *arch)
{
    int res;
    const char *prog[4];
    struct realfile *rf;
    struct program *pr;
    struct extfsdata *info = (struct extfsdata *) data;    

    if(info->needbase) {
        res = av_get_realfile(ve->mnt->base, &rf);
        if(res < 0)
            return res;
    }
    else
        rf = NULL;
    
    prog[0] = info->progpath;
    prog[1] = "list";
    prog[2] = rf == NULL ? NULL : rf->name;
    prog[3] = NULL;

    res = av_start_program(prog, &pr);
    if(res == 0) {
        struct lscache *lc = av_new_lscache();
        res = read_extfs_list(pr, lc, arch);
        av_unref_obj(lc);
        av_unref_obj(pr);
    }
    av_unref_obj(rf);

    return res;
}

static int get_key_for_node(ventry *ve, struct archfile *fil, char **resp)
{
    struct extfsnode *enod = (struct extfsnode *) fil->nod->data;
    char *key;
    int res;

    if(enod == NULL) {
        return -EISDIR;
    }

    res = av_filecache_getkey(ve, &key);
    if(res < 0)
        return res;

    key = av_stradd(key, "/", enod->fullpath, NULL);
    *resp = key;
    return 0;
}

static int get_extfs_file(ventry *ve, struct archfile *fil,
                          const char *tmpfile)
{
    int res;
    struct archparams *ap = (struct archparams *) ve->mnt->avfs->data;
    struct extfsdata *info = (struct extfsdata *) ap->data;
    struct extfsnode *enod = (struct extfsnode *) fil->nod->data;
    const char *prog[6];
    struct realfile *rf;

    if(enod == NULL) {
        /* no extfsnode means someone tries to access the extfs
	   archive as a file (e.g. open( "test.lha#" ) )
	   Although open on a directory is not forbidden we cannot
	   create an appropriate tmpfile so we return EISDIR */
        return -EISDIR;
    }
  
    if(info->needbase) {
        res = av_get_realfile(ve->mnt->base, &rf);
        if(res < 0)
            return res;
    }
    else 
        rf = NULL;
  
    prog[0] = info->progpath;
    prog[1] = "copyout";
    prog[2] = rf == NULL ? "/" : rf->name;
    prog[3] = enod->fullpath;
    prog[4] = tmpfile;
    prog[5] = NULL;
  
    res = av_run_program(prog);
    av_unref_obj(rf);

    return res;
}

static struct ext_info *create_exts(char *line)
{
    struct ext_info *exts;
    char *elist, *newelist;
    int i, n;
  
    while(*line && !isspace((unsigned char) *line)) line++;
    if(*line) *line++ = '\0';
    while(isspace((unsigned char) *line)) line++;
    elist = line;

    for(n = 0; *line && *line != '#'; n++) {
        while(*line && !isspace((unsigned char) *line)) line++;
        while(isspace((unsigned char) *line)) line++;
    }
    if(!n) return NULL;  /* No extensions */
  
    exts = av_malloc((n + 1) * sizeof(*exts) + strlen(elist) + 1);

    newelist = (char *) (&exts[n+1]);
    strcpy(newelist, elist);
  
    for(i = 0; i < n; i++) {
        exts[i].from = newelist;
        exts[i].to   = NULL;
        while(*newelist && !isspace((unsigned char) *newelist)) newelist++;
        if(*newelist) *newelist++ = '\0';
        while(isspace((unsigned char) *newelist)) newelist++;

    }
    exts[n].from = NULL;
    exts[n].to   = NULL;

    return exts;
}

static avssize_t extfs_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct archfile *fil = arch_vfile_file(vf);
    struct extfsfile *efil = (struct extfsfile *) fil->data;

    if(lseek(efil->fd, vf->ptr, SEEK_SET) == -1)
        return -errno;

    res = read(efil->fd, buf, nbyte);
    if(res == -1)
        return -errno;

    vf->ptr += res;

    return res;
}

static int extfs_open(ventry *ve, struct archfile *fil)
{
    int res;
    struct extfsfile *efil;
    struct extfsnode *enod = (struct extfsnode *) fil->nod->data;
    int fd;
    char *key;
    struct extfscacheentry *cent;
    
    /* get key for extfscache */
    res = get_key_for_node(ve, fil, &key);
    if(res < 0)
        return res;

    AV_LOCK(enod->lock);
    cent = av_cache2_get(key);
    if (cent == NULL) {
        char *tmpfile;
        avoff_t tmpsize;

	/* no entry in cache so create a temporary file... */
        res = av_get_tmpfile(&tmpfile);
        if(res < 0) {
	    av_free(key);
	    AV_UNLOCK(enod->lock);
            return res;
	}
	res = get_extfs_file(ve, fil, tmpfile);
	if(res < 0) {
	    av_free(key);
	    av_del_tmpfile(tmpfile);
	    AV_UNLOCK(enod->lock);
	    return res;
	}

	/* ...create an object to store tmpfile */
	AV_NEW_OBJ(cent, extfscacheentry_delete);
	cent->tmpfile = tmpfile;

	/* put it in the extfscache */
	av_cache2_set(cent,key);
	AV_UNLOCK(enod->lock);

        tmpsize = av_tmpfile_blksize(tmpfile);
        if(tmpsize > 0)
            av_cache2_setsize(key, tmpsize);
    } else {
	AV_UNLOCK(enod->lock);
    }
    av_free(key);

    fd = open(cent->tmpfile, O_RDONLY);
    if(fd == -1) {
        res = -errno; 
        av_log(AVLOG_ERROR, "EXTFS: Could not open %s: %s", cent->tmpfile,
               strerror(errno));
	av_unref_obj(cent);
        return res;
    }

    AV_NEW(efil);
    efil->cent = cent;
    efil->fd = fd;

    fil->data = efil;
    
    return 0;
}

static int extfs_close(struct archfile *fil)
{
    struct extfsfile *efil = (struct extfsfile *) fil->data;

    close(efil->fd);

    av_unref_obj(efil->cent);
    av_free(efil);
    
    return 0;
}

static void extfsdata_delete(struct extfsdata *info)
{
    av_free(info->progpath);
}

static int create_extfs_handler(struct vmodule *module, const char *extfs_dir,
                                char *name)
{
    int res;
    struct avfs *avfs;
    struct archparams *ap;
    struct extfsdata *info;
    struct ext_info *extlist;
    int needbase;
    int end;

    /* Creates extension list, and strips name of the extensions */
    extlist = create_exts(name);
    end = strlen(name) - 1;

    if(name[end] == ':') {
        needbase = 0;
        name[end] = '\0';
    }
    else
        needbase = 1;

    res = av_archive_init(name, extlist, AV_VER, module, &avfs);
    av_free(extlist);
    if(res < 0)
        return res;

    ap = (struct archparams *) avfs->data;

    /* FIXME: If there is no basefile then cache the listing forever? */
    AV_NEW_OBJ(info, extfsdata_delete);
    ap->data = info;
    ap->parse = extfs_list;
    ap->read = extfs_read;
    ap->open = extfs_open;
    ap->close = extfs_close;

    if(!needbase)
        ap->flags |= ARF_NOBASE;
  
    info->progpath = av_stradd(NULL, extfs_dir, "/", name, NULL);
    info->needbase = needbase;
    
    av_add_avfs(avfs);

    return 0;
}

static int extfs_init(struct vmodule *module)
{
    char *extfs_dir, *extfs_conf;
    struct filebuf *fb;
    int fd;
    int res;
    char *line;
    char *c;

    extfs_dir = av_get_config("moduledir");
    extfs_dir = av_stradd(extfs_dir, "/extfs", NULL);
    extfs_conf = av_stradd(NULL, extfs_dir, "/extfs.ini", NULL);

    fd = open(extfs_conf, O_RDONLY);
    if(fd == -1) {
        res = -errno;
        av_log(AVLOG_WARNING, "Could not open extfs config file %s: %s", 
                 extfs_conf, strerror(errno));
        av_free(extfs_conf);
        av_free(extfs_dir);
        return res;
    }
    av_free(extfs_conf);
  
    fb = av_filebuf_new(fd, 0);

    while(1) {
        res = av_filebuf_getline(fb, &line, -1);
        if(res < 0 || line == NULL)
            break;

        if (*line != '#') {
            c = line + strlen(line) - 1;
            if(*c == '\n') *c-- = '\0';

            if(*line) 
                res = create_extfs_handler(module, extfs_dir, line);
        }
        av_free(line);
        if(res < 0) 
            break;
    }
    av_unref_obj(fb);
    av_free(extfs_dir);
    
    if(res < 0)
        return res;

    return 0;
}

extern int av_init_module_extfs(struct vmodule *module);

int av_init_module_extfs(struct vmodule *module)
{
    return extfs_init(module);
}
