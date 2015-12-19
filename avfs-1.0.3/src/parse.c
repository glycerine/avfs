/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    Copyright (C) 2006  Ralf Hoffmann (ralf@boomerangsworld.de)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    Path parser module
*/

#include "internal.h"
#include "version.h"
#include "local.h"
#include "mod_static.h"
#include "operutil.h"
#include "oper.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

static AV_LOCK_DECL(initlock);
static int inited;

struct avfs_list {
    struct avfs *avfs;
    struct avfs_list *next;
    struct avfs_list *prev;
};

static AV_LOCK_DECL(avfs_lock);
static struct avfs_list avfs_list;
static int symlink_rewrite = 0;

struct parse_state {
    ventry *ve;
    char *path;
    char *prevseg;
    int islink;
    int resolvelast;
    int nextseg;
    int linkctr;
    int first_seg;  /* true if no segment was analysed, see segment_len() comment */
};

static int copyrightstat_get(struct entry *ent, const char *param, char **retp)
{
    char buf[256];

    sprintf(buf, 
            "AVFS Virtual File System (C) Miklos Szeredi 1998-2001, Version %i.%i.%i,\n"
            "AVFS comes with ABSOLUTELY NO WARRANTY.\n", 
            AV_VER / 100,
            (AV_VER / 10) % 10,
            AV_VER % 10);
    
    *retp = av_strdup(buf);
    
    return 0;
}

static int modstat_get(struct entry *ent, const char *param, char **retp)
{
    char *ret = av_strdup("");
    char buf[128];

    struct avfs_list *li;

    AV_LOCK(avfs_lock);
    for(li = avfs_list.next; li != &avfs_list; li = li->next) {
        struct avfs *avfs = li->avfs;
        struct ext_info *exts;
        int ei;
        int ver = avfs->version;

	sprintf(buf, "%2d.%d.%d\t", (ver / 100) % 100, (ver / 10) % 10,
                ver % 10);

        ret = av_stradd(ret, buf, avfs->name, ":\t", NULL);

	exts = avfs->exts;
	if(exts != NULL) 
	    for(ei = 0; exts[ei].from != NULL; ei++) {
                ret = av_stradd(ret, exts[ei].from, NULL);
		if(exts[ei].to != NULL)
                    ret = av_stradd(ret, "(", exts[ei].to, ")", NULL);
                
                ret = av_stradd(ret, " ", NULL);
	    }

        ret = av_stradd(ret, "\n", NULL);
    }
    AV_UNLOCK(avfs_lock);

    *retp = ret;

    return 0;
}

static int versionstat_get(struct entry *ent, const char *param, char **retp)
{
    char buf[128];
    char *compiledate;
    char *compilesys;
    char *moduledir;

    sprintf(buf, "%i.%i.%i", AV_VER / 100, (AV_VER / 10) % 10, AV_VER % 10);

    compiledate = av_get_config("compiledate");
    compilesys = av_get_config("compilesystem");
    moduledir = av_get_config("moduledir");

    *retp = av_stradd(NULL, "Interface version: ", buf, 
                        "\nCompile date: ", compiledate,
                        "\nCompile system: ", compilesys,
                        "\nModule directory: ", moduledir, "\n", NULL);

    av_free(compiledate);
    av_free(compilesys);
    av_free(moduledir);

    return 0;
}

static int symlinkrewrite_get(struct entry *ent, const char *param, char **retp)
{
    char buf[32];
    
    AV_LOCK(avfs_lock);
    sprintf(buf, "%d\n", symlink_rewrite);
    AV_UNLOCK(avfs_lock);

    *retp = av_strdup(buf);
    return 0;
}

static int symlinkrewrite_set(struct entry *ent, const char *param, const char *val)
{
    int mode;

    if(strlen(val) < 2)
        return -EINVAL;

    if(val[1] != '\n' && val[1] != ' ') 
        return -EINVAL;

    if(val[0] == '0')
        mode = 0;
    else if(val[0] == '1')
        mode = 1;
    else
        return -EINVAL;
    
    AV_LOCK(avfs_lock);
    symlink_rewrite = mode;
    AV_UNLOCK(avfs_lock);

    return 0;
}

static void init_stats()
{
    struct statefile statf;
    
    statf.data = NULL;
    statf.set = NULL;

    statf.get = copyrightstat_get;
    av_avfsstat_register("copyright", &statf);
    
    statf.get = modstat_get;
    av_avfsstat_register("modules", &statf);

    statf.get = versionstat_get;
    av_avfsstat_register("version", &statf);

    statf.get = symlinkrewrite_get;
    statf.set = symlinkrewrite_set;
    av_avfsstat_register("symlink_rewrite", &statf);
}

static void destroy()
{
    av_log(AVLOG_DEBUG, "DESTROY");

    AV_LOCK(initlock);
    if(inited) {
        av_close_all_files();

        AV_LOCK(avfs_lock);
        while(avfs_list.next != &avfs_list) {
            struct avfs_list *li = avfs_list.next;

            li->next->prev = li->prev;
            li->prev->next = li->next;
            av_unref_obj(li->avfs);
            av_free(li);
        }
        AV_UNLOCK(avfs_lock);

        av_do_exit();
	av_delete_tmpdir();

        inited = 0;
    }
    AV_UNLOCK(initlock);

    av_check_malloc();
    av_log(AVLOG_DEBUG, "DESTROY successful");
}

static int init()
{
    int res = 0;

    AV_LOCK(initlock);    
    if(!inited) {
        av_log(AVLOG_DEBUG, "INIT");

        avfs_list.next = &avfs_list;
        avfs_list.prev = &avfs_list;

        res = av_init_module_local();
        if(res == 0) {
            av_init_avfsstat();
            av_init_static_modules();
            av_init_dynamic_modules();
            av_init_logstat();
            init_stats();
            av_init_cache();
            av_init_filecache();
            atexit(destroy);
            inited = 1;
            av_log(AVLOG_DEBUG, "INIT successful");
        }
        else
            av_log(AVLOG_DEBUG, "INIT failed");
    }
    AV_UNLOCK(initlock);

    return res;
}

void av_add_avfs(struct avfs *newavfs)
{
    struct avfs_list *li;

    AV_NEW(li);
    AV_LOCK(avfs_lock);
    li->avfs = newavfs;
    li->next = &avfs_list;
    li->prev = avfs_list.prev;
    avfs_list.prev = li;
    li->prev->next = li;
    AV_UNLOCK(avfs_lock);
}

static int av_copy_parsestate(struct parse_state *ps, struct parse_state *destps)
{
    destps->linkctr = ps->linkctr;
    destps->nextseg = ps->nextseg;
    destps->resolvelast = ps->resolvelast;
    destps->islink = ps->islink;

    if(ps->path)
      destps->path = av_strdup(ps->path);
    else
      destps->path = NULL;

    destps->first_seg = ps->first_seg;

    if(ps->prevseg)
      destps->prevseg = av_strdup(ps->prevseg);
    else
      destps->prevseg = NULL;

    av_copy_ventry(ps->ve, &(destps->ve));
    return 0;
}

static void set_prevseg(struct parse_state *ps, const char *name)
{
    av_free(ps->prevseg);
    ps->prevseg = av_strdup(name);
}

static int lookup_virtual(struct parse_state *ps, const char *name)
{
    int res;
    ventry *ve = ps->ve;
    struct avfs *avfs = ve->mnt->avfs;
    void *newdata;

    AVFS_LOCK(avfs);
    res = avfs->lookup(ve, name, &newdata);
    AVFS_UNLOCK(avfs);
    if(res < 0)
        return res;
    
    ve->data = newdata;
    if(ve->data != NULL) {
        if(res == (AV_IFLNK >> 12))
            ps->islink = 1;

        res = 0;
    }
    else {
        ps->ve = ve->mnt->base;
        ve->mnt->base = NULL;
        av_free_ventry(ve);

        res = lookup_virtual(ps, NULL);
    }

    return res;
}

static struct avmount *new_mount(ventry *base, struct avfs *avfs,
				 const char *opts)
{
    struct avmount *mnt;

    AV_NEW(mnt);

    mnt->base = base;
    mnt->avfs = avfs;
    mnt->opts = av_strdup(opts);
    mnt->flags = 0;

    return mnt;
}

static int is_root(ventry *ve)
{
    char *path;
    struct stat pathstat;
    struct stat rootstat;
    int res;

    if(ve->mnt->base != NULL)
	return 0;

    for(path = (char *) ve->data; *path == AV_DIR_SEP_CHAR; path++);
    if(!*path)
	return 1;

    res = stat((char *) ve->data, &pathstat);
    if(res == -1)
	return 0;

    res = stat("/", &rootstat);
    if(res == -1)
	return 0;
    
    if(rootstat.st_dev == pathstat.st_dev &&
       rootstat.st_ino == pathstat.st_ino)
	return 1;

    return 0;
}

static int enter_mount(struct parse_state *ps, struct avfs *avfs,
                       const char *opts, const char *param)
{
    int res;
    ventry *newve;
    
    AV_NEW(newve);

    newve->mnt = new_mount(ps->ve, avfs, opts);
    newve->data = NULL;

    ps->ve = newve;

    if((avfs->flags & AVF_ONLYROOT) != 0 && !is_root(ps->ve->mnt->base))
        return -ENOENT;

    res = lookup_virtual(ps, param);

    return res;
}

static struct ext_info *find_ext(struct ext_info *exts, const char *prevseg)
{
    int ei;
    unsigned int prevseglen = strlen(prevseg);

    for(ei = 0; exts[ei].from != NULL; ei++) {
        unsigned int extlen = strlen(exts[ei].from);
        if(prevseglen >= extlen) {
            const char *prevsegext = prevseg + prevseglen - extlen;
            if(strncasecmp(prevsegext, exts[ei].from, extlen) == 0)
                return &exts[ei];
        }
    }
    return NULL;
}

static struct avfs *find_auto_avfs(const char *prevseg, struct ext_info **extp)
{
    struct ext_info *exts;
    struct avfs_list *li;

    for(li = avfs_list.next; li != &avfs_list; li = li->next) {
        exts = li->avfs->exts;
        if(exts != NULL) {
            struct ext_info *e;
            e = find_ext(exts, prevseg);
            if(e != NULL) {
                *extp = e;
                return li->avfs;
            }
        }
    }

    return NULL;
}

static void get_new_name(struct parse_state *ps, struct ext_info *ext)
{
    unsigned int extlen = strlen(ext->from);
    unsigned int prevseglen = strlen(ps->prevseg);
        
    ps->prevseg[prevseglen - extlen] = '\0';
    if(ext->to != NULL) 
        ps->prevseg = av_stradd(ps->prevseg, ext->to, NULL);
}


static int lookup_auto_avfs(struct parse_state *ps, const char *opts,
                            const char *param)
{
    int res;
    struct avfs *avfs;
    struct ext_info *ext = NULL;

    AV_LOCK(avfs_lock);
    avfs = find_auto_avfs(ps->prevseg, &ext);
    if(avfs == NULL)
        res = -ENOENT;
    else {
        av_ref_obj(avfs);

        get_new_name(ps, ext);
        if(find_auto_avfs(ps->prevseg, &ext) == NULL)
            set_prevseg(ps, "");
        else {
            param = "";
            ps->nextseg = 0;
        }
        res = 0;
    }
    AV_UNLOCK(avfs_lock);

    if(res == 0) {
        res = enter_mount(ps, avfs, opts, param);
        if(res == 0)
            ps->ve->mnt->flags = 1;
    }

    return res;
}

static int is_handler_char(int ch)
{
    return isalpha(ch) || isdigit(ch) || ch == '_';
}

static struct avfs *find_avfs_name(char *name)
{
    struct avfs_list *li;

    if(!*name)
	return NULL;

    AV_LOCK(avfs_lock);
    for(li = avfs_list.next; li != &avfs_list; li = li->next)
	if(li->avfs->name != NULL && 
	   strcmp(li->avfs->name, name) == 0) {
            av_ref_obj(li->avfs);
            break;
        }
    AV_UNLOCK(avfs_lock);
    
    return li->avfs;
}

static int is_special(const char *name)
{
    if(name[0] == '.' &&
       (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
	return 1;

    return 0;
}

static int lookup_avfs(struct parse_state *ps, char *name)
{
    int res;
    char c;
    char *s;
    char *opts;
    const char *param;
    struct avfs *avfs;

    if(is_special(ps->prevseg))
        return -ENOENT;

    for(s = name; *s && is_handler_char(*s); s++);
    opts = s;
    for(; *s && *s != ':'; s++);
    c = *s;
    if(*s == ':') {
        *s = '\0';
        param = s + 1;
        if(*param == '\0' || *param == AV_DIR_SEP_CHAR)
            return -ENOENT;
    }
    else
        param = "";

    if(name == opts) {
        res = lookup_auto_avfs(ps, opts, param);
        *s = c;
        return res;
    }

    c = *opts;
    *s = '\0';
    avfs = find_avfs_name(name);
    *opts = c;

    if(avfs == NULL)
        return -ENOENT;
    
    res = enter_mount(ps, avfs, opts, param);
    set_prevseg(ps, "");

    return res;
}

static int lookup_segment(struct parse_state *ps, int noavfs)
{
    int res;
    char *name = ps->path;
    ventry *ve = ps->ve;

    /* only enter next avfs hierarchie if the magic char is not the
       very first char (first_seg) and we really want this action
       (noavfs needed by segment_islocal() test */

    if((name[0] == AVFS_SEP_CHAR) && (noavfs == 0) && (ps->first_seg == 0))
      res = lookup_avfs(ps, name+1);
    else {
        /* reset first_seg as we now process a path segment and from now on 
	   the next magic char is always the magic char and not from a local
	   filename */
        ps->first_seg = 0;

        for(;*name && *name == AV_DIR_SEP_CHAR; name++);
        set_prevseg(ps, name);

	if((ve->mnt->avfs->flags & AVF_NEEDSLASH) != 0)
	   name = ps->path;
        
        if(name[0] != '\0')
            res = lookup_virtual(ps, name);
        else
            res = 0;
    }
        
    return res;
}

static int segment_islocal(struct parse_state *ps, unsigned int seglen )
{
    int islocal = 0;
    char c;
    struct parse_state tempps;
    int f;

    /* we will copy the whole parse_state and try to find a local entry
       if open succeed there is a local file and we can return true */

    av_copy_parsestate( ps, &tempps );
    
    tempps.nextseg = seglen;
    c = tempps.path[seglen];
    tempps.path[seglen] = '\0';
    
    /* we force lookup_segment() to not enter any avfs hierarchie */
    lookup_segment(&tempps, 1);
    f = av_fd_open_entry(tempps.ve, AVO_RDONLY, 0);
    av_free_ventry(tempps.ve);
    av_free(tempps.path);
    av_free(tempps.prevseg);
    if ( f >= 0 ) {
      islocal = 1;
      av_fd_close(f);
    }
    return islocal;
}

static unsigned int segment_len(struct parse_state *ps, int ignoreMagic)
{
    const char *s = ps->path,
               *first_s = ps->path;
    unsigned int seglen, orig_seglen;
    int found_magic = 0, search_avfs_key = 0;

    /* this function will find the next segment len by also checking for local files
       with magic chars inside the filename
       two cases:
       1.magic at the beginning:
         in this case we are searching for an avfs key (#utar, #ugz...)
	 so we will stop at the next magic char or dir separator
	 except when this magic char is the very first character
	 where it makes no sense to accept this as an avfs key
	 (imagine open("#utar"))
	 For this case there is a new flag first_seg which takes
	 care of this
       2.Otherwise we are searching for the longest path segment
         starting at the next dir separator skipping any magic char
	 we stop after first local hit
	 If no local file was found we return whole segment len to be able
	 to open new files with magic chars
       If no magic char was found or we are forced to ignore it
       we immediately return the whole path segment without any checking
    */

    if(s[0] == AVFS_SEP_CHAR) {
        s++;
	if(ps->first_seg == 0)
            search_avfs_key = 1;
    } else while(*s == AV_DIR_SEP_CHAR)
        s++;
    
    while(*s && *s != AV_DIR_SEP_CHAR) {
        if(*s == AVFS_SEP_CHAR) {
            if(found_magic == 0) {
	        first_s = s;
	    }
	    found_magic++;
        }
        s++;
    }
    seglen = s - ps->path;

    if((ignoreMagic == 1) || (found_magic == 0)) return seglen;

    /* a magic char was already found so first_s is correct */
    if(search_avfs_key == 1)
        return (first_s - ps->path);

    orig_seglen = seglen;
    /* found magic char so check for existing local file */
    while(seglen > 0) {
        if(segment_islocal(ps, seglen) == 1)
	    break;
        for(seglen = seglen - 1;
            (seglen > 0) && ( ps->path[seglen] != AVFS_SEP_CHAR );
            seglen--);
    }

    if(seglen > 0) return seglen;
    else return orig_seglen;
}

static int is_last(struct parse_state *ps, unsigned int seglen)
{
    const char *s;

    for(s = ps->path + seglen; *s && *s == AV_DIR_SEP_CHAR; s++);
    if(!*s)
        return 1;
    else
        return 0;
}

static struct avfs *get_local_avfs()
{
    struct avfs *localavfs;

    AV_LOCK(avfs_lock);
    localavfs = avfs_list.next->avfs;
    av_ref_obj(localavfs);
    AV_UNLOCK(avfs_lock);

    return localavfs;
}

static int parse_path(struct parse_state *ps, int force_localfile);

static int follow_link(struct parse_state *ps)
{
    int res;
    struct parse_state linkps;
    char *buf;

    if(!ps->linkctr)
        return -ELOOP;

    res = av_readlink(ps->ve, &buf);
    if(res < 0)
        return res;

    linkps.path = buf;
    linkps.resolvelast = 1;
    linkps.linkctr = ps->linkctr - 1;

    if(buf[0] != AV_DIR_SEP_CHAR) {
        linkps.ve = ps->ve;
        
        res = lookup_virtual(&linkps, NULL);
        if(res == 0)
            res = parse_path(&linkps, 0);
    }
    else {
        av_free_ventry(ps->ve);

        AV_NEW(linkps.ve);
        linkps.ve->mnt = new_mount(NULL, get_local_avfs(), NULL);
        linkps.ve->data = av_strdup("");

        res = parse_path(&linkps, 0);
    }

    
    av_free(buf);
    ps->ve = linkps.ve;
    
    return res;
}

static int parse_path(struct parse_state *ps, int force_localfile)
{
    int res = 0;
    int numseg = 0;

    ps->prevseg = av_strdup("");
    ps->first_seg = 1;
    while(ps->path[0]) {
        unsigned int seglen;
        int lastseg;
        char c;

	seglen = segment_len(ps, force_localfile);
	
        lastseg = is_last(ps, seglen);
        ps->nextseg = seglen;
        c = ps->path[seglen];
        ps->path[seglen] = '\0';
        ps->islink = 0;
        
        res = lookup_segment(ps,0);
        if(res < 0)
            break;
        
        if(ps->islink && (ps->resolvelast || !lastseg)) {
            res = follow_link(ps);
            if(res < 0) 
                break;
        }
        ps->path[seglen] = c;
        ps->path += ps->nextseg;
        numseg ++;
        
        if(numseg > 1000) {
            av_log(AVLOG_ERROR, "Infinate loop in parse_path");
            res = -EFAULT;
            break;
        }
    }

    av_free(ps->prevseg);

    return res;
}

int av_get_ventry(const char *path, int resolvelast, ventry **resp)
{
    int res;
    struct parse_state ps;
    char *copypath;

    res = init();
    if(res < 0)
        return res;

    if(path == NULL)
        return -ENOENT;

    copypath = av_strdup(path);
    ps.path = copypath;
    ps.resolvelast = resolvelast;
    ps.linkctr = 10;

    AV_NEW(ps.ve);
    ps.ve->mnt = new_mount(NULL, get_local_avfs(), NULL);
    ps.ve->data = av_strdup("");

    res = parse_path(&ps, 0);

    /* no ventry so force localfile to be able to create files with
       the magic character inside filename */
    if(res < 0) {
        av_free(copypath);
        copypath = av_strdup(path);
        av_free_ventry(ps.ve);
        ps.path = copypath;
        ps.resolvelast = resolvelast;
        ps.linkctr = 10;
        AV_NEW(ps.ve);
        ps.ve->mnt = new_mount(NULL, get_local_avfs(), NULL);
        ps.ve->data = av_strdup("");
        res = parse_path(&ps, 1);
    }

    if(res < 0) {
        av_free_ventry(ps.ve);
        *resp = NULL;
    }
    else
        *resp = ps.ve;

    av_free(copypath);

    return res;
}

int av_copy_vmount(struct avmount *mnt, struct avmount **resp)
{
    int res;
    ventry *newbase;
    
    if(mnt->base != NULL) {
        res = av_copy_ventry(mnt->base, &newbase);
        if(res < 0)
            return res;
    }
    else
        newbase = NULL;

    av_ref_obj(mnt->avfs);

    *resp = new_mount(newbase, mnt->avfs, mnt->opts);
    
    return 0;
}

int av_copy_ventry(ventry *ve, ventry **resp)
{
    int res;
    ventry *newve;
    struct avmount *newmnt;
    void *newdata;
    struct avfs *avfs = ve->mnt->avfs;

    res = av_copy_vmount(ve->mnt, &newmnt);
    if(res < 0)
	return res;

    if(ve->data != NULL) {
        AVFS_LOCK(avfs);
        res = avfs->copyent(ve, &newdata);
        AVFS_UNLOCK(avfs);
        if(res < 0)
            return res;
    }
    else
	newdata = NULL;
    
    AV_NEW(newve);
    
    newve->data = newdata;
    newve->mnt = newmnt;

    *resp = newve;

    return 0;
}

void av_free_vmount(struct avmount *mnt)
{
    av_unref_obj(mnt->avfs);

    av_free(mnt->opts);
    av_free_ventry(mnt->base);
    av_free(mnt);
}

void av_free_ventry(ventry *ve)
{
    if(ve != NULL) {
	struct avfs *avfs = ve->mnt->avfs;

        if(ve->data != NULL) {
            AVFS_LOCK(avfs);
            avfs->putent(ve);
            AVFS_UNLOCK(avfs);
        }

        av_free_vmount(ve->mnt);
        av_free(ve);
    }
}


static int ipath_len(const char *s)
{
    int cnt;

    for(cnt = 0; *s; s++, cnt++);

    return cnt;
}

static void ipath_copy(char *dst, const char *src)
{
    for(; *src; dst++, src++) {
        *dst = *src;
    }
    *dst = '\0';
}

static char *expand_segment(char *segment)
{
    char *tmp;

    tmp = (char *) av_malloc(ipath_len(segment) + 1);
    ipath_copy(tmp, segment);
    av_free(segment);

    return tmp;
}

static int add_segment(ventry *ve, char **pathp)
{
    int res;
    char *segment;
    struct avfs *avfs = ve->mnt->avfs;

    if(ve->data != NULL) {
        AVFS_LOCK(avfs);
        res = avfs->getpath(ve, &segment);
        AVFS_UNLOCK(avfs);
        if(res < 0)
            return res;
    }
    else 
        segment = av_strdup("");

    if(ve->mnt->base == NULL)
	*pathp = av_stradd(*pathp, segment, NULL);
    else {
	char *avfsname = avfs->name;
	char *opts = ve->mnt->opts;
	char avfssep[] = { AVFS_SEP_CHAR, '\0' };
        const char *paramsep;
        
        if(segment[0] && segment[0] != AV_DIR_SEP_CHAR)
            paramsep = ":";
        else
            paramsep = "";
	
        segment = expand_segment(segment);
	
	*pathp = av_stradd(*pathp, avfssep, avfsname, opts, paramsep,
                             segment, NULL);
    }
    av_free(segment);

    return 0;
}

int av_generate_path(ventry *ve, char **pathp)
{
    int res;

    if(ve == NULL) 
        *pathp = NULL;
    else {
        res = av_generate_path(ve->mnt->base, pathp);
        if(res < 0)
            return res;

        res = add_segment(ve, pathp);
        if(res < 0) {
            av_free(*pathp);
            return res;
        }
    }

    return 0;
}

int av_get_symlink_rewrite()
{
    return symlink_rewrite;
}
