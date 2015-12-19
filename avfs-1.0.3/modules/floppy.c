/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    FLOPPY module (interface for mtools)
*/

#include "remote.h"
#include "runprog.h"

#include <sys/stat.h>
#include <fcntl.h>

struct floppylocalfile {
    char *tmpfile;
    struct program *pr;
    avoff_t currsize;
};

static void strip_spaces(const char *buf, int *ip)
{
    int i = *ip;
    while(isspace((unsigned char) buf[i])) i++;
    *ip = i;
}

static void strip_nonspace(const char *buf, int *ip)
{
    int i = *ip;
    while(!isspace((unsigned char) buf[i])) i++;
    *ip = i;
}

static void strip_spaces_end(char *buf)
{
    unsigned int i = strlen(buf);

    while(i > 0 && isspace((unsigned char) buf[i-1]))
        i--;
    buf[i] = '\0';
}

static int get_num(const char *s, int *ip)
{
    int i;
    int num;
  
    i = *ip;
  
    if(s[i] < '0' || s[i] > '9') return -1;

    num = 0;
    for(;; i++) {
        if(s[i] >= '0' && s[i] <= '9') num = (num * 10) + (s[i] - '0');
        else if(s[i] != ',' && s[i] != '.') break;
    }
  
    *ip = i;
    return num;
}

static int conv_date(const char *s, struct avtm *tms)
{
    int num;
    int i;
  
    i = 0;

    if((num = get_num(s, &i)) == -1 || num < 1 || num > 12) return -1;
    tms->mon = num - 1;
    i++;
  
    if((num = get_num(s, &i)) == -1 || num < 1 || num > 31) return -1;
    tms->day = num;
    i++;

    if((num = get_num(s, &i)) == -1) return -1;
    if(num >= 80 && num < 100) num += 1900;
    else if(num >= 0 && num < 80) num += 2000;

    if(num < 1900) return -1;
    tms->year = num - 1900;

    return 0;
}


static int conv_time(const char *s, struct avtm *tms)
{
    int num;
    int i;
  
    i = 0;

    if((num = get_num(s, &i)) == -1 || num < 0) return -1;
    tms->hour = num;
    i++;
  
    if((num = get_num(s, &i)) == -1 || num < 0 || num > 59) return -1;
    tms->min = num;

    if(s[i] == ':') {
        i++;
        if((num = get_num(s, &i)) == -1 || num < 0 ||  num > 59) return -1;

        tms->sec = num;
    }
    else tms->sec = 0;
  
    if((s[i] == 'p' || s[i] == 'P') && tms->hour < 12) tms->hour += 12;
    if(tms->hour > 24) return -1;
    if(tms->hour == 24) tms->hour = 0;

    return 0;
}


static int process_vollabel(const char *buf, struct avstat *st, char **namep)
{
    *namep = av_stradd(NULL, ".vol-", buf + 22, NULL);
    strip_spaces_end(*namep);

    st->mode = AV_IFREG | 0444;
    st->size = 0;

    return 0;
}

static int process_dir_line(const char *buf, int vollabel, struct avstat *st,
                            char **namep)
{
    int i, start;
    int namelen;
    struct avtm tms;
    char shortname[32];

    i = 0;

    if(strncmp(buf, " Volume in drive ", 17) == 0 && 
       buf[17] && strncmp(buf+18, " is ", 4) == 0 && buf[22]) {
        if(vollabel)
            return process_vollabel(buf, st, namep);
        else
            return -1;
    }

    strip_nonspace(buf, &i);
    if(!buf[i] || i == 0 || i > 8) return -1;
    
    namelen = i;
    strncpy(shortname, buf, namelen);
    shortname[namelen] = '\0';
    
    strip_spaces(buf, &i);
    if(i == 9) {
        int extlen;
        
        strip_nonspace(buf, &i);
        extlen = i - 9;
        
        if(extlen > 3) return -1;
        
        shortname[namelen++] = '.';
        strncpy(shortname+namelen, buf+9, extlen);
        namelen += extlen;
        shortname[namelen] = '\0';
        
        strip_spaces(buf, &i);
    }
    
    if(!buf[i] || i < 13) return -1;
    
    start = i;
    strip_nonspace(buf, &i);
    
    if(strncmp("<DIR>", buf + start, i - start) == 0) {
        st->size = 0;
        st->mode = AV_IFDIR | 0777;
    }
    else {
        int size;
        if((size = get_num(buf, &start)) == -1) return -1;
        st->size = size;
        st->mode = AV_IFREG | 0666;
    }
    strip_spaces(buf, &i);
    if(!buf[i]) return -1;
    
    start = i;
    strip_nonspace(buf, &i);
    if(conv_date(buf + start, &tms) == -1) return -1;
    strip_spaces(buf, &i);
    if(!buf[i]) return -1;
    
    start = i;
    strip_nonspace(buf, &i);
    if(conv_time(buf + start, &tms) == -1) return -1;
    strip_spaces(buf, &i);
    
    st->mtime.sec = av_mktime(&tms);
    st->mtime.nsec = 0;
    
    if(buf[i]) {
        *namep = av_strdup(buf+i);
        strip_spaces_end(*namep);
    }
    else
        *namep = av_strdup(shortname);

    return 0;
}

static void floppy_parse_line(const char *line, struct remdirlist *dl)
{
    int res;
    char *filename;
    struct avstat stbuf;
    int vollabel;

    if(strcmp(dl->hostpath.path, "/") == 0)
        vollabel = 1;
    else
        vollabel = 0;

    av_default_stat(&stbuf);
    res = process_dir_line(line, vollabel, &stbuf, &filename);
    if(res != 0)
        return;

    stbuf.nlink = 1;
    stbuf.blksize = 512;
    stbuf.blocks = AV_BLOCKS(stbuf.size);
    stbuf.atime = stbuf.mtime;
    stbuf.ctime = stbuf.mtime;

    av_remote_add(dl, filename, NULL, &stbuf);

    av_free(filename);
}

static int floppy_read_list(struct program *pr, struct remdirlist *dl)
{
    int res;

    while(1) {
        char *line;

        res = av_program_getline(pr, &line, -1);
        if(res <= 0)
            return res;
        if(line == NULL)
            return 0;

        floppy_parse_line(line, dl);
        av_free(line);
    }
}

static int floppy_get_path(struct remote *rem, struct remhostpath *hp,
                           char **resp)
{
    char drive[2];
    char *alias = (char *) rem->data;

    if(alias != NULL)
        drive[0] = alias[0];
    else {
        if(strlen(hp->host) != 1)
            return -ENOENT;
        drive[0] = tolower((unsigned char) hp->host[0]);
        if(drive[0] < 'a' || drive[0] > 'z')
            return -ENOENT;
    }
    drive[1] = '\0';

    *resp = av_stradd(NULL, drive, ":", hp->path, NULL);
    return 0;
}


static int floppy_list(struct remote *rem, struct remdirlist *dl)
{
    int res;
    struct program *pr;
    const char *prog[4];
    char *path;

    res = floppy_get_path(rem, &dl->hostpath, &path);
    if(res < 0)
        return res;

    prog[0] = "mdir";
    prog[1] = "-a";
    prog[2] = path;
    prog[3] = NULL;

    res = av_start_program(prog, &pr);
    if(res == 0) {
        res = floppy_read_list(pr, dl);
        av_unref_obj(pr);
    }
    av_free(path);

    return res;
}

static void floppy_free_localfile(struct floppylocalfile *lf)
{
    
    if(lf->pr != NULL) {
        av_program_log_output(lf->pr);
        av_unref_obj(lf->pr);
    }
}

static int floppy_get(struct remote *rem, struct remgetparam *gp)
{
    int res;
    struct floppylocalfile *lf;
    char *tmpfile;
    const char *prog[4];
    char *path;

    res = floppy_get_path(rem, &gp->hostpath, &path);
    if(res < 0)
        return res;

    res = av_get_tmpfile(&tmpfile);
    if(res < 0) {
        av_free(path);
	return res;
    }

    if(strncmp(gp->hostpath.path, "/.vol-", 6) == 0) {
        av_free(path);
        open(tmpfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        gp->data = NULL;
        gp->localname = tmpfile;
        return 0;
    }

    AV_NEW_OBJ(lf, floppy_free_localfile);
    lf->pr = NULL;
    lf->tmpfile = tmpfile;

    prog[0] = "mcopy";
    prog[1] = path;
    prog[2] = lf->tmpfile;
    prog[3] = NULL;

    res = av_start_program(prog, &lf->pr);
    av_free(path);
    if(res < 0) {
        av_unref_obj(lf);
        av_del_tmpfile(tmpfile);
        return res;
    }

    lf->currsize = 0;

    gp->data = lf;
    gp->localname = lf->tmpfile;

    return 1;
}

static int floppy_wait(struct remote *rem, void *data, avoff_t end)
{
    int res;
    struct floppylocalfile *lf = (struct floppylocalfile *) data;

    /* FIXME: timeout? */
    do {
        struct stat stbuf;
        
        res = av_program_log_output(lf->pr);
        if(res <= 0)
            return res;

        res = stat(lf->tmpfile, &stbuf);
        if(res == 0)
            lf->currsize = stbuf.st_size;

        if(lf->currsize < end)
            av_sleep(250);

    } while(lf->currsize < end);

    return 1;
}


static void floppy_destroy(struct remote *rem)
{
    av_free(rem->name);
    av_free(rem->data);
    av_free(rem);
}

static int floppy_init(struct vmodule *module, const char *modname,
                       const char *alias)
{
    int res;
    struct remote *rem;
    struct avfs *avfs;
    
    AV_NEW(rem);
    
    /* FIXME: Dont cache (at least not for long) */
    rem->flags   = REM_DIR_ONLY | REM_NOCASE;
    rem->data    = av_strdup(alias);
    rem->name    = av_strdup(modname);
    rem->destroy = floppy_destroy;
    rem->list    = floppy_list;
    rem->get     = floppy_get;
    rem->wait    = floppy_wait;

    res = av_remote_init(module, rem, &avfs);

    return res;
}

extern int av_init_module_floppy(struct vmodule *module);

int av_init_module_floppy(struct vmodule *module)
{
    int res;

    res = floppy_init(module, "floppy", NULL);
    if(res < 0)
        return res;

    res = floppy_init(module, "a", "a");
    if(res < 0)
        return res;

    return 0;
}
