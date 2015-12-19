/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    AR module
*/

#include "archive.h"
#include "oper.h"
#include "version.h"

#define ARMAGIC     "!<arch>\n"
#define ARMAGICLEN  8
#define ENDMAGIC    "`\n"

struct ar_header {
    char name[16];
    char date[12];
    char uid[6];
    char gid[6];
    char mode[8];
    char size[10];
    char endmagic[2];
};

struct ar_values {
    avtime_t mtime;
    avuid_t  uid;
    avgid_t  gid;
    avmode_t mode;
    avsize_t size;
    avoff_t offset;
};

struct ar_nametab {
    char *names;
    avsize_t size;
};

static void fill_arentry(struct archive *arch, struct entry *ent,
                         struct ar_values *arv)
{
    struct archnode *nod;

    nod = av_arch_new_node(arch, ent, 0);
    
    nod->offset = arv->offset;
    nod->realsize = arv->size;

    nod->st.mode       = arv->mode;
    nod->st.uid        = arv->uid;
    nod->st.gid        = arv->gid;
    nod->st.blocks     = AV_BLOCKS(arv->size);
    nod->st.blksize    = 1024;
    nod->st.mtime.sec  = arv->mtime;
    nod->st.mtime.nsec = 0;
    nod->st.atime      = nod->st.mtime;
    nod->st.ctime      = nod->st.mtime;
    nod->st.size       = arv->size;
}

static void insert_arentry(struct archive *arch, struct ar_values *arv,
                           const char *name)
{
    struct entry *ent;

    if(!name[0]) {
        av_log(AVLOG_WARNING, "AR: Empty name");
        return;
    }
    if((arv->mode & AV_IFMT) == 0) {
        av_log(AVLOG_WARNING, "AR: Illegal type");
        return;
    }
        
    ent = av_arch_create(arch, name, 0);
    if(ent == NULL)
        return;

    fill_arentry(arch, ent, arv);
    av_unref_obj(ent);
}

static avulong getnum(const char *s, int len, int base)
{
    avulong num;
    int i;
  
    num = 0;
    for(i = 0; i < len; i++) {
        if(s[i] >= '0' && s[i] < '0' + base) num = (num * base) + (s[i] - '0');
        else break;
    }
  
    return num;
}

static int interpret_header(struct ar_header *hbuf, struct ar_values *arv)
{
    if(strncmp(hbuf->endmagic, ENDMAGIC, 2) != 0)
        return -1;

    arv->mtime = getnum(hbuf->date, 12, 10);
    arv->uid   = getnum(hbuf->uid,  6,  10);
    arv->gid   = getnum(hbuf->gid,  6,  10);
    arv->mode  = getnum(hbuf->mode, 8,  8);
    arv->size  = getnum(hbuf->size, 10, 10);

    return 0;
}

static int read_longnames(vfile *vf, struct ar_values *arv,
                          struct ar_nametab *nt)
{
    avssize_t rres;
    avsize_t i;
    
    if(nt->names != NULL) {
        av_log(AVLOG_WARNING, "AR: Multiple name tables");
        return 1;
    }
    
    if(arv->size == 0)
        return 1;

    if(arv->size >= (1 << 22)) {
        av_log(AVLOG_WARNING, "AR: name table too long");
        return 1;
    }

    nt->size = arv->size;
    nt->names = av_malloc(nt->size);
    
    rres = av_read(vf, nt->names, nt->size);
    if(rres < 0)
        return rres;
        
    if(rres != nt->size) {
        av_log(AVLOG_WARNING, "AR: Broken archive");
        return 0;
    }

    for(i = 0; i < nt->size; i++)
        if(nt->names[i] == '/' || nt->names[i] == '\\' || nt->names[i] == '\n')
            nt->names[i] = '\0';

    nt->names[nt->size - 1] = '\0';
    
    return 1;
}
                         
static int read_bsd_longname(vfile *vf, struct archive *arch,
                             struct ar_values *arv, char *shortname)
{
    avssize_t rres;
    avsize_t namelen;
    char *name;
    
    namelen = getnum(shortname + 3, 13, 10);

    name = av_malloc(namelen + 1);
    rres = av_read(vf, name, namelen);
    if(rres == namelen) {
        arv->size -= namelen;
        arv->offset += namelen;

        insert_arentry(arch, arv, name);
        av_free(name);
        return 1;
    }

    av_free(name);
    
    if(rres < 0)
        return rres;

    av_log(AVLOG_WARNING, "AR: Broken archive");
    return 0;
}

static void insert_longname(struct archive *arch, struct ar_values *arv,
                            char *shortname, struct ar_nametab *nt)
{
    if(nt->names != NULL) {
        avsize_t nameoffs;
	
        nameoffs = getnum(shortname + 1, 15, 10);
        if(nameoffs < nt->size)
            insert_arentry(arch, arv, nt->names + nameoffs);
        else
            av_log(AVLOG_WARNING, "AR: Bad filename table");            
    }
    else
        av_log(AVLOG_WARNING, "AR: Missing filename table");
}

static void insert_shortname(struct archive *arch, struct ar_values *arv,
                             char *name)
{
    int i;

    for(i = 0; i < 16; i++) 
        if(name[i] == '/') {
            name[i] = '\0';
            break;
        }

    /* If no slash was found, strip spaces from end */
    if(i == 16) 
        for(i = 15; i >= 0 && name[i] == ' '; i--) name[i] = '\0';
    
    insert_arentry(arch, arv, name);
}

static int process_name(vfile *vf, struct archive *arch, struct ar_values *arv,
                        char *name, struct ar_nametab *nt)
{
    if((strncmp(name, "//              ", 16) == 0 ||
        strncmp(name, "ARFILENAMES/    ", 16) == 0))
        return read_longnames(vf, arv, nt);

    if(name[0] == '#' && name[1] == '1' && name[2] == '/' &&
       name[3] >= '0' && name[3] <= '9') 
        return read_bsd_longname(vf, arch, arv, name);

    if((name[0] == '/' || name[0] == ' ') &&
       name[1] >= '0' && name[1] <= '9') {
        insert_longname(arch, arv, name, nt);
        return 1;
    }

    if(name[0] == '/' || strncmp(name, "__.SYMDEF       ", 16) == 0)
        return 1;

    insert_shortname(arch, arv, name);
    return 1;
}


static int read_entry(vfile *vf, struct archive *arch, struct ar_nametab *nt)
{
    int res;
    avssize_t rres;
    struct ar_header hbuf;
    struct ar_values arv;
    avoff_t sres, noff;
    
    rres = av_read(vf, (char *) &hbuf, sizeof(hbuf));
    if(rres <= 0) 
        return rres;
    
    if(rres != sizeof(hbuf)) {
        av_log(AVLOG_WARNING, "AR: Broken archive");
        return 0;
    }

    if(interpret_header(&hbuf, &arv) == -1) {
        av_log(AVLOG_WARNING, "AR: Broken archive");
        return 0;
    }

    arv.offset = vf->ptr;

    res = process_name(vf, arch, &arv, hbuf.name, nt);
    if(res <= 0)
        return res;

    noff = arv.offset + arv.size;
    if((noff & 1) != 0) noff++;
    
    sres = av_lseek(vf, noff, AVSEEK_SET);
    if(sres < 0)
        return sres;
    
    return 1;
}


static int read_arfile(vfile *vf, struct archive *arch)
{
    int res;
    char magic[ARMAGICLEN];
    avssize_t rres;
    struct ar_nametab nt;
  
    rres = av_read(vf, magic, ARMAGICLEN);
    if(rres < 0) 
        return rres;
    if(rres != ARMAGICLEN || strncmp(magic, ARMAGIC, ARMAGICLEN) != 0)
        return -EIO;
  
    nt.names = NULL;
    nt.size = 0;
    do res = read_entry(vf, arch, &nt);
    while(res == 1);

    av_free(nt.names);

    return res;
}

static int parse_arfile(void *data, ventry *ve, struct archive *arch)
{
    int res;
    vfile *vf;

    res = av_open(ve->mnt->base, AVO_RDONLY, 0, &vf);
    if(res < 0)
        return res;

    res = read_arfile(vf, arch);
    av_close(vf);
    
    return res;  
}

int av_init_module_uar(struct vmodule *module);

int av_init_module_uar(struct vmodule *module)
{
    int res;
    struct avfs *avfs;
    struct ext_info arexts[3];
    struct archparams *ap;
    
    arexts[0].from = ".a",   arexts[0].to = NULL;
    arexts[1].from = ".deb", arexts[1].to = NULL;
    arexts[2].from = NULL;

    res = av_archive_init("uar", arexts, AV_VER, module, &avfs);
    if(res < 0)
        return res;
    
    ap = (struct archparams *) avfs->data;
    ap->parse = parse_arfile;

    av_add_avfs(avfs);

    return 0;
}

