/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "avfs.h"
#include "serialfile.h"

struct filtdata {
    char **prog;
    char **revprog;
};

struct sfile *av_filtprog_new(vfile *vf, struct filtdata *fitdat);
void av_filtprog_change(struct sfile *sf, vfile *newvf);
