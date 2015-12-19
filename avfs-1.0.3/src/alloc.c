/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#if 1
#include "avfs.h"

#include <stdio.h>
#include <stdlib.h>

static int malloctr;
static AV_LOCK_DECL(mallock);

void av_check_malloc()
{
    int ctr;

    AV_LOCK(mallock);
    ctr = malloctr;
    AV_UNLOCK(mallock);

    if(ctr != 0) 
        av_log(AVLOG_WARNING, "Unfreed memory remaining (%i)", ctr);
    else
        av_log(AVLOG_DEBUG, "No unfreed memory remaining");
}

static void out_of_memory()
{
    av_log(AVLOG_ERROR, "Out of memory");
    fprintf(stderr, "Out of memory\n");
    exit(127);
}

void *av_malloc(avsize_t nbyte)
{
    void *p;

    AV_LOCK(mallock);
    malloctr ++;
    AV_UNLOCK(mallock);

    if(nbyte == 0)
        nbyte = 1;

    p = malloc(nbyte);
    if(p == NULL) 
        out_of_memory();
    
    return p;
}

void *av_calloc(avsize_t nbyte)
{
    void *p;

    AV_LOCK(mallock);
    malloctr ++;
    AV_UNLOCK(mallock);
    
    if(nbyte == 0)
        nbyte = 1;
    
    p = calloc(nbyte, 1);
    if(p == NULL)
	out_of_memory();

    return p;
}

void *av_realloc(void *ptr, avsize_t nbyte)
{
    void *p;
    
    AV_LOCK(mallock);
    if(ptr == 0)
        malloctr ++;
    else if(nbyte == 0)
        malloctr --;
    AV_UNLOCK(mallock);

    if(ptr == NULL && nbyte == 0)
        nbyte = 1;

    p = realloc(ptr, nbyte);
    if(p == NULL)
        out_of_memory();
  
    return p;
}

void av_free(void *ptr)
{
    AV_LOCK(mallock);
    if(ptr != NULL)
        malloctr --;
    AV_UNLOCK(mallock);

    if(ptr != NULL)
	free(ptr);
}
#endif
