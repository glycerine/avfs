/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    UBZIP2 module
*/

#include "filter.h"
#include "version.h"

extern int av_init_module_ubzip2(struct vmodule *module);

int av_init_module_ubzip2(struct vmodule *module)
{
    struct avfs *avfs;
    const char *ubz2_args[3];
    const char *bz2_args[2];
  
    ubz2_args[0] = "bzip2";
    ubz2_args[1] = "-d";
    ubz2_args[2] = NULL;

    bz2_args[0] = "bzip2";
    bz2_args[1] = NULL;

    return av_init_filt(module, AV_VER, "ubzip2", ubz2_args, bz2_args,
                        NULL, &avfs);
}
