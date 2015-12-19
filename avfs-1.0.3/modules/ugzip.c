/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
    
    UGZIP module
*/

#include "filter.h"
#include "version.h"

extern int av_init_module_ugzip(struct vmodule *module);

int av_init_module_ugzip(struct vmodule *module)
{
    struct avfs *avfs;
    const char *ugz_args[3];
    const char *gz_args[2];

    ugz_args[0] = "gzip";
    ugz_args[1] = "-d";
    ugz_args[2] = NULL;

    gz_args[0] = "gzip";
    gz_args[1] = NULL;

    return av_init_filt(module, AV_VER, "ugzip", ugz_args, gz_args,
                        NULL, &avfs);
}
