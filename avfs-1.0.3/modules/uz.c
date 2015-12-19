/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    UZ (uncompress) module 
    using gzip
*/

#include "filter.h"
#include "version.h"

int av_init_module_uz(struct vmodule *module)
{
    struct avfs *avfs;
    struct ext_info uz_exts[5];
    const char *uz_args[3];

    uz_exts[0].from = ".Z",   uz_exts[0].to = NULL;
    uz_exts[1].from = ".tpz", uz_exts[1].to = ".tar";
    uz_exts[2].from = ".tz",  uz_exts[2].to = ".tar";
    uz_exts[3].from = ".taz", uz_exts[3].to = ".tar";
    uz_exts[4].from = NULL;
  
    uz_args[0] = "gzip";
    uz_args[1] = "-d";
    uz_args[2] = NULL;

    return av_init_filt(module, AV_VER, "uz", uz_args, NULL, uz_exts, &avfs);
}
