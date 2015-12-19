/*  
    AVFS: A Virtual File System Library
    Copyright (C) 2010 Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
    
    UXZE module
*/

#include "filter.h"
#include "version.h"

extern int av_init_module_uxze(struct vmodule *module);

int av_init_module_uxze(struct vmodule *module)
{
    struct avfs *avfs;
    const char *uxze_args[3];
    const char *xze_args[2];
    struct ext_info uxze_exts[5];

    uxze_args[0] = "xz";
    uxze_args[1] = "-d";
    uxze_args[2] = NULL;

    xze_args[0] = "xz";
    xze_args[1] = NULL;

    uxze_exts[0].from = ".tar.xz",   uxze_exts[0].to = ".tar";
    uxze_exts[1].from = ".txz",  uxze_exts[1].to = ".tar";
    uxze_exts[2].from = ".xz",   uxze_exts[2].to = NULL;
    uxze_exts[3].from = ".lzma",   uxze_exts[3].to = NULL;
    uxze_exts[4].from = NULL;

    return av_init_filt(module, AV_VER, "uxze", uxze_args, xze_args,
                        uxze_exts, &avfs);
}
