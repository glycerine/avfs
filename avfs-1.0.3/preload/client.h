/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "send.h"

int __av_send_message(struct avfs_out_message *out,
                      struct avfs_in_message *in, int keepsock);
