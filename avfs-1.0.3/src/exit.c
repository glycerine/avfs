/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "exit.h"
#include "avfs.h"

struct exithandler {
    void (*func) ();
    struct exithandler *next;
};

static AV_LOCK_DECL(exit_lock);
static struct exithandler *exit_handlers = NULL;

void av_do_exit()
{
    struct exithandler *hand;

    AV_LOCK(exit_lock);
    for(hand = exit_handlers; hand != NULL; hand = exit_handlers) {
        exit_handlers = hand->next;
        hand->func();
        av_free(hand);
    }
    AV_UNLOCK(exit_lock);
}

void av_add_exithandler(void (*func)())
{
    struct exithandler *hand;
    
    AV_NEW(hand);
    hand->func = func;
    AV_LOCK(exit_lock);
    hand->next = exit_handlers;
    exit_handlers = hand;
    AV_UNLOCK(exit_lock);
}
