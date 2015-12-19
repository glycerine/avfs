/* 
   Replacement memory allocation handling etc.
   Copyright (C) 1999-2001, Joe Orton <joe@light.plus.com>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "ne_alloc.h"

static void (*oom)(void);

#define DO_MALLOC(ptr, len) do {		\
    ptr = malloc(len);				\
    if (!ptr) {					\
	if (oom != NULL)			\
	    oom();				\
	abort();				\
    }						\
} while(0);

void ne_oom_callback(void (*callback)(void))
{
    oom = callback;
}

void *ne_malloc(size_t len) 
{
    void *ptr;
    DO_MALLOC(ptr, len);
    return ptr;
}

void *ne_calloc(size_t len) 
{
    void *ptr;
    DO_MALLOC(ptr, len);
    return memset(ptr, 0, len);
}

void *ne_realloc(void *ptr, size_t len)
{
    void *ret = realloc(ptr, len);
    if (!ret) {
	if (oom)
	    oom();
	abort();
    }
    return ret;
}

char *ne_strdup(const char *s) 
{
    char *ret;
    DO_MALLOC(ret, strlen(s) + 1);
    return strcpy(ret, s);
}

char *ne_strndup(const char *s, size_t n)
{
    char *new;
    DO_MALLOC(new, n);
    new[n] = '\0';
    memcpy(new, s, n);
    return new;
}
