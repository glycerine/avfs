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

#ifndef NE_ALLOC_H
#define NE_ALLOC_H

#include "neonconf.h"

#ifdef WIN32
#include <stdlib.h>
#else
#include <sys/types.h>
#endif

/* Set callback which is called if malloc() returns NULL. */
void ne_oom_callback(void (*callback)(void));

/* Replacements for standard C library memory allocation functions.
 * These will NOT return NULL. If the C library malloc() returns NULL,
 * neon will call the OOM callback if you have registered it, or else,
 * call abort().  */
void *ne_malloc(size_t len);
void *ne_calloc(size_t len);
void *ne_realloc(void *ptr, size_t len);
char *ne_strdup(const char *s);
char *ne_strndup(const char *s, size_t n);

#endif /* NE_ALLOC_H */
