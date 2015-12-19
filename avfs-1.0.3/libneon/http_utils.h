/* 
   HTTP utility functions
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

#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>

#include "neon_defs.h"

BEGIN_NEON_DECLS

/* Returns a user-visible version string like:
 * "neon 0.2.0: Standalone build, OpenSSL support"
 */
const char *neon_version_string(void);

/* Returns non-zero if the neon API compiled in is less than
 * major.minor. i.e.
 *   I am: 1.2 -  neon_version_check(1, 3) => -1
 *   I am: 0.10 -  neon_version_check(0, 9) => 0
 */
int neon_version_minimum(int major, int minor);

#define HTTP_QUOTES "\"'"
#define HTTP_WHITESPACE " \r\n\t"

/* Handy macro to free things. */
#define HTTP_FREE(x) do { if ((x) != NULL) free((x)); (x) = NULL; } while (0)

#ifndef HTTP_PORT
#define HTTP_PORT 80
#endif

time_t http_dateparse(const char *date);

#ifndef WIN32
#undef min
#define min(a,b) ((a)<(b)?(a):(b))
#endif

/* CONSIDER: mutt has a nicer way of way of doing debugging output... maybe
 * switch to like that. */
#ifndef DEBUGGING
#define DEBUG if (0) neon_debug
#else /* DEBUGGING */
#define DEBUG neon_debug
#endif /* DEBUGGING */

#define DEBUG_SOCKET (1<<0)
#define DEBUG_HTTP (1<<1)
#define DEBUG_XML (1<<2)
#define DEBUG_HTTPAUTH (1<<3)
#define DEBUG_HTTPPLAIN (1<<4)
#define DEBUG_LOCKS (1<<5)
#define DEBUG_XMLPARSE (1<<6)
#define DEBUG_HTTPBODY (1<<7)
#define DEBUG_HTTPBASIC (1<<8)
#define DEBUG_FLUSH (1<<30)

void neon_debug_init(FILE *stream, int mask);
extern int neon_debug_mask;

void neon_debug(int ch, const char *, ...)
#ifdef __GNUC__
                __attribute__ ((format (printf, 2, 3)))
#endif /* __GNUC__ */
;

/* Storing an HTTP status result */
typedef struct {
    int major_version;
    int minor_version;
    int code; /* Status-Code value */
    /* We can't use 'class' as the member name since this crashes
     * with the C++ reserved keyword 'class', annoyingly.
     * This was '_class' previously, but that was even MORE annoying.
     * So know it is klass. */
    int klass; /* Class of Status-Code (1-5) */
    const char *reason_phrase;
} http_status;

/* Parser for strings which follow the Status-Line grammar from 
 * RFC2616.
 *  Returns:
 *    0 on success, *s will be filled in.
 *   -1 on parse error.
 */
int http_parse_statusline(const char *status_line, http_status *s);

END_NEON_DECLS

#endif /* HTTP_UTILS_H */
