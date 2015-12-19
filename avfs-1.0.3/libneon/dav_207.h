/* 
   WebDAV 207 multi-status response handling
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

#ifndef DAV207_H
#define DAV207_H

#include "hip_xml.h"
#include "http_request.h" /* for http_req */

BEGIN_NEON_DECLS

#define DAV_ELM_207_first (HIP_ELM_UNUSED)

#define DAV_ELM_multistatus (DAV_ELM_207_first)
#define DAV_ELM_response (DAV_ELM_207_first + 1)
#define DAV_ELM_responsedescription (DAV_ELM_207_first + 2)
#define DAV_ELM_href (DAV_ELM_207_first + 3)
#define DAV_ELM_propstat (DAV_ELM_207_first + 4)
#define DAV_ELM_prop (DAV_ELM_207_first + 5)
#define DAV_ELM_status (DAV_ELM_207_first + 6)

#define DAV_ELM_207_UNUSED (HIP_ELM_UNUSED + 100)

struct dav_207_parser_s;
typedef struct dav_207_parser_s dav_207_parser;

/* The name of a WebDAV property. */
typedef struct {
    const char *nspace, *name;
} dav_propname;

/* The handler structure: you provide a set of callbacks.
 * They are called in the order they are listed... start/end_prop
 * multiple times before end_prop, start/end_propstat multiple times
 * before an end_response, start/end_response multiple times.
 */

/* TODO: do we need to pass userdata to ALL of these? We could get away with
 * only passing the userdata to the start_'s and relying on the caller
 * to send it through as the _start return value if they need it. */

typedef void *(*dav_207_start_response)(void *userdata, const char *href);
typedef void (*dav_207_end_response)(
    void *userdata, void *response, const char *status_line,
    const http_status *status, const char *description);

typedef void *(*dav_207_start_propstat)(void *userdata, void *response);
typedef void (*dav_207_end_propstat)(
    void *userdata, void *propstat, const char *status_line, 
    const http_status *status, const char *description);

/* Create a 207 parser */

dav_207_parser *dav_207_create(hip_xml_parser *parser, void *userdata);

/* Set the callbacks for the parser */

void dav_207_set_response_handlers(
    dav_207_parser *p, dav_207_start_response start, dav_207_end_response end);

void dav_207_set_propstat_handlers(
    dav_207_parser *p, dav_207_start_propstat start, dav_207_end_propstat end);

void dav_207_destroy(dav_207_parser *p);

/* An acceptance function which only accepts 207 responses */
int dav_accept_207(void *userdata, http_req *req, http_status *status);

void *dav_207_get_current_propstat(dav_207_parser *p);
void *dav_207_get_current_response(dav_207_parser *p);

/* Call this as the LAST thing before beginning parsing, to install a
 * catch-all handler which means all unknown XML returned in the 207
 * response is ignored gracefully.  */
void dav_207_ignore_unknown(dav_207_parser *p);

END_NEON_DECLS

#endif /* DAV207_H */
