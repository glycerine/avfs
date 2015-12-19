/* 
   WebDAV Class 1 namespace operations and 207 error handling
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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "http_request.h"

#include "dav_basic.h"
#include "uri.h" /* for uri_has_trailing_slash */
#include "http_basic.h" /* for http_content_type */
#include "string_utils.h" /* for sbuffer */
#include "dav_207.h"
#include "ne_alloc.h"

#ifdef USE_DAV_LOCKS
#include "dav_locks.h"
#endif

/* Handling of 207 errors: we keep a string buffer, and append
 * messages to it as they come down.
 *
 * Note, 424 means it would have worked but something else went wrong.
 * We will have had the error for "something else", so we display
 * that, and skip 424 errors. */

/* This is passed as userdata to the 207 code. */
struct context {
    char *href;
    sbuffer buf;
    unsigned int is_error;
};

static void *start_response(void *userdata, const char *href)
{
    struct context *ctx = userdata;
    HTTP_FREE(ctx->href);
    ctx->href = ne_strdup(href);
    return NULL;
}

static void handle_error(struct context *ctx,
			 const char *status_line, const http_status *status,
			 const char *description)
{
    if (status && status->klass != 2) {
	if (status->code != 424) {
	    ctx->is_error = 1;
	    sbuffer_concat(ctx->buf, ctx->href, ": ", status_line, "\n", NULL);
	    if (description != NULL) {
		/* TODO: these can be multi-line. Would be good to
		 * word-wrap this at col 80. */
		sbuffer_concat(ctx->buf, " -> ", description, "\n", NULL);
	    }
	}
    }

}

static void end_response(void *userdata, void *response, const char *status_line,
			 const http_status *status, const char *description)
{
    struct context *ctx = userdata;
    handle_error(ctx, status_line, status, description);
}

static void 
end_propstat(void *userdata, void *propstat, const char *status_line,
	     const http_status *status, const char *description)
{
    struct context *ctx = userdata;
    handle_error(ctx, status_line, status, description);
}

void dav_add_depth_header(http_req *req, int depth)
{
    const char *value;
    switch(depth) {
    case DAV_DEPTH_ZERO:
	value = "0";
	break;
    case DAV_DEPTH_ONE:
	value = "1";
	break;
    default:
	value = "infinity";
	break;
    }
    http_add_request_header(req, "Depth", value);
}

/* Dispatch a DAV request and handle a 207 error response appropriately */
int dav_simple_request(http_session *sess, http_req *req)
{
    int ret;
    http_content_type ctype = {0};
    struct context ctx = {0};
    dav_207_parser *p207;
    hip_xml_parser *p;
    
    p = hip_xml_create();
    p207 = dav_207_create(p, &ctx);
    /* The error string is progressively written into the
     * sbuffer by the element callbacks */
    ctx.buf = sbuffer_create();

    dav_207_set_response_handlers(p207, start_response, end_response);
    dav_207_set_propstat_handlers(p207, NULL, end_propstat);
    
    http_add_response_body_reader(req, dav_accept_207, hip_xml_parse_v, p);
    http_add_response_header_handler(req, "Content-Type", 
				      http_content_type_handler, &ctype);

    dav_207_ignore_unknown(p207);

    ret = http_request_dispatch(req);

    if (ret == HTTP_OK) {
	if (http_get_status(req)->code == 207) {
	    if (!hip_xml_valid(p)) { 
		/* The parse was invalid */
		http_set_error(sess, hip_xml_get_error(p));
		ret = HTTP_ERROR;
	    } else if (ctx.is_error) {
		/* If we've actually got any error information
		 * from the 207, then set that as the error */
		http_set_error(sess, sbuffer_data(ctx.buf));
		ret = HTTP_ERROR;
	    }
	} else if (http_get_status(req)->klass != 2) {
	    ret = HTTP_ERROR;
	}
    }

    HTTP_FREE(ctype.value);
    dav_207_destroy(p207);
    hip_xml_destroy(p);
    sbuffer_destroy(ctx.buf);
    HTTP_FREE(ctx.href);

    http_request_destroy(req);

    return ret;
}
    
static int copy_or_move(http_session *sess, int is_move, int overwrite,
			const char *src, const char *dest ) 
{
    http_req *req = http_request_create( sess, is_move?"MOVE":"COPY", src );

#ifdef USE_DAV_LOCKS
    if (is_move) {
	dav_lock_using_resource(req, src, DAV_DEPTH_INFINITE);
    }
    dav_lock_using_resource(req, dest, DAV_DEPTH_INFINITE);
    /* And we need to be able to add members to the destination's parent */
    dav_lock_using_parent(req, dest);
#endif

    http_print_request_header(req, "Destination", "%s://%s%s", 
			      http_get_scheme(sess), 
			      http_get_server_hostport(sess), dest);
    
    http_add_request_header(req, "Overwrite", overwrite?"T":"F");

    return dav_simple_request(sess, req);
}

int dav_copy(http_session *sess, int overwrite, 
	     const char *src, const char *dest) 
{
    return copy_or_move(sess, 0, overwrite, src, dest);
}

int dav_move(http_session *sess, int overwrite,
	     const char *src, const char *dest) 
{
    return copy_or_move(sess, 1, overwrite, src, dest);
}

/* Deletes the specified resource. (and in only two lines of code!) */
int dav_delete(http_session *sess, const char *uri) 
{
    http_req *req = http_request_create(sess, "DELETE", uri);

#ifdef USE_DAV_LOCKS
    dav_lock_using_resource(req, uri, DAV_DEPTH_INFINITE);
    dav_lock_using_parent(req, uri);
#endif
    
    /* joe: I asked on the DAV WG list about whether we might get a
     * 207 error back from a DELETE... conclusion, you shouldn't if
     * you don't send the Depth header, since we might be an HTTP/1.1
     * client and a 2xx response indicates success to them.  But
     * it's all a bit unclear. In any case, DAV servers today do
     * return 207 to DELETE even if we don't send the Depth header.
     * So we handle 207 errors appropriately. */

    return dav_simple_request(sess, req);
}

int dav_mkcol(http_session *sess, const char *uri) 
{
    http_req *req;
    char *real_uri;
    int ret;

    if (uri_has_trailing_slash(uri)) {
	real_uri = ne_strdup(uri);
    } else {
	CONCAT2(real_uri, uri, "/");
    }

    req = http_request_create(sess, "MKCOL", real_uri);

#ifdef USE_DAV_LOCKS
    dav_lock_using_resource(req, real_uri, 0);
    dav_lock_using_parent(req, real_uri);
#endif
    
    ret = dav_simple_request(sess, req);

    free(real_uri);

    return ret;
}
