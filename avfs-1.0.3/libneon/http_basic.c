/* 
   HTTP/1.1 methods
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

#include <sys/types.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <errno.h>

#include "http_request.h"
#include "http_basic.h"
#ifdef USE_DAV_LOCKS
#include "dav_locks.h"
#endif
#include "dates.h"
#include "nsocket.h"
#include "neon_i18n.h"
#include "ne_alloc.h"

/* Header parser to retrieve Last-Modified date */
static void get_lastmodified(void *userdata, const char *value) {
    time_t *modtime = userdata;
    *modtime = http_dateparse(value);
}

int http_getmodtime(http_session *sess, const char *uri, time_t *modtime) 
{
    http_req *req = http_request_create(sess, "HEAD", uri);
    int ret;

    http_add_response_header_handler(req, "Last-Modified", get_lastmodified,
				     modtime);

    *modtime = -1;

    ret = http_request_dispatch(req);

    if (ret == HTTP_OK && http_get_status(req)->klass != 2) {
	*modtime = -1;
	ret = HTTP_ERROR;
    }

    http_request_destroy(req);

    return ret;
}

/* PUT's stream to URI */
int http_put(http_session *sess, const char *uri, FILE *stream) 
{
    http_req *req = http_request_create(sess, "PUT", uri);
    int ret;
    
#ifdef USE_DAV_LOCKS
    dav_lock_using_resource(req, uri, 0);
    dav_lock_using_parent(req, uri);
#endif

    http_set_request_body_stream(req, stream);
	
    ret = http_request_dispatch(req);
    
    if (ret == HTTP_OK && http_get_status(req)->klass != 2)
	ret = HTTP_ERROR;

    http_request_destroy(req);

    return ret;
}

/* Conditional HTTP put. 
 * PUTs stream to uri, returning HTTP_FAILED if resource as URI has
 * been modified more recently than 'since'.
 */
int 
http_put_if_unmodified(http_session *sess, const char *uri, 
			FILE *stream, time_t since) {
    http_req *req;
    char *date;
    int ret;
    
    if (http_version_pre_http11(sess)) {
	time_t modtime;
	/* Server is not minimally HTTP/1.1 compliant.  Do a HEAD to
	 * check the remote mod time. Of course, this makes the
	 * operation very non-atomic, but better than nothing. */
	ret = http_getmodtime(sess, uri, &modtime);
	if (ret != HTTP_OK) return ret;
	if (modtime != since)
	    return HTTP_FAILED;
    }

    req = http_request_create(sess, "PUT", uri);

    date = rfc1123_date(since);
    /* Add in the conditionals */
    http_add_request_header(req, "If-Unmodified-Since", date);
    free(date);
    
#ifdef USE_DAV_LOCKS
    dav_lock_using_resource(req, uri, 0);
    /* FIXME: this will give 412 if the resource doesn't exist, since
     * PUT may modify the parent... does that matter?  */
#endif

    http_set_request_body_stream(req, stream);

    ret = http_request_dispatch(req);
    
    if (ret == HTTP_OK) {
	if (http_get_status(req)->code == 412) {
	    ret = HTTP_FAILED;
	} else if (http_get_status(req)->klass != 2) {
	    ret = HTTP_ERROR;
	}
    }

    http_request_destroy(req);

    return ret;
}

struct get_context {
    int error;
    size_t total, progress;
    http_block_reader callback; /* used in read_file */
    FILE *file; /* used in get_to_fd */
    http_content_range *range;
    void *userdata;
};

static void get_callback(void *userdata, const char *block, size_t length) 
{
    struct get_context *ctx = userdata;

    DEBUG(DEBUG_HTTP, "Got progress: %d out of %d\n", 
	   ctx->progress, ctx->total);

    (*ctx->callback)(ctx->userdata, block, length);

    /* Increase progress */
    ctx->progress += length;
    if (ctx->progress > ctx->total) {
	/* Reset the counter if we're uploading it again */
	ctx->progress -= ctx->total;
    }
    sock_call_progress(ctx->progress, ctx->total);
}

int http_read_file(http_session *sess, const char *uri, 
		   http_block_reader reader, void *userdata) {
    struct get_context ctx;
    http_req *req = http_request_create(sess, "GET", uri);
    int ret;
    
    ctx.total = -1;
    ctx.progress = 0;
    ctx.callback = reader;
    ctx.userdata = userdata;

    /* Read the value of the Content-Length header into ctx.total */
    http_add_response_header_handler(req, "Content-Length",
				     http_handle_numeric_header,
				     &ctx.total);
    
    http_add_response_body_reader(req, http_accept_2xx, get_callback, &ctx);

    ret = http_request_dispatch(req);

    if (ret == HTTP_OK && http_get_status(req)->klass != 2)
	ret = HTTP_ERROR;

    http_request_destroy(req);

    return ret;
}

static void get_to_fd(void *userdata, const char *block, size_t length)
{
    struct get_context *ctx = userdata;
    FILE *f = ctx->file;
    size_t ret;
    if (!ctx->error) {
	while (length > 0) {
	    ret = fwrite(block, 1, length, f);
	    if (ret < 0) {
		ctx->error = errno;
		break;
	    } else {
		length -= ret;
	    }
	}
    }
}

static int accept_206(void *ud, http_req *req, http_status *st)
{
    return (st->code == 206);
}

static void clength_hdr_handler(void *ud, const char *value)
{
    struct get_context *ctx = ud;
    off_t len = strtol(value, NULL, 10);
    
    if (ctx->range->end == -1) {
	ctx->range->end = ctx->range->start + len;
    }
    else if (len != (ctx->range->end - ctx->range->start)) {
	DEBUG(DEBUG_HTTP, "Expecting %ld bytes, got entity of length %ld\n", 
	      (long int) (ctx->range->end - ctx->range->start), 
	      (long int) len);
	ctx->error = 1;
    }
}

static void content_range_hdr_handler(void *ud, const char *value)
{
    struct get_context *ctx = ud;

    if (strncmp(value, "bytes ", 6) != 0) {
	ctx->error = 1;
    }
}

int http_get_range(http_session *sess, const char *uri, 
		   http_content_range *range, FILE *f)
{
    http_req *req = http_request_create(sess, "GET", uri);
    struct get_context ctx;
    int ret;

    if (range->end == -1) {
	ctx.total = -1;
    } 
    else {
	ctx.total = range->end - range->start;
    }

    ctx.progress = 0;
    ctx.callback = get_to_fd;
    ctx.userdata = &ctx;
    ctx.file = f;
    ctx.error = 0;
    ctx.range = range;

    http_add_response_header_handler(req, "Content-Length",
				     clength_hdr_handler, &ctx);
    http_add_response_header_handler(req, "Content-Range",
				     content_range_hdr_handler,
				     &ctx);

    http_add_response_body_reader(req, accept_206, get_callback, &ctx);

    /* icky casts to long int, which should be at least as large as the
     * off_t's */
    if (range->end == -1) {
	http_print_request_header(req, "Range", "bytes=%ld-", 
				  (long int) range->start);
    }
    else {
	http_print_request_header(req, "Range", "bytes=%ld-%ld",
				  (long int) range->start, 
				  (long int)range->end);
    }
    http_add_request_header(req, "Accept-Ranges", "bytes");

    ret = http_request_dispatch(req);
    
    if (ret == HTTP_OK && http_get_status(req)->klass != 2) {
	ret = HTTP_ERROR;
    }
    else if (http_get_status(req)->code != 206) {
	http_set_error(sess, _("Server does not allow partial GETs."));
	ret = HTTP_ERROR;
    }
    
    http_request_destroy(req);

    return ret;
}


/* Get to given stream */
int http_get(http_session *sess, const char *uri, FILE *f)
{
    http_req *req = http_request_create(sess, "GET", uri);
    struct get_context ctx;
    int ret;

    ctx.total = -1;
    ctx.progress = 0;
    ctx.callback = get_to_fd;
    ctx.userdata = &ctx;
    ctx.file = f;
    ctx.error = 0;

    /* Read the value of the Content-Length header into ctx.total */
    http_add_response_header_handler(req, "Content-Length",
				     http_handle_numeric_header,
				     &ctx.total);
    
    http_add_response_body_reader(req, http_accept_2xx, get_callback, &ctx);

    ret = http_request_dispatch(req);
    
    if (ctx.error) {
	char buf[BUFSIZ];
	snprintf(buf, BUFSIZ, 
		  _("Could not write to file: %s"), strerror(ctx.error));
	http_set_error(sess, buf);
	ret = HTTP_ERROR;
    }

    if (ret == HTTP_OK && http_get_status(req)->klass != 2) {
	ret = HTTP_ERROR;
    }

    http_request_destroy(req);

    return ret;
}


/* Get to given stream */
int http_post(http_session *sess, const char *uri, FILE *f, const char *buffer)
{
    http_req *req = http_request_create(sess, "POST", uri);
    struct get_context ctx;
    int ret;

    ctx.total = -1;
    ctx.progress = 0;
    ctx.callback = get_to_fd;
    ctx.userdata = &ctx;
    ctx.file = f;
    ctx.error = 0;

    /* Read the value of the Content-Length header into ctx.total */
    http_add_response_header_handler(req, "Content-Length",
				     http_handle_numeric_header, &ctx.total);

    http_add_response_body_reader(req, http_accept_2xx, get_callback, &ctx);

    http_set_request_body_buffer(req, buffer);

    ret = http_request_dispatch(req);
    
    if (ctx.error) {
	char buf[BUFSIZ];
	snprintf(buf, BUFSIZ, 
		 _("Could not write to file: %s"), strerror(ctx.error));
	http_set_error(sess, buf);
	ret = HTTP_ERROR;
    }

    if (ret == HTTP_OK && http_get_status(req)->klass != 2) {
	ret = HTTP_ERROR;
    }

    http_request_destroy(req);

    return ret;
}

static void server_hdr_handler(void *userdata, const char *value)
{
    char **tokens = split_string(value, ' ', HTTP_QUOTES, NULL);
    http_server_capabilities *caps = userdata;
    int n;

    for (n = 0; tokens[n] != NULL; n++) {
	if (strncasecmp(tokens[n], "Apache/", 7) == 0 && 
	    strlen(tokens[n]) > 11) { /* 12 == "Apache/1.3.0" */
	    const char *ver = tokens[n] + 7;
	    int count;
	    char **vers;
	    vers = split_string_c(ver, '.', NULL, NULL, &count);
	    /* Apache/1.3.6 and before have broken Expect: 100 support */
	    if (count > 1 && atoi(vers[0]) < 2 && 
		atoi(vers[1]) < 4 && atoi(vers[2]) < 7) {
		caps->broken_expect100 = 1;
	    }
	    split_string_free(vers);
	}
    }    
    
    split_string_free(tokens);
}

void http_content_type_handler(void *userdata, const char *value)
{
    http_content_type *ct = userdata;
    char *sep, *parms;

    ct->value = ne_strdup(value);
    
    sep = strchr(ct->value, '/');
    if (!sep) {
	HTTP_FREE(ct->value);
	return;
    }

    *++sep = '\0';
    ct->type = ct->value;
    ct->subtype = sep;
    
    parms = strchr(ct->value, ';');

    if (parms) {
	*parms = '\0';
	/* TODO: handle charset. */
    }
}

static void dav_hdr_handler(void *userdata, const char *value)
{
    char **classes, **class;
    http_server_capabilities *caps = userdata;
    
    classes = split_string(value, ',', HTTP_QUOTES, HTTP_WHITESPACE);
    for (class = classes; *class!=NULL; class++) {

	if (strcmp(*class, "1") == 0) {
	    caps->dav_class1 = 1;
	} else if (strcmp(*class, "2") == 0) {
	    caps->dav_class2 = 1;
	} else if (strcmp(*class, "<http://apache.org/dav/propset/fs/1>") == 0) {
	    caps->dav_executable = 1;
	}
    }
    
    split_string_free(classes);

}

int http_options(http_session *sess, const char *uri,
		  http_server_capabilities *caps)
{
    http_req *req = http_request_create(sess, "OPTIONS", uri);
    
    int ret;

    http_add_response_header_handler(req, "Server", server_hdr_handler, caps);
    http_add_response_header_handler(req, "DAV", dav_hdr_handler, caps);

    ret = http_request_dispatch(req);
 
    if (ret == HTTP_OK && http_get_status(req)->klass != 2) {
	ret = HTTP_ERROR;
    }
    
    http_request_destroy(req);

    return ret;
}
