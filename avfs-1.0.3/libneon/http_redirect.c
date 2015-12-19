/* 
   HTTP-redirect support
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
#include "ne_alloc.h"
#include "http_private.h"
#include "http_redirect.h"
#include "uri.h"
#include "neon_i18n.h"

struct redirect {
    char *location;
    http_req *req;
    http_redirect_confirm confirm;
    http_redirect_notify notify;
    void *userdata;
};

static void *create(void *session, http_req *req, 
		    const char *method, const char *uri);
static int post_send(void *private, const http_status *status);
static void destroy(void *private);

http_request_hooks redirect_hooks = {
    "http://www.webdav.org/neon/hooks/http-redirect",
    create,
    NULL,
    NULL,
    post_send,
    destroy
};

static void *
create(void *session, http_req *req, const char *method, const char *uri)
{
    struct redirect *red = session;
    
    /* for handling 3xx redirects */
    http_add_response_header_handler(req, "Location",
				     http_duplicate_header, &red->location);

    red->req = req;

    return red;
}

/* 2616 says we can't auto-redirect if the method is not GET or HEAD.
 * We extend this to PROPFIND too, which violates a 2616 MUST, but
 * is following the spirit of the spec, I think. */
static int auto_redirect(struct redirect *red)
{
    return (red->req->method_is_head ||
	    strcasecmp(red->req->method, "GET") == 0 || 
	    strcasecmp(red->req->method, "PROPFIND") == 0);
}

static int post_send(void *private, const http_status *status)
{
    struct redirect *red = private;
    struct uri uri;

    if ((status->code != 302 && status->code != 301) ||
	red->location == NULL) {
	/* Nothing to do. */
	return HTTP_OK;
    }
    
    if (uri_parse(red->location, &uri, NULL)) {
	/* Couldn't parse the URI */
	http_set_error(red->req->session, 
		       _("Could not parse redirect location."));
	return HTTP_ERROR;
    }
    
    
    if (auto_redirect(red)) {
	if (red->notify != NULL) {
	    (*red->notify)(red->userdata, red->req->abs_path, uri.path);
	}
    } else {
	/* Need user-confirmation to follow the redirect */
	if (red->confirm == NULL || 
	    !(*red->confirm)(red->userdata, red->req->abs_path, uri.path)) {
	    return HTTP_OK;
	}
    }
    
    red->req->abs_path = ne_strdup(uri.path);

    /* Set red->req->uri and new host/port for the session, if necessary */
    
    HTTP_FREE(red->req->uri);
    if (red->req->use_proxy)
	red->req->uri = ne_strdup(red->location);
    else
	red->req->uri = ne_strdup(red->req->abs_path);
    
    if (uri.host != NULL && 
	strcasecmp(uri.host, red->req->session->server.hostname) != 0) {
	/* Handle redirecting to another host. */
	
	if (uri.port <= 0)
	    uri.port = HTTP_PORT;
	
	/* FIXME: shouldn't do this here.  Let the caller control
           this.  */
	http_session_server(red->req->session, uri.host, uri.port);
    }

    /* FIXME: need to uri_free here (the above http_session_server()
     * call prevents this at the moment). */
    
    return HTTP_RETRY;
}

static void destroy(void *private)
{
    struct redirect *red = private;
    HTTP_FREE(red->location);
}

void http_redirect_register(http_session *sess, 
			    http_redirect_confirm confirm,
			    http_redirect_notify notify,
			    void *userdata)
{
    struct redirect *red = ne_calloc(sizeof *red);
    
    red->confirm = confirm;
    red->notify = notify;
    red->userdata = userdata;
    
    http_add_hooks(sess, &redirect_hooks, red);
}
