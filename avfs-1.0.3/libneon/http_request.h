/* 
   HTTP Request Handling
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

#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include <stdio.h> /* For FILE * */

#include "http_utils.h" /* For http_status */
#include "string_utils.h" /* For sbuffer */
#include "nsocket.h" /* for nssl_context */

BEGIN_NEON_DECLS

#define HTTP_OK (0)
#define HTTP_ERROR (1) /* Generic error; use http_get_error(session) for message */
#define HTTP_LOOKUP (3) /* Name lookup failed */
#define HTTP_AUTH (4) /* User authentication failed on server */
#define HTTP_AUTHPROXY (5) /* User authentication failed on proxy */
#define HTTP_SERVERAUTH (6) /* Server authentication failed */
#define HTTP_PROXYAUTH (7) /* Proxy authentication failed */
#define HTTP_CONNECT (8) /* Could not connect to server */
#define HTTP_TIMEOUT (9) /* Connection timed out */
#define HTTP_FAILED (10) /* The precondition failed */

/* Internal use only */
#define HTTP_RETRY (101)

#define EOL "\r\n"

/****** Session Handling ******/

typedef struct http_session_s http_session;
typedef struct http_req_s http_req;

/* 
 * Session handling:
 *  Call order:
 *  0.   sock_init             MANDATORY
 *  1.   http_session_create   MANDATORY
 *  2.   http_session_proxy    OPTIONAL
 *  3.   http_session_server   MANDATORY
 *  4.   http_set_*            OPTIONAL
 *  ...  --- Any HTTP request method ---
 *  n.   http_session_destroy  MANDATORY
 */
 
/* Create a new HTTP session */
http_session *http_session_create(void);

/* Finish an HTTP session */
int http_session_destroy(http_session *sess);

/* Set the server or proxy server to be used for the session.
 * Returns:
 *   HTTP_LOOKUP if the DNS lookup for hostname failed.
 *   HTTP_OK otherwise.
 *
 * Note that if a proxy is being used, http_session_proxy should be
 * called BEFORE http_session_server, so the DNS lookup can be skipped
 * on the server. */
int http_session_server(http_session *sess, const char *hostname, int port);
int http_session_proxy(http_session *sess, const char *hostname, int port);

/* Callback to determine whether the proxy server should be used or
 * not for a request to the given hostname using the given scheme.
 * Scheme will be "http" or "https" etc.
 * Must return:
 *   Zero to indicate the proxy should NOT be used
 *   Non-zero to indicate the proxy SHOULD be used.
 */
typedef int (*http_use_proxy)(void *userdata,
			      const char *scheme, const char *hostname);

/* Register the callback for determining whether the proxy server
 * should be used or not here.  'userdata' will be passed as the first
 * argument to the callback. The callback is only called if a proxy
 * server has been set up using http_session_proxy. 
 *
 * This function MUST be called before calling http_session_server.
 */
void http_session_decide_proxy(http_session *sess, http_use_proxy use_proxy,
			       void *userdata);

/* Set protocol options for session:
 *   expect100: Defaults to OFF
 *   persist:   Defaults to ON
 *
 * expect100: When set, send the "Expect: 100-continue" request header
 * with requests with bodies.
 *
 * persist: When set, use a persistent connection. (Generally,
 * you don't want to turn this off.)
 * */
void http_set_expect100(http_session *sess, int use_expect100);
void http_set_persist(http_session *sess, int persist);

/* Using SSL/TLS connections:
 *
 * Session settings:
 *   secure:                 Defaults to OFF
 *   secure_context:         No callbacks, any protocol allowed.
 *   request_secure_upgrade: Defaults to OFF
 *   accept_secure_ugprade:  Defaults to OFF
 *
 * secure_context: When set, specifies the settings to use for secure
 * connections, and any callbacks (see nsocket.h).  The lifetime of
 * the context object must be >= to the lifetime of the session
 * object.
 *
 * secure: When set, use a secure (SSL/TLS) connection to the origin
 * server. This will tunnel (using CONNECT) through the proxy server
 * if one is being used.
 *
 * request_secure_upgrade: When set, notify the server with each
 * request made that an upgrade to a secure connection is desired, if
 * available.
 *
 * accept_secure_upgrade: When set, allow a server-requested upgrade
 * to a secure connection.
 *
 * NB: the latter three function calls will return -1 if SSL is not
 * supported by the library (i.e., it was not built against OpenSSL),
 * or 0 if it is.
 * */
void http_set_secure_context(http_session *sess, nssl_context *ctx);
int http_set_secure(http_session *sess, int secure);
int http_set_request_secure_upgrade(http_session *sess, int req_upgrade);
int http_set_accept_secure_upgrade(http_session *sess, int acc_upgrade);

/* Sets the user-agent string. neon/VERSION will be appended, to make
 * the full header "User-Agent: product neon/VERSION".
 * If this function is not called, the User-Agent header is not sent.
 * The product string must follow the RFC2616 format, i.e.
 *       product         = token ["/" product-version]
 *       product-version = token
 * where token is any alpha-numeric-y string [a-zA-Z0-9]*
 */
void http_set_useragent(http_session *sess, const char *product);

/* Determine if next-hop server claims HTTP/1.1 compliance. Returns:
 *   0 if next-hop server does NOT claim HTTP/1.1 compliance
 *   non-zero if next-hop server DOES claim HTTP/1.1 compliance
 * Not that the "next-hop" server is the proxy server if one is being
 * used, otherwise, the origin server.
 */
int http_version_pre_http11(http_session *sess);

/* Returns the 'hostport' URI segment for the end-server, e.g.
 *    "my.server.com:8080"    or    "www.server.com" 
 *  (port segment is ommitted if == 80) 
 */
const char *http_get_server_hostport(http_session *sess);

/* Returns the URL scheme being used for the current session.
 * Does NOT include a trailing ':'. 
 * Example returns: "http" or "https".
 */
const char *http_get_scheme(http_session *sess);

#if 0 /* TODO: implement */
typedef int (*http_request_redirect)(void *userdata, 
				     int code, const char *reason,
				     const char *from_uri, const char *to_uri);

void http_set_redirect_handler(http_session *sess, 
			       http_request_redirect hdlr, void *userdata); 
#endif

/* The callback used to request the username and password in the given
 * realm. The username and password must be placed in malloc()-allocated
 * memory.
 * Must return:
 *   0 on success: *username and *password must be non-NULL, and will
 *                 be free'd by the HTTP layer when necessary
 *  -1 to cancel (*username and *password are ignored.)
 */
typedef int (*http_request_auth)(
    void *userdata, const char *realm, const char *hostname,
    char **username, char **password);

/* Set callbacks to handle server and proxy authentication.
 * userdata is passed as the first argument to the callback. */
void http_set_server_auth(http_session *sess, http_request_auth callback, 
			  void *userdata);
void http_set_proxy_auth(http_session *sess, http_request_auth callback, 
			 void *userdata);

/* Set the error string for the session */
void http_set_error(http_session *sess, const char *errstring);
/* Retrieve the error string for the session */
const char *http_get_error(http_session *sess);

/**** Request hooks handling *****/

typedef struct {
    /* A slight hack? Allows access to the hook private information,
     * externally... */
    const char *id; /* id could be a URI to be globally unique */
    /* e.g. "http://webdav.org/neon/hooks/davlock" */
    
    /* Register a new request: return value passed to subsequent
     * handlers as '_private'. Session cookie passed as 'session'. */
    void *(*create)(void *cookie, http_req *req, 
		    const char *method, const char *uri);
    /* Tell them what request body we are using: either buffer or stream
     * will be non-NULL. */
    void (*use_body)(void *_private, const char *buffer, FILE *stream);
    /* Just before sending the request: let them add headers if they want */
    void (*pre_send)(void *_private, sbuffer request);
    /* After sending the request. May return:
     *  HTTP_OK     everything is okay
     *  HTTP_RETRY  try sending the request again */
    int (*post_send)(void *_private, const http_status *status);
    /* Clean up after yourself. */
    void (*destroy)(void *_private);
} http_request_hooks;

/* Add in hooks */
void http_add_hooks(http_session *sess, 
		    const http_request_hooks *hooks, void *cookie);

/* Return private data for a new request */ 
void *http_get_hook_private(http_req *req, const char *id);

/***** Request Handling *****/

/* Create a new request, with given method and URI. 
 * Returns request pointer. */
http_req *
http_request_create(http_session *sess, const char *method, const char *uri);

/* 'buffer' will be sent as the request body with given request. */
void http_set_request_body_buffer(http_req *req, const char *buffer);
/* Contents of stream will be sent as the request body with the given
 * request */
void http_set_request_body_stream(http_req *req, FILE *stream);

/* Handling response bodies... you provide TWO callbacks:
 *
 * 1) 'acceptance' callback: determines whether you want to handle the
 * response body given the response-status information, e.g., if you
 * only want 2xx responses, say so here.
 *
 * 2) 'reader' callback: passed blocks of the response-body as they
 * arrive, if the acceptance callback returned non-zero.  */

/* 'acceptance' callback type. Return non-zero to accept the response,
 * else zero to ignore it. */
typedef int (*http_accept_response)(
    void *userdata, http_req *req, http_status *st);

/* An 'acceptance' callback which only accepts 2xx-class responses.
 * Ignores userdata. */
int http_accept_2xx(void *userdata, http_req *req, http_status *st);

/* The 'reader' callback type */
typedef void (*http_block_reader)(
    void *userdata, const char *buf, size_t len);

/* Add a response reader for the given request, with the given
 * acceptance function. userdata is passed as the first argument to
 * the acceptance + reader callbacks. */
void http_add_response_body_reader(http_req *req, http_accept_response accpt,
				   http_block_reader rdr, void *userdata);

/* Handle response headers. Each handler is associated with a specific
 * header field (indicated by name). The handler is then passed the
 * value of this header field. */

/* The header handler callback type */
typedef void (*http_header_handler)(void *userdata, const char *value);

/* Adds a response header handler for the given request. userdata is passed
 * as the first argument to the header handler, and the 'value' is the
 * header field value (i.e. doesn't include the "Header-Name: " part").
 */
void http_add_response_header_handler(http_req *req, const char *name, 
				      http_header_handler hdl, void *userdata);

/* Add handler which is passed ALL header values regardless of name */
void http_add_response_header_catcher(http_req *req, 
				      http_header_handler hdl, void *userdata);

/* Stock header handlers:
 *  'duplicate': *(char **)userdata = strdup(value)
 *  'numeric':   *(int *)userdata = atoi(value)
 * e.g.
 *   int mynum;
 *   http_add_response_header_handler(myreq, "Content-Length",
 *                                    http_handle_numeric_handler, &mynum);
 * ... arranges mynum to be set to the value of the Content-Length header.
 */
void http_duplicate_header(void *userdata, const char *value);
void http_handle_numeric_header(void *userdata, const char *value);

/* Adds a header to the request with given name and value. */
void http_add_request_header(http_req *req, const char *name, 
			     const char *value);
/* Adds a header to the request with given name, using printf-like
 * format arguments for the value. */
void http_print_request_header(http_req *req, const char *name,
			       const char *format, ...)
#ifdef __GNUC__
                __attribute__ ((format (printf, 3, 4)))
#endif /* __GNUC__ */
;

sbuffer http_get_request_headers(http_req *req);

/* http_request_dispatch: Sends the given request, and reads the
 * response. Response-Status information can be retrieve with
 * http_get_status(req).
 *
 * Returns:
 *  HTTP_OK         if request sent + response read okay.
 *  HTTP_AUTH       if user authentication failed on origin server
 *  HTTP_AUTHPROXY  if user authentication failed on proxy server
 *  HTTP_SERVERAUTH server authentication failed
 *  HTTP_PROXYAUTH  proxy authentication failed
 *  HTTP_CONNECT    could not connect to server/proxy server
 *  HTTP_TIMEOUT    connection timed out mid-request
 *  HTTP_ERROR      for other errors, and http_get_error() should
 *                  return a meaningful error string
 *
 * NB: HTTP_AUTH and HTTP_AUTHPROXY mean that the USER supplied the
 * wrong username/password.  SERVER/PROXYAUTH mean that, after the
 * server has accepted a valid username/password, the server/proxy did
 * not authenticate the response message correctly.
 * */
int http_request_dispatch(http_req *req);

/* Returns a pointer to the response status information for the
 * given request. */
const http_status *http_get_status(http_req *req)

/* Declare this with attribute const, since we often call it >1 times
 * with the same argument, and it will return the same thing each
 * time. This lets the compiler optimize away any subsequent calls
 * (theoretically).  */
#ifdef __GNUC__
                __attribute__ ((const))
#endif /* __GNUC__ */
    ;

/* Destroy memory associated with request pointer */
void http_request_destroy(http_req *req);

END_NEON_DECLS

#endif /* HTTP_REQUEST_H */

