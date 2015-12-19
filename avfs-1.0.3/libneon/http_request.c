/* 
   HTTP request/response handling
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

/* This is the HTTP client request/response implementation.
 * The goal of this code is to be modular and simple.
 */

/* TODO:
 *  - Move authentication into a hook
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifdef __EMX__
#include <sys/select.h>
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h> /* just for Win32? */
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif 
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_SNPRINTF_H
#include "snprintf.h"
#endif

#include <ctype.h>

#include "neon_i18n.h"

#include "ne_alloc.h"
#include "http_request.h"
#include "http_auth.h"
#include "nsocket.h"
#include "string_utils.h" /* for sbuffer */
#include "http_utils.h"
#include "uri.h"
#include "http_private.h"

#define HTTP_PORT 80

#define HTTP_EXPECT_TIMEOUT 15
/* 100-continue only used if size > HTTP_EXPECT_MINSIZ */
#define HTTP_EXPECT_MINSIZE 1024

#define HTTP_VERSION_PRE11(s) \
((s)->version_major<1 || ((s)->version_major==1 && (s)->version_minor<1))

#define HTTP_MAXIMUM_HEADER_LENGTH 8192

#define NEON_USERAGENT "neon/" NEON_VERSION;

static void te_hdr_handler(void *userdata, const char *value);
static void connection_hdr_handler(void *userdata, const char *value);

static void set_hostinfo(struct host_info *info, const char *hostname, int port);
static int lookup_host(struct host_info *info);

static int open_connection(http_req *req);
static int close_connection(http_session *req);

static int set_sockerr(http_req *req, const char *doing, int sockerr);

static char *get_hostport(struct host_info *host);
static void add_fixed_headers(http_req *req);
static int get_request_bodysize(http_req *req);

static int send_request_body(http_req *req);
static void build_request(http_req *req, sbuffer buf);
static int read_message_header(http_req *req, sbuffer buf, char *extra);
static int read_response_block(http_req *req, struct http_response *resp,
				char *buffer, size_t *buflen);
static int read_response_body(http_req *req);

/* The iterative step used to produce the hash value.  This is DJB's
 * magic "*33" hash function.  Ralf Engelschall has done some amazing
 * statistical analysis to show that *33 really is a good hash
 * function: check the new-httpd list archives, or his 'str' library
 * source code, for the details.
 *
 * TODO: due to limited range of characters used in header names,
 * could maybe get a better hash function to use? */
 
#define HH_ITERATE(hash, char) (((hash)*33 + char) % HH_HASHSIZE);

/* Produce the hash value for a header name, which MUST be in lower
 * case.  */
static unsigned int hdr_hash(const char *name)
{
    const char *pnt;
    unsigned int hash = 0;

    for (pnt = name; *pnt != '\0'; pnt++) {
	hash = HH_ITERATE(hash,*pnt);
    }

    return hash;
}

/* Initializes an HTTP session */
http_session *http_session_create(void) 
{
    http_session *sess = ne_calloc(sizeof *sess);

    DEBUG(DEBUG_HTTP, "HTTP session begins.\n");
    strcpy(sess->error, "Unknown error.");
    sess->version_major = -1;
    sess->version_minor = -1;
    /* Default expect-100 to OFF. */
    sess->expect100_works = -1;
    return sess;
}

static char *lower_string(const char *str)
{
    char *ret = ne_malloc(strlen(str) + 1), *pnt;
    
    for (pnt = ret; *str != '\0'; str++) {
	*pnt++ = tolower(*str);
    }
    
    *pnt = '\0';

    return ret;
}

static void
set_hostinfo(struct host_info *info, const char *hostname, int port)
{
    HTTP_FREE(info->hostport);
    HTTP_FREE(info->hostname);
    info->hostname= ne_strdup(hostname);
    info->port = port;
    info->hostport = get_hostport(info);
    http_auth_init(&info->auth);
}

static int lookup_host(struct host_info *info)
{
    if (sock_name_lookup(info->hostname, &info->addr)) {
	return HTTP_LOOKUP;
    } else {
	return HTTP_OK;
    }
}

int http_version_pre_http11(http_session *sess)
{
    return HTTP_VERSION_PRE11(sess);
}

int http_session_server(http_session *sess, const char *hostname, int port)
{
    if (sess->connected && !sess->have_proxy) {
	/* Reconnect */
	close_connection(sess);
    }
    set_hostinfo(&sess->server, hostname, port);
    /* We do a name lookup on the origin server if either:
     *  1) we do not have a proxy server
     *  2) we *might not* have a proxy server (since we have a 'proxy decider' function).
     */
    if (!sess->have_proxy || sess->proxy_decider) {
	return lookup_host(&sess->server);
    } else {
	return HTTP_OK;
    }
}

void http_set_secure_context(http_session *sess, nssl_context *ctx)
{
    sess->ssl_context = ctx;
}

int http_set_request_secure_upgrade(http_session *sess, int req_upgrade)
{
#ifdef ENABLE_SSL
    sess->request_secure_upgrade = req_upgrade;
    return 0;
#else
    return -1;
#endif
}

int http_set_accept_secure_upgrade(http_session *sess, int acc_upgrade)
{
#ifdef ENABLE_SSL
    sess->accept_secure_upgrade = acc_upgrade;
    return 0;
#else
    return -1;
#endif
}

int http_set_secure(http_session *sess, int use_secure)
{
#ifdef ENABLE_SSL
    sess->use_secure = use_secure;
    return 0;
#else
    return -1;
#endif
}

void http_session_decide_proxy(http_session *sess, http_use_proxy use_proxy,
			       void *userdata)
{
    sess->proxy_decider = use_proxy;
    sess->proxy_decider_udata = userdata;
}

int http_session_proxy(http_session *sess, const char *hostname, int port)
{
    if (sess->connected) {
	/* Reconnect */
	close_connection(sess);
    }
    sess->have_proxy = 1;
    set_hostinfo(&sess->proxy, hostname, port);
    return lookup_host(&sess->proxy);
}

void http_set_server_auth(http_session *sess, 
			  http_request_auth callback, void *userdata)
{
    sess->server.auth_callback = callback;
    sess->server.auth_userdata = userdata;
}

/* Set callback to handle proxy authentication */
void http_set_proxy_auth(http_session *sess, 
			 http_request_auth callback, void *userdata)
{
    sess->proxy.auth_callback = callback;
    sess->proxy.auth_userdata = userdata;
}

void http_set_error(http_session *sess, const char *errstring)
{
    strncpy(sess->error, errstring, BUFSIZ);
    sess->error[BUFSIZ-1] = '\0';
    STRIP_EOL(sess->error);
}

const char *http_get_error(http_session *sess) {
    return sess->error;
}

/* Give authentication credentials */
static int give_creds(void *udata, const char *realm,
		      char **username, char **password) 
{ 
    http_req *req = udata;
    http_session *sess = req->session;
    if (req->status.code == 407 && req->use_proxy && sess->proxy.auth_callback) {
	return (*sess->proxy.auth_callback)(
	    sess->proxy.auth_userdata, realm, sess->proxy.hostname,
	    username, password);
    } else if (req->status.code == 401 && sess->server.auth_callback) {
	return (*sess->server.auth_callback)( 
	    sess->server.auth_userdata, realm, sess->server.hostname,
	    username, password);
    }
    return -1;
}

void http_duplicate_header(void *userdata, const char *value)
{
    char **location = userdata;
    *location = ne_strdup(value);
}

void http_handle_numeric_header(void *userdata, const char *value)
{
    int *location = userdata;
    *location = atoi(value);
}

/* The body reader callback */
static void auth_body_reader(void *userdata, const char *block, size_t length)
{
    http_auth_session *sess = userdata;
    http_auth_response_body(sess, block, length);
}

void http_add_hooks(http_session *sess, 
		    const http_request_hooks *hooks, void *private)
{
    struct hook *hk = ne_malloc(sizeof(struct hook));
    hk->hooks = hooks;
    hk->private = private;
    hk->next = sess->hooks;
    sess->hooks = hk;
}

void *http_get_hook_private(http_req *req, const char *id)
{
    struct hook_request *hk;

    for (hk = req->hook_store; hk != NULL; hk = hk->next) {
	if (strcasecmp(hk->hook->hooks->id, id) == 0) {
	    return hk->cookie;
	}
    }

    return NULL;
}

int http_session_destroy(http_session *sess) 
{
    struct hook *hk;

    DEBUG(DEBUG_HTTP, "http_session_destroy called.\n");
    http_auth_finish(&sess->server.auth);
    if (sess->have_proxy) {
	http_auth_finish(&sess->proxy.auth);
    }
    HTTP_FREE(sess->server.hostname);
    HTTP_FREE(sess->server.hostport);
    HTTP_FREE(sess->proxy.hostport);
    HTTP_FREE(sess->user_agent);

    /* Clear the hooks. */
    hk = sess->hooks;
    while (hk) {
	struct hook *nexthk = hk->next;
	free(hk);
	hk = nexthk;
    }
	
    if (sess->connected) {
	close_connection(sess);
    }

    free(sess);
    return HTTP_OK;
}

/* Sends the body down the socket.
 * Returns 0 on success, or SOCK_* code */
static int send_request_body(http_req *req)
{
    int ret;
    switch (req->body) {
    case body_stream:
	ret = sock_transfer(fileno(req->body_stream), req->session->socket, 
			    req->body_size);
	DEBUG(DEBUG_HTTP, "Sent %d bytes.\n", ret);
	rewind(req->body_stream); /* since we may have to send it again */
	break;
    case body_buffer:
	DEBUG(DEBUG_HTTP, "Sending body:\n%s\n", req->body_buffer);
	ret = sock_send_string(req->session->socket, req->body_buffer);
	DEBUG(DEBUG_HTTP, "sock_send_string returns: %d\n", ret);
	break;
    default:
	ret = 0;
	break;
    }
    if (ret < 0) {
	/* transfer failed */
	req->forced_close = 1;
    }
    return ret;
}

/* Deal with the body size.
 * Returns 0 on success or non-zero on error. */
static int get_request_bodysize(http_req *req) 
{
    struct stat bodyst;
    /* Do extra stuff if we have a body */
    switch(req->body) {
    case body_stream:
	/* Get file length */
	if (fstat(fileno(req->body_stream), &bodyst) < 0) {
	    /* Stat failed */
	    DEBUG(DEBUG_HTTP, "Stat failed: %s\n", strerror(errno));
	    return -1;
	}
	req->body_size = bodyst.st_size;
	break;
    case body_buffer:
	req->body_size = strlen(req->body_buffer);
	break;
    default:
	/* No body, so no size. */
	break;
    }
    if (req->body != body_none) {
	char tmp[BUFSIZ];
	/* Add the body length header */
	snprintf(tmp, BUFSIZ, "Content-Length: %d" EOL, req->body_size);
	sbuffer_zappend(req->headers, tmp);
    } else {
	sbuffer_zappend(req->headers, "Content-Length: 0" EOL);
    }
    return 0;
}

static char *get_hostport(struct host_info *host) 
{
    size_t len = strlen(host->hostname);
    char *ret = ne_malloc(len + 10);
    strcpy(ret, host->hostname);
    if (host->port != HTTP_PORT) {
	snprintf(ret + len, 9, ":%d", host->port);
    }
    return ret;
}

const char *http_get_server_hostport(http_session *sess) {
    return sess->server.hostport;
}

const char *http_get_scheme(http_session *sess)
{
    if (sess->use_secure) {
	return "https";
    } else {
	return "http";
    }
}

/* Lob the User-Agent, connection and host headers in to the request
 * headers */
static void add_fixed_headers(http_req *req) 
{
    if (req->session->user_agent) {
	sbuffer_concat(req->headers, 
			"User-Agent: ", req->session->user_agent, EOL, NULL);
    }
    /* Send Connection: Keep-Alive for pre-1.1 origin servers, so we
     * might get a persistent connection. 2068 sec 19.7.1 says we MUST
     * NOT do this for proxies, though. So we don't.  Note that on the
     * first request on any session, we don't know whether the server
     * is 1.1 compliant, so we presume that it is not. */
    if (HTTP_VERSION_PRE11(req->session) && !req->use_proxy) {
	sbuffer_zappend(req->headers, "Keep-Alive: " EOL);
	sbuffer_zappend(req->headers, "Connection: TE, Keep-Alive");
    } else {
	sbuffer_zappend(req->headers, "Connection: TE");
    }
    if (req->upgrade_to_tls) {
	sbuffer_zappend(req->headers, ", Upgrade");
    }
    sbuffer_zappend(req->headers, EOL);
    if (req->upgrade_to_tls) {
	sbuffer_zappend(req->headers, "Upgrade: TLS/1.0" EOL);
    }
    /* We send TE: trailers since we understand trailers in the chunked
     * response. */
    sbuffer_zappend(req->headers, "TE: trailers" EOL);

}

static int always_accept_response(void *userdata, http_req *req, http_status *st)
{
    return 1;
}				   

int http_accept_2xx(void *userdata, http_req *req, http_status *st)
{
    return (st->klass == 2);
}

/* Initializes the request with given method and URI.
 * URI must be abs_path - i.e., NO scheme+hostname. It will BREAK 
 * otherwise. */
http_req *http_request_create(http_session *sess,
			      const char *method, const char *uri) 
{
    sbuffer real_uri;
    http_req *req = ne_calloc(sizeof(http_req));

    DEBUG(DEBUG_HTTP, "Creating request...\n");

    req->session = sess;
    req->headers = sbuffer_create();
    
    /* Add in the fixed headers */
    add_fixed_headers(req);

    /* Set the standard stuff */
    req->method = method;
    req->method_is_head = (strcmp(req->method, "HEAD") == 0);
    req->body = body_none;
    
    /* FIXME: the proxy_decider is broken if they called
     * http_session_proxy before http_session_server, since in that
     * case we have not done a name lookup on the session server.  */
    if (sess->have_proxy && sess->proxy_decider != NULL) {
	req->use_proxy = 
	    (*sess->proxy_decider)(sess->proxy_decider_udata,
				   http_get_scheme(sess), sess->server.hostname);
    }
    else {
	req->use_proxy = sess->have_proxy;
    }

    if (sess->request_secure_upgrade == 1) {
	req->upgrade_to_tls = 1;
    }

    /* Add in standard callbacks */

    if (sess->server.auth_callback != NULL) {
	http_auth_set_creds_cb(&sess->server.auth, give_creds, req);
	http_add_response_body_reader(req, always_accept_response, 
				      auth_body_reader, 
				      &req->session->server.auth);
    }

    if (req->use_proxy && sess->proxy.auth_callback != NULL) {
	http_auth_set_creds_cb(&sess->proxy.auth, give_creds, req);
	http_add_response_body_reader(req, always_accept_response, 
				      auth_body_reader, 
				      &req->session->proxy.auth);
    }
    
    /* Add in handlers for all the standard HTTP headers. */

    http_add_response_header_handler(req, "Content-Length", 
				      http_handle_numeric_header, &req->resp.length);
    http_add_response_header_handler(req, "Transfer-Encoding", 
				      te_hdr_handler, &req->resp);
    http_add_response_header_handler(req, "Connection", 
				      connection_hdr_handler, req);

    if (uri) {
	req->abs_path = ne_strdup(uri);
	real_uri = sbuffer_create();
	if (req->use_proxy)
	    sbuffer_concat(real_uri, http_get_scheme(req->session), "://", 
			   req->session->server.hostport, NULL);
	sbuffer_zappend(real_uri, req->abs_path);
	req->uri = sbuffer_finish(real_uri);
    }

    {
	struct hook *hk;
	struct hook_request *store;
	void *cookie;

	DEBUG(DEBUG_HTTP, "Running request create hooks.\n");

	for (hk = sess->hooks; hk != NULL; hk = hk->next) {
	    cookie = (*hk->hooks->create)(hk->private, req, method, uri);
	    if (cookie != NULL) {
		store = ne_malloc(sizeof(struct hook_request));
		store->hook = hk;
		store->cookie = cookie;
		store->next = req->hook_store;
		req->hook_store = store;
	    }
	}
    }

    DEBUG(DEBUG_HTTP, "Request created.\n");

    return req;
}

static void run_set_body_hooks(http_req *req, const char *buf, FILE *f)
{
    struct hook_request *st;
    for (st = req->hook_store; st!=NULL; st = st->next) {
	if (HAVE_HOOK(st,use_body)) {
	    HOOK_FUNC(st,use_body)(st->cookie, buf, f);
	}
    }
}

void http_set_request_body_buffer(http_req *req, const char *buffer)
{
    req->body = body_buffer;
    req->body_buffer = buffer;
    req->body_stream = NULL;
    run_set_body_hooks(req, buffer, NULL);
}

void http_set_request_body_stream(http_req *req, FILE *stream)
{
    req->body = body_stream;
    req->body_stream = stream;
    req->body_buffer = NULL;
    run_set_body_hooks(req, NULL, stream);
}

void http_set_expect100(http_session *sess, int use_expect100)
{
    if (use_expect100) {
	sess->expect100_works = 1;
    } else {
	sess->expect100_works = -1;
    }
}

void http_set_persist(http_session *sess, int persist)
{
    sess->no_persist = !persist;
}

void http_set_useragent(http_session *sess, const char *token)
{
    static const char *fixed = " " NEON_USERAGENT;
    HTTP_FREE(sess->user_agent);
    CONCAT2(sess->user_agent, token, fixed);
}

void http_add_request_header(http_req *req, const char *name, 
			     const char *value)
{
    sbuffer_concat(req->headers, name, ": ", value, EOL, NULL);
}

sbuffer http_get_request_headers(http_req *req)
{
    return req->headers;
}

void http_print_request_header(http_req *req, const char *name,
			       const char *format, ...)
{
    va_list params;
    char buf[BUFSIZ];
    
    va_start(params, format);
    vsnprintf(buf, BUFSIZ, format, params);
    va_end(params);
    
    sbuffer_concat(req->headers, name, ": ", buf, EOL, NULL);
}

void
http_add_response_header_handler(http_req *req, const char *name, 
				 http_header_handler hdl, void *userdata)
{
    struct header_handler *new = ne_calloc(sizeof *new);
    int hash;
    new->name = lower_string(name);
    new->handler = hdl;
    new->userdata = userdata;
    hash = hdr_hash(new->name);
    new->next = req->header_handlers[hash];
    req->header_handlers[hash] = new;
}

void http_add_response_header_catcher(http_req *req, 
				      http_header_handler hdl, void *userdata)
{
    struct header_handler *new = ne_calloc(sizeof  *new);
    new->handler = hdl;
    new->userdata = userdata;
    new->next = req->header_catchers;
    req->header_catchers = new;
}

void
http_add_response_body_reader(http_req *req, http_accept_response acpt,
			       http_block_reader rdr, void *userdata)
{
    struct body_reader *new = ne_malloc(sizeof(struct body_reader));
    new->accept_response = acpt;
    new->handler = rdr;
    new->userdata = userdata;
    new->next = req->body_readers;
    req->body_readers = new;
}

void http_request_destroy(http_req *req) 
{
    struct body_reader *rdr, *next_rdr;
    struct header_handler *hdlr, *next_hdlr;
    struct hook_request *st, *next_st;
    int n;

    HTTP_FREE(req->uri);
    HTTP_FREE(req->abs_path);

    for (rdr = req->body_readers; rdr != NULL; rdr = next_rdr) {
	next_rdr = rdr->next;
	free(rdr);
    }

    for (hdlr = req->header_catchers; hdlr != NULL; hdlr = next_hdlr) {
	next_hdlr = hdlr->next;
	free(hdlr);
    }

    for (n = 0; n < HH_HASHSIZE; n++) {
	for (hdlr = req->header_handlers[n]; hdlr != NULL; 
	     hdlr = next_hdlr) {
	    next_hdlr = hdlr->next;
	    free(hdlr->name);
	    free(hdlr);
	}
    }

    sbuffer_destroy(req->headers);

    DEBUG(DEBUG_HTTP, "Running destroy hooks.\n");
    for (st = req->hook_store; st!=NULL; st = next_st) {
	next_st = st->next;
	if (HAVE_HOOK(st,destroy)) {
	    HOOK_FUNC(st,destroy)(st->cookie);
	}
	free(st);
    }

    DEBUG(DEBUG_HTTP, "Request ends.\n");
    free(req);
}


/* Reads a block of the response into buffer, which is of size buflen.
 * Returns number of bytes read, 0 on end-of-response, or HTTP_* on error.
 * TODO?: only make one actual read() call in here... 
 */
static int read_response_block(http_req *req, struct http_response *resp, 
			       char *buffer, size_t *buflen) 
{
    int willread, readlen;
    nsocket *sock = req->session->socket;
    if (resp->is_chunked) {
	/* We are doing a chunked transfer-encoding.
	 * It goes:  `SIZE CRLF CHUNK CRLF SIZE CRLF CHUNK CRLF ...'
	 * ended by a `CHUNK CRLF 0 CRLF', a 0-sized chunk.
	 * The slight complication is that we have to cope with
	 * partial reads of chunks.
	 * For this reason, resp.chunk_left contains the number of
	 * bytes left to read in the current chunk.
	 */
	if (resp->chunk_left == 0) {
	    long int chunk_len;
	    /* We are at the start of a new chunk. */
	    DEBUG(DEBUG_HTTP, "New chunk.\n");
	    readlen = sock_readline(sock, buffer, *buflen);
	    if (readlen <= 0) {
		return set_sockerr(req, _("Could not read chunk size"), readlen);
	    }
	    DEBUG(DEBUG_HTTP, "[Chunk Size] < %s", buffer);
	    chunk_len = strtol(buffer, NULL, 16);
	    if (chunk_len == LONG_MIN || chunk_len == LONG_MAX) {
		DEBUG(DEBUG_HTTP, "Couldn't read chunk size.\n");
		http_set_error(req->session, _("Could not parse chunk size"));
		return -1;
	    }
	    DEBUG(DEBUG_HTTP, "Got chunk size: %ld\n", chunk_len);
	    if (chunk_len == 0) {
		/* Zero-size chunk == end of response. */
		DEBUG(DEBUG_HTTP, "Zero-size chunk.\n");
		*buflen = 0;
		return HTTP_OK;
	    }
	    resp->chunk_left = chunk_len;
	}
	willread = min(*buflen - 1, resp->chunk_left);
    } else if (resp->length > 0) {
	/* Have we finished reading the body? */
	if (resp->left == 0) {
	    *buflen = 0;
	    return HTTP_OK;
	}
	willread = min(*buflen - 1, resp->left);
    } else {
	/* Read until socket-close */
	willread = *buflen - 1;
    }
    DEBUG(DEBUG_HTTP, "Reading %d bytes of response body.\n", willread);
    readlen = sock_read(sock, buffer, willread);
    DEBUG(DEBUG_HTTP, "Got %d bytes.\n", readlen);

    /* EOF is valid if we don't know the response body length, or
     * we've read all of the response body, and we're not using
     * chunked. */
    if (readlen == SOCK_CLOSED && resp->length <= 0 && !resp->is_chunked) {
	readlen = 0;
    } else if (readlen < 0) {
	return set_sockerr(req, _("Could not read response body"), readlen);
    }
    buffer[readlen] = '\0';
    *buflen = readlen;
    DEBUG(DEBUG_HTTPBODY, "Read block:\n%s\n", buffer);
    if (resp->is_chunked) {
	resp->chunk_left -= readlen;
	if (resp->chunk_left == 0) {
	    char crlfbuf[2];
	    /* If we've read a whole chunk, read a CRLF */
	    readlen = sock_fullread(sock, crlfbuf, 2);
	    if (readlen < 0 || strncmp(crlfbuf, EOL, 2) != 0) {
		return set_sockerr(req, 
				   _("Error reading chunked response body"),
				   readlen);
	    }
	}
    } else if (resp->length > 0) {
	resp->left -= readlen;
    }
    return HTTP_OK;
}

/* Build a request string into the buffer.
 * If we sent the data as we generated it, it's possible that multiple
 * packets could go out on the wire, which is less efficient. */
static void build_request(http_req *req, sbuffer buf) 
{
    const char *uri;
    char *tmp;
    http_session *sess = req->session;
    
    /* If we are talking to a proxy, we send them the absoluteURI
     * as the Request-URI. If we are talking to a server, we just 
     * send abs_path. */
    if (req->use_proxy)
	uri = req->uri;
    else
	uri = req->abs_path;
    
    sbuffer_clear(buf);

    /* Add in the request and the user-supplied headers */
    sbuffer_concat(buf, req->method, " ", uri, " HTTP/1.1" EOL,
		    sbuffer_data(req->headers), NULL);
    
    /* And the all-important Host header.  This is done here since it
     * might change for a new server. */
    sbuffer_concat(buf, "Host: ", req->session->server.hostport, 
		   EOL, NULL);


    /* Note that we pass the abs_path here... */
    http_auth_new_request(&sess->server.auth, req->method, req->uri,
			   req->body_buffer, req->body_stream);
    if (req->use_proxy) {
	/* ...and absoluteURI here. */
	http_auth_new_request(&sess->proxy.auth, req->method, req->uri,
			       req->body_buffer, req->body_stream);
    }

    /* Add the authorization headers in */
    tmp = http_auth_request_header(&req->session->server.auth);
    if (tmp != NULL) {
	sbuffer_concat(buf, "Authorization: ", tmp, NULL);
	free(tmp);
    }

    if (req->use_proxy) {
	tmp = http_auth_request_header(&req->session->proxy.auth);
	if (tmp != NULL) {
	    sbuffer_concat(buf, "Proxy-Authorization: ", tmp, NULL);
	    free(tmp);
	}
    }
    
    /* Now handle the body. */
    req->use_expect100 = 0;
    if (req->body!=body_none && 
	(req->session->expect100_works > -1) &&
	(req->body_size > HTTP_EXPECT_MINSIZE) && 
	!HTTP_VERSION_PRE11(req->session)) {
	/* Add Expect: 100-continue. */
	sbuffer_zappend(buf, "Expect: 100-continue" EOL);
	req->use_expect100 = 1;
    }

}

static int set_sockerr(http_req *req, const char *doing, int code)
{
    switch(code) {
    case 0: /* FIXME: still needed? */
    case SOCK_CLOSED:
	if (req->use_proxy) {
	    snprintf(req->session->error, BUFSIZ,
		      _("%s: connection was closed by proxy server."), doing);
	} else {
	    snprintf(req->session->error, BUFSIZ,
		      _("%s: connection was closed by server."), doing);
	}
	return HTTP_ERROR;
    case SOCK_TIMEOUT:
	snprintf(req->session->error, BUFSIZ, 
		  _("%s: connection timed out."), doing);
	return HTTP_TIMEOUT;
    default:
	if (req->session->socket != NULL) {
	    const char *err = sock_get_error(req->session->socket);
	    if (err != NULL) {
		snprintf(req->session->error, BUFSIZ, "%s: %s", doing, err);
	    } else {
		snprintf(req->session->error, BUFSIZ, _("%s: socket error."),
			 doing);
	    }
	} else {
	    snprintf(req->session->error, BUFSIZ,
		     "%s: %s", doing, strerror(errno));
	}	    
	return HTTP_ERROR;
    }
}

/* FIXME: this function need re-writing.
 *
 * buf is used to read response lines, must be created, and of size >= BUFSIZ.
 * Returns HTTP_*, and sets session error appropriately.
 */
static int send_request(http_req *req, const char *request, sbuffer buf)
{
    http_session *sess = req->session;
    int ret, try_again, send_attempt;

    try_again = 1;
    
    do {

	/* FIXME: this is broken */
	try_again--;

#ifdef DEBUGGING
	{ 
	    if ((DEBUG_HTTPPLAIN&neon_debug_mask) == DEBUG_HTTPPLAIN) { 
		/* Display everything mode */
		DEBUG(DEBUG_HTTP, "Sending request headers:\n%s", request);
	    } else {
		/* Blank out the Authorization paramaters */
		char *reqdebug = ne_strdup(request), *pnt = reqdebug;
		while ((pnt = strstr(pnt, "Authorization: ")) != NULL) {
		    for (pnt += 15; *pnt != '\r' && *pnt != '\0'; pnt++) {
			*pnt = 'x';
		    }
		}
		DEBUG(DEBUG_HTTP, "Sending request headers:\n%s", reqdebug);
		free(reqdebug);
	    }
	}
#endif /* DEBUGGING */
	
	/* Send the Request-Line and headers */
	for (send_attempt = 0; send_attempt < 2; send_attempt++) {
	    DEBUG(DEBUG_HTTP, "Sending headers: attempt %d\n", send_attempt);
	    /* Open the connection if necessary */
	    ret = open_connection(req);
	    if (ret != HTTP_OK) {
		return ret;
	    }
	    ret = sock_send_string(req->session->socket, request);
	    if (ret == SOCK_CLOSED) {
		/* Could happen due to a persistent connection timeout.
		 * Or the server being restarted. */
		DEBUG(DEBUG_HTTP, "Connection was closed by server.\n");
		close_connection(req->session);
	    } else {
		break;
	    }
	}
	
	if (ret < 0) {
	    return set_sockerr(req, _("Could not send request"), ret);
	}

	DEBUG(DEBUG_HTTP, "Request sent\n");
	
	/* Now, if we are doing a Expect: 100, hang around for a short
	 * amount of time, to see if the server actually cares about the 
	 * Expect and sends us a 100 Continue response if the request
	 * is valid, else an error code if it's not. This saves sending
	 * big files to the server when they will be rejected.
	 */
	
	if (req->use_expect100) {
	    DEBUG(DEBUG_HTTP, "Waiting for response...\n");
	    ret = sock_block(sess->socket, HTTP_EXPECT_TIMEOUT);
	    switch(ret) {
	    case SOCK_TIMEOUT: 
		/* Timed out - i.e. Expect: ignored. There is a danger
		 * here that the server DOES respect the Expect: header,
		 * but was going SO slowly that it didn't get time to
		 * respond within HTTP_EXPECT_TIMEOUT.
		 * TODO: while sending the body, check to see if the
		 * server has sent anything back - if it HAS, then
		 * stop sending - this is a spec compliance SHOULD */
		DEBUG(DEBUG_HTTP, "Wait timed out.\n");
		sess->expect100_works = -1; /* don't try that again */
		/* Try sending the request again without using 100-continue */
		try_again++;
		continue;
		break;
	    case SOCK_CLOSED:
	    case SOCK_ERROR: /* error */
		return set_sockerr(req, _("Error waiting for response"), ret);
	    default:
		DEBUG(DEBUG_HTTP, "Wait got data.\n");
		sess->expect100_works = 1; /* it works - use it again */
		break;
	    }
	} else if (req->body != body_none) {
	    /* Just chuck the file down the socket */
	    DEBUG(DEBUG_HTTP, "Sending body...\n");
	    ret = send_request_body(req);
	    if (ret == SOCK_CLOSED) {
		/* This happens if the persistent connection times out:
		 * the first write() of the headers gets a delayed write
		 * seemingly, so the write doesn't fail till this one.
		 */
		DEBUG(DEBUG_HTTP, "Connection closed before request sent, retrying\n");
		try_again++;
		close_connection(req->session);
		continue;
	    } else if (ret < 0) {
		DEBUG(DEBUG_HTTP, "Body send failed.\n");
		return set_sockerr(req, _("Could not send request body"), ret);
	    }
	    DEBUG(DEBUG_HTTP, "Body sent.\n");
	    
	}
	
	/* Now, we have either:
	 *   - Sent the header and body, or
	 *   - Sent the header incl. Expect: line, and got some response.
	 * In any case, we get the status line of the response.
	 */
	
	/* HTTP/1.1 says that the server MAY emit any number of
	 * interim 100 (Continue) responses prior to the normal
	 * response.  So loop while we get them.  */
	
	do {
	    if (sock_readline(sess->socket, sbuffer_data(buf), BUFSIZ) <= 0) {
		if (try_again) {
		    return set_sockerr(req, _("Could not read status line"), ret);
		}
		DEBUG(DEBUG_HTTP, "Failed to read status line.\n");
		try_again++;
		break;
	    }

	    DEBUG(DEBUG_HTTP, "[Status Line] < %s", sbuffer_data(buf));
	    
	    /* Got the status line - parse it */
	    if (http_parse_statusline(sbuffer_data(buf), &req->status)) {
		http_set_error(sess, _("Could not parse response status line."));
		return -1;
	    }

	    sess->version_major = req->status.major_version;
	    sess->version_minor = req->status.minor_version;
	    snprintf(sess->error, BUFSIZ, "%d %s", 
		     req->status.code, req->status.reason_phrase);
	    STRIP_EOL(sess->error);

	    if (req->status.klass == 1) {
		DEBUG(DEBUG_HTTP, "Got 1xx-class.\n");
		/* Skip any headers, we don't need them */
		do {
		    ret = sock_readline(sess->socket, sbuffer_data(buf), BUFSIZ);
		    if (ret <= 0) {
			return set_sockerr(
			    req, _("Error reading response headers"), ret);
		    }
		    DEBUG(DEBUG_HTTP, "[Ignored header] < %s", 
			   sbuffer_data(buf));
		} while (strcmp(sbuffer_data(buf), EOL) != 0);
	
		if (req->use_expect100 && (req->status.code == 100)) {
		    /* We are using Expect: 100, and we got a 100-continue 
		     * return code... send the request body */
		    DEBUG(DEBUG_HTTP, "Got continue... sending body now.\n");
		    ret = send_request_body(req);
		    if (ret <= 0) {
			return set_sockerr(
			    req, _("Error sending request body"), ret);
		    }

		    DEBUG(DEBUG_HTTP, "Body sent.\n");
		} else if (req->upgrade_to_tls && (req->status.code == 101)) {
		    /* Switch to TLS on the fly */
		    if (sock_make_secure(sess->socket, sess->ssl_context)) {
			close_connection(sess);
			return set_sockerr(req, _("Could not negotiate SSL session"),
					   SOCK_ERROR);
		    }
		}
	    }
	} while (req->status.klass == 1);

	if (try_again == 1) {
	    /* If we're trying again, close the conn first */
	    DEBUG(DEBUG_HTTP, "Retrying request, closing connection first.\n");
	    close_connection(sess);
	}

    } while (try_again == 1);

    return HTTP_OK;
}

/* Read a message header from sock into buf.
 * 'extra' is used to store continuation lines in, and must be
 * at least of size BUFSIZ.
 * Returns:
 *   HTTP_RETRY: Read a header into buf.
 *   HTTP_OK: End-of-headers
 *   HTTP_ERROR: Error (session error is set).
 */
static int read_message_header(http_req *req, sbuffer buf, char *extra)
{
    char *pnt, ch;
    int ret;
    nsocket *sock = req->session->socket;

    ret = sock_readline(sock, sbuffer_data(buf), BUFSIZ);
    if (ret <= 0)
	return set_sockerr(req, _("Error reading response headers"), ret);
    DEBUG(DEBUG_HTTP, "[Header:%d] < %s", 
	   strlen(sbuffer_data(buf)), sbuffer_data(buf));

    STRIP_EOL(sbuffer_data(buf));
    sbuffer_altered(buf);

    if (sbuffer_size(buf) == 0) {
	DEBUG(DEBUG_HTTP, "End of headers.\n");
	return HTTP_OK;
    }

    while (sbuffer_size(buf) < HTTP_MAXIMUM_HEADER_LENGTH) {
	/* Collect any extra lines into buffer */
	ret = sock_peek(sock, &ch, 1);
	if (ret <= 0) {
	    return set_sockerr(req, _("Error reading response headers"), ret);
	}
	if (ch != ' ' && ch != '\t') {
	    /* No continuation of this header */
	    return HTTP_RETRY;
	}
	/* Read BUFSIZ-1 bytes to guarantee that we have a \0 */
	ret = sock_readline(sock, extra, BUFSIZ-1);
	if (ret <= 0) {
	    return set_sockerr(req, _("Error reading response headers"), ret);
	}
	DEBUG(DEBUG_HTTP, "[Cont:%d] < %s", strlen(extra), extra);
	/* Append a space to the end of the last header, in
	 * place of the CRLF. */
	sbuffer_append(buf, " ", 1);
	for (pnt = extra; *pnt!='\0' && 
		 (*pnt == ' ' || *pnt =='\t'); pnt++) /*oneliner*/;
	DEBUG(DEBUG_HTTP, "[Continued] < %s", pnt);
	sbuffer_zappend(buf, pnt);
    }

    http_set_error(req->session, _("Response header too long"));
    return HTTP_ERROR;
}

static void normalize_response_length(http_req *req)
{
    /* Response entity-body length calculation, bit icky.
     * Here, we set:
     * length==-1 if we DO NOT know the exact body length
     * length>=0 if we DO know the body length.
     *
     * RFC2616, section 4.4: 
     * NO body is returned if the method is HEAD, or the resp status
     * is 204 or 304
     */
    if (req->method_is_head || req->status.code==204 || 
	req->status.code==304) {
	req->resp.length = 0;
    } else {
	/* RFC2616, section 4.4: if we have a transfer encoding
	 * and a content-length, then ignore the content-length. */
	if ((req->resp.length>-1) && 
	    (req->resp.is_chunked)) {
	    req->resp.length = -1;
	}
    }
    /* Noddy noddy noddy. Testing from Apache/mod_proxy, CONNECT does
     * not return a Content-Length... */
    if (req->resp.length == -1 && req->session->in_connect &&
	req->status.klass == 2) {
	req->resp.length = 0;
    }
       
}

/* Read response headers, using buffer buffer.
 * Returns HTTP_* code, sets session error. */
static int read_response_headers(http_req *req, sbuffer buf) 
{
    char extra[BUFSIZ] = {0};
    int ret;
    
    /* Read response headers.  This loop has been optimized: my GCC
     * will put all the local vars in registers. */
    while ((ret = read_message_header(req, buf, extra)) == HTTP_RETRY) {
	struct header_handler *hdl;
	char *hdr;
	/* hint to the compiler that we'd like these in registers */
	register char *pnt;
	register int hash = 0;

	/* Quicker than sbuffer_data(), and means 'hdr' can be 
	 * optimized away. */
	hdr = SBUFFER_CAST(buf);
	
	for (hdl = req->header_catchers; hdl != NULL; hdl = hdl->next) {
	    (*hdl->handler)(hdl->userdata, hdr);
	}
	
	/* Iterate over the header name, converting it to lower case and 
	 * calculating the hash value as we go. */
	for (pnt = hdr; *pnt != '\0' && *pnt != ':'; pnt++) {
	    *pnt = tolower(*pnt);
	    hash = HH_ITERATE(hash,*pnt);
	}

	if (*pnt != '\0') {
	    /* Null-term name at the : */
	    *pnt = '\0';
	    
	    /* Value starts after any whitespace... */
	    do {
		pnt++;
	    } while (*pnt == ' ' || *pnt == '\t');
	    
	    DEBUG(DEBUG_HTTP, "Header Name: [%s], Value: [%s]\n", hdr, pnt);
	    
	    /* Iterate through the header handlers */
	    for (hdl = req->header_handlers[hash]; hdl != NULL; 
		 hdl = hdl->next) {
		if (strcmp(hdr, hdl->name) == 0) {
		    (*hdl->handler)(hdl->userdata, pnt);
		}
	    }
	} else {
	    http_set_error(req->session, _("Malformed header line."));
	    return HTTP_ERROR;
	}
    }

    return ret;
}

/* Read the response message body */
static int read_response_body(http_req *req)
{
    char buffer[BUFSIZ];
    int ret = HTTP_OK;
    size_t readlen;
    struct body_reader *rdr;
	    
    /* If there is nothing to do... */
    if (req->resp.length == 0) {
	/* Do nothing */
	return HTTP_OK;
    }
    
    /* First off, tell all of the response body handlers that they are
     * going to get a body, and let them work out whether they want to 
     * handle it or not */
    for (rdr = req->body_readers; rdr != NULL; rdr=rdr->next) {
	rdr->use = (*rdr->accept_response)(rdr->userdata, req, &req->status);
    }    
    
    req->resp.left = req->resp.length;
    req->resp.chunk_left = 0;

    /* Now actually read the thing */
    
    do {
	/* Read a block */
	readlen = BUFSIZ;
	ret = read_response_block(req, &req->resp, buffer, &readlen);
	
	/* TODO: Do we need to call them if readlen==0, or if
	 * readlen == -1, to tell them something has gone wrong? */
	   
	if (ret == HTTP_OK) {
	    for (rdr = req->body_readers; rdr!=NULL; rdr=rdr->next) {
		if (rdr->use)
		    (*rdr->handler)(rdr->userdata, buffer, readlen);
	    }
	}

    } while (ret == HTTP_OK && readlen > 0);

    if (ret != HTTP_OK)
	req->forced_close = 1;

    return ret;
}

/* Handler for the "Transfer-Encoding" response header */
static void te_hdr_handler(void *userdata, const char *value) 
{
    struct http_response *resp = userdata;
    if (strcasecmp(value, "chunked") == 0) {
	resp->is_chunked = 1;
    } else {
	resp->is_chunked = 0;
    }
}

/* Handler for the "Connection" response header */
static void connection_hdr_handler(void *userdata, const char *value)
{
    http_req *req = userdata;
    if (strcasecmp(value, "close") == 0) {
	req->forced_close = 1;
    } else if (strcasecmp(value, "Keep-Alive") == 0) {
	req->can_persist = 1;
    }
}


/* HTTP/1.x request/response mechanism 
 *
 * Returns an HTTP_* return code. 
 *   
 * The status information is placed in status. The error string is
 * placed in req->session->error
 *
 */
int http_request_dispatch(http_req *req) 
{
    http_session *sess = req->session;
    sbuffer buf, request;
    int ret, attempt, proxy_attempt, con_attempt, can_retry;
    /* Response header storage */
    char *www_auth, *proxy_auth, *authinfo, *proxy_authinfo;
    http_status *status = &req->status;

    /* Initialization... */
    DEBUG(DEBUG_HTTP, "Request started...\n");
    http_set_error(sess, "Unknown error.");
    ret = HTTP_OK;

    if (get_request_bodysize(req))
	return HTTP_ERROR;

    buf = sbuffer_create_sized(BUFSIZ);

    if (sess->server.auth_callback != NULL) {
	http_add_response_header_handler(req, "WWW-Authenticate",
					 http_duplicate_header, &www_auth);
	http_add_response_header_handler(req, "Authentication-Info",
					 http_duplicate_header, &authinfo);
    }

    if (req->use_proxy && sess->proxy.auth_callback != NULL) {
	http_add_response_header_handler(req, "Proxy-Authenticate",
					 http_duplicate_header, &proxy_auth);
	http_add_response_header_handler(req, "Proxy-Authentication-Info",
					 http_duplicate_header, 
					 &proxy_authinfo);
    }
				     
    request = sbuffer_create();
    proxy_attempt = con_attempt = attempt = 1;
    www_auth = proxy_auth = authinfo = proxy_authinfo = NULL;
    
    /* Loop sending the request:
     * Retry whilst authentication fails and we supply it. */
    
    do {
	struct hook_request *st;
	
	can_retry = 0;
	req->can_persist = 0;
	req->forced_close = 0;

	build_request(req, request);

	DEBUG(DEBUG_HTTP, "Running pre_send hooks\n");
	for (st = req->hook_store; st!=NULL; st = st->next) {
	    if (HAVE_HOOK(st,pre_send)) {
		HOOK_FUNC(st,pre_send)(st->cookie, request);
	    }
	}						    

	/* Final CRLF */
	sbuffer_zappend(request, EOL);
	
	/* Now send the request, and read the Status-Line */
	ret = send_request(req, sbuffer_data(request), buf);
	if (ret != HTTP_OK) goto dispatch_error;

	req->resp.length = -1;
	req->resp.is_chunked = 0;

	/* Read the headers */
	if (read_response_headers(req, buf) != HTTP_OK) {
	    ret = HTTP_ERROR;
	    goto dispatch_error;
	}

	normalize_response_length(req);

	ret = read_response_body(req);
	if (ret != HTTP_OK) goto dispatch_error;

	/* Read headers in chunked trailers */
	if (req->resp.is_chunked) {
	    ret = read_response_headers(req, buf);
	    if (ret != HTTP_OK) goto dispatch_error;
	}

	DEBUG(DEBUG_HTTP, "Running post_send hooks\n");
	for (st = req->hook_store; st!=NULL; st = st->next) {
	    if (HAVE_HOOK(st,post_send)) {
		int hret = HOOK_FUNC(st,post_send)(st->cookie, status);
		/* TODO: this will simplify down to using just 'ret' once
		 * we move authentication into hooks. */
		switch(hret) {
		case HTTP_OK:
		    break;
		case HTTP_RETRY:
		    can_retry = 1;
		    break;
		default:
		    /* They must set session error */
		    ret = hret;
		}
	    }
	}

	if (proxy_authinfo != NULL && 
	    http_auth_verify_response(&sess->proxy.auth, proxy_authinfo)) {
	    DEBUG(DEBUG_HTTP, "Proxy response authentication invalid.\n");
	    ret = HTTP_SERVERAUTH;
	    http_set_error(sess, _("Proxy server was not authenticated correctly."));
	} else if (authinfo != NULL &&
		   http_auth_verify_response(&sess->server.auth, authinfo)) {
	    DEBUG(DEBUG_HTTP, "Response authenticated as invalid.\n");
	    ret = HTTP_PROXYAUTH;
	    http_set_error(sess, _("Server was not authenticated correctly."));
	} else if (status->code == 401 && www_auth != NULL && attempt++ == 1) {
	    if (!http_auth_challenge(&sess->server.auth, www_auth)) {
		can_retry = 1;
	    }		
	} else if (status->code == 407 && proxy_auth != NULL && proxy_attempt++ == 1) {
	    if (!http_auth_challenge(&sess->proxy.auth, proxy_auth)) {
		can_retry = 1;
	    }
	}

	HTTP_FREE(www_auth);
	HTTP_FREE(proxy_auth);
	HTTP_FREE(authinfo);
	HTTP_FREE(proxy_authinfo);
	
	DEBUG(DEBUG_HTTP, "Connection status: %s, %s, %s\n",
	      req->forced_close?"forced close":"no forced close",
	      sess->no_persist?"no persistent connection":"persistent connection",
	      HTTP_VERSION_PRE11(sess)?"pre-HTTP/1.1":"HTTP/1.1 or later");

	/* Close the connection if any of the following are true:
	 *  - We have a forced close (e.g. "Connection: close" header)
	 *  - We are not using persistent connections for this session
	 *  - All of the following are true:
	 *    * this is HTTP/1.0
	 *    * and they haven't said they can do persistent connections 
	 *    * we've not just done a successful CONNECT
	 */
	if (req->forced_close || sess->no_persist ||
	    (HTTP_VERSION_PRE11(sess) && 
	     !req->can_persist && 
	     (!sess->in_connect || status->klass != 2))) {
	    close_connection(sess);
	}
    
	/* Retry it if we had an auth challenge */

    } while (can_retry);

    DEBUG(DEBUG_HTTP | DEBUG_FLUSH, 
	   "Request ends, status %d class %dxx, error line:\n%s\n", 
	   status->code, status->klass, sess->error);
    DEBUG(DEBUG_HTTPBASIC, "Response: %d %s", status->code, sess->error);

    if (ret == HTTP_OK) {
	switch(status->code) {
	case 401:
	    ret = HTTP_AUTH;
	    break;
	case 407:
	    ret = HTTP_AUTHPROXY;
	    break;
	default:
	    break;
	}
    }

dispatch_error:
    
    sbuffer_destroy(request);
    sbuffer_destroy(buf);

    HTTP_FREE(www_auth);
    HTTP_FREE(proxy_auth);
    HTTP_FREE(authinfo);
    HTTP_FREE(proxy_authinfo);

    return ret;
}

const http_status *http_get_status(http_req *req)
{
    return &(req->status);
}

/* Create a CONNECT tunnel through the proxy server.
 * Returns HTTP_* */
static int proxy_tunnel(http_session *sess)
{
    /* Hack up an HTTP CONNECT request... */
    http_req *req = http_request_create(sess, "CONNECT", NULL);
    int ret = HTTP_OK;

    /* Fudge the URI to be how we want it */
    req->uri = ne_strdup(sess->server.hostport);

    sess->connected = 1;
    sess->in_connect = 1;

    ret = http_request_dispatch(req);

    sess->in_connect = 0;

    if (ret != HTTP_OK || !sess->connected || 
	req->status.klass != 2) {
	/* It failed */
	http_set_error(sess, 
		       _("Could not create SSL connection through proxy server"));
	ret = HTTP_ERROR;
    }

    http_request_destroy(req);
    
    return ret;
}

static int open_connection(http_req *req) 
{
    http_session *sess = req->session;

    if (req->use_proxy) {
	switch(sess->connected) {
	case 0:
	    /* Make the TCP connection to the proxy */
	    DEBUG(DEBUG_SOCKET, "Connecting to proxy at %s:%d...\n", 
		   sess->proxy.hostname, sess->proxy.port);
	    sess->socket = sock_connect(sess->proxy.addr, sess->proxy.port);
	    if (sess->socket == NULL) {
		(void) set_sockerr(req, _("Could not connect to proxy server"), SOCK_ERROR);
		return HTTP_CONNECT;
	    }
	    sess->connected = 1;
	    /* FALL-THROUGH */
	case 1:
	    if (sess->use_secure && !sess->in_connect) {
		int ret;
		ret = proxy_tunnel(sess);
		if (ret != HTTP_OK) {
		    close_connection(sess);
		    return ret;
		}
		if (sock_make_secure(sess->socket, sess->ssl_context)) {
		    (void) set_sockerr(req, _("Could not negotiate SSL session"), SOCK_ERROR);
		    close_connection(sess);
		    return HTTP_ERROR;
		}
		sess->connected = 2;
	    } else {
		break;
	    }
	    break;
	default:
	    /* We've got everything we need */
	    break;	    
	}
    } else if (sess->connected == 0) {

	DEBUG(DEBUG_SOCKET, "Connecting to server at %s:%d...\n", 
	       sess->server.hostname, sess->server.port);

	sess->socket = sock_connect(sess->server.addr, sess->server.port);
	    
	if (sess->socket == NULL) {
	    (void) set_sockerr(req, _("Could not connect to server"), -1);
	    return HTTP_CONNECT;
	}

	if (sess->use_secure) {
	    DEBUG(DEBUG_SOCKET, "Starting SSL...\n");
	    if (sock_make_secure(sess->socket, sess->ssl_context)) {
		(void) set_sockerr(req, _("Could not negotiate SSL session"), SOCK_ERROR);
		return HTTP_ERROR;
	    }
	}

	sess->connected = 1;
    }
    return HTTP_OK;
}

static int close_connection(http_session *sess) 
{
    DEBUG(DEBUG_SOCKET, "Closing connection.\n");
    if (sess->connected > 0) {
	sock_close(sess->socket);
	sess->socket = NULL;
    }
    sess->connected = 0;
    DEBUG(DEBUG_SOCKET, "Connection closed.\n");
    return 0;
}

