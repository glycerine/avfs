/* 
   WebDAV Class 2 locking operations
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

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "http_request.h"
#include "dav_locks.h"
#include "dav_basic.h"
#include "dav_props.h"
#include "uri.h"
#include "dav_207.h"
#include "neon_i18n.h"
#include "hip_xml.h"

#include "ne_alloc.h"

#define HOOK_ID "http://webdav.org/neon/hooks/webdav-locking"

/* The list of locks to submit in an If header 
 * for the current requests */
struct submit_locks {
    const struct dav_lock *lock;
    const char *uri;
    struct submit_locks *next;
};

struct dav_lock_session_s {
    struct dav_lock *locks;
};

/* Per-request lock structure */
struct request_locks {
    struct submit_locks *locks; /* for the If header */
    dav_lock_session *session;
};

/* Context for PROPFIND/lockdiscovery callbacks */
struct discover_ctx {
    dav_lock_result results;
    void *userdata;
};

/* Hook callbacks */
static void *create(void *session, http_req *req, 
		    const char *method, const char *uri);
static void pre_send(void *private, sbuffer req);
static void destroy(void *private);

/* The hooks are needed for construction of the If header */
static http_request_hooks lock_hooks = {
    HOOK_ID, /* unique id for the locking hooks */
    create,
    NULL, /* use_body not needed */
    pre_send,
    NULL, /* post_send not needed */
    destroy
};

/* Element ID's start at HIP_ELM_UNUSED and work upwards */

#define DAV_ELM_LOCK_FIRST (DAV_ELM_207_UNUSED)

#define DAV_ELM_lockdiscovery (DAV_ELM_LOCK_FIRST)
#define DAV_ELM_activelock (DAV_ELM_LOCK_FIRST + 1)
#define DAV_ELM_lockscope (DAV_ELM_LOCK_FIRST + 2)
#define DAV_ELM_locktype (DAV_ELM_LOCK_FIRST + 3)
#define DAV_ELM_depth (DAV_ELM_LOCK_FIRST + 4)
#define DAV_ELM_owner (DAV_ELM_LOCK_FIRST + 5)
#define DAV_ELM_timeout (DAV_ELM_LOCK_FIRST + 6)
#define DAV_ELM_locktoken (DAV_ELM_LOCK_FIRST + 7)
#define DAV_ELM_lockinfo (DAV_ELM_LOCK_FIRST + 8)
#define DAV_ELM_write (DAV_ELM_LOCK_FIRST + 9)
#define DAV_ELM_exclusive (DAV_ELM_LOCK_FIRST + 10)
#define DAV_ELM_shared (DAV_ELM_LOCK_FIRST + 11)

static const struct hip_xml_elm lock_elms[] = {
#define A(x) { "DAV:", #x, DAV_ELM_ ## x, HIP_XML_COLLECT } /* ANY */
#define D(x) { "DAV:", #x, DAV_ELM_ ## x, 0 }               /* normal */
#define C(x) { "DAV:", #x, DAV_ELM_ ## x, HIP_XML_CDATA }   /* (#PCDATA) */
#define E(x) { "DAV:", #x, DAV_ELM_ ## x, 0 /* LEAF */ }    /* EMPTY */
    D(lockdiscovery), D(activelock),
    D(prop),
    D(lockscope), D(locktype), C(depth), A(owner), C(timeout), D(locktoken),
    /* no lockentry */
    D(lockinfo), D(lockscope), D(locktype),
    E(write), E(exclusive), E(shared),
    C(href),
#undef A
#undef D
#undef C
#undef E
    { NULL, 0, 0 }
};

static const dav_propname lock_props[] = {
    { "DAV:", "lockdiscovery" },
    { NULL }
};

static void *create(void *session, http_req *req, 
		    const char *method, const char *uri)
{
    struct request_locks *rl = ne_calloc(sizeof *rl);
    rl->session = session;
    return rl;
}

static void pre_send(void *private, sbuffer req)
{
    struct request_locks *rl = private;
    
    if (rl->locks != NULL) {
	struct submit_locks *item;

	/* Add in the If header */
	sbuffer_zappend(req, "If:");
	for (item = rl->locks; item != NULL; item = item->next) {
	    sbuffer_concat(req, " <", item->lock->uri, "> (<",
			   item->lock->token, ">)", NULL);
	}
	sbuffer_zappend(req, EOL);
    }
}

static void destroy(void *priv)
{
    struct request_locks *rl = priv;
    struct submit_locks *lock, *next;
    
    for (lock = rl->locks; lock != NULL; lock = next) {
	next = lock->next;
	free(lock);
    }
    
    free(rl);
}

dav_lock_session *dav_lock_register(http_session *sess)
{
    dav_lock_session *locksess = ne_calloc(sizeof *locksess);

    /* Register the hooks */
    http_add_hooks(sess, &lock_hooks, locksess);
    
    return locksess;
}

void dav_lock_unregister(dav_lock_session *sess)
{
    /* FIXME: free the lock list */
    free(sess);
}

/* Submit the given lock for the given URI */
static void submit_lock(struct request_locks *rl, struct dav_lock *lock, 
			const char *uri)
{
    struct submit_locks *slock;

    /* Check for dups */
    for (slock = rl->locks; slock != NULL; slock = slock->next) {
	if (strcasecmp(slock->lock->token, lock->token) == 0)
	    return;
    }

    slock = ne_calloc(sizeof *slock);
    slock->lock = lock;
    slock->uri = uri;
    slock->next = rl->locks;
    rl->locks = slock;
}

struct dav_lock *dav_lock_find(dav_lock_session *sess, const char *uri)
{
    struct dav_lock *cur;
    for (cur = sess->locks; cur != NULL; cur = cur->next) {
	if (uri_compare(uri, cur->uri) == 0) 
	    return cur;
    }
    return NULL;
}

void dav_lock_using_parent(http_req *req, const char *uri)
{
    struct request_locks *rl = http_get_hook_private(req, HOOK_ID);
    char *parent;

    if (rl == NULL)
	return;	

    parent = uri_parent(uri);

    if (parent != NULL) {
	struct dav_lock *lock;
	/* Find any locks on the parent resource.
	 * FIXME: should check for depth-infinity locks too. */
	lock = dav_lock_find(rl->session, parent);
	if (lock) {
	    DEBUG(DEBUG_LOCKS, "Locked parent, %s on %s\n", lock->token, 
		  lock->uri);
	    submit_lock(rl, lock, uri);
	}
	free(parent);
    }
}

int dav_lock_iterate(dav_lock_session *sess, 
		     dav_lock_walkfunc func, void *userdata)
{
    struct dav_lock *lock;
    int count = 0;

    for (lock = sess->locks; lock != NULL; lock = lock->next) {
	if (func != NULL) {
	    (*func)(lock, userdata);
	}
	count++;
    }
    
    return count;
}

void dav_lock_using_resource(http_req *req, const char *uri, int depth)
{
    /* Grab the private cookie for this request */
    struct request_locks *rl = http_get_hook_private(req, HOOK_ID);
    struct dav_lock *lock; /* all the known locks */
    int match;

    if (rl == NULL)
	return;	

    /* Iterate over the list of session locks to see if any of
     * them apply to this resource */
    for (lock = rl->session->locks; lock != NULL; lock = lock->next) {
	
	match = 0;
	
	if (depth == DAV_DEPTH_INFINITE && uri_childof(uri, lock->uri)) {
	    /* Case 1: this is a depth-infinity request which will 
	     * modify a lock somewhere inside the collection. */
	    DEBUG(DEBUG_LOCKS, "Has child: %s\n", lock->token);
	    match = 1;
	} 
	else if (uri_compare(uri, lock->uri) == 0) {
	    /* Case 2: this request is directly on a locked resource */
	    DEBUG(DEBUG_LOCKS, "Has direct lock: %s\n", lock->token);
	    match = 1;
	}
	else if (lock->depth == DAV_DEPTH_INFINITE && 
		 uri_childof(lock->uri, uri)) {
	    /* Case 3: there is a higher-up infinite-depth lock which
	     * covers the resource that this request will modify. */
	    DEBUG(DEBUG_LOCKS, "Is child of: %s\n", lock->token);
	    match = 1;
	}
	
	if (match) {
	    submit_lock(rl, lock, uri);
	}
    }

}

void dav_lock_add(dav_lock_session *sess, struct dav_lock *lock)
{
    if (sess->locks != NULL) {
	sess->locks->prev = lock;
    }
    lock->prev = NULL;
    lock->next = sess->locks;
    sess->locks = lock;
}

void dav_lock_remove(dav_lock_session *sess, struct dav_lock *lock)
{
    if (lock->prev != NULL) {
	lock->prev->next = lock->next;
    } else {
	sess->locks = lock->next;
    }
    if (lock->next != NULL) {
	lock->next->prev = lock->prev;
    }
}

struct dav_lock *dav_lock_copy(const struct dav_lock *lock)
{
    struct dav_lock *ret = ne_calloc(sizeof *ret);

    ret->uri = ne_strdup(lock->uri);
    ret->depth = lock->depth;
    ret->type = lock->type;
    ret->scope = lock->scope;
    ret->token = ne_strdup(lock->token);
    ret->owner = ne_strdup(lock->owner);
    ret->timeout = lock->timeout;

    return ret;
}

void dav_lock_free(struct dav_lock *lock)
{
    HTTP_FREE(lock->uri);
    HTTP_FREE(lock->owner);
    HTTP_FREE(lock->token);
    free(lock);
}

int dav_unlock(http_session *sess, struct dav_lock *lock)
{
    http_req *req = http_request_create(sess, "UNLOCK", lock->uri);
    int ret;
    
    http_print_request_header(req, "Lock-Token", "<%s>", lock->token);
    
    /* TODO: need this or not?
     * it definitely goes away when lock-null resources go away */
    dav_lock_using_parent(req, lock->uri);

    ret = http_request_dispatch(req);
    
    if (ret == HTTP_OK && http_get_status(req)->klass == 2) {
	ret = HTTP_OK;    
    } else {
	ret = HTTP_ERROR;
    }

    http_request_destroy(req);
    
    return ret;
}

static int check_context(hip_xml_elmid parent, hip_xml_elmid child) {
    DEBUG(DEBUG_XML, "dav_locks: check_context %d in %d\n", child, parent);
    switch (parent) {
    case HIP_ELM_root:
	/* TODO: for LOCK requests only...
	 * shouldn't allow this for PROPFIND really */
	if (child == DAV_ELM_prop)
	    return HIP_XML_VALID;
	break;	    
    case DAV_ELM_prop:
	if (child == DAV_ELM_lockdiscovery)
	    return HIP_XML_VALID;
	break;
    case DAV_ELM_lockdiscovery:
	if (child == DAV_ELM_activelock)
	    return HIP_XML_VALID;
	break;
    case DAV_ELM_activelock:
	switch (child) {
	case DAV_ELM_lockscope:
	case DAV_ELM_locktype:
	case DAV_ELM_depth:
	case DAV_ELM_owner:
	case DAV_ELM_timeout:
	case DAV_ELM_locktoken:
	    return HIP_XML_VALID;
	default:
	    break;
	}
	break;
    case DAV_ELM_lockscope:
	switch (child) {
	case DAV_ELM_exclusive:
	case DAV_ELM_shared:
	    return HIP_XML_VALID;
	default:
	    break;
	}
    case DAV_ELM_locktype:
	if (child == DAV_ELM_write)
	    return HIP_XML_VALID;
	break;
	/* ... depth is PCDATA, owner is COLLECT, timeout is PCDATA */
    case DAV_ELM_locktoken:
	if (child == DAV_ELM_href)
	    return HIP_XML_VALID;
	break;
    }
    return HIP_XML_DECLINE;
}

static int parse_depth(const char *depth) {
    if (strcasecmp(depth, "infinity") == 0) {
	return DAV_DEPTH_INFINITE;
    } else if (isdigit(depth[0])) {
	return atoi(depth);
    } else {
	return -1;
    }
}

static long parse_timeout(const char *timeout) {
    if (strcasecmp(timeout, "infinite") == 0) {
	return DAV_TIMEOUT_INFINITE;
    } else if (strncasecmp(timeout, "Second-", 7) == 0) {
	long to = strtol(timeout, NULL, 10);
	if (to == LONG_MIN || to == LONG_MAX)
	    return DAV_TIMEOUT_INVALID;
	return to;
    } else {
	return DAV_TIMEOUT_INVALID;
    }
}

static void discover_results(void *userdata, const char *href,
			     const dav_prop_result_set *set)
{
    struct discover_ctx *ctx = userdata;
    struct dav_lock *lock = dav_propset_private(set);

    if (lock == NULL)
	return;

    lock->uri = ne_strdup(href);

    ctx->results(ctx->userdata, lock, 
		 href, dav_propset_status(set, &lock_props[0]));

    
    dav_lock_free(lock);

    DEBUG(DEBUG_LOCKS, "End of response for %s\n", href);
}

static int 
end_element_common(struct dav_lock *l, const struct hip_xml_elm *elm,
		   const char *cdata)
{
    switch (elm->id){ 
    case DAV_ELM_write:
	l->type = dav_locktype_write;
	break;
    case DAV_ELM_exclusive:
	l->scope = dav_lockscope_exclusive;
	break;
    case DAV_ELM_shared:
	l->scope = dav_lockscope_shared;
	break;
    case DAV_ELM_depth:
	DEBUG(DEBUG_LOCKS, "Got depth: %s\n", cdata);
	l->depth = parse_depth(cdata);
	if (l->depth == -1) {
	    return -1;
	}
	break;
    case DAV_ELM_timeout:
	DEBUG(DEBUG_LOCKS, "Got timeout: %s\n", cdata);
	l->timeout = parse_timeout(cdata);
	if (l->timeout == DAV_TIMEOUT_INVALID) {
	    return -1;
	}
	break;
    case DAV_ELM_owner:
	l->owner = strdup(cdata);
	break;
    case DAV_ELM_href:
	l->token = strdup(cdata);
	break;
    }
    return 0;
}

/* End-element handler for lock discovery PROPFIND response */
static int 
end_element_ldisc(void *userdata, const struct hip_xml_elm *elm, 
		  const char *cdata) 
{
    struct dav_lock *lock = dav_propfind_current_private(userdata);

    return end_element_common(lock, elm, cdata);
}

/* End-element handler for LOCK response */
static int
end_element_lock(void *userdata, const struct hip_xml_elm *elm, 
		 const char *cdata)
{
    struct dav_lock *lock = userdata;
    return end_element_common(lock, elm, cdata);
}

static void *create_private(void *userdata, const char *uri)
{
    return ne_calloc(sizeof(struct dav_lock));
}

/* Discover all locks on URI */
int dav_lock_discover(http_session *sess, const char *uri, 
		      dav_lock_result callback, void *userdata)
{
    dav_propfind_handler *handler;
    struct discover_ctx ctx = {0};
    int ret;
    
    ctx.results = callback;
    ctx.userdata = userdata;

    handler = dav_propfind_create(sess, uri, DAV_DEPTH_ZERO);

    dav_propfind_set_complex(handler, lock_props, create_private, NULL);
    
    hip_xml_push_handler(dav_propfind_get_parser(handler), lock_elms, 
			 check_context, NULL, end_element_ldisc, handler);
    
    ret = dav_propfind_named(handler, discover_results, &ctx);
    
    dav_propfind_destroy(handler);

    return ret;
}

int dav_lock(http_session *sess, struct dav_lock *lock) 
{
    http_req *req = http_request_create(sess, "LOCK", lock->uri);
    sbuffer body = sbuffer_create();
    hip_xml_parser *parser = hip_xml_create();
    int ret, parse_failed;

    hip_xml_push_handler(parser, lock_elms, check_context, 
			 NULL, end_element_lock, lock);
    
    /* Create the body */
    sbuffer_concat(body, "<?xml version=\"1.0\" encoding=\"utf-8\"?>" EOL
		    "<lockinfo xmlns='DAV:'>" EOL " <lockscope>",
		    lock->scope==dav_lockscope_exclusive?
		    "<exclusive/>":"<shared/>",
		    "</lockscope>" EOL
		    "<locktype><write/></locktype>", NULL);

    if (lock->owner) {
	sbuffer_concat(body, "<owner>", lock->owner, "</owner>" EOL, NULL);
    }
    sbuffer_zappend(body, "</lockinfo>" EOL);

    http_set_request_body_buffer(req, sbuffer_data(body));
    http_add_response_body_reader(req, http_accept_2xx, 
				  hip_xml_parse_v, parser);
    http_add_request_header(req, "Content-Type", "text/xml");
    dav_add_depth_header(req, lock->depth);

    /* TODO: 
     * By 2518, we need this only if we are creating a lock-null resource.
     * Since we don't KNOW whether the lock we're given is a lock-null
     * or not, we cover our bases.
     */
    dav_lock_using_parent(req, lock->uri);
    /* This one is clearer from 2518 sec 8.10.4. */
    dav_lock_using_resource(req, lock->uri, lock->depth);

    ret = http_request_dispatch(req);

    sbuffer_destroy(body);
    parse_failed = !hip_xml_valid(parser);
    
    if (ret == HTTP_OK && http_get_status(req)->klass == 2) {
	if (parse_failed) {
	    ret = HTTP_ERROR;
	    http_set_error(sess, hip_xml_get_error(parser));
	}
	else if (http_get_status(req)->code == 207) {
	    ret = HTTP_ERROR;
	    /* TODO: set the error string appropriately */
	}
    } else {
	ret = HTTP_ERROR;
    }

    http_request_destroy(req);
    hip_xml_destroy(parser);

    /* TODO: free the list */
    return ret;
}
