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

#ifndef DAV_LOCKS_H
#define DAV_LOCKS_H

#include "http_request.h" /* for http_session + http_req */

/* The scope of a lock */
enum dav_lock_scope {
    dav_lockscope_exclusive,
    dav_lockscope_shared
};

enum dav_lock_type {
    dav_locktype_write
};

/* Would be typedef'ed to dav_lock except lock is a verb and a noun,
 * so we already have dav_lock the function. Damn the English
 * language. */
struct dav_lock {
    char *uri;
    int depth;
    enum dav_lock_type type;
    enum dav_lock_scope scope;
    char *token;
    char *owner;
    long timeout;
    struct dav_lock *next;
    struct dav_lock *prev;
};

#define DAV_TIMEOUT_INFINITE -1
#define DAV_TIMEOUT_INVALID -2

typedef struct dav_lock_session_s dav_lock_session;

/* TODO: 
 * "session" is a bad word, and it's already used for http_session,
 * maybe think up a better name. lock_store is quite good.
 */

/* Register the locking hooks with an http_session.  Owned locks
 * persist for the duration of this session. */
dav_lock_session *dav_lock_register(http_session *sess);

/* Call this after destroying the http_session which this lock session
 * was registered with. Or register the lock session with a new
 * http_session. Using 'sess' after this function returns will have
 * undefined behaviour.  */
void dav_lock_unregister(dav_lock_session *sess);

/* Add a lock to the given session. The lock will subsequently be
 * submitted as required in an If: header with any requests created
 * using the http_session which the lock session is tied to.  Requests
 * indicate to the locking layer which locks they might need using
 * dav_lock_using_*, as described below. */
void dav_lock_add(dav_lock_session *sess, struct dav_lock *lock);

/* Remove lock, which must have been previously added to the
 * session using 'dav_lock_add' above. */
void dav_lock_remove(dav_lock_session *sess, struct dav_lock *lock);


typedef void (*dav_lock_walkfunc)(struct dav_lock *lock, void *userdata);

/* For each lock added to the session, call func, passing the lock
 * and the given userdata. Returns the number of locks. func may be
 * pass as NULL, in which case, can be used to simply return number
 * of locks in the session. */
int dav_lock_iterate(dav_lock_session *sess, 
		     dav_lock_walkfunc func, void *userdata);

/* Issue a LOCK request for the given lock. */
int dav_lock(http_session *sess, struct dav_lock *lock);
/* Issue an UNLOCK request for the given lock */
int dav_unlock(http_session *sess, struct dav_lock *lock);

/* Find a lock in the session with given URI */
struct dav_lock *dav_lock_find(dav_lock_session *sess, const char *uri);

/* Deep-copy a lock structure. */
struct dav_lock *dav_lock_copy(const struct dav_lock *lock);

/* Free a lock structure */
void dav_lock_free(struct dav_lock *lock);

/* Callback for lock discovery.  If 'lock' is NULL, 
 * something went wrong retrieving lockdiscover for the resource,
 * look at 'status' for the details. */
typedef void (*dav_lock_result)(void *userdata, const struct dav_lock *lock, 
				const char *uri, const http_status *status);

/* Perform lock discovery on the given URI.  'result' is called
 * with the results (possibly >1 times).  */
int dav_lock_discover(http_session *sess, const char *uri, 
		      dav_lock_result result, void *userdata);

/*** For use by method functions */

/* Indicate that this request is of depth n on given uri */
void dav_lock_using_resource(http_req *req, const char *uri, int depth);
/* Indicate that this request will modify parent collection of given URI */
void dav_lock_using_parent(http_req *req, const char *uri);

#endif /* DAV_LOCKS_H */
