/* 
   WebDAV Properties manipulation
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

#ifndef DAV_PROPS_H
#define DAV_PROPS_H

#include "http_request.h"
#include "dav_207.h"

BEGIN_NEON_DECLS

/* There are two interfaces for fetching properties. The first is
 * 'dav_simple_propfind', which is relatively simple, and easy to use,
 * but only lets you fetch FLAT properties, i.e. properties which are
 * just a string of bytes.  The complex interface is 'dav_propfind_*',
 * which is complicated, and hard to use, but lets you parse
 * structured properties, i.e.  properties which have XML content.  */

/* The 'dav_simple_propfind' interface. ***
 *
 * dav_get_props allows you to fetch a set of properties for a single
 * resource, or a tree of resources.  You set the operation going by
 * passing these arguments:
 *
 *  - the session which should be used.
 *  - the URI and the depth of the operation (0, 1, infinite)
 *  - the names of the properties which you want to fetch
 *  - a results callback, and the userdata for the callback.
 *
 * For each resource found, the results callback is called, passing
 * you two things along with the userdata you passed in originally:
 *
 *   - the URI of the resource (const char *href)
 *   - the properties results set (const dav_prop_result_set *results)
 *
 */

typedef struct dav_prop_result_set_s dav_prop_result_set;

/* Get the value of a given property. Will return NULL if there was an
 * error fetching this property on this resource.  Call
 * dav_propset_result to get the response-status if so.  */
const char *dav_propset_value(const dav_prop_result_set *set,
			      const dav_propname *propname);

/* Returns the status structure for fetching the given property on
 * this resource. This function will return NULL if the server did not
 * return the property (which is a server error). */
const http_status *dav_propset_status(const dav_prop_result_set *set,
				      const dav_propname *propname);

/* Returns the private pointer for the given propset. */
void *dav_propset_private(const dav_prop_result_set *set);

/* dav_propset_iterate iterates over a properties result set,
 * calling the callback for each property in the set. userdata is
 * passed as the first argument to the callback. value may be NULL,
 * indicating an error occurred fetching this property: look at 
 * status for the error in that case.
 *
 * If the iterator returns non-zero, dav_propset_iterate will return
 * immediately with that value.
 */
typedef int (*dav_propset_iterator)(void *userdata,
				    const dav_propname *pname,
				    const char *value,
				    const http_status *status);

/* Iterate over all the properties in 'set', calling 'iterator'
 * for each, passing 'userdata' as the first argument to callback.
 * 
 * Returns:
 *   whatever value iterator returns.
 */
int dav_propset_iterate(const dav_prop_result_set *set,
			dav_propset_iterator iterator, void *userdata);

typedef void (*dav_props_result)(void *userdata, const char *href,
				 const dav_prop_result_set *results);

/* Fetch properties for a resource (if depth == DAV_DEPTH_ZERO),
 * or a tree of resources (if depth == DAV_DEPTH_ONE or _INFINITE).
 *
 * Names of the properties required must be given in 'props',
 * or if props is NULL, *all* properties are fetched.
 *
 * 'results' is called for each resource in the response, userdata is
 * passed as the first argument to the callback. It is important to
 * note that the callback is called as the response is read off the
 * socket, so don't do anything silly in it (e.g. sleep(100), or call
 * any functions which use this session).
 *
 * Returns HTTP_*.  */
int dav_simple_propfind(http_session *sess, const char *uri, int depth,
			const dav_propname *props,
			dav_props_result results, void *userdata);

/* A PROPPATCH request may include any number of operations. Pass an
 * array of these operations to dav_proppatch, with the last item
 * having the name element being NULL.  If the type is propset, the
 * property of the given name is set to the new value.  If the type is
 * propremove, the property of the given name is deleted, and the
 * value is ignored.  */
typedef struct {
    const dav_propname *name;
    enum {
	dav_propset,
	dav_propremove
    } type;
    const char *value;
} dav_proppatch_operation;

int dav_proppatch(http_session *sess, const char *uri,
		  const dav_proppatch_operation *items);

/* The complex, you-do-all-the-work, property fetch interface:
 */

struct dav_propfind_handler_s;
typedef struct dav_propfind_handler_s dav_propfind_handler;

/* Retrieve the 'private' pointer for the current propset for the
 * given handler, as returned by the dav_props_create_complex
 * callback.  */
void *dav_propfind_current_private(dav_propfind_handler *handler);

/* Create a PROPFIND handler, for the given URI.
 * Depth must be one of DAV_DEPTH_*. */
dav_propfind_handler *
dav_propfind_create(http_session *sess, const char *uri, int depth);

/* Return the XML parser for the given handler. */
hip_xml_parser *dav_propfind_get_parser(dav_propfind_handler *handler);

/* A "complex property" has a value which is structured XML. To handle
 * complex properties, you must set up and register an XML handler
 * using the 'dav_propfind_get_parser' call, which will understand the
 * elements which make up such properties.
 *
 * To tell the PROPFIND handler to add the list of complex properties
 * to the list of properties to request from the server, use the
 * 'dav_propfind_set_complex' call below, and pass it a list of
 * properties. The list must be terminated by a property whose name is
 * NULL.
 *
 * To store the parsed value of the property, a 'private' structure is
 * allocated in each propset. When parsing the property value
 * elements, for each new resource encountered in the response, the
 * 'creator' callback is called to retrieve a 'private' structure for
 * this resource.
 *
 * Whilst in XML element callbacks you will have registered to handle
 * complex properties, you can use the 'dav_propfind_current_private'
 * call to retrieve the pointer to this private structure.
 *
 * To retrieve this 'private' structure from the propset in the
 * results callback, simply call 'dav_propset_private'.
 *
 * If more than one call to dav_propfind_set_complex is made for a given
 * handler, the result is undefined.
 * */

typedef void *(*dav_props_create_complex)(void *userdata,
					  const char *uri);

void dav_propfind_set_complex(dav_propfind_handler *handler,
			      const dav_propname *proplist,
			      dav_props_create_complex creator,
			      void *userdata);

/* A "simple property" is a flat string of bytes, and requires
 * no special handling by the XML parser.
 *
 * To tell the PROPFIND handler to retrieve a set of flat properties,
 * call 'dav_propfind_set_flat' with the properties. 
 *
 * If more than one call to dav_propfind_set_flat is made for a given
 * handler, the result is undefined.
 * */ 
void dav_propfind_set_flat(dav_propfind_handler *handler,
		       const dav_propname *prop);

/* Note that the call:
 * 
 *  ret = dav_simple_propfind(sess, uri, depth, props, callback, ud);
 * 
 * is equivalent to:
 *
 *  hdl = dav_propfind_create(sess, uri, depth);
 *  dav_propfind_set_flat(hdl, props);
 *  ret = dav_propfind_named(hdl, callback, ud);
 *  dav_propfind_destroy(hdl);
 *
 */

/* Find all properties.  Calls to dav_propfind_set_flat and
 * dav_propfind_set_complex are ignored: all properties are treated
 * as flat.
 *
 * Returns HTTP_*. */
int dav_propfind_allprop(dav_propfind_handler *handler, 
			 dav_props_result result, void *userdata);

/* Find properties named in a call to dav_propfind_set_flat and/or
 * dav_propfind_set_complex.
 *
 * Returns HTTP_*. */
int dav_propfind_named(dav_propfind_handler *handler, 
		       dav_props_result result, void *userdata);

/* Destroy a propfind handler after use. */
void dav_propfind_destroy(dav_propfind_handler *handler);

/* TODO: this API doesn't cope with complex properties in an allprop
 * request. But:
 *
 * 1. allprops is probably a bad thing, and might go away in a future
 * spec revision anyway.
 *
 * 2. the use case for complex properties and allprop is pretty
 * thin. If you know what properties are defined, you fetch a named
 * sets. If you don't know what props are defined on a resource, you
 * have know way of knowing what their XML values "mean", anyway. 
 * */

END_NEON_DECLS

#endif /* DAV_PROPS_H */
