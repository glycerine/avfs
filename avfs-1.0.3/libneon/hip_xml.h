/* 
   Higher Level Interface to XML Parsers.
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

#ifndef HIP_XML_H
#define HIP_XML_H

/* for sbuffer */
#include "string_utils.h"

BEGIN_NEON_DECLS

/* Generic XML parsing interface...
   
   Definitions:
   
   * A handler knows how to parse a certain set of XML elements.
   * The handler stack

   * 
   

   Basic principle is that you provide these things:
     1) a list of elements which you wish to handle 
     2) a validation callback which tells the parser whether you
     want to handle this element.
     3) a callback function which is called when a complete element
     has been parsed (provided you are handling the element).
    
   This code then deals with the boring stuff like:
     - Dealing with XML namespaces   
     - Collecting CDATA

   The element list is stored in a 'hip_xml_elm' array.  For each
   element, you specify the element name, an element id, and some
   flags for that element.

const static struct hip_xml_elm[] = {
   { "DAV:", "resourcetype", ELM_resourcetype, 0 },
   { "DAV:", "collection", ELM_collection, HIP_ELM_CDATA },
   { NULL }
};

   This list contains two elements, resourcetype and collection, both in 
   the "DAV:" namespace.  The collection element can contain cdata.
   
*/

/* Reserved element id's */
#define HIP_ELM_unknown -1
#define HIP_ELM_root 0

#define HIP_ELM_UNUSED (100)

typedef int hip_xml_elmid;

struct hip_xml_elm;

/* An element */
struct hip_xml_elm {
    const char *nspace, *name;
    hip_xml_elmid id;
    unsigned int flags;
};

/* Function to check element context... 
   This callback must return:
     HIP_XML_VALID ->
	Yes, this is valid XML, and I want to handle this element.
     HIP_XML_INVALID ->
	No, this is NOT valid XML, and parsing should stop.
     HIP_XML_DECLINE ->
	I don't know anything about this element, someone else
	can handle it.
*/


#define HIP_XML_VALID (0)
#define HIP_XML_INVALID (-1)
#define HIP_XML_DECLINE (-2)

typedef int (*hip_xml_validate_cb)
    (hip_xml_elmid parent, hip_xml_elmid child);

typedef int (*hip_xml_startelm_cb)
    (void *userdata, const struct hip_xml_elm *elm, const char **atts);

/* Called when a complete element is parsed */
typedef int (*hip_xml_endelm_cb)
    (void *userdata, const struct hip_xml_elm *s, const char *cdata);

typedef void (*hip_xml_cdata_cb)
    (void *userdata, const struct hip_xml_elm *s, 
     const char *cdata, int len);

struct hip_xml_parser_s;
typedef struct hip_xml_parser_s hip_xml_parser;

/* Flags */
/* This element has no children */
#define HIP_XML_CDATA (1<<1)
/* Collect complete contents of this node as cdata */
#define HIP_XML_COLLECT ((1<<2) | HIP_XML_CDATA)
/* Decode UTF-8 data in cdata. */
#define HIP_XML_UTF8DECODE (1<<3)
/* This element uses MIXED mode */
#define HIP_XML_MIXED (1<<4)

/* Initialise the parser */
hip_xml_parser *hip_xml_create(void);

/* Push a handler onto the handler stack for the given list of elements.
 * elements must be an array, with the last element .nspace being NULL.
 * Callbacks are called in order:
 *   1. validate_cb
 *   2. startelm_cb
 *   3. endelm_cb
 * (then back to the beginning again).
 * If any of the callbacks ever return non-zero, the parse will STOP.
 * userdata is passed as the first argument to startelm_cb and endelm_cb.
 */
void hip_xml_push_handler(hip_xml_parser *p,
			  const struct hip_xml_elm *elements, 
			  hip_xml_validate_cb validate_cb, 
			  hip_xml_startelm_cb startelm_cb, 
			  hip_xml_endelm_cb endelm_cb,
			  void *userdata);

/* Add a handler which uses a mixed-mode cdata callback */
void hip_xml_push_mixed_handler(hip_xml_parser *p,
				const struct hip_xml_elm *elements,
				hip_xml_validate_cb validate_cb,
				hip_xml_startelm_cb startelm_cb,
				hip_xml_cdata_cb cdata_cb,
				hip_xml_endelm_cb endelm_cb,
				void *userdata);

/* Returns non-zero if the parse was valid, zero if it failed (e.g.,
 * any of the callbacks return non-zero, the XML was not well-formed,
 * etc).  Use hip_xml_get_error to retrieve the error message if it
 * failed. */
int hip_xml_valid(hip_xml_parser *p);

/* Destroys the parser. Any operations on it then have 
 * undefined results. */
void hip_xml_destroy(hip_xml_parser *p);

/* Parse the given block of input of length len. Block does 
 * not need to be NULL-terminated. */
void hip_xml_parse(hip_xml_parser *p, const char *block, size_t len);

/* As above, casting (hip_xml_parser *)userdata internally.
 * (This function can be passed to http_add_response_body_reader) */
void hip_xml_parse_v(void *userdata, const char *block, size_t len);

/* Return current parse line for errors */
int hip_xml_currentline(hip_xml_parser *p);

/* Set error message for parser */
void hip_xml_set_error(hip_xml_parser *p, const char *msg);

const char *hip_xml_get_error(hip_xml_parser *p);

END_NEON_DECLS

#endif /* HIP_XML_H */
