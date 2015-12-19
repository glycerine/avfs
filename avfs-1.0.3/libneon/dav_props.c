/* 
   WebDAV Properties manipulation
   Copyright (C) 2000-2001, Joe Orton <joe@light.plus.com>

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

#include "ne_alloc.h"
#include "dav_props.h"
#include "dav_basic.h"
#include "hip_xml.h"

struct dav_propfind_handler_s {
    http_session *sess;
    const char *uri;
    int depth;

    int has_props; /* whether we've already written some
		    * props to the body. */
    sbuffer body;
    
    dav_207_parser *parser207;
    hip_xml_parser *parser;
    struct hip_xml_elm *elms;

    /* Callback to create the private structure. */
    dav_props_create_complex private_creator;
    void *private_userdata;
    
    /* Current propset. */
    dav_prop_result_set *current;

    dav_props_result callback;
    void *userdata;
};

#define ELM_namedprop (DAV_ELM_207_UNUSED)

/* We build up the results of one 'response' element in memory. */
struct prop {
    char *name, *nspace, *value;
    /* Store a dav_propname here too, for convienience.  pname.name =
     * name, pname.nspace = nspace, but they are const'ed in pname. */
    dav_propname pname;
};

struct propstat {
    struct prop *props;
    int numprops;
    http_status status;
} propstat;

/* Results set. */
struct dav_prop_result_set_s {
    struct propstat *pstats;
    int numpstats;
    void *private;
    char *href;
};

hip_xml_parser *dav_propfind_get_parser(dav_propfind_handler *handler)
{
    return handler->parser;
}

static int propfind(dav_propfind_handler *handler, 
		    dav_props_result results, void *userdata)
{
    int ret;
    http_req *req;

    /* Register the catch-all handler to ignore any cruft the
     * server returns. */
    dav_207_ignore_unknown(handler->parser207);
    
    req = http_request_create(handler->sess, "PROPFIND", handler->uri);

    handler->callback = results;
    handler->userdata = userdata;

    http_set_request_body_buffer(req, sbuffer_data(handler->body));

    http_add_request_header(req, "Content-Type", "text/xml"); /* TODO: UTF-8? */
    dav_add_depth_header(req, handler->depth);
    
    http_add_response_body_reader(req, dav_accept_207, hip_xml_parse_v, 
				  handler->parser);

    ret = http_request_dispatch(req);

    if (ret == HTTP_OK && http_get_status(req)->klass != 2) {
	ret = HTTP_ERROR;
    } else if (!hip_xml_valid(handler->parser)) {
	http_set_error(handler->sess, hip_xml_get_error(handler->parser));
	ret = HTTP_ERROR;
    }

    http_request_destroy(req);

    return ret;
}

static void set_body(dav_propfind_handler *hdl, const dav_propname *names)
{
    sbuffer body = hdl->body;
    int n;
    
    if (!hdl->has_props) {
	sbuffer_zappend(body, "<prop>" EOL);
	hdl->has_props = 1;
    }

    for (n = 0; names[n].name != NULL; n++) {
	char *name, *nspace;
	
	/* TODO:
	 * In retrospect it is probably Wrong to do UTF-8 encoding
	 * here.  More likely, it should be an API requirement that
	 * property names/values are UTF-8 encoded strings.
	 * 
	 * I'm not up on the issues and problems that need to be
	 * solved in this arena, so someone who is please shout
	 * at me and tell me I'm stupid: neon@webdav.org */

	name = ne_utf8_encode(names[n].name);
	nspace = ne_utf8_encode(names[n].nspace);

	sbuffer_concat(body, "<", names[n].name, " xmlns=\"", 
		       names[n].nspace, "\"/>" EOL, NULL);

	free(name);
	free(nspace);
    }

}

int dav_propfind_allprop(dav_propfind_handler *handler, 
			 dav_props_result results, void *userdata)
{
    sbuffer_zappend(handler->body, "<allprop/></propfind>" EOL);
    return propfind(handler, results, userdata);
}

int dav_propfind_named(dav_propfind_handler *handler,
		       dav_props_result results, void *userdata)
{
    sbuffer_zappend(handler->body, "</prop></propfind>" EOL);
    return propfind(handler, results, userdata);
}


/* The easy one... PROPPATCH */
int dav_proppatch(http_session *sess, const char *uri, 
		  const dav_proppatch_operation *items)
{
    http_req *req = http_request_create(sess, "PROPPATCH", uri);
    sbuffer body = sbuffer_create();
    char *utf8body;
    int n, ret;
    
    /* Create the request body */
    sbuffer_zappend(body, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>" EOL
		     "<propertyupdate xmlns=\"DAV:\">");

    for (n = 0; items[n].name != NULL; n++) {
	switch (items[n].type) {
	case dav_propset:
	    /* <set><prop><prop-name>value</prop-name></prop></set> */
	    sbuffer_concat(body, "<set><prop>"
			   "<", items[n].name->name, " xmlns=\"",
			   items[n].name->nspace, "\">", items[n].value,
			   "</", items[n].name->name, "></prop></set>" EOL, 
			   NULL);
	    break;

	case dav_propremove:
	    /* <remove><prop><prop-name/></prop></remove> */
	    sbuffer_concat(body, 
			   "<remove><prop><", items[n].name->name, " xmlns=\"",
			   items[n].name->nspace, "\"/></prop></remove>" EOL, 
			   NULL);
	    break;
	}
    }	

    sbuffer_zappend(body, "</propertyupdate>" EOL);
    
    utf8body = ne_utf8_encode(sbuffer_data(body));

    http_set_request_body_buffer(req, utf8body);
    http_add_request_header(req, "Content-Type", "text/xml"); /* TODO: UTF-8? */
    
    ret = dav_simple_request(sess, req);
    
    sbuffer_destroy(body);
    free(utf8body);

    return ret;
}

/* Compare two property names. */
static int pnamecmp(const dav_propname *pn1, const dav_propname *pn2)
{
    return (strcasecmp(pn1->nspace, pn2->nspace) ||
	    strcasecmp(pn1->name, pn2->name));
}

/* Find property in 'set' with name 'pname'.  If found, set pstat_ret
 * to the containing propstat, likewise prop_ret, and returns zero.
 * If not found, returns non-zero.  */
static int findprop(const dav_prop_result_set *set, const dav_propname *pname,
		    struct propstat **pstat_ret, struct prop **prop_ret)
{
    
    int ps, p;

    for (ps = 0; ps < set->numpstats; ps++) {
	for (p = 0; p < set->pstats[ps].numprops; p++) {
	    struct prop *prop = &set->pstats[ps].props[p];

	    if (pnamecmp(&prop->pname, pname) == 0) {
		if (pstat_ret != NULL)
		    *pstat_ret = &set->pstats[ps];
		if (prop_ret != NULL)
		    *prop_ret = prop;
		return 0;
	    }
	}
    }

    return -1;
}

const char *dav_propset_value(const dav_prop_result_set *set,
			      const dav_propname *pname)
{
    struct prop *prop;
    
    if (findprop(set, pname, NULL, &prop)) {
	return NULL;
    } else {
	return prop->value;
    }
}

void *dav_propfind_current_private(dav_propfind_handler *handler)
{
    return handler->current->private;
}

void *dav_propset_private(const dav_prop_result_set *set)
{
    return set->private;
}

int dav_propset_iterate(const dav_prop_result_set *set,
			dav_propset_iterator iterator, void *userdata)
{
    int ps, p;

    for (ps = 0; ps < set->numpstats; ps++) {
	for (p = 0; p < set->pstats[ps].numprops; p++) {
	    struct prop *prop = &set->pstats[ps].props[p];
	    int ret = iterator(userdata, &prop->pname, prop->value, 
			       &set->pstats[ps].status);
	    if (ret)
		return ret;

	}
    }

    return 0;
}

const http_status *dav_propset_status(const dav_prop_result_set *set,
				      const dav_propname *pname)
{
    struct propstat *pstat;
    
    if (findprop(set, pname, &pstat, NULL)) {
	/* TODO: it is tempting to return a dummy status object here
	 * rather than NULL, which says "Property result was not given
	 * by server."  but I'm not sure if this is best left to the
	 * client.  */
	return NULL;
    } else {
	return &pstat->status;
    }
}

static int check_context(hip_xml_elmid parent, hip_xml_elmid child)
{
    if (child == ELM_namedprop && parent == DAV_ELM_prop)
	return HIP_XML_VALID;

    if (child == HIP_ELM_unknown && parent == DAV_ELM_prop)
	return HIP_XML_VALID;

    return HIP_XML_DECLINE;
}

static void *start_response(void *userdata, const char *href)
{
    dav_prop_result_set *set = ne_calloc(sizeof(*set));
    dav_propfind_handler *hdl = userdata;

    set->href = ne_strdup(href);

    if (hdl->private_creator != NULL) {
	set->private = hdl->private_creator(hdl->private_userdata, href);
    }

    hdl->current = set;

    return set;
}

static void *start_propstat(void *userdata, void *response)
{
    dav_prop_result_set *set = response;
    int n;
    struct propstat *pstat;

    n = set->numpstats;
    set->pstats = realloc(set->pstats, sizeof(struct propstat) * (n+1));
    set->numpstats = n+1;

    pstat = &set->pstats[n];
    memset(pstat, 0, sizeof(*pstat));
    
    /* And return this as the new pstat. */
    return &set->pstats[n];
}

static int 
startelm(void *userdata, const struct hip_xml_elm *elm, 
	 const char **atts)
{
    dav_propfind_handler *hdl = userdata;
    struct propstat *pstat = dav_207_get_current_propstat(hdl->parser207);
    struct prop *prop;
    int n;

    /* Paranoia */
    if (pstat == NULL) {
	DEBUG(DEBUG_XML, "gp_startelm: No propstat found, or not my element.");
	return -1;
    }

    /* Add a property to this propstat */
    n = pstat->numprops;

    pstat->props = realloc(pstat->props, sizeof(struct prop) * (n + 1));
    pstat->numprops = n+1;

    /* Fill in the new property. */
    prop = &pstat->props[n];

    prop->pname.name = prop->name = ne_strdup(elm->name);
    prop->pname.nspace = prop->nspace = ne_strdup(elm->nspace);
    prop->value = NULL;

    DEBUG(DEBUG_XML, "Got property #%d: %s@@%s.\n", n, 
	  prop->nspace, prop->name);

    return 0;
}

static int 
endelm(void *userdata, const struct hip_xml_elm *elm, const char *cdata)
{
    dav_propfind_handler *hdl = userdata;
    struct propstat *pstat = dav_207_get_current_propstat(hdl->parser207);
    int n;

    if (pstat == NULL) {
	DEBUG(DEBUG_XML, "gp_endelm: No propstat found, or not my element.");
	return -1;
    }

    n = pstat->numprops - 1;

    DEBUG(DEBUG_XML, "Value of property #%d is %s\n", n, cdata);
    
    pstat->props[n].value = ne_strdup(cdata);

    return 0;
}

static void end_propstat(void *userdata, void *pstat_v, 
			 const char *status_line, const http_status *status,
			 const char *description)
{
    struct propstat *pstat = pstat_v;

    /* If we get a non-2xx response back here, we wipe the value for
     * each of the properties in this propstat, so the caller knows to
     * look at the status instead. It's annoying, since for each prop
     * we will have done an unnecessary strdup("") above, but there is
     * no easy way round that given the fact that we don't know
     * whether we've got an error or not till after we get the
     * property element. */
    if (status->klass != 2) {
	int n;
	
	for (n = 0; n < pstat->numprops; n++) {
	    free(pstat->props[n].value);
	    pstat->props[n].value = NULL;
	}
    }

    pstat->status = *status;
}

/* Frees up a results set */
static void free_propset(dav_prop_result_set *set)
{
    int n;
    
    for (n = 0; n < set->numpstats; n++) {
	int m;
	struct propstat *p = &set->pstats[n];

	for (m = 0; m < p->numprops; m++) {
	    free(p->props[m].nspace);
	    free(p->props[m].name);
	    HTTP_FREE(p->props[m].value);
	}

	free(set->pstats[n].props);
    }

    free(set->pstats);
    free(set);	 
}

static void end_response(void *userdata, void *resource,
			 const char *status_line,
			 const http_status *status,
			 const char *description)
{
    dav_propfind_handler *handler = userdata;
    dav_prop_result_set *set = resource;
    
    /* TODO: Handle status here too? The status element is mandatory
     * inside each propstat, so, not much point probably. */

    /* Pass back the results for this resource. */
    if (handler->callback != NULL) {
	handler->callback(handler->userdata, set->href, set);
    }

    free(set->href);

    /* Clean up the propset tree we've just built. */
    free_propset(set);
}

dav_propfind_handler *
dav_propfind_create(http_session *sess, const char *uri, int depth)
{
    dav_propfind_handler *ret = ne_calloc(sizeof(dav_propfind_handler));

    ret->parser = hip_xml_create();
    ret->parser207 = dav_207_create(ret->parser, ret);
    ret->uri = uri;
    ret->depth = depth;
    ret->sess = sess;
    ret->body = sbuffer_create();

    dav_207_set_response_handlers(ret->parser207, 
				  start_response, end_response);

    dav_207_set_propstat_handlers(ret->parser207, start_propstat,
				  end_propstat);

    /* The start of the request body is fixed: */
    sbuffer_concat(ret->body, 
		    "<?xml version=\"1.0\" encoding=\"utf-8\"?>" EOL 
		    "<propfind xmlns=\"DAV:\">", NULL);

    return ret;
}

static struct hip_xml_elm *make_elms(const dav_propname *props)
{
    int n;
    struct hip_xml_elm *elms;

    if (props == NULL) {
	/* Just collect unknown.  Note this is a collect, so they get
	 * a noddy text representation of the XML back, which is
	 * probably never actually useful. */

	DEBUG(DEBUG_XML, "using UNKNOWN element handler.\n");
	elms = ne_calloc(sizeof(*elms) * 2);
	
	elms[0].id = HIP_ELM_unknown;
	elms[0].flags = HIP_XML_COLLECT | HIP_XML_UTF8DECODE;

	return elms;

    } else {
	/* Count the properties */
	for (n = 0; props[n].name != NULL; n++) /* noop */;
	
	/* Allocate the array, enough for each */
	elms = ne_calloc(sizeof(*elms) * (n+1));
	
	/* Fill it in. Note that the elements all have the SAME
	 * element ID, and we COLLECT inside them, since these
	 * are flat properties. */
	for (n = 0; props[n].name != NULL; n++) {
	    elms[n].nspace = props[n].nspace;
	    elms[n].name = props[n].name;
	    elms[n].id = ELM_namedprop;
	    elms[n].flags = HIP_XML_COLLECT | HIP_XML_UTF8DECODE;
	}
    }
    
    return elms;
}

static void free_elms(struct hip_xml_elm *elms)
{
    free(elms);
}

/* Destroy a propfind handler */
void dav_propfind_destroy(dav_propfind_handler *handler)
{
    dav_207_destroy(handler->parser207);
    hip_xml_destroy(handler->parser);
    if (handler->elms != NULL)
	free_elms(handler->elms);
    sbuffer_destroy(handler->body);
    free(handler);    
}

int dav_simple_propfind(http_session *sess, const char *href, int depth,
			const dav_propname *props,
			dav_props_result results, void *userdata)
{
    dav_propfind_handler *hdl;
    int ret;

    hdl = dav_propfind_create(sess, href, depth);
    if (props != NULL) {
	/* Named. */
	dav_propfind_set_flat(hdl, props);
	ret = dav_propfind_named(hdl, results, userdata);
    } else {
	/* Allprop: register the catch-all-props handler. */
	hdl->elms = make_elms(NULL);
	hip_xml_push_handler(hdl->parser, hdl->elms, 
			     check_context, startelm, endelm, hdl);
	ret = dav_propfind_allprop(hdl, results, userdata);
    }
	
    dav_propfind_destroy(hdl);
    
    return ret;
}

void dav_propfind_set_flat(dav_propfind_handler *hdl, 
			   const dav_propname *props)
{
    set_body(hdl, props);

    /* Register our special flat-property handler, which
     * is used for every flat property that they just passed.
     */
    
    hdl->elms = make_elms(props);
    hip_xml_push_handler(hdl->parser, hdl->elms, 
			 check_context, startelm, endelm, hdl);
}

void dav_propfind_set_complex(dav_propfind_handler *hdl,
			      const dav_propname *props,
			      dav_props_create_complex creator,
			      void *userdata)
{
    set_body(hdl, props);
    hdl->private_creator = creator;
    hdl->private_userdata = userdata;
}
