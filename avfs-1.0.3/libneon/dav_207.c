/* 
   WebDAV 207 multi-status response handling
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

/* Generic handling for WebDAV 207 Multi-Status responses. */

#include "config.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "http_utils.h"
#include "hip_xml.h"
#include "dav_207.h"
#include "uri.h"
#include "ne_alloc.h"

#include "neon_i18n.h"

struct dav_207_parser_s {
    dav_207_start_response start_response;
    dav_207_end_response end_response;
    dav_207_start_propstat start_propstat;
    dav_207_end_propstat end_propstat;
    hip_xml_parser *parser;
    void *userdata;
    /* current position */
    void *response, *propstat;
    /* caching */
    http_status status;
    char *description, *href, *status_line;
};

const static struct hip_xml_elm elements[] = {
    { "DAV:", "multistatus", DAV_ELM_multistatus, 0 },
    { "DAV:", "response", DAV_ELM_response, 0 },
    { "DAV:", "responsedescription", DAV_ELM_responsedescription, 
      HIP_XML_CDATA },
    { "DAV:", "href", DAV_ELM_href, HIP_XML_CDATA },
    { "DAV:", "propstat", DAV_ELM_propstat, 0 },
    { "DAV:", "prop", DAV_ELM_prop, 0 },
    { "DAV:", "status", DAV_ELM_status, HIP_XML_CDATA },
    { NULL }
};

/* Set the callbacks for the parser */
void dav_207_set_response_handlers(dav_207_parser *p,
				   dav_207_start_response start,
				   dav_207_end_response end)
{
    p->start_response = start;
    p->end_response = end;
}

void dav_207_set_propstat_handlers(dav_207_parser *p,
				   dav_207_start_propstat start,
				   dav_207_end_propstat end)
{
    p->start_propstat = start;
    p->end_propstat = end;
}

void *dav_207_get_current_response(dav_207_parser *p)
{
    return p->response;
}

void *dav_207_get_current_propstat(dav_207_parser *p)
{
    return p->propstat;
}

static int 
start_element(void *userdata, const struct hip_xml_elm *elm, 
	      const char **atts) 
{
    dav_207_parser *p = userdata;
    
    switch (elm->id) {
    case DAV_ELM_response:
	/* Create new response delayed until we get HREF */
	break;
    case DAV_ELM_propstat:
	if (p->start_propstat) {
	    p->propstat = (*p->start_propstat)(p->userdata, p->response);
	}
	break;
    }
    return 0;
}

static int 
end_element(void *userdata, const struct hip_xml_elm *elm, const char *cdata)
{
    dav_207_parser *p = userdata;

    switch (elm->id) {
    case DAV_ELM_responsedescription:
	if (cdata != NULL) {
	    HTTP_FREE(p->description);
	    p->description = ne_strdup(cdata);
	}
	break;
    case DAV_ELM_href:
	/* Now we have the href, begin the response */
	if (p->start_response && cdata != NULL) {
	    p->response = (*p->start_response)(p->userdata, cdata);
	}
	break;
    case DAV_ELM_status:
	if (cdata) {
	    HTTP_FREE(p->status_line);
	    p->status_line = ne_strdup(cdata);
	    if (http_parse_statusline(p->status_line, &p->status)) {
		char buf[500];
		DEBUG(DEBUG_HTTP, "Status line: %s\n", cdata);
		snprintf(buf, 500, 
			 _("Invalid HTTP status line in status element at line %d of response:\nStatus line was: %s"),
			 hip_xml_currentline(p->parser), p->status_line);
		hip_xml_set_error(p->parser, buf);
		HTTP_FREE(p->status_line);
		return -1;
	    } else {
		DEBUG(DEBUG_XML, "Decoded status line: %s\n", p->status_line);
	    }
	}
	break;
    case DAV_ELM_propstat:
	if (p->end_propstat) {
	    (*p->end_propstat)(p->userdata, p->propstat, p->status_line,
			       p->status_line?&p->status:NULL, p->description);
	}
	p->propstat = NULL;
	HTTP_FREE(p->description);
	HTTP_FREE(p->status_line);
	break;
    case DAV_ELM_response:
	if (p->end_response) {
	    (*p->end_response)(p->userdata, p->response, p->status_line,
			       p->status_line?&p->status:NULL, p->description);
	}
	p->response = NULL;
	HTTP_FREE(p->status_line);
	HTTP_FREE(p->description);
	break;
    }
    return 0;
}

/* This should map directly from the DTD... with the addition of
 * ignoring anything we don't understand, being liberal in what we
 * accept. */
static int check_context(hip_xml_elmid parent, hip_xml_elmid child) 
{
    DEBUG(DEBUG_XML, "207cc: %d in %d\n", child, parent);
    switch (parent) {
    case HIP_ELM_root:
	switch (child) {
	case DAV_ELM_multistatus:
	case DAV_ELM_response: /* not sure why this is here... */
	    return HIP_XML_VALID;
	default:
	    break;
	}
	break;
    case DAV_ELM_multistatus:
	/* <!ELEMENT multistatus (response+, responsedescription?) > */
	switch (child) {
	case DAV_ELM_response:
	case DAV_ELM_responsedescription:
	    return HIP_XML_VALID;
	default:
	    break;
	}
	break;
    case DAV_ELM_response:
	/* <!ELEMENT response (href, ((href*, status)|(propstat+)),
	   responsedescription?) > */
	switch (child) {
	case DAV_ELM_href:
	case DAV_ELM_status:
	case DAV_ELM_propstat:
	case DAV_ELM_responsedescription:
	    return HIP_XML_VALID;
	default:
	    break;
	}
	break;
    case DAV_ELM_propstat:
	/* <!ELEMENT propstat (prop, status, responsedescription?) > */
	switch (child) {
	case DAV_ELM_prop: 
	case DAV_ELM_status:
	case DAV_ELM_responsedescription:
	    return HIP_XML_VALID;
	default:
	    break;
	}
	break;
    default:
	break;
    }

    return HIP_XML_DECLINE;
}

static int ignore_cc(hip_xml_elmid parent, hip_xml_elmid child) 
{
    if (child == HIP_ELM_unknown || parent == HIP_ELM_unknown) {
	DEBUG(DEBUG_XML, "207 catch-all caught %d in %d\n", child, parent);
	return HIP_XML_VALID;
    }

    return HIP_XML_DECLINE;
}

void dav_207_ignore_unknown(dav_207_parser *p)
{
    static const struct hip_xml_elm any_elms[] = {
	{ "", "", HIP_ELM_unknown, HIP_XML_COLLECT },
	{ NULL }
    };
    
    hip_xml_push_handler(p->parser, any_elms,
			 ignore_cc, NULL, NULL, NULL);
    
}

dav_207_parser *dav_207_create(hip_xml_parser *parser, void *userdata)
{
    dav_207_parser *p = ne_calloc(sizeof *p);

    p->parser = parser;
    p->userdata = userdata;
    
    /* Add handler for the standard 207 elements */
    hip_xml_push_handler(parser, elements, check_context, 
			 start_element, end_element, p);
    
    return p;
}

void dav_207_destroy(dav_207_parser *p) 
{
    free(p);
}

int dav_accept_207(void *userdata, http_req *req, http_status *status)
{
    return (status->code == 207);
}
