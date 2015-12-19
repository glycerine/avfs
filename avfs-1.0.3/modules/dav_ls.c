/* 
   ls for AVFS DAV support.
  
   Most of this file is taken from ls.c in cadaver, which has the
   following copyright notice:

   'ls' for cadaver
   Copyright (C) 2000-2001, Joe Orton <joe@orton.demon.co.uk>, 
   except where otherwise indicated.
                                   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "filebuf.h"

#include <time.h>
#include <http_request.h>
#include <dav_props.h>
#include <uri.h>
#include <ne_alloc.h>

#include <string.h>
#include <stdlib.h>
#include "dav.h"

struct fetch_context {
  struct av_dav_conn *conn;
  struct av_dav_resource **list;
  const char *target; /* Request-URI of the PROPFIND */
  unsigned int include_target; /* Include resource at href */
};  

static const dav_propname flat_props[] = {
  { "DAV:", "getcontentlength" },
  { "DAV:", "getlastmodified" },
  { "DAV:", "displayname" },
  { "http://apache.org/dav/props/", "executable" },
  { NULL }
};

static const dav_propname complex_props[] = {
  { "DAV:", "resourcetype" },
  { NULL }
};

#define ELM_resourcetype (DAV_ELM_207_UNUSED + 1)
#define ELM_collection (DAV_ELM_207_UNUSED + 4)

static const struct hip_xml_elm complex_elms[] = {
  { "DAV:", "resourcetype", ELM_resourcetype, 0 },
  { "DAV:", "collection", ELM_collection, 0 },
  { NULL }
};

static int compare_resource(const struct av_dav_resource *r1, 
              const struct av_dav_resource *r2)
{
  /* Sort errors first, then collections, then alphabetically */
  if (r1->type == resr_error) {
    return -1;
  } else if (r2->type == resr_error) {
    return 1;
  } else if (r1->type == resr_collection) {
    if (r2->type != resr_collection) {
      return -1;
    } else {
      return strcmp(r1->uri, r2->uri);
    }
  } else {
    if (r2->type != resr_collection) {
      return strcmp(r1->uri, r2->uri);
    } else {
      return 1;
    }
  }
}

static void results(void *userdata, const char *uri,
          const dav_prop_result_set *set)
{
  struct fetch_context *ctx = userdata;
  struct av_dav_resource *current, *previous, *newres;
  const char *clength, *modtime, *isexec, *abspath;
  const http_status *status = NULL;
  
  av_log (AVLOG_DEBUG, "DAV URI: %s", uri);

  newres = dav_propset_private(set);
  abspath = uri_abspath(uri);

  if (uri_compare(ctx->target, abspath) == 0 && !ctx->include_target) {
    /* This is the target URI, skip it */
    av_free(newres);
    return;
  }

  newres->uri = ne_strdup(abspath);

  clength = dav_propset_value(set, &flat_props[0]);  
  modtime = dav_propset_value(set, &flat_props[1]);
  isexec = dav_propset_value(set, &flat_props[2]);
  
  if (clength == NULL)
    status = dav_propset_status(set, &flat_props[0]);
  if (modtime == NULL)
    status = dav_propset_status(set, &flat_props[1]);

  if (newres->type == resr_normal && status) {
    /* It's an error! */
    newres->error_status = status->code;

    /* Special hack for Apache 1.3/mod_dav */
    if (strcmp(status->reason_phrase, "status text goes here") == 0) {
      const char *desc;
      if (status->code == 401) {
        desc = ("Authorization Required");
      } else if (status->klass == 3) {
        desc = ("Redirect");
      } else if (status->klass == 5) {
        desc = ("Server Error");
      } else {
        desc = ("Unknown Error");
      }
      newres->error_reason = ne_strdup(desc);
    } else {
      newres->error_reason = ne_strdup(status->reason_phrase);
    }
    newres->type = resr_error;
  }

  if (isexec && strcasecmp(isexec, "T") == 0) {
    newres->is_executable = 1;
  } else {
    newres->is_executable = 0;
  }

  if (modtime)
    newres->modtime = http_dateparse(modtime);

  if (clength)
    newres->size = strtol(clength, NULL, 10);

  for (current = *ctx->list, previous = NULL; current != NULL; 
     previous = current, current=current->next) {
    if (compare_resource(current, newres) >= 0) {
      break;
    }
  }
  if (previous) {
    previous->next = newres;
  } else {
    *ctx->list = newres;
  }
  newres->next = current;
}

static int end_element(void *userdata, const struct hip_xml_elm *elm, const char *cdata)
{
  dav_propfind_handler *pfh = userdata;
  struct av_dav_resource *r = dav_propfind_current_private(pfh);

  if (r == NULL) {
    return 0;
  }

  if (elm->id == ELM_collection) {
    r->type = resr_collection;
  }

  return 0;
}

static int check_context(hip_xml_elmid parent, hip_xml_elmid child)
{
  if ((parent == DAV_ELM_prop && child == ELM_resourcetype) ||
    (parent == ELM_resourcetype && child == ELM_collection))
  {
    return 0;
  }
  return 0;  
}

void free_resource(struct av_dav_resource *res)
{
  HTTP_FREE(res->uri);
  HTTP_FREE(res->displayname);
  HTTP_FREE(res->error_reason);
  av_free(res);
}

void free_resource_list(struct av_dav_resource *res)
{
  struct av_dav_resource *next;
  for (; res != NULL; res = next) {
    next = res->next;
    free_resource(res);
  }
}

static void *create_private(void *userdata, const char *uri)
{
  return ne_calloc(sizeof(struct av_dav_resource));
}

int fetch_resource_list(struct av_dav_conn *conn,
                const char *uri, int depth, int include_target,
                struct av_dav_resource **reslist)
{
  dav_propfind_handler *pfh = dav_propfind_create(conn->sesh, uri, depth);
  int ret;
  struct fetch_context ctx = {0};
  
  *reslist = NULL;
  ctx.conn = conn;
  ctx.list = reslist;
  ctx.target = uri;
  ctx.include_target = include_target;

  dav_propfind_set_flat(pfh, flat_props);

  hip_xml_push_handler(dav_propfind_get_parser(pfh), complex_elms, 
             check_context, NULL, end_element, pfh);

  dav_propfind_set_complex(pfh, complex_props, create_private, NULL);

  ret = dav_propfind_named(pfh, results, &ctx);

  dav_propfind_destroy(pfh);

  return ret;
}
