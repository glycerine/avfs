/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This file can be distributed either under the GNU LGPL, or under
    the GNU GPL. See the file COPYING.LIB and COPYING. 

    DAV module (see http://www.webdav.org/) using Neon
    DAV client library, by Justin Mason <jm-avfs@jmason.org>.
*/

  /* TODO -- http_request_auth implementation */
  /* TODO -- PUT */
  /* TODO -- make GET more efficient by not getting entire file
   * before returning from dav_get() */

#include "dav.h"
#include "avfs.h"
#include "version.h"
#include "remote.h"
#include "prog.h"
#include "filebuf.h"
#include "passwords.h"


#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


/* --------------------------------------------------------------------- */

static char AV_UserAgent[128];

static struct uri av_dav_uri_defaults = {
    "http", NULL, 80, NULL
};

struct davlocalfile {
    int running;
    char *tmpfile;
    char *url;
    avoff_t currsize;
    int fd;
};

/* --------------------------------------------------------------------- */

/*
char *
davlocalfile_to_string (struct davlocalfile *lf)
{
    static char buf[1024];
    snprintf (buf, 1023,
        "[davlocalfile: tmpf=%s url=%s running=%d currsz=%d]",
        lf->tmpfile, lf->url, lf->running, (int) lf->currsize);
    return buf;
}
*/

/* ---------------------------------------------------------------------- */

static char *dav_hostpath_to_url (char *urlbuf, int buflen,
                                        const struct remhostpath *hp)
{
    const char *rawp, *pathp;
    int len;

    *urlbuf = '\0';
    av_log(AVLOG_DEBUG, "DAV: hostpath-to-URL: host=%s path='%s'",
                                hp->host, hp->path);

    /* now rewrite the host bit into the urlbuf, adding:
     * - the protocol bit if http: is specified, as http://
     * - /s instead of :s
     * - a trailing slash
     */
    len = 0; rawp = hp->host;
    if (!strncmp (rawp, "http:", 5)) {
        len += snprintf (urlbuf+len, buflen-len, "http://");
        rawp += 5;
        while (*rawp == '/') { rawp++; }
    }

    for ( ; *rawp != '\0'; rawp++) {
        /* TODO: allow colons, or just pipes? */
        if (/* *rawp == ':' || */ *rawp == '|') {
            urlbuf[len] = '/';
        } else {
            urlbuf[len] = *rawp;
        }
        len++;
    }

    if (len > 0 && urlbuf[len-1] == '/') {
        len--; urlbuf[len] = '\0';
    }

    /* add the path, if it's non-empty */
    for (pathp = hp->path; *pathp == '/'; pathp++);
    if (pathp != '\0') {
        len += snprintf (urlbuf+len, buflen-len, "/%s", pathp);
    }

    /**
     * Finally, we've rewritten it.
     */
    av_log(AVLOG_DEBUG, "DAV: rewritten URL = '%s'", urlbuf);

    return urlbuf;
}

/* ---------------------------------------------------------------------- */

static void dav_free_localfile(struct davlocalfile *lf)
{
  av_free(lf->url);
}

/* ---------------------------------------------------------------------- */

static int
dav_supply_creds(int is_for_proxy, void *userdata, const char *realm,
		const char *hostname, char **username, char **password)
{
    struct pass_session *pass;
    struct davdata *davdat = (struct davdata *) userdata;

    pass = pass_get_password (&(davdat->sessions), realm, hostname);
    if (pass == NULL) {
	return -1;
    }

    /* TODO: really need to dup this? will neon free it? */
    *username = ne_strdup (pass->username);
    *password = ne_strdup (pass->password);
    return 0;
}

static int
dav_supply_creds_server(void *userdata, const char *realm,
		const char *hostname, char **username, char **password)
{
    return dav_supply_creds(0, userdata, realm, hostname, username, password);
}

static int
dav_supply_creds_proxy(void *userdata, const char *realm, 
		const char *hostname, char **username, char **password) 
{
    return dav_supply_creds(1, userdata, realm, hostname, username, password);
}

/* ---------------------------------------------------------------------- */

static int
av_dav_conn_init (struct av_dav_conn *conn, struct davdata *davdat)
{
    conn->sesh = http_session_create();

    /* TODO: provide proxy support from http_proxy env var */
    /* TODO: first make sure neon doesn't automatically do this ;) */
    /* http_session_proxy(sess, "proxy.myisp.com", 8080); */
    http_set_expect100 (conn->sesh, 1);
    http_set_useragent (conn->sesh, AV_UserAgent);
    http_set_server_auth (conn->sesh, dav_supply_creds_server, davdat);
    http_set_proxy_auth (conn->sesh, dav_supply_creds_proxy, davdat);

    return 0;
}

static struct av_dav_conn *
new_dav_conn (struct davdata *davdat)
{
    int i;
    struct av_dav_conn *conn;

    for (i = 0; i < AV_MAX_DAV_CONNS; i++) {
        conn = &(davdat->allconns[i]);
        /* skip the busy ones */
        if (conn->isbusy) { continue; }

        if (conn->sesh == NULL) {
            /* NULL session? This one hasn't been initted yet. */
	    av_dav_conn_init (conn, davdat);
            av_log(AVLOG_DEBUG, "DAV: created new HTTP session");
        }
        conn->isbusy = 1;
        return conn;
    }

    av_log(AVLOG_ERROR, "DAV: out of connections");
    return NULL;
}

/* ---------------------------------------------------------------------- */

static int
http_error_to_errno (const char *method, int httpret, const char *errstr)
{
    int errval = -EIO;

    av_log(AVLOG_ERROR, "DAV: %s failed: (neon err=%d) \"%s\"",
                                    method, httpret, errstr);

    switch (httpret) {
        case HTTP_ERROR:
        /* HTTP_ERROR (1) Generic error; use http_get_error(session) */
        /* TODO -- fill out more HTTP errors here */

        if (!strncmp (errstr, "404", 3)) {
            errval = -ENOENT;
        } else if (!strncmp (errstr, "403", 3)) {
            errval = -EACCES;
        } else if (!strncmp (errstr, "405", 3)) {
            errval = -EACCES;
        }
        break;

        case HTTP_LOOKUP:
        /* HTTP_LOOKUP (3) Name lookup failed */
        errval = -ECONNREFUSED;
        break;

        case HTTP_AUTH:
        /* HTTP_AUTH (4) User authentication failed on server */
	errval = -EACCES;
        break;

        case HTTP_AUTHPROXY:
        /* HTTP_AUTHPROXY (5) User authentication failed on proxy */
	errval = -EACCES;
        break;

        case HTTP_SERVERAUTH:
        /* HTTP_SERVERAUTH (6) Server authentication failed */
	errval = -EACCES;
        break;

        case HTTP_PROXYAUTH:
        /* HTTP_PROXYAUTH (7) Proxy authentication failed */
	errval = -EACCES;
        break;

        case HTTP_CONNECT:
        /* HTTP_CONNECT (8) Could not connect to server */
        errval = -ECONNREFUSED;
        break;

        case HTTP_TIMEOUT:
        /* HTTP_TIMEOUT (9) Connection timed out */
        errval = -ETIMEDOUT;
        break;

        case HTTP_FAILED:
        /* HTTP_FAILED (10) The precondition failed */
        errval = -ENXIO;
        break;

        default:
        av_log (AVLOG_ERROR, "Unknown HTTP error code for %s: %d %s",
                method, httpret, errstr);
	errval = -ENXIO;
        break;
    }
    av_log (AVLOG_DEBUG, "returning errno %d", errval);
    return errval;
}

/* ---------------------------------------------------------------------- */

static void av_get_cb (void *userdata, const char *buf, size_t len)
{
    struct davlocalfile *lf = (struct davlocalfile *) userdata;
    int res;

    av_log(AVLOG_DEBUG, "DAV: GET cb: writing %d", len);
    res = write (lf->fd, buf, len);
    if (res < 0) {
        av_log (AVLOG_ERROR, "DAV: write failed: %s", strerror(errno));
    }
    if (res != len) {
        av_log (AVLOG_ERROR, "DAV: short write to tmpfile (%i/%i)",
                res, len);
    }
    lf->currsize += len;
}

static int dav_http_get (struct davdata *davdat, struct davlocalfile *lf)
{
    const char *err;
    int res;
    struct av_dav_conn *conn = NULL;

    conn = new_dav_conn (davdat);
    if (conn == NULL) { return -1; }

    lf->fd = -1;

    if (uri_parse (lf->url, &(conn->uri), &av_dav_uri_defaults) != 0
        || conn->uri.path == NULL
        || conn->uri.host == NULL)
    {
        av_log(AVLOG_ERROR, "DAV: Invalid URI '%s'", lf->url);
        res = -1; goto error;
    }

    lf->fd = open (lf->tmpfile, O_WRONLY|O_CREAT|O_TRUNC|O_APPEND, 0700);
    if (lf->fd < 0) {
        av_log(AVLOG_ERROR, "DAV: failed to write to '%s': %s", lf->tmpfile,
                strerror (errno));
        res = -1; goto error;
    }

    http_session_server (conn->sesh, conn->uri.host, conn->uri.port);

    /* unfortunately the Neon API doesn't allow partial reads.
     * Perhaps redo this using the http.c code to avoid having
     * to download the entire file first */
    av_log(AVLOG_DEBUG, "DAV: GETting '%s'", lf->url);
    res = http_read_file (conn->sesh, lf->url, av_get_cb, lf);
    close (lf->fd); lf->fd = -1;

    if (res != HTTP_OK) {
        err = http_get_error(conn->sesh);
        res = http_error_to_errno ("GET", res, err);
        goto error;
    }

    conn->isbusy = 0;
    return 0;

error:
    conn->isbusy = 0;
    if (lf->fd > 0) { close (lf->fd); lf->fd = -1; }
    return res;
}

/* ---------------------------------------------------------------------- */

/*
 * TODO: rewrite using new "remote" API once it stabilises for writes
 */
#if 0
static int dav_http_put (struct file *fil, struct davlocalfile *lf)
{
  const char *err;
  struct av_dav_conn *conn;
  FILE *fin = NULL;
  int res;

  conn = new_dav_conn (davdat);
  if (conn == NULL) { return -1; }

  if (uri_parse (lf->url, &(conn->uri), &av_dav_uri_defaults) != 0
    || conn->uri.path == NULL
    || conn->uri.host == NULL)
  {
    av_log(AVLOG_ERROR, "DAV: Invalid URI '%s'", lf->url);
    res = -1; goto error;
  }

  http_session_server (conn->sesh, conn->uri.host, conn->uri.port);
  res = lseek (lf->fd, 0, SEEK_SET);
  if (res < 0) {
    res = -errno; goto error;
  }

  fin = fdopen (lf->fd, "r");

  /* unfortunately the Neon API doesn't allow partial writes.
   * Perhaps redo this using the http.c code
   */
  res = http_put (conn->sesh, lf->url, fin);
  if (res != HTTP_OK) {
    err = http_get_error(conn->sesh);
    res = http_error_to_errno ("PUT", res, err);
    goto error;
  }

  conn->isbusy = 0;
  if (fin != NULL) { fclose (fin); }
  close (lf->fd);
  return 0;

error:
  conn->isbusy = 0;
  if (fin != NULL) { fclose (fin); }
  close (lf->fd);
  return res;
}
#endif

/* ---------------------------------------------------------------------- */

static int dav_res_stat_to_avstat (struct av_dav_resource *res,
                struct avstat *stbuf)
{
    stbuf->mtime.sec = res->modtime;
    stbuf->mtime.nsec = 0;
    stbuf->atime = stbuf->mtime;
    stbuf->ctime = stbuf->mtime;

    stbuf->dev = 1;
    stbuf->ino = 1;
    stbuf->nlink = 1;
    stbuf->uid = 0;
    stbuf->gid = 0;
    stbuf->blksize = 1024;

    switch (res->type) {
    case resr_normal:
        stbuf->size = res->size;
        stbuf->blocks = AV_DIV(stbuf->size, 1024);
        if (res->is_executable) {
            stbuf->mode = AV_IFREG | 0777;
        } else {
            stbuf->mode = AV_IFREG | 0666;
        }
        break;

    case resr_reference:
        av_log(AVLOG_WARNING, "DAV: reference: TODO %d", res->type);
        /* symbolic link, doesn't seem to be supported by mod_dav
         * anyway
         */
        return -1;

    case resr_collection:
        stbuf->size = res->size;
        stbuf->blocks = AV_DIV(stbuf->size, 1024);
        stbuf->mode = AV_IFDIR | 0777;
        break;

    default:
        av_log(AVLOG_WARNING, "DAV: unknown resource type %d", res->type);
        return -1;
    }

    return 0;
}

/* ---------------------------------------------------------------------- */

static int
populate_av_tree_from_reslist (struct remdirlist *dl, struct av_dav_conn *conn,
                               struct av_dav_resource *reslist)
{
  struct av_dav_resource *current, *next;
  char *shortname, *endchar;
  int pathlen;

  pathlen = strlen (conn->uri.path);

  for (current = reslist; current!=NULL; current = next) {
      next = current->next;

      /* skip path at start of name, if possible. Also trim
       * out any slashes we won't need. */
      if (!strncmp (current->uri, conn->uri.path, pathlen)) {
          shortname = current->uri + pathlen;
          while (*shortname == '/') {
              shortname++;
          }
          if (shortname[0] == '\0' || !strcmp (shortname, "/")) {
            shortname = ".";
          }
      } else {
          shortname = current->uri;
      }

      endchar = shortname + (strlen(shortname)-1);
      if (*endchar == '/') { *endchar = '\0'; }

      {
          struct avstat stbuf;
          char *linkname = NULL;
          char *remname;

          remname = dl->hostpath.path;

          if (dav_res_stat_to_avstat (current, &stbuf) < 0) {
              av_log (AVLOG_WARNING,
                                "DAV: parsing direntry: to_avstat failed");
              goto skip;
          }

          av_log (AVLOG_DEBUG, "DAV: adding direntry \"%s\" mode=0%o",
                                        remname, stbuf.mode);
          av_remote_add (dl, remname, linkname, &stbuf);
      }

  skip:
      free_resource (current);
  }

  return 0;
}

/* ---------------------------------------------------------------------- */

static int dav_list(struct remote *rem, struct remdirlist *dl)
{
    char urlbuf[512];
    int res;
    struct davdata *davdat = (struct davdata *) rem->data;
    char *url;
    struct av_dav_conn *conn;
    struct av_dav_resource *reslist = NULL;
    const char *err;

    url = dav_hostpath_to_url (urlbuf, 511, &(dl->hostpath));
    av_log (AVLOG_DEBUG, "DAV: dav_list called on '%s' flags=%x",
                                        url, dl->flags);

    conn = new_dav_conn (davdat);
    if (conn == NULL) { return -1; }

    if (uri_parse (url, &(conn->uri), &av_dav_uri_defaults) != 0
      || conn->uri.path == NULL
      || conn->uri.host == NULL)
    {
        av_log(AVLOG_ERROR, "DAV: Invalid URI '%s'", url);
        res = -1; goto error;
    }

    http_session_server (conn->sesh, conn->uri.host, conn->uri.port);
    res = fetch_resource_list (conn, conn->uri.path, 1, 1, &reslist);
    if (res != HTTP_OK) {
        err = http_get_error(conn->sesh);
        res = http_error_to_errno ("PROPFIND", res, err);
        goto error;
    }

    if (reslist == NULL) {
        av_log (AVLOG_WARNING, "DAV: no reslist");
        res = -1; goto error;
    }

    if (populate_av_tree_from_reslist (dl, conn, reslist) < 0) {
        res = -1; goto error;
    }

    conn->isbusy = 0;
    return 0;

error:
    conn->isbusy = 0;
    return res;
}

/* ---------------------------------------------------------------------- */

static int dav_get(struct remote *rem, struct remgetparam *gp)
{
    int res;
    char urlbuf[512];
    struct davdata *davdat = (struct davdata *) rem->data;
    struct davlocalfile *lf;
    char *tmpfile;

    res = av_get_tmpfile(&tmpfile);
    if(res < 0) {
        return res;
    }

    AV_NEW_OBJ(lf, dav_free_localfile);

    lf->url = av_strdup (dav_hostpath_to_url
                                    (urlbuf, 511, &(gp->hostpath)));
    lf->tmpfile = tmpfile;
    lf->currsize = 0;
    lf->fd = -1;

    res = dav_http_get (davdat, lf);

    if (res < 0) {
        av_unref_obj(lf);
        av_free(lf->url);
        av_del_tmpfile(lf->tmpfile);
        return res;
    }

    gp->data = lf;
    gp->localname = lf->tmpfile;

    return 0;
}

/* ---------------------------------------------------------------------- */

static int dav_wait(struct remote *rem, void *data, avoff_t end)
{
    return 1;
}

/* ---------------------------------------------------------------------- */

static int dav_init_ctl(struct vmodule *module, struct davdata *davdat)
{
    int res;
    struct namespace *ns;
    struct statefile *stf;
    struct entry *ent;
    struct avfs *avfs;

    res = av_state_new(module, "dav_ctl", &ns, &avfs);
    if(res < 0)
        return res;

    ent = av_namespace_lookup(ns, NULL, "username");
    AV_NEW(stf);
    stf->data = &(davdat->sessions);
    stf->get = pass_username_get;
    stf->set = pass_username_set;
    av_namespace_set(ent, stf);

    ent = av_namespace_lookup(ns, NULL, "password");
    AV_NEW(stf);
    stf->data = &(davdat->sessions);
    stf->get = pass_password_get;
    stf->set = pass_password_set;
    av_namespace_set(ent, stf);

    ent = av_namespace_lookup(ns, NULL, "loggedin");
    AV_NEW(stf);
    stf->data = &(davdat->sessions);
    stf->get = pass_loggedin_get;
    stf->set = pass_loggedin_set;
    av_namespace_set(ent, stf);

    av_unref_obj(ns);

    return 0;
}

/* ---------------------------------------------------------------------- */

static void dav_destroy(struct remote *rem)
{
    struct davdata *davdat = (struct davdata *) rem->data;

    av_free (davdat);
    av_free (rem->name);
    av_free (rem);
}

/* ---------------------------------------------------------------------- */

int av_init_module_dav(struct vmodule *module)
{
    int res;
    struct remote *rem;
    struct avfs *avfs;
    struct davdata *davdat;

    av_log(AVLOG_DEBUG, "DAV: initializing");

    sock_init();

    AV_NEW(davdat);
    memset (&(davdat->allconns), 0, sizeof(davdat->allconns));

    snprintf (AV_UserAgent, 127, "AVFSCoda/%d", AV_VER);

    AV_NEW(rem);

    rem->data    = davdat;
    rem->flags   = REM_DIR_ONLY;
    rem->name    = av_strdup("dav");
    rem->list    = dav_list;
    rem->get     = dav_get;
    rem->wait    = dav_wait;
    rem->destroy = dav_destroy;

    res = av_remote_init(module, rem, &avfs);
    if (res == 0) {
	res = dav_init_ctl (module, davdat);
	if (res < 0) {
	    av_unref_obj(avfs);
	}
    }

    return 0;
}

// vim:sw=4:
