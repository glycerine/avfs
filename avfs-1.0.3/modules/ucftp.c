/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000  Miklos Szeredi <miklos@szeredi.hu>
    Copyright (C) 2010  Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
/*
 * This file is based on volatile.c and ftp.c and the write patch for
 * ftp.c from the Zemljanka Commander team
 */

#include "avfs.h"
#include "version.h"
#include "state.h"
#include "socket.h"
#include "filebuf.h"
#include "parsels.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define USER_SEP_STR  "@"
#define USER_SEP_CHAR (USER_SEP_STR[0])

#define FTP_REPLY_TIMEOUT 30000
#define FTP_READ_TIMEOUT 60000

#define UCFTP_ST_VALID 20
#define UCFTP_DIR_VALID 10

/***************************************
 * some internal structures
 ***************************************/

struct ucftpconn {
    char *host;
    char *user;
    char *password;
    int busy;
    int sock;
    struct filebuf *sockfb;
    struct ucftpconn *next;
    int binary;
    char *cwd;
    short ft_cancel_ok;

    struct ucftpentry *root;
};

struct ucftpfile {
    struct ucftpentry *ent;     /* corresponding entry */
    int flags;
    
    /* the following entries are used for files */
    int sock;
    struct filebuf *sockfb;
    avoff_t numbytes;
    struct ucftpconn *conn;
    int writing;
    short eof;
};

/* a generic information node */
/* analogous to the "on-disk inode" in a disk filesystem */
struct ucftpnode {
    struct avstat st;
    char *linkname;
    avtime_t valid;
    struct ucftpentry *subdir;  /* only dir */
    struct ucftpentry *parent;  /* only dir */
};

/* our ventry.data handle */
/* represents a named reference to a ucftpnode */
struct ucftpentry {
    char *name;
    struct ucftpnode *node;
    struct ucftpentry *next;
    struct ucftpentry **prevp;
    struct ucftpentry *parent;
};

struct ucftpsession {
    char *account;
    char *password;
    struct ucftpsession *next;
    struct ucftpsession *prev;
};

/* our vmount.data handle */
struct ucftpfs {
    struct avfs *avfs;
    struct ucftpconn *conns;
    struct ucftpsession sessions;
};

enum ucftp_op { OP_DELE = 0, OP_MKD = 1, OP_RMD = 2};
char *ucftp_op_cmd[3] = { "DELE ", "MKD ", "RMD " };
    
/***************************************
 * some access functions for generic
 * avfs structure
 ***************************************/

static struct ucftpentry *ucftp_ventry_ucftpentry(ventry *ve)
{
    return (struct ucftpentry *) ve->data;
}

static struct ucftpfs *ucftp_ventry_ucftpfs(ventry *ve)
{
    return (struct ucftpfs *) ve->mnt->avfs->data;
}

static struct ucftpfile *ucftp_vfile_ucftpfile(vfile *vf)
{
    return (struct ucftpfile *) vf->data;
}

static struct ucftpfs *ucftp_vfile_fs(vfile *vf)
{
    return (struct ucftpfs *) vf->mnt->avfs->data;
}

/***************************************
 * some generic code
 ***************************************/

static void strip_crlf(char *line)
{
    avsize_t len = strlen(line);
    
    if(len > 0 && line[len-1] == '\n') {
        if(len > 1 && line[len-2] == '\r')
            line[len-2] = '\0';
        else
            line[len-1] = '\0';
    }
}

static int write_socket(int sock, const char *buf, avsize_t buflen)
{
    int res;

    while(buflen > 0) {
        res = write(sock, buf, buflen);
        if(res == -1)
            return -errno;
        
        buf += res;
        buflen -= res;
    }

    return 0;
}

static int ucftp_get_addrbytes(const char *line, int addrbytes[6])
{
    int i;
    int j;
    int val;
    const char *s;

    for(s = line; *s && *s != '('; s++);
    if(!*s)
        return -1;

    s++;
    for(i = 0; i < 6; i++) {
        val = 0;
        for(j = 0; j < 3; j++) {
            if(!isdigit((int) *s))
                return -1;
            val = val * 10 + (*s - '0');
            s++;
            if(*s == ',' || *s == ')')
                break;
        }
        if(*s != ',' && *s != ')')
            return -1;
        addrbytes[i] = val;
        if(*s == ')')
            break;
        s++;        
    }
    if(i != 5 || *s != ')')
        return -1;

    return 0;
}

/***************************************
 * session code
 ***************************************/

static struct ucftpsession *ucftp_find_session(struct ucftpfs *fs,
                                               const char *account)
{
    struct ucftpsession *fts;

    for(fts = fs->sessions.next; fts != &fs->sessions; fts = fts->next) {
        if(strcmp(account, fts->account) == 0)
            return fts;
    }
    
    return NULL;
}

static struct ucftpsession *ucftp_get_session(struct ucftpfs *fs,
                                              const char *account)
{
    struct ucftpsession *fts;
    
    fts = ucftp_find_session(fs, account);
    if(fts == NULL) {
        struct ucftpsession *next;
        struct ucftpsession *prev;

        AV_NEW(fts);
        fts->account = av_strdup(account);
        fts->password = NULL;

        fts->next = next = fs->sessions.next;
        fts->prev = prev = &fs->sessions;
        next->prev = fts;
        prev->next = fts;
    }
    
    return fts;
}

static void ucftp_remove_session(struct ucftpsession *fts)
{
    struct ucftpsession *next = fts->next;
    struct ucftpsession *prev = fts->prev;
    
    next->prev = prev;
    prev->next = next;

    av_free(fts->account);
    av_free(fts->password);
    av_free(fts);
}

/***************************************
 * code for password/hostname/path splitting
 ***************************************/

static const char *ucftp_get_password(struct ucftpfs *fs, const char *host,
                                      const char *user)
{
    struct ucftpsession *fts;
    char *account;

    account = av_stradd(NULL, user, USER_SEP_STR, host, NULL);
    fts = ucftp_find_session(fs, account);
    av_free(account);
    if(fts == NULL) {
        account = av_stradd(NULL, user, USER_SEP_STR, NULL);
        fts = ucftp_find_session(fs, account);
        av_free(account);
    }
    
    if(fts != NULL)
        return fts->password;
    else
        return NULL;
}

static int ucftp_split_path(struct ucftpfs *fs, char *hostpart,
                            const char **hostp, const char **userp,
                            const char **passp)
{
    char *s, *t;
    const char *host;
    const char *user;
    const char *pass;

    for(s = hostpart; *s && *s != USER_SEP_CHAR; s++);
    for(t = s; *t; t++) if (*t == USER_SEP_CHAR) s = t;
    if(*s != '\0') {
        *s = '\0';
        host = s + 1;
        user = hostpart;
        pass = ucftp_get_password(fs, host, user);
        if(pass == NULL)
            return -EACCES;
    }
    else {
        host = hostpart;
        user = "ftp";
        pass = "avfs@";
    }

    if(host[0] == '\0')
        return -ENOENT;

    *hostp = host;
    *userp = user;
    *passp = pass;

    return 0;
}

/***************************************
 * ucftpentry constructor and destructor
 ***************************************/

/* av_obj.destr for ucftpentry */
static void ucftp_entry_destr(struct ucftpentry *ent)
{
    if(ent->prevp != NULL)
        *ent->prevp = ent->next;
    if(ent->next != NULL)
        ent->next->prevp = ent->prevp;
    av_unref_obj(ent->parent);
    av_free(ent->name);

    ent->prevp = NULL;
    ent->next = NULL;
    ent->parent = NULL;
    ent->name = NULL;
}

/* constructor for ucftpentry */
static struct ucftpentry *ucftp_new_entry(const char *name)
{
    struct ucftpentry *ent;

    AV_NEW_OBJ(ent, ucftp_entry_destr);

    ent->node = NULL;
    ent->next = NULL;
    ent->prevp = NULL;
    ent->parent = NULL;
    ent->name = av_strdup(name);

    return ent;
}

/***************************************
 * ucftpnode constructor and destructor
 ***************************************/

/* av_obj.destr for ucftpnode */
static void ucftp_node_destr(struct ucftpnode *nod)
{
    if(nod->linkname != NULL)
        av_free(nod->linkname);
}

/* constructor for ucftpnode */
static struct ucftpnode *ucftp_new_node(struct avstat *initstat)
{
    struct ucftpnode *nod;

    AV_NEW_OBJ(nod, ucftp_node_destr);
    
    nod->st = *initstat;
    nod->subdir = NULL;
    nod->parent = NULL;
    nod->valid = 0;
    nod->linkname = NULL;

    return nod;
}

/***************************************
 * code for node handling
 ***************************************/

/* link ent to nod */
static void ucftp_link_node(struct ucftpentry *ent, struct ucftpnode *nod)
{
    //TODO why do we get an ref from ent but not ent->parent (in case it exists)?
    av_ref_obj(ent);
    av_ref_obj(nod);
    ent->node = nod;
    
    if(AV_ISDIR(nod->st.mode)) {
        nod->st.nlink = 2;
        if(ent->parent != NULL) {
            nod->parent = ent->parent;
            ent->parent->node->st.nlink ++;
        }
        else 
            nod->parent = ent;
    }
    else
        nod->st.nlink ++;

    if(ent->parent != NULL)
        ent->parent->node->st.size ++;    
}

static void ucftp_unlink_node(struct ucftpentry *ent)
{
    struct ucftpnode *nod = ent->node;
    
    if(AV_ISDIR(nod->st.mode)) {
        nod->st.nlink = 0;
        if(nod->parent != NULL)
            nod->parent->node->st.nlink --;
    }
    else
        nod->st.nlink --;

    if(ent->parent != NULL)
        ent->parent->node->st.size --;

    ent->node = NULL;
    av_unref_obj(nod);
    av_unref_obj(ent);
}

static int ucftp_make_node(struct ucftpfs *fs, struct ucftpentry *ent, avmode_t mode)
{
    struct ucftpnode *nod;
    struct avstat initstat;

    if(ent->name == NULL)
        return -ENOENT;

    av_default_stat(&initstat);
    
    initstat.dev = fs->avfs->dev;
    initstat.ino = av_new_ino(fs->avfs);

    nod = ucftp_new_node(&initstat);
    nod->st.mode = mode;
    
    ucftp_link_node(ent, nod);
    av_unref_obj(nod);

    return 0;
}

static int ucftp_is_valid_node(struct ucftpnode *node)
{
    avtime_t now = av_time();

    if(now < node->valid)
        return 1;
    return 0;
}

static void ucftp_truncate_node(struct ucftpnode *nod, avoff_t length)
{
    nod->st.size = length;
    nod->st.blocks = AV_DIV(nod->st.size, 512);
    av_curr_time(&nod->st.mtime);
}

/***************************************
 * entry handling
 ***************************************/

static int ucftp_add_subentry(struct ucftpentry *parent, struct ucftpentry *ent, struct ucftpentry **startp)
{
    struct ucftpentry **entp;

    if(startp == NULL) {
        entp = &parent->node->subdir;
    } else {
        entp = startp;
    }

    for(; *entp != NULL; entp = &(*entp)->next);

    *entp = ent;
    ent->prevp = entp;
    
    ent->parent = parent;
    av_ref_obj(parent);
    
    ent->next = NULL;
    
    return 0;
}

static struct ucftpentry *find_list_entry(struct ucftpentry *oldlist, const char *filename)
{
    for(; oldlist != NULL; oldlist = oldlist->next) {
        if(strcmp(oldlist->name, filename) == 0)
            break;
    }
    return oldlist;
}

static void list_remove_entry(struct ucftpentry *ent)
{
    if(ent == NULL)
        return;
    
    if(ent->prevp != NULL)
        *ent->prevp = ent->next;
    if(ent->next != NULL)
        ent->next->prevp = ent->prevp;
    
    ent->prevp = NULL;
    ent->next = NULL;
}

/* free a all subentries from a given entry */
static void ucftp_free_tree(struct ucftpentry *ent)
{
    struct ucftpnode *nod = ent->node;

    if(nod != NULL) {
        while(nod->subdir != NULL)
            ucftp_free_tree(nod->subdir);
        
        ucftp_unlink_node(ent);
    } else {
        av_unref_obj(ent);
    }
}

/* called by ucftp_getpath */
static char *ucftp_create_path(struct ucftpentry *ent)
{
    char *path;
    
    if(ent->parent == NULL)
        return av_strdup("");
    
    path = ucftp_create_path(ent->parent);

    return av_stradd(path, "/", ent->name, NULL);
}

static int ucftp_getpath(ventry *ve, char **resp)
{
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);

    *resp = ucftp_create_path(ent);

    return 0;
}

static void ucftp_free_dirlist(struct ucftpentry *ent)
{
    if(ent->node != NULL) {
        struct ucftpentry *subent = ent->node->subdir;
        
        while(subent != NULL) {
            ucftp_free_tree(subent);

            subent = ent->node->subdir;
        }
    }
}

static void unref_list_parent(struct ucftpentry *list)
{
    while(list != NULL) {
        av_unref_obj(list->parent);
        list->parent = NULL;
        list = list->next;
    }
}

static void free_entry_list(struct ucftpentry *list)
{
    while(list != NULL) {
        struct ucftpentry *ent = list;
        list = list->next;
        
        list_remove_entry(ent);
        ucftp_free_tree(ent);
    }
}

static struct ucftpconn *ucftp_find_conn(struct ucftpfs *fs, struct ucftpentry *ent)
{
    struct ucftpconn *conn;

    while(ent->parent != NULL)
        ent = ent->parent;

    conn = fs->conns;
    while(conn != NULL) {
        if(conn->root == ent)
            break;
        conn = conn->next;
    }
    return conn;
}

static struct ucftpconn *ucftp_find_conn_ventry(ventry *ve)
{
    struct ucftpfs *fs = ucftp_ventry_ucftpfs(ve);
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);
    return ucftp_find_conn(fs, ent);
}

static void ucftp_putent(ventry *ve)
{
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);

    av_unref_obj(ent);
}

static int ucftp_copyent(ventry *ve, void **resp)
{
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);
    
    av_ref_obj(ent);

    *resp = (void *) ent;

    return 0;
}

/***************************************
 * connection code
 ***************************************/

static void ucftp_release_conn(struct ucftpconn *conn)
{
    conn->busy = 0;
}

static void ucftp_close_conn(struct ucftpconn *conn)
{
    av_unref_obj(conn->sockfb);
    conn->sockfb = NULL;
    conn->sock = -1;
    conn->binary = -1;
    conn->cwd[0] = '\0';
}

/* get a line from a connection */
static int ucftp_get_line(struct ucftpconn *conn, char **linep)
{
    int res;
    char *line;
    
    res = av_filebuf_getline(conn->sockfb, &line, FTP_REPLY_TIMEOUT);
    if(res <= 0 || line == NULL) {
        ucftp_close_conn(conn);
        if(res < 0)
            return res;

        if(res == 0)
            av_log(AVLOG_ERROR, "FTP: timeout waiting for reply");
        else
            av_log(AVLOG_ERROR, "FTP: server closed ftpconn");

        return -EIO;
    }

    strip_crlf(line);
    *linep = line;

    return 0;
}

static int ucftp_check_reply(struct ucftpconn *conn, const char *line)
{
    int reply;

    if(strlen(line) < 4 || !isdigit((int) line[0]) ||
       !isdigit((int) line[1]) || !isdigit((int) line[2]) ||
       (line[3] != ' ' && line[3] != '-')) {
        ucftp_close_conn(conn);
        av_log(AVLOG_ERROR, "FTP: malformed reply: %s", line);
        return -EIO;
    }

    reply = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');

    if(reply == 421)
        ucftp_close_conn(conn);

    return reply;
}

static int ucftp_wait_reply_code(struct ucftpconn *conn)
{
    int res;
    char *line;
    char replystr[4];
    int firstline = 1;
    int cont;
    int replycode = 0;
    
    do {
        cont = 0;
        res = ucftp_get_line(conn, &line);
        if(res < 0)
            return res;

        if(firstline) {
            res = ucftp_check_reply(conn, line);
            if(res < 0) {
                av_free(line);
                return res;
            }

            replycode = res;

            if(line[3] == '-') {
                strncpy(replystr, line, 3);
                replystr[3] = ' ';
                firstline = 0;
                cont = 1;
            }
        }
        else if(strncmp(line, replystr, 4) != 0)
            cont = 1;

        if(replycode >= 400)
            av_log(AVLOG_ERROR, "FTP: %s", line);
        else
            av_log(AVLOG_DEBUG, "FTP: %s", line);

        av_free(line);
    } while(cont);
 
    return replycode;
}

static int ucftp_write_command(struct ucftpconn *conn, const char *cmd)
{
    char *line;
    int res;

    if(strncmp(cmd, "PASS ", 5) == 0)
        av_log(AVLOG_DEBUG, "FTP: PASS *");
    else
        av_log(AVLOG_DEBUG, "FTP: %s", cmd);

    line = av_stradd(NULL, cmd, "\r\n", NULL);
    res = write_socket(conn->sock, line, strlen(line));
    av_free(line);

    return res;
}

static int ucftp_command(struct ucftpconn *conn, const char *cmd)
{
    int res;

    res = ucftp_write_command(conn, cmd);
    if(res < 0)
        return res;

    res = ucftp_wait_reply_code(conn);
    
    return res;
}

static int ucftp_set_ascii(struct ucftpconn *conn)
{
    int res;

    if(conn->binary != 0) {
        res = ucftp_command(conn, "TYPE A");
        if(res < 0)
            return res;

        conn->binary = 0;
    }

    return 0;
}

static int ucftp_set_binary(struct ucftpconn *conn)
{
    int res;

    if(conn->binary != 1) {
        res = ucftp_command(conn, "TYPE I");
        if(res < 0)
            return res;

        conn->binary = 1;
    }

    return 0;
}

static int ucftp_set_cwd(struct ucftpconn *conn, const char *dir)
{
    int res;
    char *cmd;

    if(strcmp(conn->cwd, dir) != 0) {
        cmd = av_stradd(NULL, "CWD ", ( dir[0] == '\0' ) ? "/" : dir, NULL);
        res = ucftp_command(conn, cmd);
        av_free(cmd);
        if(res < 0)
            return res;
        
        if(res == 550)
            return -ENOENT;
        if(res / 100 != 2)
            return -EIO;

        av_free(conn->cwd);
        conn->cwd = av_strdup(dir);
    }

    return 0;
}

static int ucftp_login(struct ucftpconn *conn)
{
    int res;
    char *cmd;

    cmd = av_stradd(NULL, "USER ", conn->user, NULL);
    res = ucftp_command(conn, cmd);
    av_free(cmd);

    if(res == 331) {
        cmd = av_stradd(NULL, "PASS ", conn->password, NULL);
        res = ucftp_command(conn, cmd);
        av_free(cmd);
        if(res < 0)
            return res;
    }

    if(res != 230)
        return -EACCES;

    return 0;
}

static int ucftp_init_conn(struct ucftpconn *conn)
{
    int res;

    res = ucftp_wait_reply_code(conn);
    if(res == 120)
        res = ucftp_wait_reply_code(conn);
    
    if(res < 0)
        return res;

    if(res != 220)
        return -EIO;
    
    res = ucftp_login(conn);
    if(res < 0)
        return res;

    ucftp_command(conn, "PWD");
    ucftp_command(conn, "SYST");

    return 0;
}

static int ucftp_open_conn(struct ucftpconn *conn)
{
    int res;

    if(conn->sock != -1) {
        res = ucftp_command(conn, "NOOP");
        if(res < 0)
            return res;
        
        if(res != 421)
            return 0;
    }

    res = av_sock_connect(conn->host, 21);
    if(res < 0)
        return res;

    conn->sock = res;
    conn->sockfb = av_filebuf_new(conn->sock, 0);

    res = ucftp_init_conn(conn);
    if(res < 0) {
        ucftp_close_conn(conn);
        return res;
    }

    return 0;
}

static int ucftp_check_passv_reply(struct ucftpconn *conn, const char *line,
                                   char **resp)
{
    int res;
    int replycode;
    int addrbytes[6];
    char addrbuf[128];
    int port;
    
    res = ucftp_check_reply(conn, line);
    if(res < 0)
        return res;

    replycode = res;
    
    if(replycode != 227) {
        av_log(AVLOG_ERROR, "FTP: %s", line);
        ucftp_close_conn(conn);
        return -EIO;
    }
    
    av_log(AVLOG_DEBUG, "FTP: %s", line);
        
    if(line[3] != ' ') {
        av_log(AVLOG_ERROR, "FTP: Multiline reply to PASV: %s", line);
        ucftp_close_conn(conn);
        return -EIO;
    }

    res = ucftp_get_addrbytes(line, addrbytes);
    if(res < 0) {
        av_log(AVLOG_ERROR, "FTP: Bad reply to PASV: %s", line);
        ucftp_close_conn(conn);
        return -EIO;
    }

    port = addrbytes[4] * 0x100 + addrbytes[5];
    sprintf(addrbuf, "%i.%i.%i.%i:%i", 
            addrbytes[0], addrbytes[1], addrbytes[2], addrbytes[3], port);

    *resp = av_strdup(addrbuf);

    return 0;
}

static int ucftp_open_dataconn(struct ucftpconn *conn)
{
    int res;
    char *line;
    char *host;

    res = ucftp_write_command(conn, "PASV");
    if(res < 0)
        return res;

    res = ucftp_get_line(conn, &line);
    if(res < 0)
        return res;

    res = ucftp_check_passv_reply(conn, line, &host);
    av_free(line);
    if(res < 0)
        return res;

    av_log(AVLOG_DEBUG,"FTP: remote data address: %s", host);
    
    res = av_sock_connect(host, -1);
    if(res >= 0)
       av_registerfd(res);

    av_free(host);
    
    return res;
}

static struct ucftpconn *ucftp_lookup_conn(struct ucftpfs *fs, const char *host,
                                           const char *user, const char *password)
{
    struct ucftpconn *conn;
    struct ucftpconn **cp;

    for(cp = &fs->conns; *cp != NULL; cp = &(*cp)->next) {
        conn = *cp;

        if(strcmp(conn->host, host) == 0 && strcmp(conn->user, user) == 0 &&
           strcmp(conn->password, password) == 0 && !conn->busy) {
            conn->busy = 1;
            return conn;
        }
    }

    AV_NEW(conn);
    
    conn->host = av_strdup(host);
    conn->user = av_strdup(user);
    conn->password = av_strdup(password);
    conn->busy = 1;
    conn->sock = -1;
    conn->sockfb = NULL;
    conn->next = NULL;
    conn->binary = -1;
    conn->cwd = av_strdup("");
    conn->ft_cancel_ok = 1;
    
    conn->root = ucftp_new_entry("/");
    ucftp_make_node(fs, conn->root, 0755 | AV_IFDIR);
    
    *cp = conn;
    
    return conn;
}

static int ucftp_get_conn(struct ucftpfs *fs, const char *userhost,
                          struct ucftpconn **resp)
{
    int res;
    char *tmps;
    const char *host;
    const char *user;
    const char *password;
    struct ucftpconn *conn = NULL;

    tmps = av_strdup(userhost);
    res = ucftp_split_path(fs, tmps, &host, &user, &password);
    if(res == 0)
        conn = ucftp_lookup_conn(fs, host, user, password);

    av_free(tmps);

    if(res < 0)
        return res;

    *resp = conn;

    return 0;
}

/***************************************
 * ucftpfile constructor and destructor
 ***************************************/

#define TRY_REUSE_CONN_AFTER_CLOSE

static void ucftp_free_file(struct ucftpfile *f)
{
#ifndef TRY_REUSE_CONN_AFTER_CLOSE
    if(f->conn != NULL) {
        ucftp_close_conn(f->conn);
        ucftp_release_conn(f->conn);
    }
#endif
    av_unref_obj(f->sockfb);
    
    if(f->sock >= 0)
        close(f->sock);

#ifdef TRY_REUSE_CONN_AFTER_CLOSE
    /* if control connection is busy try to wait for reply, often
       closing the data socket will bring the control connection back
       to life */
    if ( f->conn != NULL ) {
        if ( f->conn->busy ) {
            if ( f->conn->ft_cancel_ok ) {
                int res = ucftp_wait_reply_code(f->conn);

                if(res >= 0 && ( res / 10 == 45 || res == 426 ) ) {
                    /* code 45x and 426 is acceptable here, server reported abort */
                } else if(res >= 0 && res / 100 != 2)
                    res = -EIO;
                
                if(res < 0) {
                    av_log( AVLOG_WARNING, "UCFTP: canceling file transfer and reuse connection failed\n" );

                    f->conn->ft_cancel_ok = 0;
                    ucftp_close_conn(f->conn);
                }
                
                ucftp_release_conn(f->conn);
            } else {
                ucftp_close_conn(f->conn);
                ucftp_release_conn(f->conn);
            }
        }
    }
#endif
    
    f->sock = -1;
    f->sockfb = NULL;
    f->numbytes = 0;
    f->conn = NULL;
    f->writing = 0;
    f->eof = 0;
    
    av_unref_obj(f->ent);
    f->ent = NULL;
}

static struct ucftpfile *ucftp_new_file(struct ucftpentry *ent, int flags)
{
    struct ucftpfile *f;
    
    AV_NEW_OBJ(f, ucftp_free_file);
    
    f->sock = -1;
    f->sockfb = NULL;
    f->numbytes = 0;
    f->conn = NULL;
    f->flags = flags;
    f->writing = 0;
    f->eof = 0;

    av_ref_obj(ent);
    f->ent = ent;
    
    return f;
}

static int ucftp_init_file(struct ucftpfile *lf, int sock)
{
    lf->sock = sock;
    lf->sockfb = NULL;
    lf->numbytes = 0;
    lf->conn = NULL;
    lf->writing = 0;
    lf->eof = 0;

    lf->sockfb = av_filebuf_new(lf->sock, 0);

    return 0;
}

/***************************************
 * dir reading code
 ***************************************/

static int ucftp_read_list(struct ucftpfs *fs, struct filebuf *fb, struct ucftpentry *ent,
                           struct lscache *lc)
{
    int res;
    char *line;
    int eof = 0;
    avtime_t now = av_time();
    struct ucftpentry *oldlist, **entp;

    /* release current subdir and save it locally */
    oldlist = ent->node->subdir;
    if(oldlist != NULL) {
        oldlist->prevp = &oldlist;
        ent->node->subdir = NULL;
    }
    unref_list_parent(oldlist);

    entp = &ent->node->subdir;

    do {
        res = av_filebuf_getline(fb, &line, FTP_READ_TIMEOUT);
        if(res < 0) {
            free_entry_list(oldlist);
            return res;
        }
        
        if(res == 0) {
            free_entry_list(oldlist);
            av_log(AVLOG_ERROR, "FTP: read timeout");
            return -EIO;
        }
        if(line == NULL)
            eof = 1;
        else {
            struct avstat stbuf;
            char *filename;
            char *linkname;
            strip_crlf(line);
            
            av_log(AVLOG_DEBUG, "FTP: %s", line);
            res = av_parse_ls(lc, line, &stbuf, &filename, &linkname);
            av_free(line);
            if(res == 1) {
                struct ucftpentry *subent = NULL;
                int res2;

                if(strcmp(filename, "..") != 0 &&
                   strcmp(filename, ".") != 0 ) {

                    subent = find_list_entry(oldlist, filename);
                    if(subent != NULL) {
                        list_remove_entry(subent);
                    } else {
                        subent = ucftp_new_entry(filename);
                    }
                    if(subent->node == NULL) {
                        res2 = ucftp_make_node(fs, subent, stbuf.mode);
                        av_unref_obj(subent);
                    }
                    ucftp_add_subentry(ent, subent, entp);
                    entp = &subent->next;

                    /* re-use some old values */
                    if(subent->node != NULL) {
                        stbuf.dev = subent->node->st.dev;
                        stbuf.ino = subent->node->st.ino;
                    }

                    subent->node->st = stbuf;
                    if(subent->node->linkname != NULL) {
                        av_free(subent->node->linkname);
                    }
                    if(linkname != NULL) {
                        subent->node->linkname = av_strdup(linkname);
                    } else {
                        subent->node->linkname = NULL;
                    }
                }
                
                av_free(filename);
                av_free(linkname);
            }
        }
    } while(!eof);
    
    ent->node->valid = now + UCFTP_DIR_VALID;

    free_entry_list(oldlist);
    
    return 0;
}

static int ucftp_do_list(struct ucftpfs *fs, struct ucftpconn *conn, const char *dir, 
                         struct ucftpentry *ent)
{
    int res;
    char *cmd;
    int listsock;
    struct filebuf *fb;
    struct lscache *lc;

    res = ucftp_open_conn(conn);
    if(res < 0)
        return res;

    res = ucftp_set_ascii(conn);
    if(res < 0)
        return res;
    
    res = ucftp_set_cwd(conn, dir);
    if(res < 0)
        return res;

    res = ucftp_open_dataconn(conn);
    if(res < 0)
        return res;
        
    listsock = res;
    cmd = av_strdup("LIST -al");
    res = ucftp_command(conn, cmd);
    av_free(cmd);
    if(res >= 0 && res / 100 != 1)
        res = -EIO;
    
    if(res < 0) {
        close(listsock);
        return res;
    }
    
    fb = av_filebuf_new(listsock, 0);
    lc = av_new_lscache();
    res = ucftp_read_list(fs, fb, ent, lc);
    av_unref_obj(lc);
    av_unref_obj(fb);

    res = ucftp_wait_reply_code(conn);
    if(res >= 0 && res / 100 != 2)
        res = -EIO;

    if(res < 0) {
        ucftp_free_dirlist(ent);
        return res;
    }

    return 0;
}

static int ucftp_list(struct ucftpfs *fs, struct ucftpconn *conn, struct ucftpentry *ent)
{
    int res;
    char *path;

    path = ucftp_create_path(ent);
    
    res = ucftp_do_list(fs, conn, path, ent);

    ucftp_release_conn(conn);
    av_free(path);

    return res;
}

/* called by ucftp_nth_entry */
static struct ucftpnode *ucftp_special_entry(int n, struct ucftpnode *nod,
                                      const char **namep)
{
    if(n == 0) {
        *namep = ".";
        return nod;
    }
    else {
        *namep = "..";
        return nod->parent->node;
    }
}

/* called by ucftp_readdir */
static struct ucftpnode *ucftp_nth_entry(int n, struct ucftpnode *nod,
                                     const char **namep)
{
    struct ucftpentry *ent;
    int i;

    if(nod->parent != NULL) {
        //TODO should I rather not handling these special entries here?
        if(n  < 2)
            return ucftp_special_entry(n, nod, namep);

        n -= 2;
    }

    ent = nod->subdir;
    for(i = 0; i < n && ent != NULL; i++)
        ent = ent->next;
    
    if(ent == NULL)
        return NULL;

    *namep = ent->name;
    return ent->node;
}

static int ucftp_readdir(vfile *vf, struct avdirent *buf)
{
    struct ucftpfile *parentfile = ucftp_vfile_ucftpfile(vf);
    struct ucftpnode *parent = parentfile->ent->node;
    struct ucftpnode *nod;
    const char *name;
    
    if(!AV_ISDIR(parent->st.mode))
        return -ENOTDIR;
    
    if(!ucftp_is_valid_node(parent)) {
        //get dir list from ftp
        
        struct ucftpconn *conn;
        int res;
        
        conn = ucftp_find_conn(ucftp_vfile_fs(vf), parentfile->ent);
        res = ucftp_list(ucftp_vfile_fs(vf), conn, parentfile->ent);
        if(res < 0) {
            //TODO do something? aborting?
        }
    }

    nod = ucftp_nth_entry(vf->ptr, parent, &name);
    if(nod == NULL)
        return 0;

    buf->name = av_strdup(name);
    buf->ino = nod->st.ino;
    buf->type = AV_TYPE(nod->st.mode);
    
    vf->ptr ++;
    
    return 1;
}

/***************************************
 * entry look up code
 ***************************************/

/* called by ucftp_do_lookup */
static struct ucftpentry *ucftp_get_entry(struct ucftpentry *parent,
                                          const char *name)
{
    struct ucftpentry **entp;
    struct ucftpentry *ent;

    if(strcmp(name, ".") == 0) {
        ent = parent;
	av_ref_obj(ent);
	return ent;
    }
    if(strcmp(name, "..") == 0) {
        ent = parent->parent;
	av_ref_obj(ent);
	return ent;
    }
    for(entp = &parent->node->subdir; *entp != NULL; entp = &(*entp)->next)
	if(strcmp(name, (*entp)->name) == 0) {
	    ent = *entp;
	    av_ref_obj(ent);
	    return ent;
	}

    /* lookup failed, so create a new entry and add it to the
       directory list temporarily */
 
    ent = ucftp_new_entry(name);
    
    *entp = ent;
    ent->prevp = entp;
    ent->parent = parent;
    av_ref_obj(parent);

    return ent;
}

/* called by ucftp_lookup */
static int ucftp_do_lookup(ventry *ve, const char *name,
                           struct ucftpentry **entp)
{
    struct ucftpentry *parent = ucftp_ventry_ucftpentry(ve);
    
    if(parent->node == NULL)
        return -ENOENT;

    if(name == NULL) {
        *entp = parent->parent;
        av_ref_obj(*entp);
        return 0;
    }

    if(!AV_ISDIR(parent->node->st.mode))
        return -ENOTDIR;

    if(!ucftp_is_valid_node(parent->node)) {
        //get dir list from ftp
        
        struct ucftpconn *conn;
        struct ucftpfs *fs = ucftp_ventry_ucftpfs(ve);
        int res;

        conn = ucftp_find_conn_ventry(ve);
        res = ucftp_list(fs, conn, parent);
        if(res < 0) {
            //TODO do something? aborting?
        }
    }

    *entp = ucftp_get_entry(parent, name);
    
    return 0;
}

/* called by ucftp_lookup */
static struct ucftpentry *ucftp_get_root(struct ucftpconn *conn)
{
    struct ucftpentry *root = conn->root;

    av_ref_obj(root);

    return root;
}

static int ucftp_lookup(ventry *ve, const char *name, void **newp)
{
    int res = 0;
    struct ucftpentry *parent = ucftp_ventry_ucftpentry(ve);
    struct ucftpentry *ent;

    if(parent == NULL) {
        struct ucftpconn *conn;

        if(ve->mnt->opts[0] != '\0')
            return -ENOENT;

        res = ucftp_get_conn(ucftp_ventry_ucftpfs(ve), name, &conn);
        if ( res < 0 )
            return res;

        ent = ucftp_get_root(conn);
        ucftp_release_conn(conn);
    }
    else {
        res = ucftp_do_lookup(ve, name, &ent);
        if(res < 0)
            return res;

        // it's ref'd in previous lookup but not freed by using putent
        // so we need to do it here
        av_unref_obj(parent);
    }

    *newp = ent;

    if(ent != NULL && ent->node != NULL)
        return AV_TYPE(ent->node->st.mode);
    else
        return 0;
}

/***************************************
 * write code (put)
 ***************************************/

static int ucftp_do_put(const char *dir, const char *file,
                        struct ucftpconn *conn, struct ucftpfile *uf)
{
    int res;
    int putsock;
    char *cmd;

    res = ucftp_open_conn(conn);
    if(res < 0)
        return res;

    res = ucftp_set_binary(conn);
    if(res < 0)
        return res;
    
    res = ucftp_set_cwd(conn, dir);
    if(res < 0)
        return res;

    res = ucftp_open_dataconn(conn);
    if(res < 0)
        return res;

    putsock = res;
    cmd = av_stradd(NULL, "STOR ", file, NULL);
    res = ucftp_command(conn, cmd);
    av_free(cmd);
    if(res >= 0 && res / 100 != 1)
        res = -EIO;
    
    if(res < 0) {
        close(putsock);
        return res;
    }

    uf->sock = putsock;
    uf->conn = conn;

    uf->writing = 1;
    
    return 0;
}

static int ucftp_init_put(ventry *ve, int flags, struct ucftpfile **ufp)
{
    int res;
    struct ucftpfs *fs = ucftp_ventry_ucftpfs(ve);
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);
    struct ucftpconn *conn;
    char *dir;
    char *file;

    conn = ucftp_find_conn(fs, ent);
    if(!conn)
        return -EIO;   // no conn?

    if(conn->busy)
        return -EAGAIN;  // control connection busy

    conn->busy = 1;

    dir = ucftp_create_path(ent->parent);
    file = av_strdup(ent->name);

    *ufp = ucftp_new_file(ent, flags);
    res = ucftp_do_put(( dir[0] == '\0' ) ? "/" : dir, file, conn, *ufp);
    av_free(dir);
    av_free(file);

    if(res < 0) {
        av_unref_obj(*ufp);
        ucftp_release_conn(conn);
    } else {
        ucftp_truncate_node(ent->node, 0);
    }

    return res;
}

static avssize_t ucftp_write(vfile *vf, const char *buf, avsize_t nbyte)
{
    struct ucftpfile *uf = ucftp_vfile_ucftpfile(vf);
    int res;

    if(!buf)
        return -EINVAL;
    if(nbyte < 1)
        return 0;

    if(AV_ISDIR(uf->ent->node->st.mode))
        return -EISDIR;
    
    if((uf->flags & AVO_ACCMODE) != AVO_WRONLY ||
       (uf->flags & AVO_TRUNC) == 0 ||
       (uf->flags & AVO_CREAT) == 0 ||
       (uf->flags & AVO_APPEND) != 0)
        return -EINVAL;
    
    if(uf->sock < 0) {
        return -EIO;
    }

    res = write(uf->sock, buf, nbyte);
    if(res < 0 || res != nbyte)
        return -EIO;
    
    ucftp_truncate_node(uf->ent->node, uf->ent->node->st.size + res);
    return res;
}

/***************************************
 * open code
 ***************************************/

/* called by ucftp_open_check_type */
static int ucftp_need_write(int flags)
{
    if((flags & AVO_ACCMODE) == AVO_WRONLY ||
       (flags & AVO_ACCMODE) == AVO_RDWR ||
       (flags & AVO_TRUNC) != 0)
        return 1;
    
    return 0;
}

/* called by ucftp_open_check */
static int ucftp_open_check_type(avmode_t mode, int flags)
{
    if((flags & AVO_DIRECTORY) != 0 && !AV_ISDIR(mode))
        return -ENOTDIR;
    
    switch(mode & AV_IFMT) {
    case AV_IFREG:
        return 0;
        
    case AV_IFDIR:
        if(ucftp_need_write(flags))
            return -EISDIR;
        return 0;

    case AV_IFLNK:
        if((flags & AVO_ACCMODE) != AVO_NOPERM || !(flags & AVO_NOFOLLOW))
            return -ENOENT;
        return 0;

    default:
        /* FIFO, char/bockdev, socket */
        if((flags & AVO_ACCMODE) != AVO_NOPERM)
            return -ENXIO;
        return 0;
    }
}

/* called by ucftp_open */
static int ucftp_open_check(struct ucftpnode *nod, int flags)
{
    if(nod == NULL) {
        if(!(flags & AVO_CREAT))
            return -ENOENT;
        return 0;
    }

    if((flags & AVO_EXCL) != 0)
        return -EEXIST;

    return ucftp_open_check_type(nod->st.mode, flags);
}

static int ucftp_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    struct ucftpfs *fs = ucftp_ventry_ucftpfs(ve);
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);
    struct ucftpfile *file = NULL;
    int new_node = 0;

    /* check permissions */
    res = ucftp_open_check(ent->node, flags);
    if(res < 0)
        return res;

    if(ent->node == NULL) {
        // node doesn't exists so there's no such file
        // create a node in case of write
        if((flags & AVO_ACCMODE) == AVO_WRONLY &&
           (flags & AVO_CREAT) &&
           (flags & AVO_TRUNC)) {
            res = ucftp_make_node(fs, ent, mode | AV_IFREG);
            if(res < 0)
                return res;
            new_node = 1;
        } else {
            return -ENOENT;
        }
    }

    if((flags & AVO_ACCMODE) == AVO_NOPERM) {
        file = ucftp_new_file(ent, flags);
    } else {
        if((flags & AVO_DIRECTORY) != 0) {
            file = ucftp_new_file(ent, flags);
        } else {
            if(AV_ISREG(ent->node->st.mode)) {
                if((flags & AVO_ACCMODE) == AVO_RDONLY) {
                    file = ucftp_new_file(ent, flags);
                } else if((flags & AVO_ACCMODE) == AVO_WRONLY) {
                    if(ucftp_init_put(ve, flags, &file) < 0) {
                        if(new_node == 1)
                            ucftp_unlink_node(ent);
                        return -EIO;
                    }
                }
            }
        }
    }
    
    if(file == NULL)
        return -EIO;
    
    *resp = file;

    return 0;
}

/***************************************
 * close code
 ***************************************/

static int ucftp_close(vfile *vf)
{
    struct ucftpfile *f = ucftp_vfile_ucftpfile(vf);
    int res = 0;

    if(f->writing == 1) {
        close(f->sock);
        
        res = ucftp_wait_reply_code(f->conn);
        if(res >= 0 && res / 100 != 2)
            res = -EIO;

        if ( res >= 0 ) {
            ucftp_release_conn(f->conn);
        }
    }

    av_unref_obj(f);

    return res;
}

/***************************************
 * read code (get)
 ***************************************/

static int ucftp_do_get(const char *dir, const char *file,
                        struct ucftpconn *conn, struct ucftpfile *uf)
{
    int res;
    int getsock;
    char *cmd;

    res = ucftp_open_conn(conn);
    if(res < 0)
        return res;

    res = ucftp_set_binary(conn);
    if(res < 0)
        return res;
    
    res = ucftp_set_cwd(conn, dir);
    if(res < 0)
        return res;

    res = ucftp_open_dataconn(conn);
    if(res < 0)
        return res;

    getsock = res;
    cmd = av_stradd(NULL, "RETR ", file, NULL);
    res = ucftp_command(conn, cmd);
    av_free(cmd);
    if(res >= 0 && res / 100 != 1)
        res = -EIO;
    
    if(res < 0) {
        close(getsock);
        return res;
    }

    res = ucftp_init_file(uf, getsock);
    if(res < 0) {
        return res;
    }

    uf->conn = conn;
    
    return 0;
}

static int ucftp_init_get(vfile *vf)
{
    int res;
    struct ucftpfile *uf = ucftp_vfile_ucftpfile(vf);
    struct ucftpfs *fs = ucftp_vfile_fs(vf);
    struct ucftpentry *ent = uf->ent;
    struct ucftpconn *conn;
    char *dir;
    char *file;

    conn = ucftp_find_conn(fs, ent);
    if(!conn)
        return -EIO;   // no conn?

    if(conn->busy)
        return -EAGAIN;  // control connection busy

    conn->busy = 1;

    dir = ucftp_create_path(ent->parent);
    file = av_strdup(ent->name);

    res = ucftp_do_get(( dir[0] == '\0' ) ? "/" : dir, file, conn, uf);
    av_free(dir);
    av_free(file);

    if(res < 0) {
        ucftp_release_conn(conn);
    }

    return res;
}

/* TODO: perhaps try filling buf as it happens that bytes read from sock are lower than nbyte */
static avssize_t ucftp_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avoff_t nact;
    struct ucftpfile *uf = ucftp_vfile_ucftpfile(vf);
    avsize_t nbytes;
    int res;

    if(AV_ISDIR(uf->ent->node->st.mode))
        return -EISDIR;
    
    if(uf->eof) {
        return 0;
    }
    
    if(!uf->sockfb) {
        if(!AV_ISREG(uf->ent->node->st.mode))
            return -EINVAL;
        if((uf->flags & AVO_ACCMODE) != AVO_RDONLY)
            return -EINVAL;
        if(ucftp_init_get(vf) < 0)
            return -EIO;
    }

    nact = nbyte;
    
    if ( uf->numbytes != vf->ptr ) {
        av_log(AVLOG_ERROR, "UCFTP: wrong file position\n");
        return -EIO;
    }

    for(;;) {
        nbytes = av_filebuf_read(uf->sockfb, buf, nact);
        if(nbytes != 0) {
            uf->numbytes += nbytes;
            vf->ptr += nbytes;
            break;
        } else {
            if(av_filebuf_eof(uf->sockfb)) {
                av_unref_obj(uf->sockfb);
                uf->sockfb = NULL;
                close(uf->sock);
                uf->sock = -1;
                
                uf->eof = 1;
 
                res = ucftp_wait_reply_code(uf->conn);
                if(res >= 0 && res / 100 != 2)
                    res = -EIO;
            
                if(res < 0)
                    return res;
            
                ucftp_release_conn(uf->conn);
                uf->conn = NULL;
            
                return 0;
            }
            else {
                res = av_filebuf_check(&uf->sockfb, 1, FTP_READ_TIMEOUT);
                if(res < 0)
                    return res;
            
                if(res == 0) {
                    av_log(AVLOG_ERROR, "FTP: read timeout");
                    return -EIO;
                }
            }
        }
    }
    
    return nbytes;
}

/***************************************
 * attribute code (stat)
 ***************************************/

static int ucftp_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    struct ucftpfile *file = ucftp_vfile_ucftpfile(vf);

    *buf = file->ent->node->st;

    return 0;
}

#if 0
static void vol_set_attributes(struct avstat *dest, const struct avstat *src,
                               int attrmask)
{
    if((attrmask & AVA_ATIME) != 0)
        dest->atime = src->atime;
    if((attrmask & AVA_MTIME) != 0)
        dest->mtime = src->mtime;
    if((attrmask & AVA_MODE) != 0)
        dest->mode = (dest->mode & AV_IFMT) | src->mode;
    if((attrmask & AVA_UID) != 0)
        dest->uid = src->uid;
    if((attrmask & AVA_GID) != 0)
        dest->gid = src->gid;
}

static int vol_setattr(vfile *vf, struct avstat *buf, int attrmask)
{
    struct ucftpnode *nod = vol_vfile_ucftpnode(vf);

    vol_set_attributes(&nod->st, buf, attrmask);
    
    return 0;
}
#endif

/***************************************
 * access and readlink functions
 ***************************************/

static int ucftp_access(ventry *ve, int amode)
{
    struct ucftpnode *nod = ucftp_ventry_ucftpentry(ve)->node;

    if(nod == NULL) 
        return -ENOENT;
    
    return 0;
}

static int ucftp_readlink(ventry *ve, char **bufp)
{
    struct ucftpnode *nod = ucftp_ventry_ucftpentry(ve)->node;

    if(nod == NULL)
        return -ENOENT;

    if(!AV_ISLNK(nod->st.mode))
        return -EINVAL;

    if(!nod->linkname)
        return -EINVAL;

    *bufp = av_strdup(nod->linkname);

    return 0;
}

/***************************************
 * code for generic FTP commands
 ***************************************/

static int ucftp_do_op(enum ucftp_op op, const char *dir, const char *file, struct ucftpconn *conn)
{
    int res;
    char *cmd;
    
    res = ucftp_open_conn(conn);
    if(res < 0)
        return res;

    res = ucftp_set_cwd(conn, dir);
    if(res < 0)
        return res;

    res = ucftp_open_dataconn(conn);
    if(res < 0)
        return res;

    cmd = av_stradd(NULL, ucftp_op_cmd[op], file, NULL);
    res = ucftp_command(conn, cmd);
    av_free(cmd);
    if(res >= 0 && res / 100 != 2)
        res = -EIO;

    if(res < 0) {
        return res;
    }

    return 0;
}


static int ucftp_op(enum ucftp_op op, ventry *ve)
{
    int res;
    struct ucftpfs *fs = ucftp_ventry_ucftpfs(ve);
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);
    struct ucftpconn *conn;
    char *dir;
    char *file;

    conn = ucftp_find_conn(fs, ent);
    if(!conn)
        return -EIO;   // no conn?

    if(conn->busy)
        return -EAGAIN;  // control connection busy

    conn->busy = 1;

    dir = ucftp_create_path(ent->parent);
    file = av_strdup(ent->name);

    res = ucftp_do_op(op, dir[0] == '\0' ? "/" : dir, file, conn);
    av_free(dir);
    av_free(file);

    ucftp_release_conn(conn);

    return res;
}

/***************************************
 * deletion code
 ***************************************/

static int ucftp_unlink(ventry *ve)
{
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);
    int res;

    if(ent->node == NULL)
        return -ENOENT;

    if(AV_ISDIR(ent->node->st.mode))
        return -EISDIR;
    
    res = ucftp_op(OP_DELE, ve);
    if(res < 0)
        return res;
    
    ucftp_unlink_node(ent);
    
    return 0;
}

/* called by ucftp_rmdir */
static int ucftp_check_rmdir(struct ucftpentry *ent)
{
    struct ucftpnode *nod = ent->node;

    if(nod == NULL)
        return -ENOENT;

    if(!AV_ISDIR(nod->st.mode)) 
        return -ENOTDIR;

    if(nod->subdir != NULL)
        return -ENOTEMPTY;

    if(ent->parent == NULL)
        return -EBUSY;

    return 0;
}

static int ucftp_rmdir(ventry *ve)
{
    int res;
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);

    res = ucftp_check_rmdir(ent);
    if(res < 0) 
        return res;

    res = ucftp_op(OP_RMD, ve);
    if(res < 0)
        return res;
    
    ucftp_unlink_node(ent);
    
    return 0;
}

/***************************************
 * make dir code
 ***************************************/

static int ucftp_mkdir(ventry *ve, avmode_t mode)
{
    int res;
    struct ucftpfs *fs = ucftp_ventry_ucftpfs(ve);
    struct ucftpentry *ent = ucftp_ventry_ucftpentry(ve);
    
    if(ent->node != NULL)
        return -EEXIST;
    
    res = ucftp_op(OP_MKD, ve);
    if(res < 0)
        return res;

    res = ucftp_make_node(fs, ent, mode | AV_IFDIR);
    if(res < 0)
        return res;

    if(ent->parent != NULL &&
       ent->parent->node != NULL)
        ent->parent->node->valid = 0;
    return 0;
}

/***************************************
 * seeking
 ***************************************/

static avoff_t ucftp_lseek(vfile *vf, avoff_t offset, int whence)
{
    return -ENOSYS;
    /* TODO implement some kind of seeking?
     * Since seeking is not supported by FTP and no data is cached
     * seeking would be terrible expensive.
     * on the other hand, forward seeking could be implemented
     * by repeatedly call read, seek to the end as well. Seek to
     * the start could be implemented by closing and re-open
     */
}

/***************************************
 * ucftp_ctl code
 ***************************************/

static int ucftp_password_set(struct entry *ent, const char *param,
                              const char *val)
{
    struct ucftpsession *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct ucftpfs *fs = (struct ucftpfs *) sf->data;
    unsigned int len;

    fts = ucftp_get_session(fs, param);
    av_free(fts->password);
    fts->password = av_strdup(val);
    len = strlen(fts->password);
    if(len > 0) {
        if(fts->password[len - 1] == '\n')
            fts->password[len - 1] = '\0';
    }

    return 0;
}

static int ucftp_loggedin_get(struct entry *ent, const char *param, char **resp)
{
    struct ucftpsession *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct ucftpfs *fs = (struct ucftpfs *) sf->data;

    fts = ucftp_find_session(fs, param);
    if(fts == NULL)
        *resp = av_strdup("0\n");
    else
        *resp = av_strdup("1\n");

    return 0;
}

static int ucftp_loggedin_val(const char *val, int *resp)
{
    char *end;
    int ival;

    ival = strtol(val, &end, 10);
    if(end == val)
        return -EINVAL;

    if(*end == '\n')
        end++;
    if(*end != '\0')
        return -EINVAL;

    if(ival < 0 || ival > 1)
        return -EINVAL;
    
    *resp = ival;

    return 0;
}

static int ucftp_loggedin_set(struct entry *ent, const char *param,
                              const char *val)
{
    int res;
    struct ucftpsession *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct ucftpfs *fs = (struct ucftpfs *) sf->data;

    fts = ucftp_find_session(fs, param);
    if(fts == NULL)
        res = -EACCES;
    else {
        int ival;

        res = ucftp_loggedin_val(val, &ival);
        if(res == 0 && ival == 0) {
            /* FIXME: end connections using this session */
            ucftp_remove_session(fts);
        }
    }

    return res;
}

static int ucftp_init_ctl(struct vmodule *module, struct ucftpfs *fs)
{
    int res;
    struct namespace *ns;
    struct statefile *stf;
    struct entry *ent;
    struct avfs *avfs;
    
    res = av_state_new(module, "ucftp_ctl", &ns, &avfs);
    if(res < 0)
        return res;
    
    ent = av_namespace_lookup(ns, NULL, "password");
    AV_NEW(stf);
    stf->data = fs;
    stf->get = NULL;
    stf->set = ucftp_password_set;
    av_namespace_set(ent, stf);

    ent = av_namespace_lookup(ns, NULL, "loggedin");
    AV_NEW(stf);
    stf->data = fs;
    stf->get = ucftp_loggedin_get;
    stf->set = ucftp_loggedin_set;
    av_namespace_set(ent, stf);
    
    av_unref_obj(ns);

    return 0;
}

/***************************************
 * ucftp constructor and destructor
 ***************************************/

static void ucftp_destroy(struct avfs *avfs)
{
    struct ucftpfs *fs = (struct ucftpfs *) avfs->data;

    struct ucftpconn *conn;
    struct ucftpconn *nextconn;

    for(conn = fs->conns; conn != NULL; conn = nextconn) {
        nextconn = conn->next;

        ucftp_free_tree(conn->root);
        av_unref_obj(conn->root);
        ucftp_close_conn(conn);
        av_free(conn->host);
        av_free(conn->user);
        av_free(conn->password);
        av_free(conn->cwd);
        av_free(conn);
    }

    while(fs->sessions.next != &fs->sessions)
        ucftp_remove_session(fs->sessions.next);

    av_free(fs);
}

extern int av_init_module_ucftp(struct vmodule *module);

int av_init_module_ucftp(struct vmodule *module)
{
    int res;
    struct avfs *avfs;
    struct ucftpfs *fs;

    res = av_new_avfs("ucftp", NULL, AV_VER, AVF_ONLYROOT, module, &avfs);
    if(res < 0)
        return res;

    avfs->destroy = ucftp_destroy;

    AV_NEW(fs);

    avfs->data = (void *) fs;

    fs->avfs = avfs;
    fs->conns = NULL;
    fs->sessions.next = &fs->sessions;
    fs->sessions.prev = &fs->sessions;

    avfs->lookup    = ucftp_lookup;
    avfs->putent    = ucftp_putent;
    avfs->copyent   = ucftp_copyent;
    avfs->getpath   = ucftp_getpath;
    
    avfs->open      = ucftp_open;
    avfs->close     = ucftp_close;
    avfs->read      = ucftp_read;
    avfs->readdir   = ucftp_readdir;
    avfs->getattr   = ucftp_getattr;
    avfs->write     = ucftp_write;
    avfs->access    = ucftp_access;
    avfs->readlink  = ucftp_readlink;
    avfs->mkdir     = ucftp_mkdir;
    avfs->unlink    = ucftp_unlink;
    avfs->rmdir     = ucftp_rmdir;

    //avfs->lseek     = ucftp_lseek;
    
    //    avfs->rename    = vol_rename;
    //    avfs->setattr   = vol_setattr;
    //    avfs->truncate  = vol_truncate;

    av_add_avfs(avfs);
    res = ucftp_init_ctl(module, fs);
    if(res < 0)
        av_unref_obj(avfs);
    
    return res;
}

/* Local Variables: */
/* c-basic-offset:4 */
/* End: */
