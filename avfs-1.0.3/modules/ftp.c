/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

/*
  TODO:
  
  if data connection has closed, retry
  don't use NOOP (if control connection has closed (421), retry) 
  fix absolute symlinks
  close unused data connections after timeout
  close unused control connections after timeout
  limit max connections to a host
  if second connection doesn't work wait for first and retry
  retrieve restart
  seekability
  selective proxying
*/

#include "remote.h"
#include "socket.h"
#include "state.h"
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

static AV_LOCK_DECL(ftp_lock);

struct ftpconn {
    char *host;
    char *user;
    char *password;
    int busy;
    int sock;
    struct filebuf *sockfb;
    struct ftpconn *next;
    int binary;
    char *cwd;
};

struct ftpsession {
    char *account;
    char *password;
    struct ftpsession *next;
    struct ftpsession *prev;
};

struct ftpdata {
    struct ftpconn *conns;
    struct ftpsession sessions;
};

struct ftplocalfile {
    int fd;
    char *tmpfile;
    int sock;
    struct filebuf *sockfb;
    avoff_t numbytes;
    struct ftpconn *conn;
};

static struct ftpsession *ftp_find_session(struct ftpdata *ftd,
                                           const char *account)
{
    struct ftpsession *fts;

    for(fts = ftd->sessions.next; fts != &ftd->sessions; fts = fts->next) {
        if(strcmp(account, fts->account) == 0)
            return fts;
    }
    
    return NULL;
}

static struct ftpsession *ftp_get_session(struct ftpdata *ftd,
                                          const char *account)
{
    struct ftpsession *fts;
    
    fts = ftp_find_session(ftd, account);
    if(fts == NULL) {
        struct ftpsession *next;
        struct ftpsession *prev;

        AV_NEW(fts);
        fts->account = av_strdup(account);
        fts->password = NULL;

        fts->next = next = ftd->sessions.next;
        fts->prev = prev = &ftd->sessions;
        next->prev = fts;
        prev->next = fts;
    }
    
    return fts;
}

static void ftp_remove_session(struct ftpsession *fts)
{
    struct ftpsession *next = fts->next;
    struct ftpsession *prev = fts->prev;
    
    next->prev = prev;
    prev->next = next;

    av_free(fts->account);
    av_free(fts->password);
    av_free(fts);
}

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

static void ftp_release_conn(struct ftpconn *conn)
{
    AV_LOCK(ftp_lock);
    conn->busy = 0;
    AV_UNLOCK(ftp_lock);
}

static void ftp_close_conn(struct ftpconn *conn)
{
    av_unref_obj(conn->sockfb);
    conn->sockfb = NULL;
    conn->sock = -1;
    conn->binary = -1;
    conn->cwd[0] = '\0';
}

static int ftp_get_line(struct ftpconn *conn, char **linep)
{
    int res;
    char *line;
    
    res = av_filebuf_getline(conn->sockfb, &line, FTP_REPLY_TIMEOUT);
    if(res <= 0 || line == NULL) {
        ftp_close_conn(conn);
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


static int ftp_check_reply(struct ftpconn *conn, const char *line)
{
    int reply;

    if(strlen(line) < 4 || !isdigit((int) line[0]) ||
       !isdigit((int) line[1]) || !isdigit((int) line[2]) ||
       (line[3] != ' ' && line[3] != '-')) {
        ftp_close_conn(conn);
        av_log(AVLOG_ERROR, "FTP: malformed reply: %s", line);
        return -EIO;
    }

    reply = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');

    if(reply == 421)
        ftp_close_conn(conn);

    return reply;
}

static int ftp_wait_reply_code(struct ftpconn *conn)
{
    int res;
    char *line;
    char replystr[4];
    int firstline = 1;
    int cont;
    int replycode = 0;
    
    do {
        cont = 0;
        res = ftp_get_line(conn, &line);
        if(res < 0)
            return res;

        if(firstline) {
            res = ftp_check_reply(conn, line);
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

static int ftp_write_command(struct ftpconn *conn, const char *cmd)
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

static int ftp_command(struct ftpconn *conn, const char *cmd)
{
    int res;

    res = ftp_write_command(conn, cmd);
    if(res < 0)
        return res;

    res = ftp_wait_reply_code(conn);
    
    return res;
}


static int ftp_get_addrbytes(const char *line, int addrbytes[6])
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

static int ftp_check_passv_reply(struct ftpconn *conn, const char *line,
                                 char **resp)
{
    int res;
    int replycode;
    int addrbytes[6];
    char addrbuf[128];
    int port;
    
    res = ftp_check_reply(conn, line);
    if(res < 0)
        return res;

    replycode = res;
    
    if(replycode != 227) {
        av_log(AVLOG_ERROR, "FTP: %s", line);
        ftp_close_conn(conn);
        return -EIO;
    }
    
    av_log(AVLOG_DEBUG, "FTP: %s", line);
        
    if(line[3] != ' ') {
        av_log(AVLOG_ERROR, "FTP: Multiline reply to PASV: %s", line);
        ftp_close_conn(conn);
        return -EIO;
    }

    res = ftp_get_addrbytes(line, addrbytes);
    if(res < 0) {
        av_log(AVLOG_ERROR, "FTP: Bad reply to PASV: %s", line);
        ftp_close_conn(conn);
        return -EIO;
    }

    port = addrbytes[4] * 0x100 + addrbytes[5];
    sprintf(addrbuf, "%i.%i.%i.%i:%i", 
            addrbytes[0], addrbytes[1], addrbytes[2], addrbytes[3], port);

    *resp = av_strdup(addrbuf);

    return 0;
}

static int ftp_open_dataconn(struct ftpconn *conn)
{
    int res;
    char *line;
    char *host;

    res = ftp_write_command(conn, "PASV");
    if(res < 0)
        return res;

    res = ftp_get_line(conn, &line);
    if(res < 0)
        return res;

    res = ftp_check_passv_reply(conn, line, &host);
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

static int ftp_login(struct ftpconn *conn)
{
    int res;
    char *cmd;

    cmd = av_stradd(NULL, "USER ", conn->user, NULL);
    res = ftp_command(conn, cmd);
    av_free(cmd);

    if(res == 331) {
        cmd = av_stradd(NULL, "PASS ", conn->password, NULL);
        res = ftp_command(conn, cmd);
        av_free(cmd);
        if(res < 0)
            return res;
    }

    if(res != 230)
        return -EACCES;

    return 0;
}

static int ftp_init_conn(struct ftpconn *conn)
{
    int res;

    res = ftp_wait_reply_code(conn);
    if(res == 120)
        res = ftp_wait_reply_code(conn);
    
    if(res < 0)
        return res;

    if(res != 220)
        return -EIO;
    
    res = ftp_login(conn);
    if(res < 0)
        return res;

    ftp_command(conn, "PWD");
    ftp_command(conn, "SYST");

    return 0;
}

static int ftp_open_conn(struct ftpconn *conn)
{
    int res;

    if(conn->sock != -1) {
        res = ftp_command(conn, "NOOP");
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

    res = ftp_init_conn(conn);
    if(res < 0) {
        ftp_close_conn(conn);
        return res;
    }

    return 0;
}

static void ftp_free_dirlist(struct remdirlist *dl)
{
    int i;

    for(i = 0; i < dl->num; i++) {
        av_free(dl->ents[i].name);
        av_free(dl->ents[i].linkname);
    }

    av_free(dl->ents);
    dl->ents = NULL;
    dl->num = 0;
}

static int ftp_read_list(struct filebuf *fb, struct remdirlist *dl,
                         struct lscache *lc)
{
    int res;
    char *line;
    int eof = 0;

    do {
        res = av_filebuf_getline(fb, &line, FTP_READ_TIMEOUT);
        if(res < 0)
            return res;
        
        if(res == 0) {
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
                av_remote_add(dl, filename, linkname, &stbuf);
                av_free(filename);
                av_free(linkname);
            }
        }
    } while(!eof);

    return 0;
}

static int ftp_set_ascii(struct ftpconn *conn)
{
    int res;

    if(conn->binary != 0) {
        res = ftp_command(conn, "TYPE A");
        if(res < 0)
            return res;

        conn->binary = 0;
    }

    return 0;
}

static int ftp_set_binary(struct ftpconn *conn)
{
    int res;

    if(conn->binary != 1) {
        res = ftp_command(conn, "TYPE I");
        if(res < 0)
            return res;

        conn->binary = 1;
    }

    return 0;
}

static int ftp_set_cwd(struct ftpconn *conn, const char *dir)
{
    int res;
    char *cmd;

    if(strcmp(conn->cwd, dir) != 0) {
        cmd = av_stradd(NULL, "CWD ", dir, NULL);
        res = ftp_command(conn, cmd);
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

static int ftp_do_list(struct ftpconn *conn, const char *dir, 
                       struct remdirlist *dl)
{
    int res;
    char *cmd;
    int listsock;
    struct filebuf *fb;
    struct lscache *lc;

    res = ftp_open_conn(conn);
    if(res < 0)
        return res;

    res = ftp_set_ascii(conn);
    if(res < 0)
        return res;
    
    res = ftp_set_cwd(conn, dir);
    if(res < 0)
        return res;

    res = ftp_open_dataconn(conn);
    if(res < 0)
        return res;
        
    listsock = res;
    cmd = av_strdup("LIST -al");
    res = ftp_command(conn, cmd);
    av_free(cmd);
    if(res >= 0 && res / 100 != 1)
        res = -EIO;
    
    if(res < 0) {
        close(listsock);
        return res;
    }
    
    fb = av_filebuf_new(listsock, 0);
    lc = av_new_lscache();
    res = ftp_read_list(fb, dl, lc);
    av_unref_obj(lc);
    av_unref_obj(fb);

    res = ftp_wait_reply_code(conn);
    if(res >= 0 && res / 100 != 2)
        res = -EIO;

    if(res < 0) {
        ftp_free_dirlist(dl);
        return res;
    }

    return 0;
}

static const char *ftp_get_password(struct ftpdata *ftd, const char *host,
                                    const char *user)
{
    struct ftpsession *fts;
    char *account;

    account = av_stradd(NULL, user, USER_SEP_STR, host, NULL);
    fts = ftp_find_session(ftd, account);
    av_free(account);
    if(fts == NULL) {
        account = av_stradd(NULL, user, USER_SEP_STR, NULL);
        fts = ftp_find_session(ftd, account);
        av_free(account);
    }
    
    if(fts != NULL)
        return fts->password;
    else
        return NULL;
}

static int ftp_split_path(struct ftpdata *ftd, char *hostpart,
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
        pass = ftp_get_password(ftd, host, user);
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


static struct ftpconn *ftp_find_conn(struct ftpdata *ftd, const char *host,
                                     const char *user, const char *password)
{
    struct ftpconn *conn;
    struct ftpconn **cp;

    for(cp = &ftd->conns; *cp != NULL; cp = &(*cp)->next) {
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
    
    *cp = conn;
    
    return conn;
}

static int ftp_get_conn(struct ftpdata *ftd, const char *userhost,
                        struct ftpconn **resp)
{
    int res;
    char *tmps;
    const char *host;
    const char *user;
    const char *password;
    struct ftpconn *conn = NULL;

    AV_LOCK(ftp_lock);
    tmps = av_strdup(userhost);
    res = ftp_split_path(ftd, tmps, &host, &user, &password);
    if(res == 0)
        conn = ftp_find_conn(ftd, host, user, password);

    av_free(tmps);
    AV_UNLOCK(ftp_lock);

    if(res < 0)
        return res;

    *resp = conn;

    return 0;
}

static int ftp_list(struct remote *rem, struct remdirlist *dl)
{
    int res;
    struct ftpdata *ftd = (struct ftpdata *) rem->data;
    struct ftpconn *conn;

    res = ftp_get_conn(ftd, dl->hostpath.host, &conn);
    if(res < 0)
        return res;

    res = ftp_do_list(conn, dl->hostpath.path, dl);

    ftp_release_conn(conn);

    return res;
}

static void ftp_free_localfile(struct ftplocalfile *lf)
{
    if(lf->conn != NULL) {
        ftp_close_conn(lf->conn);
        ftp_release_conn(lf->conn);
    }
    av_unref_obj(lf->sockfb);
    close(lf->sock);
    close(lf->fd);
}

static int ftp_init_localfile(struct ftplocalfile *lf, int sock)
{
    int res;

    lf->fd = -1;
    lf->tmpfile = NULL;
    lf->sock = sock;
    lf->sockfb = NULL;
    lf->numbytes = 0;
    lf->conn = NULL;

    res = av_get_tmpfile(&lf->tmpfile);
    if(res < 0)
        return res;

    lf->fd = open(lf->tmpfile, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0600);
    if(lf->fd == -1)
        return -errno;

    lf->sockfb = av_filebuf_new(lf->sock, 0);

    return 0;
}


static int ftp_do_get(struct remgetparam *gp, const char *dir,
                      const char *file, struct ftpconn *conn)
{
    int res;
    int getsock;
    char *cmd;
    struct ftplocalfile *lf;

    res = ftp_open_conn(conn);
    if(res < 0)
        return res;

    res = ftp_set_binary(conn);
    if(res < 0)
        return res;
    
    res = ftp_set_cwd(conn, dir);
    if(res < 0)
        return res;

    res = ftp_open_dataconn(conn);
    if(res < 0)
        return res;

    getsock = res;
    cmd = av_stradd(NULL, "RETR ", file, NULL);
    res = ftp_command(conn, cmd);
    av_free(cmd);
    if(res >= 0 && res / 100 != 1)
        res = -EIO;
    
    if(res < 0) {
        close(getsock);
        return res;
    }

    AV_NEW_OBJ(lf, ftp_free_localfile);
    res = ftp_init_localfile(lf, getsock);
    if(res < 0) {
        av_unref_obj(lf);
        av_del_tmpfile(lf->tmpfile);
        return res;
    }

    lf->conn = conn;

    gp->data = lf;
    gp->localname = lf->tmpfile;

    return 0;
}

static int ftp_get(struct remote *rem, struct remgetparam *gp)
{
    int res;
    struct ftpdata *ftd = (struct ftpdata *) rem->data;
    struct ftpconn *conn;
    char *dir;
    char *s;
    char *file;

    res = ftp_get_conn(ftd, gp->hostpath.host, &conn);
    if(res < 0)
        return res;

    dir = av_strdup(gp->hostpath.path);
    s = strrchr(dir, '/');
    *s = '\0';
    file = s + 1;

    res = ftp_do_get(gp, ( dir[0] == '\0' ) ? "/" : dir, file, conn);
    av_free(dir);

    if(res < 0)
        ftp_release_conn(conn);

    return res;
}

static int ftp_write_localfile(int fd, char *buf, avsize_t nbytes)
{
    int res;

    res = write(fd, buf, nbytes);
    if(res == -1) {
        av_log(AVLOG_ERROR, "FTP: error writing to tmpfile: %s",
                 strerror(errno));
                
        return -EIO;
    }
    if(res != nbytes) {
        av_log(AVLOG_ERROR, "FTP: short write to tmpfile (%i/%i)",
                 res, nbytes);
        return -EIO;
    }
    
    return 0;
}

#define READBUF 4096

static int ftp_wait(struct remote *rem, void *data, avoff_t end)
{
    int res;
    struct ftplocalfile *lf = (struct ftplocalfile *) data;
    char buf[READBUF];
    avsize_t nbytes;
    
    do {
        nbytes = av_filebuf_read(lf->sockfb, buf, READBUF);
        if(nbytes != 0) {
            res = ftp_write_localfile(lf->fd, buf, nbytes);
            if(res < 0)
                return res;

            lf->numbytes += nbytes;
        }
        else {
            if(av_filebuf_eof(lf->sockfb)) {
                av_unref_obj(lf->sockfb);
                lf->sockfb = NULL;
                close(lf->sock);
                lf->sock = -1;

                res = ftp_wait_reply_code(lf->conn);
                if(res >= 0 && res / 100 != 2)
                    res = -EIO;
                
                if(res < 0)
                    return res;
                
                ftp_release_conn(lf->conn);
                lf->conn = NULL;

                return 0;
            }
            else {
                res = av_filebuf_check(&lf->sockfb, 1, FTP_READ_TIMEOUT);
                if(res < 0)
                    return res;

                if(res == 0) {
                    av_log(AVLOG_ERROR, "FTP: read timeout");
                    return -EIO;
                }
            }
        }
    } while(lf->numbytes < end);

    return 1;
}

static int ftp_password_set(struct entry *ent, const char *param,
                            const char *val)
{
    struct ftpsession *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct ftpdata *ftd = (struct ftpdata *) sf->data;
    unsigned int len;

    AV_LOCK(ftp_lock);
    fts = ftp_get_session(ftd, param);
    av_free(fts->password);
    fts->password = av_strdup(val);
    len = strlen(fts->password);
    if(len > 0) {
        if(fts->password[len - 1] == '\n')
            fts->password[len - 1] = '\0';
    }
    AV_UNLOCK(ftp_lock);

    return 0;
}

static int ftp_loggedin_get(struct entry *ent, const char *param, char **resp)
{
    struct ftpsession *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct ftpdata *ftd = (struct ftpdata *) sf->data;

    AV_LOCK(ftp_lock);
    fts = ftp_find_session(ftd, param);
    if(fts == NULL)
        *resp = av_strdup("0\n");
    else
        *resp = av_strdup("1\n");
    AV_UNLOCK(ftp_lock);

    return 0;
}

static int ftp_loggedin_val(const char *val, int *resp)
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

static int ftp_loggedin_set(struct entry *ent, const char *param,
                            const char *val)
{
    int res;
    struct ftpsession *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct ftpdata *ftd = (struct ftpdata *) sf->data;

    AV_LOCK(ftp_lock);
    fts = ftp_find_session(ftd, param);
    if(fts == NULL)
        res = -EACCES;
    else {
        int ival;

        res = ftp_loggedin_val(val, &ival);
        if(res == 0 && ival == 0) {
            /* FIXME: end connections using this session */
            ftp_remove_session(fts);
        }
    }
    AV_UNLOCK(ftp_lock);

    return res;
}

static int ftp_init_ctl(struct vmodule *module, struct ftpdata *ftd)
{
    int res;
    struct namespace *ns;
    struct statefile *stf;
    struct entry *ent;
    struct avfs *avfs;
    
    res = av_state_new(module, "ftp_ctl", &ns, &avfs);
    if(res < 0)
        return res;
    
    ent = av_namespace_lookup(ns, NULL, "password");
    AV_NEW(stf);
    stf->data = ftd;
    stf->get = NULL;
    stf->set = ftp_password_set;
    av_namespace_set(ent, stf);

    ent = av_namespace_lookup(ns, NULL, "loggedin");
    AV_NEW(stf);
    stf->data = ftd;
    stf->get = ftp_loggedin_get;
    stf->set = ftp_loggedin_set;
    av_namespace_set(ent, stf);
    
    av_unref_obj(ns);

    return 0;
}    

static void ftp_destroy(struct remote *rem)
{
    struct ftpdata *ftd = (struct ftpdata *) rem->data;
    struct ftpconn *conn;
    struct ftpconn *nextconn;

    for(conn = ftd->conns; conn != NULL; conn = nextconn) {
        nextconn = conn->next;

        ftp_close_conn(conn);
        av_free(conn->host);
        av_free(conn->user);
        av_free(conn->password);
        av_free(conn->cwd);
        av_free(conn);
        
        conn = nextconn;
    }

    AV_LOCK(ftp_lock);
    while(ftd->sessions.next != &ftd->sessions)
        ftp_remove_session(ftd->sessions.next);
    AV_UNLOCK(ftp_lock);

    av_free(ftd);

    av_free(rem->name);
    av_free(rem);
}
    
extern int av_init_module_ftp(struct vmodule *module);

int av_init_module_ftp(struct vmodule *module)
{
    int res;
    struct remote *rem;
    struct ftpdata *ftd;
    struct avfs *avfs;

    AV_NEW(ftd);
    ftd->conns = NULL;
    ftd->sessions.next = &ftd->sessions;
    ftd->sessions.prev = &ftd->sessions;

    AV_NEW(rem);

    rem->data    = ftd;
    rem->flags   = REM_DIR_ONLY;
    rem->name    = av_strdup("ftp");
    rem->list    = ftp_list;
    rem->get     = ftp_get;
    rem->wait    = ftp_wait;
    rem->destroy = ftp_destroy;
    
    res = av_remote_init(module, rem, &avfs);
    if(res == 0) {
        res = ftp_init_ctl(module, ftd);
        if(res < 0)
            av_unref_obj(avfs);
    }

    return res;
}
