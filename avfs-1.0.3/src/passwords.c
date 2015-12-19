/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

/*
    Taken from FTP code, and renamed.

    Can be used more-or-less verbatim in DAV and HTTP code.

    Reuse in FTP code will require noting that the ftpdata struct
    is not passed in; instead the sessions member is used. Also
    FTP code will need to pass in NULL for "realm" arguments.

    TODO: more fine-grained locking
*/

#include "remote.h"
#include "filebuf.h"
#include "passwords.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

static AV_LOCK_DECL(pass_lock);

static struct pass_session *pass_find_session(struct pass_session *passd,
                                           const char *account)
{
    struct pass_session *fts;

    if (passd == NULL) {
	return NULL;
    }
    for(fts = passd->next; fts != NULL && fts != passd; fts = fts->next) {
	av_log(AVLOG_DEBUG, "passwords: lookup '%s' == '%s'", account, fts->account);
        if(fts->account != NULL && strcmp(account, fts->account) == 0)
            return fts;
    }
    
    return NULL;
}

static struct pass_session *pass_get_session(struct pass_session *passd,
                                          const char *account)
{
    struct pass_session *fts;
    
    if (passd == NULL) {
	return NULL;
    }
    fts = pass_find_session(passd, account);
    if(fts == NULL) {
        struct pass_session *next;
        struct pass_session *prev;

        AV_NEW(fts);
        fts->account = av_strdup(account);
        fts->password = NULL;

        fts->next = next = passd->next;
        fts->prev = prev = passd;
	if (next != NULL) {
	    next->prev = fts;
	}
        prev->next = fts;
    }
    
    return fts;
}

void pass_remove_session(struct pass_session *fts)
{
    struct pass_session *next = fts->next;
    struct pass_session *prev = fts->prev;
    
    next->prev = prev;
    prev->next = next;

    av_free(fts->account);
    av_free(fts->password);
    av_free(fts);
}

struct pass_session *pass_get_password(struct pass_session *passd,
		const char *host, const char *user)
{
    struct pass_session *fts = NULL;
    char *account;

    if (passd == NULL) {
	return NULL;
    }
    if (fts == NULL) {
	account = av_stradd(NULL, user, USER_SEP_STR, host, NULL);
	fts = pass_find_session(passd, account);
	av_free(account);
    }

    if(fts == NULL) {
        account = av_stradd(NULL, user, USER_SEP_STR, NULL);
        fts = pass_find_session(passd, account);
        av_free(account);
    }

    if(fts == NULL) {
        account = av_stradd(NULL, USER_SEP_STR, host, NULL);
        fts = pass_find_session(passd, account);
        av_free(account);
    }

    av_log(AVLOG_DEBUG, "passwords: fts=%lx", (long) fts);
    return fts;
}


int pass_username_get(struct entry *ent, const char *param, char **resp)
{
    *resp = av_strdup("");
    return 0;
}

int pass_username_set(struct entry *ent, const char *param, const char *val)
{
    struct pass_session *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct pass_session *passd = (struct pass_session *) sf->data;
    unsigned int len;

    AV_LOCK(pass_lock);
    fts = pass_get_session(passd, param);
    av_log(AVLOG_DEBUG, "passwords: setting username '%s' %s'", param, val);

    av_free(fts->username);
    fts->username = av_strdup(val);
    len = strlen(fts->username);
    if(fts->username[len - 1] == '\n')
        fts->username[len - 1] = '\0';

    AV_UNLOCK(pass_lock);

    return 0;
}

int pass_password_get(struct entry *ent, const char *param, char **resp)
{
    *resp = av_strdup("");
    return 0;
}

int pass_password_set(struct entry *ent, const char *param, const char *val)
{
    struct pass_session *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct pass_session *passd = (struct pass_session *) sf->data;
    unsigned int len;

    AV_LOCK(pass_lock);
    fts = pass_get_session(passd, param);
    /* av_log(AVLOG_DEBUG, "passwords: setting password '%s' %s'",
     * param, val);*/

    av_free(fts->password);
    fts->password = av_strdup(val);
    len = strlen(fts->password);
    if(fts->password[len - 1] == '\n')
        fts->password[len - 1] = '\0';

    AV_UNLOCK(pass_lock);

    return 0;
}

int pass_loggedin_get(struct entry *ent, const char *param, char **resp)
{
    struct pass_session *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct pass_session *passd = (struct pass_session *) sf->data;

    AV_LOCK(pass_lock);
    fts = pass_find_session(passd, param);
    if(fts == NULL)
        *resp = av_strdup("0\n");
    else
        *resp = av_strdup("1\n");
    AV_UNLOCK(pass_lock);

    return 0;
}

static int pass_loggedin_val(const char *val, int *resp)
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

int pass_loggedin_set(struct entry *ent, const char *param, const char *val)
{
    int res;
    struct pass_session *fts;
    struct statefile *sf = (struct statefile *) av_namespace_get(ent);
    struct pass_session *passd = (struct pass_session *) sf->data;

    AV_LOCK(pass_lock);
    fts = pass_find_session(passd, param);
    if(fts == NULL)
        res = -EACCES;
    else {
        int ival;

        res = pass_loggedin_val(val, &ival);
        if(res == 0 && ival == 0) {
            /* FIXME: end connections using this session */
            pass_remove_session(fts);
        }
    }
    AV_UNLOCK(pass_lock);

    return res;
}

// vim:sw=4:
