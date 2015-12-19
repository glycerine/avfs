/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "avfs.h"
#include "config.h"

#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#define NAMLEN 256

struct ugidcache {
    int uid;
    char *uname;
    int myuid;

    int gid;
    char *gname;
    int mygid;
};

static void free_ugidcache(struct ugidcache *cache)
{
    av_free(cache->uname);
    av_free(cache->gname);
}

struct ugidcache *av_new_ugidcache()
{
    struct ugidcache *cache;

    AV_NEW_OBJ(cache, free_ugidcache);

    cache->uname = NULL;
    cache->myuid = getuid();
  
    cache->gname = NULL;
    cache->mygid = getgid();

    return cache;
}

char *av_finduname(struct ugidcache *cache, int uid, const char *deflt)
{
    if(uid == -1)
        return av_strdup(deflt);

    if(cache->uname == NULL || uid != cache->uid) {
        int res;
        struct passwd pw;
        struct passwd *pwres;
        char *buf = NULL;
        size_t bufsize = 0;

#ifdef HAVE_GETPWUID_R
        do {
            bufsize += 256;
            buf = av_realloc(buf, bufsize);
            res = getpwuid_r(uid, &pw, buf, bufsize, &pwres);
        } while(res == ERANGE);
#else
	pwres = getpwuid(uid);
#endif

        av_free(cache->uname);
        if(pwres == NULL)
            cache->uname = av_strdup("");
        else
            cache->uname = av_strdup(pwres->pw_name);

        cache->uid = uid;
#ifdef HAVE_GETPWUID_R
        av_free(buf);
#endif
    }

    if(!cache->uname[0])
        return av_strdup(deflt);
    else
        return av_strdup(cache->uname);
}

int av_finduid(struct ugidcache *cache, const char *uname, int deflt)
{
    if(uname == NULL || !uname[0])
        return deflt == -1 ? cache->myuid : deflt;

    if(cache->uname == NULL || strcmp(uname, cache->uname) != 0) {
        int res;
        struct passwd pw;
        struct passwd *pwres;
        char *buf = NULL;
        size_t bufsize = 0;

#ifdef HAVE_GETPWNAM_R
        do {
            bufsize += 256;
            buf = av_realloc(buf, bufsize);
            res = getpwnam_r(uname, &pw, buf, bufsize, &pwres);
        } while(res == ERANGE);
#else
	pwres = getpwnam(uname);
#endif

        if(pwres == NULL)
            cache->uid = -1;
        else
            cache->uid = pwres->pw_uid;

        av_free(cache->uname);
        cache->uname = av_strdup(uname);
#ifdef HAVE_GETPWNAM_R
        av_free(buf);
#endif
    }
    
    if(cache->uid == -1)
        return deflt == -1 ? cache->myuid : deflt;
    else
        return cache->uid;
}

char *av_findgname(struct ugidcache *cache, int gid, const char *deflt)
{
    if(gid == -1)
        return av_strdup(deflt);

    if(cache->gname == NULL || gid != cache->gid) {
        int res;
        struct group gr;
        struct group *grres;
        char *buf = NULL;
        size_t bufsize = 0;

#ifdef HAVE_GETGRGID_R
        do {
            bufsize += 256;
            buf = av_realloc(buf, bufsize);
            res = getgrgid_r(gid, &gr, buf, bufsize, &grres);
        } while(res == ERANGE);
#else
	grres = getgrgid(gid);
#endif

        av_free(cache->gname);
        if(grres == NULL)
            cache->gname = av_strdup("");
        else
            cache->gname = av_strdup(grres->gr_name);

        cache->gid = gid;
#ifdef HAVE_GETGRGID_R
        av_free(buf);
#endif
    }
    
    if(!cache->gname[0])
        return av_strdup(deflt);
    else
        return av_strdup(cache->gname);
}

int av_findgid(struct ugidcache *cache, const char *gname, int deflt)
{
    if(gname == NULL || !gname[0])
        return deflt == -1 ? cache->mygid : deflt;

    if(cache->gname == NULL || strcmp(gname, cache->gname) != 0) {
        int res;
        struct group gr;
        struct group *grres;
        char *buf = NULL;
        size_t bufsize = 0;

#ifdef HAVE_GETGRNAM_R
        do {
            bufsize += 256;
            buf = av_realloc(buf, bufsize);
            res = getgrnam_r(gname, &gr, buf, bufsize, &grres);
        } while(res == ERANGE);
#else
	grres = getgrnam(gname);
#endif

        if(grres == NULL)
            cache->gid = -1;
        else
            cache->gid = grres->gr_gid;

        av_free(cache->gname);
        cache->gname = av_strdup(gname);
#ifdef HAVE_GETGRNAM_R
        av_free(buf);
#endif
    }
 
    if(cache->gid == -1)
        return deflt == -1 ? cache->mygid : deflt;
    else
        return cache->gid;
}

