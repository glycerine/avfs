/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-1999  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "internal.h"

#include "config.h"
#include "info.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#endif

#ifdef MAJOR_IN_SYSMACROS
#include <sys/sysmacros.h>
#endif

#define DEFAULT_LOGMASK (AVLOG_ERROR | AVLOG_WARNING)

static int loginited;
static int logmask;
static char *logfile;
static int logfd;
static AV_LOCK_DECL(loglock);

static int debug_get(struct entry *ent, const char *param, char **retp)
{
    char buf[32];
    
    AV_LOCK(loglock);
    sprintf(buf, "%02o\n", logmask);
    AV_UNLOCK(loglock);

    *retp = av_strdup(buf);
    return 0;
}

static int debug_set(struct entry *ent, const char *param, const char *val)
{
    int mask;

    if(val[0] < '0' || val[0] > '7' || val[1] < '0' || val[1] > '7' ||
       (val[2] != '\0' && !isspace((int) val[2]))) 
        return -EIO;

    mask = (val[0] - '0') * 8 + (val[1] - '0');
    
    AV_LOCK(loglock);
    logmask = mask;
    AV_UNLOCK(loglock);

    return 0;
}

static void log_open()
{
    if(logfile != NULL) {
        if(strcmp(logfile, "-") == 0)
            logfd = STDERR_FILENO;
        else
            logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0600);
    } else {
        openlog("avfs", LOG_CONS | LOG_PID, LOG_USER);
    }
}

static void log_close()
{
    if(logfile != NULL) {
        if(strcmp(logfile, "-") != 0 && logfd != -1)
            close(logfd);
    } else {
        closelog();
    }
}

static void log_init()
{
    char *logenv;

    logmask = DEFAULT_LOGMASK;
    logenv = getenv("AVFS_DEBUG");
    if(logenv != NULL &&
       logenv[0] >= '0' && logenv[0] <= '7' &&
       logenv[1] >= '0' && logenv[1] <= '7' &&
       logenv[2] == '\0')
        logmask = (logenv[0] - '0') * 8 + (logenv[1] - '0');

    logfile = getenv("AVFS_LOGFILE");
    log_open();
    loginited = 1;
}

static int logfile_get(struct entry *ent, const char *param, char **retp)
{
    char *s;

    AV_LOCK(loglock);
    if(logfile != NULL)
        s = av_stradd(NULL, logfile, "\n", NULL);
    else
        s = av_strdup("");
    AV_UNLOCK(loglock);

    *retp = s;

    return 0;
}

static int logfile_set(struct entry *ent, const char *param, const char *val)
{
    char *s;
    unsigned int len;

    s = av_strdup(val);
    len = strlen(s);
    if(len > 0 && s[len-1] == '\n')
        s[len-1] = '\0';

    if(s[0] == '\0') {
        av_free(s);
        s = NULL;
    }

    AV_LOCK(loglock);
    log_close();
    av_free(logfile);
    logfile = s;
    log_open();
    AV_UNLOCK(loglock);

    return 0;
}

#define LOGMSG_SIZE 1024
static void filelog(const char *msg)
{
    char buf[LOGMSG_SIZE + 128];

    if(logfd != -1) {
        struct avtm tmbuf;

        av_localtime(time(NULL), &tmbuf);
        sprintf(buf, "%02i/%02i %02i:%02i:%02i avfs[%lu]: %s\n", 
                tmbuf.mon + 1, tmbuf.day, tmbuf.hour, tmbuf.min, tmbuf.sec,
                (unsigned long) getpid(), msg);
        
        write(logfd, buf, strlen(buf));
    }
}

void av_init_logstat()
{
    struct statefile statf;

    if(!loginited)
        log_init();

    statf.data = NULL;
    statf.get = debug_get;
    statf.set = debug_set;

    av_avfsstat_register("debug", &statf);

    statf.get = logfile_get;
    statf.set = logfile_set;

    av_avfsstat_register("logfile", &statf);
}

void av_log(int type, const char *format, ...)
{
    va_list ap;
    char buf[LOGMSG_SIZE+1];

    AV_LOCK(loglock);

    if(!loginited)
        log_init();

    if((type & logmask) == 0) {
        AV_UNLOCK(loglock);
        return;
    }

    va_start(ap, format);
#ifdef HAVE_VSNPRINTF
    vsnprintf(buf, LOGMSG_SIZE, format, ap);
#else
    strncpy(buf, format, LOGMSG_SIZE);
#endif  
    buf[LOGMSG_SIZE] = '\0';
    va_end(ap);

    if(logfile == NULL)
        syslog(LOG_INFO, "%s", buf);
    else
        filelog(buf);
    AV_UNLOCK(loglock);
}

avdev_t av_mkdev(int major, int minor)
{
    return makedev(major, minor);
}

void av_splitdev(avdev_t dev, int *majorp, int *minorp)
{
    *majorp = major(dev);
    *minorp = minor(dev);
}


char *av_get_config(const char *param)
{
    const char *val;

    val = NULL;

    if(strcmp(param, "moduledir") == 0) 
        val = MODULE_DIR;
    else if(strcmp(param, "compiledate") == 0) 
        val = COMPILE_DATE;
    else if(strcmp(param, "compilesystem") == 0) 
        val = COMPILE_SYSTEM;
  
    if(val == NULL)
        return NULL;

    return av_strdup(val);
}

void av_default_stat(struct avstat *stbuf)
{
    static avuid_t myuid = -1;
    static avuid_t mygid = -1;

    if(myuid == -1) {
        myuid = getuid();
        mygid = getgid();
    }

    stbuf->dev = 0;
    stbuf->ino = 0;
    stbuf->mode = 0;
    stbuf->nlink = 0;
    stbuf->uid = myuid;
    stbuf->gid = mygid;
    stbuf->rdev = 0;
    stbuf->size = 0;
    stbuf->blksize = 512;
    stbuf->blocks = 0;
    av_curr_time(&stbuf->atime);
    stbuf->mtime = stbuf->atime;
    stbuf->ctime = stbuf->atime;
}

void av_curr_time(avtimestruc_t *tim)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    tim->sec = tv.tv_sec;
    tim->nsec = tv.tv_usec * 1000;
}

avtime_t av_time()
{
    return time(NULL);
}

void av_sleep(unsigned long msec)
{
    struct timespec rem;
    int res;

    rem.tv_sec = msec / 1000;
    rem.tv_nsec = (msec % 1000) * 1000 * 1000;

    do {
        struct timespec req;

        req = rem;
        res = nanosleep(&req, &rem);
    } while(res == -1 && errno == EINTR);
}


avtime_t av_mktime(struct avtm *tp)
{
    struct tm tms;
  
    tms.tm_sec  = tp->sec;
    tms.tm_min  = tp->min;
    tms.tm_hour = tp->hour;
    tms.tm_mday = tp->day;
    tms.tm_mon  = tp->mon;
    tms.tm_year = tp->year;
    tms.tm_isdst = -1;

    return mktime(&tms);
}

void av_localtime(avtime_t t, struct avtm *tp)
{
    struct tm tms;
  
    localtime_r(&t, &tms);
  
    tp->sec  = tms.tm_sec;
    tp->min  = tms.tm_min;
    tp->hour = tms.tm_hour;
    tp->day  = tms.tm_mday;
    tp->mon  = tms.tm_mon;
    tp->year = tms.tm_year;
}


void av_registerfd(int fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

