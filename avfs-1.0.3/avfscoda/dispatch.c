/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "avfscoda.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <syslog.h>

/* #include "KERNINCLUDE/linux/coda.h" */
#include CODAINCLUDE

/* Keep file lookups cached for at least this many seconds: */
#define KEEPTIME 600

/* Flush attribute caches after this many seconds */
#define FLUSHTIME 2

/* Keep at most this many looked up files cached: */
#define MAXFILES 5000

/* Check looked up files after this many operations: */
#define CHECKNUM 1000

/* Maximum number of child processes running: */
#define MAXUSERS 10

#define MAXMSGLEN 1045


struct operation {
    struct operation *next;
    union inputArgs *req;
	
    char ibuf[MAXMSGLEN];
};

struct userinfo {
    uid_t uid;
    gid_t gid;
    volatile pid_t serverpid;
    int pipout;
    int pipin;
    time_t lastuse;
    int terminated;
    struct operation *ops;
};

static struct userinfo currusers[MAXUSERS];

static int codafd;
static const char *codadir;
static FILE *logfile;

static int numfids;
static int checknum;

static int debugmode;

struct openfile {
    pid_t pid;
    char *tmpfile;
    int fd;
    int use;
    int wuse;
	
    struct openfile *next;
};

struct fileinfo {
    struct fileinfo *prev;
    struct fileinfo *next;
	
    char *name;
    char *path;
    unsigned int unique;
    unsigned int parunique;
	
    time_t lasttime;
    int use;
	
    struct openfile *ofs;
};

#define FMAPSIZE 65536
static struct fileinfo *fmap[FMAPSIZE];
static unsigned int nextunique = 0;

#define HASHSIZE 6247
static struct fileinfo *fhash[HASHSIZE];

static int needflush;

static struct fileinfo unused_files;

static void log(const char *, ...) __attribute__ ((format (printf, 1, 2)));
static void log(const char *fmt, ...)
{
    if(debugmode) {
	va_list ap;
	
	va_start(ap, fmt);
	vfprintf(logfile, fmt, ap);
	va_end(ap);
    }
}

static void log_date()
{
    if(debugmode) {
        struct tm tm;
        struct timeval tv;

        gettimeofday(&tv, NULL);
        localtime_r(&tv.tv_sec, &tm);        
        log("%02i/%02i %02i:%02i:%02i.%03i\n", 
            tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
            (int) (tv.tv_usec / 1000));
    }
}

#define LOGMSG_SIZE 1024
static void logerr(const char *, ...) __attribute__ ((format (printf, 1, 2)));
static void logerr(const char *fmt, ...)
{
    char buf[LOGMSG_SIZE + 1];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, LOGMSG_SIZE, fmt, ap);
    va_end(ap);

    buf[LOGMSG_SIZE] = '\0';
    syslog(LOG_INFO, "%s", buf);
    log(buf);
}

static unsigned int fi_hash(unsigned int unique, const char *name)
{
    unsigned int hash = unique;

    for(; *name != 0; name++) {
	hash = (hash << 4) | (hash >> 28);
	hash ^= (unsigned int) *name;
    }
    return hash % HASHSIZE;
}

static struct fileinfo *remove_name(struct fileinfo *parentdir,
				    const char *name)
{
    struct fileinfo **fip;
    unsigned int hash = fi_hash(parentdir->unique, name);
    
    for(fip = &fhash[hash]; *fip != NULL; fip = &(*fip)->next) {
	struct fileinfo *fi = *fip;
	if(fi->parunique == parentdir->unique && strcmp(fi->name, name) == 0) {
	    *fip = fi->next;
	    return fi;
	}
    }

    return NULL;
}


static void add_name(struct fileinfo *fi, struct fileinfo *parentdir,
                     const char *name, int hash)
{
    fi->next = fhash[hash];
    fhash[hash] = fi;

    fi->name = strdup(name);
    fi->parunique = parentdir->unique;
    fi->path = (char *) malloc(strlen(parentdir->path) + 1 + strlen(name) + 1);
    sprintf(fi->path, "%s/%s", parentdir->path, name);
}

static void rename_file(struct fileinfo *oldfi, const char *oldname,
			struct fileinfo *newfi, const char *newname)
{
    struct fileinfo *fi;

    fi = remove_name(oldfi, oldname);
    if(fi != NULL) {
	unsigned int hash = fi_hash(newfi->unique, newname);
	
	free(fi->name);
	free(fi->path);
	add_name(fi, newfi, newname, hash);
    }

}

static struct fileinfo *get_file(struct fileinfo *parentdir, const char *name)
{
    unsigned int hash = fi_hash(parentdir->unique, name);
    struct fileinfo *fi;
    int i;

    for(fi = fhash[hash]; fi != NULL; fi = fi->next)
	if(fi->parunique == parentdir->unique && strcmp(fi->name, name) == 0)
	    return fi;

    fi = malloc(sizeof(*fi));
    if(fi == NULL) {
        logerr("Out of memory");
        clean_exit(1);
    }
    
    for(i = 0; i < FMAPSIZE; i++) {
        unsigned int index;

        nextunique ++;
        if(nextunique == 0)
            nextunique = 1;

        index = nextunique % FMAPSIZE;
        if(fmap[index] == NULL) {
            fmap[index] = fi;
            fi->unique = nextunique;
            break;
        }
    }

    if(i == FMAPSIZE) {
        logerr("fmap full\n");
        clean_exit(1);
    }

    log("New fid: 0x%x\n", fi->unique);

    numfids ++;

    fi->lasttime = time(NULL);
    fi->ofs = NULL;
    fi->use = 0;

    add_name(fi, parentdir, name, hash);

    return fi;
}


static void put_file(struct fileinfo *fi)
{
    struct fileinfo *prev;
    struct fileinfo *next;

    log("Put fid: 0x%x\n", fi->unique);

    prev = unused_files.prev;
    next = &unused_files;
    prev->next = fi;
    next->prev = fi;
    fi->next = next;
    fi->prev = prev;

    free(fi->name);
    fi->name = NULL;
}

static void remove_file(struct fileinfo *parentdir, const char *name)
{
    struct fileinfo *fi;

    fi = remove_name(parentdir, name);
    if(fi != NULL)
	put_file(fi);
}


static void delete_file(struct fileinfo *fi)
{
    unsigned int index;
    struct fileinfo *prev = fi->prev;
    struct fileinfo *next = fi->next;

    log("Delete fid: 0x%x\n", fi->unique);

    prev->next = next;
    next->prev = prev;

    index = fi->unique % FMAPSIZE;
    fmap[index] = NULL;

    free(fi->name);
    free(fi->path);
    free(fi);
    numfids --;
}

static struct fileinfo *get_info(unsigned int unique)
{
    struct fileinfo *fi;
    unsigned int index = (unique % FMAPSIZE);

    fi = fmap[index];
    if(fi == NULL || fi->unique != unique) {
        logerr("Deleted Fid: 0x%x\n", unique);
        return NULL;
    }
    return fi;
}

static struct fileinfo *look_info(ViceFid *id)
{
    struct fileinfo *fi;
	
    if ((id->Volume != 0) || (id->Vnode != 0)) {
        logerr("Bad handle passed %lx/%lx/%lx\n", 
            id->Volume, id->Vnode, id->Unique );
        clean_exit(1);
    }
	
    log("unique: 0x%x\n", (unsigned int) id->Unique);
	
    if(id->Unique == 0) {
	static struct fileinfo rootinfo;
	rootinfo.path = "/";
        return &rootinfo;
    }
    else {
        fi = get_info(id->Unique);
        if(fi != NULL)
            fi->lasttime = time(NULL);
		
        return fi;
    }
}

static char *look_name(ViceFid *id)
{
    struct fileinfo *fi;
	
    fi = look_info(id);
    if(fi == NULL)
        return NULL;

    log("path: %s\n", fi->path);
	
    return fi->path;
}

static void ref_fid(ViceFid *fid)
{
    struct fileinfo *fi = look_info(fid);

    if(fi != NULL)
        fi->use ++;
}

static void unref_fid(ViceFid *fid)
{
    struct fileinfo *fi = look_info(fid);

    if(fi != NULL)
        fi->use --;
}

static void reset_signal_handlers()
{
    struct sigaction sa;
	
    sa.sa_handler = SIG_DFL;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;
	
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
}


static void send_to_kernel(union outputArgs *rep, int size)
{
    int ret;
	
    log("%i bytes\n",  size);
    ret = write(codafd, rep, size);
    if(ret == -1 || ret != size) {
        logerr("Error writing to device: %s\n", strerror(errno));
    }
}

static struct fileinfo *create_file(const char *filename, ViceFid *parentid,
                                    ViceFid *newid)
{
    struct fileinfo *fi;

    fi = look_info(parentid);
    if(fi == NULL)
        return NULL;
    fi = get_file(fi, filename);

    newid->Volume = 0;
    newid->Vnode = 0;
    newid->Unique = fi->unique;

    return fi;
}

static void purge_file(struct fileinfo *fi)
{
    union outputArgs rep;

    log("=================================================================\n");
    log_date();
    log("Cleaning out 0x%x\n", fi->unique);
    log("CODA_PURGEFID\n");
    
    rep.oh.opcode = CODA_PURGEFID;
    rep.oh.result = 0;
    rep.oh.unique = 0;
    rep.coda_purgefid.CodaFid.Volume = 0;
    rep.coda_purgefid.CodaFid.Vnode  = 0;
    rep.coda_purgefid.CodaFid.Unique = fi->unique;
    
    send_to_kernel(&rep, sizeof(rep.coda_purgefid));
}

static void zap_file(struct fileinfo *fi)
{
    union outputArgs rep;

    log("=================================================================\n");
    log_date();
    log("Cleaning out 0x%x\n", fi->unique);
    log("CODA_ZAPFILE\n");
    
    rep.oh.opcode = CODA_ZAPFILE;
    rep.oh.result = 0;
    rep.oh.unique = 0;
    rep.coda_zapfile.CodaFid.Volume = 0;
    rep.coda_zapfile.CodaFid.Vnode  = 0;
    rep.coda_zapfile.CodaFid.Unique = fi->unique;
    
    send_to_kernel(&rep, sizeof(rep.coda_zapfile));
}

#if 0
static void zap_dir(struct fileinfo *fi)
{
    union outputArgs rep;

    log("=================================================================\n");
    log_date();
    log("Cleaning out 0x%x\n", fi->unique);
    log("CODA_ZAPDIR\n");
    
    rep.oh.opcode = CODA_ZAPDIR;
    rep.oh.result = 0;
    rep.oh.unique = 0;
    rep.coda_zapdir.CodaFid.Volume = 0;
    rep.coda_zapdir.CodaFid.Vnode  = 0;
    rep.coda_zapdir.CodaFid.Unique = fi->unique;
    
    send_to_kernel(&rep, sizeof(rep.coda_zapdir));
}
#endif

static void clean_up(time_t oldtime)
{
    int i;

    for(i = 0; i < HASHSIZE; i++) {
	struct fileinfo **fip = &fhash[i];

	while(*fip != NULL) {
	    struct fileinfo *fi = *fip;
		
	    if((!oldtime || fi->lasttime < oldtime) && fi->use == 0) {
		*fip = fi->next;
		purge_file(fi);
		put_file(fi);
	    }
	    else
		fip = &fi->next;        
	}
    }
}

static void clean_up_unused()
{
    struct fileinfo *fi;

    for(fi = unused_files.next; fi != &unused_files;) {
        struct fileinfo *nextfi = fi->next;
        if(fi->use == 0)
            delete_file(fi);

        fi = nextfi;
    }
}


static void clean_up_names()
{
    clean_up_unused();

    if(numfids > FMAPSIZE / 2)
        clean_up(0);
    else
        clean_up(time(NULL) - KEEPTIME);
}

static void open_file(union inputArgs *req, struct openfile *of)
{
    int ret;
    union outputArgs rep;
    struct stat stbuf;
	
    rep.oh.opcode = req->ih.opcode;
    rep.oh.unique = req->ih.unique;
	
    if(req->ih.opcode == CODA_OPEN) {
        ret = stat(of->tmpfile, &stbuf);
        if(ret == -1) 
            rep.oh.result = errno;
        else {
            rep.oh.result = 0;
            rep.coda_open.dev = stbuf.st_dev;
            rep.coda_open.inode = stbuf.st_ino;
            
            log("dev: %lli, ino: %lli\n", rep.coda_open.dev,
                rep.coda_open.inode);
            log("size: %lli\n", stbuf.st_size);
            of->use ++;
            if((req->coda_open.flags & (C_O_WRITE | C_O_TRUNC)) != 0)
                of->wuse ++;
        }
	
        send_to_kernel(&rep, sizeof(rep.coda_open));
    }
#ifdef CODA_OPEN_BY_FD
    else {
        if(of->fd == -1) {
            of->fd = open(of->tmpfile, O_RDONLY);
            if(of->fd == -1)
                rep.oh.result = errno;
        }
        if(of->fd != -1) {
            rep.oh.result = 0;
            rep.coda_open_by_fd.fd =  of->fd;
            
            log("fd: %i\n", of->fd);

            of->use ++;
            if((req->coda_open.flags & (C_O_WRITE | C_O_TRUNC)) != 0)
                of->wuse ++;
        }
        send_to_kernel(&rep, sizeof(rep.coda_open_by_fd));
    }
#endif
}

static void del_file(const char *tmpname)
{
    int res;
	
    /* Coda holds on to the inode, so to free up space: */
    truncate(tmpname, 0);
    res = unlink(tmpname);
    if(res == -1)
        fprintf(stderr, "unlink(%s) failed (%s)\n", 
                tmpname, strerror(errno));
}

static void close_file(struct openfile *of, struct openfile **ofp,
                       ViceFid *fid)
{
    
    if(of->use > 0) of->use --;
    if(of->use == 0 && of->tmpfile != NULL) {
        if(of->fd != -1)
            close(of->fd);
        del_file(of->tmpfile);
        free(of->tmpfile);
        *ofp = of->next;
        free(of);
        unref_fid(fid);
    }
}

static void reply(union inputArgs *req, int res)
{
    union outputArgs rep;
	
    rep.oh.opcode = req->ih.opcode;
    rep.oh.unique = req->ih.unique;
    rep.oh.result = res;
	
    send_to_kernel(&rep, sizeof(rep.oh));
}

static void check_servers()
{
    int i;
		
    for(i = 0; i < MAXUSERS; i++) {
        if(currusers[i].serverpid == 0) {
            /* FIXME: reply to the pending messages */
			
            close(currusers[i].pipout);
            close(currusers[i].pipin);
			
            currusers[i].serverpid = -1;
        }
    }
}

static void grab_fids(union inputArgs *req)
{
    /* All have first VFid in the same place */
    ref_fid(&req->coda_getattr.VFid);
    
    if(req->ih.opcode == CODA_LINK)
        ref_fid(&req->coda_link.destFid);
    if(req->ih.opcode == CODA_RENAME)
        ref_fid(&req->coda_rename.destFid);
}

static void release_fids(union inputArgs *req)
{
    /* All have first VFid in the same place */
    unref_fid(&req->coda_getattr.VFid);
    
    if(req->ih.opcode == CODA_LINK)
        unref_fid(&req->coda_link.destFid);
    if(req->ih.opcode == CODA_RENAME)
        unref_fid(&req->coda_rename.destFid);
}

static void process_answer(struct userinfo *user)
{
    int numread;
    char obuf[MAXMSGLEN];
    union outputArgs *rep = (union outputArgs *) obuf;
    struct operation *op, **opp;
    struct fileinfo *fi;
    struct openfile *of, **ofp;
    char *filename;
    int insize;

    if(!needflush)
        needflush = time(NULL);

    numread = read(user->pipin, &insize, sizeof(insize));
    if(numread == -1) {
        logerr("Error reading from device: %s\n", strerror(errno));
        return;
    }
    if(insize > MAXMSGLEN || insize <= 0) {
        logerr("Error: illegal size");
        return;
    }
	
    numread = read(user->pipin, obuf, insize);
    if(numread == -1) {
        logerr("Error reading from child [%i/%i]: %s\n", 
            user->uid, user->gid, strerror(errno));
        return;
    }
	
    log("+ %i/%i [%i] +++++++++++++++++++++++++++++++++++++++++++++++++++\n",
        user->uid, user->gid, user->serverpid);
    log_date();
    log("%i (%i) bytes: opcode: %li, result: %i, unique: %li\n", 
        numread, insize, rep->oh.opcode, (int) rep->oh.result, rep->oh.unique);
	
    for(opp = &user->ops; *opp != NULL; opp = &(*opp)->next) 
        if((*opp)->req->ih.unique == rep->oh.unique) break;
	
    op = *opp;
	
    if(op == NULL)
        logerr("Operation not found!!!!\n");
    else {
        log("Found operation: %li\n", op->req->ih.unique);
		
        switch(rep->oh.opcode) {
#ifdef CODA_OPEN_BY_FD
        case CODA_OPEN_BY_FD:
#endif
        case CODA_OPEN:
            fi = look_info(&op->req->coda_open.VFid);

            for(ofp = &fi->ofs; *ofp != NULL; ofp = &(*ofp)->next)
                if((*ofp)->pid == op->req->ih.pid) break;
				
            of = *ofp;

            if(of == NULL) {
                logerr("Output file not found!!!\n");
                reply(op->req, ENOENT);
            }
            else {
                if(rep->oh.result == 0) {
                    open_file(op->req, of);
                }
                else {
                    close_file(of, ofp, &op->req->coda_open.VFid);
                    send_to_kernel(rep, numread);
                }
            }
            break;
        
        case CODA_CLOSE:
            fi = look_info(&op->req->coda_close.VFid);
            
            for(ofp = &fi->ofs; *ofp != NULL; ofp = &(*ofp)->next)
                if((*ofp)->pid == op->req->ih.pid) break;
            
            of = *ofp;

            if(of == NULL) {
                logerr("Output file not found!!!\n");
                reply(op->req, ENOENT);
            }
            else
                close_file(of, ofp, &op->req->coda_close.VFid);

            send_to_kernel(rep, numread);
	    zap_file(fi);
            break;
			
        case CODA_LOOKUP:
            if(rep->oh.result == 0) {
                filename = (char *) op->req + op->req->coda_lookup.name;
                fi = create_file(filename, &op->req->coda_lookup.VFid,
                                 &rep->coda_lookup.VFid);
                if(fi == NULL)
                    rep->oh.result = ENOENT;
            }
            send_to_kernel(rep, numread);
            break;

        case CODA_CREATE:
            if(rep->oh.result == 0) {
                filename = (char *) op->req + op->req->coda_create.name;
                fi = create_file(filename, &op->req->coda_create.VFid,
                                 &rep->coda_create.VFid);
                if(fi == NULL)
                    rep->oh.result = ENOENT;
            }
            send_to_kernel(rep, numread);
            break;

        case CODA_MKDIR:
            if(rep->oh.result == 0) {
                filename = (char *) op->req + op->req->coda_mkdir.name;
                fi = create_file(filename, &op->req->coda_mkdir.VFid,
                                 &rep->coda_mkdir.VFid);
                if(fi == NULL)
                    rep->oh.result = ENOENT;
            }
            send_to_kernel(rep, numread);
            break;

        case CODA_REMOVE:
            if(rep->oh.result == 0) {
                filename = (char *) op->req + op->req->coda_remove.name;
                fi = look_info(&op->req->coda_remove.VFid);
		remove_file(fi, filename);
            }
            send_to_kernel(rep, numread);
            break;

        case CODA_RMDIR:
            if(rep->oh.result == 0) {
                filename = (char *) op->req + op->req->coda_rmdir.name;
                fi = look_info(&op->req->coda_rmdir.VFid);
		remove_file(fi, filename);
            }
            send_to_kernel(rep, numread);
            break;
            
        case CODA_RENAME:
            if(rep->oh.result == 0) {
                char *newname;
                struct fileinfo *newfi;

                newname = (char *) op->req + op->req->coda_rename.destname;
                newfi = look_info(&op->req->coda_rename.destFid);
		remove_file(newfi, newname);

                filename = (char *) op->req + op->req->coda_rename.srcname;
                fi = look_info(&op->req->coda_rename.sourceFid);
		rename_file(fi, filename, newfi, newname);
            }
            send_to_kernel(rep, numread);
            break;

        default:
            send_to_kernel(rep, numread);
			
        }
        
        release_fids(op->req);
        *opp = op->next;
        free(op);
    }
	
    if(user->ops != NULL) {
        log("Remaining operations: ");
        for(op = user->ops; op != NULL; op = op->next)
            log("%li ", op->req->ih.unique);
        log("\n");
    }	
}

static void process_child_answer()
{
    fd_set rfds;
    int ret;
    int maxfd;
    int i;
	
    check_servers();
	
    FD_ZERO(&rfds);
	
    maxfd = 0;
	
    for(i = 0; i < MAXUSERS; i++) {
        if(currusers[i].serverpid > 0) {
            int pipfd = currusers[i].pipin;
			
            FD_SET(pipfd, &rfds);
            if(pipfd > maxfd) maxfd = pipfd;
        }
    }
	
    ret = select(maxfd+1, &rfds, NULL, NULL, NULL);
    if(ret == -1) {
        if(errno != EINTR) 
            logerr("Select failed: %s\n", strerror(errno));
    }
    else {
        for(i = 0; i < MAXUSERS; i++) {
            if(currusers[i].serverpid > 0) {
                int pipfd = currusers[i].pipin;
				
                if(FD_ISSET(pipfd, &rfds)) 
                    process_answer(&currusers[i]);
            }
        }
    }
}

static void kill_child()
{
    struct userinfo *user;
    time_t oldesttime;
    int oldesti;
    int i;
    pid_t pid;
	
    oldesttime = 0;
    oldesti = -1;
	
    do {
        for(i = 0; i < MAXUSERS; i++) {
            user = currusers + i;
            if(user->serverpid == -1) return;
            if(user->serverpid == 0) {
                check_servers();
                return;
            }
			
            if(user->ops == NULL) {
                if(oldesti == -1 || 
                   user->lastuse < oldesttime) {
                    oldesttime = user->lastuse;
                    oldesti = i;
                }
            }
        }
		
        if(oldesti == -1) {
            /* If every child is busy then block */
            process_child_answer();
        }
    } while(oldesti == -1);
	
    user = currusers + oldesti;
	
    /* FIXME: This is a mess, because user->serverpid can change to 0 
       when SIGCHLD is received */
    pid = user->serverpid;
    if(pid > 0) {
        if(!user->terminated) {
            kill(pid, SIGTERM);
            user->terminated = 1;
        }
        else {
            log("kill(%i, SIGKILL)\n", pid);
            kill(pid, SIGKILL);
        }
    }
	
    /* FIXME: Need to wait for the death of the child or max 1 second. 
       How can this be done? */
    if(user->serverpid > 0)
        sleep(1);
	
    check_servers();
}

static int new_child(struct userinfo *user, uid_t uid, gid_t gid)
{
    int pipout[2];
    int pipin[2];
    int pid;
    int i;
    gid_t list[32];
    int num;
	
    if(pipe(pipout) == -1) {
        logerr("Could not open pipe for child: %s\n", strerror(errno));
        return -1;
    }
    if(pipe(pipin) == -1) {
        close(pipout[0]);
        close(pipout[1]);
        return -1;
    }
	
    user->serverpid = pid = fork();
    if(pid == -1) {
        close(pipout[0]);
        close(pipout[1]);
        close(pipin[0]);
        close(pipin[1]);
        logerr("Could not fork child: %s\n", strerror(errno));
        return -1;
    }
	
    user->pipout = pipout[1];
    user->pipin = pipin[0];
	
    if(pid == 0) {
        /* Child */
		
        reset_signal_handlers();
		
        /* Close everything, except the current pipes */
        for(i = 0; i < MAXUSERS; i++) 
            if(currusers[i].serverpid >= 0) {
                close(currusers[i].pipout);
                close(currusers[i].pipin);
            }
		
        close(codafd);
#if 0
        fclose(logfile);
#endif
        /* Don't want any troublesome signals from the child */
        setsid(); 
		
        /* FIXME: What is the proper way of dealing with
           supplementary groups? */
        list[0] = gid;
        num = 1;
        setgroups(num, list);
		
#if 1
        {
            struct passwd *pwbuf;
			
            /* FIXME: This messes up gdb. Why? */
            pwbuf = getpwuid(uid);
            if(pwbuf != NULL)
                initgroups(pwbuf->pw_name, gid);
        }
#endif
		
        setgid(gid);
        setuid(uid);
		
        fprintf(stderr, "Child process: %i/%i\n", getuid(), getgid());
		
        num = getgroups(32, list);
        fprintf(stderr, "Supplementary groups: ");
        for(i = 0; i < num; i++) fprintf(stderr, "%i, ", list[i]);
        fprintf(stderr, "\n");
		
        child_process(pipout[0], pipin[1]);
        exit(0);
    }
	
    /* Parent */
	
    close(pipout[0]);
    close(pipin[1]);
	
    user->uid = uid;
    user->gid = gid;
    user->terminated = 0;
    user->lastuse = 0;
    user->ops = NULL;
	
    return 0;
}

static struct userinfo *get_user(uid_t uid, gid_t gid)
{
    int i;
    struct userinfo *user = NULL;
	
    for(i = 0; i < MAXUSERS; i++) {
        if(currusers[i].serverpid > 0 && currusers[i].uid == uid &&
           currusers[i].gid == gid) {
            user = &currusers[i];
            break;
        }
    }
	
    if(user == NULL) {
        /* Create child */
        do {
            /* Find a free slot */
            for(i = 0; i < MAXUSERS; i++)
                if(currusers[i].serverpid == -1) break;
			
            if(i == MAXUSERS) {
                /* No free slots, must kill a child */
                kill_child();
            }
        } while(i == MAXUSERS);
		
        user = currusers + i;
        if(new_child(user, uid, gid) == -1)
            return NULL;
    }
	
    user->lastuse = time(NULL);
    return user;
}


static void send_to_child(union inputArgs *req, int reqsize, char *path1,
			  char *path2)
{
    struct operation *op;
    uid_t uid = req->ih.cred.cr_fsuid;
    gid_t gid = req->ih.cred.cr_fsgid;
    struct userinfo *user;
    int msgsize;
    struct child_message msg;
    char *message, *mp;
    int msgoff;
    int res;
    

    user = get_user(uid, gid);
    if(user == NULL) {
        reply(req, ENOMEM);
        return;
    }
	
    msg.reqsize = reqsize;
    msg.path1size = path1 ? strlen(path1) + 1 : 0;
    msg.path2size = path2 ? strlen(path2) + 1 : 0;
    msgoff = sizeof(struct child_message);
	
    msgsize = sizeof(int) + msgoff + msg.reqsize + msg.path1size + 
        msg.path2size;
	
    message = malloc(msgsize);
    if(message == NULL) {
        reply(req, ENOMEM);
        return;
    }
	
    op = malloc(sizeof(struct operation));
    if(op == NULL) {
        free(message);
        reply(req, ENOMEM);
        return;
    }
	
    memcpy(op->ibuf, req, reqsize);
    op->req = (union inputArgs *) op->ibuf;
	
    mp = message;
	
    *(int *) mp = (msgsize - sizeof(int));
    mp += sizeof(int);
	
    memcpy(mp, &msg, msgoff);
    mp += msgoff;
	
    memcpy(mp, req, msg.reqsize);
    mp += msg.reqsize;
	
    log("****** opcode: %li\n", req->ih.opcode);
    log("****** msgsize: %i, msgoff: %i, msg.reqsize: %i, \n", 
        msgsize, msgoff, msg.reqsize);
	
    if(path1) {
        memcpy(mp, path1, msg.path1size);
        mp += msg.path1size;
    }
	
    if(path2) {
        memcpy(mp, path2, msg.path2size);
        mp += msg.path2size;
    }
	
    res = write(user->pipout, message, msgsize);
    free(message);
	
    if(res != msgsize) {
        free(op);
        logerr("Error writing to child: %s\n", strerror(errno));
		
        reply(req, errno);
    }
    else {
        grab_fids(req);
        op->next = user->ops;
        user->ops = op;
    }
}

static void send_with_path(union inputArgs *req, int reqsize, char *filename,
                           ViceFid *id, char *path2)
{
    char pathbuf[1024];
    struct fileinfo *fi;
    char *path;

    fi = look_info(id);
    if(fi == NULL) {
        reply(req, ENOENT);
        return;
    }

    path = fi->path;
		
    sprintf(pathbuf, "%s/%s", path, filename);

    log("path1: %s, path2: %s\n", pathbuf, path2 ? path2 : "(null)");

    /* FIXME: */
    if(strcmp(pathbuf+1, codadir) == 0) 
            reply(req, ENOENT);
    else 
            send_to_child(req, reqsize, pathbuf, path2);
}

static void coda_flush()
{
    union outputArgs rep;
	
    log("=================================================================\n");
    log_date();
    log("CODA_FLUSH\n");
	
    rep.oh.opcode = CODA_FLUSH;
    rep.oh.result = 0;
    rep.oh.unique = 0;
	
    send_to_kernel(&rep, sizeof(rep.oh));
}

void run_exit()
{
    int i;
	
    for(i = 0; i < MAXUSERS; i++) {
        if(currusers[i].serverpid > 0) {
            kill(currusers[i].serverpid, SIGTERM);
        }
    }
	
    /* FIXME: should wait until the children are all dead */
	
    coda_flush();
    close(codafd);
    unmount_coda(codadir, 0);
}

void user_child(pid_t pid)
{
    int i;
	
    for(i = 0; i < MAXUSERS; i++) {
        if(currusers[i].serverpid == pid) {
            log("Child %i (%i/%i) exited\n", 
                pid, currusers[i].uid, 
                currusers[i].gid);
			
            currusers[i].serverpid = 0;
			
            return;
        }
    }
	
    logerr("Unknown child %i exited\n", pid);
}

static void process_kernel_req()
{
    char ibuf[MAXMSGLEN];
    char pathbuf[1024];
    union inputArgs *req = (union inputArgs *) ibuf;
    union outputArgs rep;
    struct openfile *of, **ofp;
    int numread;
    char *path;
    char *filename, *filename2;
    struct fileinfo *fi;
    struct operation **opp, *op;
    int i;
	
    numread = read(codafd, ibuf, MAXMSGLEN);
    if(numread == -1) {
        logerr("Error reading from device: %s\n", strerror(errno));
        clean_exit(1);
    }
	
    log("=================================================================\n");
    log_date();
    log("%i bytes: opcode: %li, unique: %li\n", 
        numread, req->ih.opcode, req->ih.unique);
	
    switch (req->ih.opcode) {
    case CODA_ROOT:
        log("CODA_ROOT\n");
		
        rep.oh.opcode = req->ih.opcode;
        rep.oh.unique = req->ih.unique;
        rep.oh.result = 0;
        rep.coda_root.VFid.Volume = 0;
        rep.coda_root.VFid.Vnode  = 0;
        rep.coda_root.VFid.Unique = 0;           /* 0 means root */
		
        send_to_kernel(&rep, sizeof(rep.coda_root));
        break;
		
    case CODA_GETATTR:
        log("CODA_GETATTR\n");
        path = look_name(&req->coda_getattr.VFid);
        if(path == NULL)
            reply(req, ENOENT);
        else
            send_to_child(req, numread, path, NULL); 
        break;
		
    case CODA_ACCESS:
        log("CODA_ACCESS, flags: 0x%04x\n", req->coda_access.flags);
		
        path = look_name(&req->coda_access.VFid);
        if(path == NULL)
            reply(req, ENOENT);
        else
            send_to_child(req, numread, path, NULL);
        break;
		
#ifdef CODA_OPEN_BY_FD
    case CODA_OPEN_BY_FD:
        log("CODA_OPEN_BY_FD, flags: 0x%04x\n", req->coda_open.flags);
#endif
    case CODA_OPEN:
        if(req->ih.opcode == CODA_OPEN)
            log("CODA_OPEN, flags: 0x%04x\n", req->coda_open.flags);
        
        fi = look_info(&req->coda_open.VFid);
        if(fi == NULL) {
            reply(req, ENOENT);
            break;
        }

        path = fi->path;
        log("path: %s\n", path);
		
        for(of = fi->ofs; of != NULL; of = of->next) 
            if(of->pid == req->ih.pid) break;
		
        if(of != NULL) {
            if((req->coda_open.flags & C_O_TRUNC) != 0) 
                truncate(of->tmpfile, 0);

            open_file(req, of);
        }
        else {
            char tmpname[64];
            int fd;
			
            strcpy(tmpname, "/tmp/.avfs_coda_XXXXXX");
            fd = mkstemp(tmpname);
			
            if(fd == -1) {
                logerr("Could not make temporary file: %s\n", strerror(errno));
                reply(req, ENFILE);
            }
            else {
                fchown(fd, req->ih.cred.cr_fsuid, req->ih.cred.cr_fsgid);
                close(fd);

                of = malloc(sizeof(struct openfile));
                if(of == NULL) {
                    reply(req, ENOMEM);
                }
                else {
                    of->use = 0;
                    of->wuse = 0;
                    of->pid = req->ih.pid;
                    of->tmpfile = strdup(tmpname);
                    of->fd = -1;
                    of->next = fi->ofs;
                    fi->ofs = of;
                    ref_fid(&req->coda_open.VFid);

                    log("tmpfile: %s\n", of->tmpfile);
                    send_to_child(req, numread, path, tmpname);
                }
            }
        }
        break;
		
    case CODA_CLOSE:
        log("CODA_CLOSE, flags: 0x%04x\n", req->coda_close.flags);
		
        fi = look_info(&req->coda_close.VFid);
        if(fi == NULL) {
            reply(req, ENOENT);
            break;
        }

        path = fi->path;
        log("path: %s\n", path);
		
        for(ofp = &fi->ofs; *ofp != NULL; ofp = &(*ofp)->next)
            if((*ofp)->pid == req->ih.pid) break;
		
        of = *ofp;
		
        if(of == NULL) {
            logerr("File not found\n");
            reply(req, ENOENT);
        }
        else {
            int dowrite = 0;

            log("use: %i\n", of->use);
            log("wuse: %i\n", of->wuse);
            if(of->wuse > 0 &&
               (req->coda_close.flags & (C_O_WRITE | C_O_TRUNC)) != 0) {
                of->wuse --;
                
                if(of->wuse == 0 && of->tmpfile != NULL) {
                    log("tmpfile: %s\n", of->tmpfile);
                    dowrite = 1;
                    send_to_child(req, numread, path, of->tmpfile);
                }
            }
            if(!dowrite) {
                close_file(of, ofp, &req->coda_close.VFid);
                reply(req, 0);
            }
        }
        break;
		
    case CODA_LOOKUP:
        /* It is not clear to me, whether lookups should be
           done as 'user' or as 'root' */
		
        filename = ibuf + req->coda_lookup.name;
		
        log("CODA_LOOKUP, name: '%s', flags: 0x%04x\n", 
            filename, req->coda_lookup.flags);
		
        send_with_path(req, numread, filename, &req->coda_lookup.VFid, NULL);
        break;

    case CODA_CREATE:
        filename = ibuf + req->coda_create.name;
		
        log("CODA_CREATE, name: '%s', mode: 0%o, rdev: 0x%04x\n", 
            filename, req->coda_create.mode,
            (int) req->coda_create.attr.va_rdev);
		
        send_with_path(req, numread, filename, &req->coda_create.VFid, NULL);
        break;
		
    case CODA_READLINK:
        log("CODA_READLINK\n");
		
        path = look_name(&req->coda_readlink.VFid);
        if(path == NULL)
            reply(req, ENOENT);
        else
            send_to_child(req, numread, path, NULL);
        break;

    case CODA_SETATTR:
        log("CODA_SETATTR\n");

        path = look_name(&req->coda_setattr.VFid);
        if(path == NULL)
            reply(req, ENOENT);
        else
            send_to_child(req, numread, path, NULL);
        break;

    case CODA_REMOVE:
        filename = ibuf + req->coda_remove.name;
		
        log("CODA_REMOVE, name: '%s'\n", filename);
	       
        send_with_path(req, numread, filename, &req->coda_remove.VFid, NULL);
        break;

    case CODA_RMDIR:
        filename = ibuf + req->coda_rmdir.name;
        
        log("CODA_RMDIR, name: '%s'\n", filename);
	       
        send_with_path(req, numread, filename, &req->coda_rmdir.VFid, NULL);
        break;
        
    case CODA_MKDIR:
        filename = ibuf + req->coda_mkdir.name;
        
        log("CODA_MKDIR, name: '%s', mode: 0%o\n", filename, 
            req->coda_mkdir.attr.va_mode);
	       
        send_with_path(req, numread, filename, &req->coda_mkdir.VFid, NULL);
        break;

    case CODA_RENAME:
        filename = ibuf + req->coda_rename.srcname;
        filename2 = ibuf + req->coda_rename.destname;

        log("CODA_RENAME, name1: '%s', name2: '%s'\n", filename, filename2); 

        fi = look_info(&req->coda_rename.destFid);
        if(fi == NULL) {
            reply(req, ENOENT);
            break;
        }
        sprintf(pathbuf, "%s/%s", fi->path, filename2);
        
        send_with_path(req, numread, filename, &req->coda_rename.sourceFid,
                       pathbuf);
        break;

    case CODA_SYMLINK:
        filename = ibuf + req->coda_symlink.srcname;
        filename2 = ibuf + req->coda_symlink.tname;

        log("CODA_SYMLINK, src: '%s', tname: '%s'\n", filename, filename2); 
        
        send_with_path(req, numread, filename2, &req->coda_symlink.VFid,
                       filename);
        break;

    case CODA_LINK:
        fi = look_info(&req->coda_link.sourceFid);
        if(fi == NULL) {
            reply(req, ENOENT);
            break;
        }
        filename = fi->path;
        filename2 = ibuf + req->coda_link.tname;        
        
        log("CODA_LINK, src: '%s', tname: '%s'\n", filename, filename2);

        send_with_path(req, numread, filename2, &req->coda_link.destFid,
                       filename);
        break;

    case CODA_SIGNAL:
        log("CODA_SIGNAL\n");
        for(i = 0; i < MAXUSERS; i++) {
            for(opp = &currusers[i].ops; *opp != NULL; 
                opp = &(*opp)->next) 
                if((*opp)->req->ih.unique == req->ih.unique) 
                    break;
			
            if(*opp != NULL) break;
        }
        op = *opp;
		
        if(op == NULL) 
            logerr("Operation not found!!!!\n");
        else {
            /* FIXME: Inform the child that the operation
               is interrupted */

            switch(op->req->ih.opcode) {
#ifdef CODA_OPEN_BY_FD
            case CODA_OPEN_BY_FD:
#endif
            case CODA_OPEN:
                fi = look_info(&op->req->coda_open.VFid);

                for(ofp = &fi->ofs; *ofp != NULL; ofp = &(*ofp)->next)
                    if((*ofp)->pid == op->req->ih.pid) break;
				
                of = *ofp;
                if(of != NULL)
                    close_file(of, ofp, &op->req->coda_open.VFid);

                break;

            default:;
            }

            release_fids(op->req);
            *opp = op->next;
            free(op);
        }
        break;
		
    default:
        reply(req, EOPNOTSUPP);
		
        log("========================================\n");
        log("     N o t   I m p l e m e n t e d      \n");
        log("========================================\n");
    }	
}

static void process()
{
    fd_set rfds;
    int ret;
    int maxfd;
    int i;

    unused_files.prev = &unused_files;
    unused_files.next = &unused_files;
	
    while(1) {
        struct timeval timeout;

        check_servers();

        checknum ++;
        if(numfids > MAXFILES && checknum > CHECKNUM) {
            clean_up_names();
            checknum = 0;
	}
		
        FD_ZERO(&rfds);		
        FD_SET(codafd, &rfds);
        maxfd = codafd;
		
        for(i = 0; i < MAXUSERS; i++) {
            if(currusers[i].serverpid > 0) {
                int pipfd = currusers[i].pipin;
				
                FD_SET(pipfd, &rfds);
                if(pipfd > maxfd) maxfd = pipfd;
            }
        }

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
		
        ret = select(maxfd+1, &rfds, NULL, NULL, &timeout);
        if(ret == -1) {
            if(errno == EINTR)
                continue;
            logerr("Select failed: %s\n", strerror(errno));
            continue;
        }
        
        if(needflush && needflush + FLUSHTIME <= time(NULL)) {
            coda_flush();
            needflush = 0;
        }

        if(ret == 0)
            continue;

        log("Numfids: %i\n", numfids);

        if(FD_ISSET(codafd, &rfds))
            process_kernel_req();
		
        for(i = 0; i < MAXUSERS; i++) {
            if(currusers[i].serverpid > 0) {
                int pipfd = currusers[i].pipin;
				
                if(FD_ISSET(pipfd, &rfds))
                    process_answer(&currusers[i]);
            }
        }
    }
}


void run(int cfs, const char *dir, int dm)
{
    int i;

    openlog("avfscoda", LOG_CONS, LOG_USER);
	
    codafd = cfs;
    codadir = dir;
    logfile = stderr;
    numfids = 0;
    checknum = 0;
    debugmode = dm;
	
    for(i = 0; i < MAXUSERS; i++)
        currusers[i].serverpid = -1;
	
    set_signal_handlers();
	
    process();
}
