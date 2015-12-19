/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "server.h"
#include "cmd.h"
#include "send.h"
#include "internal.h"
#include "operutil.h"
#include "oper.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <poll.h>
#include <assert.h>

#define MULTITHREADED 1

#if MULTITHREADED
#include <pthread.h>
#endif

enum file_holder_state {
    FIH_DELETED = -1,
    FIH_UNUSED = 0,
    FIH_USED = 1,
};

struct file_holder {
    enum file_holder_state state;
    int serverfh;
};

static struct file_holder *file_holders;
static unsigned int file_holder_num;
static AV_LOCK_DECL(file_holder_lock);

struct cmdinfo {
    int fd;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
};

static void init_inmsg(struct avfs_in_message *inmsg)
{
    int i;

    for(i = 1; i < MAXSEG; i++)
        inmsg->seg[i].buf = NULL;
}

static void free_inmsg(struct avfs_in_message *inmsg)
{
    int i;

    for(i = 1; i < MAXSEG; i++) {
        if(inmsg->seg[i].buf)
            free(inmsg->seg[i].buf);
    }
}

static int entry_local(ventry *ve)
{
    if(ve->mnt->base == NULL)
        return 1;
    else
        return 0;
}


static int getattr_entry(ventry *ve, struct avstat *stbuf, int attrmask,
                         int flags)
{
    int res;
    vfile vf;
    
    res = av_file_open(&vf, ve, AVO_NOPERM | flags, 0);
    if(res == 0) {
        res = av_file_getattr(&vf, stbuf, attrmask);
        av_file_close(&vf);
    }

    return res;
}

static void send_error(int fd, int error)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_result result;
    
    outmsg.num = 1;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    
    result.result = error;
    res = __av_write_message(fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");
}

static int do_readdir(int fd, struct avfs_direntry *de, char *name)
{
    int res;
    struct avdirent buf;
    avoff_t n;
    
    res = av_fd_readdir(fd, &buf, &n);
    if(res > 0) {
        de->ino = buf.ino;
        de->type = buf.type;
        de->n = n;
        strncpy(name, buf.name, NAME_MAX);
        name[NAME_MAX] = '\0';
        av_free(buf.name);
    }

    return res;
}

static void process_getattr(struct cmdinfo *ci)
{
    int res;
    char *path = ci->inmsg.seg[1].buf;
    int flags = ci->cmd.u.getattr.flags;
    int attrmask = ci->cmd.u.getattr.attrmask;
    struct avstat stbuf;
    ventry *ve;
    struct avfs_out_message outmsg;
    struct avfs_result result;

    av_log(AVLOG_SYSCALL, "getattr(\"%s\", 0%o, 0%o)",
             path, flags, attrmask);
    
    outmsg.num = 3;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    outmsg.seg[1].len = 0;
    outmsg.seg[2].len = 0;

    res = av_get_ventry(path, !(flags & AVO_NOFOLLOW), &ve);
    if(res < 0)
        result.result = res;
    else {
        if(entry_local(ve)) {
            result.result = -EPERM;
            outmsg.seg[1].buf = (char *) ve->data;
            outmsg.seg[1].len = strlen(outmsg.seg[1].buf) + 1;
            if(outmsg.seg[1].len > PATHBUF_LEN) {
                outmsg.seg[1].len = 0;
                result.result = -ENAMETOOLONG;
            }
        }
        else {
            res = getattr_entry(ve, &stbuf, attrmask, flags);
            result.result = res;
            if(res == 0) {
                outmsg.seg[2].buf = &stbuf;
                outmsg.seg[2].len = sizeof(stbuf);
            }
        }
    }

    av_log(AVLOG_SYSCALL, "   getattr(\"%s\", 0%o, 0%o) = %i (%s)",
             path, flags, attrmask, result.result,
             outmsg.seg[1].len ? (char *) ve->data : "");

    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");

    av_free_ventry(ve);    
}

static void register_holder(int holderfd, int serverfh)
{
    int needclose = 0;
    int state;

    AV_LOCK(file_holder_lock);
    state = file_holders[holderfd].state;

    av_log(AVLOG_DEBUG, "register_holder: %i, state: %i/%i, serverfh: %i",
             holderfd, state,  file_holders[holderfd].serverfh, serverfh);
    
    if(state == FIH_USED) {
        if(serverfh < 0)
            file_holders[holderfd].state = FIH_UNUSED;
        else
            file_holders[holderfd].serverfh = serverfh;
    }
    else {
        if(serverfh >= 0)
            needclose = 1;

        file_holders[holderfd].state = FIH_UNUSED;
        close(holderfd);
    }
    AV_UNLOCK(file_holder_lock);

    if(needclose)
        av_fd_close(serverfh);
}

static void process_open(struct cmdinfo *ci)
{
    int res;
    char *path = ci->inmsg.seg[1].buf;
    int flags = ci->cmd.u.open.flags;
    mode_t mode = ci->cmd.u.open.mode;
    ventry *ve;
    struct avfs_out_message outmsg;
    struct avfs_result result;

    av_log(AVLOG_SYSCALL, "open(\"%s\", 0%o, 0%lo)", path, flags,
           (unsigned long) mode);
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    outmsg.seg[1].len = 0;

    res = av_get_ventry(path, 1, &ve);
    if(res < 0)
        result.result = res;
    else {
        if(entry_local(ve)) {
            result.result = -EPERM;
            outmsg.seg[1].buf = (char *) ve->data;
            outmsg.seg[1].len = strlen(outmsg.seg[1].buf) + 1;
            if(outmsg.seg[1].len > PATHBUF_LEN) {
                outmsg.seg[1].len = 0;
                result.result = -ENAMETOOLONG;
            }
        }
        else {
            struct avstat stbuf;

            res = getattr_entry(ve, &stbuf, AVA_MODE, 0);
            if(res == 0) {
                if(AV_ISDIR(stbuf.mode))
                    res = av_fd_open_entry(ve, flags | AVO_DIRECTORY, mode);
                else
                    res = av_fd_open_entry(ve, flags, mode);
            }
            else if(res == -ENOENT && (flags & AVO_CREAT) != 0)
                res = av_fd_open_entry(ve, flags, mode);

            result.result = res;
        }
    }
    av_log(AVLOG_SYSCALL, "   open(\"%s\", 0%o, 0%lo) = %i (%s)",
             path, flags, (unsigned long) mode, result.result,
             outmsg.seg[1].len ? (char *) ve->data : "");

    register_holder(ci->fd, result.result);

    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");

    av_free_ventry(ve);    
}


static void process_close(struct cmdinfo *ci)
{
    int res;
    int fh = ci->cmd.u.fdops.serverfh;
    struct avfs_out_message outmsg;
    struct avfs_result result;

    av_log(AVLOG_SYSCALL, "close(%i)", fh);
    
    outmsg.num = 1;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;

    result.result = av_fd_close(fh);
    av_log(AVLOG_SYSCALL, "   close(%i) = %i", fh, result.result);

    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");
}

static void process_fstat(struct cmdinfo *ci)
{
    int res;
    int fh = ci->cmd.u.fdops.serverfh;
    struct avfs_out_message outmsg;
    struct avfs_result result;
    struct avstat stbuf;

    av_log(AVLOG_SYSCALL, "fstat(%i)", fh);
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    outmsg.seg[1].len = 0;

    result.result = av_fd_getattr(fh, &stbuf, AVA_ALL);
    if(result.result == 0) {
        outmsg.seg[1].len = sizeof(stbuf);
        outmsg.seg[1].buf = &stbuf;
    }

    av_log(AVLOG_SYSCALL, "   fstat(%i) = %i", fh, result.result);

    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");
}

static void process_readdir(struct cmdinfo *ci)
{
    int res;
    int fh = ci->cmd.u.fdops.serverfh;
    struct avfs_out_message outmsg;
    struct avfs_result result;
    char name[NAME_MAX + 1];
    struct avfs_direntry de;

    av_log(AVLOG_SYSCALL, "readdir(%i, ...)", fh);
    
    outmsg.num = 3;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    outmsg.seg[1].len = 0;
    outmsg.seg[2].len = 0;

    result.result = do_readdir(fh, &de, name);
    if(result.result > 0) {
        outmsg.seg[1].len = sizeof(de);
        outmsg.seg[1].buf = &de;
        outmsg.seg[2].len = strlen(name) + 1;
        outmsg.seg[2].buf = name;
    }

    av_log(AVLOG_SYSCALL, "   readdir(%i, {%s, %lli, %i}) = %i",
             fh, result.result > 0 ? name : "", de.ino, de.n, result.result);

    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");
}

static void process_lseek(struct cmdinfo *ci)
{
    int res;
    int fh = ci->cmd.u.lseek.serverfh;
    avoff_t offset = ci->cmd.u.lseek.offset;
    int whence = ci->cmd.u.lseek.whence;
    struct avfs_out_message outmsg;
    struct avfs_result result;

    av_log(AVLOG_SYSCALL, "lseek(%i, %lli, %i)", fh, offset, whence);
    
    outmsg.num = 1;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;

    result.u.lseek.offset = av_fd_lseek(fh, offset, whence);

    av_log(AVLOG_SYSCALL, "   lseek(%i, %lli, %i) == %lli",
             fh, offset, whence, result.u.lseek.offset);

    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");
}

static void process_read(struct cmdinfo *ci)
{
    int res;
    int fh = ci->cmd.u.readwrite.serverfh;
    avsize_t nbyte = ci->cmd.u.readwrite.nbyte;
    struct avfs_out_message outmsg;
    struct avfs_result result;
    void *buf;
        
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    outmsg.seg[1].len = 0;
    
    buf = av_malloc(nbyte);

    result.result = av_fd_read(fh, buf, nbyte);
    if(result.result > 0) {
        outmsg.seg[1].len = result.result;
        outmsg.seg[1].buf = buf;
    }
   
    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");

    av_free(buf);
}

static void process_write(struct cmdinfo *ci)
{
    int res;
    int fh = ci->cmd.u.readwrite.serverfh;
    avsize_t nbyte = ci->cmd.u.readwrite.nbyte;
    struct avfs_out_message outmsg;
    struct avfs_result result;
    const void *buf = ci->inmsg.seg[1].buf;

    av_log(AVLOG_SYSCALL, "write(%i, ..., %u)", fh, nbyte);
    
    outmsg.num = 1;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    
    result.result = av_fd_write(fh, buf, nbyte);
   
    av_log(AVLOG_SYSCALL, "   write(%i, ..., %u) = %i",
             fh, nbyte, result.result);


    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");
}


static void process_resolve(struct cmdinfo *ci)
{
    int res;
    char *path = ci->inmsg.seg[1].buf;
    ventry *ve;
    struct avfs_out_message outmsg;
    struct avfs_result result;
    char *newpath = NULL;
    
    av_log(AVLOG_SYSCALL, "resolve(\"%s\")", path);
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    outmsg.seg[1].len = 0;

    res = av_get_ventry(path, 1, &ve);
    if(res < 0)
        result.result = res;
    else {
        if(entry_local(ve))
            result.u.resolve.isvirtual = 0;
        else
            result.u.resolve.isvirtual = 1;

        res = av_generate_path(ve, &newpath);
        result.result = res;
        if(res == 0) {
            outmsg.seg[1].buf = newpath;
            outmsg.seg[1].len = strlen(outmsg.seg[1].buf) + 1;
            if(outmsg.seg[1].len > PATHBUF_LEN) {
                outmsg.seg[1].len = 0;
                result.result = -ENAMETOOLONG;
            }
        }
        av_free_ventry(ve);    
    }

    av_log(AVLOG_SYSCALL, "   resolve(\"%s\", \"%s\", %i) = %i",
             path, outmsg.seg[1].len ? newpath : "", 
             result.u.resolve.isvirtual, result.result);

    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");
    
    av_free(newpath);
}

static void process_readlink(struct cmdinfo *ci)
{
    int res;
    char *path = ci->inmsg.seg[1].buf;
    avsize_t bufsize = ci->cmd.u.readlink.bufsize;
    char *buf = NULL;
    ventry *ve;
    struct avfs_out_message outmsg;
    struct avfs_result result;

    av_log(AVLOG_SYSCALL, "readlink(\"%s\", ..., %u)", path, bufsize);
    
    outmsg.num = 3;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    outmsg.seg[1].len = 0;
    outmsg.seg[2].len = 0;

    res = av_get_ventry(path, 0, &ve);
    if(res < 0)
        result.result = res;
    else {
        if(entry_local(ve)) {
            result.result = -EPERM;
            outmsg.seg[1].buf = (char *) ve->data;
            outmsg.seg[1].len = strlen(outmsg.seg[1].buf) + 1;
            if(outmsg.seg[1].len > PATHBUF_LEN) {
                outmsg.seg[1].len = 0;
                result.result = -ENAMETOOLONG;
            }
        }
        else {
            res = av_readlink(ve, &buf);
            if(res == 0) {
                avsize_t linklen = strlen(buf);

                result.result = AV_MIN(linklen, bufsize);
                outmsg.seg[2].len = AV_MIN(linklen + 1, bufsize);
                outmsg.seg[2].buf = buf;
            }
            else
                result.result = res;
        }
    }

    av_log(AVLOG_SYSCALL, "   readlink(\"%s\", \"%.*s\", %i) = %i (%s)",
             path, 
             result.result < 0 ? 0 : result.result, buf == NULL ? "" : buf,
             bufsize, result.result, 
             outmsg.seg[1].len ? (char *) ve->data : "");

    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");

    av_free_ventry(ve);    
    av_free(buf);
}

static void process_access(struct cmdinfo *ci)
{
    int res;
    char *path = ci->inmsg.seg[1].buf;
    int amode = ci->cmd.u.access.amode;
    ventry *ve;
    struct avfs_out_message outmsg;
    struct avfs_result result;

    av_log(AVLOG_SYSCALL, "access(\"%s\", 0%o)", path, amode);
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(result);
    outmsg.seg[0].buf = &result;
    outmsg.seg[1].len = 0;

    res = av_get_ventry(path, 1, &ve);
    if(res < 0)
        result.result = res;
    else {
        if(entry_local(ve)) {
            result.result = -EPERM;
            outmsg.seg[1].buf = (char *) ve->data;
            outmsg.seg[1].len = strlen(outmsg.seg[1].buf) + 1;
            if(outmsg.seg[1].len > PATHBUF_LEN) {
                outmsg.seg[1].len = 0;
                result.result = -ENAMETOOLONG;
            }
        }
        else
            result.result =  av_access(ve, amode);
    }

    av_log(AVLOG_SYSCALL, "   access(\"%s\", 0%o) = %i (%s)",
           path, amode, result.result, 
           outmsg.seg[1].len ? (char *) ve->data : "");

    res = __av_write_message(ci->fd, &outmsg);
    if(res == -1)
        av_log(AVLOG_ERROR, "Error sending message\n");

    av_free_ventry(ve);    
}


static void *process_message(void *arg)
{
    struct cmdinfo *ci = (struct cmdinfo *) arg;
    
    switch(ci->cmd.type) {
    case CMD_GETATTR:
        process_getattr(ci);
        break;
        
    case CMD_OPEN:
        process_open(ci);
        break;
        
    case CMD_CLOSE:
        process_close(ci);
        break;
        
    case CMD_FSTAT:
        process_fstat(ci);
        break;
        
    case CMD_READDIR:
        process_readdir(ci);
        break;
        
    case CMD_LSEEK:
        process_lseek(ci);
        break;
        
    case CMD_READ:
        process_read(ci);
        break;

    case CMD_WRITE:
        process_write(ci);
        break;
        
    case CMD_RESOLVE:
        process_resolve(ci);
        break;
        
    case CMD_READLINK:
        process_readlink(ci);
        break;

    case CMD_ACCESS:
        process_access(ci);
        break;
        
    default:
        av_log(AVLOG_ERROR, "Unknown command: %i", ci->cmd.type);
        send_error(ci->fd, -ENOSYS);
    }

    if(ci->cmd.type != CMD_OPEN)
        close(ci->fd);
    free_inmsg(&ci->inmsg);
    av_free(ci);

    return NULL;
}

static void mark_file_holder(int holderfd)
{
    AV_LOCK(file_holder_lock);
    if(holderfd >= file_holder_num) {
        int i;
        unsigned int newnum = holderfd + 1;
        unsigned int newsize = newnum  * sizeof(struct file_holder);

        file_holders = realloc(file_holders, newsize);
        assert(file_holders != NULL);

        for(i = file_holder_num; i <= holderfd; i++)
            file_holders[i].state = FIH_UNUSED;

        file_holder_num = newnum;
    }
    
    if(file_holders[holderfd].state != FIH_UNUSED)
        av_log(AVLOG_ERROR, "Internal Error: file holder %i already used",
                 holderfd);

    file_holders[holderfd].state = FIH_USED;
    file_holders[holderfd].serverfh = -1;
    
    AV_UNLOCK(file_holder_lock);
}

static void unmark_file_holder(int serverfh)
{
    int i;

    AV_LOCK(file_holder_lock);
    for(i = 0; i < file_holder_num; i++) {
        if(file_holders[i].state == FIH_USED &&
           file_holders[i].serverfh == serverfh) {
            file_holders[i].state = FIH_UNUSED;
            close(i);
            break;
        }
    }
    if(i == file_holder_num)
        av_log(AVLOG_DEBUG, "File holder not found for %i", serverfh);

    AV_UNLOCK(file_holder_lock);    
}

static int wait_message(int sock)
{
    int i;
    int nfds;
    struct pollfd *fds;
    int canaccept;
    int res;

    while(1) {
        AV_LOCK(file_holder_lock);
        nfds = 1;
        for(i = 0; i < file_holder_num; i++) {
            if(file_holders[i].state == FIH_USED)
                nfds++;
        }
        /* This is not av_malloc(), because exit will usually happen
           during poll(), and then there would be one unfreed memory. */
        fds = malloc(sizeof(struct pollfd) * nfds);
        nfds = 1;
        for(i = 0; i < file_holder_num; i++) {
            if(file_holders[i].state == FIH_USED) {
                fds[nfds].fd = i;
                fds[nfds].events = POLLIN;
                nfds++;
            }
        }
        AV_UNLOCK(file_holder_lock);
        fds[0].fd = sock;
        fds[0].events = POLLIN;
        
        do res = poll(fds, nfds, -1);
        while(res == -1 && (errno == EAGAIN || errno == EINTR));

        if(res == -1) {
            av_log(AVLOG_ERROR, "poll(): %s", strerror(errno));
            exit(1);
        }

        for(i = 1; i < nfds; i++) {
            if(fds[i].revents != 0) {
                int holderfd = fds[i].fd;
                int serverfh;

                AV_LOCK(file_holder_lock);
                serverfh = file_holders[holderfd].serverfh;

                {
                    char c;
                    av_log(AVLOG_DEBUG, "File holder closed: %i", holderfd);
                    av_log(AVLOG_DEBUG, "serverfh: %i", serverfh);
                    av_log(AVLOG_DEBUG, "state: %i",
                             file_holders[holderfd].state);
                    av_log(AVLOG_DEBUG, "revents: 0%o", fds[i].revents);
                    res = read(holderfd, &c, 1);
                    av_log(AVLOG_DEBUG, "read: %i, (%i)", res, c);
                }
                
                if(file_holders[holderfd].state == FIH_USED) {
                    if(serverfh == -1)
                        file_holders[holderfd].state = FIH_DELETED;
                    else {
                        close(holderfd);
                        file_holders[holderfd].state = FIH_UNUSED;
                    }
                }
                else 
                    close(holderfd);

                AV_UNLOCK(file_holder_lock);

                av_log(AVLOG_DEBUG, "File holder for %i closed", serverfh);
                                
                if(serverfh != -1)
                    av_fd_close(serverfh);
            }
        }

        canaccept = fds[0].revents;

        free(fds);
        
        if(canaccept) {
            int fd;

            fd = accept(sock, NULL, NULL);
            if(fd == -1) {
                av_log(AVLOG_ERROR, "accept(): %s", strerror(errno));
                exit(1);
            }

            return fd;
        }
    }
}

int main()
{
    int sock;

#if MULTITHREADED
    pthread_attr_t attr;
    pthread_t thrid;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#endif

    sock = server_init();

    while(1) {
        int fd;
        int res;
        struct cmdinfo *ci;

        fd = wait_message(sock);
        
        AV_NEW(ci);
        init_inmsg(&ci->inmsg);
        ci->inmsg.seg[0].buf = &ci->cmd;

        res = __av_read_message(fd, &ci->inmsg);
        if(res == -1)
            av_log(AVLOG_ERROR, "Error reading message");
        else {
            ci->fd = fd;

            if(ci->cmd.type == CMD_OPEN)
                mark_file_holder(ci->fd);
            else if(ci->cmd.type == CMD_CLOSE)
                unmark_file_holder(ci->cmd.u.fdops.serverfh);
            
#if MULTITHREADED
            res = pthread_create(&thrid, &attr, process_message, ci);
            if(res != 0) 
                av_log(AVLOG_ERROR, "Error creating thread: %i",
                         res);
#else
            process_message(ci);
#endif
        }
    }
    
    return 0;
}

