/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "utils.h"
#include "config.h"

#include <sys/stat.h>
#ifdef HAVE_ACL
#include <sys/acl.h>
#endif

#ifdef HAVE_STAT64
static int real_stat64(const char *path, struct stat64 *buf, int deref,
                       int undersc)
{
    if(!deref) {
        if(undersc == 0) {
            static int (*prev)(const char *, struct stat64 *);
            if(!prev) 
                prev = (int (*)(const char *, struct stat64 *))
                    __av_get_real("lstat64");
            
            return prev(path, buf);
        }
        else {
            static int (*prev)(const char *, struct stat64 *);
            if(!prev) 
                prev = (int (*)(const char *, struct stat64 *))
                    __av_get_real("_lstat64");
            
            return prev(path, buf);
        }
    }
    else {
        if(undersc == 0) {
            static int (*prev)(const char *, struct stat64 *);
            if(!prev) 
                prev = (int (*)(const char *, struct stat64 *)) 
                    __av_get_real("stat64");
            
            return prev(path, buf);
        }
        else {
            static int (*prev)(const char *, struct stat64 *);
            if(!prev) 
                prev = (int (*)(const char *, struct stat64 *)) 
                    __av_get_real("_stat64");
            
            return prev(path, buf);
        }
    }
}

static int real_fstat64(int fd, struct stat64 *buf, int undersc)
{
    if(undersc == 0) {
        static int (*prev)(int, struct stat64 *);
        if(!prev)
            prev = (int (*)(int, struct stat64 *)) __av_get_real("fstat64");
        
        return prev(fd, buf);
    }
    else {
        static int (*prev)(int, struct stat64 *);
        if(!prev)
            prev = (int (*)(int, struct stat64 *)) __av_get_real("_fstat64");
        
        return prev(fd, buf);        
    }
}
#endif

static int real_stat(const char *path, struct stat *buf, int deref,
                     int undersc)
{
    if(!deref) {
        if(undersc == 0) {
            static int (*prev)(const char *, struct stat *);
            if(!prev) 
                prev = (int (*)(const char *, struct stat *))
                    __av_get_real("lstat");
            
            return prev(path, buf);
        }
        else {
            static int (*prev)(const char *, struct stat *);
            if(!prev) 
                prev = (int (*)(const char *, struct stat *))
                    __av_get_real("_lstat");
            
            return prev(path, buf);
        }
    }
    else {
        if(undersc == 0) {
            static int (*prev)(const char *, struct stat *);
            if(!prev) 
                prev = (int (*)(const char *, struct stat *))
                    __av_get_real("stat");
            
            return prev(path, buf);
        }
        else {
            static int (*prev)(const char *, struct stat *);
            if(!prev) 
                prev = (int (*)(const char *, struct stat *))
                    __av_get_real("_stat");
            
            return prev(path, buf);
        }
    }
}

static int real_fstat(int fd, struct stat *buf, int undersc)
{
    if(undersc == 0) {
        static int (*prev)(int, struct stat *);
        if(!prev)
            prev = (int (*)(int, struct stat *)) __av_get_real("fstat");
        
        return prev(fd, buf);
    }
    else {
        static int (*prev)(int, struct stat *);
        if(!prev)
            prev = (int (*)(int, struct stat *)) __av_get_real("_fstat");
        
        return prev(fd, buf);        
    }
}

#ifdef HAVE_ACL
static int real_acl(const char *path, int cmd, int nent, aclent_t *aclbuf,
                    int undersc)
{
    if(undersc == 0) {
        static int (*prev)(const char *, int, int, aclent_t *);
        if(!prev)
            prev = (int (*)(const char *, int, int, aclent_t *)) 
                __av_get_real("acl");
        
        return prev(path, cmd, nent, aclbuf);
    }
    else {
        static int (*prev)(const char *, int, int, aclent_t *);
        if(!prev)
            prev = (int (*)(const char *, int, int, aclent_t *)) 
                __av_get_real("_acl");
        
        return prev(path, cmd, nent, aclbuf);
    }
}
#endif

static int real_access(const char *path, int amode, int undersc)
{
    if(undersc == 0) {
        static int (*prev)(const char *, int);
        if(!prev)
            prev = (int (*)(const char *, int))  __av_get_real("access");
        
        return prev(path, amode);
    }
    else {
        static int (*prev)(const char *, int);
        if(!prev)
            prev = (int (*)(const char *, int))  __av_get_real("_access");
        
        return prev(path, amode);
    }
}

static int cmd_getattr(const char *path, struct avstat *buf, int deref,
                       char *pathbuf, int attrmask)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
    struct avfs_result result;
    const char *abspath;

    res = __av_get_abs_path(path, pathbuf, &abspath);
    if(res < 0)
        return res;
    
    cmd.type = CMD_GETATTR;
    if(deref)
        cmd.u.getattr.flags = 0;
    else
        cmd.u.getattr.flags = AVO_NOFOLLOW;
    cmd.u.getattr.attrmask = attrmask;
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;
    outmsg.seg[1].len = strlen(abspath) + 1;
    outmsg.seg[1].buf = abspath;

    inmsg.seg[0].buf = &result;
    inmsg.seg[1].buf = pathbuf;
    inmsg.seg[2].buf = buf;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    if(inmsg.seg[1].len == 0)
        pathbuf[0] = '\0';

    return result.result;
}

static int cmd_access(const char *path, int amode,  char *pathbuf)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
    struct avfs_result result;
    const char *abspath;

    res = __av_get_abs_path(path, pathbuf, &abspath);
    if(res < 0)
        return res;
    
    cmd.type = CMD_ACCESS;
    cmd.u.access.amode = amode;
    
    outmsg.num = 2;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;
    outmsg.seg[1].len = strlen(abspath) + 1;
    outmsg.seg[1].buf = abspath;

    inmsg.seg[0].buf = &result;
    inmsg.seg[1].buf = pathbuf;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    if(inmsg.seg[1].len == 0)
        pathbuf[0] = '\0';

    return result.result;
}


static int fstat_server(int serverfh, struct avstat *buf)
{
    int res;
    struct avfs_out_message outmsg;
    struct avfs_in_message inmsg;
    struct avfs_cmd cmd;
    struct avfs_result result;

    cmd.type = CMD_FSTAT;
    cmd.u.fdops.serverfh = serverfh;
    
    outmsg.num = 1;
    outmsg.seg[0].len = sizeof(cmd);
    outmsg.seg[0].buf = &cmd;

    inmsg.seg[0].buf = &result;
    inmsg.seg[1].buf = buf;

    res = __av_send_message(&outmsg, &inmsg, 0);
    if(res == -1)
        return -EIO;

    return result.result;
}



#ifdef HAVE_STAT64
static void convert_stat64(struct avstat *vbuf, struct stat64 *lbuf)
{
    memset((void *) lbuf, 0, sizeof(*lbuf));
  
    lbuf->st_dev      = vbuf->dev;
    lbuf->st_ino      = vbuf->ino;
    lbuf->st_mode     = vbuf->mode;
    lbuf->st_nlink    = vbuf->nlink;
    lbuf->st_uid      = vbuf->uid;
    lbuf->st_gid      = vbuf->gid;
    lbuf->st_rdev     = vbuf->rdev;
    lbuf->st_size     = vbuf->size;
    lbuf->st_blksize  = vbuf->blksize;
    lbuf->st_blocks   = vbuf->blocks;
    lbuf->st_atime    = vbuf->atime.sec;
    lbuf->st_mtime    = vbuf->mtime.sec;
    lbuf->st_ctime    = vbuf->ctime.sec;
}

static int virt_stat64(const char *path, struct stat64 *buf, int deref,
                       int undersc)
{
    int res = 0;
    int local = 0;

    if(__av_maybe_local(path)) {
        res = real_stat64(path, buf, deref, undersc);
        local = __av_is_local(res, path);
    }
    
    if(!local) {
        int errnosave;
        struct avstat vbuf;
        char pathbuf[PATHBUF_LEN];

        errnosave = errno;
        res = cmd_getattr(path, &vbuf, deref, pathbuf, AVA_ALL);
        errno = errnosave;
        if(pathbuf[0])
            res = real_stat64(pathbuf, buf, deref, undersc);
        else if(res < 0)
            errno = -res, res = -1;
        else
            convert_stat64(&vbuf, buf);
    }

    return res;
}

static int virt_fstat64(int fd, struct stat64 *buf, int undersc)
{
    int res;

    if(!FD_OK(fd) || !ISVIRTUAL(fd))
        res =  real_fstat64(fd, buf, undersc);
    else {
        struct avstat vbuf;
        int errnosave = errno;
        res = fstat_server(SERVERFH(fd), &vbuf);
        if(res < 0)
            errno = -res, res = -1;
        else {
            errno = errnosave;
            convert_stat64(&vbuf, buf);
        }
    }

    return res;
}
#endif

static void convert_stat(struct avstat *vbuf, struct stat *lbuf)
{
    memset((void *) lbuf, 0, sizeof(*lbuf));
  
    lbuf->st_dev      = vbuf->dev;
    lbuf->st_ino      = vbuf->ino;
    lbuf->st_mode     = vbuf->mode;
    lbuf->st_nlink    = vbuf->nlink;
    lbuf->st_uid      = vbuf->uid;
    lbuf->st_gid      = vbuf->gid;
    lbuf->st_rdev     = vbuf->rdev;
    lbuf->st_size     = vbuf->size;
    lbuf->st_blksize  = vbuf->blksize;
    lbuf->st_blocks   = vbuf->blocks;
    lbuf->st_atime    = vbuf->atime.sec;
    lbuf->st_mtime    = vbuf->mtime.sec;
    lbuf->st_ctime    = vbuf->ctime.sec;
}

static int virt_stat(const char *path, struct stat *buf, int deref, 
                     int undersc)
{
    int res = 0;
    int local = 0;

    if(__av_maybe_local(path)) {
        res = real_stat(path, buf, deref, undersc);
        local = __av_is_local(res, path);
    }
    
    if(!local) {
        int errnosave;
        struct avstat vbuf;
        char pathbuf[PATHBUF_LEN];

        errnosave = errno;
        res = cmd_getattr(path, &vbuf, deref, pathbuf, AVA_ALL);
        errno = errnosave;
        if(pathbuf[0])
            res = real_stat(pathbuf, buf, deref, undersc);
        else if(res < 0)
            errno = -res, res = -1;
        else
            convert_stat(&vbuf, buf);
    }

    return res;
}

static int virt_fstat(int fd, struct stat *buf, int undersc)
{
    int res;

    if(!FD_OK(fd) || !ISVIRTUAL(fd))
        res =  real_fstat(fd, buf, undersc);
    else {
        struct avstat vbuf;
        int errnosave = errno;
        res = fstat_server(SERVERFH(fd), &vbuf);
        if(res < 0)
            errno = -res, res = -1;
        else {
            errno = errnosave;
            convert_stat(&vbuf, buf);
        }
    }

    return res;
}

#ifdef HAVE_ACL
static int convert_acl(struct avstat *vbuf, int cmd, int nent,
                       aclent_t *aclbuf)
{
    int res;

    switch(cmd) {
    case GETACLCNT:
        res = 4;
        break;
        
    case SETACL:
        errno = ENOSYS;
        res = -1;
        break;

    case GETACL:
        if(nent < 4) {
            errno = ENOSPC;
            res = -1;
        }
        else {
            aclbuf[0].a_type = USER_OBJ;
            aclbuf[0].a_id   = vbuf->uid;
            aclbuf[0].a_perm = (vbuf->mode & 0700) >> 6;

            aclbuf[1].a_type = GROUP_OBJ;
            aclbuf[1].a_id   = vbuf->gid;
            aclbuf[1].a_perm = (vbuf->mode & 0070) >> 3;

            aclbuf[2].a_type = CLASS_OBJ;
            aclbuf[2].a_id   = -1;
            aclbuf[2].a_perm = 0777;

            aclbuf[3].a_type = OTHER_OBJ;
            aclbuf[3].a_id   = -1;
            aclbuf[3].a_perm = (vbuf->mode & 0007);
            res = 4;
        }
        break;

        default:
            errno = EINVAL;
            res = -1;
            break;
    }

    return res;
}

static int virt_acl(const char *path, int cmd, int nent, aclent_t *aclbuf,
                    int undersc)
{
    int res = 0;
    int local = 0;

    if(__av_maybe_local(path)) {
        res = real_acl(path, cmd, nent, aclbuf, undersc);
        local = __av_is_local(res, path);
    }
    
    if(!local) {
        int errnosave;
        struct avstat vbuf;
        char pathbuf[PATHBUF_LEN];
        int attrmask = AVA_UID | AVA_GID | AVA_MODE;

        errnosave = errno;
        res = cmd_getattr(path, &vbuf, 1, pathbuf, attrmask);
        errno = errnosave;
        if(pathbuf[0])
            res = real_acl(pathbuf, cmd, nent, aclbuf, undersc);
        else if(res < 0)
            errno = -res, res = -1;
        else
            res = convert_acl(&vbuf, cmd, nent, aclbuf);
    }

    return res;
}
#endif

static int virt_access(const char *path, int amode, int undersc)
{
    int res = 0;
    int local = 0;

    if(__av_maybe_local(path)) {
        res = real_access(path, amode, undersc);
        local = __av_is_local(res, path);
    }
    
    if(!local) {
        int errnosave;
        char pathbuf[PATHBUF_LEN];

        errnosave = errno;
        res = cmd_access(path, amode, pathbuf);
        errno = errnosave;
        if(pathbuf[0])
            res = real_access(pathbuf, amode, undersc);
        else if(res < 0)
            errno = -res, res = -1;
    }

    return res;
}


#ifdef HAVE_STAT64
int lstat64(const char *path, struct stat64 *buf)
{
    return virt_stat64(path, buf, 0, 0);
}

int _lstat64(const char *path, struct stat64 *buf)
{
    return virt_stat64(path, buf, 0, 1);
}

int stat64(const char *path, struct stat64 *buf)
{
    return virt_stat64(path, buf, 1, 0);
}

int _stat64(const char *path, struct stat64 *buf)
{
    return virt_stat64(path, buf, 1, 1);
}

int fstat64(int fd, struct stat64 *buf)
{
    return virt_fstat64(fd, buf, 0);
}

int _fstat64(int fd, struct stat64 *buf)
{
    return virt_fstat64(fd, buf, 1);
}
#endif

int lstat(const char *path, struct stat *buf)
{
    return virt_stat(path, buf, 0, 0);
}

int _lstat(const char *path, struct stat *buf)
{
    return virt_stat(path, buf, 0, 1);
}

int stat(const char *path, struct stat *buf)
{
    return virt_stat(path, buf, 1, 0);
}

int _stat(const char *path, struct stat *buf)
{
    return virt_stat(path, buf, 1, 1);
}

int fstat(int fd, struct stat *buf)
{
    return virt_fstat(fd, buf, 0);
}

int _fstat(int fd, struct stat *buf)
{
    return virt_fstat(fd, buf, 1);
}

#ifdef HAVE_ACL
int acl(const char *path, int cmd, int nent, aclent_t *aclbuf)
{
    return virt_acl(path, cmd, nent, aclbuf, 0);
}

int _acl(const char *path, int cmd, int nent, aclent_t *aclbuf)
{
    return virt_acl(path, cmd, nent, aclbuf, 1);
}
#endif

int access(const char *path, int amode)
{
    return virt_access(path, amode, 0);
}

int _access(const char *path, int amode)
{
    return virt_access(path, amode, 1);
}
