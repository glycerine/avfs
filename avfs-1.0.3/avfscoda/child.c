/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "virtual.h"
#include "avfscoda.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/stat.h>

/* #include "KERNINCLUDE/linux/coda.h" */
#include CODAINCLUDE

#define MULTITHREADED 1

#define MAXPMSGLEN 8192
#define MAXMSGLEN 1045

/* #define HAVE_FIFO_BUG */

static int child_outfd;

static int st2type(struct stat *s)
{
    if (S_ISDIR(s->st_mode))
        return C_VDIR;

    if (S_ISREG(s->st_mode))
        return C_VREG;

    if (S_ISBLK(s->st_mode))
        return C_VBLK;

    if (S_ISCHR(s->st_mode))
        return C_VCHR;

    if (S_ISLNK(s->st_mode))
        return C_VLNK;

    if (S_ISSOCK(s->st_mode))
        return C_VSOCK;

    if (S_ISFIFO(s->st_mode))
        return C_VFIFO;

    fprintf(stderr, "Unknown type\n");
    return C_VNON;
}


static void st2attr(struct stat *s, struct coda_vattr *a, ViceFid *id)
{
    memset(a, 0, sizeof(struct coda_vattr));
    a->va_type = st2type(s);
	
    a->va_mode = s->st_mode & 07777;
	
    /* File type handling in linux-coda is a mess */
    a->va_mode |= (s->st_mode  & S_IFMT);
	
    a->va_nlink = s->st_nlink;
    a->va_uid = s->st_uid;
    a->va_gid = s->st_gid;
    a->va_fileid = coda_f2i(id);
    a->va_size = s->st_size;
    a->va_blocksize = 1024; /* s->st_blksize */
    a->va_atime.tv_nsec = a->va_ctime.tv_nsec = a->va_mtime.tv_nsec = 0;
    a->va_atime.tv_sec = s->st_atime;
    a->va_mtime.tv_sec = s->st_mtime;
    a->va_ctime.tv_sec = s->st_ctime;
    a->va_gen = 0;
    a->va_flags = 0;
    a->va_rdev = s->st_rdev;
	
    a->va_bytes = s->st_blocks * s->st_blksize;
    a->va_filerev = 0;
	
#ifdef HAVE_FIFO_BUG
    /* Make a char device (255/255) out of pipes */
    if(S_ISFIFO(s->st_mode)) {
        a->va_mode = (s->st_mode & 07777) | S_IFCHR;
        a->va_type = C_VCHR;
        a->va_rdev = ~0;
    }
#endif
}


static int set_attr(const char *path, struct coda_vattr *a)
{
    
    if(a->va_mode != (u_short) -1) {
        if(virt_chmod(path, a->va_mode & 07777) == -1)
            return -1;
    }
    
    if(a->va_uid != (vuid_t) -1 || a->va_gid != (vuid_t) -1) {
        if(virt_lchown(path, a->va_uid, a->va_gid) == -1)
            return -1;
    }

    if(a->va_size != (u_quad_t) -1) {
        if(virt_truncate(path, a->va_size) == -1)
            return -1;
    }

    if(a->va_atime.tv_sec != (time_t) -1 ||
       a->va_mtime.tv_sec != (time_t) -1) {
        struct utimbuf utbuf;

        utbuf.actime = a->va_atime.tv_sec;
        utbuf.modtime = a->va_mtime.tv_sec;

        if(virt_utime(path, &utbuf) == -1)
            return -1;
    }

    return 0;
}

static int create_empty_dir(const char *tmpname)
{
    int outfd;

    outfd = open(tmpname, O_WRONLY | O_TRUNC);
    if(outfd == -1) {
        fprintf(stderr, "open(%s, O_WRONLY | O_TRUNC) failed (%s)\n", tmpname, 
                strerror(errno));
        return -EIO;
    }

    close(outfd);
    return 0;
}

static int copy_dir(const char *path, const char *tmpname)
{
    struct venus_dirent vd;
    int res;
    DIR *dirp;
    int outfd;
    struct dirent *ent;
	
    dirp = virt_opendir(path);
    if(dirp == NULL)
        return -errno;
	
    outfd = open(tmpname, O_WRONLY | O_TRUNC);
    if(outfd == -1) {
        fprintf(stderr, "open(%s, O_WRONLY | O_TRUNC) failed (%s)\n", tmpname, 
                strerror(errno));
        virt_closedir(dirp);
        return -EIO;
    }

    while(1) {
        errno = 0;
        ent = virt_readdir(dirp);
        if(ent == NULL) {
            if(errno != 0)
                res = -errno;
            else
                res = 0;
            break;
        }

        vd.d_fileno = 1; /* We don't know the inode number */
        vd.d_type   = CDT_UNKNOWN;
        strncpy(vd.d_name, ent->d_name, CODA_MAXNAMLEN);
        vd.d_name[CODA_MAXNAMLEN] = '\0';
        vd.d_namlen = strlen(vd.d_name);
        vd.d_reclen = DIRSIZ(&vd);
        
        res = write(outfd, &vd, vd.d_reclen);
        if(res == -1) {
            fprintf(stderr, "write failed (%s)\n", strerror(errno));
            res = -EIO;
            break;
        }
    } while(ent != NULL);
	
    close(outfd);
    if(res == 0) {
        res = virt_closedir(dirp);
        if(res == -1)
            return -errno;
    }
    else
        virt_closedir(dirp);

    return res;
}

#define COPYBUF 16384

static int copy_file(const char *name, const char *tmpname)
{
    char buf[COPYBUF];
    int infd;
    int outfd;
    int res;
	
    infd = virt_open(name, O_RDONLY, 0);
    if(infd == -1)
        return -errno;
	
    outfd = open(tmpname, O_WRONLY | O_TRUNC);
    if(outfd == -1) {
        fprintf(stderr, "open(%s) failed (%s)\n", tmpname, strerror(errno));
        virt_close(infd);
        return -EIO;
    }
	
    do {
        res = virt_read(infd, buf, COPYBUF);
        if(res == -1) {
            res = -errno;
            break;
        }
        if (res > 0) {
            res = write(outfd, buf, res);
            if(res == -1) {
                fprintf(stderr, "write failed (%s)\n", strerror(errno));
                res = -EIO;
                break;
            }
        }
    } while(res > 0);

    close(outfd);
    if(res == 0) {
        res = virt_close(infd);
        if(res == -1)
            return -errno;
    }
    else
        virt_close(infd);

    return res;
}

static int write_file(const char *tmpname, const char *name)
{
    char buf[COPYBUF];
    int infd;
    int outfd;
    int res;
	
    outfd = virt_open(name, O_WRONLY | O_TRUNC, 0);
    if(outfd == -1)
        return -errno;
	
    infd = open(tmpname, O_RDONLY, 0);
    if(infd == -1) {
        fprintf(stderr, "open(%s) failed (%s)\n", tmpname, strerror(errno));
        virt_close(outfd);
        return -EIO;
    }
	
    do {
        res = read(infd, buf, COPYBUF);
        if(res == -1) {
            fprintf(stderr, "read failed (%s)\n", strerror(errno));
            res = -EIO;
            break;
        }
        if (res > 0) {
            res = virt_write(outfd, buf, res);
            if(res == -1) {
                res = -errno;
                break;
            }
        }
    } while(res > 0);

    close(infd);
    if(res == 0) {
        res = virt_close(outfd);
        if(res == -1)
            return -errno;
    }
    
    return res;
}

static int create_empty_file(const char *tmpname)
{
    int fd;

    fprintf(stderr, "create_empty_file: %s\n", tmpname);

    fd = open(tmpname, O_WRONLY | O_TRUNC);
    if(fd == -1) {
        fprintf(stderr, "open(%s, O_WRONLY | O_TRUNC) failed (%s)\n", tmpname,
                strerror(errno));
        
        return -EIO;
    }

    close(fd);
    return 0;
}


void *process_request(void *arg)
{
    char *ibuf = (char *) arg;
    int ret;
    struct child_message *msg = (struct child_message *) ibuf;
    union inputArgs *req;
    char obuf[MAXMSGLEN + sizeof(int)];
    union outputArgs *rep = (union outputArgs *) (obuf + sizeof(int));
    int size, noff;
    char *path1;
    char *path2;
    int offset = sizeof(struct child_message);
    struct stat stbuf;
    int outfd = child_outfd;

    req = (union inputArgs *)  (ibuf + offset);

    if(msg->path1size != 0)
	path1 = ibuf + offset + msg->reqsize;
    else
	path1 = NULL;
    
    if(msg->path2size != 0)
	path2 = ibuf + offset + msg->reqsize + msg->path1size;
    else
	path2 = NULL;
    
    
#if 0
    fprintf(stderr, 
	    "- %i/%i [%i] ---------------------------------------------------\n", 
	    uid, gid, pid);
    fprintf(stderr, 
	    "%i (%i (%i)) bytes: opcode: %li, unique: %li\n", 
	    msg->reqsize, numread, insize, req->ih.opcode, 
	    req->ih.unique);
    fprintf(stderr, "ibuf: %p, req: %p msg: %p\n", ibuf, req, msg);
#endif
    
    size = sizeof(rep->oh);
    rep->oh.opcode = req->ih.opcode;
    rep->oh.unique = req->ih.unique;
    rep->oh.result = 0;
    
    switch (req->ih.opcode) {
    case CODA_GETATTR:
	size = sizeof(rep->coda_getattr);
	
	ret = virt_lstat(path1, &stbuf);
	if(ret == -1) 
	    rep->oh.result = errno;
	else 
	    st2attr(&stbuf, &rep->coda_getattr.attr, 
		    &req->coda_getattr.VFid);
	break;
			
    case CODA_ACCESS:
	size = sizeof(rep->oh);
			
	ret = virt_access(path1, req->coda_access.flags & 0x7);
	if(ret == -1) 
	    rep->oh.result = errno;
	break;
			
#ifdef CODA_OPEN_BY_FD
    case CODA_OPEN_BY_FD:
#endif
    case CODA_OPEN:
	size = sizeof(rep->oh);
	if(strcmp(path1, "/") == 0)
	    ret = create_empty_dir(path2);
	else {
	    if((req->coda_open.flags & C_O_TRUNC) != 0)
		ret = create_empty_file(path2);
	    else {
		ret = virt_stat(path1, &stbuf);
		if(ret == -1)
                    ret = -errno;
		else {
		    if(S_ISDIR(stbuf.st_mode))
			ret = copy_dir(path1, path2);
		    else 
			ret = copy_file(path1, path2);
		}
	    }
        }
        if(ret < 0)
            rep->oh.result = -ret;
	break;

    case CODA_CREATE:
	size = sizeof(rep->coda_create);
	if((req->coda_create.mode & S_IFMT) == S_IFREG) {
	    ret = virt_open(path1, O_WRONLY | O_CREAT | O_TRUNC, 
			    req->coda_create.mode & 07777);
	    if(ret != -1) 
		ret = virt_close(ret);
	}
	else {
	    ret = virt_mknod(path1, req->coda_create.mode,
			     req->coda_create.attr.va_rdev);
	}
	if(ret == -1)
	    rep->oh.result = errno;
	break;


    case CODA_CLOSE:
	size = sizeof(rep->oh);
	ret = write_file(path2, path1);
	if(ret < 0)
	    rep->oh.result = -ret;
	break;
			
    case CODA_LOOKUP:
	size = sizeof(rep->coda_lookup);
			
	ret = virt_lstat(path1, &stbuf);
	if(ret == -1) 
	    rep->oh.result = errno;
	else {
	    /* We don't know these */
	    rep->coda_lookup.VFid.Volume = 0;
	    rep->coda_lookup.VFid.Vnode  = 0;
	    rep->coda_lookup.VFid.Unique = 0; 
	    rep->coda_lookup.vtype = st2type(&stbuf);
	}
	break;
			
    case CODA_READLINK:
	size = sizeof(rep->coda_readlink);
	noff = size;
			
	ret = virt_readlink(path1, (char *) rep + noff,
			    MAXMSGLEN - noff);
	if(ret == -1) 
	    rep->oh.result = errno;
	else {
	    rep->coda_readlink.data = (void *) noff;
	    rep->coda_readlink.count = ret;
	    size += ret;
	}
	break;

    case CODA_SETATTR:
	size = sizeof(rep->oh);
	ret = set_attr(path1, &req->coda_setattr.attr);
	if(ret == -1)
	    rep->oh.result = errno;
	break;

    case CODA_REMOVE:
	size = sizeof(rep->oh);
	ret = virt_unlink(path1);
	if(ret == -1)
	    rep->oh.result = errno;
	break;

    case CODA_RMDIR:
	size = sizeof(rep->oh);
	ret = virt_rmdir(path1);
	if(ret == -1)
	    rep->oh.result = errno;
	break;

    case CODA_MKDIR:
	size = sizeof(rep->coda_mkdir);
	ret = virt_mkdir(path1, req->coda_mkdir.attr.va_mode & 07777);
	if(ret == -1)
	    rep->oh.result = errno;
	break;

    case CODA_RENAME:
	size = sizeof(rep->oh);
	ret = virt_rename(path1, path2);
	if(ret == -1)
	    rep->oh.result = errno;
	break;

    case CODA_SYMLINK:
	size = sizeof(rep->oh);
	ret = virt_symlink(path2, path1);
	if(ret == -1)
	    rep->oh.result = errno;
	break;

    case CODA_LINK:
	size = sizeof(rep->oh);
	ret = virt_link(path2, path1);
	if(ret == -1)
	    rep->oh.result = errno;
	break;

    default:
	rep->oh.result = EOPNOTSUPP;
    }
		
    *(int *) obuf = size;
    size += sizeof(int);
    ret = write(outfd, obuf, size);
    if(ret == -1 || ret != size) {
	fprintf(stderr, "Error writing to parent: %s\n", strerror(errno));
	exit(1);
    }
    
    free(ibuf);

    return NULL;
}

void child_process(int infd, int outfd)
{
    int res;
    int insize;
    int numread;
    char ibuf[MAXPMSGLEN];
    char *bufcpy;
    pthread_attr_t attr;
    pthread_t thrid;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    child_outfd = outfd;

#if 0
    pid_t pid = getpid();
    uid_t uid = getuid();
    gid_t gid = getgid();
	

    fprintf(stderr, "My pid: %i\n", pid);
    sleep(15);
#endif
    
    while(1) {
        numread = read(infd, &insize, sizeof(insize));
        if(numread == -1) {
            fprintf(stderr, "Error reading from device: %s\n",
                    strerror(errno));
            exit(1);
        }
        if(insize > MAXPMSGLEN || insize <= 0) {
            fprintf(stderr, "Error: illegal size");
            exit(1);
        }
		
        numread = read(infd, ibuf, insize);
        if(numread == -1) {
            fprintf(stderr, "Error reading from device: %s\n", 
                    strerror(errno));
            exit(1);
        }
	
	bufcpy = malloc(numread);
	if(bufcpy == NULL) {
	    fprintf(stderr, "Out of memory\n");
	    exit(1);
	}
	
	memcpy(bufcpy, ibuf, numread);


#if MULTITHREADED
	res = pthread_create(&thrid, &attr, process_request, bufcpy);
	if(res != 0) {
	    fprintf(stderr, "Error creating thread: %s\n", strerror(errno));
	    exit(1);
	}
#else
        process_request(bufcpy);
#endif
	
    }
}

