/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <mntent.h>

#include CODAINCLUDE


int mount_coda(const char *dev, const char *dir, int devfd, int quiet)
{
    int res;
    const char *type;
    FILE *fd;
    struct mntent ent;
    void *mntdata = NULL;
#ifdef CODA_MOUNT_VERSION
    struct coda_mount_data data;
    
    data.version = CODA_MOUNT_VERSION;
    data.fd = devfd;
    mntdata = &data;
#endif
    type = "coda";
    res = mount("coda", dir, type, MS_MGC_VAL | MS_NOSUID | MS_NODEV, mntdata);
    
    if(res == -1) {
	if(!quiet) 
	    fprintf(stderr, "mount failed: %s\n", strerror(errno));

	return -1;
    }
    
    fd = setmntent("/etc/mtab", "a");
    if(fd == NULL) {
	fprintf(stderr, "setmntent(\"/etc/mtab\") failed: %s\n",
		strerror(errno));
	return -1;
    }
    
    ent.mnt_fsname = (char *) dev;
    ent.mnt_dir = (char *) dir;
    ent.mnt_type = (char *) type;
    ent.mnt_opts = "rw,nosuid,nodev";
    ent.mnt_freq = 0;
    ent.mnt_passno = 0;
    res = addmntent(fd, & ent);
    if(res != 0) {
	fprintf(stderr, "addmntent() failed: %s\n", strerror(errno));
    }
    
    endmntent(fd);
    
    return 0;
}

int unmount_coda(const char *dir, int quiet)
{
    int res;
    FILE *fdold, *fdnew;
    struct mntent *entp;
    
    res = umount(dir);
    
    if(res == -1) {
	if(!quiet) 
	    fprintf(stderr, "umount failed: %s\n", strerror(errno));

	return -1;
    }
    
    fdold = setmntent("/etc/mtab", "r");
    if(fdold == NULL) {
	fprintf(stderr, "setmntent(\"/etc/mtab\") failed: %s\n",
		strerror(errno));
	return -1;
    }

    fdnew = setmntent("/etc/mtab~", "w");
    if(fdnew == NULL) {
	fprintf(stderr, "setmntent(\"/etc/mtab~\") failed: %s\n",
		strerror(errno));
	return -1;
    }

    do {
	entp = getmntent(fdold);
	if(entp != NULL) {
	    if(strcmp(entp->mnt_dir, dir) != 0) {
		res = addmntent(fdnew, entp);
		if(res != 0) {
		    fprintf(stderr, "addmntent() failed: %s\n",
			    strerror(errno));
		}
	    }
	}
    } while(entp != NULL);

    endmntent(fdold);
    endmntent(fdnew);

    res = rename("/etc/mtab~", "/etc/mtab");
    if(res == -1) {
	fprintf(stderr, "rename(\"/etc/mtab~\", \"/etc/mtab\") failed: %s\n", 
		strerror(errno));
	return -1;
    }
    
    return 0;
}
