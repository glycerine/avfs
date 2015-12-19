/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "avfscoda.h"

#define DEFAULT_DEV "/dev/cfs0"
#define SECONDARY_DEV "/dev/cfs1"
#define DEFAULT_DEVFS_DEV "/dev/coda/0"
#define SECONDARY_DEVFS_DEV "/dev/coda/1"
#define DEFAULT_DIR "/overlay"

static pid_t mount_pid = -1;
static pid_t main_pid = -1;

void clean_exit(int status)
{
    /* Just in case */
    if(getpid() != main_pid) exit(status);

    run_exit();

    if(mount_pid != -1) kill(mount_pid, SIGKILL);

    exit(status);
}


static void exit_handler(int sig)
{
    clean_exit(0);
}

static void child_handler(int sig)
{
    int status;
    pid_t pid;
    
    pid = wait(&status);
    if(pid == -1) {
	perror("Error calling wait()");
	return;
    }
    
    if(pid != mount_pid) {
	user_child(pid);
    }
    else {
	if(!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
	    
	    fprintf(stderr, "Mount child exited with an error\n");
	    clean_exit(1);
	}
	mount_pid = -1;
    }

}

void set_signal_handlers()
{
    struct sigaction sa;

    sa.sa_handler = exit_handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(SIGHUP, &sa, NULL) == -1 || 
	sigaction(SIGINT, &sa, NULL) == -1 || 
	sigaction(SIGTERM, &sa, NULL) == -1) {
	
	perror("Cannot set exit signal handlers");
	clean_exit(1);
    }

    sa.sa_handler = SIG_IGN;
    
    if(sigaction(SIGPIPE, &sa, NULL) == -1) {
	perror("Cannot set ignored signals");
	clean_exit(1);
    }

}

static void turn_off_avfs()
{
    struct stat stbuf;

    if(stat("/@avfs-off", &stbuf) == -1 && errno == EEXIST) 
        fprintf(stderr, "Succesfuly turned off AVFS\n");
    else
        fprintf(stderr, "AVFS cannot be turned off\n");
    

#if 0    
    if(stat("/@avfsstat", &stbuf) == 0) {
        fprintf(stderr, "Cannot start, because AVFS is already loaded\n");
        exit(1);
    }
#endif

}

static const char *progname;

static void usage()
{
    fprintf(stderr,
            "usage: %s [-h] [-d] [coda_dev [dir]]\n"
            "   -h         print this help\n"
            "   -d         debug mode (do not run in background)\n"
            "   coda_dev   coda device (default: %s)\n"
            "   dir        mountpoint (default: %s)\n",
            progname, DEFAULT_DEV, DEFAULT_DIR);

    exit(1);
}

int main(int argc, char *argv[])
{
    int cfs;
    int res;
    pid_t pid;
    const char *codadev = DEFAULT_DEV;
    const char *codadir = DEFAULT_DIR;
    struct sigaction sa;
    int devnull;
    int ctr;
    int debugmode = 0;

    progname = argv[0];

    ctr = 1;

    if(argc > ctr && argv[ctr][0] == '-') {
        if(argv[ctr][1] == 'h')
            usage();
        else if(argv[ctr][1] == 'd')
            debugmode = 1;
        else
            usage();

        ctr++;
    }
    
    if(argc > ctr) {
	codadev = argv[ctr];
        ctr++;
    }
    
    if(argc > ctr) {
	codadir = argv[ctr];
        ctr++;
    }
    
    if(!debugmode) {
        setsid();
        /* Run in background */
        
        devnull = open("/dev/null", O_RDWR);
        if(devnull == -1) {
            perror("Could not open '/dev/null'");
            exit(1);
        }
        
        pid = fork();
        if(pid == -1) {
            perror("Could not fork");
            exit(1);
        }
        else if(pid != 0) {
            /* parent */
            return 0;
        }
        
        dup2(devnull, 0);
        dup2(devnull, 1);
        dup2(devnull, 2);
    }

    turn_off_avfs();

    unmount_coda(codadir, 1);

    cfs = open(codadev, O_RDWR);

    if(cfs == -1 && errno == ENODEV) {
	/* try inserting module first */
	
	mount_coda(codadev, codadir, 0, 1);
	cfs = open(codadev, O_RDWR);
    }

    if(cfs == -1) {
	codadev = SECONDARY_DEV;
	cfs = open(codadev, O_RDWR);
    }

    if(cfs == -1) {
	codadev = DEFAULT_DEVFS_DEV;
	cfs = open(codadev, O_RDWR);
    }

    if(cfs == -1) {
	codadev = SECONDARY_DEVFS_DEV;
	cfs = open(codadev, O_RDWR);
    }

    if(cfs == -1) {
	fprintf(stderr, "Error opening '%s': %s\n", codadev, strerror(errno));
	exit(1);
    }

    sa.sa_handler = child_handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = SA_NOCLDSTOP;
    
    if(sigaction(SIGCHLD, &sa, NULL) == -1) {
	perror("Cannot set SIGCHLD handler");
	exit(1);
    }

    pid = mount_pid = fork();
    if(pid == -1) {
	perror("fork() failed");
	close(cfs);
	exit(1);
    }

    if(pid == 0) {
	/* Child */
	
	res = mount_coda(codadev, codadir, cfs, 0);
	if(res == -1)
            exit(1);
	
	exit(0);
    }

    fprintf(stderr, "Mount pid: %i\n", mount_pid);

    main_pid = getpid();
    fprintf(stderr, "Main pid: %i\n", main_pid);

    run(cfs, codadir, debugmode);

    return 0;
}
