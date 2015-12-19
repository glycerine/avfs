/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "send.h"
#include "avfs.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

static int get_sockname(char *sockname)
{
    int res;
    char username[33];
    char sockdir[128];
    char lockfile[128];
    struct passwd *pw;
    int uid;
    int lockfd;
    struct flock flock;
    char *variant;
    char varbuf[32];
    
    uid = getuid();
    pw = getpwuid(uid);
    if(pw != NULL) {
        strncpy(username, pw->pw_name, 32);
        username[32] = '\0';
    }
    else 
        sprintf(username, "%i", uid);

    varbuf[0] = '\0';
    variant = getenv("AVFS_VARIANT");
    if(variant != NULL) {
        unsigned long i = strtol(variant, NULL, 10);
        sprintf(varbuf, "-%lu", i);
    }

    sprintf(sockdir, "/tmp/.avfsconn-%s%s", username, varbuf);
    sprintf(sockname, "%s/server", sockdir);
    sprintf(lockfile, "%s/lock", sockdir);

    res = mkdir(sockdir, 0700);
    if(res == -1) {
        struct stat stbuf;

        if(errno != EEXIST) {
            perror("mkdir()");
            exit(1);
        }
        res = stat(sockdir, &stbuf);
        if(res == -1) {
            perror(sockdir);
            exit(1);
        }
        if(stbuf.st_uid != uid || (stbuf.st_mode & 0077) != 0) {
            fprintf(stderr, "Bad owner or permissons on %s\n", sockdir);
            exit(1);
        }
    }

    lockfd = open(lockfile, O_CREAT | O_RDWR, 0644);
    if(lockfd == -1) {
        perror(lockfile);
        exit(1);
    }
    fcntl(lockfd, F_SETFD, FD_CLOEXEC);

    memset(&flock, 0, sizeof(flock));
    flock.l_type = F_WRLCK;
    flock.l_whence = 0;
    flock.l_start = 0;
    flock.l_len = 0;

    res = fcntl(lockfd, F_SETLK, &flock);
    if(res == -1) {
        if(errno == EAGAIN || errno == EACCES)
            return -1;

        perror("fcntl(F_SETLK)");
        exit(1);
    }

    unlink(sockname);
    
    return 0;
}


static int socket_init(const char *sockname)
{
    int sock;
    int res;
    struct sockaddr_un addr;
    unsigned int addrlen;
    
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sock == -1) {
        perror("socket()");
        exit(1);
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sockname);
    
    addrlen = (size_t) (((struct sockaddr_un *) 0)->sun_path)
        + strlen(addr.sun_path);
    
    res = bind(sock, (struct sockaddr *) &addr, addrlen);
    if(res == -1) {
        perror("bind()");
        exit(1);
    }
    
    res = listen(sock, 5);
    if(res == -1) {
        perror("listen()");
        exit(1);
    }

    return sock;
}

static void exit_handler(int sig)
{
    exit(0);
}

#if 0
static void bad_handler(int sig)
{
    av_log(AVLOG_ERROR, "%s, Exiting",
             strsignal(sig));
    _exit(1);
}
#endif

int server_init()
{
    int res;
    int pip[2];
    int pid;
    int nullfd;
    int i;
    char sockname[128];
    int numfd;
    sigset_t newset;
    struct sigaction act;

    sigemptyset(&newset);
    sigprocmask(SIG_SETMASK, &newset, NULL);

    for(i = 0; i < 3; i++) {
        nullfd = open("/dev/null", O_RDONLY);
        if(nullfd == -1) {
            perror("avfs_server: open(/dev/null)");
            exit(1);
        }
    }

    res = pipe(pip);
    if(res == -1) {
        perror("avfs_server: pipe()");
        exit(1);
    }

    pid = fork();
    if(pid == -1) {
        perror("avfs_server: fork()");
        exit(1);
    }

    if(pid != 0) {
        int res;
        char c;

        close(pip[1]);
        res = read(pip[0], &c, 1);
        if(res == -1) {
            perror("avfs_server: read()");
            exit(1);
        }
        if(res == 0)
            exit(1);
        
        exit(0);
    }
    
    setuid(getuid());
    setgid(getgid());
//    chdir("/");
    chdir("/tmp");
    setsid();

    numfd = getdtablesize();
    for(i = 0; i < numfd; i++) {
        if(i != pip[1])
            close(i);
    }

    nullfd = open("/dev/null", O_RDWR);
    if(nullfd == -1)
        exit(1);
    
    for(i = 0; i < 3; i++)
        res = dup2(nullfd, i);

    res = get_sockname(sockname);
    if(res != -1)
        res = socket_init(sockname);

    if(write(pip[1], "m", 1) != 1)
        exit(1);

    if(res == -1)
        exit(0);
    
    close(pip[1]);

    act.sa_handler = exit_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGINT, &act, NULL);

    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);

#if 0
    act.sa_handler = bad_handler;
    sigfillset(&act.sa_mask);
    sigaction(SIGQUIT, &act, NULL);
    sigaction(SIGILL, &act, NULL);
    sigaction(SIGFPE, &act, NULL);
    sigaction(SIGABRT, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);
#endif

    return res;
}

