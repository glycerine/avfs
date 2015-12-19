/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "send.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef AVFS_SERVER_DIR
#define AVFS_SERVER_DIR "/usr/lib/avfs"
#endif

#define AVFS_SERVER_PATH AVFS_SERVER_DIR "/avfs_server"

#define PWBUFSIZE 256
#define MAXUSERNAME 32

extern char **environ;

static const char *get_conndir()
{
    static char conndir[64];
    static pthread_mutex_t mutex;
    static int inited;
    char username[MAXUSERNAME + 1];
    struct passwd pw;
    struct passwd *pwres;
    char buf[PWBUFSIZE];
    int uid;
    int res;
    struct stat stbuf;
    
    pthread_mutex_lock(&mutex);
    if(!inited) {
        char *variant;
        char varbuf[32];

        inited = 1;

        uid = getuid();
        res = getpwuid_r(uid, &pw, buf, PWBUFSIZE, &pwres);
        if(res == 0) {
            strncpy(username, pwres->pw_name, MAXUSERNAME);
            username[MAXUSERNAME] = '\0';
        }
        else 
            sprintf(username, "%i", uid);

        varbuf[0] = '\0';
        variant = getenv("AVFS_VARIANT");
        if(variant != NULL) {
            unsigned long i = strtol(variant, NULL, 10);
            sprintf(varbuf, "-%lu", i);
        }
        
        sprintf(conndir, "/tmp/.avfsconn-%s%s", username, varbuf);

        res = stat(conndir, &stbuf);
        if(res == -1 && errno == ENOENT) {
            mkdir(conndir, 0700);
            res = stat(conndir, &stbuf);
        }
        
        if(res == -1 || stbuf.st_uid != uid || (stbuf.st_mode & 0077) != 0) {
            fprintf(stderr, "AVFS: please check permissions of <%s>\n",
                    conndir);
            conndir[0] = '\0';
        }
    }
    pthread_mutex_unlock(&mutex);
    
    if(conndir[0] != '\0')
        return conndir;
    else
        return NULL;
}

static int start_server()
{
    int res;
    int pid;
    int status;
    sigset_t oldset;
    sigset_t newset;
    int success;
    const char *serverpath;
    
    serverpath = getenv("AVFS_SERVER_PATH");
    if(serverpath == NULL || serverpath[0] == '\0')
        serverpath = AVFS_SERVER_PATH;

    sigfillset(&newset);
    sigprocmask(SIG_SETMASK, &newset, &oldset);

    pid = fork();
    if(pid == -1)
        return -1;

    if(pid == 0) {
        int i;
        char **envp = environ;

        for(i = 0; envp[i] != NULL; i++) {
            if(strncmp(envp[i], "PWD=", 4) == 0)
                envp[i][4] = '\0';
            else if(strncmp(envp[i], "LD_PRELOAD=", 11) == 0)
                envp[i][11] = '\0';
        }
        
        res = execl(serverpath, "avfs_server", NULL);
        if(res == -1)
            fprintf(stderr, "AVFS: could not start server (%s): %s\n",
                    serverpath, strerror(errno));
        exit(1);
    }

    res = waitpid(pid, &status, 0);
    if(res != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        success = 0;
    else
        success = -1;

    sigprocmask(SIG_SETMASK, &oldset, NULL);
    
    return success;
}

static int connect_server(int sock)
{
    int res;
    struct sockaddr_un addr;
    unsigned int addrlen;
    const char *conndir = get_conndir();

    if(conndir == NULL)
        return -1;

    addr.sun_family = AF_UNIX;
    sprintf(addr.sun_path, "%s/server", conndir);
    addrlen = (size_t) (((struct sockaddr_un *) 0)->sun_path)
        + strlen(addr.sun_path);

    res = connect(sock, (struct sockaddr *) &addr, addrlen);
    if(res == -1) {
        res = start_server();
        if(res == -1)
            return -1;

        res = connect(sock, (struct sockaddr *) &addr, addrlen);
        if(res == -1)
            fprintf(stderr,
                    "AVFS: could not connect to server socket (%s): %s\n",
                    addr.sun_path, strerror(errno));
    }
    
    return res;
}

static int sock_send_message(int sock, struct avfs_out_message *out,
                             struct avfs_in_message *in)
{
    int res;

    res = connect_server(sock);
    if(res == -1)
        return -1;

    res = __av_write_message(sock, out);
    if(res == -1)
        return -1;
    
    res = __av_read_message(sock, in);
    if(res == -1)
        return -1;
    
    return 0;
}

int __av_send_message(struct avfs_out_message *out,
                      struct avfs_in_message *in, int keepsock)
{
    int res;
    int sock;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sock == -1)
        return -1;

    res = sock_send_message(sock, out, in);
    if(res == -1)
        return -1;

    if(keepsock)
        return sock;
    else {
        close(sock);
        return 0;
    }
}
