/*
    AVFS: A Virtual File System Library
    Copyright (C) 2000-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "socket.h"
#include "avfs.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>


static int sock_connect_host(const char *hostname, int port)
{
    struct hostent *host;
    struct sockaddr_in sn;
    int sock;
    int res;

    host = gethostbyname(hostname);
    if(host == NULL) {
        av_log(AVLOG_ERROR, "Could not resolve host %s", hostname);
        return -ENOENT;
    }
    
    if(host->h_addrtype != AF_INET) {
        av_log(AVLOG_ERROR, "Cannot handle non-inet address %s", hostname);
        return -ENOENT;
    }

    sn.sin_family = AF_INET;
    sn.sin_port = htons(port);
    memcpy(&sn.sin_addr, host->h_addr_list[0], host->h_length);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1) {
        av_log(AVLOG_ERROR, "socket(): %s", strerror(errno));
        return -errno;
    }

    res = connect(sock, (struct sockaddr *) &sn, sizeof(sn));
    if(res == -1) {
        av_log(AVLOG_ERROR, "connect(): %s", strerror(errno));
        close(sock);
        return -errno;
    }

    return sock;
}

int av_sock_connect(const char *name, int defaultport)
{
    char *hostname;
    char *s;
    int port = defaultport;
    int sock;

    hostname = av_strdup(name);
    s = strrchr(hostname, ':');
    if(s != NULL) {
        char *end;

        *s = '\0';
        s++;
        port = strtol(s, &end, 10);
        if(end == s || *end != '\0') {
            av_free(hostname);
            av_log(AVLOG_ERROR, "Bad port: %s", name);
            return -ENOENT;
        }
    }
    else if(defaultport == -1) {
        av_free(hostname);
        av_log(AVLOG_ERROR, "Missing port: %s", name);
        return -ENOENT;
    }
    
    sock = sock_connect_host(hostname, port);
    av_free(hostname);
    
    return sock;
}
