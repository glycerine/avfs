#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

int main(int argc, char *argv[])
{
    int res;
    FILE *fp;
  
    if(argc != 3) {
        fprintf(stderr, "usage: %s from to\n", argv[0]);
        exit(1);
    }

    fp = fopen("/proc/fs/redir2/mount_pid", "w");
    if(fp == NULL) {
            perror("opening /proc/fs/redir2/mount_pid");
            exit(1);
    }
    fprintf(fp, "%u", getpid());
    fclose(fp);
    
    if (argv[1][0] == '-') {
        res = umount2(argv[2], 0);
        if (res == -1) {
            perror("umount failed");
            exit(1);
        }
    } else {
        res = mount(argv[1], argv[2], "none", MS_BIND, NULL);
        if(res == -1) {
            perror("mount failed");
            exit(1);
        }
    }
    return 0;
}
