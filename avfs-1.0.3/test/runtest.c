/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "virtual.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define TESTDIR "/tmp/avfstest"

typedef int (*testfunc) (void *);

struct test {
    char *name;
    struct test *next;

    struct test *sub;
    void *data;
    testfunc func;
};


#define TESTFILESIZE 102400
struct filetest {
    const char *filename;
    unsigned char data[TESTFILESIZE];
};

static struct test *test_new(struct test *tg, const char *name)
{
    struct test *ng;
    struct test **tgp;

    for(tgp = &tg->sub; *tgp != NULL; tgp = &(*tgp)->next);

    ng = malloc(sizeof(*ng));
    ng->sub = NULL;
    ng->next = NULL;
    ng->name = strdup(name);
    ng->data = NULL;
    ng->func = NULL;
    
    *tgp = ng;

    return ng;
}

static void test_add(struct test *tg, const char *name, void *data,
                     testfunc func)
{
    struct test *tc;

    tc = test_new(tg, name);
    tc->data = data;
    tc->func = func;
}

static void tab(int i)
{
    for(; i > 0; i--)
        putchar(' ');
}

static int test_run_path(struct test *tg, const char *path)
{
    int ok;
    int res;
    char *newpath;

    if(tg == NULL)
        return 0;

    newpath = malloc(strlen(path) + 1 + strlen(tg->name) + 1);

    sprintf(newpath, "%s.%s", path, tg->name);
    ok = test_run_path(tg->sub, newpath);
    if(tg->func != NULL) {
        int len = printf("%s:", newpath);
        tab(60 - len);
        
        res = tg->func(tg->data);
        printf("%s\n", res ? "OK" : "FAILED");
        if(!res)
            ok = 0;
    }

    free(newpath);

    res = test_run_path(tg->next, path);
    if(!res)
        ok = 0;

    return ok;
}

static int test_run(struct test *tg)
{
    return test_run_path(tg, "");
}

static int test_rmr(const char *file)
{
    int res;
    DIR *dirp;
    struct dirent *ent;
    char *name;

    res = unlink(file);
    if(res == 0)
        return 0;

    res = rmdir(file);
    if(res == 0)
        return 0;

    dirp = opendir(file);
    if(dirp == NULL)
        return -1;

    while((ent = readdir(dirp)) != NULL) {
        name = ent->d_name;
    
        if(name[0] != '.' || (name[1] && (name[1] != '.' || name[2]))) {
            char *newname;

            newname = malloc(strlen(file) + 1 + strlen(name) + 1);
            sprintf(newname, "%s/%s", file, name);
            test_rmr(newname);
            free(newname);
        }
    }
    closedir(dirp);

    return rmdir(file);
}

static void test_init()
{
    test_rmr(TESTDIR);
    mkdir(TESTDIR, 0777);
}

static char *test_file(const char *name)
{
    char *fullname = malloc(strlen(TESTDIR) + 1 + strlen(name) + 1);

    sprintf(fullname, "%s/%s", TESTDIR, name);

    return fullname;
}

static int file_create(struct filetest *ft)
{
    int res;
    int fd;
    off_t off;
    size_t size;

    res = virt_open(ft->filename, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if(res == -1)
        return 0;

    fd = res;
    for(off = 0; off < TESTFILESIZE; off += size) {
        size = rand() % TESTFILESIZE / 2;

        if(off + size > TESTFILESIZE)
            size = TESTFILESIZE - off;
        
        res = virt_write(fd, ft->data + off, size);
        if(res != size)
            return 0;
    }

    res = virt_close(fd);
    if(res == -1)
        return 0;

    return 1;
}

static int flush_cache()
{
    int res;
    int fd;

    fd = virt_open("/#avfsstat/cache/clear", O_WRONLY, 0);
    if(fd == -1)
        return -1;

    res = virt_write(fd, "1", 1);
    if(res == -1)
        return -1;

    res = virt_close(fd);
    if(res == -1)
        return -1;

    return 0;
}

static int file_contents(struct filetest *ft)
{
    int res;
    int fd;
    off_t off;
    size_t size;
    char buf[TESTFILESIZE / 2];

    res = flush_cache();
    if(res == -1)
        return 0;

    res = virt_open(ft->filename, O_RDONLY, 0);
    if(res == -1)
        return 0;

    fd = res;
    for(off = 0; off < TESTFILESIZE; off += size) {
        size = rand() % TESTFILESIZE / 2;

        res = virt_read(fd, buf, size);

        if(off + size > TESTFILESIZE)
            size = TESTFILESIZE - off;

        if(res != size)
            return 0;

        if(memcmp(ft->data + off, buf, size) != 0)
            return 0;
    }
    
    res = virt_read(fd, buf, 100);
    if(res != 0)
        return 0;

    res = virt_close(fd);
    if(res == -1)
        return 0;

    return 1;
}



static void add_filetest(struct test *tg, const char *testname,
                         const char *filename)
{
    struct filetest *ft;
    struct test *ftg;
    int i;

    srand(1);
    ft = (struct filetest *) malloc(sizeof(*ft));

    ftg = test_new(tg, testname);

    ft->filename = filename;
    for(i = 0; i < TESTFILESIZE; i++)
        ft->data[i] = (i + (!(rand() % 30) ? rand() : 0)) % 0x100;

    test_add(ftg, "create", ft, (testfunc) file_create);
    test_add(ftg, "contents", ft, (testfunc) file_contents);
}


int main(int argc, char *argv[])
{
    int res;
    struct test root;
    struct test *tg;

    test_init();

    root.sub = NULL;
    tg = test_new(&root, "filetest");
    add_filetest(tg, "ugzip", test_file("t.gz#ugzip"));
    add_filetest(tg, "ubzip2", test_file("t.bz2#ubzip2"));
    add_filetest(tg, "volatile", "/#volatile/testfile");
    
    res = test_run(tg);

    if(res == 0)
        return 1;
    else
        return 0;
}
