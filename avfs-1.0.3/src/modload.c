/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
#include "avfs.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#define MAX_MODULENAME 32
#define MODULEPREFIX "avfs_module_"
#define MODULEPREFIXLEN 12

struct vmodule {
    void *handle;
};

static void *load_module(const char *modname, const char *moduledir)
{
    char *modpath;
    void *lib_handle;

    modpath = av_stradd(NULL, moduledir, "/", modname, NULL);

    lib_handle = dlopen(modpath, RTLD_NOW);
    if(lib_handle == NULL)
        av_log(AVLOG_ERROR, "load_module: %s", dlerror());

    av_free(modpath);
  
    return lib_handle;
}

static void delete_module(struct vmodule *module)
{
    dlclose(module->handle);
}

static int init_module(void *lib_handle, const char *initname)
{
    int (*initfunc) (struct vmodule *);
    struct vmodule *module;
    int res;

    initfunc = (int (*)(struct vmodule *)) dlsym(lib_handle, initname);
    if(initfunc == NULL) {
        av_log(AVLOG_ERROR, "init_module: %s", dlerror());
        return -EFAULT;
    }

    AV_NEW_OBJ(module, delete_module);
    module->handle = lib_handle;

    res = (*initfunc)(module);
    av_unref_obj(module);
    
    return res;
}

static char *get_modulename(const char *filename)
{
    int i;

    if(strncmp(filename, MODULEPREFIX, MODULEPREFIXLEN) != 0)
        return NULL;
    
    filename += MODULEPREFIXLEN;

    for(i = 0; filename[i] && filename[i] != '.'; i++);
    if(strcmp(filename + i, ".so") != 0)
        return NULL;

    return  av_strndup(filename, i);
}

static void check_moduledir_entry(const char *moduledir, const char *filename)
{            
    int res;
    char *modulename;
    void *lib_handle;

    modulename = get_modulename(filename);
    if(modulename == NULL)
        return;

    lib_handle = load_module(filename, moduledir);
    if(lib_handle != NULL) {
        char *initname;
        void *lib_handle = NULL;

        initname = av_stradd(NULL, "av_init_module_", modulename, NULL);
        res = init_module(lib_handle, initname);
        if(res < 0 && lib_handle != NULL)
            dlclose(lib_handle);

        av_free(initname);
    }
    av_free(modulename);
}

void av_init_dynamic_modules(void)
{
    DIR *dirp;
    struct dirent *ent;
    char *moduledir;

    moduledir = av_get_config("moduledir");
    if(moduledir == NULL)
        return;

    dirp = opendir(moduledir);
    if(dirp != NULL) {
        while((ent = readdir(dirp)) != NULL)
            check_moduledir_entry(moduledir, ent->d_name);

        closedir(dirp);
    }
    av_free(moduledir);
}

