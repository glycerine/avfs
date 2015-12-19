/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
/* namespace.c

   Provides functions for manipulating string-indexed tree-structured
   'namespaces'.

   For examples of use see archive.c, remote.c, state.c.
*/

#include "namespace.h"
#include "avfs.h"
#include <stdlib.h>

#define HASH_TABLE_MIN_SIZE 11
#define HASH_TABLE_MAX_SIZE 13845163

static AV_LOCK_DECL(namespace_lock);
static pthread_once_t namespace_lock_initialized = PTHREAD_ONCE_INIT;

static void namespace_init_lock()
{
    AV_INIT_RECURSIVELOCK(namespace_lock);
}

#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct entry {
    char *name;
    int flags;
    struct list_head subdir;
    struct list_head child;
    struct list_head hash;
    struct entry *parent;
    struct namespace *ns;
    void *data;
};

struct namespace {
    struct list_head root;
    unsigned int hashsize;
    unsigned int numentries;
    struct list_head *hashtab;
};

static void init_list_head(struct list_head *head)
{
    head->next = head;
    head->prev = head;
}

static void list_del(struct list_head *entry)
{
    struct list_head *next = entry->next;
    struct list_head *prev = entry->prev;
    prev->next = next;
    next->prev = prev;
}

static void list_add(struct list_head *entry, struct list_head *head)
{
    struct list_head *next = head;
    struct list_head *prev = head->prev;

    entry->next = next;
    entry->prev = prev;
    prev->next = entry;
    next->prev = entry;
}

static unsigned int spaced_primes_closest (unsigned int num)
{
    static const unsigned int primes[] = { 
	11, 19, 37, 73, 109, 163, 251, 367, 557, 823, 1237, 1861, 2777, 4177,
	6247, 9371, 14057, 21089, 31627, 47431, 71143, 106721, 160073, 240101,
	360163, 540217, 810343, 1215497, 1823231, 2734867, 4102283, 6153409,
	9230113, 13845163
    };
    static const unsigned int nprimes = sizeof(primes) / sizeof(primes[0]);
    unsigned int i;

    for (i = 0; i < nprimes; i++)
	if (primes[i] > num)
	    return primes[i];

    return primes[nprimes - 1];
}

static unsigned int namespace_hash(struct entry *parent, const char *name,
				   unsigned int namelen)
{
    unsigned int hash = (unsigned long) parent >> 2;
    for(; namelen; namelen--, name++) {
	hash = (hash << 4) | (hash >> 28);
	hash ^= (unsigned int) *name;
    }
    return hash;
}

static struct list_head *alloc_hash_table(unsigned int size)
{
    struct list_head *hashtab;
    unsigned int i;

    hashtab = (struct list_head *) av_malloc(sizeof(*hashtab) * size);
    for(i = 0; i < size; i++)
	init_list_head(&hashtab[i]);

    return hashtab;
}

static void resize_hashtable(struct namespace *ns)
{
    float nodes_per_list;
    unsigned int new_size;
    struct list_head *new_tab;
    unsigned int i;
    int maxlen = 0;
    
    nodes_per_list = (float) ns->numentries / (float) ns->hashsize;
	
    if ((nodes_per_list > 0.1 || ns->hashsize <= HASH_TABLE_MIN_SIZE) &&
	(nodes_per_list < 3.0 || ns->hashsize >= HASH_TABLE_MAX_SIZE))
	return;
    
    new_size = spaced_primes_closest(ns->numentries);
    new_tab = alloc_hash_table(new_size);

    for(i = 0; i < ns->hashsize; i++) {
	struct list_head *head = &ns->hashtab[i];
	struct list_head *ptr;
	int len = 0;

	for(ptr = head->next; ptr != head;) {
	    struct entry *ent = list_entry(ptr, struct entry, hash);
	    unsigned int hash = namespace_hash(ent->parent, ent->name,
					       strlen(ent->name));
	    ptr = ptr->next;
	    list_add(&ent->hash, &new_tab[hash % new_size]);
	    len ++;
	}
	if(len > maxlen)
	    maxlen = len;
    }
  
    av_free(ns->hashtab);
    ns->hashtab = new_tab;
    ns->hashsize = new_size;
}

static void namespace_delete(struct namespace *ns)
{
    av_free(ns->hashtab);
}

struct namespace *av_namespace_new()
{
    struct namespace *ns;

    pthread_once(&namespace_lock_initialized, namespace_init_lock);

    AV_NEW_OBJ(ns, namespace_delete);
    init_list_head(&ns->root);
    ns->numentries = 0;
    ns->hashsize = HASH_TABLE_MIN_SIZE;
    ns->hashtab = alloc_hash_table(ns->hashsize);

    return ns;
}

/* remove the entry from internal list while holding the locked
 * so it cannot be looked up by a different thread */
static void free_entry_locked(struct entry *ent)
{
    list_del(&ent->child);
    list_del(&ent->hash);
    ent->ns->numentries --;
    resize_hashtable(ent->ns);
}

/* this is the regular destructor called outside the lock */
static void free_entry(struct entry *ent)
{
    av_free(ent->name);
    av_unref_obj(ent->parent);
    av_unref_obj(ent->ns);
}

static struct list_head *subdir_head(struct namespace *ns, struct entry *ent)
{
    if(ent != NULL)
	return &ent->subdir;
    else
	return &ns->root;
}

static struct entry *lookup_name(struct namespace *ns, struct entry *parent,
				 const char *name, unsigned int namelen)
{
    struct entry *ent;
    struct list_head *ptr;
    unsigned int hash = namespace_hash(parent, name, namelen);
    struct list_head *hashlist = &ns->hashtab[hash % ns->hashsize];

    for(ptr = hashlist->next; ptr != hashlist; ptr = ptr->next) {
	ent = list_entry(ptr, struct entry, hash);
	if(ent->parent == parent && strlen(ent->name) == namelen &&
	   strncmp(name, ent->name, namelen) == 0) {
	    av_ref_obj(ent);
	    return ent;
	}
    }
        
    AV_NEW_OBJ(ent, free_entry);
        
    ent->name = av_strndup(name, namelen);
    ent->flags = 0;

    /* set namespace lock since the entry will be in the hash without
       a reference. This prevents deleting the object in one thread
       while finding the pointer in another thread. */
    av_obj_set_ref_lock(ent, &namespace_lock);

    /* activate destructor called while holding the lock */
    av_obj_set_destr_locked(ent,(void (*)(void *))  free_entry_locked);

    init_list_head(&ent->subdir);
    list_add(&ent->child, subdir_head(ns, parent));
    list_add(&ent->hash, hashlist);
    ent->ns = ns;
    av_ref_obj(ent->ns);
    ent->parent = parent;
    av_ref_obj(ent->parent);

    ns->numentries ++;
    resize_hashtable(ns);

    return ent;
}

struct entry *av_namespace_lookup(struct namespace *ns, struct entry *prev,
				  const char *name)
{
    struct entry *ent;

    AV_LOCK(namespace_lock);
    if(name == NULL) {
        ent = prev->parent;
        av_ref_obj(ent);
    }
    else
        ent = lookup_name(ns, prev, name, strlen(name));
    AV_UNLOCK(namespace_lock);

    return ent;
}

struct entry *av_namespace_lookup_all(struct namespace *ns, struct entry *prev,
                                      const char *name)
{
    if(name != NULL) {
        if(strcmp(name, ".") == 0) {
            av_ref_obj(prev);
            return prev;
        }
        if(strcmp(name, "..") == 0)
            name = NULL;
    }
    
    return av_namespace_lookup(ns, prev, name);
}

struct entry *av_namespace_resolve(struct namespace *ns, const char *path)
{
    struct entry *ent;
    const char *s;
    
    AV_LOCK(namespace_lock);
    ent = NULL;
    while(*path) {
        struct entry *next;

        for(s = path; *s && *s != '/'; s++);
        next = lookup_name(ns, ent, path, s - path);
        av_unref_obj(ent);
        ent = next;
        for(path = s; *path == '/'; path++);
    }
    AV_UNLOCK(namespace_lock);

    return ent;
}

static char *getpath(struct entry *ent)
{
    char *path;
    
    if(ent->parent == NULL)
        return av_strdup(ent->name);
    
    path = getpath(ent->parent);

    return av_stradd(path, "/", ent->name, NULL);
}

char *av_namespace_getpath(struct entry *ent)
{
    char *path;

    AV_LOCK(namespace_lock);
    path = getpath(ent);
    AV_UNLOCK(namespace_lock);

    return path;
}

void av_namespace_setflags(struct entry *ent, int setflags, int resetflags)
{
    AV_LOCK(namespace_lock);
    ent->flags = (ent->flags | setflags) & ~resetflags;
    AV_UNLOCK(namespace_lock);
}

void av_namespace_set(struct entry *ent, void *data)
{
    AV_LOCK(namespace_lock);
    ent->data = data;
    AV_UNLOCK(namespace_lock);
}

void *av_namespace_get(struct entry *ent)
{
    void *data;
    
    AV_LOCK(namespace_lock);
    data = ent->data;
    AV_UNLOCK(namespace_lock);

    return data;
}

char *av_namespace_name(struct entry *ent)
{
    return av_strdup(ent->name);
}

static struct entry *current_entry(struct list_head *head,
				   struct list_head *curr)
{
    if(curr == head)
	return NULL;
    else
	return list_entry(curr, struct entry, child);
}

struct entry *av_namespace_next(struct entry *ent)
{
    struct entry *rent;

    AV_LOCK(namespace_lock);
    rent = current_entry(subdir_head(ent->ns, ent->parent), ent->child.next);
    av_ref_obj(rent);
    AV_UNLOCK(namespace_lock);

    return rent;
}

struct entry *av_namespace_subdir(struct namespace *ns, struct entry *ent)
{
    struct entry *rent;
    struct list_head *head;

    AV_LOCK(namespace_lock);
    head = subdir_head(ns, ent);
    rent = current_entry(head, head->next);
    av_ref_obj(rent);
    AV_UNLOCK(namespace_lock);

    return rent;
}

struct entry *av_namespace_parent(struct entry *ent)
{
    struct entry *parent;

    AV_LOCK(namespace_lock);
    parent = ent->parent;
    av_ref_obj(parent);
    AV_UNLOCK(namespace_lock);

    return parent;
}

struct entry *av_namespace_nth(struct namespace *ns, struct entry *parent,
			       unsigned int n)
{
    struct list_head *ptr;
    struct list_head *head;
    struct entry *ent = NULL;

    AV_LOCK(namespace_lock);
    head = subdir_head(ns, parent);
    for(ptr = head->next; ptr != head; ptr = ptr->next) {
	if(n == 0) {
	    ent = list_entry(ptr, struct entry, child);
	    av_ref_obj(ent);
	    break;
	}
	n--;
    }
    AV_UNLOCK(namespace_lock);

    return ent;
}
