// (c) 1999 Erwin S. Andreasen <erwin@andreasen.org>
// Homepage: http://www.andreasen.org/LeakTracer/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "internal.h"

static int
    new_count, // how many memory blocks do we have
    leaks_count, // amount of entries in the below array
    first_free_spot; // Where is the first free spot in the leaks array?

static size_t new_size;  // total size

typedef struct {
    void *addr;
    size_t size;
    void *ret[10];
//    void *ret2; // Not necessary anymore
} Leak;
    
static Leak *leaks;

static AV_LOCK_DECL(lock);

static int x(void *p)
{
    int i = (int) p;

#ifdef __linux__
    if(!(i & 0x8000000))
        return 0;
    
    return 1;
#else
    if(i == 0 || i < 0)
        return 0;
#endif

//    av_log(AVLOG_DEBUG, "p: 0x%08x", i);
    
    return 1;
}

static void* register_alloc (size_t size) {
    void *p = malloc(size);

    new_count++;
    new_size += size;
    
    if (!p) { // We should really throw some sort of exception or call the new_handler
        av_log(AVLOG_ERROR, "LeakTracer: out of memory");
        _exit (1);
    }
    
    for (;;) {
        int i;
        int new_leaks_count;
        for (i = first_free_spot; i < leaks_count; i++)
            if (leaks[i].addr == NULL) {
                leaks[i].addr = p;
                leaks[i].size = size;

                do {
                    if(!x(leaks[i].ret[0] = __builtin_return_address(0))) break;
                    if(!x(leaks[i].ret[1] = __builtin_return_address(1))) break;
                    if(!x(leaks[i].ret[2] = __builtin_return_address(2))) break;
                    if(!x(leaks[i].ret[3] = __builtin_return_address(3))) break;
                    if(!x(leaks[i].ret[4] = __builtin_return_address(4))) break;
                    if(!x(leaks[i].ret[5] = __builtin_return_address(5))) break;
                    if(!x(leaks[i].ret[6] = __builtin_return_address(6))) break;
                    if(!x(leaks[i].ret[7] = __builtin_return_address(7))) break;
                    if(!x(leaks[i].ret[8] = __builtin_return_address(8))) break;
                    if(!x(leaks[i].ret[9] = __builtin_return_address(9))) break;
                } while(0);

//                leaks[i].ret2 = __builtin_return_address(2);
                first_free_spot = i+1;
                return p;
            }
        
        // Allocate a bigger array
        // Note that leaks_count starts out at 0.
        new_leaks_count = leaks_count == 0 ? 16 : leaks_count * 2;
        leaks = (Leak*)realloc(leaks, sizeof(*leaks) * new_leaks_count);
        if (!leaks) {
            av_log(AVLOG_ERROR, "LeakTracer: out of memory");
            _exit(1);
        }
        memset(leaks+leaks_count, 0, sizeof(*leaks) * (new_leaks_count-leaks_count));
        leaks_count = new_leaks_count;
    }
}

static void *register_realloc (void *p, size_t size)
 {
     void *p1;
     int i;

     p1 = realloc(p, size);
    for (i = 0; i < leaks_count; i++)
        if (leaks[i].addr == p) {
            leaks[i].addr = p1;
            new_size += size - leaks[i].size;
            leaks[i].size = size;
            return p1;
        }
    
    av_log(AVLOG_ERROR, "LeakTracer: realloc on an already deleted value");
    abort();
}


static void register_free (void *p) 
{
    int i;
    if (p == NULL)
        return;
    
    new_count--;
    for (i = 0; i < leaks_count; i++)
        if (leaks[i].addr == p) {
            leaks[i].addr = NULL;
            new_size -= leaks[i].size;
            if (i < first_free_spot)
                first_free_spot = i;
            free(p);
            return;
        }

    av_log(AVLOG_ERROR, "LeakTracer: free on an already deleted value");
    abort();
}

void *av_malloc(size_t size)
{
    void *res;

    AV_LOCK(lock);
    res = register_alloc(size);
    AV_UNLOCK(lock);

    return res;
}

void *av_calloc(size_t size)
{
    void *res;
    
    AV_LOCK(lock);
    res = register_alloc(size);
    memset(res, 0, size);
    AV_UNLOCK(lock);

    return res;
}

void *av_realloc(void *p, size_t size)
{
    void *res;

    AV_LOCK(lock);
    if(p == NULL)
        res = register_alloc(size);
    else if(size == 0) {
        register_free(p);
        res =  NULL;
    }
    else
        res = register_realloc(p, size);
    AV_UNLOCK(lock);

    return res;
}

void av_free(void *p)
{
    AV_LOCK(lock);
    register_free(p);
    AV_UNLOCK(lock);
}


void av_check_malloc()
 {
    const char *filename = "/tmp/leak.out";
    FILE *fp;

    av_log(AVLOG_DEBUG, "leak_count: %i (%i)", new_count, leaks_count);
    
    if (!(fp = fopen(filename, "w")))
        av_log(AVLOG_ERROR, "LeakTracer: Could not open %s: %s\n", filename,
                 strerror(errno));
    else {
        int i;
        int numunfreed = 0;

        AV_LOCK(lock);

        fprintf(fp, 
                "set prompt\n"
                "echo\n"
                "set listsize 0\n"
                "set height 0\n");
        fprintf(fp, "echo leak size: %6d\\n\n", new_size);
        for (i = 0; i <  leaks_count; i++)

            if (leaks[i].addr != NULL) {
                int j;
                
                numunfreed ++;
                fprintf(fp, "echo -------------------------------------------------------------------------\\n\n");
                fprintf(fp, "echo addr: %8p size: %9ld\\n\n",
                        leaks[i].addr,  (long) leaks[i].size);
                for(j = 0; j < 10; j++) {
                    if(!x(leaks[i].ret[j]))
                        break;

                    fprintf(fp, "l *0x%x\n", (int) leaks[i].ret[j]);
                }
            }
        AV_UNLOCK(lock);

        fclose(fp);
        av_log(AVLOG_WARNING, "number of unfreed pointers: %i", numunfreed);
    }
}

