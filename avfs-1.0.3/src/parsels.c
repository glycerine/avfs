/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    PARSELS module

    This module is partly based on the 'vfs.c' module of 
    Midnight Commander VFS, by Miguel de Icaza, Jakub Jelinek and 
    Pavel Machek.
*/

#include "parsels.h"
#include "ugid.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "config.h"

#define MAXCOLS		30

struct columns {
    int idx;
    int num;

    char *cols[MAXCOLS];
    int   cptr[MAXCOLS];
};

#define CURR_COL(col) (col->cols[col->idx])
#define INC_COL(col)  (col->cols[col->idx++])


struct lscache {
    struct ugidcache *ugid;
    struct avtm currtim;
};

static void free_lscache(struct lscache *cache)
{
    av_unref_obj(cache->ugid);
}

struct lscache *av_new_lscache()
{
    struct lscache *cache;

    AV_NEW_OBJ(cache, free_lscache);

    cache->ugid = av_new_ugidcache();
    av_localtime(time(NULL), &cache->currtim);

    return cache;
}

static void split_text(char *p, struct columns *col)
{
    char *original = p;
    int  numcols;
    for (numcols = 0; *p && numcols < MAXCOLS; numcols++){
        while (*p == ' ' || *p == '\r' || *p == '\n'){
            *p = 0;
            p++;
        }
        col->cols [numcols] = p;
        col->cptr [numcols] = p - original;
        while (*p && *p != ' ' && *p != '\r' && *p != '\n')
            p++;
    }
    col->idx = 0;
    col->num = numcols;
}

static int is_num (struct columns *col)
{
    if (!CURR_COL(col) || CURR_COL(col)[0] < '0' || CURR_COL(col)[0] > '9')
        return 0;
    return 1;
}

static int is_dos_date(const char *str)
{
    int len;

    if (!str)
	return 0;

    len = strlen (str);
    if (len != 8 && len != 10)
	return 0;

    if (str[2] != str[5])
	return 0;

    if (!strchr ("\\-/", (int) str[2]))
	return 0;

    return 1;
}

static int is_iso_date(const char *str)
{
    int len;

    if (!str)
	return 0;

    len = strlen (str);
    if (len != 10)
	return 0;

    if (str[4] != str[7])
	return 0;

    if (!strchr ("\\-/", (int) str[4]))
	return 0;

    return 1;
}


static int is_week(const char *str)
{
    if(strstr("SunMonTueWedThuFriSat", str) != NULL) return 1;

    return 0;
}

static int is_month(const char *str, struct avtm *tim)
{
    static const char *const month = "JanFebMarAprMayJunJulAugSepOctNovDec";
    char *pos;
    
    if((pos=strstr(month, str)) != NULL){
        if(tim != NULL)
            tim->mon = (pos - month)/3;
        return 1;
    }
    return 0;
}

static int is_time(const char *str, struct avtm *tim)
{
    char *p, *p2;
  
    if ((p=strchr(str, ':')) && (p2=strrchr(str, ':'))) {
        if (p != p2) {
            if (sscanf (str, "%2d:%2d:%2d", &tim->hour, &tim->min, &tim->sec) != 3)
                return 0;
        }
        else {
            if (sscanf (str, "%2d:%2d", &tim->hour, &tim->min) != 2)
                return 0;
        }
    }
    else return 0;
  
    return 1;
}

static int is_year(const char *str, struct avtm *tim)
{
    long year;
  
    if (strchr(str,':'))
        return (0);
  
    if (strlen(str)!=4)
        return (0);
  
    if (sscanf(str, "%ld", &year) != 1)
        return (0);
  
    if (year < 1900 || year > 3000)
        return (0);
  
    tim->year = (int) (year - 1900);
  
    return (1);
}

/*
 * FIXME: this is broken. Consider following entry:
 * -rwx------   1 root     root            1 Aug 31 10:04 2904 1234
 * where "2904 1234" is filename. Well, this code decodes it as year :-(.
 */

static int parse_filetype (char c)
{
    switch (c){
    case 'd': return AV_IFDIR; 
    case 'b': return AV_IFBLK;
    case 'c': return AV_IFCHR;
    case 'l': return AV_IFLNK;
    case 's': return AV_IFSOCK;
    case 'p': return AV_IFIFO;
    case 'm': 
    case 'n':		/* Don't know what these are :-) */
    case '-': 
    case '?': return AV_IFREG;
  
    default: return -1;
    }
}

/* converts rw-rw-rw- into 0666 */
static int parse_filemode (const char *p)
{	
    int res = 0;

    switch (*(p++)){
    case 'r': res |= 0400; break;
    case '-': break;
    default: return -1;
    }

    switch (*(p++)){
    case 'w': res |= 0200; break;
    case '-': break;
    default: return -1;
    }

    switch (*(p++)){
    case 'x': res |= 0100; break;
    case 's': res |= 0100 | AV_ISUID; break;
    case 'S': res |= AV_ISUID; break;
    case '-': break;
    default: return -1;
    }

    switch (*(p++)){
    case 'r': res |= 0040; break;
    case '-': break;
    default: return -1;
    }

    switch (*(p++)){
    case 'w': res |= 0020; break;
    case '-': break;
    default: return -1;
    }
  
    switch (*(p++)){
    case 'x': res |= 0010; break;
    case 's': res |= 0010 | AV_ISGID; break;
    case 'S': res |= AV_ISGID; break;
    case '-': break;
    default: return -1;
    }

    switch (*(p++)){
    case 'r': res |= 0004; break;
    case '-': break;
    default: return -1;
    }

    switch (*(p++)){
    case 'w': res |= 0002; break;
    case '-': break;
    default: return -1;
    }

    switch (*(p++)){
    case 'x': res |= 0001; break;
    case 't': res |= 0001 | AV_ISVTX; break;
    case 'T': res |= AV_ISVTX; break;
    case '-': break;
    default: return -1;
    }
  
    return res;
}

static avtime_t parse_filedate(struct columns *col, struct avtm *currtim)
{	
    char *p;
    struct avtm tim;
    int d[3];
    int got_year = 0;
    avtime_t t;

    /* Let's setup default time values */
    tim.year = currtim->year;
    tim.mon  = currtim->mon;
    tim.day  = currtim->day;
    tim.hour = 0;
    tim.min  = 0;
    tim.sec  = 0;
    
    p = INC_COL(col);
    
    /* We eat weekday name in case of extfs */
    if(is_week(p)) p = INC_COL(col);
  
    /* Month name */
    if(is_month(p, &tim)){
        /* And we expect, it followed by day number */
        if (is_num (col))
            tim.day = (int) atol (INC_COL(col));
        else
            return -1; /* No day */
    
    } else {
        /* We usually expect:
           Mon DD hh:mm
           Mon DD  YYYY
           But in case of extfs we allow these date formats:
           Mon DD YYYY hh:mm
           Mon DD hh:mm YYYY
           Wek Mon DD hh:mm:ss YYYY
           MM-DD-YY hh:mm
           YYYY-MM-DD hh:mm (ISO 8601)
           where Mon is Jan-Dec, DD, MM, YY two digit day, month, year,
           YYYY four digit year, hh, mm, ss two digit hour, minute or second. */
    
        /* Here just this special case with MM-DD-YY or MM-DD-YYYY */
        if (is_dos_date(p)){
            p[2] = p[5] = '-';
      
            if(sscanf(p, "%2d-%2d-%2d", &d[0], &d[1], &d[2]) == 3){
                /*  We expect to get:
                    1. MM-DD-YY
                    2. DD-MM-YY
                    3. YY-MM-DD
                    4. YY-DD-MM  */
	
                /* Hmm... maybe, next time :)*/
	
                /* At last, MM-DD-YY or MM-DD-YYYY*/
	      
	        /* Months are zero based */
	        if (d[0] > 0)
		    d[0]--;

		if (d[2] > 1900) {
		    d[2] -= 1900;
		} else {
		    /* Y2K madness */
		    if (d[2] < 70)
			d[2] += 100;
		}
		
                tim.mon   = d[0];
                tim.day   = d[1];
                tim.year = d[2];
                got_year = 1;
            } else
                return -1; /* sscanf failed */
        } else if (is_iso_date(p)) {
            if(sscanf(p, "%4d-%2d-%2d", &d[0], &d[1], &d[2]) == 3){
                if(d[0] < 1900) return -1;
                d[0] -= 1900;
                
                if(d[1] < 1 || d[1] > 12) return -1;
                d[1]--; /* Months are zero based */

                if(d[2] < 1 || d[2] > 31) return -1;
                
                tim.mon   = d[1];
                tim.day   = d[2];
                tim.year = d[0];
                got_year = 1;
            } else
                return -1; /* sscanf failed */
        } else
            return -1; /* unsupported format */
    }
  
    /* Here we expect to find time and/or year */
  
    if (is_num (col)) {
        if(is_time(CURR_COL(col), &tim) || 
           (got_year = is_year(CURR_COL(col), &tim))) {
            col->idx++;

            /* This is a special case for ctime() or Mon DD YYYY hh:mm */
            if(is_num (col)) {
                if(got_year) {
                    if(is_time(CURR_COL(col), &tim))
                        col->idx++; /* year & time */
                }
                else if((got_year = is_year(CURR_COL(col), &tim)))
                    col->idx++; /* time & year */
            }
        } /* only time or date */
    }
    else 
        return -1; /* Nor time or date */

    /*
     * If the date is less than 6 months in the past, it is shown without year
     * other dates in the past or future are shown with year but without time
     * This does not check for years before 1900 ... I don't know, how
     * to represent them at all
     */
    if (!got_year &&
        currtim->mon < 6 && currtim->mon < tim.mon && 
        tim.mon - currtim->mon >= 6) tim.year--;
  
    t = av_mktime(&tim);
    if(t < 0) t = 0;

    return t;
}

int av_parse_ls(struct lscache *cache, const char *line,
                  struct avstat *stbuf, char **filename, char **linkname)
{
    struct columns colstruct;
    struct columns *col = &colstruct;
    int i;
    int saveidx, lnkidx;
    char *p_copy = NULL;
    const char *lineorig = line;

    *linkname = NULL;
    *filename = NULL;
    
    if (strncmp (line, "total", 5) == 0)
        return 0;

    if ((i = parse_filetype(*(line++))) == -1)
        goto error;
  
    stbuf->mode = i;
    if (*line == ' ')	/* Notwell 4 */
        line++;
    if (*line == '['){
        if (strlen (line) <= 8 || line [8] != ']')
            goto error;
        /* Should parse here the Notwell permissions :) */
        if (AV_ISDIR (stbuf->mode))
            stbuf->mode |= 755;
        else
            stbuf->mode |= 644;
        line += 9;
    } else {
        if ((i = parse_filemode(line)) == -1)
            goto error;
        stbuf->mode |= i;
        line += 9;
    
        /* This is for an extra ACL attribute (HP-UX) */
        if (*line == '+')
            line++;
    }

    p_copy = av_strdup(line);

    split_text (p_copy, col);

  
    stbuf->nlink = atol (INC_COL(col));
    if (stbuf->nlink <= 0)
        goto error;
  
    if (!is_num (col))
        stbuf->uid = av_finduid (cache->ugid, CURR_COL(col), -1);
    else
        stbuf->uid = (uid_t) atol (CURR_COL(col));
  
    /* Mhm, the ls -lg did not produce a group field */
    for (col->idx = 3; col->idx <= 5; col->idx++) 
        if (is_month(CURR_COL(col), NULL) || 
            is_week(CURR_COL(col)) || 
            is_dos_date(CURR_COL(col)) ||
            is_iso_date(CURR_COL(col)))
            break;

    saveidx = col->idx;
    col->idx = 2;

  
    if (saveidx == 6 || 
        (saveidx == 5 && !AV_ISCHR(stbuf->mode) && !AV_ISBLK(stbuf->mode)))
        goto error;

    if (!(saveidx == 3 || 
          (saveidx == 4 && (AV_ISCHR(stbuf->mode) || AV_ISBLK (stbuf->mode))))) {
        /* We have gid field */

        if (is_num (col))
            stbuf->gid = (gid_t) atol (INC_COL(col));
        else
            stbuf->gid = av_findgid (cache->ugid, INC_COL(col), -1);
    }
  
    /* This is device */
    if (AV_ISCHR (stbuf->mode) || AV_ISBLK (stbuf->mode)){
        int maj, min;
	
        if (!is_num (col) || sscanf(INC_COL(col), " %d,", &maj) != 1)
            goto error;
    
        if (!is_num (col) || sscanf(INC_COL(col), " %d", &min) != 1)
            goto error;
	
        stbuf->rdev = av_mkdev(maj, min);
        stbuf->size = 0;
    
    } else {
        /* Common file size */
        if (!is_num (col))
            goto error;
    
#ifdef HAVE_ATOLL
        stbuf->size = (avoff_t) atoll (INC_COL(col));
#else
        stbuf->size = (avoff_t) atol (INC_COL(col));
#endif
        stbuf->rdev = 0;
    }
  
    col->idx = saveidx;
  
    stbuf->mtime.nsec = 0;
    stbuf->mtime.sec = parse_filedate(col, &cache->currtim);
    if (stbuf->mtime.sec == -1)
        goto error;

    /* Use resulting time value */
    stbuf->atime = stbuf->ctime = stbuf->mtime;
    stbuf->dev = 0;
    stbuf->ino = 0;
    stbuf->blksize = 512;
    stbuf->blocks = AV_DIV(stbuf->size, 512);

    saveidx = col->idx;
    lnkidx = 0;

    for (col->idx ++; col->idx < col->num; col->idx++) 
        if (strcmp (CURR_COL(col), "->") == 0) {
            lnkidx = col->idx;
            break;
        }
  
    col->idx = saveidx;

    if (((AV_ISLNK (stbuf->mode) || 
          /* Maybe a hardlink? (in extfs) */
          (col->num == saveidx + 3 && stbuf->nlink > 1))) 
        && lnkidx){
        int p;
        int len;
        char *s;
  
        len = col->cptr[lnkidx] - col->cptr[col->idx] - 1;
        s = av_malloc(len + 1);
        strncpy(s, line + col->cptr[col->idx], len);
        s[len] = '\0';
        *filename = s;
    
        s = av_strdup (line + col->cptr[lnkidx + 1]);
        p = strlen (s);
        if (s [p-1] == '\r' || s [p-1] == '\n')
            s [p-1] = 0;
        if (s [p-2] == '\r' || s [p-2] == '\n')
            s [p-2] = 0;
    
        *linkname = s;

    } else {
        int p;
        char *s;
    
        s = av_strdup (line + col->cptr[col->idx]);
        p = strlen (s);
    
        if (p >= 1 && (s [p-1] == '\r' || s [p-1] == '\n'))
            s [p-1] = 0;
        if (p >= 2 && (s [p-2] == '\r' || s [p-2] == '\n'))
            s [p-2] = 0;
    
        *filename = s;
    }
    av_free (p_copy);
    return 1;
  
  error:
    av_free(p_copy);
    av_log(AVLOG_WARNING, "Could not parse %s", lineorig);

    return 0;
}
