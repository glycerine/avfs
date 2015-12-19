/* 
   String utility functions
   Copyright (C) 1999-2001, Joe Orton <joe@light.plus.com>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

#ifndef STRING_UTILS_H
#define STRING_UTILS_H

#include "neon_defs.h"

#include <stdarg.h>

#include <ctype.h> /* for tolower */

BEGIN_NEON_DECLS

#define ASC2HEX(x) (((x) <= '9') ? ((x) - '0') : (tolower((x)) + 10 - 'a'))
#define HEX2ASC(x) ((x) > 9 ? ((x) - 10 + 'a') : ((x) + '0'))

/* Returns a ne_malloc-allocated UTF-8 encoded copy of 'str'. */
char *ne_utf8_encode(const char *str);

/* Splits str into component parts using given seperator,
 * skipping given whitespace around separators and at the 
 * beginning and end of str. Separators are ignored within
 * any pair of characters specified as being quotes.
 * Returns array of components followed by a NULL pointer. The
 * components are taken from dynamically allocated memory, and
 * the entire array can be easily freed using split_string_free.
 *
 * aka: What strtok should have been.
 */
char **split_string(const char *str, const char seperator,
		    const char *quotes, const char *whitespace);

/* As above, but returns count of items as well */
char **split_string_c(const char *str, const char seperator,
		      const char *quotes, const char *whitespace, int *count);

/* A bit like split_string, except each component is split into a pair.
 * Each pair is returned consecutively in the return array.
 *  e.g.:
 *     strpairs("aa=bb,cc=dd", ',', '=', NULL, NULL)
 *  =>   "aa", "bb", "cc", "dd", NULL, NULL
 * Note, that if a component is *missing* it's key/value separator,
 * then the 'value' in the array will be a NULL pointer. But, if the
 * value is zero-length (i.e., the component separator follows directly
 * after the key/value separator, or with only whitespace inbetween),
 * then the value in the array will be a zero-length string.
 *  e.g.:
 *     pair_string("aaaa,bb=cc,dd=,ee=ff", ',', '=', NULL, NULL)
 *  =>   "aaaa", NULL, "bb", "cc", "dd", "", "ee", "ff"
 * A NULL key indicates the end of the array (the value will also 
 * be NULL, for convenience).
 */
char **pair_string(const char *str, const char compsep, const char kvsep, 
		   const char *quotes, const char *whitespace);

/* Frees the array returned by split_string */
void split_string_free(char **components);

/* Frees the array returned by pair_string */
void pair_string_free(char **pairs);

/* Returns a string which is str with ch stripped from
 * beggining and end, if present in either. The string returned
 * is dynamically allocated using malloc().
 *
 * e.g.  shave_string("abbba", 'a')  => "bbb". */
char *shave_string(const char *str, const char ch);

#define EOL "\r\n"

#define STRIP_EOL(str)				\
do {							\
   char *p;						\
   if ((p = strrchr(str, '\r')) != NULL) *p = '\0';	\
   if ((p = strrchr(str, '\n')) != NULL) *p = '\0';	\
} while (0)

/* Return concatenation of all given strings. */
char *ne_concat(const char *str, ...);

/* String buffer handling. (Strings are zero-terminated still).
 * A string buffer sbuffer * which grows dynamically with the string. */

struct sbuffer_s;
typedef struct sbuffer_s *sbuffer;

/* Returns contents of buffer at current point in time.
 * NOTE: if the buffer is modified with _concat, _append etc,
 * this value may no longer be correct. */
char *sbuffer_data(sbuffer buf);

/* Quick and dirty cast of buf into a 'char *'. 
 * Relies on sbuffer internal ordering. */
#define SBUFFER_CAST(buf) (*(char **)buf)

/* Returns size of data in buffer, equiv to strlen(sbuffer_data(buf)) */
int sbuffer_size(sbuffer buf);

/* Concatenate all given strings onto the end of the buffer.
 * The strings must be null-terminated, and MUST be followed by a
 * NULL argument marking the end of the list.
 * Returns:
 *   0 on success
 *   non-zero on error
 */
int sbuffer_concat(sbuffer buf, ...);

/* Create a new sbuffer. Returns NULL on error */
sbuffer sbuffer_create(void);

/* Create a new sbuffer of given minimum size. Returns NULL on error */
sbuffer sbuffer_create_sized(size_t size);

/* Destroys (deallocates) a buffer */
void sbuffer_destroy(sbuffer buf);

/* Append a zero-terminated string 'str' to buf.
 * Returns 0 on success, non-zero on error. */
int sbuffer_zappend(sbuffer buf, const char *str);

/* Append 'len' bytes of 'data' to buf.  'data' does not need to be
 * zero-terminated. The resultant string will have a zero-terminator,
 * either way. Returns 0 on success, non-zero on error.  */
int sbuffer_append(sbuffer buf, const char *data, size_t len);

/* Empties the contents of buf; makes the buffer zero-length. */
void sbuffer_clear(sbuffer buf);

/* Grows the sbuffer to a minimum size.
 * Returns 0 on success, non-zero on error */
int sbuffer_grow(sbuffer buf, size_t size);

void sbuffer_altered(sbuffer buf);

/* MD5 ascii->binary conversion */
void md5_to_ascii(const unsigned char md5_buf[16], char *buffer);
void ascii_to_md5(const char *buffer, unsigned char md5_buf[16]);

/* Destroys a buffer, WITHOUT freeing the data, and returns the
 * data. */
char *sbuffer_finish(sbuffer buf);

/* Handy macro to free things. */
#define SAFE_FREE(x) \
do { if ((x)!=NULL) free((x)); (x) = NULL; } while (0)

/* TODO: do these with stpcpy instead... more efficient, but means 
 * bloat on non-GNU platforms. */

/* TODO: could replace with glib equiv's where available, too */

/* NOTES:
 *  - These abort() on malloc() returning NULL
 *  - You will need to #include <string.h> / <strings.h> YOURSELF to
 *    prototype strlen and strcat.
 */

#define CONCAT2(out, str1, str2)			\
do {							\
    out = malloc(strlen(str1) + strlen(str2) + 1);	\
    if (out != NULL) {					\
	strcpy(out, str1);				\
	strcat(out, str2);				\
    } else {						\
	abort();					\
    }							\
} while (0)

#define CONCAT3(out, str1, str2, str3)				\
do {									\
    out = malloc(strlen(str1) + strlen(str2) + strlen(str3) + 1);	\
    if (out != NULL) {							\
	strcpy(out, str1);						\
	strcat(out, str2);						\
	strcat(out, str3);						\
    } else {								\
	abort();							\
    }									\
} while (0)

#define CONCAT4(out, str1, str2, str3, str4)		\
do {							\
    out = malloc(strlen(str1) + strlen(str2)		\
		  + strlen(str3) + strlen(str4) + 1);	\
    if (out != NULL) {					\
	strcpy(out, str1);				\
	strcat(out, str2);				\
	strcat(out, str3);				\
	strcat(out, str4);				\
    } else {						\
	abort();					\
    }							\
} while (0)

END_NEON_DECLS

#endif /* STRING_UTILS_H */


