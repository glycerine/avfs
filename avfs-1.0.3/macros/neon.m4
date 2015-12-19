# Copyright (C) 1998-2000 Joe Orton.  
# This file is free software; you may copy and/or distribute it with
# or without modifications, as long as this notice is preserved.
# This software is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even
# the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.

# The above license applies to THIS FILE ONLY, the neon library code
# itself may be copied and distributed under the terms of the GNU
# LGPL, see COPYING.LIB for more details

# This file is part of the neon HTTP/WebDAV client library.
# See http://www.webdav.org/neon/ for the latest version. 
# Please send any feedback to <neon@webdav.org>

#
# Usage:
#
#      NEON_LIBRARY
# or   NEON_BUNDLED(srcdir, [ACTIONS-IF-BUNDLED]) 
# or   NEON_VPATH_BUNDLED(srcdir, builddir, [ACTIONS-IF-BUNDLED])
#
#   where srcdir is the location of bundled neon 'src' directory.
#   If using a VPATH-enabled build, builddir is the location of the
#   build directory corresponding to srcdir.
#
#   If a bundled build *is* being used, ACTIONS-IF-BUNDLED will be
#   evaluated. These actions should ensure that 'make' is run
#   in srcdir, and that one of NEON_NORMAL_BUILD or NEON_LIBTOOL_BUILD 
#   is called.
#
# After calling one of the above macros, if the NEON_NEED_XML_PARSER
# variable is set to "yes", then you must configure an XML parser
# too. You can do this your own way, or do it easily using the
# NEON_XML_PARSER() macro. Example usage for where we have bundled the
# neon sources in a directory called libneon, and bundled expat
# sources in a directory called 'expat'.
#
#   NEON_BUNDLED(libneon, [
#	SUBDIRS="$SUBDIRS libneon"
#	NEON_XML_PARSER(expat)
#	NEON_NORMAL_BUILD
#   ])
#
# Alternatively, for a simple standalone app with neon as a
# dependancy, use just:
#
#   NEON_LIBRARY
# 
# and rely on the user installing neon correctly.
#
# You are free to configure an XML parser any other way you like,
# but the end result must be, either expat or libxml will get linked
# in, and HAVE_EXPAT or HAVE_LIBXML is defined appropriately.
#
# To set up the bundled build environment, call 
#
#    NEON_NORMAL_BUILD
# or
#    NEON_LIBTOOL_BUILD
# 
# depending on whether you are using libtool to build, or not.
# Both these macros take an optional argument specifying the set
# of object files you wish to build: if the argument is not given,
# all of neon will be built.

AC_DEFUN([NEON_BUNDLED],[

neon_bundled_srcdir=$1
neon_bundled_builddir=$1

NEON_COMMON_BUNDLED([$2])

])

AC_DEFUN([NEON_VPATH_BUNDLED],[

neon_bundled_srcdir=$1
neon_bundled_builddir=$2
NEON_COMMON_BUNDLED([$3])

])

AC_DEFUN([NEON_COMMON_BUNDLED],[

AC_ARG_WITH(included-neon,
[  --with-included-neon    Force use of included neon library ],
[neon_force_included="$withval"],
[neon_force_included="no"])

NEON_COMMON

if test "$neon_force_included" = "yes"; then
	# The colon is here so there is something to evaluate
	# here in case the argument was not passed.
	:
	$1
fi

])

dnl Not got any bundled sources:
AC_DEFUN([NEON_LIBRARY],[

neon_force_included=no
neon_bundled_srcdir=
neon_bundled_builddir=

NEON_COMMON

])

AC_DEFUN([NEON_VERSIONS], [

# Define the current versions.
NEON_VERSION_MAJOR=0
NEON_VERSION_MINOR=12
NEON_VERSION_RELEASE=0
NEON_VERSION_TAG=

NEON_VERSION="${NEON_VERSION_MAJOR}.${NEON_VERSION_MINOR}.${NEON_VERSION_RELEASE}${NEON_VERSION_TAG}"

# the libtool interface version is
#   current:revision:age
NEON_INTERFACE_VERSION="12:0:0"

AC_DEFINE_UNQUOTED(NEON_VERSION, "${NEON_VERSION}", 
	[Define to be the neon version string])
AC_DEFINE_UNQUOTED(NEON_VERSION_MAJOR, [(${NEON_VERSION_MAJOR})],
	[Define to be major number of neon version])
AC_DEFINE_UNQUOTED(NEON_VERSION_MINOR, [(${NEON_VERSION_MINOR})],
	[Define to be minor number of neon version])

])

dnl Define the minimum required version
AC_DEFUN([NEON_REQUIRE], [
neon_require_major=$1
neon_require_minor=$2
])

dnl Check that the external library found in a given location
dnl matches the min. required version (if any)
dnl Usage:
dnl    NEON_CHECK_VERSION(instroot[, ACTIONS-IF-OKAY[, ACTIONS-IF-FAILURE]])
dnl
AC_DEFUN([NEON_CHECK_VERSION], [

if test "x$neon_require_major" = "x"; then
    :
    $2
else
    config=$1/bin/neon-config
    oLIBS="$LIBS"
    oCFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS `$config --cflags`"
    LIBS="$LIBS `$config --libs`"
    ver=`$config --version`
    AC_MSG_CHECKING(for neon library version)
    AC_TRY_RUN([
#include <http_utils.h>
    
int main(void) {
return neon_version_minimum($neon_require_major, $neon_require_minor);
}
], [
    AC_MSG_RESULT([okay (found $ver)])
    LIBS="$oLIBS"
    CFLAGS="$oCFLAGS"
    $2
], [
    AC_MSG_RESULT([failed, found $ver wanted >=$neon_require_major.$neon_require_minor])
    LIBS="$oLIBS"
    CFLAGS="$oCFLAGS"
    $3
])

fi

])

AC_DEFUN([NEON_COMMON],[

NEON_VERSIONS

AC_ARG_WITH(neon,
	[  --with-neon	          Specify location of neon library ],
	[neon_loc="$withval"])

AC_MSG_CHECKING(for neon location)

if test "$neon_force_included" = "no"; then
    # We don't have an included neon source directory,
    # or they aren't force us to use it.

    if test -z "$neon_loc"; then
	# Look in standard places
	for d in /usr /usr/local; do
	    if test -x $d/bin/neon-config; then
		neon_loc=$d
	    fi
	done
    fi

    if test -x $neon_loc/bin/neon-config; then
	# Found it!
	AC_MSG_RESULT(found in $neon_loc)
	NEON_CHECK_VERSION([$neon_loc], [
	  NEON_CONFIG=$neon_loc/bin/neon-config
	  CFLAGS="$CFLAGS `$NEON_CONFIG --cflags`"
	  NEONLIBS="$NEONLIBS `$NEON_CONFIG --libs`"
	  neon_library_message="library in $neon_loc (`$NEON_CONFIG --version`)"
	  neon_xml_parser_message="using whatever libneon uses"
	  neon_got_library=yes
        ], [
	  neon_got_library=no
	])
    else
	neon_got_library=no
    fi

    if test "$neon_got_library" = "no"; then 
	if test -n "$neon_bundled_srcdir"; then
	    # Couldn't find external neon, forced to use bundled sources
	    neon_force_included="yes"
	else
	    # Couldn't find neon, and don't have bundled sources
	    AC_MSG_ERROR(could not find neon)
	fi
    fi
fi

# This isn't a simple 'else' branch, since neon_force_included
# is set to yes if the search fails.

if test "$neon_force_included" = "yes"; then
    AC_MSG_RESULT([using supplied ($NEON_VERSION)])
    CFLAGS="$CFLAGS -I$neon_bundled_srcdir"
    LDFLAGS="$LDFLAGS -L$neon_bundled_builddir"
    NEONLIBS="$LIBS -lneon"
    NEON_BUILD_BUNDLED="yes"
    LIBNEON_SOURCE_CHECKS
    NEON_NEED_XML_PARSER=yes
    neon_library_message="included libneon (${NEON_VERSION})"
else
    # Don't need to configure an XML parser
    NEON_NEED_XML_PARSER=no
    NEON_BUILD_BUNDLED="yes"
fi

AC_SUBST(NEON_BUILD_BUNDLED)
AC_SUBST(NEONLIBS)

])

dnl Call these checks when compiling the libneon source package.

AC_DEFUN([LIBNEON_SOURCE_CHECKS],[

AC_C_BIGENDIAN
AC_C_INLINE
AC_C_CONST

AC_CHECK_HEADERS(stdarg.h string.h strings.h sys/time.h regex.h \
	stdlib.h unistd.h limits.h sys/select.h arpa/inet.h)

AC_REPLACE_FUNCS(strcasecmp)

AC_SEARCH_LIBS(gethostbyname, nsl)

AC_SEARCH_LIBS(socket, socket inet)

NEON_SSL()

])

dnl Call to put lib/snprintf.o in LIBOBJS and define HAVE_SNPRINTF_H
dnl if snprintf isn't in libc.

AC_DEFUN([NEON_REPLACE_SNPRINTF], [

dnl Check for snprintf
AC_CHECK_FUNC(snprintf,,
	AC_DEFINE(HAVE_SNPRINTF_H, 1, [Define if need to include snprintf.h])
	AC_LIBOBJ([lib/snprintf.o])

])

dnl Common macro to NEON_LIBTOOL_BUILD and NEON_NORMAL_BUILD
dnl Sets NEONOBJS appropriately if it has not already been set.
dnl 
dnl NOT FOR EXTERNAL USE: use LIBTOOL_BUILD or NORMAL_BUILD.
dnl

dnl turn off webdav, boo hoo.
AC_DEFUN([NEON_WITHOUT_WEBDAV], [
neon_no_webdav=yes
NEON_NEED_XML_PARSER=no
neon_xml_parser_message="none needed"
])

AC_DEFUN([NEON_COMMON_BUILD], [

dnl Cunning hack: $1 is passed as the number of arguments passed
dnl to the NORMAL or LIBTOOL macro, so we know whether they 
dnl passed any arguments or not.

ifelse($1, 0, [

 # Using the default set of object files to build.

 # 'o' is the object extension in use
 o=$NEON_OBJEXT

 AC_MSG_CHECKING(whether to enable WebDAV support in neon)

 dnl Did they want DAV support?
 if test "x$neon_no_webdav" = "xyes"; then
  # No WebDAV support
  NEONOBJS="http_request.$o http_basic.$o string_utils.$o uri.$o  \
    dates.$o ne_alloc.$o base64.$o md5.$o http_utils.$o		  \
    socket.$o http_auth.$o http_cookies.$o http_redirect.$o"

  AC_MSG_RESULT(no)

 else
	
 # WebDAV support
  NEONOBJS="http_request.$o http_basic.$o dav_basic.$o	\
    dav_207.$o string_utils.$o dates.$o ne_alloc.$o	\
    hip_xml.$o base64.$o md5.$o http_utils.$o		\
    uri.$o socket.$o http_auth.$o dav_props.$o		\
    http_cookies.$o dav_locks.$o http_redirect.$o"

  # Turn on DAV locking please then.
  AC_DEFINE(USE_DAV_LOCKS, 1, [Support WebDAV locking through the library])

  AC_MSG_RESULT(yes)

 fi

], [
 
 # Using a specified set of object files.
 NEONOBJS=$1

])

AC_SUBST(NEON_TARGET)
AC_SUBST(NEON_OBJEXT)
AC_SUBST(NEONOBJS)
AC_SUBST(NEON_LINK_FLAGS)

AC_PATH_PROG(AR, ar)

])

# The libtoolized build case:
AC_DEFUN([NEON_LIBTOOL_BUILD], [

NEON_TARGET=libneon.la
NEON_OBJEXT=lo

NEON_COMMON_BUILD($#, $*)

])

# The non-libtool build case:
AC_DEFUN([NEON_NORMAL_BUILD], [

NEON_TARGET=libneon.a
NEON_OBJEXT=o

NEON_COMMON_BUILD($#, $*)

])
