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
# $Id: neon-xml-parser.m4,v 1.2 2002/12/03 18:51:31 mszeredi Exp $

# Check for XML parser.
# Supports:
#  *  libxml (requires version 1.8.3 or later)
#  *  expat in -lexpat
#  *  expat in -lxmlparse and -lxmltok (as packaged by Debian/Red Hat)
#  *  Bundled expat if a directory name argument is passed
#     -> expat dir must contain minimal expat sources, i.e.
#        xmltok, xmlparse sub-directories.  See sitecopy/cadaver for
#	 examples of how to do this.
#
# Usage: 
#  NEON_XML_PARSER()
# or
#  NEON_XML_PARSER(expat-dir)

AC_DEFUN([NEON_XML_PARSER], [

if test "$NEON_NEED_XML_PARSER" = "yes"; then

AC_ARG_ENABLE([libxml],
	[  --enable-libxml         force use of libxml ],
	[neon_force_libxml=$enableval],
	[neon_force_libxml=no])

AC_ARG_WITH([expat],
[  --with-expat=DIR        specify Expat location], [
	if test "$withval" != "no"; then
		case "$withval" in
		*/libexpat.la)
			neon_using_libtool_expat=yes
			withval=`echo $withval | sed 's:/libexpat.la$::'`
		esac
		if test -r "$withval/xmlparse.h"; then
			AC_DEFINE(HAVE_EXPAT, 1, [Define if you have expat])
			CFLAGS="$CFLAGS -I$withval"
			dnl add the library (if it isn't a libtool library)
			if test -z "$neon_using_libtool_expat"; then
				NEONLIBS="$NEONLIBS -L$withval -lexpat"
			fi

			neon_xml_parser_message="expat in $withval"
			neon_found_parser="yes"
		fi
	fi
],[
	neon_found_parser="no"
])

if test "$neon_found_parser" = "no" -a "$neon_force_libxml" = "no"; then
	AC_CHECK_LIB(expat, XML_Parse,
		neon_expat_libs="-lexpat" neon_found_parser="expat",
		AC_CHECK_LIB(xmlparse, XML_Parse,
			neon_expat_libs="-lxmltok -lxmlparse" 
			neon_found_parser="expat",
			neon_found_parser="no",
			-lxmltok )
		)
fi

if test "$neon_found_parser" = "no"; then
	# Have we got libxml 1.8.3 or later?
	AC_CHECK_PROG(XML_CONFIG, xml-config, xml-config)
	if test "$XML_CONFIG" != ""; then
		# Check for recent library
		oLIBS="$LIBS"
		oCFLAGS="$CFLAGS"
		NEWLIBS="`$XML_CONFIG --libs`"
		LIBS="$LIBS $NEWLIBS"
		CFLAGS="$CFLAGS `$XML_CONFIG --cflags`"
		AC_CHECK_LIB(xml, xmlCreatePushParserCtxt,
			neon_found_parser="libxml" neon_xml_parser_message="libxml"
			NEONLIBS="$NEONLIBS $NEWLIBS"
			AC_DEFINE(HAVE_LIBXML, 1, [Define if you have libxml])
			,
			CFLAGS="$oCFLAGS"
			LIBS="$oLIBS"
			AC_WARN([cannot use old libxml (1.8.3 or newer required)])
		)
	fi
fi

if test "$neon_found_parser" = "expat"; then
	# This is crap. Maybe just use AC_CHECK_HEADERS and use the
	# right file by ifdef'ing is best
	AC_CHECK_HEADER(xmlparse.h,
	[neon_expat_incs="" neon_found_expatincs="yes"],
	[AC_CHECK_HEADER(xmltok/xmlparse.h,
	[neon_expat_incs="-I/usr/include/xmltok" neon_found_expatincs="yes"],
	)])
	if test "$neon_found_expatincs" = "yes"; then
		AC_DEFINE(HAVE_EXPAT, 1, [Define if you have expat])
		if test "$neon_expat_incs"; then
			CFLAGS="$CFLAGS $neon_expat_incs"
		fi	
		NEONLIBS="$NEONLIBS $neon_expat_libs"
	else
	       AC_MSG_ERROR(["found expat library but could not find xmlparse.h"])
	fi
	neon_xml_parser_message="expat in $neon_expat_libs"
fi

if test "$neon_found_parser" = "no" ; then

    if test "x$1" != "x"; then
	# Use the bundled expat sources
	AC_LIBOBJ([$1/xmltok/xmltok.o $1/xmltok/xmlrole.o $1/xmlparse/xmlparse.o $1/xmlparse/hashtable.o])
	CFLAGS="$CFLAGS -DXML_DTD -I$1/xmlparse -I$1/xmltok"
	AC_MSG_RESULT(using supplied expat XML parser)	
	AC_DEFINE(HAVE_EXPAT, 1, [Define if you have expat] )
	neon_xml_parser_message="supplied expat in $1"
    else
	AC_MSG_ERROR([no XML parser was found])
    fi

fi

fi

])
