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
# $Id: neon-ssl.m4,v 1.1 2001/03/13 09:47:51 mszeredi Exp $

# $1 specifies the location of the bundled neon "src" directory, or
# is empty if none is bundled. $1 specifies the location of the bundled
# expat directory, or is empty if none is bundled.

AC_DEFUN([NEON_SSL],[

AC_ARG_WITH(ssl, 
	[  --with-ssl[=DIR]        enable OpenSSL support ],,
	[with_ssl="no"])

# In an ideal world, we would default to with_ssl="yes".
# But this might lead to packagers of neon-enabled apps
# unknowingly exporting crypto binaries.

AC_MSG_CHECKING(for OpenSSL)

if test "$with_ssl" = "yes"; then
	# They didn't specify a location: look in
	# some usual places
	neon_ssl_dirs="/usr/local/ssl /usr/ssl /usr"
	neon_ssl_location=""

	for d in $neon_ssl_dirs; do
		if test -r $d/include/openssl/ssl.h; then
			neon_ssl_location=$d
			break
		fi
	done
elif test "$with_ssl" = "no"; then
	neon_ssl_location=""
else
	neon_ssl_location=$with_ssl
fi

if test -n "$neon_ssl_location"; then
	CFLAGS="$CFLAGS -I${neon_ssl_location}/include"
	LDFLAGS="$LDFLAGS -L${neon_ssl_location}/lib"
	NEONLIBS="$NEONLIBS -lssl -lcrypto"
	AC_DEFINE([ENABLE_SSL], 1, [Define to enable OpenSSL support])
	AC_MSG_RESULT(found in $neon_ssl_location)
else
	AC_MSG_RESULT(not found)
fi

])

