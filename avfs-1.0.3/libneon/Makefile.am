EXTRA_DIST = README ChangeLog COPYING.LIB

if BUILD_NEON_LIB

noinst_LTLIBRARIES = libneon.la

AM_CFLAGS = -I${top_srcdir}/include @CFLAGS@ @DEFS@
neon_link_flags = @NEON_LINK_FLAGS@

libneon_la_LDFLAGS = $(neon_link_flags) -module

if BUILD_DAVSUPPORT

libneon_la_SOURCES = \
	base64.c \
	dates.c \
	dav_207.c \
	dav_basic.c \
	dav_locks.c \
	dav_props.c \
	hip_xml.c \
	http_auth.c \
	http_basic.c \
	http_cookies.c \
	http_redirect.c \
	http_request.c \
	http_utils.c \
	md5.c \
	ne_alloc.c \
	socket.c \
	string_utils.c \
	uri.c

else

libneon_la_SOURCES = \
	base64.c \
	dates.c \
	http_auth.c \
	http_basic.c \
	http_cookies.c \
	http_redirect.c \
	http_request.c \
	http_utils.c \
	md5.c \
	ne_alloc.c \
	socket.c \
	string_utils.c \
	uri.c

endif


endif

noinst_HEADERS = \
	base64.h \
	dates.h \
	dav_207.h \
	dav_basic.h \
	dav_locks.h \
	dav_props.h \
	hip_xml.h \
	http_auth.h \
	http_basic.h \
	http_cookies.h \
	http_private.h \
	http_redirect.h \
	http_request.h \
	http_utils.h \
	ne_alloc.h \
	neon_defs.h \
	neon_i18n.h \
	neon_md5.h \
	neonconf.h \
	nsocket.h \
	string_utils.h \
	uri.h
