AM_CFLAGS = -I$(top_srcdir)/include @CFLAGS@ @CPPFLAGS@ 

noinst_LTLIBRARIES = libmodules.la
EXTRA_DIST = make_initmod

libmodules_la_LDFLAGS = -module

modules = \
	volatile.c   \
	rsh.c        \
	http.c       \
	ftp.c        \
	ugz.c        \
	ubz2.c       \
	ugzip.c      \
	ubzip2.c     \
	gz.c         \
	bz2.c        \
	uz.c         \
	uar.c        \
	utar.c       \
	urar.c       \
	uzip.c       \
	floppy.c     \
	extfs.c      \
	ucftp.c      \
	uxze.c

if USE_LIBLZMA
    modules += uxz.c
endif

libmodules_la_SOURCES = \
	$(modules)

if BUILD_DAVSUPPORT
    modules += dav.c
    libmodules_la_SOURCES += dav.c dav_ls.c
endif

nodist_libmodules_la_SOURCES = \
	mod_static.c

noinst_HEADERS = \
	dav.h \
	gtar.h \
	zipconst.h

mod_static.c: make_initmod
	$(srcdir)/make_initmod $(modules) > mod_static.c

CLEANFILES = mod_static.c
