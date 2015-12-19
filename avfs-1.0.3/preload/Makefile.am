AM_CFLAGS = -I$(top_srcdir)/include @CFLAGS@ @CPPFLAGS@ \
	-DAVFS_SERVER_DIR=\"@moduledir@\"

EXTRA_DIST = leak.c leakcheck
LIBS = 

noinst_HEADERS = \
	client.h \
	cmd.h \
	send.h \
	server.h \
	utils.h

if INSTALL_PRELOAD

lib_LTLIBRARIES = avfs_preload.la

avfs_preload_la_LDFLAGS = -module
avfs_preload_la_LIBADD = @PRELOAD_LIBS@
avfs_preload_la_SOURCES = \
	client.c  \
	utils.c   \
	send.c    \
	file.c    \
	open.c    \
	stat.c    \
	misc.c

server_PROGRAMS = avfs_server
serverdir = @moduledir@
avfs_server_LDFLAGS = @LDFLAGS@ @LIBS@
avfs_server_DEPENDENCIES = send.lo
avfs_server_LDADD = ../lib/libavfs_static.la send.lo @LIBS@

avfs_server_SOURCES = \
	avfs_server.c       \
	server.c
#avfs_server_SOURCES = \
#	avfs_server.c       \
#	server.c            \
#	leak.c

endif
