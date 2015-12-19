EXTRA_DIST = redir/Makefile.in redir/redir.c

noinst_HEADERS = avfscoda.h

if INSTALL_AVFSCODA

sbin_PROGRAMS = avfscoda

AM_CFLAGS = -I$(top_srcdir)/include -DCODAINCLUDE=\"@KERNINCLUDE@/linux/coda.h\" @CFLAGS@ @CPPFLAGS@

avfscoda_LDFLAGS = @LDFLAGS@ @LIBS@
avfscoda_LDADD = ../lib/libavfs_static.la
avfscoda_DEPENDENCIES = redir_module
avfscoda_SOURCES = \
	avfscoda.c          \
	mount.c              \
	dispatch.c           \
	child.c

redir_module:
	( cd redir && make )

install-exec-hook:
	( cd redir && make install )

uninstall-hook:
	( cd redir && make uninstall )

CLEANFILES = redir/redir.o

else

install-exec-hook:
uninstall-hook:

endif
