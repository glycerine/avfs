if INSTALL_FUSE

bin_PROGRAMS = avfsd

AM_CFLAGS = -I$(top_srcdir)/include @CFLAGS@ @CPPFLAGS@

avfsd_LDFLAGS = @LDFLAGS@ @LIBS@ @FUSELIBS@
avfsd_LDADD = ../lib/libavfs_static.la
avfsd_SOURCES = avfsd.c

endif
