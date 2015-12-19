##TODO Using automake 1.9 it would be possible to conditional
## use lib_ or noinst_ for libavfs depending on configure flag
## Currently a static is always built but the shared is only built if wanted

if BUILD_SHARED
lib_LTLIBRARIES = libavfs.la
endif

noinst_LTLIBRARIES = libavfs_static.la

##TODO --version-script is not supported by some linkers (Sun linker for example)
##libavfs_la_LDFLAGS = -Wl,--version-script=libavfs.map -version-info 0:1:0
##TODO Exporting only virt_ symbols doesn't work because avfs_server needs
##     other symbols too
##     Possible solution: Also build a static library which doesn't get installed

libavfs_la_LDFLAGS = @VERSIONSCRIPT_OPTS@ -version-info 0:2:0
libavfs_la_LIBADD = ../src/libavfscore.la ../modules/libmodules.la @LIBZ@ @LIBBZ2@ @LIBDAV@
libavfs_la_SOURCES = 

libavfs_static_la_LDFLAGS = -static
libavfs_static_la_LIBADD = ../src/libavfscore.la ../modules/libmodules.la  @LIBZ@ @LIBBZ2@ @LIBDAV@
libavfs_static_la_SOURCES = 

EXTRA_DIST = libavfs.map
