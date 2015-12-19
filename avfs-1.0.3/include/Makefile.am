## Before Automake 1.8.1 the conditional include_HEADERS are not
## correctly added to the distribution
## Possible solution: Require Automake 1.8.1
## Or (chosen here): Add both files to noinst_HEADERS

if BUILD_SHARED
include_HEADERS = avfs.h virtual.h
else
include_HEADERS = avfs.h
endif

noinst_HEADERS = archive.h \
	bzfile.h \
	cache.h \
	exit.h \
	filebuf.h \
	filecache.h \
	filter.h \
	internal.h \
	namespace.h \
	oper.h \
	operutil.h \
	parsels.h \
	passwords.h \
	prog.h \
	realfile.h \
	remote.h \
	runprog.h \
	serialfile.h \
	socket.h \
	state.h \
	tmpfile.h \
	ugid.h \
	zfile.h \
	avfs.h \
	virtual.h

if USE_LIBLZMA
noinst_HEADERS += xzfile.h
endif

BUILT_SOURCES = version.h
