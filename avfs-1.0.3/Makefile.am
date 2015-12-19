## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = dist-bzip2
ACLOCAL_AMFLAGS = -I macros

SUBDIRS =        \
	src      \
	modules  \
	zlib     \
	bzlib    \
	libneon  \
	lib      \
	preload  \
	avfscoda \
	include  \
	test     \
	scripts  \
	spec     \
	patch    \
	macros   \
	extfs    \
	doc	\
	fuse

EXTRA_DIST =                 \
	glassfs/Makefile     \
	glassfs/glassfs.c    \
	glassfs/redir2.c     \
	glassfs/redir2mount.c

start:
	( cd scripts && make start )
