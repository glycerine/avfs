EXTFS_CONST =		\
	bpp		\
        ftplist		\
        rpm		\
        trpm		\
	uadf		\
	uarc		\
	ucab		\
        ucpio		\
	udar		\
	uimg

EXTFS_IN =	\
	a		\
	apt		\
	audio		\
	deb		\
	deba		\
	debd		\
	dpkg		\
	hp48		\
	iso9660		\
	lslR		\
	mailfs		\
	patchfs		\
	rpms		\
	u7z		\
	uace		\
	uar		\
	uarj		\
	uc1541		\
	uha		\
	ulha		\
	upp		\
	uextrar		\
	uxdms		\
	uxpk		\
	uzip		\
	uzoo

extfsscriptsdir = @moduledir@/extfs
extfsscripts_SCRIPTS = $(EXTFS_IN) $(EXTFS_CONST)

extfsdatadir = @moduledir@/extfs
extfsdata_DATA = extfs.ini README

EXTRA_DIST = $(extfsdata_DATA) $(EXTFS_CONST)
