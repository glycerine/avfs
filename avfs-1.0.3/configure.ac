dnl Process this file with autoconf to produce a configure script.

define(AVFS_MAJOR,[1])
define(AVFS_MINOR,[0])
define(AVFS_PATCH,[3])
define(AVFS_COMMENT,[])

define(AVFS_VERSION,AVFS_MAJOR[.]AVFS_MINOR[.]AVFS_PATCH[]AVFS_COMMENT)
define(AVFS_NUMVERSION,m4_eval(AVFS_MAJOR*100+AVFS_MINOR*10+AVFS_PATCH))

AC_PREREQ([2.50])
AC_INIT([avfs], AVFS_VERSION)
AC_CONFIG_SRCDIR([include/avfs.h])
AM_INIT_AUTOMAKE

AC_CONFIG_HEADER(include/config.h:config.h.in)
AC_PREFIX_DEFAULT(/usr)
AC_CONFIG_MACRO_DIR([macros])

dnl Check if on the same host if reconfiguring

AC_CANONICAL_HOST

AC_MSG_CHECKING([if configuration is valid])
AC_CACHE_VAL(szm_cv_host_system, [szm_cv_host_system=$host])
if test "$host" = "$szm_cv_host_system"; then
  validstring="valid"
else
  validstring="invalid"
fi
AC_MSG_RESULT([$validstring])
if test "$validstring" = invalid; then
  AC_MSG_ERROR([type 'make realclean' before running configure])
fi

VERSION=AVFS_VERSION
AC_SUBST(VERSION)

NUMVERSION=AVFS_NUMVERSION
AC_SUBST(NUMVERSION)

os=`uname -s`
kernver=`uname -r | sed -n 's/\([[0-9]]\+\)\.\([[0-9]]\+\)\..*/\1\2/p'`
if test -z "$kernver"; then
  kernver="0"
fi

AC_MSG_CHECKING([whether to build preload, avfscoda, shared library and/or fuse daemon])

dnl here come the default values
shared=yes
if test "$os" = "Linux"; then
    if test "$kernver" -ge "22" \
            -a "$kernver" -le "24"; then
        avfscoda=yes
    else
        fuse=yes
    fi
elif test "$os" = "SunOS"; then
    preload=yes
fi

AC_ARG_ENABLE([preload],
              AC_HELP_STRING([--enable-preload],[Compile the preloaded library and server]),
              [if test "$enableval" = yes; then preload=yes; else preload=no; fi])

AC_ARG_ENABLE([avfscoda],
              AC_HELP_STRING([--enable-avfscoda],[Compile avfscoda (which uses the coda interface)]),
              [if test "$enableval" = yes; then avfscoda=yes; else avfscoda=no; fi])

AC_ARG_ENABLE([library],
              AC_HELP_STRING([--enable-library],[Compile avfs as a shared or static library]),
              [if test "$enableval" = yes; then shared=yes; else shared=no; fi])

AC_ARG_ENABLE([fuse],
              AC_HELP_STRING([--enable-fuse],[Compile avfsd for fuse]),
              [if test "$enableval" = yes; then fuse=yes; else fuse=no; fi])

shared_build=no
avfscoda_build=no
preload_build=no
fuse_build=no
build_result=

if test "$avfscoda" = yes; then
   avfscoda_build=yes
   build_result=avfscoda
fi
if test "$preload" = yes; then
   preload_build=yes
   if test -z "$build_result"; then
      build_result=preload
   else
      build_result="$build_result preload"
   fi
fi
if test "$shared" = yes; then
   shared_build=yes
   if test -z "$build_result"; then
      build_result=shared
   else
      build_result="$build_result shared"
   fi
fi
if test "$fuse" = yes; then
   fuse_build=yes
   if test -z "$build_result"; then
      build_result=fuse
   else
      build_result="$build_result fuse"
   fi
fi

AC_MSG_RESULT([$build_result])

AC_MSG_CHECKING([whether debugging is enabled])
AC_ARG_ENABLE(debug,
[  --enable-debug          Compile in debug information
  --disable-debug         Do not compile in debug information],
[if test "$enableval" = yes; then debugmode=yes; else debugmode=no; fi],
debugmode=yes)
AC_MSG_RESULT([$debugmode])

AC_MSG_CHECKING([whether building the dav module is enabled])
AC_ARG_ENABLE(dav,
[  --enable-dav            Compile the dav module (needs an xml library)],
[if test "$enableval" = yes; then dav=yes; else dav=no; fi],
dav=no)
AC_MSG_RESULT([$dav])

AC_ARG_WITH(system-zlib,
            AC_HELP_STRING([--with-system-zlib],[Use system zlib instead of builtin]),
            [if test "$withval" = yes; then use_system_zlib=yes; else use_system_zlib=no; fi],
            [use_system_zlib=no])
AM_CONDITIONAL(USE_SYSTEM_ZLIB,[test x$use_system_zlib = xyes])
if test x$use_system_zlib = xyes; then
    AC_DEFINE(USE_SYSTEM_ZLIB, 1, [Define if you want to use system zlib library])
    LIBZ=-lz
    ZLIB_INCLUDE=
else
    LIBZ=../zlib/libzlib.la
    ZLIB_INCLUDE='-I$(top_srcdir)/zlib'
fi
AC_SUBST(LIBZ)
AC_SUBST(ZLIB_INCLUDE)

AC_ARG_WITH(system-bzlib,
            AC_HELP_STRING([--with-system-bzlib],[Use system bzlib instead of builtin]),
            [if test "$withval" = yes; then use_system_bzlib=yes; else use_system_bzlib=no; fi],
            [use_system_bzlib=no])
AM_CONDITIONAL(USE_SYSTEM_BZLIB,[test x$use_system_bzlib = xyes])
if test x$use_system_bzlib = xyes; then
    AC_DEFINE(USE_SYSTEM_BZLIB, 1, [Define if you want to use system bzlib library])
    LIBBZ2=-lbz2
    BZLIB_INCLUDE=
else
    LIBBZ2=../bzlib/libbz.la
    BZLIB_INCLUDE='-I$(top_srcdir)/bzlib'
fi
AC_SUBST(LIBBZ2)
AC_SUBST(BZLIB_INCLUDE)

dnl Checks for programs.
cflags="$CFLAGS"
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL

PKG_PROG_PKG_CONFIG

if test ! "$preload_build" = "yes"; then
  AC_SYS_LARGEFILE
fi


fob_set=no
if test "x$ac_cv_sys_file_offset_bits" != x -a "$ac_cv_sys_file_offset_bits" != no; then
  CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=$ac_cv_sys_file_offset_bits"
  fob_set=yes
fi
if test "x$ac_cv_sys_large_files" != x -a "$ac_cv_sys_large_files" != no; then
  CPPFLAGS="$CPPFLAGS -D_LARGE_FILES=$ac_cv_sys_large_files"
fi

if test "$enable_largefile" != no -a "$fob_set" != "yes" -a "$fuse_build" = "yes"; then
  dnl FIXME this is kind of a hack to force the flag _FILE_OFFSET_BITS
  dnl if large file support was requested but the macro decided not to
  dnl use it (for example if arch doesn't need it)
  dnl This is currently required because fuse refuses to work without it
  CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64"
  fob_set=yes
fi

if test -z "$cflags"; then
   if test "$GCC" = yes; then
      if test "$debugmode" = yes; then
         CFLAGS="-Wall -g"
      else 
         CFLAGS="-Wall -O3"
      fi
      ZLIB_CFLAGS="-Wall -O3"
   else
      if test "$debugmode" = yes; then
         CFLAGS="-g"
      else
         CFLAGS="-O"
      fi
      ZLIB_CFLAGS="-O"
   fi
fi

AC_SUBST(ZLIB_CFLAGS)

CPPFLAGS="$CPPFLAGS -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -D_GNU_SOURCE"

if test -z "$LD"; then
	AC_CHECK_PROG(LD, ld, [ld -r], [$CC -Wl,-r -nostdlib])
else
	LD="$LD -r"
	AC_SUBST(LD)
fi

AC_CHECK_FUNCS(vsnprintf strncasecmp strcasecmp mkdtemp)
AC_CHECK_FUNCS(getpwuid_r getpwnam_r getgrgid_r getgrnam_r)
AC_CHECK_FUNCS(atoll)
AC_HEADER_MAJOR

dnl For zlib
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(sys/statvfs.h)

AC_CACHE_CHECK([for d_type in struct dirent], my_cv_struct_d_type,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <dirent.h>], [struct dirent d; d.d_type;],
my_cv_struct_d_type=yes, my_cv_struct_d_type=no)])
if test $my_cv_struct_d_type = yes; then
  AC_DEFINE(HAVE_D_TYPE, 1, [Define if your struct direntry has d_type])
fi

AC_CACHE_CHECK([for d_off in struct dirent], my_cv_struct_d_off,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <dirent.h>], [struct dirent d; d.d_off;],
my_cv_struct_d_off=yes, my_cv_struct_d_off=no)])
if test $my_cv_struct_d_off = yes; then
  AC_DEFINE(HAVE_D_OFF, 1, [Define if your struct direntry has d_off])
fi

AC_SEARCH_LIBS(nanosleep, posix4)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket inet)

build_neon_lib=no
if test "$dav" = yes; then
  dnl We require neon 0.12
  NEON_REQUIRE(0,12)

  dnl Build neon. We support a VPATH build.
  NEON_BUNDLED('${top_srcdir}/libneon', [
      NEON_NORMAL_BUILD
      NEON_XML_PARSER
  ])
#  LIBS=$NEONLIBS
  DAV=dav.c
  DAV_LS=dav_ls.c
  LIBDAV=../libneon/libneon.la
  build_neon_lib=yes
else
  NEON_BUILD_BUNDLED=no
  AC_SUBST(NEON_BUILD_BUNDLED)
  DAV=
  DAV_LS=
  LIBDAV=
fi

AM_CONDITIONAL(BUILD_NEON_LIB, test x$build_neon_lib = xyes)
AM_CONDITIONAL(BUILD_DAVSUPPORT, test x$build_neon_lib = xyes)

AC_SUBST(DAV)
AC_SUBST(DAV_LS)
AC_SUBST(LIBDAV)

AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(pthread, pthread_create)
if test -z "`echo "$LIBS"|grep pthread`"; then
	LIBS="$LIBS -pthread"
fi

moduledir='${libdir}/avfs'

AC_SUBST(moduledir)

install_scriptcomps=

AC_CHECK_PROG(EMACS, emacs, yes, no)
MC_EXTFS_CHECKS

AM_CONDITIONAL(INSTALL_EMACS, test x$EMACS = xyes)

dnl ================================================================
dnl == Now comes the stuff that is only for preload               ==
dnl ================================================================

if test $preload_build = yes; then
	origlibs=$LIBS
	LIBS=
	AC_CHECK_FUNCS(lseek64 getdents64 open64 creat64 stat64 acl)
	AC_SEARCH_LIBS(socket, socket inet)
	AC_SEARCH_LIBS(dlsym, dl)
	PRELOAD_LIBS=$LIBS
	AC_SUBST(PRELOAD_LIBS)
	LIBS=$origlibs
fi
AM_CONDITIONAL(INSTALL_PRELOAD, test x$preload_build = xyes)

dnl ================================================================
dnl == Now comes the stuff that is only for avfscoda              ==
dnl ================================================================

install_profilescripts=no
install_avfscoda=no
install_initscript=no
install_scriptlinks=no
install_codadev=no
install_fuse=no

if test $avfscoda_build = yes; then

	AC_MSG_CHECKING([kernel source directory])
	kernelsrc=
	AC_ARG_WITH(kernel,
		[  --with-kernel           Specify location of kernel source ],
		[kernelsrc="$withval"])
	
	if test -z "$kernelsrc"; then
		buildlink=/lib/modules/`uname -r`/build
		if test -e $buildlink; then
			kernelsrc=`(cd $buildlink; /bin/pwd)`
		elif test -e /usr/src/linux; then
			kernelsrc=/usr/src/linux
		else
			AC_MSG_RESULT([Not found])
			AC_MSG_ERROR([
*** Please specify the location of the kernel source with
*** the '--with-kernel=SRCDIR' option])
		fi
	fi
	AC_MSG_RESULT([$kernelsrc])
	AC_MSG_CHECKING([kernel source version])

	origlibs=$LIBS
	LIBS=""
	kernsrcver=`AC_TRY_RUN([
	#include "$kernelsrc/include/linux/version.h"
	#include <stdio.h>
	
	int main() {
	printf("%s\n", UTS_RELEASE);
		return 0;
	}
	], , , true)`
	
	if test -z "$kernsrcver"; then
		AC_MSG_RESULT([Not found])
		AC_MSG_ERROR([
*** Cannot determine the version of the linux kernel source. Please 
*** configure the kernel before running this script])
	fi
	LIBS=$origlibs
	AC_MSG_RESULT([$kernsrcver])

	KERNINCLUDE=${kernelsrc}/include
	AC_SUBST(KERNINCLUDE)

	kmoduledir=/lib/modules/${kernsrcver}/misc
	AC_SUBST(kmoduledir)

	initstyle=
	AC_MSG_CHECKING([for init-script style])
	if test -d /sbin/init.d -a -f /etc/rc.config; then
		initstyle=suse
	elif test -f /etc/rc.d/init.d/functions; then
		initstyle=redhat
        elif test -d /etc/rc2.d; then
		initstyle=debian
	else
		initstyle=generic
	fi;
	AC_MSG_RESULT([$initstyle])

	rcdir=
	rcscriptdir=
	start_levels=
	stop_levels=
	start_prio=
	stop_prio=

	install_initscript=yes

	if test "$initstyle" = redhat; then
		install_scriptlinks=yes
		rcdir=/etc/rc.d
		rcscriptdir=init.d
		start_levels="2 3 4 5"
		stop_levels="0 1 6"
		start_prio=85
		stop_prio=25
	elif test "$initstyle" = suse; then
		install_scriptlinks=yes
		rcdir=/sbin/init.d
		rcscriptdir=
		start_levels="2 3"
		stop_levels="2 3"
		start_prio=20
		stop_prio=20
	elif test "$initstyle" = debian; then
		install_scriptlinks=yes
		rcdir=/etc
		rcscriptdir=init.d
		start_levels="2 3 4 5"
		stop_levels="0 1 6"
		start_prio=85
		stop_prio=25
	else
		rcdir=/etc/rc.d
		rcscriptdir=
	fi

	AC_SUBST(initstyle)
	AC_SUBST(rcdir)
	AC_SUBST(rcscriptdir)
	AC_SUBST(start_levels)
	AC_SUBST(stop_levels)
	AC_SUBST(start_prio)
	AC_SUBST(stop_prio)

	profiledir=
        newredir=no
	if test "$newredir" = no; then
		AC_MSG_CHECKING([for profile directory])
                install_profilescripts=yes
		if test -d /etc/profile.d; then
			profiledir=/etc/profile.d
		else 
			profiledir=/etc
		fi
		AC_MSG_RESULT([$profiledir])
	fi
	AC_SUBST(profiledir)

	install_codadev=yes
	install_avfscoda=yes
fi

dnl ================================================================
dnl == Now comes the stuff for fuse                               ==
dnl ================================================================

run_fuse_test=yes
AC_ARG_ENABLE([fuse-test],
              AC_HELP_STRING([--disable-fuse-test],[Disable test for fuse version]),
              [if test "$enableval" = yes; then run_fuse_test=yes; else run_fuse_test=no; fi])

if test $fuse_build = yes; then
  if test $run_fuse_test = yes; then
    AC_MSG_CHECKING([whether fuse is new enough])

    pkg-config --atleast-version=2.6.0 fuse >/dev/null 2>/dev/null

    if test $? != 0; then
      dnl too old fuse or no fuse or no pkg-config
      dnl in any case disable fuse_build
      AC_MSG_RESULT([no])
      fuse_build=no
    else
      AC_MSG_RESULT([yes])
    fi
  fi
fi

if test $fuse_build = yes; then
    fuse_pkg_found=no
    PKG_CHECK_EXISTS([fuse],[
                     PKG_CHECK_MODULES([LIBFUSE],[fuse],
                                       [fuse_pkg_found=yes])
                     ])

    if test "$fuse_pkg_found" = "yes" -o "$run_fuse_test" = "no"; then
        AC_DEFINE(HAVE_LIBFUSE, 1, [Define to 1 if your system has libfuse installed])
        CPPFLAGS="$CPPFLAGS $LIBFUSE_CFLAGS"
        FUSELIBS="$LIBFUSE_LIBS"
        AC_SUBST(FUSELIBS)
        install_fuse=yes
        install_scriptcomps="$install_scriptcomps mountavfs umountavfs"
    else
        fuse_build=no
    fi

dnl  AC_CHECK_LIB(fuse, fuse_main,[fuse_found=yes],[fuse_found=false])
dnl  if test x$fuse_found == xyes; then
dnl    FUSELIBS="-lfuse"
dnl    AC_SUBST(FUSELIBS)
dnl    install_fuse=yes
dnl    install_scriptcomps="$install_scriptcomps mountavfs umountavfs"
dnl  else
dnl    fuse_build=no
dnl  fi
fi


dnl ================================================================
dnl == check for liblzma                                          ==
dnl ================================================================

have_liblzma=no
use_liblzma=no
AC_ARG_WITH(xz,AC_HELP_STRING([--with-xz],[use xz (default is YES, force to always enable)]),
            ac_cv_use_xz=$withval, ac_cv_use_xz=yes)
if test "$ac_cv_use_xz" = "yes" -o "$ac_cv_use_xz" = "force"; then
    PKG_CHECK_EXISTS([liblzma],[
                     PKG_CHECK_MODULES([LIBLZMA],[liblzma],
                                       [have_liblzma=yes])
                     ])

    dnl AC_MSG_CHECKING(for liblzma)
    if test "$have_liblzma" = "yes" -o "$ac_cv_use_xz" = "force"; then
        AC_DEFINE(HAVE_LIBLZMA, 1, [Define to 1 if your system has liblzma installed])
        CPPFLAGS="$CPPFLAGS $LIBLZMA_CFLAGS"
        LIBS="$LIBS $LIBLZMA_LIBS"
        use_liblzma=yes
    fi
    dnl AC_MSG_RESULT($have_liblzma)
fi


AM_CONDITIONAL(USE_LIBLZMA, test x$use_liblzma = xyes)
AM_CONDITIONAL(INSTALL_FUSE, test x$install_fuse = xyes)
AM_CONDITIONAL(INSTALL_AVFSCODA_PROFILE, test x$install_profilescripts = xyes)
AM_CONDITIONAL(INSTALL_AVFSCODA, test x$install_avfscoda = xyes)
AM_CONDITIONAL(INSTALL_INITSCRIPT, test x$install_initscript = xyes)
AM_CONDITIONAL(INSTALL_SCRIPTLINKS, test x$install_scriptlinks = xyes)
AM_CONDITIONAL(INSTALL_CODADEV, test x$install_codadev = xyes)

dnl ================================================================
dnl == Now comes the stuff that is only for shared                ==
dnl ================================================================

if test $shared_build = yes; then
	install_scriptcomps="$install_scriptcomps avfs-config"
fi
AM_CONDITIONAL(BUILD_SHARED, test x$shared_build = xyes)

dnl Test whether linker supports symbol versioning 

CHECK_LD_VERSIONSCRIPT

AC_SUBST(install_scriptcomps)
AC_SUBST(avfscoda_build)
AC_SUBST(preload_build)
AC_SUBST(shared_build)

AC_OUTPUT([
Makefile
src/Makefile
modules/Makefile
zlib/Makefile
bzlib/Makefile
lib/Makefile
include/Makefile
avfscoda/Makefile
avfscoda/redir/Makefile
preload/Makefile
libneon/Makefile
extfs/Makefile
scripts/Makefile
scripts/init/Makefile
test/Makefile
spec/Makefile
macros/Makefile
patch/Makefile
doc/Makefile
fuse/Makefile

scripts/avfs-config

extfs/a
extfs/apt
extfs/audio
extfs/deb
extfs/deba
extfs/debd
extfs/dpkg
extfs/hp48
extfs/iso9660
extfs/lslR
extfs/mailfs
extfs/patchfs
extfs/rpms
extfs/u7z
extfs/uace
extfs/uar
extfs/uarj
extfs/uc1541
extfs/uha
extfs/ulha
extfs/upp
extfs/uextrar
extfs/uxdms
extfs/uxpk
extfs/uzip
extfs/uzoo

include/version.h
], [chmod +x scripts/avfs-config])

echo ""
echo "Configuration details:"
if test "$shared_build" = "yes"; then
  echo "  Building library                          : yes (recommended: yes)"
else
  echo "  Building library                          : no  (recommended: yes)"
fi
if test "$fuse_build" = "yes"; then
  echo "  Building avfsd for fuse                   : yes (recommended: yes)"
else
  echo "  Building avfsd for fuse                   : no  (recommended: yes)"
fi
if test "$preload_build" = "yes"; then
  echo "  Building preload library                  : yes (recommended: no)"
else
  echo "  Building preload library                  : no  (recommended: no)"
fi
if test "$avfscoda_build" = "yes"; then
  echo "  Building avfscoda daemon and kernel module: yes (recommended: no)"
else
  echo "  Building avfscoda daemon and kernel module: no  (recommended: no)"
fi
echo ""
if test "x$use_system_zlib" = "xyes"; then
  echo "  Use system zlib                           : yes (recommended: no, slower access)"
else
  echo "  Use system zlib                           : no  (recommended: no)"
fi
if test "x$use_system_bzlib" = "xyes"; then
  echo "  Use system bzlib                          : yes (recommended: no, slower access)"
else
  echo "  Use system bzlib                          : no  (recommended: no)"
fi
if test "x$use_liblzma" = "xyes"; then
  echo "  Use liblzma                               : yes (recommended: yes)"
else
  echo "  Use liblzma                               : no  (recommended: yes)"
fi
echo ""
echo "  Installation prefix                       : $prefix"
echo ""
