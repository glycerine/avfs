# Copyright (C) 2005 Ralf Hoffmann
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
 
# See if the linker supports symbol versioning
AC_DEFUN([CHECK_LD_VERSIONSCRIPT],[
AC_MSG_CHECKING([whether the linker ($LD) supports symbol versioning])
ld_versionscript=no
if test "$ld_shlibs" = yes -a "$enable_shared" = yes; then
  if test "$with_gnu_ld" = yes; then
    if test -n "`$LD --help 2>/dev/null | grep version-script`"; then
      ld_versionscript=yes
      VERSIONSCRIPT_OPTS="-Wl,--version-script=\$(srcdir)/libavfs.map"
    fi
  else
    case $host_os in
    solaris*|sunos4*)
      if test -n "`$LD --help 2>&1 | grep "M mapfile"`"; then
        ld_versionscript=yes
        VERSIONSCRIPT_OPTS="-Wl,-M,\$(srcdir)/libavfs.map"
      fi
      ;;
    *)
      ;;
    esac
  fi
fi
AC_SUBST(VERSIONSCRIPT_OPTS)
AC_MSG_RESULT([$ld_versionscript])
])
