dnl MC_EXTFS_CHECKS
dnl    Check for tools used in extfs scripts.
dnl Macro is from the mc-4.6.1pre1 distribution
AC_DEFUN([MC_EXTFS_CHECKS], [
    AC_PATH_PROG([ZIP], [zip], [/usr/bin/zip])
    AC_PATH_PROG([UNZIP], [unzip], [/usr/bin/unzip])
    AC_CACHE_CHECK([for zipinfo code in unzip], [mc_cv_have_zipinfo],
	[mc_cv_have_zipinfo=no
	if $UNZIP -Z </dev/null >/dev/null 2>&1; then
	    mc_cv_have_zipinfo=yes
	fi])
    if test "x$mc_cv_have_zipinfo" = xyes; then
	HAVE_ZIPINFO=1
    else
	HAVE_ZIPINFO=0
    fi
    AC_SUBST([HAVE_ZIPINFO])
    AC_PATH_PROG([PERL], [perl], [/usr/bin/perl])
])
