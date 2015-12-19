%define avfs_version 0.9.8

Summary: A Virtual File System
Name: avfsfuse
Version: %{avfs_version}
Release: 1
License: LGPL
Group: System Environment/Daemons
URL: http://www.inf.bme.hu/~mszeredi/avfs
Source0: avfs-%{version}.tar.bz2
# Patch0: sizefix.patch

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
AVFS is a system, which enables all programs to look inside gzip, tar,
zip, ... files, without recompiling the programs or changing the
kernel. It also has capability of mounting remote directories by ftp and 
ssh, and remote documents by http. An implementation of extfs allows 
browsing of installed rpms etc.

%prep
%setup -q -n avfs-%{version}
# avfs extfs needs the size to be correct
# %patch0 -p1

%build
aclocal -I macros && autoconf && automake
./configure --enable-fuse --enable-dav --enable-libxml
make

%install
rm -rf $RPM_BUILD_ROOT
make prefix="$RPM_BUILD_ROOT/usr" install

%clean
rm -rf "$RPM_BUILD_ROOT"

%pre
if test "$1" -gt 1; then
  for t in `sed -n -e 's/avfsd \([^ ]*\).*/\1/p' /etc/mtab`; do
      /usr/bin/fusermount -u "$t"
  done
fi

%preun
if test "$1" -gt 1; then
  for t in `sed -n -e 's/avfsd \([^ ]*\).*/\1/p' /etc/mtab`; do
      /usr/bin/fusermount -u "$t"
  done
fi

%files
%defattr(-,root,root,-)
%doc README doc/README.avfs-fuse doc/INSTALL.fuse COPYING COPYING.LIB doc/FORMAT NEWS TODO
%dir /usr/lib/avfs
%dir /usr/lib/avfs/extfs
/usr/bin/avfsd
/usr/bin/avfs-config
/usr/bin/ftppass
/usr/bin/davpass
/usr/bin/mountavfs
/usr/bin/umountavfs
/usr/lib/libavfs.a
/usr/lib/libavfs.la
/usr/lib/libavfs.so
/usr/lib/libavfs.so.0
/usr/lib/libavfs.so.0.0.1
/usr/lib/avfs/extfs/*
/usr/include/avfs.h
/usr/include/virtual.h


%changelog
* Sat Feb 10 2007 Tanmoy Bhattacharya <tanmoy@mindspring.com> - 0.9.7
- Initial build.

