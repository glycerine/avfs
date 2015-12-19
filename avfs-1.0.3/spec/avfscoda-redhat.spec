%define avfs_release redhat60
%define avfs_version 0.5.2
%define kernel_version 2.2.5-15
Summary: A Virtual File System
Name: avfs
Version: %{avfs_version}
Release: %{avfs_release}
Copyright: LGPL
Group: System_Environment/Daemons
Source: http://www.inf.bme.hu/~mszeredi/avfs/avfs-%{avfs_version}.tar.gz
URL: http://www.inf.bme.hu/~mszeredi/avfs
Packager: Miklos Szeredi <miklos@szeredi.hu>
BuildRoot: /tmp/avfs
AutoReqProv: no
Requires: kernel = %{kernel_version}


%description
AVFS is a system, which enables all programs to look inside gzip, tar,
zip, ... files, without recompiling the programs or changing the
kernel.

%prep
%setup

%build
./configure --disable-debug
make

%install
rm -rf "$RPM_BUILD_ROOT"
make install_root="$RPM_BUILD_ROOT" install

%clean
rm -rf "$RPM_BUILD_ROOT"

%pre
if test "$1" -gt 1; then 
  /etc/rc.d/init.d/avfscoda stop
fi

%post
if test ! -e /overlay; then mkdir /overlay; fi
if test "$1" = 1; then
  /etc/rc.d/init.d/avfscoda start
fi

%preun
if test "$1" = 0; then
  /etc/rc.d/init.d/avfscoda stop
fi

%postun
if test "$1" -ge 1; then
  /etc/rc.d/init.d/avfscoda start
fi

%files
%doc README INSTALL.avfscoda INSTALL.preload COPYING COPYING.LIB FORMAT NEWS TODO
%dir /usr/lib/avfs
%dir /usr/lib/avfs/extfs
/usr/sbin/avfscoda
/dev/cfs0
/usr/lib/avfs/extfs/*
/lib/modules/%{kernel_version}/misc/redir.o
/etc/profile.d/avfscoda.sh
/etc/profile.d/avfscoda.csh
/etc/rc.d/init.d/avfscoda
/etc/rc.d/rc?.d/???avfscoda
