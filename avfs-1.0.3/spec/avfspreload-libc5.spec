%define libcver libc5
%define avfs_version 0.5.2
Summary: A Virtual File System
Name: avfs
Version: %{avfs_version}
Release: %{libcver}
Copyright: LGPL
Group: Libraries
Source: http://www.inf.bme.hu/~mszeredi/avfs/avfs-%{avfs_version}.tar.gz
URL: http://www.inf.bme.hu/~mszeredi/avfs
Packager: Miklos Szeredi <miklos@szeredi.hu>
BuildRoot: /tmp/avfs

%description
AVFS is a C library add-on, which enables all programs to look inside
gzip, tar, zip, ... files, without recompiling the programs or changing
the kernel.

%prep
%setup

%build
./configure --disable-debug --enable-preload
make

%install
rm -rf "$RPM_BUILD_ROOT"
make install_root="$RPM_BUILD_ROOT" install

%clean
rm -rf "$RPM_BUILD_ROOT"

%post
/sbin/ldconfig

%files
%doc README COPYING COPYING.LIB FORMAT NEWS TODO
%dir /usr/lib/avfs
/usr/lib/libavfs.so*
/usr/lib/avfs/avfs_module*
/usr/lib/avfs/extfs/*
