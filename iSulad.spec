%global _version 1.1.5
%global _release 20200106.022952.git939935db
%global is_systemd 1
%global debug_package %{nil}

Name:      iSulad
Version:   %{_version}
Release:   %{_release}
Summary:   Lightweight Container Runtime Daemon
License:   Mulan PSL v1
URL:       lcrd
Source:    iSulad-1.0.tar.gz
BuildRoot: {_tmppath}/iSulad-%{version}
ExclusiveArch:  x86_64 aarch64

%ifarch x86_64 aarch64
Provides:       libhttpclient.so()(64bit)
Provides:       liblcrc.so()(64bit)
%endif

%if 0%{?is_systemd}
# Systemd 230 and up no longer have libsystemd-journal
BuildRequires: pkgconfig(systemd)
Requires: systemd-units
%else
Requires(post): chkconfig
Requires(preun): chkconfig
# This is for /sbin/service
Requires(preun): initscripts
%endif

BuildRequires: cmake gcc-c++ lxc lxc-devel lcr yajl yajl-devel clibcni-devel
BuildRequires: grpc grpc-devel protobuf-devel
BuildRequires: libcurl libcurl-devel sqlite-devel
BuildRequires: http-parser-devel libevhtp-devel libevent-devel
BuildRequires: libseccomp-devel libcap-devel libwebsockets libwebsockets-devel
BuildRequires: systemd-devel git

Requires:      iSulad-kit lcr lxc clibcni
Requires:      grpc protobuf yajl
Requires:      libcurl
Requires:      sqlite http-parser libseccomp
Requires:      libcap libwebsockets
Requires:      libevhtp libevent systemd

%description
This is a umbrella project for gRPC-services based Lightweight Container
Runtime Daemon, written by C.

%prep
%autosetup -c -n iSulad-%{version}

%build
mkdir -p build
cd build
%cmake -DDEBUG=OFF -DLIB_INSTALL_DIR=%{_libdir} -DCMAKE_INSTALL_PREFIX=/usr ../
%make_build

%install
rm -rf %{buildroot}
cd build
install -d $RPM_BUILD_ROOT/%{_libdir}
install -m 0644 ./src/liblcrc.so             %{buildroot}/%{_libdir}/liblcrc.so
install -m 0644 ./src/http/libhttpclient.so  %{buildroot}/%{_libdir}/libhttpclient.so

install -d $RPM_BUILD_ROOT/%{_libdir}/pkgconfig
install -m 0640 ./conf/lcrd.pc              %{buildroot}/%{_libdir}/pkgconfig/lcrd.pc

install -d $RPM_BUILD_ROOT/%{_bindir}
install -m 0755 ./src/lcrc                  %{buildroot}/%{_bindir}/lcrc
install -m 0755 ./src/lcrd                  %{buildroot}/%{_bindir}/lcrd

install -d $RPM_BUILD_ROOT/%{_includedir}/lcrd
install -m 0644 ../src/liblcrc.h                        %{buildroot}/%{_includedir}/lcrd/liblcrc.h
install -m 0644 ../src/connect/client/lcrc_connect.h    %{buildroot}/%{_includedir}/lcrd/lcrc_connect.h
install -m 0644 ../src/container_def.h                  %{buildroot}/%{_includedir}/lcrd/container_def.h
install -m 0644 ../src/types_def.h                      %{buildroot}/%{_includedir}/lcrd/types_def.h
install -m 0644 ../src/error.h                          %{buildroot}/%{_includedir}/lcrd/error.h
install -m 0644 ../src/engines/engine.h                 %{buildroot}/%{_includedir}/lcrd/engine.h

install -d $RPM_BUILD_ROOT/%{_sysconfdir}/isulad
install -m 0640 ../src/contrib/config/daemon.json           %{buildroot}/%{_sysconfdir}/isulad/daemon.json
install -m 0640 ../src/contrib/config/seccomp_default.json  %{buildroot}/%{_sysconfdir}/isulad/seccomp_default.json

install -d $RPM_BUILD_ROOT/%{_sysconfdir}/default/lcrd
install -m 0640 ../src/contrib/config/config.json           %{buildroot}/%{_sysconfdir}/default/lcrd/config.json
install -m 0640 ../src/contrib/config/systemcontainer_config.json           %{buildroot}/%{_sysconfdir}/default/lcrd/systemcontainer_config.json
install -m 0550 ../src/contrib/sysmonitor/isulad-check.sh        %{buildroot}/%{_sysconfdir}/default/lcrd/isulad-check.sh

mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/sysmonitor/process
cp ../src/contrib/sysmonitor/isulad-monit $RPM_BUILD_ROOT/etc/sysmonitor/process

install -d $RPM_BUILD_ROOT/%{_sysconfdir}/default/lcrd/hooks
install -m 0640 ../src/contrib/config/hooks/default.json %{buildroot}/%{_sysconfdir}/default/lcrd/hooks/default.json

install -d $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig
install -p -m 0640 ../src/contrib/config/iSulad.sysconfig $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/iSulad

%if 0%{?is_systemd}
install -d $RPM_BUILD_ROOT/%{_unitdir}
install -p -m 0640 ../src/contrib/init/lcrd.service $RPM_BUILD_ROOT/%{_unitdir}/lcrd.service
%else
install -d $RPM_BUILD_ROOT/%{_initddir}
install -p -m 0640 ../src/contrib/init/lcrd.init $RPM_BUILD_ROOT/%{_initddir}/lcrd.init
%endif

%clean
rm -rf %{buildroot}

%post
if ! getent group lcrd > /dev/null; then
    groupadd --system lcrd
fi

if [ "$1" = "1" ]; then
%if 0%{?is_systemd}
systemctl enable lcrd
systemctl start lcrd
%else
/sbin/chkconfig --add lcrd
%endif
elif [ "$1" = "2" ]; then
%if 0%{?is_systemd}
systemctl status lcrd | grep 'Active:' | grep 'running'
if [ $? -eq 0 ]; then
  systemctl restart lcrd
fi
%else
/sbin/service lcrd status | grep 'Active:' | grep 'running'
if [ $? -eq 0 ]; then
  /sbin/service lcrd restart
fi
%endif
fi

if ! getent group lcrd > /dev/null; then
    groupadd --system lcrd
fi

%preun
%if 0%{?is_systemd}
%systemd_preun lcrd
%else
if [ $1 -eq 0 ] ; then
    /sbin/service lcrd stop >/dev/null 2>&1
    /sbin/chkconfig --del lcrd
fi
%endif

%postun
%if 0%{?is_systemd}
%systemd_postun_with_restart lcrd
%else
if [ "$1" -ge "1" ] ; then
    /sbin/service lcrd condrestart >/dev/null 2>&1 || :
fi
%endif

%files
%attr(0600,root,root) %{_sysconfdir}/sysmonitor/process/isulad-monit
%attr(0550,root,root) %{_sysconfdir}/default/lcrd/isulad-check.sh
%defattr(0640,root,root,0750)
%{_sysconfdir}/isulad
%{_sysconfdir}/isulad/*
%{_sysconfdir}/default/*
%defattr(-,root,root,-)
%if 0%{?is_systemd}
%{_unitdir}/lcrd.service
%attr(0640,root,root) %{_unitdir}/lcrd.service
%else
%{_initddir}/lcrd.init
%attr(0640,root,root) %{_initddir}/lcrd.init
%endif
%{_includedir}/lcrd/*
%attr(0755,root,root) %{_libdir}/pkgconfig
%attr(0640,root,root) %{_libdir}/pkgconfig/lcrd.pc
%defattr(0550,root,root,0750)
%{_bindir}/*
%{_libdir}/*
%attr(0640,root,root) %{_sysconfdir}/sysconfig/iSulad
%attr(0640,root,root) %{_sysconfdir}/isulad/daemon.json

%config(noreplace,missingok) %{_sysconfdir}/sysconfig/iSulad
%config(noreplace,missingok) %{_sysconfdir}/isulad/daemon.json
%if 0%{?is_systemd}
%config(noreplace,missingok) %{_unitdir}/lcrd.service
%else
%config(noreplace,missingok) %{_initddir}/lcrd.init
%endif
