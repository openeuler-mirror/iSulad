%global _version 2.1.5
%global _release 1
%global is_systemd 1
%global enable_criv1 1
%global enable_shimv2 1
%global is_embedded 1
%global cpp_std 17

Name:      iSulad
Version:   %{_version}
Release:   %{_release}
Summary:   Lightweight Container Runtime Daemon
License:   Mulan PSL v2
URL:       https://gitee.com/openeuler/iSulad
Source:    https://gitee.com/openeuler/iSulad/repository/archive/v%{version}.tar.gz
BuildRoot: {_tmppath}/iSulad-%{version}

%ifarch x86_64 aarch64
Provides:       libhttpclient.so()(64bit)
Provides:       libisula_client.so()(64bit)
Provides:       libisulad_tools.so()(64bit)
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

%if 0%{?is_embedded}
BuildRequires: sqlite-devel
Requires: sqlite
%endif

%if %{defined openeuler}
BuildRequires: gtest-devel gmock-devel
%endif

%define lcrver_lower 2.1.4-0
%define lcrver_upper 2.1.5-0

BuildRequires: libisula-devel > %{lcrver_lower} libisula-devel < %{lcrver_upper}
BuildRequires: cmake gcc-c++ yajl-devel
BuildRequires: grpc grpc-plugins grpc-devel protobuf-devel
BuildRequires: libcurl libcurl-devel libarchive-devel device-mapper-devel
BuildRequires: http-parser-devel
BuildRequires: libseccomp-devel libcap-devel libselinux-devel libwebsockets libwebsockets-devel
BuildRequires: systemd-devel git
BuildRequires: libevhtp-devel libevent-devel
%if 0%{?enable_shimv2}
BuildRequires: lib-shim-v2 lib-shim-v2-devel
%endif


Requires:      libisula > %{lcrver_lower} libisula < %{lcrver_upper}
Requires:      grpc protobuf
Requires:      libcurl
Requires:      http-parser libseccomp
Requires:      libcap libselinux libwebsockets libarchive device-mapper
Requires:      systemd
Requires:      (docker-runc or runc)
BuildRequires: libevhtp libevent
%if 0%{?enable_shimv2}
Requires:      lib-shim-v2
%endif

%description
This is a umbrella project for gRPC-services based Lightweight Container
Runtime Daemon, written by C.

%prep
%autosetup -n iSulad-v%{_version} -Sgit -p1

%build
mkdir -p build
cd build
%cmake \
    -DDEBUG=ON \
    -DCMAKE_SKIP_RPATH=TRUE \
    -DLIB_INSTALL_DIR=%{_libdir} \
    -DCMAKE_INSTALL_PREFIX=/usr \
%if 0%{?enable_criv1}
    -DENABLE_CRI_API_V1=ON \
    -DENABLE_SANDBOXER=ON \
%endif
%if 0%{?enable_shimv2}
    -DENABLE_SHIM_V2=ON \
%endif
%if %{defined openeuler}
    -DENABLE_UT=OFF \
%endif
    -DENABLE_GRPC_REMOTE_CONNECT=OFF \
    -DENABLE_GRPC=ON \
    -DCMAKE_CXX_STANDARD=%{cpp_std} \
    ../

sed -i "10 a\# undef linux" grpc/src/api/services/cri/v1alpha/api.pb.h
%if 0%{?enable_criv1}
sed -i "10 a\# undef linux" grpc/src/api/services/cri/v1/api_v1.pb.h
%endif

%make_build

%check
%if %{defined openeuler}
cd build
# registry_images_ut and volume_ut must run with root user
ctest -E "registry_images_ut|volume_ut"
%endif

%install
rm -rf %{buildroot}
cd build
install -d $RPM_BUILD_ROOT/%{_libdir}
install -m 0755 ./src/libisula_client.so             %{buildroot}/%{_libdir}/libisula_client.so
install -m 0755 ./src/utils/http/libhttpclient.so  %{buildroot}/%{_libdir}/libhttpclient.so
install -m 0755 ./src/libisulad_tools.so  %{buildroot}/%{_libdir}/libisulad_tools.so

install -d $RPM_BUILD_ROOT/%{_libdir}/pkgconfig
install -m 0640 ./conf/isulad.pc              %{buildroot}/%{_libdir}/pkgconfig/isulad.pc

install -d $RPM_BUILD_ROOT/%{_bindir}

install -m 0755 ./src/isula                  %{buildroot}/%{_bindir}/isula
install -m 0755 ./src/isulad-shim            %{buildroot}/%{_bindir}/isulad-shim

install -m 0755 ./src/isulad                 %{buildroot}/%{_bindir}/isulad

install -d $RPM_BUILD_ROOT/%{_includedir}/isulad

install -d $RPM_BUILD_ROOT/%{_sysconfdir}/isulad
install -m 0640 ../src/contrib/config/daemon.json           %{buildroot}/%{_sysconfdir}/isulad/daemon.json
install -m 0440 ../src/contrib/config/daemon_constants.json %{buildroot}/%{_sysconfdir}/isulad/daemon_constants.json
install -m 0640 ../src/contrib/config/seccomp_default.json  %{buildroot}/%{_sysconfdir}/isulad/seccomp_default.json

install -d $RPM_BUILD_ROOT/%{_sysconfdir}/default/isulad
install -m 0640 ../src/contrib/config/config.json           %{buildroot}/%{_sysconfdir}/default/isulad/config.json
install -m 0640 ../src/contrib/config/systemcontainer_config.json           %{buildroot}/%{_sysconfdir}/default/isulad/systemcontainer_config.json
install -m 0550 ../src/contrib/sysmonitor/isulad-check.sh        %{buildroot}/%{_sysconfdir}/default/isulad/isulad-check.sh

mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/sysmonitor/process
cp ../src/contrib/sysmonitor/isulad-monit $RPM_BUILD_ROOT/etc/sysmonitor/process

install -d $RPM_BUILD_ROOT/%{_sysconfdir}/default/isulad/hooks
install -m 0640 ../src/contrib/config/hooks/default.json %{buildroot}/%{_sysconfdir}/default/isulad/hooks/default.json

install -d $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig
install -p -m 0640 ../src/contrib/config/iSulad.sysconfig $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/iSulad

%if 0%{?is_systemd}
install -d $RPM_BUILD_ROOT/%{_unitdir}
install -p -m 0640 ../src/contrib/init/isulad.service $RPM_BUILD_ROOT/%{_unitdir}/isulad.service
%else
install -d $RPM_BUILD_ROOT/%{_initddir}
install -p -m 0640 ../src/contrib/init/isulad.init $RPM_BUILD_ROOT/%{_initddir}/isulad.init
%endif

%clean
rm -rf %{buildroot}

%pre
# support update from lcrd to isulad, will remove in next version
if [ "$1" = "2" ]; then
%if 0%{?is_systemd}
systemctl stop lcrd &>/dev/null
systemctl disable lcrd &>/dev/null
if [ -e %{_sysconfdir}/isulad/daemon.json ];then
    sed -i 's#/etc/default/lcrd/hooks#/etc/default/isulad/hooks#g' %{_sysconfdir}/isulad/daemon.json
fi
%else
/sbin/chkconfig --del lcrd &>/dev/null
%endif
fi

%post
if ! getent group isula > /dev/null; then
    groupadd --system isula
fi

if [ "$1" = "1" ]; then
%if 0%{?is_systemd}
systemctl enable isulad
systemctl start isulad
%else
/sbin/chkconfig --add isulad
%endif
elif [ "$1" = "2" ]; then
%if 0%{?is_systemd}
# support update from lcrd to isulad, will remove in next version
if [ -e %{_unitdir}/lcrd.service.rpmsave ]; then
    mv %{_unitdir}/lcrd.service.rpmsave %{_unitdir}/isulad.service
    sed -i 's/lcrd/isulad/g' %{_unitdir}/isulad.service
fi
# During the isulad upgrade process, the isulad service may still be running, but the service may be unavailable 
# due to configuration updates and other reasons.
# it may fail if the X package is upgraded synchronously with isulad and depends on the isulad command, 
# For example syscontianer-tools and lxcfs-tools.
# Therefore, after upgrading isulad, if the original status of isulad is running, 
# we need to restart isulad to ensure that the service is available during the upgrade process.
systemctl status isulad | grep 'Active:' | grep 'running'
if [ $? -eq 0 ]; then
  systemctl restart isulad
fi
%else
/sbin/service isulad status | grep 'Active:' | grep 'running'
if [ $? -eq 0 ]; then
  /sbin/service isulad restart
fi
%endif
fi

if ! getent group isula > /dev/null; then
    groupadd --system isula
fi

%preun
%if 0%{?is_systemd}
%systemd_preun isulad
%else
if [ $1 -eq 0 ] ; then
    /sbin/service isulad stop >/dev/null 2>&1
    /sbin/chkconfig --del isulad
fi
%endif

%postun
%if 0%{?is_systemd}
%systemd_postun_with_restart isulad
%else
if [ "$1" -ge "1" ] ; then
    /sbin/service isulad condrestart >/dev/null 2>&1 || :
fi
%endif

%files
%attr(0600,root,root) %{_sysconfdir}/sysmonitor/process/isulad-monit
%attr(0550,root,root) %{_sysconfdir}/default/isulad/isulad-check.sh
%defattr(0640,root,root,0750)
%{_sysconfdir}/isulad
%{_sysconfdir}/isulad/*
%{_sysconfdir}/default/*
%defattr(-,root,root,-)
%if 0%{?is_systemd}
%{_unitdir}/isulad.service
%attr(0640,root,root) %{_unitdir}/isulad.service
%else
%{_initddir}/isulad.init
%attr(0640,root,root) %{_initddir}/isulad.init
%endif
%attr(0755,root,root) %{_libdir}/pkgconfig
%attr(0640,root,root) %{_libdir}/pkgconfig/isulad.pc
%defattr(0755,root,root,0755)
%{_bindir}/*
%{_libdir}/*
%attr(0640,root,root) %{_sysconfdir}/sysconfig/iSulad
%attr(0640,root,root) %{_sysconfdir}/isulad/daemon.json

%config(noreplace,missingok) %{_sysconfdir}/sysconfig/iSulad
%config(noreplace,missingok) %{_sysconfdir}/isulad/daemon.json
%if 0%{?is_systemd}
%config(noreplace,missingok) %{_unitdir}/isulad.service
%else
%config(noreplace,missingok) %{_initddir}/isulad.init
%endif

%changelog
