%global _version 2.0.10
%global _release 8
%global is_systemd 1
%global enable_shimv2 1

Name:      iSulad
Version:   %{_version}
Release:   %{_release}
Summary:   Lightweight Container Runtime Daemon
License:   Mulan PSL v2
URL:       https://gitee.com/openeuler/iSulad
Source:    https://gitee.com/openeuler/iSulad/repository/archive/v%{version}.tar.gz
BuildRoot: {_tmppath}/iSulad-%{version}

Patch0001: 0001-add-self-def-runtime-for-shimv2.patch
Patch0002: 0002-fix-memleak-when-use-multiple-volumes-from.patch
Patch0003: 0003-Modified-the-procedure-of-running-a-pod-to-adapt-to-.patch
Patch0004: 0004-add-new-function-mock-for-ut.patch
Patch0005: 0005-delete-isulad-h-flag.patch
Patch0006: 0006-Fix-memory-leak-in-ClearCniNetwork-when-calling-get_.patch
Patch0007: 0007-fix-cri-libwebsockets-sync_close_sem-memory-leak.patch
Patch0008: 0008-fix-cpu-variant-get-error.patch
Patch0009: 0009-fix-unit-test-error-of-registry-in-armv8.patch
Patch0010: 0010-Modified-cmakelist-of-storage_layer-and-added-a-new-.patch
Patch0011: 0011-add-fuzz-build-in-CI.patch
Patch0012: 0012-print-valgrind-log.patch
Patch0013: 0013-fix-cri-version-memory-leak.patch
Patch0014: 0014-fix-undefined-reference-in-libisulad_img.so.patch
Patch0015: 0015-fix-undefined-reference-to-service_arguments_free-in.patch

%ifarch x86_64 aarch64
Provides:       libhttpclient.so()(64bit)
Provides:       libisula.so()(64bit)
Provides:       libisulad_img.so()(64bit)
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

BuildRequires: cmake gcc-c++ lxc lxc-devel lcr-devel yajl-devel clibcni-devel
BuildRequires: grpc grpc-plugins grpc-devel protobuf-devel
BuildRequires: libcurl libcurl-devel sqlite-devel libarchive-devel device-mapper-devel
BuildRequires: http-parser-devel
BuildRequires: libseccomp-devel libcap-devel libselinux-devel libwebsockets libwebsockets-devel
BuildRequires: systemd-devel git chrpath
%if 0%{?enable_shimv2}
BuildRequires: lib-shim-v2 lib-shim-v2-devel
%endif

Requires:      lcr lxc clibcni
Requires:      grpc protobuf
Requires:      libcurl
Requires:      sqlite http-parser libseccomp
Requires:      libcap libselinux libwebsockets libarchive device-mapper
Requires:      systemd
%if 0%{?enable_shimv2}
Requires:      lib-shim-v2
%endif

%description
This is a umbrella project for gRPC-services based Lightweight Container
Runtime Daemon, written by C.

%prep
%autosetup -n %{name} -Sgit -p1

%build
mkdir -p build
cd build
%if 0%{?enable_shimv2}
%cmake -DDEBUG=ON -DLIB_INSTALL_DIR=%{_libdir} -DCMAKE_INSTALL_PREFIX=/usr -DENABLE_SHIM_V2=ON ../
%else
%cmake -DDEBUG=ON -DLIB_INSTALL_DIR=%{_libdir} -DCMAKE_INSTALL_PREFIX=/usr ../
%endif
%make_build

%install
rm -rf %{buildroot}
cd build
install -d $RPM_BUILD_ROOT/%{_libdir}
install -m 0644 ./src/libisula.so             %{buildroot}/%{_libdir}/libisula.so
install -m 0644 ./src/utils/http/libhttpclient.so  %{buildroot}/%{_libdir}/libhttpclient.so
chrpath -d ./src/daemon/modules/image/libisulad_img.so
install -m 0644 ./src/daemon/modules/image/libisulad_img.so   %{buildroot}/%{_libdir}/libisulad_img.so
chmod +x %{buildroot}/%{_libdir}/libisula.so
chmod +x %{buildroot}/%{_libdir}/libhttpclient.so
chmod +x %{buildroot}/%{_libdir}/libisulad_img.so

install -d $RPM_BUILD_ROOT/%{_libdir}/pkgconfig
install -m 0640 ./conf/isulad.pc              %{buildroot}/%{_libdir}/pkgconfig/isulad.pc

install -d $RPM_BUILD_ROOT/%{_bindir}
chrpath -d ./src/isula
install -m 0755 ./src/isula                  %{buildroot}/%{_bindir}/isula
install -m 0755 ./src/isulad-shim            %{buildroot}/%{_bindir}/isulad-shim
chrpath -d ./src/isulad
install -m 0755 ./src/isulad                 %{buildroot}/%{_bindir}/isulad

install -d $RPM_BUILD_ROOT/%{_includedir}/isulad
install -m 0644 ../src/daemon/modules/api/image_api.h         %{buildroot}/%{_includedir}/isulad/image_api.h

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
systemctl stop lcrd
systemctl disable lcrd
if [ -e %{_sysconfdir}/isulad/daemon.json ];then
    sed -i 's#/etc/default/lcrd/hooks#/etc/default/isulad/hooks#g' %{_sysconfdir}/isulad/daemon.json
fi
%else
/sbin/chkconfig --del lcrd
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
systemctl status isulad | grep 'Active:' | grep 'running'
if [ $? -eq 0 ]; then
  systemctl restart isulad
else
  systemctl start isulad
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
%{_includedir}/isulad/*
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
* Thu Dec 03 2021 wangfengtu <wangfengtu@huawei.com> - 2.0.10-8
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: fix undefined reference to `service_arguments_free' in libisulad_img.so

* Thu Dec 02 2021 wangfengtu <wangfengtu@huawei.com> - 2.0.10-7
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: sync patches from upstream

* Tue Nov 23 2021 chengzeruizhi <chengzeruizhi@huawei.com> - 2.0.10-6
- Type: enhancement
- ID: NA
- SUG: NA
- DESC: modify the procedure of running a pod

* Fri Nov 19 2021 gaohuatao <gaohuatao@huawei.com> - 2.0.10-5
- Type: enhancement
- ID: NA
- SUG: NA
- DESC: sync from upstream

* Fri Nov 19 2021 wangfengtu <wangfengtu@huawei.com> - 2.0.10-4
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: fix memleak when use multiple --volumes-from

* Tue Nov 16 2021 wujing <wujing50@huawei.com> - 2.0.10-3
- Type: enhancement
- ID: NA
- SUG: NA
- DESC: add shimv2 build switch

* Tue Nov 16 2021 wujing <wujing50@huawei.com> - 2.0.10-2
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: remove build platform restrictions

* Tue Nov 09 2021 gaohuatao <gaohuatao@huawei.com> - 2.0.10-1
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: update from openeuler

* Tue Oct 19 2021 wangfengtu <wangfengtu@huawei.com> - 2.0.9-20211019.121837.gitf067b3ce
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: strip sha256 prefix when decrease hold references

* Fri Jun 25 2021 wujing <wujing50@huawei.com> - 2.0.9-20210625.165022.git5a088d9c
- Type: update to v2.0.9
- ID: NA
- SUG: NA
- DESC: update from master

* Tue May 18 2021 wangfengtu <wangfengtu@huawei.com> - 2.0.8-20210518.144540.git5288ed92
- Type: sync from upstream
- ID: NA
- SUG: NA
- DESC: update from master

* Fri Mar 26 2021 zhangxiaoyu <zhangxiaoyu58@huawei.com> - 2.0.8-20210326.094027.gitac974aa6
- Type: sync from upstream
- ID: NA
- SUG: NA
- DESC: update from master

* Tue Mar 23 2021 haozi007 <liuhao27@huawei.com> - 20210323.094917.git7e6aa593
- Type: sync from upstream
- ID: NA
- SUG: NA
- DESC: update from master

* Tue Feb 2 2021 lifeng <lifeng68@huawei.com> - 2.0.8-20210202.153251.gite082dcf3
- Type: sync from upstream
- ID: NA
- SUG: NA
- DESC: update from master

* Mon Jan 18 2021 lifeng <lifeng68@huawei.com> - 2.0.8-20210118.195254.git077e10f2
- Type: sync from upstream
- ID: NA
- SUG: NA
- DESC: update from master

* Wed Dec 30 2020 lifeng <lifeng68@huawei.com> - 2.0.8-20201230.155843.git6557a6eb
- Type: update to v2.0.8
- ID: NA
- SUG: NA
- DESC: update from master

* Mon Dec 7 2020 zhangxiaoyu <zhangxiaoyu58@huawei.com> - 2.0.7-20201207.151847.gita1fce123
- Type: update
- ID: NA
- SUG: NA
- DESC: update from master

* Sat Dec 5 2020 lifeng <lifeng68@huawei.com> - 2.0.7-20201205.145752.gita461cc51
- Type: bugfix
- ID:NA
- SUG:NA
- DESC: ignore list containers errors

* Thu Dec 3 2020 haozi007 <liuhao27@huawei.com> - 2.0.7-20201203.190902.git48f598fd
- Type:update from master
- ID:NA
- SUG:NA
- DESC: update from master

* Sat Nov 28 2020 lifeng<lifeng68@huawei.com> - 2.0.7-20201128.095506.git1e1623a5
- Type: bugfix
- ID:NA
- SUG:NA
- DESC: Mounts: only qsort the configed mounts and make possible to bind mount /proc and /sys/fs.
- related lxc PR fixed:
- 1.add check whether have /proc mounts entry, if has, skip the auto
- 2.mount cgroup before do mount entrys
- 3.pass if the mount on top of /proc and the source of the mount is a proc filesystem

* Wed Nov 25 2020  wangfengtu<wangfengtu@huawei.com> - 2.0.7-20201125.165149.git7d150c3c
- Type: bugfix
- ID:NA
- SUG:NA
- DESC: update from openeuler

* Wed Nov 25 2020  wangfengtu<wangfengtu@huawei.com> - 2.0.6-20201125.160534.git9fb5e75d
- Type: bugfix
- ID:NA
- SUG:NA
- DESC: fix rpath not work

* Thu Nov 12 2020  gaohuatao<gaohuatao@huawei.com> - 2.0.6-20201112.193005.git8a6b73c8
- Type: update from openeuler
- ID:NA
- SUG:NA
- DESC: update from openeuler

* Wed Oct 14 2020  lifeng68<lifeng68@huawei.com> - 2.0.6-20201014.152749.gitc8a43925
- Type: upgrade to v2.0.6
- ID:NA
- SUG:NA
- DESC: upgrade to v2.0.6

* Fri Sep 18 2020  <lifeng68@huawei.com> - 2.0.5-20200918.112827.git9aea9b75
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: modify log level to warn

* Mon Sep 14 2020  <lifeng68@huawei.com> - 2.0.5-20200914.172527.gitae86920a
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: remove unused config

* Thu Sep 10 2020  <yangjiaqi11@huawei.com> - 2.0.5-20200910.144345.git71b1055b
- Type:enhancement
- ID:NA
- SUG:NA
- DESC: add chrpath

* Fri Sep 04 2020 zhangxiaoyu <zhangxiaoyu58@huawei.com> - 2.0.5-20200904.114315.gitff1761c3
- Type:enhancement
- ID:NA
- SUG:NA
- DESC: upgrade from v2.0.3 to v2.0.5

* Wed Sep 02 2020 YoungJQ <yangjiaqi11@huawei.com> - 2.0.3-20200902.114727.git6d945f26
- Type:enhancement
- ID:NA
- SUG:NA
- DESC: modify source0 address
