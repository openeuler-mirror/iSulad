%global _version 2.0.13
%global _release 5
%global is_systemd 1
%global enable_shimv2 1
%global is_embedded 1

Name:      iSulad
Version:   %{_version}
Release:   %{_release}
Summary:   Lightweight Container Runtime Daemon
License:   Mulan PSL v2
URL:       https://gitee.com/openeuler/iSulad
Source:    https://gitee.com/openeuler/iSulad/repository/archive/v%{version}.tar.gz
BuildRoot: {_tmppath}/iSulad-%{version}

Patch0001:  0001-cleancode-http-request.patch
Patch0002:  0002-refactor-mount-parse-in-spec-module.patch
Patch0003:  0003-support-isula-wait-even-if-it-s-not-oci-image.patch
Patch0004:  0004-add-isula-import-restful-mode.patch
Patch0005:  0005-Adapt-to-bionic-libc-parser-for-passwd-and-group-obj.patch
Patch0006:  0006-test-adapt-to-the-enabled-selinux-host-environment.patch
Patch0007:  0007-Adapt-to-bionic-libc-improve-lcov-coverage.patch
Patch0008:  0008-fix-cmd-isulad-shim-module-encoding-problem.patch
Patch0009:  0009-fix-utils-module-encoding-problem.patch
Patch0010:  0010-clean-the-gRPC-client-module-code.patch
Patch0011:  0011-remove-redundant-code.patch
Patch0012:  0012-fix-coding-irregularities-of-entry-module.patch
Patch0013:  0013-fix-coding-irregularities.patch
Patch0014:  0014-fix-ut-bug-and-arguments-check.patch
Patch0015:  0015-refactor-util_getgrent_r-and-util_getpwent_r.patch
Patch0016:  0016-add-check-result-argument-ut.patch

%ifarch x86_64 aarch64
Provides:       libhttpclient.so()(64bit)
Provides:       libisula.so()(64bit)
Provides:       libisulad_img.so()(64bit)
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

%define lcrver 2.0.7
%define clibcniver 2.0.7


BuildRequires: lcr-devel >= %{lcrver} clibcni-devel >= %{clibcniver}
BuildRequires: cmake gcc-c++ yajl-devel lxc lxc-devel
BuildRequires: grpc grpc-plugins grpc-devel protobuf-devel
BuildRequires: libcurl libcurl-devel libarchive-devel device-mapper-devel
BuildRequires: http-parser-devel
BuildRequires: libseccomp-devel libcap-devel libselinux-devel libwebsockets libwebsockets-devel
BuildRequires: systemd-devel git chrpath
%if 0%{?enable_shimv2}
BuildRequires: lib-shim-v2 lib-shim-v2-devel
%endif


Requires:      clibcni >= %{clibcniver} lcr >= %{lcrver}
Requires:      grpc protobuf lxc
Requires:      libcurl
Requires:      http-parser libseccomp
Requires:      libcap libselinux libwebsockets libarchive device-mapper
Requires:      systemd
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
chrpath -d ./src/libisulad_tools.so
install -m 0644 ./src/libisulad_tools.so  %{buildroot}/%{_libdir}/libisulad_tools.so
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
* Mon May 16 2022 haozi007<liuhao27@huawei.com> - 2.0.13-5
- Type: enhancement
- ID: NA
- SUG: NA
- DESC: sync from upstream openEuler/iSulad

* Tue May 10 2022 hejunjie<hejunjie10@huawei.com> - 2.0.13-4
- Type: enhancement
- ID: NA
- SUG: NA
- DESC: bionic adaptation, increase lcov coverage

* Thu May 5 2022 hejunjie<hejunjie10@huawei.com> - 2.0.13-3
- Type: enhancement
- ID: NA
- SUG: NA
- DESC: bionic adaptation for pwgr obj parser

* Mon Apr 25 2022 zhangxiaoyu <zhangxiaoyu58@huawei.com> - 2.0.13-2
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: sync from upstream

* Mon Apr 18 2022 wangfengtu <wangfengtu@huawei.com> - 2.0.13-1
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: update version to v2.0.13

* Fri Mar 25 2022 wangfengtu <wangfengtu@huawei.com> - 2.0.12-1
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: update version to v2.0.12

* Thu Mar 17 2022 haozi007 <liuhao27@huawei.com> - 2.0.11-6
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: remove unnecessary error message

* Thu Mar 17 2022 wangfengtu <wangfengtu@huawei.com> - 2.0.11-5
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: fix uid/gid error when load image

* Wed Mar 09 2022 wangfengtu <wangfengtu@huawei.com> - 2.0.11-4
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: add provides of libisulad_tools.so

* Thu Mar 03 2022 wangfengtu <wangfengtu@huawei.com> - 2.0.11-3
- Type: enhancement
- ID: NA
- SUG: NA
- DESC: Add the function of isolating the user namespaces

* Thu Mar 03 2022 wangfengtu <wangfengtu@huawei.com> - 2.0.11-2
- Type: enhancement
- ID: NA
- SUG: NA
- DESC: add libisulad_tools.so

* Thu Feb 24 2022 wangfengtu <wangfengtu@huawei.com> - 2.0.11-1
- Type: enhancement
- ID: NA
- SUG: NA
- DESC: update version to v2.0.11

* Wed Jan 12 2022 wangfengtu <wangfengtu@huawei.com> - 2.0.10-15
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: fix compile error of isula-transform

* Wed Jan 12 2022 zhangxiaoyu <zhangxiaoyu58@huawei.com> - 2.0.10-14
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: fix compile error with grpc 1.41.x

* Tue Jan 4 2022 wangfengtu <wangfengtu@huawei.com> - 2.0.10-13
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: fix compile error when building embedded image

* Mon Dec 27 2021 wangfengtu <wangfengtu@huawei.com> - 2.0.10-12
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: sync patches from upstream

* Thu Dec 09 2021 chengzeruizhi <chengzeruizhi@huawei.com> - 2.0.10-11
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: fixed a bug that occurs when starting a container in host mode

* Thu Dec 09 2021 wangfengtu <wagnfengtu@huawei.com> - 2.0.10-10
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: remove dependance of sqlite

* Mon Dec 06 2021 gaohuatao <gaohuatao@huawei.com> - 2.0.10-9
- Type: bugfix
- ID: NA
- SUG: NA
- DESC: specify version

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
