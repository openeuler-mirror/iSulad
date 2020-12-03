%global _version 2.0.7
%global _release 20201203.191812.gitab7e0035
%global is_systemd 1

Name:      iSulad
Version:   %{_version}
Release:   %{_release}
Summary:   Lightweight Container Runtime Daemon
License:   Mulan PSL v2
URL:       https://gitee.com/openeuler/iSulad
Source:    https://gitee.com/openeuler/iSulad/repository/archive/v%{version}.tar.gz
BuildRoot: {_tmppath}/iSulad-%{version}
ExclusiveArch:  x86_64 aarch64

Patch0001: 0001-Add-a-solution-to-the-gpgkey-problem.patch
Patch0002: 0002-change-default-tmp-directory-from-var-tmp-to-var-lib.patch
Patch0003: 0003-update-api.proto-to-v1.19.3-according-to-kubelet.patch
Patch0004: 0004-adapt-CI-ISULAD_TMPDIR-testcases.patch
Patch0005: 0005-listening-127.0.0.1-port-in-cri-stream-websocket-ser.patch
Patch0006: 0006-using-64-bit-unique-token-in-CRI-websockets-server-R.patch
Patch0007: 0007-add-mock-conf_get_use_decrypted_key_flag-and-setup-a.patch
Patch0008: 0008-show-all-mutl-network-ips.patch
Patch0009: 0009-iSulad-only-qsort-the-configed-mounts.patch
Patch0010: 0010-CI-add-testcases-for-bind-proc-and-sys-fs.patch
Patch0011: 0011-verify-peer-if-it-s-secure-registry.patch
Patch0012: 0012-make-sure-all-certs-load-success-if-any-provided.patch
Patch0013: 0013-add-ch-docs-for-install-iSulad.patch
Patch0014: 0014-error-out-if-unpack-layer-failed.patch
Patch0015: 0015-ignore-get-ip-error-for-mutlnetwork.patch
Patch0016: 0016-support-default-container-log-options.patch
Patch0017: 0017-add-testcase-for-default-container-log-configs.patch


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

Requires:      lcr lxc clibcni
Requires:      grpc protobuf
Requires:      libcurl
Requires:      sqlite http-parser libseccomp
Requires:      libcap libselinux libwebsockets libarchive device-mapper
Requires:      systemd

%description
This is a umbrella project for gRPC-services based Lightweight Container
Runtime Daemon, written by C.

%prep
%autosetup -n %{name} -Sgit -p1

%build
mkdir -p build
cd build
%cmake -DDEBUG=ON -DLIB_INSTALL_DIR=%{_libdir} -DCMAKE_INSTALL_PREFIX=/usr ../
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
* Thu Dec 3 2020 haozi007 <liuhao27@huawei.com> - 2.0.7-20201203.191812.gitab7e0035
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

* Wed Nov 25 2020 lifeng68<lifeng68@huawei.com> - 2.0.7-20201125.165149.git7d150c3c
- Type: update base version to v2.0.7
- ID:NA
- SUG:NA
- DESC: 1. update with upstream version v2.0.7, release notes: https://gitee.com/openeuler/iSulad/releases/v2.0.7 2. add chrpath for isula and isulad

+* Thu Nov 12 2020  <gaohuatao@huawei.com> - 2.0.5-20201112.192302.gitedce3879
+- Type:update from openeuler
+- ID:NA
+- SUG:NA
+- DESC: update from openeuler

+* Mon Sep 14 2020  <lifeng68@huawei.com> - 2.0.5-20200914.172527.gitae86920a
+- Type:bugfix
+- ID:NA
+- SUG:NA
+- DESC: remove unused config

* Tue Sep 10 2020  <yangjiaqi11@huawei.com> - 2.0.5-20200910.144345.git71b1055b
- Type:enhancement
- ID:NA
- SUG:NA
- DESC: add chrpath

* Fri Sep 04 2020 zhangxiaoyu <zhangxiaoyu58@huawei.com> - 2.0.5-20200904.114315.gitff1761c3
- Type:enhancement
- ID:NA
- SUG:NA
- DESC: upgrade from v2.0.3 to v2.0.5
