%global _version 2.0.8
%global _release 20221018.110323.gita792f081
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

Patch1: 0001-make-thread-detach-to-avoid-resource-leak.patch
Patch2: 0002-devmapper-fix-udev-wait-thread-resource-leak.patch
Patch3: 0003-clean-code-fix-clean-code.patch
Patch4: 0004-judge-isula-load-file-exists.patch
Patch5: 0005-modify-image_load.sh-CI-to-test-file-not-exist.patch
Patch6: 0006-do-not-pause-container-when-copy.patch
Patch7: 0007-add-testcases-for-isula-cp.patch
Patch8: 0008-image_cb-rename-the-function-isula_-docker_-to-do_.patch
Patch9: 0009-fix-small-probability-of-coredump-in-CRI-streaming-s.patch
Patch10: 0010-fix-ramdom-coredump-if-pull-failed.patch
Patch11: 0011-shim-optimize-io-stream.patch
Patch12: 0012-add-CI-to-test-shim-io.patch
Patch13: 0013-CI-add-testcase-for-exec-without-pty.patch
Patch14: 0014-adapt-for-sparse-file-when-tar-file.patch
Patch15: 0015-driver-do-not-unlock-and-destroy-lock-when-clean-up.patch
Patch16: 0016-driver-do-not-set-g_graphdriver-to-NULL.patch
Patch17: 0017-ignore-error-if-get-ip-failed.patch
Patch18: 0018-GC-add-log-container-info-when-add-into-gc.patch
Patch19: 0019-log-use-the-same-function-to-init-log-in-export-paus.patch
Patch20: 0020-init-log-config-should-before-command-parse.patch
Patch21: 0021-spec-add-verify-for-device-cgroup-access-mode.patch
Patch22: 0022-log-change-log-level-from-warn-to-error.patch
Patch23: 0023-Fix-create-env-path-dir-if-dir-exist.patch
Patch24: 0024-iSulad-calculate-memusage-with-used-total_inactive_f.patch
Patch25: 0025-fix-container-exit-health-check-residue-and-multiple.patch
Patch26: 0026-CI-supplementary-testcase-for-health-check-monitor.patch
Patch27: 0027-add-container-lock-when-clean-container-resource.patch
Patch28: 0028-sleep-some-time-before-calculate-to-make-sure-fd-clo.patch
Patch29: 0029-stats-fix-wrong-memory-usage-info-in-stats.patch
Patch30: 0030-save-health-check-log-to-disk-before-unhealthy.patch
Patch31: 0031-unpack-try-to-remove-and-replace-dst_path-while-unpa.patch
Patch32: 0032-fd-leak-check-in-cp.sh-should-not-include-pull-fd-ch.patch
Patch33: 0033-devmapper-modify-log-msg.patch
Patch34: 0034-name_id_index-fix-restore-fail-to-remove-name-index.patch
Patch35: 0035-thread-function-calls-DAEMON_CLEAR_ERRORMSG-to-preve.patch
Patch36: 0036-modify-resume-task-name.patch
Patch37: 0037-cleadcode-Remove-extra-semicolons.patch
Patch38: 0038-restart-policy-add-support-unless-stopped-policy.patch
Patch39: 0039-CI-add-testcase-for-unless-stopped-restart-policy.patch
Patch40: 0040-bugfix-for-embedded-image.patch
Patch41: 0041-console-client-ignore-stdin-close-event.patch
Patch42: 0042-delete-lxc-from-runc-CI-test.patch
Patch43: 0043-add-embedded-testcases.patch
Patch44: 0044-fix-the-error-of-ContainerStats-interface-field-valu.patch
Patch45: 0045-rollback-setuped-network-if-mult-network-failed.patch
Patch46: 0046-add-testcase-for-rollback-mutlnetworks.patch
Patch47: 0047-log-adjust-log-level-from-EVENT-to-WARN-to-reduce-lo.patch
Patch48: 0048-isulad-shim-fix-shim-exit-bug.patch
Patch49: 0049-support-pull-option-when-create-run-container.patch
Patch50: 0050-add-testcase-for-pull-option.patch
Patch51: 0051-remove-redundant-code.patch
Patch52: 0052-devicemapper-umount-when-resize2fs-command-failed.patch
Patch53: 0053-support-isula-exec-workdir.patch
Patch54: 0054-add-testcase-for-isula-exec-workdir.patch
Patch55: 0055-ignore-to-create-mtab-when-runtime-is-kata-runtime.patch
Patch56: 0056-remove-unchecked-layer-ignore-rootfs-layer.patch
Patch57: 0057-add-test-to-check-running-container-with-image-integ.patch
Patch58: 0058-fix-coredump-when-inspect-container-when-daemon-sets.patch
Patch59: 0059-Readme-add-related-resouces-in-readme.patch
Patch60: 0060-update-docs-build_guide_zh.md.patch
Patch61: 0061-fix-health_check.sh-execute-failure.patch
Patch62: 0062-support-cgroup-v2.patch
Patch63: 0063-add-testcases-for-cgroup-v2.patch
Patch64: 0064-Readme-add-configure-image-registry-address.patch
Patch65: 0065-add-iSulad-experiment-in-README.patch
Patch66: 0066-CI-add-testcase-for-long-label.patch
Patch67: 0067-event-fix-memory-leak-when-pack-annotation-failed.patch
Patch68: 0068-Readme-add-script-to-install-iSulad-on-Centos7.patch
Patch69: 0069-cri-fix-residual-IO-copy-thread-in-CRI-exec-operatio.patch
Patch70: 0070-CI-add-testcase-for-cri-stream.patch
Patch71: 0071-stats-show-cpu-usage-normal-when-stats-with-no-strea.patch
Patch72: 0072-Readme-add-script-to-install-iSulad-on-Ubuntu-20.04-.patch
Patch73: 0073-update-libarchive-requirement-to-v3.4.patch
Patch74: 0074-correct-the-mistake-package-libarchive-dev.patch
Patch75: 0075-Added-autocomplete-in-isula-command-line-mode.patch
Patch76: 0076-iSulad-fix-bugs-of-isula-runtime-ops.patch
Patch77: 0077-Compatible-with-registry-URL-ending-in.patch
Patch78: 0078-CI-fix-CI-to-fit-run-on-2-cpu-4G-memory-environment.patch
Patch79: 0079-added-default-completion.patch
Patch80: 0080-fix-coredump-when-poweroff.patch
Patch81: 0081-CI-keep-container-when-build-failed-for-debug.patch
Patch82: 0082-devmapper-decrease-log-level-of-check-dm-device.patch
Patch83: 0083-fix-bugs-when-pulling-image.patch
Patch84: 0084-add-testcase-for-pulling-image.patch
Patch85: 0085-check-return-value-to-valid-use-NULL-pointer.patch
Patch86: 0086-move-reinstall_thinpool-to-helper.sh.patch
Patch87: 0087-CI-activate-vg-isulad.patch
Patch88: 0088-CI-devicemapper-add-filter.patch
Patch89: 0089-syslog-tag-support-dynamic-tag-values.patch
Patch90: 0090-add-testcase-for-contailer-log-opts.patch
Patch91: 0091-CI-run-the-containers-one-by-one.patch
Patch92: 0092-completion-isula-images.patch
Patch93: 0093-fix-memory-leak-when-pulling-image.patch
Patch94: 0094-isula-fix-help-xx-coredump.patch
Patch95: 0095-workdir-must-be-absolute-path.patch
Patch96: 0096-check-if-pull-option-is-valid.patch
Patch97: 0097-fix-memory-usage-of-stats-not-right-when-runtime-is-.patch
Patch98: 0098-log-adjust-log-level-to-reduce-log.patch
Patch99: 0099-CI-use-ali-registry-instead-of-docker.io.patch
Patch100: 0100-do-not-check-key-s-case-when-parse-http-header.patch
Patch101: 0101-CI-use-docker.io-registry.patch
Patch102: 0102-CI-fix-integration_check.sh.patch
Patch103: 0103-optimize-token-generation.patch
Patch104: 0104-fix-string-array-initialization-failure.patch
Patch105: 0105-suppress-proxy-connect-headers-message.patch

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
* Tue Oct 18 2022 huangsong <huangsong14@huawei.com> - 2.0.8-20221018.110323.gita792f081
- Type: sync from upstream
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

* Mon Dec 7 2020 zhangxiaoyu <zhangxiaoyu58@huawei.com> - 2.0.7-20201207.153005.git41c86050
- Type: update
- ID: NA
- SUG: NA
- DESC: update from master

* Sat Dec 5 2020 lifeng <lifeng68@huawei.com> - 2.0.7-20201205.145752.gita461cc51
- Type: bugfix
- ID:NA
- SUG:NA
- DESC: ignore list containers errors

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
