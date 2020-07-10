#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2019. All rights reserved.
# - lcr licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description: prepare compile container envrionment
##- @Author: lifeng
##- @Create: 2020-01-10
#######################################################################
# This file describes the isulad compile container image.
#
# Usage:
#
# docker build --build-arg http_proxy=YOUR_HTTP_PROXY_IF_NEEDED \
#		--build-arg https_proxy=YOUR_HTTPS_PROXY_IF_NEEDED \
#		-t YOUR_IMAGE_NAME -f ./Dockerfile .


FROM	centos:7.6.1810
MAINTAINER LiFeng <lifeng68@huawei.com>

RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf && \
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf && \
    echo "search localdomain" >> /etc/resolv.conf

# Install dependency package
RUN yum clean all && yum makecache && yum install -y epel-release && yum swap -y fakesystemd systemd && \
	yum update -y && \
	yum install -y  automake \
			autoconf \
			libtool \
			make \
			which \
			gdb \
			strace \
			rpm-build \
			graphviz \
			libcap \
			libcap-devel \
			libxslt  \
			docbook2X \
			libselinux \
			libselinux-devel \
			libseccomp \
			libseccomp-devel \
			yajl-devel \
			git \
			dnsmasq \
			libcgroup \
			rsync \
			iptables \
			iproute \
			net-tools \
			unzip \
			tar \
			wget \
			cppcheck \
			python3 \
			python3-pip \
			device-mapper-devel \
			xz-devel \
			libtar \
			libtar-devel \
			libcurl-devel \
			zlib-devel \
			glibc-headers \
			openssl-devel \
			gcc \
			gcc-c++ \
			hostname \
			sqlite-devel \
			gpgme \
			gpgme-devel \
			expect \
			systemd-devel \
			systemd-libs \
			go \
			CUnit \
			CUnit-devel \
			valgrind \
			e2fsprogs \
			lcov \
			libasan \
			lvm2

RUN yum clean all && \
    (cd /lib/systemd/system/sysinit.target.wants/; for i in *; \
    do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
    rm -f /lib/systemd/system/multi-user.target.wants/*;\
    rm -f /etc/systemd/system/*.wants/*;\
    rm -f /lib/systemd/system/local-fs.target.wants/*; \
    rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
    rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
    rm -f /lib/systemd/system/basic.target.wants/*;\
    rm -f /lib/systemd/system/anaconda.target.wants/*;

RUN echo "export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH" >> /etc/bashrc && \
    echo "export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH" >> /etc/bashrc && \
    echo "/usr/lib" >> /etc/ld.so.conf && \
    echo "/usr/local/lib" >> /etc/ld.so.conf

	
# disalbe sslverify
RUN git config --global http.sslverify false

# install cmake
RUN set -x && \
	cd ~ && \
	git clone https://gitee.com/src-openeuler/cmake.git && \
	cd cmake && \
	git checkout origin/openEuler-20.03-LTS && \
	tar -xzvf cmake-3.12.1.tar.gz && \
	cd cmake-3.12.1 && \
	./bootstrap && make && make install && \
	ldconfig

# Centos has no protobuf, protobuf-devel, grpc, grpc-devel, grpc-plugin
# and we should install them manually.
# install protobuf
RUN set -x && \
	cd ~ && \
	git clone https://gitee.com/src-openeuler/protobuf.git && \
	cd protobuf && \
	tar -xzvf protobuf-all-3.9.0.tar.gz && \
	cd protobuf-3.9.0 && \
	./autogen.sh && \
	./configure && \
	make -j $(nproc) && \
	make install && \
	ldconfig

# install c-ares
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
	set -x && \
	cd ~ && \
	git clone https://gitee.com/src-openeuler/c-ares.git && \
	cd c-ares && \
	tar -xzvf c-ares-1.15.0.tar.gz && \
	cd c-ares-1.15.0 && \
	autoreconf -if && \
	./configure --enable-shared --disable-dependency-tracking && \
	make -j $(nproc) && \
	make install && \
	ldconfig
	
# install grpc
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
	set -x && \
	cd ~ && \
	git clone https://gitee.com/src-openeuler/grpc.git && \
	cd grpc && \
	git checkout -b openEuler-20.03-LTS-tag openEuler-20.03-LTS-tag && \
	tar -xzvf grpc-1.22.0.tar.gz && \
	cd grpc-1.22.0 && \
	make -j $(nproc) && \
	make install && \
	ldconfig

# install libevent
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
	set -x && \
	cd ~ && \
	git clone https://gitee.com/src-openeuler/libevent.git && \
	cd libevent && \
	tar -xzvf libevent-2.1.11-stable.tar.gz && \
	cd libevent-2.1.11-stable && \
	./autogen.sh && \
	./configure && \
	make -j $(nproc) && \
	make install && \
	ldconfig

# install libevhtp
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
	set -x && \
	cd ~ && \
	git clone https://gitee.com/src-openeuler/libevhtp.git && \
	cd libevhtp && \
	tar -xzvf libevhtp-1.2.18.tar.gz && \
	cd libevhtp-1.2.18 && \
	patch -p1 -F1 -s < ../0001-decrease-numbers-of-fd-for-shared-pipe-mode.patch && \
	patch -p1 -F1 -s < ../0002-evhtp-enable-dynamic-thread-pool.patch && \
	patch -p1 -F1 -s < ../0003-close-open-ssl.-we-do-NOT-use-it-in-lcrd.patch && \
	patch -p1 -F1 -s < ../0004-Use-shared-library-instead-static-one.patch && \
	rm -rf build && \
	mkdir build && \
	cd build && \
	cmake -D EVHTP_BUILD_SHARED=on -D EVHTP_DISABLE_SSL=on ../ && \
	make -j $(nproc) && \
	make install && \
	ldconfig

# install http-parser
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
	set -x && \
	cd ~ && \
	git clone https://gitee.com/src-openeuler/http-parser.git && \
	cd http-parser && \
	tar -xzvf http-parser-2.9.4.tar.gz && \
	cd http-parser-2.9.4 && \
	make -j CFLAGS="-Wno-error" && \
	make CFLAGS="-Wno-error" install && \
	ldconfig

# install libwebsockets
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
	set -x && \
	cd ~ && \
	git clone https://gitee.com/src-openeuler/libwebsockets.git && \
	cd libwebsockets && \
	tar -xzvf libwebsockets-4.0.1.tar.gz && \
	cd libwebsockets-4.0.1 && \
	mkdir build && \
	cd build && \
	cmake -DLWS_WITH_SSL=0 -DLWS_MAX_SMP=32 -DCMAKE_BUILD_TYPE=Debug ../ && \
	make -j $(nproc) && \
	make install && \
	ldconfig

# install gtest/gmock
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
	set -x && \
	cd ~ && \
	git clone https://gitee.com/src-openeuler/gtest.git && \
	cd gtest && \
	tar xf release-1.8.1.tar.gz && \
	cd googletest-release-1.8.1 && \
	patch -p1 -F1 -s < ../gtest-1.8.1-null-pointer.patch && \
	patch -p1 -F1 -s < ../gtest-PR1839-Fix-Python3-support.patch && \
	patch -p1 -F1 -s < ../gtest-1.8.1-libversion.patch && \
	patch -p1 -F1 -s < ../gtest-1.8.1-add-missing-pkgconfig-requires.patch && \
	mkdir -p build && \
	cd build && \
	cmake -DBUILD_SHARED_LIBS=ON ../ && \
	make -j $(nproc) && \
	make install && \
	ldconfig

# install libarchive
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
        set -x && \
        cd ~ && \
        git clone https://gitee.com/src-openeuler/libarchive.git && \
        cd libarchive && \
        tar -zxvf libarchive-3.4.1.tar.gz && \
        cd libarchive-3.4.1 && \
        patch -p1 -F1 -s < ../libarchive-uninitialized-value.patch && \
        patch -p1 -F1 -s < ../CVE-2020-9308.patch && \
        cd build && \
        cmake -DCMAKE_USE_SYSTEM_LIBRARIES=ON ../ && \
        make -j $(nproc) && \
        make install && \
        ldconfig

VOLUME [ "/sys/fs/cgroup" ]
CMD ["/usr/sbin/init"]
