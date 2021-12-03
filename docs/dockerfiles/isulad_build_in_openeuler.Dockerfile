FROM openeuler-21.03:latest

RUN echo "export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH" >> /etc/bashrc && \
    echo "export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH" >> /etc/bashrc && \
    echo "/usr/lib" >> /etc/ld.so.conf && \
    echo "/usr/local/lib" >> /etc/ld.so.conf

# this is full depends of build iSulad, you can remove which you do not need.

# basic depends of build
RUN dnf install -y cmake gcc-c++ make libtool chrpath

# depends for version control
RUN dnf install -y diffutils patch git

# depends for ut of iSulad: -DENABLE_UT=ON
RUN dnf install -y gtest-devel gmock-devel

# depends for metrics of iSulad and restful connection: -DENABLE_METRICS=ON or -DENABLE_GRPC=OFF
RUN dnf install -y libevent-devel libevhtp-devel

# depends for lib-shim-v2: -DENABLE_SHIM_V2=ON
RUN dnf install -y rust rust-packaging cargo

# depends for grpc of iSulad: -DENABLE_GRPC=ON
RUN dnf install -y grpc grpc-plugins grpc-devel protobuf-devel libwebsockets libwebsockets-devel

# depends for image module and restful client of iSulad
RUN dnf install -y libcurl libcurl-devel libarchive-devel http-parser-devel

# depends for embedded image of iSulad: -DENABLE_EMBEDDED=ON
RUN dnf install -y sqlite-devel

# depends for systemd notify of iSulad: -DENABLE_SYSTEMD_NOTIFY=ON
RUN dnf install -y systemd-devel systemd

# depneds for security of iSulad
RUN dnf install -y libseccomp-devel libcap-devel libselinux-devel

# depends for json parse
RUN dnf install -y yajl-devel

# depends for device-mapper image storage of iSulad
RUN dnf install -y device-mapper-devel
