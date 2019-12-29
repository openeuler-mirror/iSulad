## Install Dependencies

```sh
$ sudo yum install -y cmake gcc-c++ systemd-devel yajl-devel libcurl libcurl-devel clibcni clibcni-devel protobuf-devel grpc-devel grpc-plugins http-parser-devel libwebsockets-devel libevhtp-devel libevent-devel lcr lxc-devel
```



## Build steps:

Run the cmds under the iSulad source directory
```sh
$ sudo mkdir build
$ sudo cd build
$ sudo cmake ..
$ sudo make
$ sudo make install
```

