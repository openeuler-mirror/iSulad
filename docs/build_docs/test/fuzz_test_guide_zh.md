## 安装编译fuzz用例依赖包

除了安装编译lxc/lcr/iSulad的编译依赖外，还需要安装如下依赖并配置PATH环境变量指向gclang所在二进制目录：

```bash
$ yum makecache
$ yum install -y git unzip patch golang llvm clang compiler-rt libasan-static libasan
$ go env -w GO111MODULE=auto
$ go env -w GOPROXY="https://goproxy.io,direct"
$ go get -v github.com/SRI-CSL/gllvm/cmd/...
$ export PATH=/root/go/bin:$PATH
```

##  编译iSulad

```bash
# 进入iSulad源码所在目录
$ mkdir build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON -DENABLE_FUZZ=ON ..
$ cmake -DCMAKE_BUILD_TYPE=Debug -DGCOV=ON -DENABLE_ASAN=ON -DENABLE_FUZZ=ON ..
$ make -j $(nproc)
```

##  执行fuzz用例

执行所有的fuzz用例：

```bash
$ cd test/fuzz/
$ ./fuzz.sh
```

执行部分fuzz用例：

```bash
$ cd test/fuzz/
$ ./fuzz.sh test_gr_obj_parser_fuzz test_pw_obj_parser_fuzz test_volume_mount_spec_fuzz test_volume_parse_volume_fuzz
```

用例执行成功会在iSulad根目录生成执行过程的日志

```bash
$ ls -la *.log
-rw-------. 1 root root 2357 Jul  4 10:23 test_gr_obj_parser_fuzz.log
-rw-------. 1 root root 3046 Jul  4 10:23 test_pw_obj_parser_fuzz.log
-rw-------. 1 root root 1167 Jul  4 10:23 test_volume_mount_spec_fuzz.log
-rw-------. 1 root root 3411 Jul  4 10:23 test_volume_parse_volume_fuzz.log
```

##  覆盖率信息

可以使用第三方工具收集覆盖率信息并进行分析，例如使用lcov收集cover.info覆盖率信息，其中ISULAD_SRC_PATH填写iSulad源代码路径：

```bash
$ lcov -gcov-tool /usr/bin/llvm-gcov.sh -c -d -m $ISULAD_SRC_PATH -o cover.info
```