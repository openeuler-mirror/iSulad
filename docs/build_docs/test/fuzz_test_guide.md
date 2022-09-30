## Build and install fuzz dependencies

You need to install the following dependencies and configure the PATH environment variable to point to the binary directory where gclang is located:

```bash
$ yum makecache
$ yum install -y git unzip patch golang llvm clang compiler-rt libasan-static libasan
$ go env -w GO111MODULE=auto
$ go env -w GOPROXY="https://goproxy.io,direct"
$ go get -v github.com/SRI-CSL/gllvm/cmd/...
$ export PATH=/root/go/bin:$PATH
```

##  Build iSulad

```bash
# cd the iSulad root directory
$ mkdir build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON -DENABLE_FUZZ=ON ..
$ cmake -DCMAKE_BUILD_TYPE=Debug -DGCOV=ON -DENABLE_ASAN=ON -DENABLE_FUZZ=ON ..
$ make -j $(nproc)
```

##  Execute fuzz test cases

Execute all fuzz test cases:

```bash
$ cd test/fuzz/
$ ./fuzz.sh
```

Execute some fuzz test cases:

```bash
$ cd test/fuzz/
$ ./fuzz.sh test_gr_obj_parser_fuzz test_pw_obj_parser_fuzz test_volume_mount_spec_fuzz test_volume_parse_volume_fuzz
```

If the test is successful, a log will be generated in the iSulad root directory:

```bash
$ ls -la *.log
-rw-------. 1 root root 2357 Jul  4 10:23 test_gr_obj_parser_fuzz.log
-rw-------. 1 root root 3046 Jul  4 10:23 test_pw_obj_parser_fuzz.log
-rw-------. 1 root root 1167 Jul  4 10:23 test_volume_mount_spec_fuzz.log
-rw-------. 1 root root 3411 Jul  4 10:23 test_volume_parse_volume_fuzz.log
```

##  Coverage information

You can use third-party tools to collect coverage information and analyze it. For example, you can run the following command to let lcov collect cover.info, where ISULAD_SRC_PATH is filled with iSulad source code path:

```bash
$ lcov -gcov-tool /usr/bin/llvm-gcov.sh -c -d -m $ISULAD_SRC_PATH -o cover.info
```

