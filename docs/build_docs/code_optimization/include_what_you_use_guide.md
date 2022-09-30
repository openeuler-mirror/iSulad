| Author | 刘昊                 |
| ------ | -------------------- |
| Date   | 2022-08-11           |
| Email  | knowledgehao@163.com |

-------------

## Install

```bash
# download the code
$ git clone https://github.com/include-what-you-use/include-what-you-use.git
# according to the clang version, switch to the corresponding branch, such as clang-14
$ cd include-what-you-use
$ git checkout clang_14
# create build directory
$ mkdir build && cd build
# start build
$ cmake -G "Unix Makefiles" -DCMAKE_PREFIX_PATH=/usr/lib/llvm-7 ..
$ make -j8
# copy the generated binary to /usr/bin
$ cp bin/include-what-you-use /usr/bin/include-what-you-use
```

For more details, please refer to [Official Tutorial](https://github.com/include-what-you-use/include-what-you-use).

## Usage

Take [lcr](https://gitee.com/openeuler/lcr) for example:

```bash
$ mkdir build && cd build
# 1. use clang as the compiler;
# 2. set CMAKE_C_INCLUDE_WHAT_YOU_USE configuration;
# 3. Set CXX to DCMAKE_CXX_INCLUDE_WHAT_YOU_USE
$ CC="clang" CXX="clang++" cmake -DCMAKE_C_INCLUDE_WHAT_YOU_USE=include-what-you-use ..
# build
$ make > iwyu.log 2>&1
```

You can view the analysis report through the log file `iwyu.log`. Also, you can use the keyword `should remove` to quickly view unnecessary header files and remove them.

**Note: After deletion, you need to compile and verify**.

## Effect

The effect after optimization: [lcr](https://gitee.com/openeuler/lcr/pulls/195). This tool can be used later to optimize unnecessary header files in `iSulad`.

## Reference

- https://github.com/include-what-you-use/include-what-you-use