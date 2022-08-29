| Author | 刘昊                 |
| ------ | -------------------- |
| Date   | 2022-08-11           |
| Email  | knowledgehao@163.com |

-------------

## 安装

```bash
# 下载源码
$ git clone https://github.com/include-what-you-use/include-what-you-use.git
# 根据clang版本，切到对应分支，例如clang-14
$ cd include-what-you-use
$ git checkout clang_14
# 创建编译目录
$ mkdir build && cd build
# 执行cmake开始编译
$ cmake -G "Unix Makefiles" -DCMAKE_PREFIX_PATH=/usr/lib/llvm-7 ..
$ make -j8
# 拷贝生成的二进制到/usr/bin
$ cp bin/include-what-you-use /usr/bin/include-what-you-use
```

更详细内容可以参考，[官方教程](https://github.com/include-what-you-use/include-what-you-use)。

## 用法

以 [项目lcr](https://gitee.com/openeuler/lcr) 为例。

```bash
$ mkdir build && cd build
# 1. 使用clang作为编译器；
# 2. 设置CMAKE_C_INCLUDE_WHAT_YOU_USE配置；
# 3. CXX可以设置：DCMAKE_CXX_INCLUDE_WHAT_YOU_USE
$ CC="clang" CXX="clang++" cmake -DCMAKE_C_INCLUDE_WHAT_YOU_USE=include-what-you-use ..
# 正常编译即可
$ make > iwyu.log 2>&1
```

编译过程会生成很多分析报告，可以查看生成的日志文件 `iwyu.log`。
通过关键字 `should remove` 进行快速查看，把工具认为不需要的头文件删除即可。

**注意：可能存在误报，删除之后需要编译进行验证。**

## 效果

根据工具梳理出来的效果：[lcr优化PR](https://gitee.com/openeuler/lcr/pulls/195)。

后续可以在 `iSulad` 项目中进行分析，优化不必要的头文件。

## 参考文档

- https://github.com/include-what-you-use/include-what-you-use