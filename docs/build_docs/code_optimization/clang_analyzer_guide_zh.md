## scan-build用法

```bash
# 以fedora为例
$ dnf install clang clang-analyzer
# 编译iSulad
$ cd iSulad && mkdir build && cd build
# 执行通过scan-build执行cmake
$ scan-build cmake ..
# 使用clang编译，生成的报告在scanout目录
$ scan-build --use-cc=clang --use-c++=clang++ -o ./scanout make
```

**查看scanout目录的html报告，依次分析即可。**

