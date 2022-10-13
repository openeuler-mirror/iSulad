- [English version](README.md)

# 上手开发iSulad

如果您想要参与iSulad的开发，可以参考以下指南。

## 自动化构建脚本

### OpenEuler

我们在代码仓中提供了spec文件：[iSulad.spec](../../iSulad.spec) , 您可以直接执行以下命令编译安装isulad的基本依赖：

```bash
 dnf builddep iSulad.spec
```
之后源码编译安装isulad：

```bash
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```
**注意：** isula与isulad之间的通信默认使用grpc，若想要使用rest进行通信，可使用如下编译选项更换：

```c
cmake -DENABLE_GRPC=OFF ../
```

### Centos

我们在代码仓中提供了在Centos7上自动化安装的脚本: [install_iSulad_on_Centos_7](./guide/script/install_iSulad_on_Centos_7.sh)，您只需要执行这个脚本就可以自动编译安装iSulad以及其依赖的组件。

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs/build_docs/guide/script
$ sudo ./install_iSulad_on_Centos_7.sh
```

### Ubuntu

我们同样在代码仓中提供了在Ubuntu上自动化安装的脚本: [install_iSulad_on_Ubuntu_20_04_LTS](./guide/script/install_iSulad_on_Ubuntu_20_04_LTS.sh)，您只需要执行这个脚本就可以自动编译安装iSulad以及其依赖的组件。

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs/build_docs/guide/script
$ sudo chmod +x ./install_iSulad_on_Ubuntu_20_04_LTS.sh
$ sudo ./install_iSulad_on_Ubuntu_20_04_LTS.sh
```

## 构建指南

我们提供了多种构建iSulad的方式：

- 如果您想要通过rpm包构建iSulad，请参考[build_guide_with_rpm](./guide/build_guide_with_rpm_zh.md)。

- 如果您想要通过源码构建iSulad，请参考[build_guide](./guide/build_guide_zh.md)。

- 如果您想要在RISC-V架构的openEuler上构建iSulad，请参考[build_guide_riscv](./guide/build_guide_riscv_zh.md)。

- 如果您想要利用镜像快速构建iSulad，请参考[build_guide_with_docker_image](./guide/build_guide_with_docker_image_zh.md)。

## 测试指南

Fuzz 是一种自动化软件测试方法，它将无效、格式错误或意外的输入注入系统以揭示软件缺陷和漏洞。如果您想要通过Fuzz测试iSulad，请参考[fuzz_test_guide](./test/fuzz_test_guide_zh.md)。

## 代码优化指南

Clang Static Analyer是一个源码分析工具，它可以发现C、C++和Objective-C程序中的bug。如果您想要通过Clang Static Analyer分析iSulad，请参考[clang_analyzer_guide](./code_optimization/clang_analyzer_guide_zh.md)。

Include-what-you-use 是一个与 clang 一起使用的工具，用于分析 C 和 C++ 源文件中的头文件。如果您想要通过 include-what-you-use 分析iSulad，请参考[include_what_you_use_guide](./code_optimization/include_what_you_use_guide_zh.md)。