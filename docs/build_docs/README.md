[中文版入口](README_zh.md)

# Get set up for iSulad development

This section contains some guides for iSulad project users who want to contribute code to the isulad project. 

## Build guide

We provide multiple ways to build iSulad:

- If you want to build and install iSulad through rpm package, please refer to [build_guide_with_rpm](./guide/build_guide_with_rpm.md).

- If you want to build and install iSulad from suorce, please refer to [build_guide](./guide/build_guide.md).

- If you want to build iSulad from source on an openeuler-deployed risc-v machine, please refer to [build_guide_riscv](./guide/build_guide_riscv.md).

- If you want to build iSulad and install iSulad with docker image, please refer to [build_guide_with_docker_image](./guide/build_guide_with_docker_image.md).

## Test guide

Fuzz testing is an automated software testing method that injects invalid, malformed, or unexpected inputs into a system to reveal software defects and vulnerabilities. If you want to test iSulad with fuzz, please refer to [fuzz_test_guide](./test/fuzz_test_guide.md).

## Code optomization guide

The Clang Static Analyzer is a source code analysis tool that finds bugs in C, C++, and Objective-C programs. If you want to analyze iSulad by it, please refer to [clang_analyzer_guide](./code_optimization/clang_analyzer_guide.md).

Include-what-you-use is a tool for use with clang to analyze #includes in C and C++ source files. If you want to analyze iSulad by it, please refer to [include_what_you_use_guide](./code_optimization/include_what_you_use_guide.md).




