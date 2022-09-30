## scan-build usage

```bash
# Take fedora as an example
$ dnf install clang clang-analyzer
# Build iSulad
$ cd iSulad && mkdir build && cd build
# Execute cmake via scan-build
$ scan-build cmake ..
# Compiled with clang, the generated report is in the scanout directory
$ scan-build --use-cc=clang --use-c++=clang++ -o ./scanout make
```

**View the html report of the scanout directory and analyze it in turn**.

