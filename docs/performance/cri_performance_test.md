## Machine configuration

ARM machine:

| Configuration | Information                            |
| ------------- | -------------------------------------- |
| OS            | openEuler 22.03-LTS                    |
| Kernel        | linux 5.10.0-136.12.0.86.oe2203.aarch64 |
| CPU           | 96 cores                               |
| Memory        | 128 GB                                 |

## Version of Softwares

| Name   | Version                                                      |
| ------ | ------------------------------------------------------------ |
| iSulad | Version: 2.1.5 , Git commit:  5ebca976dd591a5676527be1bde950e5ce93eac0 |
| containerd | Version: v2.0.0-beta.2, Git commit: 290194fe77d48521d3ea78ec02e2e406c4bf91b6 |
| crio | version: 1.30.0, Git commit: b43e0d63a8af3277dbfc555f62d07bb2305a72c7 |

## Test tool

tools/benchmark/cri_perf_test.sh

## Compare with other container engines

### run operator once

#### ARM

run 1 pod and 1 container

|  measure | iSulad | containerd | crio | vs containerd | vs crio |
| ----------------- | ------ | ------ | ------ | ------ | ------ |
| time(ms)          | 580     | 812     | 567     | -28.5%  | 2.3%    |
| engine mem(kb)    | 38704   | 66806   | 58760   | -42.0%  | -34.2%  |
| shim mem(kb)      | 1700    | 13876   | 4648    | -87.7%  | -63.4%  |

run 10 pods and 10 containers

|  measure | iSulad | containerd | crio | vs containerd | vs crio |
| ----------------- | ------ | ------ | ------ | ------ | ------ |
| time(ms)          | 1141   | 4000   | 1749   | -71.5% | -34.8%  |
| engine mem(kb)    | 47688  | 82580  | 86128  | -42.2% | -44.6%  |
| shim mem(kb)      | 16764  | 154872 | 46836  | -89.2% | -64.2%  |

run 50 pods and 50 containers

|  measure | iSulad | containerd | crio | vs containerd | vs crio |
| ----------------- | ------ | ------ | ------ | ------ | ------ |
| time(ms)          | 4544   | 19963  | 8503   | -77.2% | -46.9%  |
| engine mem(kb)    | 88700  | 134384 | 115560 | -34.0% | -23.2%  |
| shim mem(kb)      | 83892  | 750924 | 233480 | -88.8% | -64.0%  |

run 100 pods and 100 containers

|  measure | iSulad | containerd | crio | vs containerd | vs crio |
| ----------------- | ------ | ------ | ------ | ------ | ------ |
| time(ms)          | 10012  | 39629  | 18278  | -74.7% | -45.5%  |
| engine mem(kb)    | 148464 | 185700 | 147836 | -20.0% | 0.4%    |
| shim mem(kb)      | 168420 | 1506268| 462000 | -88.8% | -63.3%  |
