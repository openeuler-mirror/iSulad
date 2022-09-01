## Machine configuration

X86 machine:

| Configuration | Information                                          |
| ------------- | ---------------------------------------------------- |
| OS            | openEuler 22.03-LTS                                  |
| Kernel        | linux 5.10.0-60.18.0.50.oe2203.x86_64                |
| CPU           | 104 cores，Intel(R) Xeon(R) Gold 6278C CPU @ 2.60GHz |
| Memory        | 754 GB                                               |

ARM machine:

| Configuration | Information                            |
| ------------- | -------------------------------------- |
| OS            | openEuler 22.03-LTS                    |
| Kernel        | linux 5.10.0-60.18.0.50.oe2203.aarch64 |
| CPU           | 64 cores                               |
| Memory        | 196 GB                                 |

## Version of Softwares

| Name   | Version                                                      |
| ------ | ------------------------------------------------------------ |
| iSulad | Version:	2.0.12 , Git commit:  9025c4b831b3c8240297f52352dec64368aa4f08 |
| docker | Version:    18.09.0, Git commit:   aa1eee8                   |
| podman | version 0.10.1                                               |

## Test tool

Power by [ptcr](https://gitee.com/openeuler/ptcr)

## Compare with other container engines

### run operator once

#### X86

base operators of client

| operator (ms) | Docker | Podman | iSulad | vs Docker | vs Podman |
| ------------- | ------ | ------ | ------ | --------- | --------- |
| create        | 29     | 49     | 19     | -34.48%   | -61.22%   |
| start         | 193    | 158    | 51     | -73.58%   | -67.72%   |
| stop          | 21     | 25     | 14     | -33.33%   | -44.00%   |
| rm            | 22     | 101    | 14     | -36.36%   | -86.14%   |
| run           | 184    | 164    | 54     | -70.65%   | -67.07%   |

#### ARM

base operators of client

| operator (ms) | Docker | Podman | iSulad | vs Docker | vs Podman |
| ------------- | ------ | ------ | ------ | --------- | --------- |
| create        | 334    | 380    | 101    | -69.76%   | -73.42%   |
| start         | 1087   | 636    | 103    | -90.52%   | -83.81%   |
| stop          | 49     | 108    | 38     | -22.45%   | -64.81%   |
| rm            | 92     | 573    | 39     | -57.61%   | -93.19%   |
| run           | 1059   | 761    | 192    | -81.87%   | -74.77%   |

### parallel to run operator 100 times

#### X86

base operator of client

| operator (ms) | Docker | Podman  | iSulad | vs Docker | vs Podman |
| ------------- | ------ | ------- | ------ | --------- | --------- |
| 100 * create  | 32307  | 1078391 | 8558   | -73.51%   | -99.21%   |
| 100 * start   | 610723 | 472437  | 42204  | -93.06%   | -91.07%   |
| 100 * stop    | 16951  | 25663   | 6438   | -62.02%   | -74.91%   |
| 100 * rm      | 17962  | 377677  | 6299   | -64.93%   | -98.33%   |
| 100 * run     | 316828 | 466688  | 43269  | -86.34%   | -90.73%   |

#### ARM

base operator of client

| operator (ms) | Docker  | Podman  | iSulad | vs Docker | vs Podman |
| ------------- | ------- | ------- | ------ | --------- | --------- |
| 100 * create  | 681423  | 3365343 | 67568  | -90.08%   | -97.99%   |
| 100 * start   | 3012528 | 2347719 | 98737  | -96.72%   | -95.79%   |
| 100 * stop    | 26973   | 358485  | 17423  | -35.41%   | -95.14%   |
| 100 * rm      | 60899   | 3469354 | 17742  | -70.87%   | -99.49%   |
| 100 * run     | 2626248 | 3083552 | 129860 | -95.06%   | -95.79%   |


## origin data

### configs

#### searially

```bash
$ cat ptcr.yml
log_lever       : 3
image_name      : rnd-dockerhub.huawei.com/official/busybox-aarch64
mixed_cmd       : 0

measure_count   :
        serially : 10
        parallerlly : 0

runtime_names :
        - isula
        - docker
        - podman

runtime_endpoint:
        #- unix:///var/run/isulad.sock
start_cmd :
        - /bin/sh
        - -c
        - while true; do echo hello world; sleep 1; done
```

#### parallerlly

```bash
$ cat ptcr.yml
log_lever       : 3
image_name      : rnd-dockerhub.huawei.com/official/busybox-aarch64
mixed_cmd       : 0

measure_count   :
        serially : 0
        parallerlly : 100

runtime_names :
        - isula
        - docker
        - podman

runtime_endpoint:
        #- unix:///var/run/isulad.sock
start_cmd :
        - /bin/sh
        - -c
        - while true; do echo hello world; sleep 1; done

```

### arm

#### searially test

```bash
$ ptcr -c ptcr.yml
Thu Mar 31 10:29:53 2022
unit: msec
------------------------------------------------------------------
TargetName:isula	Type: searially
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|10		|998			|101
Start	|10		|1039			|103
Stop	|10		|378			|38
Remove	|10		|398			|39
Run	|10		|1915			|192
------------------------------------------------------------------
TargetName:docker	Type: searially
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|10		|3336			|334
Start	|10		|10617			|1087
Stop	|10		|494			|49
Remove	|10		|935			|92
Run	|10		|10596			|1059
------------------------------------------------------------------
TargetName:podman	Type: searially
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|10		|3791			|380
Start	|10		|6332			|636
Stop	|10		|1100			|108
Remove	|10		|5749			|573
Run	|10		|7536			|761
------------------------------------------------------------------
```


#### parallerlly test

```bash
$ ptcr -c ptcr.yml
Thu Mar 31 11:02:49 2022
unit: msec
------------------------------------------------------------------
TargetName:isula	Type: parallerlly
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|100		|67568			|677
Start	|100		|98737			|982
Stop	|100		|17423			|173
Remove	|100		|17742			|177
Run	|100		|129860			|1299
------------------------------------------------------------------
TargetName:docker	Type: parallerlly
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|100		|681423			|6816
Start	|100		|3012528			|30122
Stop	|100		|26973			|267
Remove	|100		|60899			|611
Run	|100		|2626248			|26356
------------------------------------------------------------------
TargetName:podman	Type: parallerlly
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|100		|3365343			|33777
Start	|100		|2347719			|23483
Stop	|100		|358485			|3591
Remove	|100		|3469354			|34805
Run	|100		|3083552			|30855
------------------------------------------------------------------
```

### X86

#### searially test

```bash
$ ptcr -c ptcr.yml
Thu Mar 31 14:47:48 2022
unit: msec
------------------------------------------------------------------
TargetName:isula	Type: searially
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|10		|194			|19
Start	|10		|509			|51
Stop	|10		|143			|14
Remove	|10		|148			|14
Run	|10		|549			|54
------------------------------------------------------------------
TargetName:docker	Type: searially
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|10		|290			|29
Start	|10		|1963			|193
Stop	|10		|209			|21
Remove	|10		|226			|22
Run	|10		|1850			|184
------------------------------------------------------------------
TargetName:podman	Type: searially
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|10		|494			|49
Start	|10		|1590			|158
Stop	|10		|254			|25
Remove	|10		|1020			|101
Run	|10		|1648			|164
------------------------------------------------------------------
```

#### parallerlly test

```bash
$ ptcr -c ptcr.yml
Thu Mar 31 15:09:12 2022
unit: msec
------------------------------------------------------------------
TargetName:isula	Type: parallerlly
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|100		|8558			|85
Start	|100		|42204			|422
Stop	|100		|6438			|64
Remove	|100		|6299			|63
Run	|100		|43269			|432
------------------------------------------------------------------
TargetName:docker	Type: parallerlly
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|100		|32307			|323
Start	|100		|610723			|6107
Stop	|100		|16951			|169
Remove	|100		|17962			|180
Run	|100		|316828			|3170
------------------------------------------------------------------
TargetName:podman	Type: parallerlly
------------------------------------------------------------------
action	|count		|total spent		|average spent
Create	|100		|1078391			|10836
Start	|100		|472437			|4726
Stop	|100		|25663			|256
Remove	|100		|377677			|3783
Run	|100		|466688			|4670
------------------------------------------------------------------
```