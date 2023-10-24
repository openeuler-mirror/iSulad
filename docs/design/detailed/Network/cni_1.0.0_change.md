# CNI接口升级背景

背景：CNI spec社区规范已升至[spec-v1.0.0](https://github.com/containernetworking/cni/blob/spec-v1.0.0/SPEC.md)，由于iSulad的网络模块实现了CNI规范，所以需要从[spec-v0.4.0](https://github.com/containernetworking/cni/blob/spec-v0.4.0/SPEC.md)版本适配升级到spec-v1.0.0版本。本文主要描述完成该升级需要做的适配。

# 功能变更
## 1. Network configuration format
### Capabilities

在plugins字段中，capabilities的取值范围存在变动，增加了ips、mac、infiniband guid、device id、aliases字段，实际需要增加的是aliases字段，其他字段iSulad已支持。

改动后相关结构体的结果如下：
```c
typedef struct {
    ...

    char **aliases;
    size_t aliases_len;

    ...
}
cni_cached_info;

typedef struct {
    ...

    char **aliases;
    size_t aliases_len;

    ...
}
cni_net_conf_runtime_config;
```
## 2. Execution Protocol
### VERSION

VERSION操作用于检查插件支持的CNI规范的版本，在spec-v1.0.0中，它增加了输入参数cniVersion，iSulad未使用VERSION功能，因此不涉及。

## 3. Execution of Network Configurations

无变更

## 4. Plugin Delegation

无变更

## 5. Result Types
### Interfaces

spec-v1.0.0删除了spec v0.4.0中interfaces的version字段，iSulad已支持。

spec-v1.0.0版本的interfaces的示例如下:
```json
"interfaces": [
    {
        "name": "cni0",
        "mac": "00:11:22:33:44:55"
    },
    {
        "name": "veth3243",
        "mac": "55:44:33:22:11:11"
    },
    {
        "name": "eth0",
        "mac": "99:88:77:66:55:44",
        "sandbox": "/var/run/netns/blue"
    }
]
```
### Error Code

spec-v1.0.0相比于spec v0.4.0增加了4，5，6，7的错误码定义，iSulad已支持。

spec-v1.0.0版本的error code的示例如下:
```json
{
  "cniVersion": "1.0.0",
  "code": 7,
  "msg": "Invalid Configuration",
  "details": "Network 192.168.0.0/31 too small to allocate from."
}
```
## 6. Other Optimizations
### Version Check

Support versions数组中需要增加"1.0.0"字符串表示支持了v1.0.0版本。

改动后的相关代码如下：
```c
#define CURR_SUPPORT_VERSION_LEN 5
const char *g_curr_support_versions[CURR_SUPPORT_VERSION_LEN] = { "0.3.0", "0.3.1", "0.4.0", CURRENT_VERSION, NULL };
```
### Plugin-finding Logic

在指定路径下查找plugin的逻辑中，提前检查plugin，如果有分隔符，比如Linux为"/"，就判断plugin非法，达到加速的目的。