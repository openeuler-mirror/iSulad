#  iSulad 网络模块概要设计

为了更好的完善iSulad的使用场景，Native网络支持是很重要的，常用的测试、开发场景基本都是通过客户端的方式启动容器进行的。因此，本文详细说明iSulad的Native网络设计。

## 设计思路

CRI接口中通过对CNI的封装，实现了容器网络的能力。其高度的灵活性和可拓展性，是极具借鉴意义的。那么，我们本地的Native网络是否也可以基于CNI的能力实现呢？当然是可以的。这种设计思路有很多的优势：

- 高度的灵活性和可拓展性；
- 依托开源的网络插件，极大的减少工作量；
- 对当前iSulad的架构影响降低到最小；
- 符合当前业界标准，可以更好的拓展iSulad的生态；

## 总体设计

我们把整改iSulad的网络设计划分为四个模块：

1. network api模块：提供了整个网络组件的API接口，为容器提供了网络能力（网络的创建、删除，容器加入、退出网络等等能力），通过`type`参数决定网络类型；
2. adaptor模块：提供不同的网络类型实现，当前支持`CRI`和`native`两种网络类型，分别对应CRI接口的网络实现和客户端的本地网络能力
3. cni-operator模块：封装libcni模块，为上层提供更加合理友好的网络管理接口，负责用户配置和网络配置的组合适配；
4. libcni模块：基于已有的clibcni自研项目，升级适配最新的cni 0.4.0版本，提供check、cache等新的机制和功能；

整体结构如下：

为了更好的完善iSulad的使用场景，Native网络支持是很重要的，常用的测试、开发场景基本都是通过客户端的方式启动容器进行的。因此，本文详细说明iSulad的Native网络设计。

## 设计思路

CRI接口中通过对CNI的封装，实现了容器网络的能力。其高度的灵活性和可拓展性，是极具借鉴意义的。那么，我们本地的Native网络是否也可以基于CNI的能力实现呢？当然是可以的。这种设计思路有很多的优势：

- 高度的灵活性和可拓展性；
- 依托开源的网络插件，极大的减少工作量；
- 对当前iSulad的架构影响降低到最小；
- 符合当前业界标准，可以更好的拓展iSulad的生态；

## 总体设计

整体结构如下：

![输入图片说明](https://images.gitee.com/uploads/images/2020/1228/161128_5ca842d8_5595769.png "屏幕截图.png")

序列图如下：

![输入图片说明](https://images.gitee.com/uploads/images/2021/0219/092345_561c8afa_5595769.png "屏幕截图.png")

### 代码结构目录结构

```bash
# api 头文件所在位置：
src/daemon/modules/api/network_api.h

# 网络模块代码结构如下：
src/daemon/modules/network/
├── CMakeLists.txt
├── cni_operator
│   ├── CMakeLists.txt
│   ├── cni_operate.c
│   ├── cni_operate.h
│   └── libcni
│       ├── CMakeLists.txt
│       ├── invoke
│       │   ├── CMakeLists.txt
│       │   ├── libcni_errno.c
│       │   ├── libcni_errno.h
│       │   ├── libcni_exec.c
│       │   ├── libcni_exec.h
│       │   ├── libcni_result_parse.c
│       │   └── libcni_result_parse.h
│       ├── libcni_api.c
│       ├── libcni_api.h
│       ├── libcni_cached.c
│       ├── libcni_cached.h
│       ├── libcni_conf.c
│       ├── libcni_conf.h
│       ├── libcni_result_type.c
│       └── libcni_result_type.h
├── cri
│   ├── adaptor_cri.c
│   ├── adaptor_cri.h
│   └── CMakeLists.txt
├── native
│   ├── adaptor_native.c
│   ├── adaptor_native.h
│   └── CMakeLists.txt
├── network.c
└── network_tools.h
```

### 网络模块对外接口

#### 结构体和常量说明

```
#define MAX_CONFIG_FILE_COUNT 1024

// support network type
#define NETWOKR_API_TYPE_NATIVE "native"
#define NETWOKR_API_TYPE_CRI "cri"

struct attach_net_conf {
    char *name;
    char *interface;
};

typedef struct network_api_conf_t {
    char *name;
    char *ns;
    char *pod_id;
    char *netns_path;
    char *default_interface;

    // attach network panes config
    struct {
        struct attach_net_conf **extral_nets;
        size_t extral_nets_len;
    };

    // external args;
    json_map_string_string *args;

    // extention configs: map<string, string>
    map_t *annotations;
} network_api_conf;

struct network_api_result {
    char *name;
    char *interface;

    char **ips;
    size_t ips_len;
    char *mac;
};

typedef struct network_api_result_list_t {
    struct network_api_result **items;
    size_t len;
    size_t cap;
} network_api_result_list;
```

+ 最多支持1024个CNI配置文件；
+ 支持两种网络类型：`native`和`cri`；
+ 接口入参类型：`network_api_conf`；
+ 网络操作结果类型：`network_api_result_list`和`network_api_result`；

#### 接口说明

```
1. 网络模块初始化接口；
bool network_module_init(const char *network_plugin, const char *cache_dir, const char *conf_dir, const char* bin_path);

2. 容器连接到网络平面接口；
int network_module_attach(const network_api_conf *conf, const char *type, network_api_result_list **result);

3. 网络check操作，可用于获取容器的网络配置信息；
int network_module_check(const network_api_conf *conf, const char *type, network_api_result_list **result);

4. 容器从网络平面退出接口；
int network_module_detach(const network_api_conf *conf, const char *type);

5. 网络配置生成接口；
int network_module_conf_create(const char *type, const network_create_request *request,
                               network_create_response **response);

6. 网络配置查看接口；
int network_module_conf_inspect(const char *type, const char *name, char **network_json);

7. 网络配置文件列举接口；
int network_module_conf_list(const char *type, const struct filters_args *filters, network_network_info ***networks,
                             size_t *networks_len);

8. 网络配置文件删除接口；
int network_module_conf_rm(const char *type, const char *name, char **res_name);

9. 网络模块是否就绪检查接口；
bool network_module_ready(const char *type);

10. 网络模块配置更新接口；
int network_module_update(const char *type);

11. 网络模块退出资源清理接口；
void network_module_exit();

12. 设置annotations的portmapping设置；
int network_module_insert_portmapping(const char *val, network_api_conf *conf);

13. 设置annotations的bandwith设置；
int network_module_insert_bandwith(const char *val, network_api_conf *conf);

14. 设置annotations的iprange设置；
int network_module_insert_iprange(const char *val, network_api_conf *conf);

15. 网络模块网络存在与否检查接口；
int network_module_exist(const char *type, const char *name);
```

### libcni模块

为上层提供CNI的基础能力，根据传入的CNI网络配置信息完成CNI网络的构建、删除、检查等功能。当前libcni模块已提供了`v0.3.0`版本的能力，当前迭代需要升级到`v0.4.0`，而`v0.4.0`需要支持`check`和`cache`机制。如下图红色部分标识的部分。

![输入图片说明](https://images.gitee.com/uploads/images/2020/1228/161204_2d5abaa1_5595769.png "屏幕截图.png")

## 详细设计

见各子模块的详细设计