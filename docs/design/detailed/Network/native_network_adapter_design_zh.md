Native-adaptor主要包括config及容器网络两部分。config模块主要实现了用户对网络的管理功能，包括网络的创建、查询、删除。容器网络模块则主要是针对某个容器进行网络的创建、删除操作。

## 结构体及常量说明

```
struct subnet_scope {
    char *begin;
    char *end;
};
/* Reserved IPv4 address ranges for private networks */
const struct subnet_scope g_private_networks[] = {
    /* Class C network 192.168.0.0/16 */
    { "192.168.0.0/24", "192.168.255.0/24" },
    /* Class B network 172.16.0.0/12 */
    { "172.16.0.0/24", "172.31.255.0/24" },
    /* Class A network 10.0.0.0/8 */
    { "10.0.0.0/24", "10.255.255.0/24" },
};

typedef struct native_newtork_t {
    // network conflist
    struct cni_network_list_conf *conflist;

    // containers linked to network
    struct linked_list containers_list;

    pthread_rwlock_t rwlock;
} native_network;

typedef struct native_store_t {
    // string -> ptr(native_newtork)
    map_t *name_to_network;

    size_t network_len;

    char *conf_dir;

    char **bin_paths;
    size_t bin_paths_len;

    // do not need write lock in native_init and native_destory
    pthread_rwlock_t rwlock;
} native_store;

struct plugin_op {
    const char *plugin;
    cni_net_conf * (*op)(const network_create_request *request);
};

struct net_driver_ops {
    cni_net_conf_list * (*conf)(const network_create_request *request);
    int (*check)(const network_create_request *request);
    int (*detect)(const char **cni_bin_dir, int bin_dir_len);
    int (*remove)(cni_net_conf_list *list);
};

struct net_driver {
    const char *driver;
    const struct net_driver_ops *ops;
};
```

- g_private_networks记录了公认的私有网络段地址，用来分配创建网络的subnet
- native_store_t记录当前保存的网络信息
- plugin_op记录plugin(bridge/portmap/firewall)及其对应的operation
- net_driver_ops及net_driver记录了driver(bridge)及其对应的operation

## 对外函数接口说明

```
/*
* 说明：初始化，读取本地存储的network conflist，设置配置文件、bin文件的目录；
* conf_dir: cni配置文件存储目录；
* bin_paths: cni插件存储目录列表；
* bin_paths_len: 目录列表长度；
* 返回值：成功返回0，失败返回非0
*/
int native_init(const char *conf_dir, const char **bin_paths, const size_t bin_paths_len);

/*
* 说明：检查是否存在可用的network；
* 返回值：存在返回true，不存在返回非false
*/
bool native_ready();

/*
* 说明：销毁内存中存储的network信息；
* 返回值：无
*/
void native_destory();

/*
* 说明：将一个或多个网络加入到容器；
* conf：准备的网络、容器等信息；
* result：返回的attach结果；
* 返回值：成功返回0，失败返回非0
*/
int native_attach_networks(const network_api_conf *conf, network_api_result_list *result);

/*
* 说明：将一个或多个网络从容器中删除；
* conf：准备的网络、容器等信息；
* result：返回的detach结果；
* 返回值：成功返回0，失败返回非0
*/
int native_detach_networks(const network_api_conf *conf, network_api_result_list *result);

/*
* 说明：检查某个network是否存在；
* name：网络的名字；
* 返回值：存在返回true，不存在返回非false
*/
bool native_network_exist(const char *name);

/*
* 说明：创建一个网络；
* request：创建网络的请求；
* response：创建网络请求的返回信息；
* 返回值：成功返回0，失败返回非0
*/
int native_config_create(const network_create_request *request, network_create_response **response);

/*
* 说明：查询一个网络；
* name：查询的网络名字；
* network_json：查询到的网络json；
* 返回值：成功返回0，失败返回非0
*/
int native_config_inspect(const char *name, char **network_json);

/*
* 说明：查询所有的网络；
* filters：筛选条件；
* networks：查询到的网络信息；
* networks_len：查询到的网络数量；
* 返回值：成功返回0，失败返回非0
*/
int native_config_list(const struct filters_args *filters, network_network_info ***networks, size_t *networks_len);

/*
* 说明：删除网络；
* name：删除网络的名字；
* res_name：返回删除的网络名字；
* 返回值：成功返回0，失败返回非0
*/
int native_config_remove(const char *name, char **res_name);

/*
* 说明：将容器加入到某个网络的container list中；
* network_name：网络的名字；
* cont_id：容器的id；
* 返回值：成功返回0，失败返回非0
*/
int native_network_add_container_list(const char *network_name, const char *cont_id);
```

## 详细设计及流程

### 容器加入网络流程

1. 判断容器的网络模式是否为bridge，且容器非系统容器。如果不符合，则直接退出，不需要为容器prepare network
2. 判断容器网络是否已经启动，已经启动则直接退出
3. 校验容器网络是否合法，如果非法则退出报错
4. 准备网络命名空间
5. 准备attach网络、port端口映射数据
6. 首先为容器attach loopback设备
7. 依次为容器attach指定的网络平面，并记录结果。如果失败，则detach网络，删除网络命名空间
8. 更新容器的网络信息，端口映射信息，并落盘
9. 更新容器内的hosts、resolve.conf文件
   ![enter image description here](https://images.gitee.com/uploads/images/2021/0330/162647_d85d58af_5609952.png "屏幕截图.png")

### 容器退出网络流程

1. 判断容器的网络模式是否为bridge，且容器非系统容器。如果不符合，则直接退出，不需要为容器remove network
2. 如果容器在restart阶段，则跳过remove network阶段
3. 准备detach网络、port端口映射的数据
4. 首先为容器detach loopback设备
5. 容器detach网络平面 
6. 更新容器内的hosts、resolve.conf文件
7. 更新容器的网络信息，端口映射信息，并落盘
8. 删除容器网络命名空间
   ![enter image description here](https://images.gitee.com/uploads/images/2021/0330/162736_b4bf0266_5609952.png "屏幕截图.png")

### 网络生成流程

#### 主体流程

客户端：

1. 解析用户传入的参数
2. 对传入的参数进行校验，包括
   1. 每次只允许创建一个网络， 即最多指定一个name
   2. 若指定name，检查name长度是否超过MAX_NETWORK_NAME_LEN(128)
3. 发送请求到服务端
   服务端：
4. 对接收到的参数校验，包括
   1. 若指定name，则对name的合法性进行检查，包括name长度是否超过MAX_NETWORK_NAME_LEN，name是否匹配正则表达式^[a-zA-Z0-9][a-zA-Z0-9_.-]*$
   2. 若指定subnet或gateway，检查用户是否仅指定了gateway而未指定subnet，检查subnet及gateway的格式是否正确，及检查subnet及gateway是否匹配
5. 如果用户指定driver，则检查 driver 是否为 bridge
6. 如果用户指定name，则检查name是否与已经配置的native网络的name冲突；若未指定，则将生成的网桥名字作为网络的name。网桥name保证与已有的网络name、网桥名字以及主机上网络设备名不冲突
7. 如果用户指定subnet，则检查subnet网段与已经配置的网络subnet，以及主机的IP是否冲突；若未指定，则寻找空闲的私有网段作为subnet网段
8. 如果用户指定gateway，则将gateway IP设为用户指定的IP；若未指定，则将subnet网段中的第一个IP作为网关IP
9. 检查主机上CNI网络插件是否存在
10. 生成网络配置
11. 写网络配置文件
    ![enter image description here](https://images.gitee.com/uploads/images/2021/0330/163307_2027883d_5609952.png "屏幕截图.png")

#### 对外接口变更

命令行

```
➜  ~ isula network create --help

Usage:  isula network create [OPTIONS] [NETWORK]

Create a network

  -d, --driver       Driver to manager the network (default "bridge")
      --gateway      IPv4 or IPv6 gateway for the subnet
      --internal     Restrict external access from this network
      --subnet       Subnet in CIDR format
```

grpc 接口

```
service NetworkService {
    rpc Create(NetworkCreateRequest) returns (NetworkCreateResponse);
}

message NetworkCreateRequest {
	string name = 1;
	string driver = 2;
	string gateway = 3;
	bool internal = 4;
	string subnet = 5;
}

message NetworkCreateResponse {
	string name = 1;
	uint32 cc = 2;
	string errmsg = 3;
}
```

rest 接口

```
#define NetworkServiceCreate "/NetworkService/Create"
```

#### 生成的网络配置文件

```
➜  ~ cat /etc/cni/net.d/isulacni-isula-br0.conflist
{
    "cniVersion": "0.4.0",
    "name": "isula-br0",
    "plugins": [
        {
            "type": "bridge",
            "bridge": "isula-br0",
            "isGateway": true,
            "ipMasq": true,
            "hairpinMode": true,
            "ipam": {
                "type": "host-local",
                "routes": [
                    {
                        "dst": "0.0.0.0/0"
                    }
                ],
                "ranges": [
                    [
                        {
                            "subnet": "192.168.0.0/24",
                            "gateway": "192.168.0.1"
                        }
                    ]
                ]
            }
        },
        {
            "type": "portmap",
            "capabilities": {
                "portMappings": true
            }
        },
        {
            "type": "firewall"
        }
    ]
}
```

### 网络查询流程

#### 主体流程

客户端：

1. 解析用户传入的参数
2. 对传入的参数进行校验，包括
   1. 至少指定一个需要查询的name
   2. 若指定format，检查format是否合法
3. 发送请求到服务端
   服务端：
4. 对接收到的网络name进行校验 
5. 查询内存中对应的网络。如果存在，则将返回网络信息json。如果没有，则返回未找到。
   ![enter image description here](https://images.gitee.com/uploads/images/2021/0330/163544_0db4b1ac_5609952.png "屏幕截图.png")

#### 对外接口变更

命令行

```
isula network inspect [OPTIONS] NETWORK [NETWORK...] 
	-f, --format 	Format the output using the given go template
```

grpc 接口

```
service NetworkService {
    rpc Inspect(NetworkInspectRequest) returns (NetworkInspectResponse);
}

message NetworkInspectRequest {
	string name = 1;
}

message NetworkInspectResponse {
	string NetworkJSON = 1;
	uint32 cc = 2;
	string errmsg = 3;
}
```

rest 接口

```
#define NetworkServiceInspect "/NetworkService/Inspect"
```

### 网络罗列流程

#### 主体流程

客户端：

1. 解析用户传入的参数
2. 发送请求到服务端
   服务端：
3. 读取客户端发来的请求信息
4. 校验filter指定的condition是否合法
5. 根据用户指定的filter condition筛选出合适的网络，返回给客户端
   ![enter image description here](https://images.gitee.com/uploads/images/2021/0330/163705_15aec22a_5609952.png "屏幕截图.png")

#### 对外接口变更

命令行

```
isula network ls [OPTIONS]  
	-q, --quiet 	Only display network Names
        -f, --filter 	Filter output based on conditions provided
```

grpc 接口

```
service NetworkService {
    rpc List(NetworkListRequest) returns (NetworkListResponse);
}

message Network {
    string name = 1;
    string version = 2;
    repeated string plugins = 3;
}

message NetworkListRequest {
	map<string, string>  filters = 1;
}

message NetworkListResponse {
	repeated Network networks = 1;
	uint32 cc = 2;
	string errmsg = 3;
```

rest 接口

```
#define NetworkServiceList "/NetworkService/List"
```

### 网络删除流程

#### 主体流程

客户端：

1. 解析用户传入的参数
2. 发送请求给服务端
   服务端：
3. 校验name是否合法
4. 找到对应的网络
5. 判断是否有容器使用该网络。如果有，则不能删除该网络。
6. 删除主机上的网桥设备
7. 删除网络配置文件
8. 删除内存中的网络信息
   ![enter image description here](https://images.gitee.com/uploads/images/2021/0330/163852_30fb9316_5609952.png "屏幕截图.png")

#### 对外接口变更

命令行

```
isula network rm [OPTIONS] NETWORK [NETWORK...] 
```

grpc 接口

```
service NetworkService {
    rpc Remove(NetworkRemoveRequest) returns (NetworkRemoveResponse);
}

message NetworkRemoveRequest {
	string name = 1;
}

message NetworkRemoveResponse {
	string name = 1;
	uint32 cc = 2;
	string errmsg = 3;
}
```

rest 接口

```
#define NetworkServiceRemove "/NetworkService/Remove"
```

