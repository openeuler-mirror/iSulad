| Author | 刘昊                                       |
| ------ | ------------------------------------------ |
| Date   | 2021-02-19                                 |
| Email  | [liuhao27@huawei.com](liuhao27@huawei.com) |

# 1. Program Objectives

Native-adaptor mainly includes two parts: config and container network. The config module mainly implements the user's management functions for the network, including the creation, query, and deletion of the network. The container network module mainly performs network creation and deletion operations for a container.

# 2. Overall Design

# 3. Interface Description

## 3.1 structure and constant description

````c
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
````

- g_private_networks records the address of the recognized private network segment, which is used to assign the subnet to create the network
- native_store_t records the currently saved network information
- plugin_op records plugin (bridge/portmap/firewall) and its corresponding operation
- net_driver_ops and net_driver record the driver (bridge) and its corresponding operation

## 3.2 external functions

````c
/*
* Description: Initialize, read the locally stored network conflist, set the directory of the configuration file and bin file;
* conf_dir: cni configuration file storage directory;
* bin_paths: cni plugin storage directory list;
* bin_paths_len: directory listing length;
* Return value: return 0 on success, non-zero on failure
*/
int native_init(const char *conf_dir, const char **bin_paths, const size_t bin_paths_len);

/*
* Description: Check if there is an available network;
* Return value: Returns true if it exists, returns non-false if it does not exist
*/
bool native_ready();

/*
* Description: Destroy the network information stored in memory;
* return value: none
*/
void native_destory();

/*
* Description: Add one or more networks to the container;
* conf: prepared network, container and other information;
* result: the returned attach result;
* Return value: return 0 on success, non-zero on failure
*/
int native_attach_networks(const network_api_conf *conf, network_api_result_list *result);

/*
* Description: remove one or more networks from the container;
* conf: prepared network, container and other information;
* result: the returned detach result;
* Return value: return 0 on success, non-zero on failure
*/
int native_detach_networks(const network_api_conf *conf, network_api_result_list *result);

/*
* Description: Check whether a network exists;
* name: the name of the network;
* Return value: Returns true if it exists, returns non-false if it does not exist
*/
bool native_network_exist(const char *name);

/*
* Description: Create a network;
* request: request to create a network;
* response: the return information for creating a network request;
* Return value: return 0 on success, non-zero on failure
*/
int native_config_create(const network_create_request *request, network_create_response **response);

/*
* Description: query a network;
* name: query network name;
* network_json: the queried network json;
* Return value: return 0 on success, non-zero on failure
*/
int native_config_inspect(const char *name, char **network_json);

/*
* Description: Query all networks;
* filters: filter conditions;
* networks: the network information queried;
* networks_len: the number of queried networks;
* Return value: return 0 on success, non-zero on failure
*/
int native_config_list(const struct filters_args *filters, network_network_info ***networks, size_t *networks_len);

/*
* Description: delete network;
* name: delete the name of the network;
* res_name: Returns the deleted network name;
* Return value: return 0 on success, non-zero on failure
*/
int native_config_remove(const char *name, char **res_name);

/*
* Description: Add the container to the container list of a network;
* network_name: the name of the network;
* cont_id: the id of the container;
* Return value: return 0 on success, non-zero on failure
*/
int native_network_add_container_list(const char *network_name, const char *cont_id);

````

# 4. Detailed Design

## 4.1 container join network process

1. Determine whether the network mode of the container is bridge and the container is not a system container. If it does not meet, exit directly, no need to prepare network for the container.
2. Determine whether the container network has been started, and exit directly if it has been started.
3. Check whether the container network is legal, if it is illegal, exit and report an error.
4. Prepare the network namespace.
5. Prepare attach network, port port mapping data.
6. First attach the loopback device to the container.
7. Attach the specified network plane to the container in turn, and record the result. If it fails, detach the network, delete the network namespace.
8. Update the container's network information, port mapping information, and place it on the disk.
9. Update the hosts and resolve.conf files in the container.

![](https://images.gitee.com/uploads/images/2021/0330/162647_d85d58af_5609952.png)

## 4.2 the container exits the network process

1. Determine whether the network mode of the container is bridge and the container is not a system container. If it does not meet, exit directly, no need to remove network for the container.
2. If the container is in the restart phase, skip the remove network phase.
3. Prepare detached network and port mapping data.
4. First detach the loopback device for the container.
5. The container detaches the network plane.
6. Update the hosts and resolve.conf files in the container.
7. Update the container's network information, port mapping information, and place it on the disk.
8. Delete the container network namespace.

![](https://images.gitee.com/uploads/images/2021/0330/162736_b4bf0266_5609952.png )

## 4.3 network generation process

### main process

Client:

1. Parse the parameters passed in by the user.
2. Verify the incoming parameters, including:
   - Only one network is allowed to be created at a time, that is, at most one name can be specified.
   - If name is specified, check whether the length of name exceeds MAX_NETWORK_NAME_LEN(128).
3. Send the request to the server

Server:

4. Check the received parameters, including
   - If name is specified, check the validity of the name, including whether the length of the name exceeds MAX_NETWORK_NAME_LEN, and whether the name matches the regular expression ^[a-zA-Z0-9][a-zA-Z0-9_.-]* $.
   - If the subnet or gateway is specified, check whether the user only specifies the gateway without specifying the subnet, check whether the format of the subnet and gateway is correct, and check whether the subnet and gateway match.
5. If the user specifies a driver, check if the driver is a bridge
6. If the user specifies a name, check whether the name conflicts with the name of the configured native network; if it is not specified, the generated bridge name will be used as the name of the network. The bridge name ensures that it does not conflict with the existing network name, bridge name and network device name on the host.
7. If the user specifies a subnet, check whether the subnet network segment is in conflict with the configured network subnet and the host's IP; if it is not specified, find an idle private network segment as the subnet network segment
8. If the user specifies a gateway, set the gateway IP as the IP specified by the user; if not specified, use the first IP in the subnet network segment as the gateway IP
9. Check whether the CNI network plug-in exists on the host
10. Generate network configuration
11. Write the network configuration file

![](https://images.gitee.com/uploads/images/2021/0330/163307_2027883d_5609952.png)

### external interface changes

Command Line

````sh
➜ ~ isula network create --help

Usage: isula network create [OPTIONS] [NETWORK]

Create a network

  -d, --driver Driver to manager the network (default "bridge")
      --gateway IPv4 or IPv6 gateway for the subnet
      --internal Restrict external access from this network
      --subnet Subnet in CIDR format
````

grpc interface

````c
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
````

rest interface

````c
#define NetworkServiceCreate "/NetworkService/Create"
````

### generated network configuration file

````sh
➜ ~ cat /etc/cni/net.d/isulacni-isula-br0.conflist
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
````

## 4.4 network query process

### main process

Client:

1. Parse the parameters passed in by the user.
2. Verify the incoming parameters, including
   - Specify at least one name that needs to be queried.
   - If format is specified, check whether the format is legal.
3. Send the request to the server.

Server:

4. Verify the received network name.
5. Query the corresponding network in memory. If present, network information json will be returned. If not, return not found.

![](https://images.gitee.com/uploads/images/2021/0330/163544_0db4b1ac_5609952.png)

### external interface changes

Command Line

````sh
isula network inspect [OPTIONS] NETWORK [NETWORK...]
-f, --format Format the output using the given go template
````

grpc interface

````c
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
````

rest interface

````c
#define NetworkServiceInspect "/NetworkService/Inspect"
````

## 4.5 network listing process

### main process

Client:

1. Parse the parameters passed in by the user
2. Send the request to the server

Server:

3. Read the request information sent by the client
4. Check whether the condition specified by the filter is legal
5. Filter out the appropriate network according to the filter condition specified by the user and return it to the client

![](https://images.gitee.com/uploads/images/2021/0330/163705_15aec22a_5609952.png )

### external interface changes

Command Line

````sh
isula network ls [OPTIONS]
-q, --quiet Only display network Names
        -f, --filter Filter output based on conditions provided
````

grpc interface

````c
service NetworkService {
    rpc List(NetworkListRequest) returns (NetworkListResponse);
}

message Network {
    string name = 1;
    string version = 2;
    repeated string plugins = 3;
}

message NetworkListRequest {
map<string, string> filters = 1;
}

message NetworkListResponse {
repeated Network networks = 1;
uint32 cc = 2;
string errmsg = 3;
````

rest interface

````c
#define NetworkServiceList "/NetworkService/List"
````

## 4.6 network deletion process

### main process

Client:

1. Parse the parameters passed in by the user.
2. Send a request to the server.

Server:

3. Check whether the name is legal.
4. Find the corresponding network.
5. Determine whether any containers use the network. If there is, the network cannot be deleted.
6. Remove the bridge device on the host.
7. Delete the network configuration file.
8. Delete network information in memory.

![](https://images.gitee.com/uploads/images/2021/0330/163852_30fb9316_5609952.png)

### external interface changes

Command Line

````sh
isula network rm [OPTIONS] NETWORK [NETWORK...]
````

grpc interface

````c
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
````

rest interface

````c
#define NetworkServiceRemove "/NetworkService/Remove"
````