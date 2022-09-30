| Author | 刘昊                                    |
| ------ | ------------------------------------------ |
| Date   | 2021-03-30                                 |
| Email  | [liuhao27@huawei.com](liuhao27@huawei.com) |

# 1. Program Objectives

The CRI adapter is used to implement CRI's network functions for Pod joining, exiting, and network information acquisition; and management of network configuration files.

# 2. Overall Design

# 3. Interface Description

````c
##

​````
/*
* Description: adapter initialization, set the directory where the cni configuration file is located, and the directory list where the cni plugin is located;
* conf_dir: cni configuration file storage directory;
* bin_paths: cni plugin storage directory list;
* bin_paths_len: directory listing length;
* Return value: return 0 on success, non-zero on failure
*/
int adaptor_cni_init_confs(const char *conf_dir, const char **bin_paths, const size_t bin_paths_len);

/*
* Description: Update the cni configuration file collection;
* Return value: return 0 on success, non-zero on failure
*/
int adaptor_cni_update_confs();

/*
* Description: Check whether the adapter initialization is successful;
* Return value: return true on success, false on failure;
*/
bool adaptor_cni_check_inited();

/*
* Description: Add the pod to the network plane;
* conf: configuration parameters, including the list of added network plane names, pod id and other information;
* result: The return information of adding network operation, including network information such as ip, mac;
* Return value: return 0 on success, non-zero on failure
*/
int adaptor_cni_setup(const network_api_conf *conf, network_api_result_list *result);

/*
* Description: Exit the pod from the network plane;
* conf: configuration parameters, including the list of exited network plane names, pod id and other information;
* result: The return information of adding network operation, including network information such as ip, mac;
* Return value: return 0 on success, non-zero on failure
*/
int adaptor_cni_teardown(const network_api_conf *conf, network_api_result_list *result);

/*
* Description: Check the network plane of the pod;
* conf: configuration parameters, including check network plane name list, pod id and other information;
* result: The return information of the check network operation, including network information such as ip and mac;
* Return value: return 0 on success, non-zero on failure
*/
int adaptor_cni_check(const network_api_conf *conf, network_api_result_list *result);
​````

##
````

# 4. Detailed Design

## 4.1 update process

```mermaid
graph TD
	A(获取CNI配置文件信息列表)
	B(foreach配置)
	C{网络是否已存在}
	D(忽略当前配置)
	E(记录配置的索引到全局map)
	F(next)
	A -->B
	B -->C
	C -->|No|E
	C -->|Yes|D
	D -->F
	E -->F
	F --> B
```

## 4.2 network operation process

```mermaid
graph TD
	A(attach loop网络)
	B(操作的网络列表)
	C(foreach网络列表)
	D(执行默认网口的网络操作)
	E(准备配置)
	F(退出)
	G{是否存在}
	H{是否忽略}
	I{是否默认网口}
	J(忽略当前配置)
	K(报错退出)
	L(退出for循环)
	M(记录默认网口的网络索引)
	N(执行网络操作attach/detach)
	O(next)
	A -->B
	B -->C
	B -->D
	D -->F
	C -->E
	E -->G
	G -->|No|H
	G -->|Yes|I
	H -->|Yes|J
	H -->|No|K
	I -->|Yes|M
	I -->|No|N
	J -->E
	K -->L
	M -->O
	N -->O
	O -->E
```