| Author | 高华涛     |
| ------ | ---------- |
| Date   | 2021-01-22 |
| Email  | -          |

# 1. Program Objectives

The cni-operator module encapsulates the libcni module, provides a more reasonable and friendly network management interface for generation, and is responsible for loading and updating network configuration files.

# 2. Overall Design

# 3. Interface Description

````c
/*
* Description: Network management module initialization: Initialize libcni network module and network management layer data;;
* cache_dir: Network cache configuration file storage directory;
* conf_path: cni configuration file storage directory;
* bin_paths: cni plugin storage directory list;
* bin_paths_len: directory listing length;
* Return value: return 0 on success, non-zero on failure
*/
int cni_manager_store_init(const char *cache_dir, const char *conf_path, const char * const *bin_paths, size_t bin_paths_len);

/*
* Description: According to the filtering rules, load the cni configuration file to the memory;
* store: cni configuration list;
* res_len: length of cni configuration list;
* filter_ops: Customize the cni configuration loading rules, and load the configuration files that meet the rules;
* Return value: return 0 on success, non-zero on failure
*/
int get_net_conflist_from_dir(struct cni_network_list_conf ***store, size_t *res_len, cni_conf_filter_t filter_ops);

/*
* Description: Create a container loopback network
* id: container id;
* netns: container network namespace;
* Return value: return 0 on success, non-zero on failure
*/
int attach_loopback(const char *id, const char *netns);

/*
* Description: delete the container loopback network
* id: container id;
* netns: container network namespace;
* Return value: return 0 on success, non-zero on failure
*/
int detach_loopback(const char *id, const char *netns);

/*
* Description: Create a container single network plane;
* manager: The set of parameters required for container network creation;
* list: network configuration;
* result: record necessary network information;
* Return value: return 0 on success, non-zero on failure
*/
int attach_network_plane(const struct cni_manager *manager, const struct cni_network_list_conf *list, struct cni_opt_result **result);

/*
* Description: delete the container single network plane;
* manager: The set of parameters required for container network deletion;
* list: network configuration;
* result: record necessary network information;
* Return value: return 0 on success, non-zero on failure
*/
int detach_network_plane(const struct cni_manager *manager, const struct cni_network_list_conf *list, struct cni_opt_result **result);

/*
* Description: Check the status of the single network plane of the container;
* manager: set of parameters required for container network check;
* list: network configuration;
* result: record necessary network information;
* Return value: return 0 on success, non-zero on failure
*/
int check_network_plane(const struct cni_manager *manager, const struct cni_network_list_conf *list, struct cni_opt_result **result);
````

# 4. Detailed Design

## 4.1 load network configuration file

![Enter image description](https://images.gitee.com/uploads/images/2021/0122/094638_d03ff180_5626156.png "screenshot.png")

## 4.2 create network process

![Enter image description](https://images.gitee.com/uploads/images/2021/0122/094708_ec1f2f75_5626156.png "screenshot.png")

## 4.3 delete network process

![Enter image description](https://images.gitee.com/uploads/images/2021/0122/094727_20f3222d_5626156.png "screenshot.png")