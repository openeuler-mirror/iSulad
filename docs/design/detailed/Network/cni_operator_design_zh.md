cni-operator模块封装libcni模块，为生成提供更加合理友好的网络管理接口，负责网络配置文件的加载更新。

## 网络管理层cni-operator对外接口

```
/*
* 说明：网络管理模块初始化，完成libcni网络模块的初始化和网络管理层数据初始化；
* cache_dir: 网络缓存配置文件存储目录；
* conf_path: cni配置文件存储目录；
* bin_paths: cni插件存储目录列表；
* bin_paths_len：目录列表长度；
* 返回值：成功返回0，失败返回非0
*/
int cni_manager_store_init(const char *cache_dir, const char *conf_path, const char * const *bin_paths, size_t bin_paths_len);

/*
* 说明：根据过滤规则，加载cni配置文件到内存；
* store：cni配置列表；
* res_len: cni配置列表长度；
* filter_ops：自定义cni配置加载规则，加载符合规则的配置文件；
* 返回值：成功返回0，失败返回非0
*/
int get_net_conflist_from_dir(struct cni_network_list_conf ***store, size_t *res_len, cni_conf_filter_t filter_ops);

/*
* 说明：创建容器loopback网络
* id: 容器id；
* netns: 容器网络命名空间；
* 返回值：成功返回0，失败返回非0
*/
int attach_loopback(const char *id, const char *netns);

/*
* 说明：删除容器loopback网络
* id: 容器id；
* netns: 容器网络命名空间；
* 返回值：成功返回0，失败返回非0
*/
int detach_loopback(const char *id, const char *netns);

/*
* 说明：创建容器单网络平面；
* manager: 容器网络创建所需要的参数集合；
* list: 网络配置；
* result：记录必要的网络信息；
* 返回值：成功返回0，失败返回非0
*/
int attach_network_plane(const struct cni_manager *manager, const struct cni_network_list_conf *list, struct cni_opt_result **result);

/*
* 说明：删除容器单网络平面；
* manager: 容器网络删除所需要的参数集合；
* list: 网络配置；
* result：记录必要的网络信息；
* 返回值：成功返回0，失败返回非0
*/
int detach_network_plane(const struct cni_manager *manager, const struct cni_network_list_conf *list, struct cni_opt_result **result);

/*
* 说明：检查容器单网络平面状态；
* manager: 容器网络检查所需要的参数集合；
* list: 网络配置；
* result：记录必要的网络信息；
* 返回值：成功返回0，失败返回非0
*/
int check_network_plane(const struct cni_manager *manager, const struct cni_network_list_conf *list, struct cni_opt_result **result);
```

## 流程分析

### 加载网络配置文件

![输入图片说明](https://images.gitee.com/uploads/images/2021/0122/094638_d03ff180_5626156.png "屏幕截图.png")

### 创建网络流程

![输入图片说明](https://images.gitee.com/uploads/images/2021/0122/094708_ec1f2f75_5626156.png "屏幕截图.png")

### 删除网络流程

![输入图片说明](https://images.gitee.com/uploads/images/2021/0122/094727_20f3222d_5626156.png "屏幕截图.png")