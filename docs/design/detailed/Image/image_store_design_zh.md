| Author | 吴景                                     |
| ------ | ------------------------------------------ |
| Date   | 2020-03-27                                 |
| Email  | [wujing50@huawei.com](wujing50@huawei.com) |

# 1.方案目标

**Image模块**提供储存以及获取images信息的功能，包含以下功能：

> 读操作：查询镜像是否存在、根据ID或者名称获取镜像信息、根据镜像名称返回镜像ID、获取所有镜像信息、根据Digest获取镜像信息、加载从磁盘重新加载存储的内容、读取与具有指定ID关联的元数据、只读的big-data相关方法(获取big-data的content、size、digest、names)

> 写操作：创建镜像，设置镜像名称、删除镜像记录、清空所有镜像记录、设置镜像拉取时间、为镜像添加名称、镜像信息存储至磁盘、更新具有指定ID关联的元数据、存储big-data

# 2.总体设计

![](https://images.gitee.com/uploads/images/2020/0327/160234_e46b36bc_5595733.png)

# 3.接口描述


| 函数   | int new_image_store(bool daemon, bool readonly, const char *dir, image_store_t *image_store) |
| ------ | ------------------------------------------------------------ |
| 作用   | 从指定目录下遍历镜像目录下json文件并load镜像的元数据并添加至image_store中 |
| 入参   | bool daemon, bool readonly, const char *dir                  |
| 出参   | image_store_t *image_store                                   |
| 返回值 | success: 0   failure: -1                                     |


|  接口  | int (*create)(const char *id, const char **names, size_t names_len, const char *layer, const char *metadata, timestamp time, const char *searchable_digest, image_store_t *image_store, image_storage_images *image); |
| :----: | ------------------------------------------------------------ |
|  作用  | 根据输入生成镜像的元数据并添加至image_store中并进行持久化至磁盘 |
|  入参  | const char *id, const char **names, size_t names_len, const char *layer, const char 	 *metadata, timestamp time, const char *searchable_digest, image_store_t *image_store |
|  出参  | image_storage_images *image                                  |
| 返回值 | success: 0   failure: -1                                     |


|  接口  | int (*set_names)(const char *id, const char **names, size_t names_len, image_store_t *image_store); |
| :----: | ------------------------------------------------------------ |
|  作用  | 根据输入设置镜像的名称列表并添加至image_store中并进行持久化至磁盘 |
|  入参  | const char *id, const char **names, size_t names_len, image_store_t *image_store |
|  出参  | NA                                                           |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*delete)(const char *id, image_store_t *image_store); |
| :----: | ---------------------------------------------------------- |
|  作用  | 从image_store内存中删除镜像id并从磁盘删除相关文件          |
|  入参  | const char *id, image_store_t *image_store                 |
|  出参  | NA                                                         |
| 返回值 | success: 0   failure: -1                                   |

|  接口  | int (*wipe)(image_store_t *image_store);            |
| :----: | --------------------------------------------------- |
|  作用  | 从image_store内存中删除所有镜像并从磁盘删除相关文件 |
|  入参  | image_store_t *image_store                          |
|  出参  | NA                                                  |
| 返回值 | success: 0   failure: -1                            |

|  接口  | int (*set_loaded_time)(const char *id, timestamp loaded, image_store_t *image_store); |
| :----: | ------------------------------------------------------------ |
|  作用  | 在image_store内存中为指定镜像设置加载时间并持久化至磁盘      |
|  入参  | const char *id, timestamp loaded, image_store_t *image_store |
|  出参  | NA                                                           |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*add_name)(const char *id, const char *name, image_store_t *image_store); |
| :----: | ------------------------------------------------------------ |
|  作用  | 添加镜像名称，重复的名称会自动从列表中删除并持久化至磁盘     |
|  入参  | const char *id, const char *name, image_store_t *image_store |
|  出参  | NA                                                           |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*save)(const image_store_t *image_store) |
| :----: | --------------------------------------------- |
|  作用  | 将image_store中内存数据持久化至磁盘           |
|  入参  | const image_store_t *image_store              |
|  出参  | NA                                            |
| 返回值 | success: 0   failure: -1                      |

|  接口  | int (*set_metadata)(image_store_t *image_store, const char *id, const char *metadta); |
| :----: | ------------------------------------------------------------ |
|  作用  | 在image_store中设置指定镜像的元数据信息并持久化至磁盘        |
|  入参  | image_store_t *image_store, const char *id, const char *metadta |
|  出参  | NA                                                           |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*set_big_data)(image_store_t *image_store, const char *id, const char *key, const char *data); |
| :----: | ------------------------------------------------------------ |
|  作用  | 在image_store中查找到指定镜像指定key的big_data文件并将数据写入持久化至磁盘 |
|  入参  | image_store_t *image_store, const char *id, const char *key, const char *data |
|  出参  | NA                                                           |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | bool (*exists)(const char *id, const image_store_t *image_store); |
| :----: | ------------------------------------------------------------ |
|  作用  | 判断image_store中是否存在指定镜像                            |
|  入参  | const char *id, image_store_t *image_store                   |
|  出参  | NA                                                           |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*get)(const char *id, const image_store_t *image_store, image_storage_images *image); |
| :----: | ------------------------------------------------------------ |
|  作用  | 从image_store中拷贝指定镜像信息                              |
|  入参  | const char *id, const image_store_t *image_store             |
|  出参  | image_storage_images *image                                  |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*lookup)(const char *name, const image_store_t *image_store, char **id); |
| :----: | ------------------------------------------------------------ |
|  作用  | 将镜像名称转换为ID                                           |
|  入参  | const char *name, const image_store_t *image_store           |
|  出参  | char **id                                                    |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*images)(const image_store_t *image_store, image_storage_images **images, size_t *len); |
| :----: | ------------------------------------------------------------ |
|  作用  | 获取image_store中所有镜像信息                                |
|  入参  | const image_store_t *image_store                             |
|  出参  | image_storage_images **images, size_t *len                   |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*by_digest)(const image_store_t *image_store，const char *digest,  image_storage_images **images, size_t *len); |
| :----: | ------------------------------------------------------------ |
|  作用  | 从image_store中获取指定digest的镜像列表信息                  |
|  入参  | const image_store_t *image_store，const char *digest         |
|  出参  | image_storage_images **images, size_t *len                   |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*load)(image_store_t *image_store);                     |
| :----: | ------------------------------------------------------------ |
|  作用  | 从指定目录下遍历镜像目录下json文件并load镜像的元数据并添加至image_store中 |
|  入参  | NA                                                           |
|  出参  | image_storage_images **images, size_t *len                   |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*metadata)(const image_store_t *image_store，const char *id, char **metadata); |
| :----: | ------------------------------------------------------------ |
|  作用  | 从image_store中获取指定镜像的metadata信息                    |
|  入参  | const image_store_t *image_store，const char *id             |
|  出参  | char **metadata                                              |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*big_data)(const image_store_t *image_store，const char *id, const char *key, char **bigdata); |
| :----: | ------------------------------------------------------------ |
|  作用  | 从image_store中获取指定镜像指定key的big_data内容             |
|  入参  | const image_store_t *image_store，const char *id, const char *key |
|  出参  | char **bigdata                                               |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*big_data_size)(const image_store_t *image_store，const char *id, const char *key, int64_t *big_data_size); |
| :----: | ------------------------------------------------------------ |
|  作用  | 从image_store中获取指定镜像指定key的big_data大小             |
|  入参  | const image_store_t *image_store，const char *id, const char *key |
|  出参  | int64_t *big_data_size                                       |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*big_data_digest)(const image_store_t *image_store，const char *id, const char *key, char **big_data_digest); |
| :----: | ------------------------------------------------------------ |
|  作用  | 从image_store中获取指定镜像指定key的big_data的digest         |
|  入参  | const image_store_t *image_store，const char *id, const char *key |
|  出参  | char **big_data_digest                                       |
| 返回值 | success: 0   failure: -1                                     |

|  接口  | int (*big_data_names)(const image_store_t *image_store，const char *id, char ***big_data_names, size_t *big_data_names_len); |
| :----: | ------------------------------------------------------------ |
|  作用  | 从image_store中获取指定镜像的名称列表                        |
|  入参  | const image_store_t *image_store，const char *id             |
|  出参  | char ***big_data_names, size_t *big_data_names_len           |
| 返回值 | success: 0   failure: -1                                     |

# 4.详细设计

**Images模块**主要管理$driver-images目录下的**images.json镜像信息文件**、**manifest镜像数据索引文件**、以及以**镜像配置文件的base64作为文件名保存的镜像配置文件**
**Images模块主要包括下面的操作：**

> **创建镜像**：镜像的管理和层的管理是单独分开的，要创建镜像，必须先把所有对应的层创建好了，然后再把top层的信息，镜像名称，以及镜像配置，镜像id等信息保存到对应的文件即可。同时需要在内存中保存一份基本信息数据，以便在一些接口调用时可以快速返回数据(有必要时再这么实现)。
>
> **新增镜像名称**：将新增的镜像名称保存到images.json文件中即可，注意名称去重。
>
> **获取数据**：获取各种该模块保存的数据，包括配置文件、包含的层数据等信息，这些信息都可以通过images模块里保存的这三个文件找到(通过images.json作为索引依次查找)。对于一些其它信息，例如一层的数据等，可以直接调用层的接口返回数据。
>
> **删除镜像**：直接删除对应的文件夹。