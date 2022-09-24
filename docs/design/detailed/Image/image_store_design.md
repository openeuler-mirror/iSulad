| Author | 吴景                                     |
| ------ | ------------------------------------------ |
| Date   | 2020-03-27                                 |
| Email  | [wujing50@huawei.com](wujing50@huawei.com) |

# 1.Program Objectives

**Image module** provides functions to store and obtain images information, including the following functions:

> Read operation: 

- query whether the image exists
- obtain image information according to ID or name
- return image ID according to image name
- obtain all image information
- obtain image information according to Digest
- load and reload the stored content from disk
- read and have the specified ID Associated metadata
- read-only big-data related methods (get big-data content, size, digest, names)

> Write operation: 

- create image
- set image name
- delete image records
- clear all image records
- set image pull time
- add image name, store image information to disk
- update metadata associated with specified ID
- store big-data

# 2.Overall Design

![输入图片说明](https://images.gitee.com/uploads/images/2020/0327/160234_e46b36bc_5595733.png "屏幕截图.png")

# 3.Interface Description


| Function   | int new_image_store(bool daemon, bool readonly, const char *dir, image_store_t *image_store) |
| ------ | ------------------------------------------------------------ |
| Effect   | traverse the json file in the image directory, load the metadata of the image and add it to image_store |
| Input parameter   | bool daemon, bool readonly, const char *dir                  |
| Output  parameter  | image_store_t *image_store                                   |
| Return value | success: 0   failure: -1                                     |


|  Function  | int (*create)(const char *id, const char **names, size_t names_len, const char *layer, const char *metadata, timestamp time, const char *searchable_digest, image_store_t *image_store, image_storage_images *image); |
| :----: | ------------------------------------------------------------ |
|  Effect  | generate image metadata based on input, add it to image_store and persist it to disk |
|  Input parameter  | const char *id, const char **names, size_t names_len, const char *layer, const char 	 *metadata, timestamp time, const char *searchable_digest, image_store_t *image_store |
|  Output parameter  | image_storage_images *image                                  |
| Return value | success: 0   failure: -1                                     |


|  Function  | int (*set_names)(const char *id, const char **names, size_t names_len, image_store_t *image_store); |
| :----: | ------------------------------------------------------------ |
|  Effect  | set the name list of the image according to the input, add it to the image_store and persist it to disk |
|  Input parameter  | const char *id, const char **names, size_t names_len, image_store_t *image_store |
|  Output  parameter  | NA                                                           |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*delete)(const char *id, image_store_t *image_store); |
| :----: | ---------------------------------------------------------- |
|  Effect  | remove image id from image_store memory and delete related files from disk          |
|  Input parameter  | const char *id, image_store_t *image_store                 |
|  Output  parameter  | NA                                                         |
| Return value | success: 0   failure: -1                                   |

|  Function  | int (*wipe)(image_store_t *image_store);            |
| :----: | --------------------------------------------------- |
|  Effect  | delete all images from image_store memory and delete related files from disk |
|  Input parameter  | image_store_t *image_store                          |
|  Output  parameter  | NA                                                  |
| Return value | success: 0   failure: -1                            |

|  Function  | int (*set_loaded_time)(const char *id, timestamp loaded, image_store_t *image_store); |
| :----: | ------------------------------------------------------------ |
|  Effect  | set the load time for the specified image in image_store memory and persist to disk      |
|  Input parameter  | const char *id, timestamp loaded, image_store_t *image_store |
|  Output  parameter  | NA                                                           |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*add_name)(const char *id, const char *name, image_store_t *image_store); |
| :----: | ------------------------------------------------------------ |
|  Effect  | add image names, duplicate names are automatically removed from the list and persisted to disk     |
|  Input parameter  | const char *id, const char *name, image_store_t *image_store |
|  Output  parameter  | NA                                                           |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*save)(const image_store_t *image_store) |
| :----: | --------------------------------------------- |
|  Effect  | persist memory data in image_store to disk           |
|  Input parameter  | const image_store_t *image_store              |
|  Output  parameter  | NA                                            |
| Return value | success: 0   failure: -1                      |

|  Function  | int (*set_metadata)(image_store_t *image_store, const char *id, const char *metadta); |
| :----: | ------------------------------------------------------------ |
|  Effect  | set the metadata information of the specified image in image_store and persist it to disk        |
|  Input parameter  | image_store_t *image_store, const char *id, const char *metadta |
|  Output  parameter  | NA                                                           |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*set_big_data)(image_store_t *image_store, const char *id, const char *key, const char *data); |
| :----: | ------------------------------------------------------------ |
|  Effect  | Find the big_data file with the specified key of the specified image in the image_store and write the data to the disk and persist it to the disk |
|  Input parameter  | image_store_t *image_store, const char *id, const char *key, const char *data |
|  Output  parameter  | NA                                                           |
| Return value | success: 0   failure: -1                                     |

|  Function  | bool (*exists)(const char *id, const image_store_t *image_store); |
| :----: | ------------------------------------------------------------ |
|  Effect  | determine whether the specified image exists in image_store                            |
|  Input parameter  | const char *id, image_store_t *image_store                   |
|  Output  parameter  | NA                                                           |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*get)(const char *id, const image_store_t *image_store, image_storage_images *image); |
| :----: | ------------------------------------------------------------ |
|  Effect  | copy the specified image information from image_store                              |
|  Input parameter  | const char *id, const image_store_t *image_store             |
|  Output  parameter  | image_storage_images *image                                  |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*lookup)(const char *name, const image_store_t *image_store, char **id); |
| :----: | ------------------------------------------------------------ |
|  Effect  | convert image name to ID                                           |
|  Input parameter  | const char *name, const image_store_t *image_store           |
|  Output  parameter  | char **id                                                    |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*images)(const image_store_t *image_store, image_storage_images **images, size_t *len); |
| :----: | ------------------------------------------------------------ |
|  Effect  | get all image information in image_store                                |
|  Input parameter  | const image_store_t *image_store                             |
|  Output  parameter  | image_storage_images **images, size_t *len                   |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*by_digest)(const image_store_t *image_store，const char *digest,  image_storage_images **images, size_t *len); |
| :----: | ------------------------------------------------------------ |
|  Effect  | get the image list information of the specified digest from image_store                  |
|  Input parameter  | const image_store_t *image_store，const char *digest         |
|  Output  parameter  | image_storage_images **images, size_t *len                   |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*load)(image_store_t *image_store);                     |
| :----: | ------------------------------------------------------------ |
|  Effect  | traverse the json file in the image directory from the specified directory and load the metadata of the image and add it to image_store |
|  Input parameter  | NA                                                           |
|  Output  parameter  | image_storage_images **images, size_t *len                   |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*metadata)(const image_store_t *image_store，const char *id, char **metadata); |
| :----: | ------------------------------------------------------------ |
|  Effect  | get the metadata information of the specified image from image_store                    |
|  Input parameter  | const image_store_t *image_store，const char *id             |
|  Output  parameter  | char **metadata                                              |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*big_data)(const image_store_t *image_store，const char *id, const char *key, char **bigdata); |
| :----: | ------------------------------------------------------------ |
|  Effect  | get the big_data content of the specified key of the specified image from the image_store             |
|  Input parameter  | const image_store_t *image_store，const char *id, const char *key |
|  Output  parameter  | char **bigdata                                               |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*big_data_size)(const image_store_t *image_store，const char *id, const char *key, int64_t *big_data_size); |
| :----: | ------------------------------------------------------------ |
|  Effect  | get the big_data size of the specified key of the specified image from image_store             |
|  Input parameter  | const image_store_t *image_store，const char *id, const char *key |
|  Output  parameter  | int64_t *big_data_size                                       |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*big_data_digest)(const image_store_t *image_store，const char *id, const char *key, char **big_data_digest); |
| :----: | ------------------------------------------------------------ |
|  Effect  | get the digest of the big_data of the specified key of the specified image from the image_store         |
|  Input parameter  | const image_store_t *image_store，const char *id, const char *key |
|  Output  parameter  | char **big_data_digest                                       |
| Return value | success: 0   failure: -1                                     |

|  Function  | int (*big_data_names)(const image_store_t *image_store，const char *id, char ***big_data_names, size_t *big_data_names_len); |
| :----: | ------------------------------------------------------------ |
|  Effect  | get the name list of the specified image from image_store                        |
|  Input parameter  | const image_store_t *image_store，const char *id             |
|  Output  parameter  | char ***big_data_names, size_t *big_data_names_len           |
| Return value | success: 0   failure: -1                                     |

# 4. Detailed Design

The **Images module** mainly manages the **images.json image information file**, **manifest image data index file** in the $driver-images directory, And **the image configuration file saved with the base64 of the image configuration file as the file name**.

**Images module mainly includes the following operations:**

> **Create image**: Image management and layer management are separate. To create an image, you must first create all the corresponding layers, and then add the top layer information, image name, and image configuration. The image ID and other information can be saved to the corresponding file. At the same time, it is necessary to save a copy of basic information data in the memory, so that the data can be quickly returned when some interface calls are made (this is implemented when necessary).
>
> **Add image name**: Save the newly added image name to the images.json file, pay attention to deduplication of the name.
>
> **Get data**: Get various data saved by this module, including configuration files, included layer data and other information, which can be found through the three files saved in the images module (using images.json as an index search in turn). For some other information, such as the data of a layer, etc., you can directly call the interface of the layer to return the data.
>
> **Delete Image**: Directly delete the corresponding folder.