| Author | 李峰                                    |
| ------ | ------------------------------------------ |
| Date   | 2020-08-28                                 |
| Email  | [lifeng68@huawei.com](lifeng68@huawei.com) |

# 1. Program Objectives

The Driver module needs to support overlay2 and devicemapper drivers to achieve the following functions:

- Initialize the driver;
- return the driver status;
- return the metadata information of the driver;
- cleanup the driver;
- create a read-only layer;
- create a read-write layer;
- delete the layer, obtain the rootfs path of the layer;
- release the layer;

The quota function also needs to be implemented for the overlay2 driver.

# 2. Overall Design

![Enter image description](https://images.gitee.com/uploads/images/2020/0327/103225_bed304d3_5226885.png "screenshot.png")

# 3. Interface Description

## 3.1 driver initialization

````c
int graphdriver_init(const char *name, const char *isulad_root, char **storage_opts,
                     size_t storage_opts_len);
````

## 3.2 create a read-write layer

````c
int graphdriver_create_rw(const char *id, const char *parent, struct driver_create_opts *create_opts);
````

## 3.3 create a read-only layer

````c
int graphdriver_create_ro(const char *id, const char *parent, const struct driver_create_opts *create_opts);
````

## 3.4 delete layer

````c
int graphdriver_rm_layer(const char *id)
````

## 3.5 mount layer

````c
char *graphdriver_mount_layer(const char *id, const struct driver_mount_opts *mount_opts)
````

## 3.6 umount layers

````c
int graphdriver_umount_layer(const char *id)
````

## 3.7 check if the layer exists

````c
bool graphdriver_layer_exists(const char *id)
````

## 3.8 decompression layer data

````c
int graphdriver_apply_diff(const char *id, const struct io_read_wrapper *content, int64_t *layer_size)
````

## 3.9 get layer meta data

````c
int graphdriver_get_layer_metadata(const char *id, json_map_string_string *map_info)
````

## 3.10 view the driver status

````c
struct graphdriver_status *graphdriver_get_status(void)
````

## 3.11 clean up the driver

````c
int graphdriver_cleanup(void)
````

# 4. Detailed Design

## 3.1 driver initialization

Driver initialization initialization process:

![Enter image description](https://images.gitee.com/uploads/images/2020/0327/103821_1d31a134_5226885.png "driver_init.png")

Overlay module initialization process:

![Enter image description](https://images.gitee.com/uploads/images/2020/0327/103713_4db8b576_5226885.png "overlay_init.png")

Devicemapper module initialization process:

![Enter image description](https://images.gitee.com/uploads/images/2020/0327/172343_7483d81e_5626156.png "devmapper_init.png")

## 3.2 create read-write layer

````c
struct driver_create_opts {
    char *mount_label;
    json_map_string_string *storage_opt;
};
````

1. According to the incoming ID, parent layer ID and configuration creation options, call the actual driver create_rw interface to realize the function of creating layer layer.
2. When creating the read-write layer, you need to determine whether the quota option is set. If the quota option is not set, the quota value of the default configuration of the daemon will be added as the quota limit of the read-write layer of the container.
3. If the quota option is set and the current file system does not support setting quota, an error will be reported.
4. The current overlay only supports the quota option. If there are other creation options, an error will be reported.

## 3.3 create a read-only layer

````c
struct driver_create_opts {
    char *mount_label;
    json_map_string_string *storage_opt;
};
````

1. According to the incoming ID, parent layer ID and creation options in configuration, call the actual driver create_ro interface to create a layer read-only layer.
2. When creating a read-only layer, you need to determine whether the quota option is set. If the quota option is set, an error will be reported.
3. If there are other creation options, an error will be reported.

## 3.4 delete layer

Call the actual driver rm_layer interface according to the incoming ID to delete the corresponding layer.

## 3.5 Mount layer

````c
struct driver_mount_opts {
    char *mount_label;
    char **options;
    size_t options_len;
};
````

1. Call the actual driver mount_layer interface according to the incoming ID to mount the corresponding layer and return the mounted file system path.

## 3.6 umount layers

Call the actual driver umount_layer interface according to the incoming ID to umount the corresponding layer.

## 3.7 check if the layer exists

Call the actual driver exists interface according to the incoming ID to query whether the corresponding layer exists.

## 3.8 decompression layer data

````c
struct io_read_wrapper {
    void *context;
    io_read_func_t read;
    io_close_func_t close;
};
````

1. Call the actual driver apply_diff interface according to the incoming ID to decompress the data.

2. Overlay driver: When decompressing data, special processing is required for the overlay .whout file.

   - If it is a file starting with .wh., it is marked as deleted and needs to be converted to char data, and the file needs to be skipped for subsequent decompression. For example, after deleting the home directory, the corresponding layer data is decompressed locally, and the corresponding home needs to create a character device with the same name.

     ````c
     drwxr-xr-x 4 root root 55 Mar 16 15:52 .
     drwxrwxrwt. 26 root root 4096 Mar 26 12:02 ..
     drwxr-xr-x 2 root root 38 Mar 16 12:49 etc
     c--------- 1 root root 0, 0 Mar 16 15:52 home
     -rw-r--r-- 1 root root 140543 Mar 13 12:12 index.html
     dr-xr-x--- 2 root root 26 Mar 13 12:13 root
     ````

3. The decompressed data should be chrooted to the corresponding directory to prevent soft link attacks.

## 3.9 get layer meta data

1. Call the actual driver get_layer_metadata interface according to the incoming ID to query the metadata of the corresponding layer.

2. The metadata supported by overlay query is as follows:

   | key       | value                                          |
   | :-------- | ---------------------------------------------- |
   | WorkDir   | the work path of the overlay layer                            |
   | MergedDir | the work path of the overlay layer                           |
   | UpperDir  | the diff path of the overlay layer                            |
   | LowerDir  | the underlying path of the overlay layer, including all the underlying paths, divided by: |
 

## 3.10 view the driver status

````c
struct graphdriver_status {
    char *driver_name;
    char *backing_fs;
    char *status;
};
````

1. Query the status of the driver.

2. The driver status that supports query is as follows:

   | key         | value                                                        |
   | :---------- | ------------------------------------------------------------ |
   | driver_name | driver name                                                     |
   | backing_fs  | the name of the file system where storage is located           |
   | status      | corresponds to the status of the underlying driver<br />the status return information supported by overlay is:<br />Backing Filesystem<br /> Supports d_type: true |


## 3.11 clean up the driver

1. Clean up the resources of the corresponding driver according to the call to the clean_up interface of the underlying driver
2. The overlay driver implements uninstalling the storage home directory