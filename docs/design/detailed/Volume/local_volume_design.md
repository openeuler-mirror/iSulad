| Author | 王丰土                                     |
| ------ | ---------------------------------------------- |
| Date   | 2020-10-21                                     |
| Email  | [wangfengtu@huawei.com](wangfengtu@huawei.com) |

# 1. Program Objectives

The volume command during image creation can specify the container runtime to create an anonymous volume for storing the data that needs to be persisted during the container operation.
corresponding to the following configuration items:

```bash
$ isula inspect -f "{{.image.Spec.config.Volumes}}" vol
{
"/vol":{}
}
````

The volume module needs to support the configuration of this item to support anonymous volumes. Since anonymous volumes will remain after the container is destroyed, the volume module also needs to provide a means to delete volumes to prevent unused volumes from remaining.

The volume module also needs to provide commands to list local volumes and delete volumes.

In addition, the volume module also supports volume management for the -v and --mount parameters.

# 2. Overall Design

## 2.1 timing diagram

````mermaid
sequenceDiagram
participant isula
participant isulad
participant volume_store
participant volume_driver(local)
isulad -->> volume_store:volume_init
volume_store -->> volume_driver(local):register_local_volume
volume_driver(local) -->> volume_driver(local):local_volume_init
volume_driver(local) -->> volume_driver(local):register_driver
isula ->> isulad:create request
isulad -->> volume_driver(local):volume_create
isula ->> isulad:volume ls request
isulad -->> volume_driver(local):volume_list
isulad -->> isula:return all volume info
isula ->> isulad:volume remove request
isulad -->> volume_driver(local):volume_remove
isulad -->> isula:return removed volume id
isula ->> isulad:volume prune request
isulad -->> volume_driver(local):volume_prune
isulad -->> isula:return all removed volume id
````
# 3. Interface Description

## 3.1 external interface

````c
typedef struct {
    struct volume *(*create)(char *name);

    struct volume *(*get)(char *name);

    int (*mount)(char *name);

    int (*umount)(char *name);

    struct volumes *(*list)(void);

    int (*remove)(char *name);
} volume_driver;

struct volume {
    char *driver;
    char *name;
    char *path;
    // volume mount point, valid only when mounted
    char *mount_point;
};

struct volumes {
    struct volume **vols;
    size_t vols_len;
};

struct volume_names {
    char **names;
    size_t names_len;
};

struct volume_options {
    char *ref;
};

// Initialization of volume
int volume_init(char *root_dir);

// Register volume_driver in volume_store
int register_driver(char *name, volume_driver *driver);

// Create a new volume named name in the volume_driver of the specified driver_name,
// The container id refering the volume is stored in volume_options
struct volume *volume_create(char *driver_name, char *name, struct volume_options *opts);

int volume_mount(char *name);

int volume_umount(char *name);

// list all volumes
struct volumes *volume_list(void);

// Add the container id refering the volume
int volume_add_ref(char *name, char *ref);

// delete container id refering volume
int volume_del_ref(char *name, char *ref);

// Add the volume with the specified name
int volume_remove(char *name);

// clear all unused volumes
int volume_prune(struct volume_names **pruned);
````

## 3.2 related commands

### 3.2.1 volume creation/Reuse

The container creation/running process creates/reuses anonymous volumes:

1. Use anonymous volumes in the mirror. No change in interface. During the container creation/running process, whether to create an anonymous volume is determined according to whether this parameter exists in the image configuration.

2. Specify the use of anonymous volumes on the command line.

````sh
   # isula run -v /vol busybox sh or
   # isula run --mount type=volume,dst=/vol busybox sh
````

   Use the -v or --volume command to add an anonymous volume. Note that the anonymous volume only has a path inside the container, without ":".

   If the source source is not filled in, it is an anonymous volume. --mount also needs to specify the type as the volume mode.

   In addition, dst can also be written as target (new keyword).

3. Specify the use of a named volume on the command line.

````sh
   # isula run -v vol:/vol busybox sh or
   # isula run --mount type=volume,src=vol,dst=/vol busybox sh
````

The volume name filled in the source parameter of -v or --mount is a named volume (other parameters are the same as the above description).

4. Reuse volumes or bind mounts of other containers.

```bash
# isula run --volumes-from from-container image-name sh
````

Use the --volumes-from parameter to specify which container's volumes and bind mounts to reuse. The --volumes-from parameter can be used multiple times, that is, it can be specified to reuse anonymous volumes from multiple containers.

### 3.2.2 volume query

Use the following command to query the currently existing anonymous volume (the inspect command is not provided):

````sh
# isula volume ls
DRIVER VOLUME NAME
local f6391b735a917ffbaff138970dc45290508574e6ab92e06a1e9dd290f31592ca
````

### 3.2.3 destruction of volumes

When the container is stopped/destroyed, the anonymous volume will not be destroyed. You need to manually execute the command to destroy:
1. Delete a single anonymous volume:

```bash
# isula volume rm f6391b735a917ffbaff138970dc45290508574e6ab92e06a1e9dd290f31592ca
````

The name of the anonymous volume queried by isula volume ls is followed by rm.
2. Delete all unused anonymous volumes:
```bash
# isula volume prune -f
````
Where -f means that no manual confirmation is required, and the deletion is performed directly.

# 4. Detailed Design

## 4.1 anonymous volume data organization

Add a new folder volumes under the directory /var/lib/isulad to save anonymous volumes. Each anonymous volume creates a folder named after the anonymous volume name. The anonymous volume name is a 64-bit random character (character range a-f, 0-9), save the data and configuration in the folder. The configuration is temporarily unavailable, and the space in the folder is reserved for saving the configuration. The data is stored in a folder named _data, which is the source mount directory of the anonymous volume:

```bash
$ tree 71c0fba4a5fd549133d92a5826f821128714e43a0eef46ee4569b627488d0f79
71c0fba4a5fd549133d92a5826f821128714e43a0eef46ee4569b627488d0f79
└── _data

1 directory, 0 files
````

## 4.2 initialization of volume management

When iSulad is initialized, it traverses the /var/lib/isulad/volumes directory and loads the following directory information into memory.

## 4.3 volume creation

1. The volume is specified in the command line parameter, or the anonymous volume is specified in the mirror. When isulad creates a container, it adds the configuration of anonymous volume to the configuration of the container, and creates an anonymous volume in the /var/lib/isulad/volumes directory (see the figure above for the structure). At the same time, the information is stored in the volume management structure of the memory.

2. If selinux is enabled and mountlabel is configured, relabel the newly created directory.

3. If there are files in the volume mount path of the image, copy these files to /var/lib/isulad/volume/$volumename. Note that this copy is only made once when the container is created, and if the volume already has content, it will not be copied again.

Copied file types include:

Hard links, soft links, normal files, normal folders, character device files, block device files. Other files are not supported, for example, if there is a fifo file in the source path, an error will be reported. During the copying process, the corresponding time, permissions, and extended attributes are also copied.

4. Mount the volume of the container into the container, which is completed by the original volume mount function of the container (the configuration item has been added earlier).

## 4.4 reuse of volumes

It is similar to the "volume creation" process, except that steps 2 and 3 are not actually created, but the volume path of the original container is directly reused as the source path of the current volume.

## 4.5 volume query

Returns all in-memory volume information.

## 4.6 deletion of volumes

Iterates over all containers, checks volume usage, and prohibits deletion if any container is still in use.