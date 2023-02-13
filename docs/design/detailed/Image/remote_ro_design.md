| Author | 王润泽                 |
| ------ | ---------------------- |
| Date   | 2023-2-13              |
| Email  | wangrunze13@huawei.com |

# 1. 方案目标
目标有两个：
1. 把isulad当前的layer store里的RO层分离出来，把RW layer和RO layer分开到不同到目录存储。
2. isulad在运行时如果在相关目录里恢复了正确的镜像数据(image和layer数据), 可实现不重启isulad, 直接使用新恢复的镜像。如果移除当前没有容器正在使用的镜像数据，可实现不重启isulad，isulad更新当前管理的镜像列表去除该镜像。只考虑完全正确的新增和删除。


## 1.1 用法说明
通过源码编译打开编译选项来开启功能，cmake添加`cmake -DENABLE_REMOTE_LAYER_STORE=ON ..`, 然后`make -j`即可。启动iSulad之前，还需要在配置文件`/etc/isulad/daemon.json`里面添加`"storage-enable-remote-layer": true`来打开开关。

# 2. 总体设计

*Modules Dependencies*
```
=> New Added Module:

   +===================================+
   |    Remote Supporter Module        |
   +===================================+
   |                                   |
   |    +-------------------------+    |                       
   |    |   maintainer submod     |    |                       
   |    +-------------------------+    |                       
   |    |   global data initer    |    |                       
   |    |  symbol link maintainer |    |                       
   |    |   global data getter    |    |                       
   |    +-------------------------+    |                       
   |                                   |
   |    +-------------------------+    |
   |    |    Supporter submod     |    |
   |    +-------------------------+    |
   |    |   supporter interface   |    |
   |    |  overlay supporter impl |    |
   |    |   layer supporter impl  |    |
   |    |   image supporter impl  |    |
   |    |  remote refresh thread  |    |
   |    +-------------------------+    |
   +-----------------------------------+


=> Modified Modules:

   +===================================+
   |          Storage Module           |
   +===================================+
   |                                   |
   |    +-------------------------+    |                       
   |    |   Image Store submod    |    |                       
   |    |     Added Functions     |    |                       
   |    +-------------------------+    |                       
   |    |   add image in memory   |    |                       
   |    |  delete image in memory |    |                       
   |    |   get image top layer   |    |                       
   |    |   valid image manifest  |    |                       
   |    +-------------------------+    |                       
   |                                   |
   |    +-------------------------+    |
   |    |    Layer Store submod   |    |
   |    |     Added Functions     |    |                       
   |    +-------------------------+    |
   |    |   add layer in memory   |    |
   |    |  delete layer in memory |    |
   |    +-------------------------+    |
   |                                   |
   |    +-------------------------+    |
   |    |  Driver Overlay submod  |    |
   |    |     Added Functions     |    |                       
   |    +-------------------------+    |
   |    |          -              |    |
   |    +-------------------------+    |
   +-----------------------------------+


=>  Modules Dependencies:      

                          +-------------------------+          +---------------+                                           
                          |    Supporter submod     |          |   Image Store |                                           
                          +-------------------------+    +----▶|    submod     ---------+                                  
                          |   supporter interface   |    |     +---------------+        |                                  
                          |  overlay supporter impl -----+                              |                                  
                          |   layer supporter impl  -----+                              |                                  
+----------------+        |   image supporter impl  |    |     +----------------+       |                                  
| storage module |-------▶|  remote refresh thread  |    +----▶|    Layer Store |       | init    +-----------------------+
+----------------+        +-------------------------+          |     submod     --------+--------▶|   maintainer submod   |
                                     |                         +----------------+       |         +-----------------------+
                                     |                                                  |                     ▲            
                                     |                                                  |                     |            
                                     |                         +----------------+       |                     |            
                                     |                         |    Layer Store |       |                     |            
                                     |                         |     submod     --------+                     |            
                                     |                         +----------------+                             |            
                                     |                                                                        |            
                                     +------------------------------------------------------------------------+               
                                                                 get global data                                       
```


总体来说有两部分的功能：
- iSulad原有的image storage适配分离的RO目录结构，*分离的RO目录*可用于远程挂载
- iSulad实例同步内存数据，镜像数据和layer数据*定期更新*，不通过`isula pull` 和 `isula rmi` 等命令，直接通过分离目录里面的数据来更新镜像数据。

*分离RO目录*
修改前后storage目录结构对比：

```
old:
overlay-layer
├── b703587
│    └── layer.json
└── b64792c
     └── layer.json 
     └── b64792.tar.gz

new:
overlay-layer
├── b64792c -> ../RO/b64792c
├── b703587
│   └── layer.json
└── RO
    └── b64792c
        └── layer.json
        └── b64792.tar.gz
```

以overlay-layers目录为例，创建新layer时，如果是只读层，就把层数据放到RO目录下，在RO上层目录创建软连接指向真实数据。删除layer时需要额外删除软连接。


*定期更新*
定期更新通过启动一个线程周期扫描`overlay`, `overlay-layers`, `overlay-image`这三个目录，通过比较当前时刻与上一时刻的目录差异，来获取镜像和层的删减情况，进而同步isulad的storage内存数据和维护软链接。

```
+---------------------+       +---------------------+           +---------------------+           +-----------------------+
| refresh thread loop |       | overlay remote impl |           |  layer remote impl  |           |   image remote impl   |
+---------------------+       +---------------------+           +---------------------+           +-----------------------+
        |                              |                                  |                                  |
        | refresh start                |                                  |                                  |
        |-----------------------------▶|                                  |                                  |
        |                              | overlay dir scan                 |                                  |
        |                              |                                  |                                  |
        |                              | to added layers                  |                                  |
        |                              | memory and symlink add           |                                  |
        |                              | to deleted layers                |                                  |
        |                              | memory and symlink del           |                                  |
        |                              | valid overlay layers             |                                  |
        |                              |---------------------------------▶|                                  |
        |                              |         next scan                |                                  |
        |                              |                                  |                                  |
        |                              |                                  |                                  |
        |                              |                                  |                                  |
        |                              |                                  | overlay-layers dir scan          |
        |                              |    check overlay layer ready     |                                  |
        |                              |◀---------------------------------| to added layers                  |
        |                              |---------------------------------▶| filter invalid layers            |
        |                              |           result                 | memory and symlink add           |
        |                              |                                  | to deleted layers                |
        |                              |                                  | memory and symlink del           |
        |                              |                                  | valid overlay layers             |
        |                              |                                  |---------------------------------▶|
        |                              |                                  |        next scan                 |
        |                              |                                  |                                  |
        |                              |                                  |                                  |
        |                              |                                  |                                  |
        |                              |                                  |                                  | overlay-image dir scan
        |                              |                                  |       check layers ready         |
        |                              |                                  |◀---------------------------------| to added images        
        |                              |                                  |---------------------------------▶| filter invalid images   
        |                              |                                  |           result                 | memory add images   
        |                              |                                  |                                  | to deleted images   
        |                              |                                  |                                  | memory del images   
        |                              |                                  |                                  |
        |◀---------------------------------------------------------------------------------------------------|
        | refresh end                  |                                  |                                  |
        |                              |                                  |                                  |
+---------------------+       +---------------------+          +---------------------+            +-----------------------+
| refresh thread loop |       | image remote module |          | layer remote module |            | overlay remote module |
+---------------------+       +---------------------+          +---------------------+            +-----------------------+

```

# 3. 接口描述

```c
// 初始化remote模块里的layer data
int remote_layer_init(const char *root_dir);

// 初始化remote模块里的overlay data
int remote_overlay_init(const char *driver_home);

// 清理remote模块的资源
void remote_maintain_cleanup();

// 启动 定期更新的thread
int start_refresh_thread(void);

// 创建新layer目录
int remote_layer_build_ro_dir(const char *id);

// 创建新overlay目录
int remote_overlay_build_ro_dir(const char *id);

// 删除layer目录
int remote_layer_remove_ro_dir(const char *id);

// 删除overlay目录
int remote_overlay_remove_ro_dir(const char *id);
```

# 4. 详细设计
分离RO目录的关键在于适配原来的代码逻辑，原先的代码在操作镜像和层的时候，不管是RO层还是RW层，从创建到删除都是在当前目录下进行的，这就是我们额外创建一个软连接的作用:
- RO目录的作用是为了支持远程挂载
- 软连接的作用是模拟原来的目录结构

这样以来，image module的逻辑几乎不需要改动，除了以下几点需要注意：
- 创建和删除的时候需要处理一个额外的资源：软连接，之前只需要关注目录即可，现在如果创建的是只读层，就需要额外创建软连接，如果删除的是只读层，就需要额外删除软连接
- 以`overlay-layers`目录为例，isulad启动时会以正则规则扫描当前目录下的子目录是否合法，所以需要屏蔽`RO`目录

定时刷新的逻辑如下：
以`overlay-image`目录的刷新为例，通过维护两个集合`new` 和 `old`, 这两个集合初始都为空，通过扫描目录里面所有的子目录，把合法的image id 加入`new`集合， 通过计算两个集合的差， 在集合`new`里面存在而在集合`old`里面不存在的id则为新增加的镜像， 在集合`old`里面存在而在集合`new`里面不存在的id则为删除的镜像。处理新增加的镜像还需要额外的一个判断，就是判断镜像的层数据是否已经加载，如果没加载则该镜像本轮不加载。`overlay-layers` 和 `overlay` 目录的处理逻辑类似。


*可能的使用场景*
一个可能的使用场景就是通过远程文件共享(nfs)让多台启动的isulad实例共享某些只读的数据；具体来说，在两个host A和B上都启动了iSulad, 如果A pull或者load了镜像busybox, 那么B上的isulad同样可以使用这个镜像。

```
operations:

+--------------------+           +--------------------+           +--------------------+
| isula pull busybox |           | without pull       |           | without pull       |
| isula pull nginx   |           | isula run busybox  |           | isula run ngxinx   |
| isula pull ...     |           | isula run ...      |           | isula run centos   |
+--------------------+           +--------------------+           +--------------------+
    |                                |                                |
    ▼                                ▼                                ▼
+======================+         +======================+         +======================+
| isulad on Host A     |         | isulad on Host B     |         | isulad on Host C     |
+======================+         +======================+         +======================+
| image store module   |         | image store module   |         | image store module   |
+----------------------+         +----------------------+         +----------------------+
| refresh thread off   |         | refresh thread on    |         | refresh thread on    |
+----------------------+         +----------------------+         +----------------------+
| local rw | remote ro |         | local rw | remote ro |         | local rw | remote ro |
+----------------------+         +----------------------+         +----------------------+
                |                               |                             |            
                | enable nfs                    | mounted on                  | mounted on
                ▼                               ▼                             ▼           
            +=====================================================================+
            |                    nfs directory over network                       |
            +=====================================================================+
            |                          image store                                |
            +---------------------------------------------------------------------+
            |   image      |   image     |   image   |   image     |   image      | 
            |   busybox    |   nginx     |   my-app  |   ubuntu    |   centos     | 
            |   4MB        |   100MB     |   1.2GB   |   5MB       |   6MB        | 
            +---------------------------------------------------------------------+
            |                          layers store                               |
            +---------------------------------------------------------------------+
            |     layer            |      layer            |        layer         |
            |   05c361054          |    8a9d75caad         |      789d605ac       |
            +---------------------------------------------------------------------+
```

*同步问题*
共享资源并发使用发生竞争的条件是：`two process access the same resource concurrently and at least one of the access is a writer`。这里的共享资源有：

```
+============================+         +=====================================+
|      Sharing Resource      |         |          Storage                    |
+============================+         +=====================================+
| read-only overlay layers   | mounted | /var/lib/isulad/overlay/RO          |
+----------------------------+ ======▶ +-------------------------------------+
| reald-only layers metadata | shared  | /var/lib/isulad/overlay-layers/RO   |
+----------------------------+         +-------------------------------------+
| reald-only images          |         | /var/lib/isulad/overlay-images      |
+----------------------------+         +-------------------------------------+

```
而分布在不同host上的isulad进程通过网络共享这些资源，如果不考虑新增删除的情况，不会出现资源竞争，所有的节点都是reader。

对于主节点pull镜像，其他节点使用镜像的情况，主节点是writer，其他节点是reader。这时候可能出现的问题是主节点pull镜像的流程没有完全结束，但是其他节点开始使用这个不完整的镜像。对于这个问题的解决方案是通过扫描image目录来新增镜像，通过这种方式能确保一定该新增镜像的信息完整。

```
+---------------------+         +--------------------+         +-----------------------+         +-----------------------+
|    registry         |         | image module       |         | layer store module    |         | driver overlay module |
+---------------------+         +--------------------+         +-----------------------+         +-----------------------+
        |                                |                                 |                                 |
        |                                |                                 |                                 |
        | registry_pull                  |                                 |                                 |
        | fetch_manifest                 |                                 |                                 |
        | check reuse and fetch          |                                 |                                 |
        | +----------------+             |                                 |                                 |
        | | register_layer |             |                                 |                                 |
        | +----------------+             |                                 |                                 |
        |-----------------------------------------------------------------▶|                                 |
        |                                |                                 | layer_store_create              |
        |                                |                                 |--------------------------------▶|
        |                                |                                 |                                 | driver_create_layer
        |                                |                                 |                                 | +--------------------+ 
        |                                |                                 |                                 | | setup overlay dir  |
        |                                |                                 |                                 | +--------------------+
        |                                |                                 |                                 | driver_create_layer done
        |                                |                                 |◀--------------------------------|
        |                                |                                 | +------------+                  |
        |                                |                                 | | save layer |                  |
        |                                |                                 | +------------+                  |
        |                                |                                 | layer create done               |
        |◀-----------------------------------------------------------------|                                 |
        | all layer setup                |                                 |                                 |
        | +----------------+             |                                 |                                 |
        | | register image |             |                                 |                                 |
        | +----------------+             |                                 |                                 |
        |-------------------------------▶|                                 |                                 |
        |                                | storage_img_create              |                                 |
        |                                | set img top layer               |                                 |
        |                                | img create                      |                                 |
        |                                | +------------+                  |                                 |
        |                                | | save image |                  |                                 |
        |                                | +------------+                  |                                 |
        |                                | create image done               |                                 |
        |◀-------------------------------|                                 |                                 |
        | pull img done                  |                                 |                                 |
        |                                |                                 |                                 |
        |                                |                                 |                                 |
+---------------------+         +--------------------+         +-----------------------+         +-----------------------+
|    registry         |         | image module       |         | layer store module    |         | driver overlay module |
+---------------------+         +--------------------+         +-----------------------+         +-----------------------+

```

至于主节点删除镜像的情况，主节点是writer，其他节点是reader，可能出现的情况是其他节点还有容器在使用镜像的时候，镜像被删除，但是根据需求场景暂不处理这种情况。其他的处理与新增镜像相同，依然以image dir作为入口，扫描发现删除的镜像。删除时需要关注layer和overlay目录下的软链接。
