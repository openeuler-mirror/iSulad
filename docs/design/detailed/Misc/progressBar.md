# 方案目标
在Image pull过程中，显示多个layer下载的进度。

之前的grpc pull和cri pull共用了接口，需要新增grpc pull接口，该接口类型为stream，带progress status。
重写函数oci_do_pull_image，底层函数pull_image复用。
在结构体registry_pull_options增加map。

# 限制
1. 每一个connection只做一件事，否则progress store会混乱。
2. 这个功能只为grpc 连接服务。

# 总体设计
## 主要功能模块
### Progress status store
每次pull命令或者行为为一个connection。每个image会按照layer来下载。所以我们建立了一个status map。 map的key为Layer ID，内容结构体定义如下:

```
struct progress_status {
    // Layer ID
    char ID[13];

    // total is the end value describing when we made 100% progress for an operation. Unit is Byte.
    int64 total;

    // current is the current value for the operation. Unit is Byte.
    int64 current;
}
```

#### API
```
progress_status_map *progress_status_map_new();

bool progress_status_map_insert(progress_status_map *progress_status_map, char *key, progress *value);

```

### Client Progress 显示
在client每次读到消息时，获取当前窗口宽度(termios.h: tcgetattr)，如果宽度小于110字符，则压缩显示(已下载/全部字节)，如果不是，则显示进度条。
当第一次收到时，计算需要显示的任务数task number，每个任务显示一行。
当更新状态时，将光标回退task number行，清除该行，打印完一行，将光标移到下一行清除该行并打印新的进度，重复上述步骤直至所有任务打印完成。

## 主要流程
### 下载任务获取下载状态
在结构体pull_descriptor新增*progress_status_store， 传递write_progress_status的map *。

在http_request中，修改原来的桩函数xfer，这个函数将实时采集curl pull的状态，如当前下载的字节数，总的字节数。


### server获取下载状态并传递给client
新增函数int ImagesServiceImpl::PullImage，函数Response参数为stream，每隔100ms读取progress status map并序列化为json message，写入response stream。
```
Status ImagesServiceImpl::PullImage(ServerContext *context, const PullImageRequest *request,
                                    ServerWriter<PullImageResponse> *writer)
```

### client收取状态并显示
修改原来的grpc_images_client中ImagesPull函数。阻塞式读取response stream， 流不为空则一直读取并打印显示每个progress status。
