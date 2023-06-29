| Author | 刘昊 |
| ------ | ---- |
| Date   |  2023-06-30     |
| Email   |    liuhao27@huawei.com    |

# 重构目的

`iSulad` 开发之初，由于 `SPDY` 协议已废弃，并且 `K8S` 在实现 `CRI dockershim` 的流式服务时，同时支持 `SPDY` 和 `websocket` 协议。因此，`iSulad` 直接选择 `websocket` 作为流式服务的通信协议，以满足后续的演进发展。但是由于 `websocket` 协议存在[一些问题](./k8s_websockets_problem.md)，导致 `K8S` 社区一直无法合入[支持 websocket 协议的客户端代码](https://github.com/kubernetes/kubernetes/pull/116778)。这些问题导致 `iSulad` 对接 `K8S` 需要对 `K8S` 代码进行[定制化修改](https://gitee.com/src-openeuler/kubernetes/blob/master/0002-kubelet-support-exec-and-attach-websocket-protocol.patch)。

为了解决这些问题，本次重构 `CRI stream server` 部分的代码架构，为后续支持 `SPDY` 以及其他协议提供架构基础。

# 重构方案

## 原有方案

### 代码目录结构

```bash
cri/websocket/service
	- attach_serve.* # 负责attach流式操作的具体实现，实现流式接口
	- exec_serve.* # 负责exec流式操作，实现流式接口
	- route_callback_register.* # 抽象流式统一接口，并且提供统一注册机制
	- stream_server.* # CRI 流式服务入口，管理流式服务的启动、停止
	- ws_server.* # websocket的流式服务具体实现
```

**问题：** 不同层级的代码存放在一起，无法区分架构层级；

### 类图

本章节，主要是描述老方案的类关系，可以更好的了解该模块的关联关系。

![old class](./isulad_cri_stream_server_old_class_diagram.svg)

问题：
- CRI 上层模块直接依赖 `ws_server.h`；
- Stream Server模块入口依赖 `ExecServe` 和 `AttachServe` 两个底层实现；
- `route_callback_register.h` 和 `ws_server.h` 相互依赖；
- `ExecServe` 和 `AttachServe` 反向依赖 `ws_server.h`；


## 重构后方案

### 代码目录结构

主要对目录结构进行重新组织，通用部分放到一级目录，而不同的协议实现放到特定目录进行管理。

```bash
cri/streams/
├── attach_serve.* # 负责attach流式操作的具体实现，实现流式接口
├── exec_serve.* # 负责exec流式操作，实现流式接口
├── route_callback_register.* # 抽象流式统一接口，并且提供统一注册机制
├── session.* # session的数据管理，以及相关操作实现
├── stream_server.* # CRI 流式服务入口，管理流式服务的启动、停止
└── websocket # websocket 实现
    └── ws_server.*
```

### 类图

主要是为了解决老架构中混乱的依赖关系，优化后的类图依赖如下：

![new class](./isulad_cri_stream_server_new_class_diagram.svg)

*说明：由于当前没有新的网络协议支持，初步Stream Server还保留直接依赖 attach_serve.h 和 exec_serve.h。*

# 差异对比

- 代码目录结构更加合理、清晰；
- 代码依赖关系更加清晰；
- 拆分 `session` 独立模块，使得依赖更加合理清晰；

