- [English version](README.md)

# 设计文档

如果您想要更充分的了解iSulad，可以查看以下设计文档。

## architecture

- 查看iSulad的架构：[architecture](./architecture_zh.md) 。

## Container

- 查看 gc 和 supervisor模块的设计文档：[gc_and_supervisor_design](./detailed/Container/gc_and_supervisor_design_zh.md) 。

- 查看 restore 模块的设计文档： [restore_design](./detailed/Container/restore_design_zh.md) 。

- 查看 健康检查 模块的设计文档： [health_check_design](./detailed/Container/health_check_design.md)。

- 查看 restart 模块的设计文档： [restart_manager_design](./detailed/Container/restart_manager_design.md)。

- 查看 cgroup v2 的设计文档： [cgroup_v2_design](./detailed/Container/cgroup_v2_design_zh.md)。

## CRI

- 查看 CRI的启动程序的重构文档： [cri_cni_refactor](./detailed/CRI/cri_cni_refactor_zh.md) 。

## CDI
- 查看 CDI 的设计文档： [cdi_design](./detailed/CDI/cdi_design_zh.md.md)。

## Events

- 查看 events 模块的设计文档： [events_design](./detailed/Events/events_design_zh.md) 。

## Image

- 查看 image storage driver 模块的设计文档： [image_storage_driver_design](./detailed/Image/image_storage_driver_design_zh.md)。

- 查看 image store 模块的设计文档： [image_store_design](./detailed/Image/image_store_design_zh.md) 。

- 查看 layer store 模块的设计文档 [layer_store_degisn](./detailed/Image/layer_store_degisn_zh.md) 。

- 查看 registry 模块的设计文档： [registry_degisn](./detailed/Image/registry_degisn_zh.md) 。

- 查看 isula search 的设计文档：[image_search_design](./detailed/Image/image_search_design_zh.md) 。

- 查看 ro目录分离的设计文档： [remote_ro_design](./detailed/Image/remote_ro_design.md) 。

## Network

- 查看 cni operator 模块的设计文档： [cni_operator_design](./detailed/Network/cni_operator_design_zh.md) 。

- 查看 cni operator 模块升级到CNI v1.0.0的设计文档： [cni_1.0.0_change](./detailed/Network/cni_1.0.0_change.md) 。

- 查看 CRI adapter 模块的设计文档： [CRI_adapter_design](./detailed/Network/CRI_adapter_design_zh.md) 。

- 查看 native network adapter 模块的设计文档： [native_network_adapter_design](./detailed/Network/native_network_adapter_design_zh.md) 。

- 查看 native network 模块的设计文档： [native_network_design](./detailed/Network/native_network_design_zh.md) 。

## Runtime

- 查看 runtime 模块的设计文档： [runtime_design](./detailed/Runtime/runtime_design_zh.md) 。
- 查看 isulad 支持runc 的设计文档：[runc_design](./detailed/Runtime/runc_design_zh.md)。

## Security

- 查看 seccomp 的优化文档： [seccomp_optimization](./detailed/Security/seccomp_optimization_zh.md) 。

## Volume

- 查看 local volume 模块的设计文档： [local_volume_design](./detailed/Volume/local_volume_design_zh.md).

## CRI V1 Sandbox

- 查看 Sandbox 模块的设计文档： [sandbox_design_zh](./detailed/Sandbox/sandbox_design_zh.md) 。
- 查看 Controller 模块的设计文档： [controller_design_zh](./detailed/Sandbox/controller_design_zh.md) 。
- 查看 CRI V1 模块的设计文档： [podsandbox_cri_interface_design](./detailed/Sandbox/podsandbox_cri_interface_design.md) 。
- 查看 CRI 1.29 更新模块的设计文档： [cri_1.29_update_design](./detailed/CRI/CRI_1.29_update_design.md) 。
