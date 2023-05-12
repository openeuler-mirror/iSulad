# 章节一：CRI接口升级背景及版本
背景：当前iSulad CRI接口版本采用的K8s 1.15版本,升级至k8s1.25，CRI接口需要对升级后的新增CRI字段进行补充。

版本：升级至k8s1.25。
# 章节二：新增功能
	
## 1、Image

### 1.1、ListImages
	void ListImages(const runtime::v1alpha2::ImageFilter &filter,
                    std::vector<std::unique_ptr<runtime::v1alpha2::Image>> *images, Errors &error) override;"

**新增CRI字段**

ImageFilter里面的ImageSpec新增 map<string, string> annotations = 2。
Image中新增ImageSpec spec = 7;bool pinned = 8;ImageSpec里面新增 map<string, string> annotations = 2。
### 1.2、ImageStatus
	std::unique_ptr<runtime::v1alpha2::Image> ImageStatus(construntime::v1alpha2::ImageSpec &image,Errors &error) override;

**新增CRI字段**

Image中新增ImageSpec spec = 7;bool pinned = 8;ImageSpec里面新增 map<string, string> annotations = 2;
### 1.3、PullImage
	std::string PullImage(const runtime::v1alpha2::ImageSpec &image, const runtime::v1alpha2::AuthConfig &auth,Errors &error) override;

**新增CRI字段**

ImageSpec里面新增 map<string, string> annotations = 2;AuthConfig 无新增
### 1.4、RemoveImage
	void RemoveImage(const runtime::v1alpha2::ImageSpec &image, Errors &error) override;

**新增CRI字段**

ImageSpec里面新增 map<string, string> annotations = 2;
### 1.5、ImageFsInfo
无新增CRI字段
## 2、POD
### 2.1、RunPodSandbox
	auto RunPodSandbox(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &runtimeHandler,Errors &error) -> std::string;

**新增CRI字段**

1、新增WindowsPodSandboxConfig windows = 9;

2、原有LinuxPodSandboxConfig中新增LinuxContainerResources overhead = 4;LinuxContainerResources resources = 5；

3、原有LinuxPodSandboxConfig中原有LinuxSandboxSecurityContext中新增新增SecurityProfile seccomp = 9;SecurityProfile apparmor = 10;

4、原有LinuxPodSandboxConfig中原有LinuxSandboxSecurityContext中原有NamespaceOption中新增string target_id = 4;新增UserNamespace userns_options = 5;

5、原有LinuxPodSandboxConfig中原有LinuxSandboxSecurityContext中原有NamespaceOption原有中NamespaceMode新增TARGET
### 2.2、StopPodSandbox
	void StopPodSandbox(const std::string &podSandboxID, Errors &error);

**新增CRI字段**

1、原有PodSandboxNetworkStatus中新增repeated PodIP additional_ips  = 2;

2、原有LinuxPodSandboxStatus中原有NamespaceOption中新增string target_id = 4;新增UserNamespace userns_options = 5;

3、原有LinuxPodSandboxStatus中原有NamespaceOption中原有中NamespaceMode新增TARGET
### 2.3、RemovePodSandbox
无新增CRI字段
### 2.4、PodSandboxStatus
	auto PodSandboxStatus(const std::string &podSandboxID, Errors &error)
            -> std::unique_ptr<runtime::v1alpha2::PodSandboxStatus>;

**新增CRI字段**

1、原有PodSandboxNetworkStatus中新增repeated PodIP additional_ips  = 2;

2、原有LinuxPodSandboxStatus中原有NamespaceOption中新增string target_id = 4;新增UserNamespace userns_options = 5;

3、原有LinuxPodSandboxStatus中原有NamespaceOption中原有中NamespaceMode新增TARGET
### 2.5、ListPodSandbox
无新增CRI字段
### 2.6、PortForward
该函数未实现
## 3、Container
### 3.1、CreateContainer
	auto CreateContainer(const std::string &podSandboxID, const runtime::v1alpha2::ContainerConfig &containerConfig,
                         const runtime::v1alpha2::PodSandboxConfig &podSandboxConfig, Errors &error) -> std::string;
**新增CRI字段1**

1、原有ImageSpec中新增map<string, string> annotations = 2;

2、原有LinuxContainerConfig中原有LinuxContainerResources新增repeated HugepageLimit hugepage_limits = 8;map<string, string> unified = 9;int64 memory_swap_limit_in_bytes = 10;

3、原有LinuxContainerConfig中原有LinuxContainerSecurityContext新增SecurityProfile seccomp = 15;SecurityProfile apparmor = 16;

4、原有LinuxContainerConfig中原有LinuxContainerSecurityContext中原有Capability新增repeated string add_ambient_capabilities = 3;

5、原有LinuxContainerConfig中原有LinuxContainerSecurityContext中原有NamespaceOption中新增string target_id = 4;新增UserNamespace userns_options = 5;

6、原有LinuxContainerConfig中原有LinuxContainerSecurityContext中原有NamespaceOption中原有NamespaceMode新增TARGET

7、原有WindowsContainerConfig中原有WindowsContainerResources新增int64 rootfs_size_in_bytes = 5;

8、原有WindowsContainerConfig中原有WindowsContainerSecurityContext新增bool host_process = 3;

**新增CRI字段2**

1、新增WindowsPodSandboxConfig windows = 9;

2、原有LinuxPodSandboxConfig中新增LinuxContainerResources overhead = 4;LinuxContainerResources resources = 5

3、原有LinuxPodSandboxConfig中原有LinuxSandboxSecurityContext中新增新增SecurityProfile seccomp = 9;SecurityProfile apparmor = 10;

4、原有LinuxPodSandboxConfig中原有LinuxSandboxSecurityContext中原有NamespaceOption中新增string target_id = 4;新增UserNamespace userns_options = 5;

5、原有LinuxPodSandboxConfig中原有LinuxSandboxSecurityContext中原有NamespaceOption原有中NamespaceMode新增TARGET
### 3.2、StartContainer
无新增CRI字段
### 3.3、StopContainer
无新增CRI字段
### 3.4、RemoveContainer
无新增CRI字段
### 3.5、ListContainers
	void ListContainers(const runtime::v1alpha2::ContainerFilter *filter,
                    std::vector<std::unique_ptr<runtime::v1alpha2::Container>> *containers, Errors &error);

**新增CRI字段**

Container中原有ImageSpec新增 map<string, string> annotations = 2;
### 3.6、ListContainerStats
 	void ListContainerStats(const runtime::v1alpha2::ContainerStatsFilter *filter,
                            std::vector<std::unique_ptr<runtime::v1alpha2::ContainerStats>> *containerstats,
                            Errors &error);

**新增CRI字段**

ContainerStatsFilter无新增CRI字段，ContainerStats中新增字段如下：

1、原有MemoryUsage新增UInt64Value available_bytes = 3;UInt64Value usage_bytes = 4; UInt64Value rss_bytes = 5;UInt64Value page_faults = 6;UInt64Value major_page_faults = 7;

2、原有CpuUsage新增UInt64Value usage_nano_cores = 3;
## 3.7、ContainerStatus
	auto ContainerStatus(const std::string &containerID, Errors &error)
		-> std::unique_ptr<runtime::v1alpha2::ContainerStatus>;

**新增CRI字段**

ContainerStatus中新增字段ContainerResources resources = 16;
### 3.8、UpdateContainerResources
	void UpdateContainerResources(const std::string &containerID,const runtime::v1alpha2::LinuxContainerResources &resources, Errors &error)

**新增CRI字段**

LinuxContainerResources中新增字段repeated HugepageLimit hugepage_limits = 8;map<string, string> unified = 9;int64 memory_swap_limit_in_bytes = 10;

### 3.9、UpdateRuntimeConfig
无新增CRI字段
### 3.10、Status
无新增CRI字段
### 3.11、Version
无新增CRI字段
### 3.12、ExecSync
无新增CRI字段
### 3.13、Exec
无新增CRI字段
### 3.14、Attach
无新增CRI字段
