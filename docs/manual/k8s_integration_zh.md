# 整合kubernetes

## 配置

1. 配置`isulad`

   在`/etc/isulad/daemon.json`中先配置`pod-sandbox-image` :

   ```json
   "pod-sandbox-image": "my-pause:1.0.0"
   ```

   之后配置`isulad`的 `endpoint`:

   ```json
   "hosts": [
           "unix:///var/run/isulad.sock"
       ]
   ```

   如果`hosts`没有配置，默认的`endpoint`为``unix:///var/run/isulad.sock``

2. 重启`isulad`

   ```bash
   $ sudo systemctl restart isulad
   ```

3. 基于配置或者默认值启动`kubelet`

   ```bash
   $ /usr/bin/kubelet 
   --container-runtime-endpoint=unix:///var/run/isulad.sock
   --image-service-endpoint=unix:///var/run/isulad.sock 
   --pod-infra-container-image=my-pause:1.0.0
   --container-runtime=remote
   ...
   ```

## 使用 RuntimeClass

RuntimeClass 用于选择容器运行时配置从而运行 pod 的容器，RuntimeClass 的具体信息请查看 [runtime-class](https://kubernetes.io/docs/concepts/containers/runtime-class/)。目前，只支持`kata-containers` 和 `runc`这两种`oci runtime`。

1. 在`/etc/isulad/daemon.json`中配置`isulad`

   ```json
   "runtimes": {
           "kata-runtime": {
               "path": "/usr/bin/kata-runtime",
               "runtime-args": [
                   "--kata-config",
                   "/usr/share/defaults/kata-containers/configuration.toml"
               ]
           }
       }
   ```

2. 其他配置

   `isulad`支持`overlay2` 和 `devicemapper`作为存储驱动程序，默认的为`overlay2` 。

   在某些情况下，更适合使用块设备类型作为存储驱动程序，例如运行 `kata-containers`。配置`devicemapper`的过程如下：

   首先创建ThinPool：

   ```bash
   $ sudo pvcreate /dev/sdb1 # /dev/sdb1 for example
   $ sudo vgcreate isulad /dev/sdb
   $ sudo echo y | lvcreate --wipesignatures y -n thinpool isulad -L 200G
   $ sudo echo y | lvcreate --wipesignatures y -n thinpoolmeta isulad -L 20G
   $ sudo lvconvert -y --zero n -c 512K --thinpool isulad/thinpool --poolmetadata isulad/thinpoolmeta
   $ sudo lvchange --metadataprofile isulad-thinpool isulad/thinpool
   ```

   之后在`/etc/isulad/daemon.json`中增加 `devicemapper` 的配置 :

   ```json
   "storage-driver": "devicemapper"
   "storage-opts": [
   		"dm.thinpooldev=/dev/mapper/isulad-thinpool",
   	    "dm.fs=ext4",
   	    "dm.min_free_space=10%"
       ]
   ```

3. 重启`isulad`

   ```bash
   $ sudo systemctl restart isulad
   ```

4. 定义 `kata-runtime.yaml`，例如创建一个`kata-runtime.yaml`内容如下：

   ```yaml
   apiVersion: node.k8s.io/v1beta1
   kind: RuntimeClass
   metadata:
     name: kata-runtime
   handler: kata-runtime
   ```

    之后运行`kubectl apply -f kata-runtime.yaml`命令在kubectl中让这个配置生效。

5. 定义 pod spec `kata-pod.yaml` ，例如创建一个`kata-pod.yaml`，内容如下：

   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: kata-pod-example
   spec:
     runtimeClassName: kata-runtime
     containers:
     - name: kata-pod
       image: busybox:latest
       command: ["/bin/sh"]
       args: ["-c", "sleep 1000"]
   ```

6. 运行 pod

   ```bash
   $ kubectl create -f kata-pod.yaml
   $ kubectl get pod
   NAME               READY   STATUS    RESTARTS   AGE
   kata-pod-example   1/1     Running   4          2s
   ```

## CNI 网络配置

`isulad`实现了CRI接口从而可以连接CNI网络、解析CNI的网络配置文件、加入或者退出CNI网络。在本节中，我们调用 CRI 接口启动 pod 来验证 CNI 网络配置。

1. 在`/etc/isulad/daemon.json`中配置`isulad`：

   ```json
   "network-plugin": "cni",
   "cni-bin-dir": "/opt/cni/bin",
   "cni-conf-dir": "/etc/cni/net.d",
   ```

2. 准备CNI网络的插件：

   编译生成 CNI 插件的二进制文件，并将该二进制文件复制到 `/opt/cni/bin`。

    ```bash
      $ git clone https://github.com/containernetworking/plugins.git
      $ cd plugins && ./build_linux.sh
      $ cd ./bin && ls
      bandwidth bridge dhcp firewall flannel ...
    ```

3. 准备CNI网络的配置：

   配置文件的后缀可以是`.conflist`或者`.conf`，区别在于是否包含多个插件。例如，我们在目录`/etc/cni/net.d/`下创建`10-mynet.conflist`文件，内容如下：

    ```json
      {
          "cniVersion": "0.3.1",
          "name": "default",
          "plugins": [
              {
                  "name": "default",
                  "type": "ptp",
                  "ipMasq": true,
                  "ipam": {
                      "type": "host-local",
                      "subnet": "10.1.0.0/16",
                      "routes": [
                          {
                              "dst": "0.0.0.0/0"
                          }
                      ]
                  }
              },
              {
                  "type": "portmap",
                  "capabilities": {
                      "portMappings": true
                  }
              }
          ]
      }
    ```

4. 配置`sandbox-config.json`：

   ```json
    {
        "port_mappings":[{"protocol": 1, "container_port": 80, "host_port": 8080}],
        "metadata": {
            "name": "test",
            "namespace": "default",
            "attempt": 1,
            "uid": "hdishd83djaidwnduwk28bcsb"
        },
        "labels": {
    	    "filter_label_key": "filter_label_val" 
        },
        "linux": {
        }
    }
   ```

5. 重启`isulad`并且启动pod：

   ```sh
   $ sudo systemctl restart isulad
   $ sudo crictl -i unix:///var/run/isulad.sock -r unix:///var/run/isulad.sock runp sandbox-config.json
   ```

6. 查看pod网络信息：

    ```sh
     $ sudo crictl -i unix:///var/run/isulad.sock -r unix:///var/run/isulad.sock inspectp <pod-id>
    ```