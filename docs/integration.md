# Integrate kubenetes

## Configuration

1. Configure `isulad`

   Configure the `pod-sandbox-image`  in `/etc/isulad/daemon.json`:

   ```json
   "pod-sandbox-image": "my-pause:1.0.0"
   ```

   Configure the `endpoint`of `isulad`:

   ```json
   "hosts" : [
           "unix:///var/run/isulad.sock"
       ]
   ```

   if `hosts` is not configured, the default endpoint is `unix:///var/run/isulad.sock`.

2. Restart `isulad`:

   ```bash
   $ sudo systemctl restart isulad
   ```

3. Start `kubelet` based on the configuration or default value:

   ```bash
   $ /usr/bin/kubelet 
   --container-runtime-endpoint=unix:///var/run/isulad.sock
   --image-service-endpoint=unix:///var/run/isulad.sock 
   --pod-infra-container-image=my-pause:1.0.0
   ...
   ```

## Use  RuntimeClass

RuntimeClass is used for selecting the container runtime configuration to use to run a pod’s containers, see [runtime-class](https://kubernetes.io/docs/concepts/containers/runtime-class/). Currently, only `kata-containers` and `runc`  this two `oci runtime` are supported.

1. Configure `isulad` in `/etc/isulad/daemon.json`:

   ```json
   "runtimes": {
           "runc":{
               "path": "/usr/bin/runc",
               "runtime-args": []
           },
           "kata-runtime": {
               "path": "/usr/bin/kata-runtime",
               "runtime-args": [
                   "--kata-config",
                   "/usr/share/defaults/kata-containers/configuration.toml"
               ]
           }
       }
   ```

2. Extra configuration

   `iSulad` supports the `overlay2` and `devicemapper` as storage drivers. The default value is `overlay2`.

   In some scenarios, using block device type as storage drivers is a better choice, such as run a `kata-containers`. The procedure for configuring the `devicemapper` is as follows:

   Create ThinPool:

   ```bash
   $ sudo pvcreate /dev/sdb1 # /dev/sdb1 for example
   $ sudo vgcreate isulad /dev/sdb
   $ sudo echo y | lvcreate --wipesignatures y -n thinpool isulad -L 200G
   $ sudo echo y | lvcreate --wipesignatures y -n thinpoolmeta isulad -L 20G
   $ sudo lvconvert -y --zero n -c 512K --thinpool isulad/thinpool --poolmetadata isulad/thinpoolmeta
   $ sudo lvchange --metadataprofile isulad-thinpool isulad/thinpool
   ```

   Add configuration for `devicemapper` in `/etc/isulad/daemon.json`:

   ```json
   "storage-driver": "devicemapper"
   "storage-opts": [
   		"dm.thinpooldev=/dev/mapper/isulad-thinpool",
   	    "dm.fs=ext4",
   	    "dm.min_free_space=10%"
       ]
   ```

3. Restart `isulad`:

   ```bash
   $ sudo systemctl restart isulad
   ```

4. Define `RuntimeClass CRD` for example:

   ```yaml
   apiVersion: node.k8s.io/v1beta1
   kind: RuntimeClass
   metadata:
     name: kata-runtime
   handler: kata-runtime
   ```

5. Define pod spec `kata-pod.yaml` for example:

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
     hostNetwork: true
   ```

6. Run pod:

   ```bash
   $ kubectl create -f kata-pod.yaml
   $ kubectl get pod
   NAME               READY   STATUS    RESTARTS   AGE
   kata-pod-example   1/1     Running   4          2s
   ```

   