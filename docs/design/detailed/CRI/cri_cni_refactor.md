| Author | 程泽睿志                                       |
| ------ | ---------------------------------------------------- |
| Date   | 2021-12-30                                           |
| Email  | [chengzeruizhi@huawei.com](chengzeruizhi@huawei.com) |

# 1. Refactoring Purpose

The process of starting a pod before refactoring is to create the container first, and then the network namespace is created by the container runtime. After the container is running, use the CNI plugin to configure the network namespace. This process is different from containerd's implementation, and is not compatible with secure containers. Secure containers involve communication between the virtual machine and the host, and thus require a network namespace to be available before the container can run. The existing process cannot meet this requirement, which makes it necessary to refactor the pod startup process.

The refactored pod startup process should have the following operations:

- Proactively create network namespaces if needed;
- Configure the network first, that is, set the network of the namespace through the CNI plugin;
- When starting the container, specify the network namespace of the pod container as the configured namespace.

After the modification, it is required to be compatible with the security container (kata) and to ensure the existing functions.

# 2. Refactoring Scheme

There are three main problems during refactoring, one is how to avoid conflicts with the client's starting container process; the other is how to save the path of the namespace; the third is how to deal with resource recycling after introducing new data and files.

The solution is as follows:

## 2.1 how to avoid conflicts with the client to start the container process

- Introduce a new network mode: cni, as the default mode when CRI starts pods.

## 2.2 how to save the path of the namespace

- Add the sandbox key as the path to the self-created network namespace in the network settings. When creating a pod, a thread creates a new file in this path and mounts the thread network space to the file to achieve persistence;

- The network settings need to be dropped to prevent iSulad from restarting;

- If the network mode is cni, the sandbox key should also be included in the inspect.

## 2.3 resource recovery

- After refactoring, the startup process is as follows:
  1. After receiving the request, start to create a pod, parse the request, generate the configuration and place it on the disk, etc. At this time, the sandbox key will be generated, and a file will be created under /var/run/netns;
  2. Set the network to ready;
  3. Network namespace mount;
  4. Pass the namespace path to the CNI plugin through annotation to configure the pod network;
  5. When starting the container, get the network namespace path from the runtime data structure (in the network settings of container_t) and hand it over to the lower-level container runtime to make the pod run in the self-generated network namespace.
- According to this process, the resource recovery strategy is as follows:
  1. When deleting a container, umount the namespace first, and then delete the file;
  2. Corresponding to the logic of startup, clean up the cni network when stopping the pod. If successful, umount the namespace, but do not delete the file;
  3. The exception handling also corresponds to the startup logic. If an exception occurs in a startup step, only the existing resources before that step are cleaned up.

# 3. Contrast Differences

## 3.1 timing diagram

![Sequence before reconstruction](../../../images/sequencebefore.png)

Timing diagram before reconstruction

![Sequence after reconstruction](../../../images/sequenceafter.png)

Timing diagram after reconstruction

## 3.2 network Settings

````json
{
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "Bridge": {
            "type": "string"
        },
        "SandboxID": {
           "type": "string"
        },
        "LinkLocalIPv6Address": {
            "type": "string"
        },
        "LinkLocalIPv6PrefixLen": {
            "type": "integer"
        },
        "Ports": {
            "$ref": "../defs.json#/definitions/mapStringObjectPortBindings"
        },
        "CNIPorts": {
            "$ref": "../cni/anno_port_mappings.json"
        },
        "SandboxKey": {
            "type": "string"
        },
        "EndpointID": {
            "type": "string"
        },
        "Gateway": {
            "type": "string"
        },
        "GlobalIPv6Address": {
            "type": "string"
        },
        "GlobalIPv6PrefixLen": {
            "type": "integer"
        },
        "IPAddress": {
            "type": "string"
        },
        "IPPrefixLen": {
            "type": "integer"
        },
        "IPv6Gateway": {
            "type": "string"
        },
        "MacAddress": {
            "type": "string"
        },
        "Activation": {
            "type": "boolean"
        },
        "Networks": {
            "$ref": "../defs.json#/definitions/mapStringObjectNetworks"
        }
    }
}
````