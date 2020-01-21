# iSulad Architecture

## Overview

![architecture](design/arch.jpg)

iSulad is an OCI-compliant container running engine that emphasizes simplicity, robustness, and lightweight. 

As a daemon process, it manages the entire container life cycle of the host system, including image transmission and storage, container execution and monitoring management, container resource management, and network management. iSulad provides Docker-like CLI man-machine interfaces for external systems.

You can use Docker-like commands to manage containers and provides gRPC APIs that comply with the CRI interface standard for Kubernetes to invoke based on the CRI interface protocol. 

For easily understanding, the behavior unit of the iSulad is divided into different modules, and the modules are roughly organized into subsystems. Understanding these modules, subsystems, and their relationships is key to modifying and extending iSulad. 

This document describes only the high-level function design of each module. For more information about each module, see the relevant design documents. 

## Subsystem

You can interact with the iSulad by calling  gRPC APIs provided by the subsystem. 

- **image service** :   Image management service, which provides image-related operations, such as image download, query, and deletion. 
- **execution service**:  Container life cycle management service, which provides container-related operations, such as container creation, startup, and deletion. 
- **network**：The network subsystem is responsible for network management capabilities of the pod of the CRI. When a pod is started, the pod is added to the network plane specified in the configuration file through the CNI interface. When a pod is stopped, the CNI API is used to remove the pod from the network plane where the pod is located and clear related network resources. 

## Module 

- **image content** :   Managing Image Metadata and Container File Systems 

- **resource manage**:  Container resource management, for example, setting available CPU and memory resource limits 

- **Executor**：Runtime for executing actual container operations. The LCR is provided as the default runtime and can be extended through the plug-in mechanism. 

- **Events**：Container event collection 

- **Plugins**：Provides the plugin mechanism to extend container functions through different plugins.

- **HA**：The log mechanism is provided for fault locating. The garbage collection mechanism is provided to reclaim abnormal container resources such as D and Z. 

### Network architecture design 

The following figure shows the architecture:

![CNI_architecture](./design/CNI_architecture.png)
