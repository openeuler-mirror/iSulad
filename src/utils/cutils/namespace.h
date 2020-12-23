/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide namespace definition
 ******************************************************************************/
#ifndef __NAMESPACE_H
#define __NAMESPACE_H

#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NAMESPACE_USER = 0,
    NAMESPACE_MNT,
    NAMESPACE_PID,
    NAMESPACE_UTS,
    NAMESPACE_IPC,
    NAMESPACE_NET,
    NAMESPACE_CGROUP,
    NAMESPACE_MAX
} Namespace_Type_t;

#define SHARE_NAMESPACE_PREFIX "container:"
#define SHARE_NAMESPACE_HOST "host"
#define SHARE_NAMESPACE_NONE "none"
#define SHARE_NAMESPACE_SHAREABLE "shareable"
#define SHARE_NAMESPACE_BRIDGE "bridge"
#define SHARE_NAMESPACE_FILE "file"

#define SHARE_NAMESPACE_PID_HOST_PATH "/proc/1/ns/pid"
#define SHARE_NAMESPACE_NET_HOST_PATH "/proc/1/ns/net"
#define SHARE_NAMESPACE_IPC_HOST_PATH "/proc/1/ns/ipc"
#define SHARE_NAMESPACE_UTS_HOST_PATH "/proc/1/ns/uts"
#define SHARE_NAMESPACE_MNT_HOST_PATH "/proc/1/ns/mnt"
#define SHARE_NAMESPACE_USER_HOST_PATH "/proc/1/ns/user"
#define SHARE_NAMESPACE_CGROUP_HOST_PATH "/proc/1/ns/cgroup"

#define TYPE_NAMESPACE_PID "pid"
#define TYPE_NAMESPACE_NETWORK "network"
#define TYPE_NAMESPACE_IPC "ipc"
#define TYPE_NAMESPACE_UTS "uts"
#define TYPE_NAMESPACE_MOUNT "mount"
#define TYPE_NAMESPACE_USER "user"
#define TYPE_NAMESPACE_CGROUP "cgroup"

#define ETC_HOSTS "/etc/hosts"
#define ETC_HOSTNAME "/etc/hostname"
#define RESOLV_CONF_PATH "/etc/resolv.conf"

static inline bool namespace_is_host(const char *mode)
{
    if (mode != NULL && strcmp(mode, SHARE_NAMESPACE_HOST) == 0) {
        return true;
    }
    return false;
}

static inline bool namespace_is_none(const char *mode)
{
    if (mode != NULL && strcmp(mode, SHARE_NAMESPACE_NONE) == 0) {
        return true;
    }
    return false;
}

static inline bool namespace_is_container(const char *mode)
{
    if (mode != NULL && strncmp(mode, SHARE_NAMESPACE_PREFIX, strlen(SHARE_NAMESPACE_PREFIX)) == 0) {
        return true;
    }
    return false;
}

static inline bool namespace_is_bridge(const char *mode)
{
    if (mode != NULL && strcmp(mode, SHARE_NAMESPACE_BRIDGE) == 0) {
        return true;
    }
    return false;
}

static inline bool namespace_is_file(const char *mode)
{
    if (mode != NULL && strcmp(mode, SHARE_NAMESPACE_FILE) == 0) {
        return true;
    }
    return false;
}

static inline bool namespace_is_shareable(const char *mode)
{
    if (mode != NULL && strcmp(mode, SHARE_NAMESPACE_SHAREABLE) == 0) {
        return true;
    }
    return false;
}

static inline bool namespace_is_bridge(const char *mode)
{
    if (mode != NULL && strcmp(mode, SHARE_NAMESPACE_BRIDGE) == 0) {
        return true;
    }
    return false;
}

char *namespace_get_connected_container(const char *mode);
char *namespace_get_host_namespace_path(const char *type);

#ifdef __cplusplus
}
#endif

#endif
