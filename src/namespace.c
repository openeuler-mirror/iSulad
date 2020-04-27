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
 * Description: provide namespace functions
 ******************************************************************************/
#include "namespace.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "log.h"
#include "utils.h"
#include "containers_store.h"


char *connected_container(const char *mode)
{
    const char *p = mode != NULL ? (mode + strlen(SHARE_NAMESPACE_PREFIX)) : NULL;

    if (is_container(mode)) {
        return util_strdup_s(p);
    }

    return NULL;
}

static char *get_host_namespace_path(const char *type)
{
    if (type == NULL) {
        return NULL;
    }
    if (strcmp(type, TYPE_NAMESPACE_PID) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_PID_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_NETWORK) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_NET_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_IPC) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_IPC_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_UTS) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_UTS_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_MOUNT) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_MNT_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_USER) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_USER_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_CGROUP) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_CGROUP_HOST_PATH);
    }
    return NULL;
}

static char *parse_share_namespace_with_prefix(const char *type, const char *path)
{
    char *tmp_cid = NULL;
    char *result = NULL;
    container_t *cont = NULL;
    int pid;
    int ret = 0;
    char ns_path[PATH_MAX] = { 0 };
    char *ns_type = NULL;

    tmp_cid = connected_container(path);
    if (tmp_cid == NULL) {
        goto out;
    }
    cont = containers_store_get(tmp_cid);
    if (cont == NULL) {
        ERROR("Invalid share path: %s", path);
        goto out;
    }

    if (!is_running(cont->state)) {
        ERROR("Can not join namespace of a non running container %s", tmp_cid);
        isulad_set_error_message("Can not join namespace of a non running container %s", tmp_cid);
        goto out;
    }

    if (is_restarting(cont->state)) {
        ERROR("Container %s is restarting, wait until the container is running", tmp_cid);
        isulad_set_error_message("Container %s is restarting, wait until the container is running", tmp_cid);
        goto out;
    }

    pid = state_get_pid(cont->state);
    if (pid < 1 || kill(pid, 0) < 0) {
        ERROR("Container %s pid %d invalid", tmp_cid, pid);
        goto out;
    }

    if (strcmp(type, TYPE_NAMESPACE_NETWORK) == 0) {
        ns_type = util_strdup_s("net");
    } else if (strcmp(type, TYPE_NAMESPACE_MOUNT) == 0) {
        ns_type = util_strdup_s("mnt");
    } else {
        ns_type = util_strdup_s(type);
    }

    ret = snprintf(ns_path, PATH_MAX, "/proc/%d/ns/%s", pid, ns_type);
    if (ret < 0 || (size_t)ret >= PATH_MAX) {
        ERROR("Failed to print string %s", ns_type);
        goto out;
    }

    result = util_strdup_s(ns_path);

out:
    container_unref(cont);
    free(tmp_cid);
    free(ns_type);
    return result;
}

int get_share_namespace_path(const char *type, const char *src_path, char **dest_path)
{
    int ret = 0;

    if (type == NULL || dest_path == NULL) {
        return -1;
    }

    if (is_none(src_path)) {
        *dest_path = NULL;
    } else if (is_host(src_path)) {
        *dest_path = get_host_namespace_path(type);
        if (*dest_path == NULL) {
            ret = -1;
        }
    } else if (is_container(src_path)) {
        *dest_path = parse_share_namespace_with_prefix(type, src_path);
        if (*dest_path == NULL) {
            ret = -1;
        }
    }

    return ret;
}

char *get_container_process_label(const char *cid)
{
    char *result = NULL;
    container_t *cont = NULL;

    if (cid == NULL) {
        return NULL;
    }

    cont = containers_store_get(cid);
    if (cont == NULL) {
        ERROR("Invalid share path: %s", cid);
        goto out;
    }
    result = util_strdup_s(cont->common_config->process_label);
    container_unref(cont);

out:
    return result;
}

