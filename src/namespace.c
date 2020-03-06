/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide namespace functions
 ******************************************************************************/
#include "namespace.h"
#include <string.h>
#include <stdlib.h>

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

static char *parse_share_namespace_with_prefix(const char *path)
{
    char *tmp_cid = NULL;
    char *result = NULL;
    container_t *cont = NULL;

    if (path == NULL) {
        return NULL;
    }

    tmp_cid = connected_container(path);
    if (tmp_cid == NULL) {
        goto out;
    }
    cont = containers_store_get(tmp_cid);
    if (cont == NULL) {
        ERROR("Invalid share path: %s", path);
        goto out;
    }
    result = util_strdup_s(cont->common_config->id);
    container_unref(cont);

out:
    free(tmp_cid);
    return result;
}

char *get_share_namespace_path(const char *type, const char *src_path)
{
    char *tmp_mode = NULL;

    if (is_none(src_path)) {
        tmp_mode = NULL;
    } else if (is_host(src_path)) {
        tmp_mode = get_host_namespace_path(type);
    } else if (is_container(src_path)) {
        tmp_mode = parse_share_namespace_with_prefix(src_path);
    }

    return tmp_mode;
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

