/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-06-11
 * Description: provide namespace spec definition
 ******************************************************************************/
#include "specs_namespace.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <isula_libutils/log.h>
#include <isula_libutils/container_config_v2.h>

#include "utils.h"
#include "utils_network.h"
#include "namespace.h"
#include "container_api.h"
#include "err_msg.h"
#include "network_namespace_api.h"

static char *parse_share_namespace_with_prefix(const char *type, const char *path)
{
    char *tmp_cid = NULL;
    char *result = NULL;
    container_t *cont = NULL;
    int pid;
    int ret = 0;
    char ns_path[PATH_MAX] = { 0 };
    char *ns_type = NULL;

    tmp_cid = namespace_get_connected_container(path);
    if (tmp_cid == NULL) {
        goto out;
    }
    cont = containers_store_get(tmp_cid);
    if (cont == NULL) {
        ERROR("Invalid share path: %s", path);
        goto out;
    }

    if (!container_is_running(cont->state)) {
        ERROR("Can not join namespace of a non running container %s", tmp_cid);
        isulad_set_error_message("Can not join namespace of a non running container %s", tmp_cid);
        goto out;
    }

    if (container_is_restarting(cont->state)) {
        ERROR("Container %s is restarting, wait until the container is running", tmp_cid);
        isulad_set_error_message("Container %s is restarting, wait until the container is running", tmp_cid);
        goto out;
    }

    pid = container_state_get_pid(cont->state);
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

    if (namespace_is_none(src_path)) {
        *dest_path = NULL;
    } else if (namespace_is_host(src_path)) {
        *dest_path = namespace_get_host_namespace_path(type);
        if (*dest_path == NULL) {
            ret = -1;
        }
    } else if (namespace_is_container(src_path)) {
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

typedef int (*namespace_mode_check)(const host_config *host_spec,
                                    const container_network_settings *network_settings,
                                    const char *type, char **dest_path);

struct get_netns_path_handler {
    char *mode;
    namespace_mode_check handle;
};

static int handle_get_path_from_none(const host_config *host_spec,
                                     const container_network_settings *network_settings,
                                     const char *type, char **dest_path)
{
    *dest_path = NULL;
    return 0;
}

static int handle_get_path_from_host(const host_config *host_spec,
                                     const container_network_settings *network_settings,
                                     const char *type, char **dest_path)
{
    *dest_path = namespace_get_host_namespace_path(type);
    if (*dest_path == NULL) {
        return -1;
    }
    return 0;
}

static int handle_get_path_from_container(const host_config *host_spec,
                                          const container_network_settings *network_settings, const char *type,
                                          char **dest_path)
{
    *dest_path = parse_share_namespace_with_prefix(type, host_spec->network_mode);
    if (*dest_path == NULL) {
        return -1;
    }
    return 0;
}

static int handle_get_path_from_file(const host_config *host_spec,
                                     const container_network_settings *network_settings,
                                     const char *type, char **dest_path)
{
    if (network_settings == NULL || network_settings->sandbox_key == NULL) {
        ERROR("Invalid sandbox key for file mode network");
        return -1;
    }

    *dest_path = util_strdup_s(network_settings->sandbox_key);
    return 0;
}

#ifdef ENABLE_NATIVE_NETWORK
static int handle_get_path_from_bridge(const host_config *host_spec,
                                     const container_network_settings *network_settings,
                                     const char *type, char **dest_path)
{

    if (host_spec->system_container || util_post_setup_network(host_spec->user_remap)) {
        *dest_path = NULL;
        return 0;
    }

    if (network_settings == NULL || network_settings->sandbox_key == NULL) {
        ERROR("Invalid sandbox key for bridge network");
        return -1;
    }

    *dest_path = util_strdup_s(network_settings->sandbox_key);
    return 0;
}
#endif

int get_network_namespace_path(const host_config *host_spec,
                               const container_network_settings *network_settings,
                               const char *type, char **dest_path)
{
    int index;
    int ret = -1;
    struct get_netns_path_handler handler_jump_table[] = {
        { SHARE_NAMESPACE_NONE, handle_get_path_from_none },
        { SHARE_NAMESPACE_HOST, handle_get_path_from_host },
        { SHARE_NAMESPACE_PREFIX, handle_get_path_from_container },
        { SHARE_NAMESPACE_FILE, handle_get_path_from_file },
#ifdef ENABLE_NATIVE_NETWORK
        { SHARE_NAMESPACE_BRIDGE, handle_get_path_from_bridge },
#endif
    };
    size_t jump_table_size = sizeof(handler_jump_table) / sizeof(handler_jump_table[0]);
    const char *network_mode = host_spec->network_mode;

    if (network_mode == NULL || dest_path == NULL) {
        return -1;
    }

    for (index = 0; index < jump_table_size; ++index) {
        if (strncmp(network_mode, handler_jump_table[index].mode, strlen(handler_jump_table[index].mode)) == 0) {
            ret = handler_jump_table[index].handle(host_spec, network_settings, type, dest_path);
            if (ret != 0) {
                ERROR("Failed to get ns path, network mode is %s, type is %s", network_mode, type);
            }
            return ret;
        }
    }

    return ret;
}
