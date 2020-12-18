/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2020-12-05
 * Description: provide cni network functions
 *********************************************************************************/
#include "network_api.h"

#include<isula_libutils/log.h>
#include "manager.h"
#include "utils.h"
#include "map.h"
#include "libcni_types.h"

// do not need lock;
// because cri can make sure do not concurrent to call these apis
typedef struct network_store_t {
    struct cni_network_list_conf **conflist;
    size_t conflist_len;
    map_t *g_net_index_map;
} network_store;

#define DEFAULT_NETWORK_INTERFACE "eth0"

static network_store g_net_store = { 0 };

bool adaptor_cni_check_inited()
{
    return g_net_store.conflist_len > 0;
}

int adaptor_cni_update_confs()
{
    int ret = 0;
    map_t *work = NULL;
    struct cni_network_list_conf **tmp_net_list = NULL;
    size_t tmp_net_list_len = 0;
    size_t i;
    char message[MAX_BUFFER_SIZE] = { 0 };
    int pos = 0;

    if (cri_update_confist_from_dir() != 0) {
        ERROR("update cni manager module failed");
        return -1;
    }

    work = map_new(MAP_STR_INT, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (work == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    // get new conflist data
    ret = cri_get_conflist_from_dir(&tmp_net_list, &tmp_net_list_len);
    if (ret != 0) {
        ERROR("Update new config list failed");
        goto out;
    }
    if (tmp_net_list_len == 0) {
        WARN("No cni config list found");
        goto out;
    }

    for (i = 0; i < tmp_net_list_len; i++) {
        if (!map_replace(work, (void *)tmp_net_list[i]->name, (void *)&i)) {
            ERROR("add net failed");
            ret = -1;
            goto out;
        }
        if (strlen(tmp_net_list[i]->name) + 1 < MAX_BUFFER_SIZE - pos) {
            sprintf(message + pos, "%s,", tmp_net_list[i]->name);
            pos += strlen(tmp_net_list[i]->name) + 1;
        }
    }
    // update current conflist data
    map_free(g_net_store.g_net_index_map);
    g_net_store.g_net_index_map = work;
    work = NULL;

    for (i = 0; i < g_net_store.conflist_len; i++) {
        free_cni_network_list_conf(g_net_store.conflist[i]);
    }
    free(g_net_store.conflist);
    g_net_store.conflist = tmp_net_list;
    g_net_store.conflist_len = tmp_net_list_len;
    tmp_net_list_len = 0;
    tmp_net_list = NULL;

    if (pos > 0) {
        message[pos - 1] = '\0';
    }
    INFO("Loaded cni plugins successfully, [ %s ]", message);
out:
    for (i = 0; i < tmp_net_list_len; i++) {
        free_cni_network_list_conf(tmp_net_list[i]);
    }
    free(tmp_net_list);
    map_free(work);
    return ret;
}

//int attach_network_plane(struct cni_manager *manager, const char *net_list_conf_str);
typedef int (*net_op_t)(const struct cni_manager *manager, const char *net_list_conf_str, struct result **result);

static void prepare_cni_manager(const network_api_conf *conf, struct cni_manager *manager)
{
    manager->annotations = conf->annotations;
    manager->id = conf->pod_id;
    manager->netns_path = conf->netns_path;
    manager->cni_args = conf->args;
}

static int do_append_cni_result(const char *name, const char *interface, const struct result *cni_result,
                                network_api_result_list *result)
{
    struct network_api_result *work = NULL;
    int ret = 0;

    if (cni_result == NULL || result == NULL) {
        return 0;
    }

    if (result->len == result->cap) {
        ERROR("Out of capability of result");
        return -1;
    }

    work = util_common_calloc_s(sizeof(struct network_api_result));
    if (work == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    if (cni_result->ips_len > 0) {
        size_t i;
        work->ips = util_smart_calloc_s(sizeof(char *), cni_result->ips_len);
        if (work->ips == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < cni_result->ips_len; i++) {
            work->ips[work->ips_len] = ipnet_to_string(cni_result->ips[i]->address);
            if (work->ips[work->ips_len] == NULL) {
                WARN("parse cni result ip: %zu failed", i);
                continue;
            }
            work->ips_len += 1;
        }
    }

    work->name = util_strdup_s(name);
    work->interface = util_strdup_s(interface);
    if (cni_result->interfaces_len > 0) {
        work->mac = util_strdup_s(cni_result->interfaces[0]->mac);
    }

    result->items[result->len] = work;
    result->len += 1;
    work = NULL;
out:
    free_network_api_result(work);
    return ret;
}

static int do_foreach_network_op(const network_api_conf *conf, net_op_t op, network_api_result_list *result)
{
    int ret = 0;
    size_t i;
    int default_idx = 0;
    struct cni_manager manager = { 0 };
    const char *default_interface = DEFAULT_NETWORK_INTERFACE;
    struct result *cni_result = NULL;

    if (conf->default_interface != NULL) {
        default_interface = conf->default_interface;
    }

    // Step1, build cni manager config
    prepare_cni_manager(conf, &manager);

    // Step 2, foreach operator for all network plane
    for (i = 0; i < conf->extral_nets_len; i++) {
        int *tmp_idx = NULL;
        if (conf->extral_nets[i] == NULL || conf->extral_nets[i]->name == NULL || conf->extral_nets[i]->interface == NULL) {
            WARN("ignore net idx: %zu", i);
            continue;
        }
        tmp_idx = map_search(g_net_store.g_net_index_map, (void *)conf->extral_nets[i]->name);
        if (tmp_idx == NULL) {
            ERROR("Can not find network: %s", conf->extral_nets[i]->name);
            ret = -1;
            goto out;
        }
        // update interface
        manager.ifname = conf->extral_nets[i]->interface;
        if (strcmp(default_interface, manager.ifname) == 0) {
            default_idx = *tmp_idx;
            continue;
        }

        // clear cni result
        free_result(cni_result);
        cni_result = NULL;

        if (op(&manager, g_net_store.conflist[*tmp_idx]->bytes, &cni_result) != 0) {
            ERROR("Do op on net: %s failed", conf->extral_nets[i]->name);
            ret = -1;
            goto out;
        }
        if (do_append_cni_result(conf->extral_nets[i]->name, conf->extral_nets[i]->interface, cni_result, result) != 0) {
            ERROR("parse cni result failed");
            ret = -1;
            goto out;
        }
    }

    if (g_net_store.conflist_len > 0) {
        free_result(cni_result);
        cni_result = NULL;

        manager.ifname = (char *)default_interface;
        ret = op(&manager, g_net_store.conflist[default_idx]->bytes, &cni_result);
        if (ret != 0) {
            ERROR("Do op on default net: %s failed", g_net_store.conflist[default_idx]->name);
            goto out;
        }

        if (do_append_cni_result(g_net_store.conflist[default_idx]->name, manager.ifname, cni_result, result) != 0) {
            ERROR("parse cni result failed");
            ret = -1;
            goto out;
        }
    }

out:
    free_result(cni_result);
    return ret;
}

int adaptor_cni_setup(const network_api_conf *conf, network_api_result_list *result)
{
    int ret = 0;

    if (conf == NULL) {
        ERROR("Invalid argument");
        return -1;
    }
    if (g_net_store.conflist_len == 0) {
        ERROR("Not found cni networks");
        return -1;
    }

    // first, attach to loopback network
    ret = attach_loopback(conf->pod_id, conf->netns_path);
    if (ret != 0) {
        ERROR("Attach to loop net failed");
        return -1;
    }

    ret = do_foreach_network_op(conf, cri_attach_network_plane, result);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

int adaptor_cni_teardown(const network_api_conf *conf, network_api_result_list *result)
{
    int ret = 0;

    if (conf == NULL) {
        ERROR("Invalid argument");
        return -1;
    }
    if (g_net_store.conflist_len == 0) {
        ERROR("Not found cni networks");
        return -1;
    }

    // first, detach to loopback network
    ret = detach_loopback(conf->pod_id, conf->netns_path);
    if (ret != 0) {
        ERROR("Deatch to loop net failed");
        return -1;
    }

    ret = do_foreach_network_op(conf, cri_detach_network_plane, result);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

