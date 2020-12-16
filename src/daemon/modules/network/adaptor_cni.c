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
#include "adaptor_cni.h"

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

bool adaptor_cni_init(const char *cache_dir, const char *conf_dir, const char* const *bin_paths, size_t bin_paths_len)
{
    if (cni_manager_store_init(cache_dir, conf_dir, bin_paths, bin_paths_len) != 0) {
        ERROR("init cni manager failed");
        return false;
    }

    return adaptor_cni_update_confs() == 0;
}

bool check_cni_inited()
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
        ret = -1;
        ERROR("No cni config list found");
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
    map_free(work);
    return ret;
}

//int attach_network_plane(struct cni_manager *manager, const char *net_list_conf_str);
typedef int (*net_op_t)(const struct cni_manager *manager, const char *net_list_conf_str, struct result **result);

static void prepare_cni_manager(const adaptor_cni_config *conf, struct cni_manager *manager)
{
    manager->annotations = conf->annotations;
    manager->id = conf->pod_id;
    manager->netns_path = conf->netns_path;
    manager->cni_args = conf->args;
}

static int do_foreach_network_op(const adaptor_cni_config *conf, net_op_t op, struct result **result)
{
    int ret = 0;
    size_t i;
    bool need_do_default_net = true;
    struct cni_manager manager = { 0 };
    const char *default_interface = DEFAULT_NETWORK_INTERFACE;

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
            need_do_default_net = false;
        }
        if (op(&manager, g_net_store.conflist[*tmp_idx]->bytes, result) != 0) {
            ERROR("Do op on net: %s failed", conf->extral_nets[i]->name);
            ret = -1;
            goto out;
        }
    }

    if (need_do_default_net && g_net_store.conflist_len > 0) {
        manager.ifname = (char *)default_interface;
        ret = op(&manager, g_net_store.conflist[0]->bytes, result);
        if (ret != 0) {
            ERROR("Do op on default net: %s failed", g_net_store.conflist[0]->name);
            goto out;
        }
    }

out:
    return ret;
}

int adaptor_cni_setup(const adaptor_cni_config *conf)
{
    int ret = 0;
    struct result *result = NULL;

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

    ret = do_foreach_network_op(conf, cri_attach_network_plane, &result);
    if (ret != 0) {
        return -1;
    }

    // TODO: just free result now
    free_result(result);

    return 0;
}

int adaptor_cni_teardown(const adaptor_cni_config *conf)
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

    ret = do_foreach_network_op(conf, cri_detach_network_plane, NULL);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

void free_attach_net_conf(struct attach_net_conf *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->name);
    ptr->name = NULL;
    free(ptr->interface);
    ptr->interface = NULL;
    free(ptr);
}

void free_adaptor_cni_config(adaptor_cni_config *conf)
{
    size_t i;

    if (conf == NULL) {
        return;
    }
    free(conf->name);
    conf->name = NULL;
    free(conf->ns);
    conf->ns = NULL;
    free(conf->pod_id);
    conf->pod_id = NULL;
    free(conf->netns_path);
    conf->netns_path = NULL;
    free(conf->default_interface);
    conf->default_interface = NULL;
    free_json_map_string_string(conf->args);
    conf->args = NULL;
    map_free(conf->annotations);
    conf->annotations = NULL;
    for (i = 0; i < conf->extral_nets_len; i++) {
        free_attach_net_conf(conf->extral_nets[i]);
    }
    free(conf->extral_nets);
    conf->extral_nets = NULL;
    conf->extral_nets_len = 0;

    free(conf);
}
