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
 * Author: gaohuatao
 * Create: 2020-11-09
 * Description: provide CNI network manager function definition
 ******************************************************************************/
#include "cni_operate.h"

#include <pthread.h>
#include <sys/types.h>

#include "isula_libutils/log.h"
#include "isula_libutils/cni_net_conf.h"
#include "isula_libutils/cni_net_conf_list.h"
#include "isula_libutils/cni_anno_port_mappings.h"
#include "utils.h"
#include "utils_network.h"

#define LO_IFNAME "lo"

typedef int (*annotation_add_cap_t)(const char *value, struct runtime_conf *);
typedef int (*annotation_add_json_t)(const char *value, const struct cni_network_list_conf *old,
                                     struct cni_network_list_conf **p_new);

struct anno_registry_conf_rt {
    char *name;
    annotation_add_cap_t ops;
};

struct anno_registry_conf_json {
    char *name;
    annotation_add_json_t ops;
};

typedef struct cni_manager_store_t {
    char *conf_path;
    struct cni_network_list_conf *loopback_conf;
} cni_manager_store_t;

#define LOOPBACK_CONFLIST_STR "{\"cniVersion\": \"0.3.1\", \"name\": \"cni-loopback\",\"plugins\":[{\"type\": \"loopback\" }]}"

static cni_manager_store_t g_cni_manager;

static void parse_inner_portmapping(const cni_inner_port_mapping *src, struct cni_port_mapping *dst)
{
    if (src->protocol != NULL) {
        dst->protocol = util_strdup_s(src->protocol);
    }
    if (src->host_ip != NULL) {
        dst->host_ip = util_strdup_s(src->host_ip);
    }
    dst->container_port = src->container_port;
    dst->host_port = src->host_port;
}

static int bandwidth_inject(const char *value, struct runtime_conf *rt)
{
    int ret = 0;
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    cni_bandwidth_entry *bwith = NULL;

    if (value == NULL || rt == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    bwith = cni_bandwidth_entry_parse_data(value, &ctx, &err);
    if (bwith == NULL) {
        ERROR("Failed to parse bandwidth datas from value:%s, err:%s", value, err);
        ret = -1;
        goto out;
    }

    rt->bandwidth = bwith;
    bwith = NULL;

out:
    free(err);
    return ret;
}

static int copy_port_mapping_from_anno(const cni_anno_port_mappings_element *src, struct cni_port_mapping *dst)
{
    if (src == NULL) {
        ERROR("Invalid param");
        return -1;
    }

    if (src->protocol != NULL) {
        dst->protocol = util_strdup_s(src->protocol);
    }
    if (src->host_ip != NULL) {
        dst->host_ip = util_strdup_s(src->host_ip);
    }
    dst->container_port = src->container_port;
    dst->host_port = src->host_port;

    return 0;
}

static int port_mappings_inject(const char *value, struct runtime_conf *rt)
{
    int ret = 0;
    size_t i = 0;
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    cni_anno_port_mappings_container *anno_p = NULL;
    struct cni_port_mapping **new_p = NULL;
    size_t new_len = 0;

    if (value == NULL || rt == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    anno_p = cni_anno_port_mappings_container_parse_data(value, &ctx, &err);
    if (anno_p == NULL) {
        ERROR("Failed to parse port mapping datas from value:%s, err:%s", value, err);
        ret = -1;
        goto out;
    }

    if (anno_p->len == 0) {
        WARN("No port mapping found, just do nothing");
        goto out;
    }

    new_p = (struct cni_port_mapping **)util_smart_calloc_s(sizeof(struct cni_port_mapping *), anno_p->len);
    if (new_p == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < anno_p->len; i++) {
        new_p[i] = (struct cni_port_mapping *)util_smart_calloc_s(sizeof(struct cni_port_mapping), 1);
        if (new_p[i] == NULL) {
            ERROR("Out of memory, calloc failed");
            ret = -1;
            goto free_out;
        }
        new_len++;

        if (copy_port_mapping_from_anno(anno_p->items[i], new_p[i]) != 0) {
            ERROR("Copy port mapping from annotations failed");
            ret = -1;
            goto free_out;
        }
    }

    rt->p_mapping = new_p;
    new_p = NULL;
    rt->p_mapping_len = new_len;
    new_len = 0;

free_out:
    for (i = 0; i < new_len; i++) {
        free_cni_port_mapping(new_p[i]);
        new_p[i] = NULL;
    }
    free(new_p);

out:
    free(err);
    free_cni_anno_port_mappings_container(anno_p);
    return ret;
}

static int ip_ranges_inject(const char *value, struct runtime_conf *rt)
{
    int ret = -1;
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    cni_ip_ranges_array_container *ip_ranges = NULL;

    if (value == NULL || rt == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    ip_ranges = cni_ip_ranges_array_container_parse_data(value, &ctx, &err);
    if (ip_ranges == NULL) {
        ERROR("Failed to parse ip ranges data from value:%s, err:%s", value, err);
        ret = -1;
        goto out;
    }

    rt->ip_ranges = ip_ranges;
    ip_ranges = NULL;

out:
    free(err);
    return ret;
}

static struct anno_registry_conf_rt g_registrant_rt[] = {
    { .name = CNI_ARGS_BANDWIDTH_KEY, .ops = bandwidth_inject },
    { .name = CNI_ARGS_PORTMAPPING_KEY, .ops = port_mappings_inject },
    { .name = CNI_ARGS_IPRANGES_KEY, .ops = ip_ranges_inject },
};

static struct anno_registry_conf_json g_registrant_json[] = {
    // Whitelist of appending to net_list_conf_str
};

static const size_t g_numregistrants_rt = sizeof(g_registrant_rt) / sizeof(struct anno_registry_conf_rt);
static const size_t g_numregistrants_json = sizeof(g_registrant_json) / sizeof(struct anno_registry_conf_json);

static struct cni_network_list_conf *load_cni_config_file_list(const char *fname)
{
    int ret = 0;
    struct cni_network_conf *n_conf = NULL;
    struct cni_network_list_conf *n_list = NULL;

    if (fname == NULL) {
        ERROR("Invalid NULL params");
        return NULL;
    }

    if (util_has_suffix(fname, ".conflist")) {
        n_list = cni_conflist_from_file(fname);
        if (n_list == NULL) {
            ERROR("Error loading CNI config list file %s", fname);
            ret = -1;
            goto out;
        }
    } else {
        n_conf = cni_conf_from_file(fname);
        if (n_conf == NULL || n_conf->network == NULL) {
            ERROR("Error loading CNI config file %s", fname);
            ret = -1;
            goto out;
        }

        if (!util_valid_str(n_conf->network->type)) {
            ERROR("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", fname);
            ret = -1;
            goto out;
        }

        n_list = cni_conflist_from_conf(n_conf);
        if (n_list == NULL) {
            ERROR("Error converting CNI config file %s to list", fname);
            ret = -1;
            goto out;
        }
    }

    if (n_list->list->name == NULL || strcmp(n_list->list->name, "") == 0) {
        free(n_list->list->name);
        n_list->list->name = util_path_base(fname);
    }

    // to compatibility for old version of clibcni
    if (!util_validate_network_name(n_list->list->name)) {
        ERROR("Invalid network name: %s", n_list->list->name);
        ret = -1;
        goto out;
    }

out:
    free_cni_network_conf(n_conf);

    if (ret != 0) {
        free_cni_network_list_conf(n_list);
        n_list = NULL;
    }

    return n_list;
}

// Try my best to load file, when error occured, just skip and continue
static int update_conflist_from_files(struct cni_network_list_conf **conflists, const char **files, size_t files_num,
                                      size_t *nets_num, cni_conf_filter_t filter_ops)
{
    size_t i = 0;
    int ret = 0;
    char *fname = NULL;

    if (nets_num == NULL) {
        ERROR("Invalid input parmas");
        return -1;
    }

    if (g_cni_manager.conf_path == NULL) {
        ERROR("CNI conf path is null");
        return -1;
    }

    *nets_num = 0;
    for (i = 0; i < files_num; i++) {
        struct cni_network_list_conf *n_list = NULL;

        UTIL_FREE_AND_SET_NULL(fname);
        fname = util_path_base(files[i]);
        if (fname == NULL) {
            ERROR("Get file name from full path:%s failed", files[i]);
            ret = -1;
            goto out;
        }

        if (filter_ops != NULL && !filter_ops(fname)) {
            DEBUG("Net config file:%s donot match, skip", fname);
            continue;
        }

        n_list = load_cni_config_file_list(files[i]);
        if (n_list == NULL) {
            WARN("Load cni network conflist from file:%s failed", files[i]);
            continue;
        }

        if (n_list->list == NULL || n_list->list->plugins_len == 0) {
            WARN("CNI config list %s has no networks, skipping", files[i]);
            free_cni_network_list_conf(n_list);
            continue;
        }

        // TODO: check plugins of config

        DEBUG("parse cni network: %s", n_list->list->name);

        conflists[*nets_num] = n_list;
        (*nets_num)++;
    }

out:
    free(fname);
    return ret;
}

static void free_conflists_data(struct cni_network_list_conf **conflist, size_t len)
{
    size_t i = 0;

    if (conflist == NULL) {
        return;
    }

    for (i = 0; i < len; i++) {
        free_cni_network_list_conf(conflist[i]);
        conflist[i] = NULL;
    }
    free(conflist);
}

// Lexicographical order in ascending order
static int cmpstr(const void *a, const void *b)
{
    return strcmp(*((const char **)a), *((const char **)b));
}

static int get_conf_files(char ***files, size_t *length)
{
    int ret = 0;
    const char *exts[] = { ".conf", ".conflist", ".json" };

    if (files == NULL || length == NULL) {
        ERROR("Input params");
        return -1;
    }

    if (g_cni_manager.conf_path == NULL) {
        ERROR("CNI conf path is null");
        return -1;
    }

    if (cni_conf_files(g_cni_manager.conf_path, exts, sizeof(exts) / sizeof(char *), files) != 0) {
        ERROR("Get conf files from dir:%s failed", g_cni_manager.conf_path);
        ret = -1;
        goto out;
    }

    *length = util_array_len((const char **)*files);
    if (*length == 0) {
        WARN("No network conf files found");
        goto out;
    }

    qsort(*files, *length, sizeof(char *), cmpstr);

out:
    return ret;
}

int get_net_conflist_from_dir(struct cni_network_list_conf ***store, size_t *res_len, cni_conf_filter_t filter_ops)
{
    int ret = 0;
    size_t files_num = 0;
    size_t nets_num = 0;
    char **files = NULL;
    struct cni_network_list_conf **tmp_conflists = NULL;

    if (store == NULL || res_len == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    if (get_conf_files(&files, &files_num) != 0) {
        ERROR("Get cni conf files in ascending order failed");
        ret = -1;
        goto out;
    }

    if (files_num == 0) {
        goto out;
    }

    tmp_conflists =
        (struct cni_network_list_conf **)util_smart_calloc_s(sizeof(struct cni_network_list_conf *), files_num);
    if (tmp_conflists == NULL) {
        ERROR("Out of memory, cannot allocate mem to store conflists");
        ret = -1;
        goto out;
    }

    if (update_conflist_from_files(tmp_conflists, (const char **)files, files_num, &nets_num, filter_ops) != 0) {
        ERROR("Update conflist from files failed");
        free_conflists_data(tmp_conflists, nets_num);
        ret = -1;
        goto out;
    }

    *store = tmp_conflists;
    tmp_conflists = NULL;
    *res_len = nets_num;

out:
    util_free_array_by_len(files, files_num);
    return ret;
}

static struct runtime_conf *build_loopback_runtime_conf(const char *cid, const char *netns_path)
{
    struct runtime_conf *rt = NULL;

    if (cid == NULL || netns_path == NULL) {
        ERROR("Invalid input params");
        return NULL;
    }

    rt = util_smart_calloc_s(sizeof(struct runtime_conf), 1);
    if (rt == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    rt->container_id = util_strdup_s(cid);
    rt->netns = util_strdup_s(netns_path);
    rt->ifname = util_strdup_s(LO_IFNAME);

out:
    return rt;
}

// inject runtime_conf args from annotation
static int inject_annotations_runtime_conf(map_t *annotations, struct runtime_conf *rt)
{
    int ret = 0;
    size_t i = 0;
    char *value = NULL;

    if (rt == NULL) {
        ERROR("Invalid input param");
        return -1;
    }
    if (annotations == NULL) {
        DEBUG("No annotations data to parse");
        goto out;
    }

    for (i = 0; i < g_numregistrants_rt; i++) {
        value = map_search(annotations, (void *)g_registrant_rt[i].name);
        if (value == NULL) {
            DEBUG("This key:%s is not found", g_registrant_rt[i].name);
            continue;
        }

        if (g_registrant_rt[i].ops(value, rt) != 0) {
            ERROR("The format of annotation is not right with key:%s, value:%s", g_registrant_rt[i].name, value);
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

// inject cni net conflist json from annotation
static int inject_annotations_json(map_t *annotations, const struct cni_network_list_conf *old,
                                   struct cni_network_list_conf **p_new)
{
    int ret = 0;
    size_t i = 0;
    char *value = NULL;

    if (annotations == NULL) {
        DEBUG("Empty extension configs");
        return 0;
    }

    if (old == NULL || p_new == NULL) {
        ERROR("Invalid input param");
        return -1;
    }

    for (i = 0; i < g_numregistrants_json; i++) {
        value = map_search(annotations, (void *)g_registrant_json[i].name);
        if (value == NULL) {
            DEBUG("This key:%s is not surpported", g_registrant_json[i].name);
            continue;
        }

        if (g_registrant_json[i].ops(value, old, p_new) != 0) {
            ERROR("The format of annotation is not right with key:%s, value:%s", g_registrant_json[i].name, value);
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int inject_cni_args_into_runtime_conf(const struct cni_manager *manager, struct runtime_conf *rt)
{
    size_t i = 0;

    if (manager->cni_args == NULL || manager->cni_args->len == 0) {
        WARN("No cni args found");
        return 0;
    }

    rt->args = (char *(*)[2])util_smart_calloc_s(sizeof(char *) * 2, manager->cni_args->len);
    if (rt->args == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    rt->args_len = manager->cni_args->len;
    for (i = 0; i < manager->cni_args->len; i++) {
        rt->args[i][0] = util_strdup_s(manager->cni_args->keys[i]);
        rt->args[i][1] = util_strdup_s(manager->cni_args->values[i]);
    }

    return 0;
}

static struct runtime_conf *build_cni_runtime_conf(const struct cni_manager *manager)
{
    int ret = 0;
    struct runtime_conf *rt = NULL;

    rt = (struct runtime_conf *)util_smart_calloc_s(sizeof(struct runtime_conf), 1);
    if (rt == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    rt->container_id = util_strdup_s(manager->id);
    rt->netns = util_strdup_s(manager->netns_path);
    rt->ifname = util_strdup_s(manager->ifname);

    if (inject_cni_args_into_runtime_conf(manager, rt) != 0) {
        ERROR("Inject cni args to runtime conf failed");
        ret = -1;
        goto out;
    }

    if (inject_annotations_runtime_conf(manager->annotations, rt) != 0) {
        ERROR("Inject annotations to runtime conf failed");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free_runtime_conf(rt);
        rt = NULL;
    }
    return rt;
}

// setup container loopback
int attach_loopback(const char *id, const char *netns)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    struct cni_opt_result *lo_result = NULL;

    if (id == NULL || netns == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    rc = build_loopback_runtime_conf(id, netns);
    if (rc == NULL) {
        ERROR("Error building loopback runtime config");
        ret = -1;
        goto out;
    }

    if (cni_add_network_list(g_cni_manager.loopback_conf, rc, &lo_result) != 0) {
        ERROR("Add loopback network failed");
        ret = -1;
        goto out;
    }

out:
    free_cni_opt_result(lo_result);
    free_runtime_conf(rc);
    return ret;
}

static int update_runtime_conf_portmappings_by_cached(cni_cached_info *info, struct runtime_conf *rc)
{
    size_t i = 0;
    struct cni_port_mapping **tmp_ports = NULL;
    size_t tmp_ports_len = 0;

    if (info->port_mappings_len == 0) {
        return 0;
    }
    tmp_ports = util_smart_calloc_s(sizeof(struct cni_port_mapping), info->port_mappings_len);
    if (tmp_ports == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < info->port_mappings_len; i++) {
        tmp_ports[i] = util_common_calloc_s(sizeof(struct cni_port_mapping));
        if (tmp_ports[i] == NULL) {
            ERROR("Out of memory");
            goto err_out;
        }
        tmp_ports_len++;
        parse_inner_portmapping(info->port_mappings[i], tmp_ports[i]);
    }
    for (i = 0; i < rc->p_mapping_len; i++) {
        free_cni_port_mapping(rc->p_mapping[i]);
    }
    free(rc->p_mapping);
    rc->p_mapping = tmp_ports;
    rc->p_mapping_len = tmp_ports_len;
    return 0;
err_out:
    for (i = 0; i < tmp_ports_len; i++) {
        free_cni_port_mapping(tmp_ports[i]);
    }
    free(tmp_ports);
    return -1;
}

static int update_runtime_conf_cni_args_by_cached(cni_cached_info *info, struct runtime_conf *rc)
{
    size_t i = 0;
    char *(*tmp_args)[2] = NULL;

    if (info->cni_args == NULL || info->cni_args->len == 0) {
        return 0;
    }
    tmp_args = util_smart_calloc_s(sizeof(char *) * 2, info->cni_args->len);
    if (tmp_args == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < info->cni_args->len; i++) {
        tmp_args[i][0] = util_strdup_s(info->cni_args->keys[i]);
        tmp_args[i][1] = util_strdup_s(info->cni_args->values[i]);
    }

    for (i = 0; i < rc->args_len; i++) {
        free(rc->args[i][0]);
        free(rc->args[i][1]);
    }
    free(rc->args);
    rc->args = tmp_args;
    rc->args_len = info->cni_args->len;
    return 0;
}

static int get_configs_from_cached(const char *network, struct runtime_conf *rc, char **conf_list)
{
    int ret = 0;
    cni_cached_info *info = NULL;

    info = cni_get_network_list_cached_info(network, rc);
    if (info == NULL) {
        return 0;
    }

    // check cache data is valid
    if (info->network_name == NULL || strcmp(network, info->network_name) != 0) {
        WARN("Invalid cached config: %s, ignore it", info->network_name != NULL ? info->network_name : "");
        goto out;
    }

    // step 1: update cni_args;
    if (update_runtime_conf_cni_args_by_cached(info, rc) != 0) {
        ret = -1;
        goto out;
    }
    // step 2: update capabilities
    // step 2.1: update portmappings
    if (update_runtime_conf_portmappings_by_cached(info, rc) != 0) {
        ret = -1;
        goto out;
    }
    // step 2.2: update bandwidth
    free_cni_bandwidth_entry(rc->bandwidth);
    rc->bandwidth = info->bandwidth;
    info->bandwidth = NULL;

    // step 2.3: update ip ranges
    if (info->ip_ranges != NULL && info->ip_ranges_len > 0) {
        cni_ip_ranges_array_container *tmp_ip_ranges = util_common_calloc_s(sizeof(cni_ip_ranges_array_container));
        if (tmp_ip_ranges == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        tmp_ip_ranges->items = info->ip_ranges;
        info->ip_ranges = NULL;
        tmp_ip_ranges->len = info->ip_ranges_len;
        info->ip_ranges_len = 0;
        tmp_ip_ranges->subitem_lens = info->ip_ranges_item_lens;
        info->ip_ranges_item_lens = NULL;
    }

    // step 3: return config list string
    if (conf_list != NULL) {
        *conf_list = info->config;
        info->config = NULL;
    }

out:
    free_cni_cached_info(info);
    return ret;
}

int attach_network_plane(const struct cni_manager *manager, const struct cni_network_list_conf *list,
                         struct cni_opt_result **result)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    struct cni_network_list_conf *use_list = NULL;

    if (manager == NULL || list == NULL || result == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    rc = build_cni_runtime_conf(manager);
    if (rc == NULL) {
        ERROR("Error building CNI runtime config");
        ret = -1;
        goto out;
    }

    if (inject_annotations_json(manager->annotations, list, &use_list) != 0) {
        ERROR("Inject annotations to net conf json failed");
        ret = -1;
        goto out;
    }

    if (cni_add_network_list(list, rc, result) != 0) {
        ERROR("Add CNI network failed");
        ret = -1;
        goto out;
    }

out:
    free_runtime_conf(rc);
    free_cni_network_list_conf(use_list);
    return ret;
}

int check_network_plane(const struct cni_manager *manager, const struct cni_network_list_conf *list,
                        struct cni_opt_result **result)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    struct cni_network_list_conf *use_list = NULL;

    if (manager == NULL || list == NULL || list->list == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    rc = build_cni_runtime_conf(manager);
    if (rc == NULL) {
        ERROR("Error building CNI runtime config");
        ret = -1;
        goto out;
    }

    ret = get_configs_from_cached(list->list->name, rc, NULL);
    if (ret != 0) {
        ERROR("Get cached info failed");
        ret = -1;
        goto out;
    }

    if (inject_annotations_json(manager->annotations, list, &use_list) != 0) {
        ERROR("Inject annotations to net conf json failed");
        ret = -1;
        goto out;
    }

    if (cni_check_network_list(list, rc, result) != 0) {
        ERROR("Error deleting network");
        ret = -1;
        goto out;
    }

out:
    free_runtime_conf(rc);
    free_cni_network_list_conf(use_list);
    return ret;
}

int detach_network_plane(const struct cni_manager *manager, const struct cni_network_list_conf *list,
                         struct cni_opt_result **result)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    struct cni_network_list_conf *use_list = NULL;

    if (manager == NULL || list == NULL || list->list == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    rc = build_cni_runtime_conf(manager);
    if (rc == NULL) {
        ERROR("Error building CNI runtime config");
        ret = -1;
        goto out;
    }

    ret = get_configs_from_cached(list->list->name, rc, NULL);
    if (ret != 0) {
        ERROR("Get cached info failed");
        ret = -1;
        goto out;
    }

    if (inject_annotations_json(manager->annotations, list, &use_list) != 0) {
        ERROR("Inject annotations to net conf json failed");
        ret = -1;
        goto out;
    }

    if (cni_del_network_list(list, rc) != 0) {
        ERROR("Error deleting network");
        ret = -1;
        goto out;
    }

out:
    free_runtime_conf(rc);
    free_cni_network_list_conf(use_list);
    return ret;
}

int detach_loopback(const char *id, const char *netns)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;

    if (id == NULL || netns == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    rc = build_loopback_runtime_conf(id, netns);
    if (rc == NULL) {
        ERROR("Error building loopback runtime config");
        ret = -1;
        goto out;
    }

    if (cni_del_network_list(g_cni_manager.loopback_conf, rc) != 0) {
        ERROR("Error delete loopback network");
        ret = -1;
        goto out;
    }

out:
    free_runtime_conf(rc);
    return ret;
}

int cni_manager_store_init(const char *cache_dir, const char *conf_path, const char * const *bin_paths,
                           size_t bin_paths_len)
{
    int ret = 0;

    if (conf_path == NULL) {
        ERROR("Invalid input param");
        return -1;
    }

    if (!cni_module_init(cache_dir, bin_paths, bin_paths_len)) {
        ERROR("Init libcni module failed");
        ret = -1;
        goto out;
    }

    g_cni_manager.loopback_conf = cni_conflist_from_bytes(LOOPBACK_CONFLIST_STR);
    if (g_cni_manager.loopback_conf == NULL) {
        ERROR("Init loopback config failed");
        ret = -1;
        goto out;
    }

    g_cni_manager.conf_path = util_strdup_s(conf_path);

out:
    return ret;
}
