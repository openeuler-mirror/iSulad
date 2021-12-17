/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide cni api functions
 ********************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "libcni_api.h"

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <isula_libutils/log.h>

#include "utils.h"
#include "utils_network.h"
#include "libcni_cached.h"
#include "libcni_conf.h"
#include "libcni_result_parse.h"
#include "libcni_exec.h"
#include "libcni_result_type.h"
#include "err_msg.h"

typedef struct _cni_module_conf_t {
    char **bin_paths;
    size_t bin_paths_len;
    char *cache_dir;
} cni_module_conf_t;

static cni_module_conf_t g_module_conf;

bool cni_module_init(const char *cache_dir, const char * const *paths, size_t paths_len)
{
    size_t i;

    if (paths_len > 0) {
        g_module_conf.bin_paths = util_smart_calloc_s(sizeof(char *), paths_len);
        if (g_module_conf.bin_paths == NULL) {
            ERROR("Out of memory");
            return false;
        }
        for (i = 0; i < paths_len; i++) {
            g_module_conf.bin_paths[i] = util_strdup_s(paths[i]);
            g_module_conf.bin_paths_len += 1;
        }
    }

    g_module_conf.cache_dir = util_strdup_s(cache_dir);
    return true;
}

struct cni_opt_result *cni_get_network_list_cached_result(const struct cni_network_list_conf *list,
                                                          const struct runtime_conf *rc)
{
    struct cni_opt_result *result = NULL;
    if (list == NULL || list->list == NULL) {
        ERROR("Empty net list conf argument");
        return NULL;
    }

    if (cni_get_cached_result(g_module_conf.cache_dir, list->list->name, list->list->cni_version, rc, &result) != 0) {
        ERROR("Get cached result failed");
    }

    return result;
}

cni_cached_info *cni_get_network_list_cached_info(const char *network, const struct runtime_conf *rc)
{
    if (network == NULL) {
        ERROR("Empty network");
        return NULL;
    }

    return cni_cache_read(g_module_conf.cache_dir, network, rc);
}

static int args(const char *action, const struct runtime_conf *rc, struct cni_args **cargs);

typedef int (*cap_fn_t)(const struct runtime_conf *, cni_net_conf_runtime_config *);
struct cap_inject_item {
    const char *name;
    cap_fn_t cb;
};

static int inject_cni_port_mapping(const struct runtime_conf *rt, cni_net_conf_runtime_config *rt_config)
{
    size_t j = 0;

    rt_config->port_mappings = util_smart_calloc_s(sizeof(cni_inner_port_mapping *), (rt->p_mapping_len));
    if (rt_config->port_mappings == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (j = 0; j < rt->p_mapping_len; j++) {
        rt_config->port_mappings[j] = util_common_calloc_s(sizeof(cni_inner_port_mapping));
        if (rt_config->port_mappings[j] == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        rt_config->port_mappings_len += 1;
        if (copy_cni_port_mapping(rt->p_mapping[j], rt_config->port_mappings[j]) != 0) {
            ERROR("Out of memory");
            return -1;
        }
    }

    return 0;
}

static int inject_cni_bandwidth_entry(const struct runtime_conf *rt, cni_net_conf_runtime_config *rt_config)
{
    if (rt->bandwidth == NULL) {
        return 0;
    }
    rt_config->bandwidth = util_common_calloc_s(sizeof(cni_bandwidth_entry));
    if (rt_config->bandwidth == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    rt_config->bandwidth->ingress_burst = rt->bandwidth->ingress_burst;
    rt_config->bandwidth->ingress_rate = rt->bandwidth->ingress_rate;
    rt_config->bandwidth->egress_burst = rt->bandwidth->egress_burst;
    rt_config->bandwidth->egress_rate = rt->bandwidth->egress_rate;
    return 0;
}

static cni_ip_ranges *copy_cni_ip_ranges(cni_ip_ranges *src)
{
    cni_ip_ranges *ret = NULL;

    if (src == NULL) {
        return NULL;
    }
    ret = util_common_calloc_s(sizeof(cni_ip_ranges));
    if (ret == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ret->subnet = util_strdup_s(src->subnet);
    ret->range_start = util_strdup_s(src->range_start);
    ret->range_end = util_strdup_s(src->range_end);
    ret->gateway = util_strdup_s(src->gateway);
    return ret;
}

static int inject_cni_ip_ranges(const struct runtime_conf *rt, cni_net_conf_runtime_config *rt_config)
{
    size_t i, j;

    if (rt->ip_ranges == NULL || rt->ip_ranges->len == 0 || rt->ip_ranges->subitem_lens == NULL) {
        return 0;
    }

    rt_config->ip_ranges = util_smart_calloc_s(sizeof(cni_ip_ranges **), rt->ip_ranges->len);
    if (rt_config->ip_ranges == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    rt_config->ip_ranges_item_lens = util_smart_calloc_s(sizeof(size_t), rt->ip_ranges->len);
    if (rt_config->ip_ranges_item_lens == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < rt->ip_ranges->len; i++) {
        rt_config->ip_ranges[i] = util_smart_calloc_s(sizeof(cni_ip_ranges *), rt->ip_ranges->subitem_lens[i]);
        if (rt_config->ip_ranges[i] == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        for (j = 0; j < rt->ip_ranges->subitem_lens[i]; j++) {
            rt_config->ip_ranges[i][j] = copy_cni_ip_ranges(rt->ip_ranges->items[i][j]);
            if (rt_config->ip_ranges[i][j] == NULL) {
                return -1;
            }
        }
    }

    return 0;
}

static struct cap_inject_item g_cap_inject_items[] = {
    {
        .name = SUPPORT_CAPABILITY_PORTMAPPINGS,
        .cb = inject_cni_port_mapping
    },
    {
        .name = SUPPORT_CAPABILITY_BANDWIDTH,
        .cb = inject_cni_bandwidth_entry
    },
    {
        .name = SUPPORT_CAPABILITY_IPRANGES,
        .cb = inject_cni_ip_ranges
    }
};

static int inject_runtime_config_items(const struct cni_network_conf *orig, const struct runtime_conf *rt,
                                       cni_net_conf_runtime_config **rt_config, bool *inserted)
{
    char *work = NULL;
    bool value = false;
    int ret = -1;
    size_t i, j;

    *rt_config = util_common_calloc_s(sizeof(cni_net_conf_runtime_config));
    if (*rt_config == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    for (i = 0; i < orig->network->capabilities->len; i++) {
        work = orig->network->capabilities->keys[i];
        value = orig->network->capabilities->values[i];
        if (!value || work == NULL) {
            continue;
        }

        /* new capabilities add to g_cap_inject_items */
        for (j = 0; j < sizeof(g_cap_inject_items) / sizeof(struct cap_inject_item); j++) {
            if (strcmp(work, g_cap_inject_items[j].name) != 0) {
                continue;
            }
            if (g_cap_inject_items[j].cb(rt, *rt_config) != 0) {
                goto free_out;
            }
            *inserted = true;
        }
    }
    ret = 0;
free_out:
    return ret;
}

static int do_generate_cni_net_conf_json(const struct cni_network_conf *orig, char **result)
{
    struct parser_context ctx = { OPT_PARSE_FULLKEY | OPT_GEN_SIMPLIFY, 0 };
    parser_error jerr = NULL;
    int ret = 0;

    /* generate new json str for injected config */
    *result = cni_net_conf_generate_json(orig->network, &ctx, &jerr);
    if (*result == NULL) {
        ERROR("Generate cni net conf error: %s", jerr);
        ret = -1;
        goto out;
    }

out:
    free(jerr);
    return ret;
}

static int copy_cni_net_conf(const cni_net_conf *orig, cni_net_conf **copied)
{
    struct parser_context ctx = { OPT_PARSE_FULLKEY | OPT_GEN_SIMPLIFY, 0 };
    parser_error jerr = NULL;
    char *tmp_json = NULL;
    int ret = 0;

    /* generate new json str for injected config */
    tmp_json = cni_net_conf_generate_json(orig, &ctx, &jerr);
    if (tmp_json == NULL) {
        ERROR("Generate cni net conf error: %s", jerr);
        ret = -1;
        goto out;
    }

    *copied = cni_net_conf_parse_data(tmp_json, &ctx, &jerr);
    if (*copied == NULL) {
        ERROR("parse cni net conf error: %s", jerr);
        ret = -1;
        goto out;
    }

out:
    free(jerr);
    free(tmp_json);
    return ret;
}

static inline bool check_inject_runtime_config_args(const struct cni_network_conf *orig, const struct runtime_conf *rt,
                                                    char * const *result)
{
    return (orig == NULL || rt == NULL || result == NULL);
}

static int inject_runtime_config(const struct cni_network_conf *orig, const struct runtime_conf *rt, char **result)
{
    bool insert_rt_config = false;
    int ret = -1;
    cni_net_conf_runtime_config *rt_config = NULL;
    cni_net_conf_runtime_config *save_conf = NULL;

    if (check_inject_runtime_config_args(orig, rt, result)) {
        ERROR("Invalid arguments");
        return -1;
    }

    if (orig->network == NULL || orig->network->capabilities == NULL) {
        return 0;
    }

    save_conf = orig->network->runtime_config;

    ret = inject_runtime_config_items(orig, rt, &rt_config, &insert_rt_config);
    if (ret != 0) {
        ERROR("inject runtime config failed");
        goto free_out;
    }

    if (!insert_rt_config) {
        goto generate_result;
    }

    orig->network->runtime_config = rt_config;

generate_result:
    ret = do_generate_cni_net_conf_json(orig, result);
    if (ret != 0) {
        ERROR("Generate cni net conf json failed");
    }

free_out:
    orig->network->runtime_config = save_conf;
    free_cni_net_conf_runtime_config(rt_config);
    if (ret != 0) {
        free(*result);
        *result = NULL;
    }
    return ret;
}

static int do_inject_prev_result(const struct cni_opt_result *prev_result, cni_net_conf *work)
{
    if (prev_result == NULL) {
        return 0;
    }

    free_cni_result_curr(work->prev_result);
    work->prev_result = cni_result_curr_to_json_result(prev_result);
    if (work->prev_result == NULL) {
        return -1;
    }
    return 0;
}

static inline bool check_build_one_config(const struct cni_network_conf *orig, const struct runtime_conf *rt,
                                          char * const *result)
{
    return (orig == NULL || rt == NULL || result == NULL);
}

static int build_one_config(const char *name, const char *version, struct cni_network_conf *orig,
                            const struct cni_opt_result *prev_result, const struct runtime_conf *rt, char **result)
{
    int ret = -1;
    cni_net_conf *work = NULL;

    if (check_build_one_config(orig, rt, result)) {
        ERROR("Invalid arguments");
        return ret;
    }

    work = orig->network;
    free(work->name);
    work->name = util_strdup_s(name);
    free(work->cni_version);
    work->cni_version = util_strdup_s(version);

    if (do_inject_prev_result(prev_result, work) != 0) {
        ERROR("Inject pre result failed");
        goto free_out;
    }

    if (inject_runtime_config(orig, rt, result) != 0) {
        goto free_out;
    }

    ret = 0;
free_out:
    return ret;
}

static int do_check_generate_cni_net_conf_json(char **full_conf_bytes, struct cni_network_conf *pnet)
{
    struct parser_context ctx = { OPT_PARSE_FULLKEY | OPT_GEN_SIMPLIFY, 0 };
    parser_error serr = NULL;
    int ret = 0;

    if (*full_conf_bytes != NULL) {
        pnet->bytes = *full_conf_bytes;
        *full_conf_bytes = NULL;
    } else {
        pnet->bytes = cni_net_conf_generate_json(pnet->network, &ctx, &serr);
        if (pnet->bytes == NULL) {
            ERROR("Generate cni net conf error: %s", serr);
            ret = -1;
            goto out;
        }
    }

out:
    free(serr);
    return ret;
}

static int do_check_file(const char *plugin, const char *path, char **find_path)
{
    int nret = 0;
    char tmp_path[PATH_MAX] = { 0 };
    struct stat rt_stat = { 0 };

    nret = snprintf(tmp_path, PATH_MAX, "%s/%s", path, plugin);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Sprint failed with %s/%s", path, plugin);
        return -1;
    }
    nret = stat(tmp_path, &rt_stat);
    if (nret == 0 && S_ISREG(rt_stat.st_mode)) {
        *find_path = util_strdup_s(tmp_path);
        return 0;
    } else {
        return -1;
    }
}

static inline bool check_find_in_path_args(const char *plugin, const char * const *paths, size_t len,
                                           char * const *find_path)
{
    return (plugin == NULL || strlen(plugin) == 0 || paths == NULL || len == 0 || find_path == NULL);
}

static int find_plugin_in_path(const char *plugin, const char * const *paths, size_t len, char **find_path)
{
    int ret = -1;
    size_t i = 0;

    if (check_find_in_path_args(plugin, paths, len, find_path)) {
        ERROR("Invalid arguments");
        return -1;
    }
    for (i = 0; i < len; i++) {
        if (do_check_file(plugin, paths[i], find_path) == 0) {
            ret = 0;
            break;
        }
    }

    if (ret != 0) {
        ERROR("Can not find plugin: %s", plugin);
    }

    return ret;
}

static int run_cni_plugin(const cni_net_conf *p_net, const char *name, const char *version, const char *operator,
                          const struct runtime_conf * rc, struct cni_opt_result * * pret, bool with_result)
{
    int ret = -1;
    struct cni_network_conf net = { 0 };
    char *plugin_path = NULL;
    struct cni_args *cargs = NULL;
    char *full_conf_bytes = NULL;
    struct cni_opt_result *tmp_result = NULL;
    cni_net_conf *used_net = NULL;

    if (copy_cni_net_conf(p_net, &used_net) != 0) {
        return -1;
    }
    net.network = used_net;

    ret = find_plugin_in_path(net.network->type, (const char * const *)g_module_conf.bin_paths,
                              g_module_conf.bin_paths_len, &plugin_path);
    if (ret != 0) {
        ERROR("Failed to find plugin: \"%s\"", net.network->type);
        isulad_append_error_message("Failed to find plugin: \"%s\". ", net.network->type);
        goto free_out;
    }

    tmp_result = pret != NULL ? *pret : NULL;
    ret = build_one_config(name, version, &net, tmp_result, rc, &full_conf_bytes);
    if (ret != 0) {
        ERROR("build config failed");
        goto free_out;
    }

    ret = do_check_generate_cni_net_conf_json(&full_conf_bytes, &net);
    if (ret != 0) {
        ERROR("check gengerate net config failed");
        goto free_out;
    }

    ret = args(operator, rc, &cargs);
    if (ret != 0) {
        ERROR("get plugin arguments failed");
        goto free_out;
    }

    if (with_result) {
        ret = exec_plugin_with_result(plugin_path, net.bytes, cargs, pret);
    } else {
        ret = exec_plugin_without_result(plugin_path, net.bytes, cargs);
    }
free_out:
    free_cni_args(cargs);
    free(plugin_path);
    free_cni_net_conf(used_net);
    free(net.bytes);
    return ret;
}

struct parse_version {
    int major;
    int minor;
    int micro;
};

static bool do_parse_version(const char **splits, size_t splits_len, struct parse_version *ret)
{
    if (util_safe_int(splits[0], &ret->major) != 0) {
        ERROR("failed to convert major version part: %s", splits[0]);
        return false;
    }

    if (splits_len >= 2 && util_safe_int(splits[1], &ret->minor) != 0) {
        ERROR("failed to convert minor version part: %s", splits[1]);
        return false;
    }

    if (splits_len >= 3 && util_safe_int(splits[2], &ret->micro) != 0) {
        ERROR("failed to convert micro version part: %s", splits[2]);
        return false;
    }

    return true;
}

static bool parse_version_from_str(const char *src_version, struct parse_version *result)
{
    char **splits = NULL;
    const size_t max_len = 4;
    size_t tlen = 0;
    bool ret = false;

    splits = util_string_split(src_version, '.');
    if (splits == NULL) {
        ERROR("Split version: \"%s\" failed", src_version);
        return false;
    }
    tlen = util_array_len((const char **)splits);
    if (tlen < 1 || tlen >= max_len) {
        ERROR("Invalid version: \"%s\"", src_version);
        goto out;
    }

    ret = do_parse_version((const char **)splits, tlen, result);

out:
    util_free_array(splits);
    return ret;
}

static bool do_compare_version(const struct parse_version *p_first, const struct parse_version *p_second)
{
    bool ret = false;

    if (p_first->major > p_second->major) {
        ret = true;
    } else if (p_first->major == p_second->major) {
        if (p_first->minor > p_second->minor) {
            ret = true;
        } else if (p_first->minor == p_second->minor && p_first->micro >= p_second->micro) {
            ret = true;
        }
    }

    return ret;
}

static int version_greater_than_or_equal_to(const char *first, const char *second, bool *result)
{
    struct parse_version first_parsed = { 0 };
    struct parse_version second_parsed = { 0 };

    if (result == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (!parse_version_from_str(first, &first_parsed)) {
        return -1;
    }

    if (!parse_version_from_str(second, &second_parsed)) {
        return -1;
    }

    *result = do_compare_version(&first_parsed, &second_parsed);

    return 0;
}

static inline bool check_add_network_args(const cni_net_conf *net, const struct runtime_conf *rc)
{
    return (net == NULL || rc == NULL);
}

static int add_network(const cni_net_conf *net, const char *name, const char *version, const struct runtime_conf *rc,
                       struct cni_opt_result **add_result)
{
    if (check_add_network_args(net, rc)) {
        ERROR("Empty arguments");
        return -1;
    }
    if (!util_valid_container_id(rc->container_id)) {
        ERROR("Invalid container id: %s", rc->container_id);
        return -1;
    }
    if (!util_validate_network_name(name)) {
        ERROR("Invalid network name: %s", name);
        return -1;
    }
    if (!util_validate_network_interface(rc->ifname)) {
        ERROR("Invalid interface name: %s", rc->ifname);
        return -1;
    }

    return run_cni_plugin(net, name, version, "ADD", rc, add_result, true);
}

static inline bool check_add_network_list_args(const struct cni_network_list_conf *list, const struct runtime_conf *rc,
                                               struct cni_opt_result * const *pret)
{
    return (list == NULL || list->list == NULL || rc == NULL || pret == NULL);
}

int cni_add_network_list(const struct cni_network_list_conf *list, const struct runtime_conf *rc,
                         struct cni_opt_result **pret)
{
    int ret = 0;
    size_t i = 0;
    bool greated = false;

    if (check_add_network_list_args(list, rc, pret)) {
        ERROR("Empty arguments");
        return -1;
    }

    for (i = 0; i < list->list->plugins_len; i++) {
        ret = add_network(list->list->plugins[i], list->list->name, list->list->cni_version, rc, pret);
        if (ret != 0) {
            ERROR("Run ADD plugin: %zu failed", i);
            return ret;
        }
    }

    if (*pret != NULL && version_greater_than_or_equal_to((*pret)->cniversion, CURRENT_VERSION, &greated) != 0) {
        WARN("result version: %s is too old, do not save this cache", (*pret)->cniversion);
        return 0;
    }

    if (!greated) {
        return 0;
    }

    ret = cni_cache_add(g_module_conf.cache_dir, *pret, list->bytes, list->list->name, rc);
    if (ret != 0) {
        ERROR("failed to set network: %s cached result", list->list->name);
    }

    return ret;
}

static inline bool check_del_network_args(const cni_net_conf *net, const struct runtime_conf *rc)
{
    return (net == NULL || rc == NULL);
}

static int del_network(const cni_net_conf *net, const char *name, const char *version, const struct runtime_conf *rc,
                       struct cni_opt_result **prev_result)
{
    if (check_del_network_args(net, rc)) {
        ERROR("Empty arguments");
        return -1;
    }

    return run_cni_plugin(net, name, version, "DEL", rc, prev_result, false);
}

static inline bool check_del_network_list_args(const struct cni_network_list_conf *list, const struct runtime_conf *rc)
{
    return (list == NULL || list->list == NULL || rc == NULL);
}

int cni_del_network_list(const struct cni_network_list_conf *list, const struct runtime_conf *rc)
{
    int i = 0;
    int ret = 0;
    bool greated = false;
    struct cni_opt_result *prev_result = NULL;

    if (check_del_network_list_args(list, rc)) {
        ERROR("Empty arguments");
        return -1;
    }

    if (version_greater_than_or_equal_to(list->list->cni_version, CURRENT_VERSION, &greated) != 0) {
        return -1;
    }

    if (greated) {
        ret = cni_get_cached_result(g_module_conf.cache_dir, list->list->name, list->list->cni_version, rc, &prev_result);
        if (ret != 0) {
            ret = -1;
            ERROR("failed to get network: %s cached result", list->list->name);
            goto free_out;
        }
    }

    for (i = list->list->plugins_len - 1; i >= 0; i--) {
        ret = del_network(list->list->plugins[i], list->list->name, list->list->cni_version, rc, &prev_result);
        if (ret != 0) {
            ERROR("Run DEL plugin: %d failed", i);
            goto free_out;
        }
    }

    if (greated && cni_cache_delete(g_module_conf.cache_dir, list->list->name, rc) != 0) {
        WARN("failed to delete network: %s cached result", list->list->name);
    }

free_out:
    free_cni_opt_result(prev_result);
    return ret;
}

static inline bool do_check_network_args(const cni_net_conf *net, const struct runtime_conf *rc)
{
    return (net == NULL || rc == NULL);
}

static int check_network(const cni_net_conf *net, const char *name, const char *version, const struct runtime_conf *rc,
                         struct cni_opt_result **prev_result)
{
    if (do_check_network_args(net, rc)) {
        ERROR("Empty arguments");
        return -1;
    }

    return run_cni_plugin(net, name, version, "CHECK", rc, prev_result, false);
}

static inline bool do_check_network_list_args(const struct cni_network_list_conf *list, const struct runtime_conf *rc,
                                              struct cni_opt_result **p_result)
{
    return (list == NULL || list->list == NULL || rc == NULL || p_result == NULL);
}

int cni_check_network_list(const struct cni_network_list_conf *list, const struct runtime_conf *rc,
                           struct cni_opt_result **p_result)
{
    int i = 0;
    int ret = 0;
    bool greated = false;
    struct cni_opt_result *tmp_result = NULL;

    if (do_check_network_list_args(list, rc, p_result)) {
        ERROR("Empty arguments");
        return -1;
    }

    if (version_greater_than_or_equal_to(list->list->cni_version, CURRENT_VERSION, &greated) != 0) {
        return -1;
    }

    // CHECK was added in CNI spec version 0.4.0 and higher
    if (!greated) {
        ERROR("configuration version %s does not support CHECK", list->list->cni_version);
        return -1;
    }

    if (list->list->disable_check) {
        INFO("network %s disable check command", list->list->name);
        return 0;
    }

    ret = cni_get_cached_result(g_module_conf.cache_dir, list->list->name, list->list->cni_version, rc, &tmp_result);
    if (ret != 0) {
        ret = -1;
        ERROR("failed to get network: %s cached result", list->list->name);
        goto free_out;
    }

    for (i = list->list->plugins_len - 1; i >= 0; i--) {
        if (check_network(list->list->plugins[i], list->list->name, list->list->cni_version, rc, &tmp_result) != 0) {
            ret = -1;
            ERROR("Run check plugin: %d failed", i);
            goto free_out;
        }
    }
    *p_result = tmp_result;
    tmp_result = NULL;

free_out:
    free_cni_opt_result(tmp_result);
    return ret;
}

static int do_copy_plugin_args(const struct runtime_conf *rc, struct cni_args **cargs)
{
    size_t i = 0;

    if (rc->args_len == 0) {
        return 0;
    }

    (*cargs)->plugin_args = util_smart_calloc_s(sizeof(char *) * 2, rc->args_len);
    if ((*cargs)->plugin_args == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < rc->args_len; i++) {
        (*cargs)->plugin_args[i][0] = util_strdup_s(rc->args[i][0]);
        (*cargs)->plugin_args[i][1] = util_strdup_s(rc->args[i][1]);
        (*cargs)->plugin_args_len = (i + 1);
    }

    return 0;
}

static int copy_args(const struct runtime_conf *rc, struct cni_args **cargs)
{
    if (rc->container_id != NULL) {
        (*cargs)->container_id = util_strdup_s(rc->container_id);
    }
    if (rc->netns != NULL) {
        (*cargs)->netns = util_strdup_s(rc->netns);
    }
    if (rc->ifname != NULL) {
        (*cargs)->ifname = util_strdup_s(rc->ifname);
    }

    return do_copy_plugin_args(rc, cargs);
}

static int do_copy_args_paths(struct cni_args **cargs)
{
    if (g_module_conf.bin_paths_len == 0) {
        (*cargs)->path = util_strdup_s("");
    } else {
        (*cargs)->path = util_string_join(":", (const char **)g_module_conf.bin_paths, g_module_conf.bin_paths_len);
        if ((*cargs)->path == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }
    return 0;
}

static inline bool check_args_args(const struct runtime_conf *rc, struct cni_args * const *cargs)
{
    return (rc == NULL || cargs == NULL);
}

static int args(const char *action, const struct runtime_conf *rc, struct cni_args **cargs)
{
    int ret = -1;

    if (check_args_args(rc, cargs)) {
        ERROR("Empty arguments");
        return ret;
    }
    *cargs = util_common_calloc_s(sizeof(struct cni_args));
    if (*cargs == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    if (action != NULL) {
        (*cargs)->command = util_strdup_s(action);
    }
    if (do_copy_args_paths(cargs) != 0) {
        goto free_out;
    }
    ret = copy_args(rc, cargs);

free_out:
    if (ret != 0) {
        free_cni_args(*cargs);
        *cargs = NULL;
    }
    return ret;
}

void free_cni_port_mapping(struct cni_port_mapping *val)
{
    if (val != NULL) {
        free(val->protocol);
        free(val->host_ip);
        free(val);
    }
}

void free_runtime_conf(struct runtime_conf *rc)
{
    size_t i = 0;

    if (rc == NULL) {
        return;
    }

    free(rc->container_id);
    rc->container_id = NULL;
    free(rc->netns);
    rc->netns = NULL;
    free(rc->ifname);
    rc->ifname = NULL;

    for (i = 0; i < rc->args_len; i++) {
        free(rc->args[i][0]);
        free(rc->args[i][1]);
    }
    free(rc->args);
    rc->args = NULL;

    for (i = 0; i < rc->p_mapping_len; i++) {
        free_cni_port_mapping(rc->p_mapping[i]);
    }
    free(rc->p_mapping);
    rc->p_mapping = NULL;
    free_cni_bandwidth_entry(rc->bandwidth);
    rc->bandwidth = NULL;

    free_cni_ip_ranges_array_container(rc->ip_ranges);
    rc->ip_ranges = NULL;

    free(rc);
}
