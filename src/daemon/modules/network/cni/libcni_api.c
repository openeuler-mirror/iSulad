/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
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
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "libcni_api.h"

#include "utils.h"
#include "isula_libutils/log.h"
#include "libcni_errno.h"
#include "libcni_current.h"
#include "libcni_conf.h"
#include "libcni_args.h"
#include "libcni_tools.h"
#include "libcni_exec.h"
#include "libcni_types.h"

static int add_network_list(const struct network_config_list *list, const struct runtime_conf *rc,
                            const char * const *paths, size_t paths_len, struct result **pret, char **err);

static int del_network_list(const struct network_config_list *list, const struct runtime_conf *rc,
                            const char * const *paths, size_t paths_len, char **err);

static int add_network(const struct network_config *net, const struct runtime_conf *rc, const char * const *paths,
                       size_t paths_len, struct result **add_result, char **err);

static int del_network(const struct network_config *net, const struct runtime_conf *rc, const char * const *paths,
                       size_t paths_len, char **err);

static int args(const char *action, const struct runtime_conf *rc, const char * const *paths, size_t paths_len,
                struct cni_args **cargs, char **err);

static int copy_cni_port_mapping(cni_inner_port_mapping *dst, const struct cni_port_mapping *src)
{
    bool invalid_arg = (dst == NULL || src == NULL);
    if (invalid_arg) {
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

static int inject_cni_port_mapping(const struct runtime_conf *rt, cni_net_conf_runtime_config *rt_config, char **err)
{
    size_t j = 0;

    if (rt_config->port_mappings != NULL) {
        for (j = 0; j < rt_config->port_mappings_len; j++) {
            free_cni_inner_port_mapping(rt_config->port_mappings[j]);
            rt_config->port_mappings[j] = NULL;
        }
        free(rt_config->port_mappings);
        rt_config->port_mappings = NULL;
    }

    if (rt->p_mapping_len > (SIZE_MAX / sizeof(cni_inner_port_mapping*))) {
        *err = util_strdup_s("Too many mapping");
        ERROR("Too many mapping");
        return -1;
    }

    rt_config->port_mappings = util_common_calloc_s(sizeof(cni_inner_port_mapping*) * (rt->p_mapping_len));
    if (rt_config->port_mappings == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        return -1;
    }
    for (j = 0; j < rt->p_mapping_len; j++) {
        rt_config->port_mappings[j] = util_common_calloc_s(sizeof(cni_inner_port_mapping));
        if (rt_config->port_mappings[j] == NULL) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
            return -1;
        }
        (rt_config->port_mappings_len)++;
        if (copy_cni_port_mapping(rt_config->port_mappings[j], rt->p_mapping[j]) != 0) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
            return -1;
        }
    }
    return 0;
}

static int inject_runtime_config_items(const struct network_config *orig, const struct runtime_conf *rt,
                                       cni_net_conf_runtime_config **rt_config, bool *inserted, char **err)
{
    char *work = NULL;
    bool value = false;
    int ret = -1;
    size_t i = 0;

    *rt_config = util_common_calloc_s(sizeof(cni_net_conf_runtime_config));
    if (*rt_config == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        goto free_out;
    }
    for (i = 0; i < orig->network->capabilities->len; i++) {
        work = orig->network->capabilities->keys[i];
        value = orig->network->capabilities->values[i];
        if (!value || work == NULL) {
            continue;
        }
        if (strcmp(work, "portMappings") == 0 && rt->p_mapping_len > 0) {
            if (inject_cni_port_mapping(rt, *rt_config, err) != 0) {
                ERROR("Inject port mappings failed");
                goto free_out;
            }
            *inserted = true;
        }
        /* new capabilities add here */
    }
    ret = 0;
free_out:
    return ret;
}

static int do_generate_cni_net_conf_json(const struct network_config *orig, char **result, char **err)
{
    struct parser_context ctx = { OPT_PARSE_FULLKEY | OPT_GEN_SIMPLIFY, 0 };
    parser_error jerr = NULL;
    int ret = 0;

    /* generate new json str for injected config */
    *result = cni_net_conf_generate_json(orig->network, &ctx, &jerr);
    if (*result == NULL) {
        if (asprintf(err, "generate json failed: %s", jerr) < 0) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
        }
        ERROR("Generate json: %s", jerr);
        ret = -1;
        goto out;
    }

out:
    free(jerr);
    return ret;
}

static inline bool check_inject_runtime_config_args(const struct network_config *orig, const struct runtime_conf *rt,
                                                    char * const *result, char * const *err)
{
    return (orig == NULL || rt == NULL || result == NULL || err == NULL);
}

static int inject_runtime_config(const struct network_config *orig, const struct runtime_conf *rt, char **result,
                                 char **err)
{
    bool insert_rt_config = false;
    int ret = -1;
    cni_net_conf_runtime_config *rt_config = NULL;
    cni_net_conf_runtime_config *save_conf = NULL;

    if (check_inject_runtime_config_args(orig, rt, result, err)) {
        ERROR("Invalid arguments");
        return -1;
    }

    if (orig->network == NULL || orig->network->capabilities == NULL) {
        return 0;
    }

    save_conf = orig->network->runtime_config;

    ret = inject_runtime_config_items(orig, rt, &rt_config, &insert_rt_config, err);
    if (ret != 0) {
        ERROR("inject runtime config failed: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    if (!insert_rt_config) {
        goto generate_result;
    }

    orig->network->runtime_config = rt_config;

generate_result:
    ret = do_generate_cni_net_conf_json(orig, result, err);

free_out:
    orig->network->runtime_config = save_conf;
    free_cni_net_conf_runtime_config(rt_config);
    if (ret != 0) {
        free(*result);
        *result = NULL;
    }
    return ret;
}

static int do_inject_prev_result(const struct result *prev_result, cni_net_conf *work, char **err)
{
    if (prev_result == NULL) {
        return 0;
    }

    free_cni_result_curr(work->prev_result);
    work->prev_result = cni_result_curr_to_json_result(prev_result, err);
    if (work->prev_result == NULL) {
        return -1;
    }
    return 0;
}

static inline bool check_build_one_config(const struct network_config_list *list, const struct network_config *orig,
                                          const struct runtime_conf *rt, char * const *result, char * const *err)
{
    return (list == NULL || orig == NULL || rt == NULL || result == NULL || err == NULL);
}

static int build_one_config(const struct network_config_list *list, struct network_config *orig,
                            const struct result *prev_result, const struct runtime_conf *rt, char **result, char **err)
{
    int ret = -1;
    cni_net_conf *work = NULL;

    if (check_build_one_config(list, orig, rt, result, err)) {
        ERROR("Invalid arguments");
        return ret;
    }

    work = orig->network;
    free(work->name);
    work->name = util_strdup_s(list->list->name);
    free(work->cni_version);
    work->cni_version = util_strdup_s(list->list->cni_version);

    if (do_inject_prev_result(prev_result, work, err) != 0) {
        ERROR("Inject pre result failed: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    if (inject_runtime_config(orig, rt, result, err) != 0) {
        ERROR("Inject runtime config failed: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    ret = 0;
free_out:
    if (ret != 0 && *err == NULL) {
        *err = util_strdup_s("Out of memory");
    }
    return ret;
}

static int do_check_generate_cni_net_conf_json(char **full_conf_bytes, struct network_config *pnet, char **err)
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
            if (asprintf(err, "Generate json failed: %s", serr) < 0) {
                *err = util_strdup_s("Out of memory");
            }
            ERROR("Generate json: %s", serr);
            ret = -1;
            goto out;
        }
    }

out:
    free(serr);
    return ret;
}

static int run_cni_plugin(const struct network_config_list *list, size_t i, const char *operator,
                          const struct runtime_conf *rc, const char * const *paths, size_t paths_len,
                          struct result **pret, char **err)
{
    int ret = -1;
    struct network_config net = { 0 };
    char *plugin_path = NULL;
    struct cni_args *cargs = NULL;
    char *full_conf_bytes = NULL;
    struct result *tmp_result = NULL;
    int save_errno = 0;

    net.network = list->list->plugins[i];
    if (net.network == NULL) {
        *err = util_strdup_s("Empty network");
        ERROR("Empty network");
        goto free_out;
    }

    ret = find_in_path(net.network->type, paths, paths_len, &plugin_path, &save_errno);
    if (ret != 0) {
        if (asprintf(err, "find plugin: \"%s\" failed: %s", net.network->type, get_invoke_err_msg(save_errno)) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        ERROR("find plugin: \"%s\" failed: %s", net.network->type, get_invoke_err_msg(save_errno));
        goto free_out;
    }

    tmp_result = pret != NULL ? *pret : NULL;
    ret = build_one_config(list, &net, tmp_result, rc, &full_conf_bytes, err);
    if (ret != 0) {
        ERROR("build config failed: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    ret = do_check_generate_cni_net_conf_json(&full_conf_bytes, &net, err);
    if (ret != 0) {
        ERROR("check gengerate net config failed: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    ret = args(operator, rc, paths, paths_len, &cargs, err);
    if (ret != 0) {
        ERROR("get plugin arguments failed: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    if (pret == NULL) {
        ret = exec_plugin_without_result(plugin_path, net.bytes, cargs, err);
    } else {
        free_result(*pret);
        *pret = NULL;
        ret = exec_plugin_with_result(plugin_path, net.bytes, cargs, pret, err);
    }
free_out:
    free_cni_args(cargs);
    free(plugin_path);
    free(net.bytes);
    return ret;
}

static inline bool check_add_network_list_args(const struct network_config_list *list, const struct runtime_conf *rc,
                                               struct result * const *pret, char * const *err)
{
    return (list == NULL || list->list == NULL || rc == NULL || pret == NULL || err == NULL);
}

static int add_network_list(const struct network_config_list *list, const struct runtime_conf *rc,
                            const char * const *paths, size_t paths_len, struct result **pret, char **err)
{
    int ret = -1;
    size_t i = 0;
    struct result *prev_result = NULL;

    if (check_add_network_list_args(list, rc, pret, err)) {
        ERROR("Empty arguments");
        return -1;
    }

    for (i = 0; i < list->list->plugins_len; i++) {
        ret = run_cni_plugin(list, i, "ADD", rc, paths, paths_len, &prev_result, err);
        if (ret != 0) {
            ERROR("Run ADD cni failed: %s", *err != NULL ? *err : "");
            goto free_out;
        }
    }

    *pret = prev_result;
    ret = 0;
free_out:
    if (ret != 0) {
        free_result(prev_result);
    }
    return ret;
}

static inline bool check_del_network_list_args(const struct network_config_list *list, const struct runtime_conf *rc,
                                               char * const *err)
{
    return (list == NULL || list->list == NULL || rc == NULL || err == NULL);
}

static int del_network_list(const struct network_config_list *list, const struct runtime_conf *rc,
                            const char * const *paths, size_t paths_len, char **err)
{
    size_t i = 0;
    int ret = 0;

    if (check_del_network_list_args(list, rc, err)) {
        ERROR("Empty arguments");
        return -1;
    }

    for (i = list->list->plugins_len; i > 0; i--) {
        ret = run_cni_plugin(list, (i - 1), "DEL", rc, paths, paths_len, NULL, err);
        if (ret != 0) {
            ERROR("Run DEL cni failed: %s", *err != NULL ? *err : "");
            goto free_out;
        }
    }

free_out:
    return ret;
}

static inline bool check_add_network_args(const struct network_config *net, const struct runtime_conf *rc,
                                          char * const *err)
{
    return (net == NULL || rc == NULL || err == NULL);
}

static int add_network(const struct network_config *net, const struct runtime_conf *rc, const char * const *paths,
                       size_t paths_len, struct result **add_result, char **err)
{
    int ret = 0;
    char *plugin_path = NULL;
    char *net_bytes = NULL;
    struct cni_args *cargs = NULL;
    int save_errno = 0;

    if (check_add_network_args(net, rc, err)) {
        ERROR("Empty arguments");
        return -1;
    }
    ret = find_in_path(net->network->type, paths, paths_len, &plugin_path, &save_errno);
    if (ret != 0) {
        if (asprintf(err, "find plugin: \"%s\" failed: %s", net->network->type, get_invoke_err_msg(save_errno)) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        ERROR("find plugin: \"%s\" failed: %s", net->network->type, get_invoke_err_msg(save_errno));
        goto free_out;
    }

    ret = inject_runtime_config(net, rc, &net_bytes, err);
    if (ret != 0) {
        ERROR("Inject runtime config: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    ret = args("ADD", rc, paths, paths_len, &cargs, err);
    if (ret != 0) {
        ERROR("Get ADD cni arguments: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    ret = exec_plugin_with_result(plugin_path, net_bytes, cargs, add_result, err);
free_out:
    free(plugin_path);
    free(net_bytes);
    free_cni_args(cargs);
    return ret;
}

static inline bool check_del_network_args(const struct network_config *net, const struct runtime_conf *rc,
                                          char * const *err)
{
    return (net == NULL || net->network == NULL || rc == NULL || err == NULL);
}

static int del_network(const struct network_config *net, const struct runtime_conf *rc, const char * const *paths,
                       size_t paths_len, char **err)
{
    int ret = 0;
    char *plugin_path = NULL;
    char *net_bytes = NULL;
    struct cni_args *cargs = NULL;
    int save_errno = 0;

    if (check_del_network_args(net, rc, err)) {
        ERROR("Empty arguments");
        return -1;
    }
    ret = find_in_path(net->network->type, paths, paths_len, &plugin_path, &save_errno);
    if (ret != 0) {
        if (asprintf(err, "find plugin: \"%s\" failed: %s", net->network->type, get_invoke_err_msg(save_errno)) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        ERROR("find plugin: \"%s\" failed: %s", net->network->type, get_invoke_err_msg(save_errno));
        goto free_out;
    }

    ret = inject_runtime_config(net, rc, &net_bytes, err);
    if (ret != 0) {
        ERROR("Inject runtime config: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    ret = args("DEL", rc, paths, paths_len, &cargs, err);
    if (ret != 0) {
        ERROR("Get DEL cni arguments: %s", *err != NULL ? *err : "");
        goto free_out;
    }

    ret = exec_plugin_without_result(plugin_path, net_bytes, cargs, err);
free_out:
    free(plugin_path);
    free(net_bytes);
    free_cni_args(cargs);
    return ret;
}

static int do_copy_plugin_args(const struct runtime_conf *rc, struct cni_args **cargs)
{
    size_t i = 0;

    if (rc->args_len == 0) {
        return 0;
    }

    if (rc->args_len > (INT_MAX / sizeof(char *)) / 2) {
        ERROR("Large arguments");
        return -1;
    }
    (*cargs)->plugin_args = util_common_calloc_s((rc->args_len) * sizeof(char *) * 2);
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

static int do_copy_args_paths(const char * const *paths, size_t paths_len, struct cni_args **cargs)
{
    if (paths == NULL) {
        return 0;
    }

    if (paths_len == 0) {
        (*cargs)->path = util_strdup_s("");
    } else {
        (*cargs)->path = util_string_join(":", (const char **)paths, paths_len);
        if ((*cargs)->path == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }
    return 0;
}

static inline bool check_args_args(const struct runtime_conf *rc, struct cni_args * const *cargs, char * const *err)
{
    return (rc == NULL || cargs == NULL || err == NULL);
}

static int args(const char *action, const struct runtime_conf *rc, const char * const *paths, size_t paths_len,
                struct cni_args **cargs, char **err)
{
    int ret = -1;

    if (check_args_args(rc, cargs, err)) {
        ERROR("Empty arguments");
        return ret;
    }
    *cargs = util_common_calloc_s(sizeof(struct cni_args));
    if (*cargs == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        goto free_out;
    }
    if (action != NULL) {
        (*cargs)->command = util_strdup_s(action);
    }
    if (do_copy_args_paths(paths, paths_len, cargs) != 0) {
        goto free_out;
    }
    ret = copy_args(rc, cargs);

free_out:
    if (ret != 0) {
        free_cni_args(*cargs);
        *cargs = NULL;
        if (*err == NULL) {
            *err = util_strdup_s("Out of memory");
        }
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

void free_cni_network_conf(struct cni_network_conf *val)
{
    if (val != NULL) {
        free(val->name);
        free(val->type);
        free(val->bytes);
        free(val);
    }
}

void free_cni_network_list_conf(struct cni_network_list_conf *val)
{
    if (val != NULL) {
        free(val->bytes);
        free(val->name);
        free(val->first_plugin_name);
        free(val->first_plugin_type);
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
    free(rc);
}

int cni_add_network_list(const char *net_list_conf_str, const struct runtime_conf *rc, char **paths,
                         struct result **pret, char **err)
{
    struct network_config_list *list = NULL;
    int ret = 0;
    size_t len = 0;

    if (err == NULL) {
        ERROR("Empty arguments");
        return -1;
    }
    if (net_list_conf_str == NULL) {
        *err = util_strdup_s("Empty net list conf argument");
        ERROR("Empty net list conf argument");
        return -1;
    }

    ret = conflist_from_bytes(net_list_conf_str, &list, err);
    if (ret != 0) {
        ERROR("Parse conf list failed: %s", *err != NULL ? *err : "");
        return ret;
    }

    len = util_array_len((const char **)paths);
    ret = add_network_list(list, rc, (const char * const *)paths, len, pret, err);

    DEBUG("Add network list return with: %d", ret);
    free_network_config_list(list);
    return ret;
}

int cni_add_network(const char *cni_net_conf_str, const struct runtime_conf *rc, char **paths,
                    struct result **add_result,
                    char **err)
{
    struct network_config *net = NULL;
    int ret = 0;
    size_t len = 0;

    if (err == NULL) {
        ERROR("Empty err");
        return -1;
    }
    if (cni_net_conf_str == NULL) {
        *err = util_strdup_s("Empty net conf argument");
        ERROR("Empty net conf argument");
        return -1;
    }

    ret = conf_from_bytes(cni_net_conf_str, &net, err);
    if (ret != 0) {
        ERROR("Parse conf failed: %s", *err != NULL ? *err : "");
        return ret;
    }

    len = util_array_len((const char **)paths);
    ret = add_network(net, rc, (const char * const *)paths, len, add_result, err);
    free_network_config(net);
    return ret;
}

int cni_del_network_list(const char *net_list_conf_str, const struct runtime_conf *rc, char **paths, char **err)
{
    struct network_config_list *list = NULL;
    int ret = 0;
    size_t len = 0;

    if (err == NULL) {
        ERROR("Empty err");
        return -1;
    }
    if (net_list_conf_str == NULL) {
        *err = util_strdup_s("Empty net list conf argument");
        ERROR("Empty net list conf argument");
        return -1;
    }

    ret = conflist_from_bytes(net_list_conf_str, &list, err);
    if (ret != 0) {
        ERROR("Parse conf list failed: %s", *err != NULL ? *err : "");
        return ret;
    }

    len = util_array_len((const char **)paths);
    ret = del_network_list(list, rc, (const char * const *)paths, len, err);

    DEBUG("Delete network list return with: %d", ret);
    free_network_config_list(list);
    return ret;
}

int cni_del_network(const char *cni_net_conf_str, const struct runtime_conf *rc, char **paths, char **err)
{
    struct network_config *net = NULL;
    int ret = 0;
    size_t len = 0;

    if (err == NULL) {
        ERROR("Empty err");
        return -1;
    }
    if (cni_net_conf_str == NULL) {
        *err = util_strdup_s("Empty net conf argument");
        ERROR("Empty net conf argument");
        return -1;
    }

    ret = conf_from_bytes(cni_net_conf_str, &net, err);
    if (ret != 0) {
        ERROR("Parse conf failed: %s", *err != NULL ? *err : "");
        return ret;
    }

    len = util_array_len((const char **)paths);
    ret = del_network(net, rc, (const char * const *)paths, len, err);
    free_network_config(net);
    return ret;
}

int cni_get_version_info(const char *plugin_type, char **paths, struct plugin_info **pinfo, char **err)
{
    int ret = 0;
    char *plugin_path = NULL;
    size_t len;
    int save_errno = 0;

    if (err == NULL) {
        ERROR("Empty err");
        return -1;
    }
    len = util_array_len((const char **)paths);
    ret = find_in_path(plugin_type, (const char * const *)paths, len, &plugin_path, &save_errno);
    if (ret != 0) {
        if (asprintf(err, "find plugin: \"%s\" failed: %s", plugin_type, get_invoke_err_msg(save_errno)) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        ERROR("find plugin: \"%s\" failed: %s", plugin_type, get_invoke_err_msg(save_errno));
        return ret;
    }

    ret = raw_get_version_info(plugin_path, pinfo, err);
    free(plugin_path);
    return ret;
}

int cni_conf_files(const char *dir, const char **extensions, size_t ext_len, char ***result, char **err)
{
    if (err == NULL) {
        ERROR("Empty err");
        return -1;
    }
    return conf_files(dir, extensions, ext_len, result, err);
}

int cni_conf_from_file(const char *filename, struct cni_network_conf **config, char **err)
{
    int ret = 0;
    struct network_config *netconf = NULL;

    if (err == NULL) {
        ERROR("Empty err");
        return -1;
    }
    ret = conf_from_file(filename, &netconf, err);
    if (ret != 0) {
        ERROR("Parse conf file: %s failed: %s", filename, *err != NULL ? *err : "");
        return ret;
    }

    *config = util_common_calloc_s(sizeof(struct cni_network_conf));
    if (*config == NULL) {
        *err = util_strdup_s("Out of memory");
        ret = -1;
        ERROR("Out of memory");
        goto free_out;
    }

    if (netconf != NULL && netconf->network != NULL) {
        (*config)->type = netconf->network->type ? util_strdup_s(netconf->network->type) : NULL;
        (*config)->name = netconf->network->name ? util_strdup_s(netconf->network->name) : NULL;
    }
    if (netconf != NULL) {
        (*config)->bytes = netconf->bytes;
        netconf->bytes = NULL;
    }

    ret = 0;

free_out:
    free_network_config(netconf);
    return ret;
}

static void json_obj_to_cni_list_conf(struct network_config_list *src, struct cni_network_list_conf *list)
{
    if (src == NULL) {
        return;
    }

    list->bytes = src->bytes;
    src->bytes = NULL;
    if (src->list != NULL) {
        list->name = src->list->name ? util_strdup_s(src->list->name) : NULL;
        list->plugin_len = src->list->plugins_len;
        if (src->list->plugins_len > 0 && src->list->plugins != NULL && src->list->plugins[0] != NULL) {
            list->first_plugin_name = src->list->plugins[0]->name != NULL ?
                                      util_strdup_s(src->list->plugins[0]->name) : NULL;
            list->first_plugin_type = src->list->plugins[0]->type != NULL ?
                                      util_strdup_s(src->list->plugins[0]->type) : NULL;
        }
    }
}

int cni_conflist_from_bytes(const char *bytes, struct cni_network_list_conf **list, char **err)
{
    struct network_config_list *tmp_cni_net_conf_list = NULL;
    int ret = 0;

    if (err == NULL) {
        ERROR("Empty err");
        return -1;
    }
    ret = conflist_from_bytes(bytes, &tmp_cni_net_conf_list, err);
    if (ret != 0) {
        return ret;
    }
    *list = util_common_calloc_s(sizeof(struct cni_network_list_conf));
    if (*list == NULL) {
        *err = util_strdup_s("Out of memory");
        ret = -1;
        ERROR("Out of memory");
        goto free_out;
    }

    json_obj_to_cni_list_conf(tmp_cni_net_conf_list, *list);

    ret = 0;
free_out:
    free_network_config_list(tmp_cni_net_conf_list);
    return ret;
}

int cni_conflist_from_file(const char *filename, struct cni_network_list_conf **list, char **err)
{
    struct network_config_list *tmp_cni_net_conf_list = NULL;
    int ret = 0;

    if (err == NULL) {
        ERROR("Empty err");
        return -1;
    }
    ret = conflist_from_file(filename, &tmp_cni_net_conf_list, err);
    if (ret != 0) {
        return ret;
    }
    *list = util_common_calloc_s(sizeof(struct cni_network_list_conf));
    if (*list == NULL) {
        *err = util_strdup_s("Out of memory");
        ret = -1;
        ERROR("Out of memory");
        goto free_out;
    }

    json_obj_to_cni_list_conf(tmp_cni_net_conf_list, *list);

    ret = 0;
free_out:
    free_network_config_list(tmp_cni_net_conf_list);
    return ret;
}

static inline bool check_cni_conflist_from_conf_args(const struct cni_network_conf *cni_conf,
                                                     struct cni_network_list_conf * const *cni_conf_list)
{
    return (cni_conf == NULL || cni_conf_list == NULL);
}

int cni_conflist_from_conf(const struct cni_network_conf *cni_conf, struct cni_network_list_conf **cni_conf_list,
                           char **err)
{
    struct network_config *net = NULL;
    struct network_config_list *net_list = NULL;
    int ret = 0;
    bool invalid_arg = false;

    if (err == NULL) {
        ERROR("Empty err");
        return -1;
    }

    invalid_arg = check_cni_conflist_from_conf_args(cni_conf, cni_conf_list);
    if (invalid_arg) {
        *err = util_strdup_s("Empty cni conf or conflist argument");
        ERROR("Empty cni conf or conflist argument");
        return -1;
    }

    ret = conf_from_bytes(cni_conf->bytes, &net, err);
    if (ret != 0) {
        goto free_out;
    }

    ret = conflist_from_conf(net, &net_list, err);
    if (ret != 0) {
        goto free_out;
    }

    *cni_conf_list = util_common_calloc_s(sizeof(struct cni_network_list_conf));
    if (*cni_conf_list == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }

    json_obj_to_cni_list_conf(net_list, *cni_conf_list);
    ret = 0;

free_out:
    if (net != NULL) {
        free_network_config(net);
    }
    free_network_config_list(net_list);
    return ret;
}

