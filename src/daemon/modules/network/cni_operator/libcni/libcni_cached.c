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
 * Author: haozi007
 * Create: 2020-09-28
 * Description: cached for cni
 **********************************************************************************/
#define _GNU_SOURCE
#include "libcni_cached.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>

#include <isula_libutils/log.h>
#include <isula_libutils/cni_cached_info.h>

#include "utils.h"
#include "libcni_result_parse.h"

#define DEFAULT_CACHE_DIR "/var/lib/cni"

#define CNI_CACHE_V1 "cniCacheV1"

int copy_cni_port_mapping(const struct cni_port_mapping *src, cni_inner_port_mapping *dst)
{
    if (src == NULL) {
        return 0;
    }
    if (dst == NULL) {
        ERROR("Invalid dst");
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

int copy_port_mapping_from_inner(const cni_inner_port_mapping *src, struct cni_port_mapping *dst)
{
    if (src == NULL) {
        return 0;
    }
    if (dst == NULL) {
        ERROR("Invalid dst");
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

static char *get_cache_file_path(const char *net_name, const char *cache_dir, const struct runtime_conf *rc)
{
    const char *use_dir = cache_dir;
    char buff[PATH_MAX] = { 0 };

    if (rc == NULL || net_name == NULL || rc->container_id == NULL || rc->ifname == NULL) {
        ERROR("cache file path requires network name: '$=%s', container id: '%s', if name: '%s'", net_name,
              rc != NULL ? rc->container_id : "", rc != NULL ? rc->ifname : "");
        return NULL;
    }

    if (use_dir == NULL) {
        use_dir = DEFAULT_CACHE_DIR;
    }
    if (snprintf(buff, PATH_MAX, "%s/results/%s-%s-%s", use_dir, net_name, rc->container_id, rc->ifname) < 0) {
        ERROR("format cache file path failed");
        return NULL;
    }

    return util_strdup_s(buff);
}

static bool parse_portmapping_for_cache(const struct runtime_conf *rc, cni_cached_info *p_info)
{
    size_t i;

    if (rc->p_mapping_len == 0) {
        return true;
    }
    p_info->port_mappings = util_smart_calloc_s(sizeof(cni_inner_port_mapping *), rc->p_mapping_len);
    if (p_info->port_mappings == NULL) {
        ERROR("Out of memory");
        return false;
    }

    for (i = 0; i < rc->p_mapping_len; i++) {
        p_info->port_mappings[i] = util_common_calloc_s(sizeof(cni_inner_port_mapping));
        if (p_info->port_mappings[i] == NULL) {
            ERROR("Out of memory");
            return false;
        }
        if (copy_cni_port_mapping(rc->p_mapping[i], p_info->port_mappings[i]) != 0) {
            return false;
        }
        p_info->port_mappings_len += 1;
    }

    return true;
}

static int do_save_cache(const char *fname, const cni_cached_info *p_info)
{
    struct parser_context ctx = { OPT_PARSE_STRICT, stderr };
    char *data = NULL;
    parser_error jerr = NULL;
    int ret = 0;

    data = cni_cached_info_generate_json(p_info, &ctx, &jerr);
    if (data == NULL) {
        ERROR("generate cache data failed: %s", jerr);
        ret = -1;
        goto out;
    }

    ret = util_atomic_write_file(fname, data, strlen(data), SECURE_CONFIG_FILE_MODE, true);

out:
    free(data);
    free(jerr);
    return ret;
}

static int do_cache_insert_cni_args(const struct runtime_conf *rc, cni_cached_info *p_info)
{
    size_t i;
    int ret = 0;
    json_map_string_string *tmp_args = NULL;

    if (rc->args_len == 0) {
        return 0;
    }

    tmp_args = util_common_calloc_s(sizeof(json_map_string_string));
    if (tmp_args == NULL) {
        ret = -1;
        ERROR("Out of memory");
        goto free_out;
    }
    tmp_args->keys = util_smart_calloc_s(sizeof(char *), rc->args_len);
    if (tmp_args->keys == NULL) {
        ret = -1;
        ERROR("Out of memory");
        goto free_out;
    }
    tmp_args->values = util_smart_calloc_s(sizeof(char *), rc->args_len);
    if (tmp_args->values == NULL) {
        ret = -1;
        ERROR("Out of memory");
        goto free_out;
    }

    for (i = 0; i < rc->args_len; i++) {
        tmp_args->keys[i] = util_strdup_s(rc->args[i][0]);
        tmp_args->values[i] = util_strdup_s(rc->args[i][1]);
        tmp_args->len += 1;
    }

    p_info->cni_args = tmp_args;
    tmp_args = NULL;

free_out:
    free_json_map_string_string(tmp_args);
    return ret;
}

int cni_cache_add(const char *cache_dir, const struct cni_opt_result *res, const char *config, const char *net_name,
                  const struct runtime_conf *rc)
{
    int ret = 0;
    char *file_path = NULL;
    cni_cached_info *p_info = NULL;

    if (rc == NULL || res == NULL || net_name == NULL) {
        ERROR("Empty arguments");
        return -1;
    }

    file_path = get_cache_file_path(net_name, cache_dir, rc);
    if (file_path == NULL) {
        return -1;
    }

    if (util_build_dir(file_path) != 0) {
        goto free_out;
    }

    p_info = util_common_calloc_s(sizeof(cni_cached_info));
    if (p_info == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    // parse result
    p_info->result = cni_result_curr_to_json_result(res);
    if (p_info->result == NULL) {
        ret = -1;
        goto free_out;
    }

    // add capability args at here:
    // 1. add portmappings
    if (!parse_portmapping_for_cache(rc, p_info)) {
        ERROR("parse portmapping failed");
        ret = -1;
        goto free_out;
    }
    // 2. add bandwidth

    // 3. add cni args
    if (do_cache_insert_cni_args(rc, p_info) != 0) {
        ret = -1;
        goto free_out;
    }

    p_info->kind = util_strdup_s(CNI_CACHE_V1);
    p_info->container_id = util_strdup_s(rc->container_id);
    p_info->config = util_strdup_s(config);
    p_info->if_name = util_strdup_s(rc->ifname);
    p_info->network_name = util_strdup_s(net_name);

    ret = do_save_cache(file_path, p_info);

free_out:
    free(file_path);
    free_cni_cached_info(p_info);
    return ret;
}

int cni_cache_delete(const char *cache_dir, const char *net_name, const struct runtime_conf *rc)
{
    int ret = 0;
    char *file_path = NULL;
    int get_err = 0;

    if (rc == NULL || net_name == NULL) {
        ERROR("Empty arguments");
        return -1;
    }

    file_path = get_cache_file_path(net_name, cache_dir, rc);
    if (file_path == NULL) {
        return -1;
    }

    if (!util_force_remove_file(file_path, &get_err)) {
        ERROR("Failed to delete %s, error: %s", file_path, strerror(get_err));
    }

    free(file_path);
    return ret;
}

cni_cached_info *cni_cache_read(const char *cache_dir, const char *net_name, const struct runtime_conf *rc)
{
    char *file_path = NULL;
    struct parser_context ctx = { OPT_PARSE_STRICT, stderr };
    parser_error jerr = NULL;
    cni_cached_info *info = NULL;

    if (rc == NULL || net_name == NULL) {
        ERROR("Empty arguments");
        return NULL;
    }

    file_path = get_cache_file_path(net_name, cache_dir, rc);
    if (file_path == NULL) {
        return NULL;
    }

    info = cni_cached_info_parse_file(file_path, &ctx, &jerr);
    if (info == NULL) {
        ERROR("Parse cache info failed: %s", jerr);
    }

    free(jerr);
    free(file_path);
    return info;
}

static bool do_check_version_of_result(const cni_cached_info *c_info, const char *hope_version)
{
    if (hope_version == NULL) {
        return true;
    }

    if (c_info->result == NULL) {
        ERROR("Empty result");
        return false;
    }

    if (c_info->result->cni_version == NULL) {
        ERROR("Empty version of result");
        return false;
    }

    if (strcmp(c_info->result->cni_version, hope_version) != 0) {
        ERROR("hope version: %s, but get: %s", hope_version, c_info->result->cni_version);
        return false;
    }

    return true;
}

int cni_get_cached_result(const char *cache_dir, const char *net_name, const char *hope_version,
                          const struct runtime_conf *rc, struct cni_opt_result **result)
{
    cni_cached_info *c_info = NULL;
    struct cni_opt_result *cached_res = NULL;
    int ret = 0;

    if (rc == NULL || result == NULL) {
        ERROR("Empty return arguments");
        return -1;
    }

    c_info = cni_cache_read(cache_dir, net_name, rc);
    if (c_info == NULL) {
        // ignore read errors
        WARN("failed to unmarshal cached network: %s config", net_name);
        goto out;
    }

    if (c_info->kind == NULL || strcmp(c_info->kind, CNI_CACHE_V1) != 0) {
        ERROR("read cached network: %s config has wrong kind: %s", net_name, c_info->kind);
        ret = -1;
        goto out;
    }

    if (!do_check_version_of_result(c_info, hope_version)) {
        ret = -1;
        goto out;
    }

    cached_res = copy_result_from_current(c_info->result);
    if (cached_res == NULL) {
        ret = -1;
        ERROR("Parse result failed");
        goto out;
    }

    *result = cached_res;
    cached_res = NULL;
out:
    free_cni_opt_result(cached_res);
    free_cni_cached_info(c_info);
    return ret;
}
