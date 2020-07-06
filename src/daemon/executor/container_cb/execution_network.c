/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container network callback function definition
 ********************************************************************************/
#include "execution_network.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/json_common.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "container_api.h"
#include "namespace.h"
#include "path.h"
#include "constants.h"
#include "err_msg.h"
#include "utils_file.h"
#include "utils_string.h"

static int write_hostname_to_file(const char *rootfs, const char *hostname)
{
    int ret = 0;
    char *file_path = NULL;
    char *tmp = NULL;
    char sbuf[MAX_HOST_NAME_LEN] = { 0 };

    if (hostname == NULL) {
        goto out;
    }

    if (realpath_in_scope(rootfs, "/etc/hostname", &file_path) < 0) {
        SYSERROR("Failed to get real path '/etc/hostname' under rootfs '%s'", rootfs);
        isulad_set_error_message("Failed to get real path '/etc/hostname' under rootfs '%s'", rootfs);
        goto out;
    }

    if (util_file_exists(file_path) && util_file2str(file_path, sbuf, sizeof(sbuf)) > 0) {
        tmp = util_strdup_s(sbuf);
        (void)util_trim_newline(tmp);
        tmp = util_trim_space(tmp);
        if (strcmp("", tmp) != 0 && strcmp("localhost", tmp) != 0) {
            goto out;
        }
    }

    ret = util_write_file(file_path, hostname, strlen(hostname), NETWORK_MOUNT_FILE_MODE);
    if (ret) {
        SYSERROR("Failed to write %s", file_path);
        isulad_set_error_message("Failed to write %s: %s", file_path, strerror(errno));
        goto out;
    }

out:
    free(tmp);
    free(file_path);
    return ret;
}

static int fopen_network(FILE **fp, char **file_path, const char *rootfs, const char *filename)
{
    if (realpath_in_scope(rootfs, filename, file_path) < 0) {
        SYSERROR("Failed to get real path '%s' under rootfs '%s'", filename, rootfs);
        isulad_set_error_message("Failed to get real path '%s' under rootfs '%s'", filename, rootfs);
        return -1;
    }
    *fp = util_fopen(*file_path, "a+");
    if (*fp == NULL) {
        SYSERROR("Failed to open %s", *file_path);
        isulad_set_error_message("Failed to open %s: %s", *file_path, strerror(errno));
        return -1;
    }
    return 0;
}

static int get_content_and_hosts_map(FILE *fp, char **content, json_map_string_bool *hosts_map)
{
    int ret = 0;
    size_t length = 0;
    char *pline = NULL;
    char *tmp = NULL;
    char *host_name = NULL;
    char *host_ip = NULL;
    char *saveptr = NULL;

    while (getline(&pline, &length, fp) != -1) {
        char *tmp_str = NULL;
        char host_key[MAX_BUFFER_SIZE] = { 0 };
        if (pline == NULL) {
            ERROR("get hosts content failed");
            return -1;
        }
        if (pline[0] == '#') {
            tmp = util_string_append(pline, *content);
            free(*content);
            *content = tmp;
            continue;
        }
        tmp_str = util_strdup_s(pline);
        if (tmp_str == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        util_trim_newline(tmp_str);
        host_ip = strtok_r(tmp_str, " ", &saveptr);
        host_name = strtok_r(NULL, " ", &saveptr);
        if (host_ip != NULL && host_name != NULL) {
            int nret = snprintf(host_key, sizeof(host_key), "%s:%s", host_ip, host_name);
            if ((size_t)nret >= sizeof(host_key) || nret < 0) {
                free(tmp_str);
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
            if (append_json_map_string_bool(hosts_map, host_key, true)) {
                free(tmp_str);
                ERROR("append data to hosts map failed");
                ret = -1;
                goto out;
            }
            tmp = util_string_append(pline, *content);
            free(*content);
            *content = tmp;
        }
        free(tmp_str);
    }

out:
    free(pline);
    return ret;
}

static int write_content_to_file(const char *file_path, const char *content)
{
    int ret = 0;

    if (content != NULL) {
        ret = util_write_file(file_path, content, strlen(content), NETWORK_MOUNT_FILE_MODE);
        if (ret != 0) {
            SYSERROR("Failed to write file %s", file_path);
            isulad_set_error_message("Failed to write file %s: %s", file_path, strerror(errno));
            return ret;
        }
    }
    return ret;
}

static int merge_hosts_content(const host_config *host_spec, char **content, json_map_string_bool *hosts_map)
{
    size_t i, j;
    char *tmp = NULL;
    char *saveptr = NULL;

    for (i = 0; i < host_spec->extra_hosts_len; i++) {
        bool need_to_add = true;
        char *host_name = NULL;
        char *host_ip = NULL;
        char *hosts = NULL;
        char host_key[MAX_BUFFER_SIZE] = { 0 };
        hosts = util_strdup_s(host_spec->extra_hosts[i]);
        if (hosts == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        host_name = strtok_r(hosts, ":", &saveptr);
        host_ip = strtok_r(NULL, ":", &saveptr);
        if (host_name == NULL || host_ip == NULL) {
            free(hosts);
            ERROR("extra host '%s' format error.", host_spec->extra_hosts[i]);
            return -1;
        }
        int nret = snprintf(host_key, sizeof(host_key), "%s:%s", host_ip, host_name);
        if ((size_t)nret >= sizeof(host_key) || nret < 0) {
            free(hosts);
            ERROR("Out of memory");
            return -1;
        }
        for (j = 0; j < hosts_map->len; j++) {
            if (strcmp(host_key, hosts_map->keys[j]) == 0) {
                need_to_add = false;
                break;
            }
        }
        if (need_to_add) {
            tmp = util_string_append(host_ip, *content);
            free(*content);
            *content = tmp;
            tmp = util_string_append(" ", *content);
            free(*content);
            *content = tmp;
            tmp = util_string_append(host_name, *content);
            free(*content);
            *content = tmp;
            tmp = util_string_append("\n", *content);
            free(*content);
            *content = tmp;
            if (append_json_map_string_bool(hosts_map, host_key, true)) {
                free(hosts);
                ERROR("append data to hosts map failed");
                return -1;
            }
        }
        free(hosts);
    }
    return 0;
}

static int merge_hosts(const host_config *host_spec, const char *rootfs)
{
    int ret = 0;
    char *content = NULL;
    char *file_path = NULL;
    FILE *fp = NULL;
    json_map_string_bool *hosts_map = NULL;

    hosts_map = (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
    if (hosts_map == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto error_out;
    }
    ret = fopen_network(&fp, &file_path, rootfs, "/etc/hosts");
    if (ret != 0) {
        goto error_out;
    }
    ret = get_content_and_hosts_map(fp, &content, hosts_map);
    if (ret != 0) {
        goto error_out;
    }
    ret = merge_hosts_content(host_spec, &content, hosts_map);
    if (ret != 0) {
        goto error_out;
    }
    ret = write_content_to_file(file_path, content);
    if (ret != 0) {
        goto error_out;
    }

error_out:
    free(content);
    free(file_path);
    if (fp != NULL) {
        fclose(fp);
    }
    free_json_map_string_bool(hosts_map);
    return ret;
}

static int merge_dns_search(const host_config *host_spec, char **content, const char *token, char *saveptr)
{
    int ret = 0;
    size_t i, j;
    size_t content_len = strlen(*content);
    char *tmp = NULL;
    json_map_string_bool *dns_search_map = NULL;

    dns_search_map = (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
    if (dns_search_map == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto error_out;
    }
    while (token != NULL) {
        token = strtok_r(NULL, " ", &saveptr);
        if (token != NULL) {
            if (append_json_map_string_bool(dns_search_map, token, true)) {
                ERROR("append data to dns search map failed");
                ret = -1;
                goto error_out;
            }
        }
    }
    for (i = 0; i < host_spec->dns_search_len; i++) {
        bool need_to_add = true;
        for (j = 0; j < dns_search_map->len; j++) {
            if (strcmp(host_spec->dns_search[i], dns_search_map->keys[j]) == 0) {
                need_to_add = false;
                break;
            }
        }
        if (need_to_add) {
            if (strlen(*content) > 0) {
                (*content)[strlen(*content) - 1] = ' ';
            }
            tmp = util_string_append(host_spec->dns_search[i], *content);
            free(*content);
            *content = tmp;
            tmp = util_string_append(" ", *content);
            free(*content);
            *content = tmp;
            if (append_json_map_string_bool(dns_search_map, host_spec->dns_search[i], true)) {
                ERROR("append data to dns search map failed");
                ret = -1;
                goto error_out;
            }
        }
    }
    if (*content != NULL && strlen(*content) > content_len) {
        (*content)[strlen(*content) - 1] = '\n';
    }

error_out:
    free_json_map_string_bool(dns_search_map);
    return ret;
}

static int merge_dns_options(const host_config *host_spec, char **content, const char *token, char *saveptr)
{
    int ret = 0;
    size_t i, j;
    size_t content_len = strlen(*content);
    char *tmp = NULL;
    json_map_string_bool *dns_options_map = NULL;

    dns_options_map = (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
    if (dns_options_map == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto error_out;
    }
    while (token != NULL) {
        token = strtok_r(NULL, " ", &saveptr);
        if (token != NULL) {
            if (append_json_map_string_bool(dns_options_map, token, true)) {
                ERROR("append data to dns options map failed");
                ret = -1;
                goto error_out;
            }
        }
    }
    for (i = 0; i < host_spec->dns_options_len; i++) {
        bool need_to_add = true;
        for (j = 0; j < dns_options_map->len; j++) {
            if (strcmp(host_spec->dns_options[i], dns_options_map->keys[j]) == 0) {
                need_to_add = false;
                break;
            }
        }
        if (need_to_add) {
            if (strlen(*content) > 0) {
                (*content)[strlen(*content) - 1] = ' ';
            }
            tmp = util_string_append(host_spec->dns_options[i], *content);
            free(*content);
            *content = tmp;
            tmp = util_string_append(" ", *content);
            free(*content);
            *content = tmp;
            if (append_json_map_string_bool(dns_options_map, host_spec->dns_options[i], true)) {
                ERROR("append data to dns options map failed");
                ret = -1;
                goto error_out;
            }
        }
    }
    if (*content != NULL && strlen(*content) > content_len) {
        (*content)[strlen(*content) - 1] = '\n';
    }

error_out:
    free_json_map_string_bool(dns_options_map);
    return ret;
}

static int merge_dns(const host_config *host_spec, char **content, json_map_string_bool *dns_map)
{
    size_t i, j;
    char *tmp = NULL;

    for (i = 0; i < host_spec->dns_len; i++) {
        bool need_to_add = true;
        for (j = 0; j < dns_map->len; j++) {
            if (strcmp(host_spec->dns[i], dns_map->keys[j]) == 0) {
                need_to_add = false;
                break;
            }
        }
        if (need_to_add) {
            tmp = util_string_append("nameserver ", *content);
            free(*content);
            *content = tmp;
            tmp = util_string_append(host_spec->dns[i], *content);
            free(*content);
            *content = tmp;
            tmp = util_string_append("\n", *content);
            free(*content);
            *content = tmp;
            if (append_json_map_string_bool(dns_map, host_spec->dns[i], true)) {
                ERROR("append data to dns map failed");
                return -1;
            }
        }
    }
    return 0;
}

static bool is_need_add(const char *dns_search, const json_map_string_bool *dns_search_map)
{
    bool need_to_add = true;
    size_t j;

    for (j = 0; j < dns_search_map->len; j++) {
        if (strcmp(dns_search, dns_search_map->keys[j]) == 0) {
            need_to_add = false;
            break;
        }
    }

    return need_to_add;
}

static int generate_new_search(const host_config *host_spec, json_map_string_bool *dns_search_map, char **content,
                               bool search)
{
    char *tmp = NULL;

    if (!search && host_spec->dns_search_len > 0) {
        size_t i;
        tmp = util_string_append("search ", *content);
        free(*content);
        *content = tmp;
        for (i = 0; i < host_spec->dns_search_len; i++) {
            if (!is_need_add(host_spec->dns_search[i], dns_search_map)) {
                continue;
            }

            if (append_json_map_string_bool(dns_search_map, host_spec->dns_search[i], true)) {
                ERROR("append data to dns search map failed");
                return -1;
            }
            tmp = util_string_append(host_spec->dns_search[i], *content);
            free(*content);
            *content = tmp;
            tmp = util_string_append(" ", *content);
            free(*content);
            *content = tmp;
        }
        tmp = util_string_append("\n", *content);
        free(*content);
        *content = tmp;
    }
    return 0;
}

static int generate_new_options(const host_config *host_spec, json_map_string_bool *dns_options_map, char **content,
                                bool options)
{
    char *tmp = NULL;

    if (!options && host_spec->dns_options_len > 0) {
        size_t i;
        tmp = util_string_append("options ", *content);
        free(*content);
        *content = tmp;
        for (i = 0; i < host_spec->dns_options_len; i++) {
            if (!is_need_add(host_spec->dns_options[i], dns_options_map)) {
                continue;
            }

            if (append_json_map_string_bool(dns_options_map, host_spec->dns_options[i], true)) {
                ERROR("append data to dns options map failed");
                return -1;
            }
            tmp = util_string_append(host_spec->dns_options[i], *content);
            free(*content);
            *content = tmp;
            tmp = util_string_append(" ", *content);
            free(*content);
            *content = tmp;
        }
        tmp = util_string_append("\n", *content);
        free(*content);
        *content = tmp;
    }
    return 0;
}

static int generate_new_search_and_options(const host_config *host_spec, char **content, bool search, bool options)
{
    int ret = 0;
    json_map_string_bool *dns_search_map = NULL;
    json_map_string_bool *dns_options_map = NULL;

    dns_search_map = (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
    if (dns_search_map == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto error_out;
    }
    dns_options_map = (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
    if (dns_options_map == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto error_out;
    }
    ret = generate_new_search(host_spec, dns_search_map, content, search);
    if (ret) {
        goto error_out;
    }
    ret = generate_new_options(host_spec, dns_options_map, content, options);
    if (ret) {
        goto error_out;
    }

error_out:
    free_json_map_string_bool(dns_search_map);
    free_json_map_string_bool(dns_options_map);
    return ret;
}

static int resolve_handle_content(const char *pline, const host_config *host_spec, char **content,
                                  json_map_string_bool *dns_map, bool *search, bool *options)
{
    int ret = 0;
    char *tmp = NULL;
    char *token = NULL;
    char *saveptr = NULL;
    char *tmp_str = NULL;

    if (pline[0] == '#') {
        tmp = util_string_append(pline, *content);
        free(*content);
        *content = tmp;
        return 0;
    }
    tmp_str = util_strdup_s(pline);
    if (tmp_str == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto cleanup;
    }
    util_trim_newline(tmp_str);
    tmp_str = util_trim_space(tmp_str);
    if (strcmp("", tmp_str) == 0) {
        goto cleanup;
    }
    token = strtok_r(tmp_str, " ", &saveptr);
    if (token == NULL) {
        ret = -1;
        goto cleanup;
    }
    if (strcmp(token, "search") == 0) {
        *search = true;
        tmp = util_string_append(pline, *content);
        if (tmp == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto cleanup;
        }
        free(*content);
        *content = tmp;
        ret = merge_dns_search(host_spec, content, token, saveptr);
    } else if (strcmp(token, "options") == 0) {
        *options = true;
        tmp = util_string_append(pline, *content);
        if (tmp == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto cleanup;
        }
        free(*content);
        *content = tmp;
        ret = merge_dns_options(host_spec, content, token, saveptr);
    } else if (strcmp(token, "nameserver") == 0) {
        tmp = util_string_append(pline, *content);
        free(*content);
        *content = tmp;
        token = strtok_r(NULL, " ", &saveptr);
        if (token == NULL) {
            ret = -1;
            goto cleanup;
        }
        if (append_json_map_string_bool(dns_map, token, true)) {
            ERROR("append data to dns map failed");
            ret = -1;
            goto cleanup;
        }
    }
cleanup:
    free(tmp_str);
    return ret;
}

static int merge_resolv(const host_config *host_spec, const char *rootfs, const char *resolv_conf_path)
{
    int ret = 0;
    size_t length = 0;
    bool search = false;
    bool options = false;
    char *pline = NULL;
    char *content = NULL;
    char *file_path = NULL;
    FILE *fp = NULL;
    json_map_string_bool *dns_map = NULL;

    dns_map = (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
    if (dns_map == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto error_out;
    }
    ret = fopen_network(&fp, &file_path, rootfs, resolv_conf_path);
    if (ret != 0) {
        goto error_out;
    }

    while (getline(&pline, &length, fp) != -1) {
        if (pline == NULL) {
            ERROR("get resolv content failed");
            ret = -1;
            goto error_out;
        }
        ret = resolve_handle_content(pline, host_spec, &content, dns_map, &search, &options);
        if (ret != 0) {
            goto error_out;
        }
    }
    ret = merge_dns(host_spec, &content, dns_map);
    if (ret) {
        goto error_out;
    }
    ret = generate_new_search_and_options(host_spec, &content, search, options);
    if (ret) {
        goto error_out;
    }
    ret = write_content_to_file(file_path, content);
    if (ret) {
        goto error_out;
    }

error_out:
    free(pline);
    free(file_path);
    free(content);
    if (fp != NULL) {
        fclose(fp);
    }
    free_json_map_string_bool(dns_map);
    return ret;
}

static int chown_network(const char *user_remap, const char *rootfs, const char *filename)
{
    int ret = 0;
    char *file_path = NULL;
    unsigned int host_uid = 0;
    unsigned int host_gid = 0;
    unsigned int size = 0;

    if (user_remap == NULL) {
        return 0;
    }
    ret = util_parse_user_remap(user_remap, &host_uid, &host_gid, &size);
    if (ret) {
        ERROR("Failed to parse user remap:'%s'", user_remap);
        ret = -1;
        goto out;
    }
    if (realpath_in_scope(rootfs, filename, &file_path) < 0) {
        SYSERROR("Failed to get real path '%s' under rootfs '%s'", filename, rootfs);
        isulad_set_error_message("Failed to get real path '%s' under rootfs '%s'", filename, rootfs);
        ret = -1;
        goto out;
    }
    if (chown(file_path, host_uid, host_gid) != 0) {
        SYSERROR("Failed to chown network file '%s' to %u:%u", filename, host_uid, host_gid);
        isulad_set_error_message("Failed to chown network file '%s' to %u:%u: %s", filename, host_uid, host_gid,
                                 strerror(errno));
        ret = -1;
        goto out;
    }

out:
    free(file_path);
    return ret;
}

static int merge_network_for_universal_container(const host_config *host_spec, const char *runtime_root, const char *id)
{
    int ret = 0;
    int nret = 0;
    char root_path[PATH_MAX] = { 0x00 };

    if (runtime_root == NULL || id == NULL) {
        ERROR("empty runtime root or id");
        return -1;
    }

    nret = snprintf(root_path, PATH_MAX, "%s/%s", runtime_root, id);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Failed to print string");
        return -1;
    }

    ret = merge_resolv(host_spec, root_path, "/resolv.conf");
    if (ret) {
        return -1;
    }

    return 0;
}

static int merge_network_for_syscontainer(const host_config *host_spec, const char *rootfs, const char *hostname)
{
    int ret = 0;

    ret = write_hostname_to_file(rootfs, hostname);
    if (ret) {
        return -1;
    }
    ret = chown_network(host_spec->user_remap, rootfs, "/etc/hostname");
    if (ret) {
        return -1;
    }
    ret = merge_hosts(host_spec, rootfs);
    if (ret) {
        return -1;
    }
    ret = chown_network(host_spec->user_remap, rootfs, "/etc/hosts");
    if (ret) {
        return -1;
    }
    ret = merge_resolv(host_spec, rootfs, "/etc/resolv.conf");
    if (ret) {
        return -1;
    }
    ret = chown_network(host_spec->user_remap, rootfs, "/etc/resolv.conf");
    if (ret) {
        return -1;
    }
    return 0;
}

int merge_network(const host_config *host_spec, const char *rootfs, const char *runtime_root, const char *id,
                  const char *hostname)
{
    int ret = 0;

    if (host_spec == NULL) {
        return -1;
    }

    if (!host_spec->system_container || rootfs == NULL) {
        ret = merge_network_for_universal_container(host_spec, runtime_root, id);
    } else {
        ret = merge_network_for_syscontainer(host_spec, rootfs, hostname);
    }

    return ret;
}

static container_t *get_networked_container(const char *id, const char *connected_id, bool check_state)
{
    container_t *nc = NULL;

    nc = containers_store_get(connected_id);
    if (nc == NULL) {
        ERROR("No such container: %s", connected_id);
        isulad_set_error_message("No such container: %s", connected_id);
        return NULL;
    }
    if (strcmp(id, nc->common_config->id) == 0) {
        ERROR("cannot join own network");
        isulad_set_error_message("cannot join own network");
        goto cleanup;
    }
    if (!check_state) {
        return nc;
    }
    if (!container_is_running(nc->state)) {
        ERROR("cannot join network of a non running container: %s", connected_id);
        isulad_set_error_message("cannot join network of a non running container: %s", connected_id);
        goto cleanup;
    }
    if (container_is_restarting(nc->state)) {
        ERROR("Container %s is restarting, wait until the container is running", connected_id);
        isulad_set_error_message("Container %s is restarting, wait until the container is running", connected_id);
        goto cleanup;
    }

    return nc;

cleanup:
    container_unref(nc);
    return NULL;
}

static int init_container_network_confs_container(const char *id, const host_config *hc,
                                                  container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    size_t len = strlen(SHARE_NAMESPACE_PREFIX);
    container_t *nc = NULL;

    nc = get_networked_container(id, hc->network_mode + len, false);
    if (nc == NULL) {
        ERROR("Error to get networked container");
        return -1;
    }

    if (nc->common_config->hostname_path != NULL) {
        free(v2_spec->hostname_path);
        v2_spec->hostname_path = util_strdup_s(nc->common_config->hostname_path);
    }
    if (nc->common_config->hosts_path != NULL) {
        free(v2_spec->hosts_path);
        v2_spec->hosts_path = util_strdup_s(nc->common_config->hosts_path);
    }
    if (nc->common_config->resolv_conf_path != NULL) {
        free(v2_spec->resolv_conf_path);
        v2_spec->resolv_conf_path = util_strdup_s(nc->common_config->resolv_conf_path);
    }

    if (nc->common_config->config != NULL && nc->common_config->config->hostname != NULL) {
        free(v2_spec->config->hostname);
        v2_spec->config->hostname = util_strdup_s(nc->common_config->config->hostname);
    }

    container_unref(nc);
    return ret;
}

static int create_default_hostname(const char *id, const char *rootpath, bool share_host,
                                   container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    int nret = 0;
    char file_path[PATH_MAX] = { 0x0 };
    char hostname_content[MAX_HOST_NAME_LEN + 2] = { 0 };

    if (v2_spec->config->hostname == NULL) {
        if (share_host) {
            char hostname[MAX_HOST_NAME_LEN] = { 0x00 };
            ret = gethostname(hostname, sizeof(hostname));
            if (ret != 0) {
                ERROR("Get hostname error");
                goto out;
            }
            v2_spec->config->hostname = util_strdup_s(hostname);
        } else {
            v2_spec->config->hostname = util_strdup_s("localhost");
        }
    }

    nret = snprintf(file_path, PATH_MAX, "%s/%s/%s", rootpath, id, "hostname");
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    nret = snprintf(hostname_content, MAX_HOST_NAME_LEN + 2, "%s\n", v2_spec->config->hostname);
    if (nret < 0 || (size_t)nret >= sizeof(hostname_content)) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    if (util_write_file(file_path, hostname_content, strlen(hostname_content), NETWORK_MOUNT_FILE_MODE) != 0) {
        ERROR("Failed to create default hostname");
        ret = -1;
        goto out;
    }

    free(v2_spec->hostname_path);
    v2_spec->hostname_path = util_strdup_s(file_path);

out:
    return ret;
}

static int write_default_hosts(const char *file_path, const char *hostname)
{
    int ret = 0;
    char *content = NULL;
    size_t content_len = 0;
    const char *default_config = "127.0.0.1       localhost\n"
                                 "::1     localhost ip6-localhost ip6-loopback\n"
                                 "fe00::0 ip6-localnet\n"
                                 "ff00::0 ip6-mcastprefix\n"
                                 "ff02::1 ip6-allnodes\n"
                                 "ff02::2 ip6-allrouters\n";
    const char *loop_ip = "127.0.0.1    ";

    if (strlen(hostname) > (((SIZE_MAX - strlen(default_config)) - strlen(loop_ip)) - 2)) {
        ret = -1;
        goto out_free;
    }

    content_len = strlen(default_config) + strlen(loop_ip) + strlen(hostname) + 1 + 1;
    content = util_common_calloc_s(content_len);
    if (content == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out_free;
    }

    ret = snprintf(content, content_len, "%s%s%s\n", default_config, loop_ip, hostname);
    if (ret < 0 || (size_t)ret >= content_len) {
        ERROR("Failed to generate default hosts");
        ret = -1;
        goto out_free;
    }

    ret = util_write_file(file_path, content, strlen(content), NETWORK_MOUNT_FILE_MODE);
    if (ret != 0) {
        ret = -1;
        goto out_free;
    }

out_free:
    free(content);
    return ret;
}

static int create_default_hosts(const char *id, const char *rootpath, bool share_host,
                                container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    char file_path[PATH_MAX] = { 0x0 };

    ret = snprintf(file_path, PATH_MAX, "%s/%s/%s", rootpath, id, "hosts");
    if (ret < 0 || ret >= PATH_MAX) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    if (share_host && util_file_exists(ETC_HOSTS)) {
        ret = util_copy_file(ETC_HOSTS, file_path, NETWORK_MOUNT_FILE_MODE);
    } else {
        ret = write_default_hosts(file_path, v2_spec->config->hostname);
    }

    if (ret != 0) {
        ERROR("Failed to create default hosts");
        goto out;
    }

    free(v2_spec->hosts_path);
    v2_spec->hosts_path = util_strdup_s(file_path);

out:
    return ret;
}

static int write_default_resolve(const char *file_path)
{
    const char *default_ipv4_dns = "\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n";
    ;

    return util_write_file(file_path, default_ipv4_dns, strlen(default_ipv4_dns), NETWORK_MOUNT_FILE_MODE);
}

static int create_default_resolv(const char *id, const char *rootpath, container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    char file_path[PATH_MAX] = { 0x0 };

    ret = snprintf(file_path, PATH_MAX, "%s/%s/%s", rootpath, id, "resolv.conf");
    if (ret < 0 || ret >= PATH_MAX) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    if (util_file_exists(RESOLV_CONF_PATH)) {
        ret = util_copy_file(RESOLV_CONF_PATH, file_path, NETWORK_MOUNT_FILE_MODE);
    } else {
        ret = write_default_resolve(file_path);
    }

    if (ret != 0) {
        ERROR("Failed to create default resolv.conf");
        goto out;
    }

    free(v2_spec->resolv_conf_path);
    v2_spec->resolv_conf_path = util_strdup_s(file_path);

out:
    return ret;
}

int init_container_network_confs(const char *id, const char *rootpath, const host_config *hc,
                                 container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    bool share_host = is_host(hc->network_mode);

    // is container mode
    if (is_container(hc->network_mode)) {
        return init_container_network_confs_container(id, hc, v2_spec);
    }

    if (create_default_hostname(id, rootpath, share_host, v2_spec) != 0) {
        ERROR("Failed to create default hostname");
        ret = -1;
        goto out;
    }

    if (create_default_hosts(id, rootpath, share_host, v2_spec) != 0) {
        ERROR("Failed to create default hosts");
        ret = -1;
        goto out;
    }

    if (create_default_resolv(id, rootpath, v2_spec) != 0) {
        ERROR("Failed to create default resolv.conf");
        ret = -1;
        goto out;
    }

out:
    return ret;
}
