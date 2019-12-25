/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container network callback function definition
 ********************************************************************************/
#include "execution_network.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <lcr/lcrcontainer.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <malloc.h>

#include "log.h"
#include "utils.h"
#include "lcrd_config.h"
#include "config.h"
#include "containers_store.h"
#include "namespace.h"
#include "path.h"

static int write_hostname_to_file(const char *rootfs, const char *hostname)
{
    int ret = 0;
    char *file_path = NULL;

    if (realpath_in_scope(rootfs, "/etc/hostname", &file_path) < 0) {
        SYSERROR("Failed to get real path '/etc/hostname' under rootfs '%s'", rootfs);
        lcrd_set_error_message("Failed to get real path '/etc/hostname' under rootfs '%s'", rootfs);
        goto error_out;
    }
    if (hostname != NULL) {
        ret = util_write_file(file_path, hostname, strlen(hostname));
        if (ret) {
            SYSERROR("Failed to write %s", file_path);
            lcrd_set_error_message("Failed to write %s: %s", file_path, strerror(errno));
            goto error_out;
        }
    }

error_out:
    free(file_path);
    return ret;
}

static int fopen_network(FILE **fp, char **file_path, const char *rootfs, const char *filename)
{
    if (realpath_in_scope(rootfs, filename, file_path) < 0) {
        SYSERROR("Failed to get real path '%s' under rootfs '%s'", filename, rootfs);
        lcrd_set_error_message("Failed to get real path '%s' under rootfs '%s'", filename, rootfs);
        return -1;
    }
    *fp = util_fopen(*file_path, "a+");
    if (*fp == NULL) {
        SYSERROR("Failed to open %s", *file_path);
        lcrd_set_error_message("Failed to open %s: %s", *file_path, strerror(errno));
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
            if (sprintf_s(host_key, sizeof(host_key), "%s:%s", host_ip, host_name) < 0) {
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
        ret = util_write_file(file_path, content, strlen(content));
        if (ret != 0) {
            SYSERROR("Failed to write file %s", file_path);
            lcrd_set_error_message("Failed to write file %s: %s", file_path, strerror(errno));
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
        if (sprintf_s(host_key, sizeof(host_key), "%s:%s", host_ip, host_name) < 0) {
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

static int generate_new_search(const host_config *host_spec,
                               json_map_string_bool *dns_search_map,
                               char **content,
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

static int generate_new_options(const host_config *host_spec,
                                json_map_string_bool *dns_options_map,
                                char **content,
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

static int resolve_handle_content(const char *pline, const host_config *host_spec,
                                  char **content, json_map_string_bool *dns_map, bool *search, bool *options)
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

static int merge_resolv(const host_config *host_spec, const char *rootfs)
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
    ret = fopen_network(&fp, &file_path, rootfs, "/etc/resolv.conf");
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
    size_t path_len = 0;
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
    path_len = strlen(rootfs) + strlen(filename) + 1;
    if (path_len > PATH_MAX) {
        ERROR("Invalid path length");
        ret = -1;
        goto out;
    }
    file_path = util_common_calloc_s(path_len);
    if (file_path == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (sprintf_s(file_path, path_len, "%s%s", rootfs, filename) < 0) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }
    if (chown(file_path, host_uid, host_gid) != 0) {
        SYSERROR("Failed to chown network file '%s' to %u:%u", filename, host_uid, host_gid);
        lcrd_set_error_message("Failed to chown network file '%s' to %u:%u: %s",
                               filename,
                               host_uid,
                               host_gid,
                               strerror(errno));
        ret = -1;
        goto out;
    }

out:
    free(file_path);
    return ret;
}

int merge_network(const host_config *host_spec, const char *rootfs, const char *hostname)
{
    int ret = 0;

    if (host_spec == NULL) {
        return -1;
    }
    if (!host_spec->system_container || rootfs == NULL) {
        return 0;
    }
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
    ret = merge_resolv(host_spec, rootfs);
    if (ret) {
        return -1;
    }
    ret = chown_network(host_spec->user_remap, rootfs, "/etc/resolv.conf");
    if (ret) {
        return -1;
    }
    return 0;
}

static container_t *get_networked_container(const char *id, const char *connected_id, bool check_state)
{
    container_t *nc = NULL;

    nc = containers_store_get(connected_id);
    if (nc == NULL) {
        ERROR("No such container: %s", connected_id);
        lcrd_set_error_message("No such container: %s", connected_id);
        return NULL;
    }
    if (strcmp(id, nc->common_config->id) == 0) {
        ERROR("cannot join own network");
        lcrd_set_error_message("cannot join own network");
        goto cleanup;
    }
    if (!check_state) {
        return nc;
    }
    if (!is_running(nc->state)) {
        ERROR("cannot join network of a non running container: %s", connected_id);
        lcrd_set_error_message("cannot join network of a non running container: %s", connected_id);
        goto cleanup;
    }
    if (is_restarting(nc->state)) {
        ERROR("Container %s is restarting, wait until the container is running", connected_id);
        lcrd_set_error_message("Container %s is restarting, wait until the container is running", connected_id);
        goto cleanup;
    }

    return nc;

cleanup:
    container_unref(nc);
    return NULL;
}

static int init_container_network_confs_container(const char *id, const host_config *hc,
                                                  container_config_v2_common_config *common_config)
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
        free(common_config->hostname_path);
        common_config->hostname_path = util_strdup_s(nc->common_config->hostname_path);
    }
    if (nc->common_config->hosts_path != NULL) {
        free(common_config->hosts_path);
        common_config->hosts_path = util_strdup_s(nc->common_config->hosts_path);
    }
    if (nc->common_config->resolv_conf_path != NULL) {
        free(common_config->resolv_conf_path);
        common_config->resolv_conf_path = util_strdup_s(nc->common_config->resolv_conf_path);
    }

    if (nc->common_config->config != NULL && nc->common_config->config->hostname != NULL) {
        if (common_config->config == NULL) {
            common_config->config = util_common_calloc_s(sizeof(container_config));
            if (common_config->config == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto cleanup;
            }
        }

        free(common_config->config->hostname);
        common_config->config->hostname = util_strdup_s(nc->common_config->config->hostname);
    }

cleanup:
    container_unref(nc);
    return ret;
}

int init_container_network_confs(const char *id, const char *rootpath, const host_config *hc,
                                 container_config_v2_common_config *common_config)
{
    int ret = 0;
    char file_path[PATH_MAX] = { 0x0 };

    // is container mode
    if (is_container(hc->network_mode)) {
        ret = init_container_network_confs_container(id, hc, common_config);
        goto cleanup;
    }

    // is host mode
    if (is_host(hc->network_mode)) {
        if (common_config->config == NULL) {
            common_config->config = util_common_calloc_s(sizeof(container_config));
            if (common_config->config == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto cleanup;
            }
        }
        if (common_config->config->hostname == NULL) {
            char hostname[MAX_HOST_NAME_LEN] = { 0x00 };
            ret = gethostname(hostname, sizeof(hostname));
            if (ret != 0) {
                ERROR("Get hostname error");
                goto cleanup;
            }
            common_config->config->hostname = util_strdup_s(hostname);
        }
    }

    // create hosts, resolv.conf and so
    if (sprintf_s(file_path, PATH_MAX, "%s/%s/%s", rootpath, id, "hosts") < 0) {
        ERROR("Failed to print string");
        ret = -1;
        goto cleanup;
    }
    free(common_config->hosts_path);
    common_config->hosts_path = util_strdup_s(file_path);
    if (sprintf_s(file_path, PATH_MAX, "%s/%s/%s", rootpath, id, "resolv.conf") < 0) {
        ERROR("Failed to print string");
        ret = -1;
        goto cleanup;
    }
    free(common_config->resolv_conf_path);
    common_config->resolv_conf_path = util_strdup_s(file_path);

cleanup:
    return ret;
}

int container_initialize_networking(const container_t *cont)
{
    int ret = 0;
    size_t len = strlen(SHARE_NAMESPACE_PREFIX);
    container_t *nc = NULL;
    host_config *hc = cont->hostconfig;

    // is container mode
    if (is_container(hc->network_mode)) {
        nc = get_networked_container(cont->common_config->id, hc->network_mode + len, true);
        if (nc == NULL) {
            ERROR("Error to get networked container");
            return -1;
        }
    }

    container_unref(nc);
    return ret;
}


