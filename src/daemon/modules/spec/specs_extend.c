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
 * Description: provide container specs functions
 ******************************************************************************/
#include "specs_extend.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_runtime_config_linux.h>
#include <stdint.h>

#include "isula_libutils/log.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/host_config.h"
#include "utils.h"
#include "path.h"
#include "isulad_config.h"
#include "daemon_arguments.h"
#include "err_msg.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"

#define MERGE_HOOKS_ITEM_DEF(item)                                                     \
    int merge_##item##_conf(oci_runtime_spec_hooks *dest, oci_runtime_spec_hooks *src) \
    {                                                                                  \
        size_t old_size = 0;                                                           \
        size_t new_size = 0;                                                           \
        int ret = 0;                                                                   \
        size_t i = 0;                                                                  \
        if (src->item##_len) {                                                         \
            defs_hook **item = NULL;                                                   \
            if (dest->item##_len > (LIST_SIZE_MAX - src->item##_len) - 1) {            \
                ERROR("the length of item element is too long!");                      \
                ret = -1;                                                              \
                goto out;                                                              \
            }                                                                          \
            old_size = dest->item##_len * sizeof(defs_hook *);                         \
            new_size = (dest->item##_len + src->item##_len + 1) * sizeof(defs_hook *); \
            ret = util_mem_realloc((void **)&(item), new_size, dest->item, old_size);  \
            if (ret != 0) {                                                            \
                ERROR("Failed to realloc memory for hooks_" #item " variables");       \
                ret = -1;                                                              \
                goto out;                                                              \
            }                                                                          \
            dest->item = item;                                                         \
            for (; i < src->item##_len; i++) {                                         \
                dest->item[dest->item##_len] = src->item[i];                           \
                dest->item##_len++;                                                    \
                src->item[i] = NULL;                                                   \
            }                                                                          \
            src->item##_len = 0;                                                       \
            free(src->item);                                                           \
            src->item = NULL;                                                          \
        }                                                                              \
    out:                                                                               \
        return ret;                                                                    \
    }

MERGE_HOOKS_ITEM_DEF(prestart)
MERGE_HOOKS_ITEM_DEF(poststart)
MERGE_HOOKS_ITEM_DEF(poststop)

int merge_hooks(oci_runtime_spec_hooks *dest, oci_runtime_spec_hooks *src)
{
    if (dest == NULL || src == NULL) {
        return -1;
    }

    if (merge_prestart_conf(dest, src) || merge_poststart_conf(dest, src) || merge_poststop_conf(dest, src)) {
        return -1;
    }
    return 0;
}

int merge_global_hook(oci_runtime_spec *oci_spec)
{
    int ret = 0;
    oci_runtime_spec_hooks *hooks = NULL;
    oci_runtime_spec_hooks *tmp = NULL;

    if (conf_get_isulad_hooks(&hooks)) {
        ERROR("Failed to get isulad hooks");
        ret = -1;
        goto out;
    }
    if (oci_spec->hooks != NULL) {
        if (hooks != NULL) {
            if (merge_hooks(hooks, oci_spec->hooks)) {
                ret = -1;
                goto out;
            }
            tmp = hooks;
            hooks = oci_spec->hooks;
            oci_spec->hooks = tmp;
        }
    } else {
        oci_spec->hooks = hooks;
        hooks = NULL;
    }
out:
    free_oci_runtime_spec_hooks(hooks);
    return ret;
}

static int make_one_id_mapping(defs_id_mapping ***mappings, unsigned int id, unsigned int size)
{
    *mappings = util_common_calloc_s(sizeof(defs_id_mapping *));
    if (*mappings == NULL) {
        return -1;
    }
    (*mappings)[0] = util_common_calloc_s(sizeof(defs_id_mapping));
    if ((*mappings)[0] == NULL) {
        return -1;
    }
    (*mappings)[0]->host_id = id;
    (*mappings)[0]->container_id = 0;
    (*mappings)[0]->size = size;
    return 0;
}

static int make_linux_uid_gid_mappings(oci_runtime_spec *container, unsigned int host_uid, unsigned int host_gid,
                                       unsigned int size)
{
    int ret = 0;
    if (container->linux->uid_mappings == NULL) {
        ret = make_one_id_mapping(&(container->linux->uid_mappings), host_uid, size);
        if (ret < 0) {
            return ret;
        }
        container->linux->uid_mappings_len++;
    }
    if (container->linux->gid_mappings == NULL) {
        ret = make_one_id_mapping(&(container->linux->gid_mappings), host_gid, size);
        if (ret < 0) {
            return ret;
        }
        container->linux->gid_mappings_len++;
    }

    return ret;
}

int make_userns_remap(oci_runtime_spec *container, const char *user_remap)
{
    int ret = 0;
    unsigned int host_uid = 0;
    unsigned int host_gid = 0;
    unsigned int size = 0;

    if (user_remap == NULL) {
        return 0;
    }

    ret = util_parse_user_remap(user_remap, &host_uid, &host_gid, &size);
    if (ret) {
        ERROR("User remap '%s' format error", user_remap);
        return ret;
    }
    if (host_uid == 0 && host_gid == 0) {
        return 0;
    }

    if (make_sure_oci_spec_linux(container) != 0) {
        ERROR("Failed to make oci spce linux");
        return -1;
    }

    ret = make_linux_uid_gid_mappings(container, host_uid, host_gid, size);
    if (ret) {
        ERROR("Make linux uid and gid mappings failed");
        return ret;
    }
    return ret;
}

static int generate_env_map_from_file(FILE *fp, json_map_string_string *env_map)
{
    int ret = 0;
    char *key = NULL;
    char *value = NULL;
    char *pline = NULL;
    size_t length = 0;
    char *saveptr = NULL;
    char empty_str[1] = {'\0'};

    while (getline(&pline, &length, fp) != -1) {
        util_trim_newline(pline);
        pline = util_trim_space(pline);
        if (pline == NULL || pline[0] == '#') {
            continue;
        }
        key = strtok_r(pline, "=", &saveptr);
        value = strtok_r(NULL, "=", &saveptr);
        // value of an env varible is allowed to be empty
        value = value ? value : empty_str;
        if (key != NULL) {
            key = util_trim_space(key);
            value = util_trim_space(value);
            if ((size_t)(MAX_BUFFER_SIZE - 1) - strlen(key) < strlen(value)) {
                ERROR("env length exceed %d bytes", MAX_BUFFER_SIZE);
                ret = -1;
                goto out;
            }
            ret = append_json_map_string_string(env_map, key, value);
            if (ret < 0) {
                ERROR("append env to map failed");
                goto out;
            }
        }
    }
out:
    free(pline);
    return ret;
}

static json_map_string_string *parse_env_target_file(const char *env_path)
{
    int ret = 0;
    FILE *fp = NULL;
    json_map_string_string *env_map = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));

    if (env_map == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    fp = util_fopen(env_path, "r");
    if (fp == NULL) {
        SYSERROR("Failed to open env target file '%s'", env_path);
        goto out;
    }
    ret = generate_env_map_from_file(fp, env_map);
    if (ret != 0) {
        ERROR("Failed to generate env map from file");
        goto out;
    }
    fclose(fp);
    return env_map;
out:
    if (fp != NULL) {
        fclose(fp);
    }
    free_json_map_string_string(env_map);
    return NULL;
}

static int do_append_env(char ***env, size_t *env_len, const char *key, const char *value)
{
    char *tmp_env = NULL;
    size_t tmp_env_len = 0;

    if (strlen(value) > ((SIZE_MAX - 2) - strlen(key))) {
        ERROR("env value length too big");
        return -1;
    }

    tmp_env_len = strlen(key) + strlen(value) + 2;

    tmp_env = util_common_calloc_s(tmp_env_len);
    if (tmp_env == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    int nret = snprintf(tmp_env, tmp_env_len, "%s=%s", key, value);
    if (nret < 0 || (size_t)nret >= tmp_env_len) {
        ERROR("Out of memory");
        free(tmp_env);
        return -1;
    }
    if (util_array_append(env, tmp_env) < 0) {
        ERROR("Failed to append env");
        free(tmp_env);
        return -1;
    }
    free(tmp_env);
    (*env_len)++;
    return 0;
}

static int check_env_need_append(const oci_runtime_spec *oci_spec, const char *env_key, bool *is_append)
{
    size_t i = 0;
    char *key = NULL;
    char *saveptr = NULL;

    for (i = 0; i < oci_spec->process->env_len; i++) {
        char *tmp_env = NULL;
        tmp_env = util_strdup_s(oci_spec->process->env[i]);
        key = strtok_r(tmp_env, "=", &saveptr);
        // value of an env varible is allowed to be empty
        if (key == NULL) {
            ERROR("Bad env format");
            free(tmp_env);
            tmp_env = NULL;
            return -1;
        }
        if (strcmp(key, env_key) == 0) {
            *is_append = false;
            free(tmp_env);
            tmp_env = NULL;
            return 0;
        }
        free(tmp_env);
        tmp_env = NULL;
    }
    return 0;
}

static int do_merge_env_target(oci_runtime_spec *oci_spec, const json_map_string_string *env_map)
{
    int ret = 0;
    size_t i = 0;
    char **env = NULL;
    size_t env_len = 0;

    env = (char **)util_common_calloc_s(sizeof(char *));
    if (env == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < env_map->len; i++) {
        bool is_append = true;
        ret = check_env_need_append(oci_spec, env_map->keys[i], &is_append);
        if (ret < 0) {
            goto out;
        }
        if (!is_append) {
            continue;
        }
        if (do_append_env(&env, &env_len, (const char *)env_map->keys[i], (const char *)env_map->values[i]) < 0) {
            ERROR("Failed to append env");
            ret = -1;
            goto out;
        }
    }
    ret = merge_env(oci_spec, (const char **)env, env_len);
out:
    util_free_array(env);
    return ret;
}

static char *get_env_abs_file_path(const oci_runtime_spec *oci_spec, const char *env_target_file)
{
    char *env_path = NULL;
    int64_t file_size = 0;

    if (oci_spec->root == NULL || oci_spec->root->path == NULL) {
        return NULL;
    }
    if (util_realpath_in_scope(oci_spec->root->path, env_target_file, &env_path) < 0) {
        ERROR("env target file '%s' real path must be under rootfs '%s'", env_target_file, oci_spec->root->path);
        goto out;
    }
    if (!util_file_exists(env_path)) {
        return env_path;
    }
    file_size = util_file_size(env_path);
    if (file_size > REGULAR_FILE_SIZE) {
        ERROR("env target file %s, size exceed limit: %lld", env_target_file, REGULAR_FILE_SIZE);
        goto out;
    }
    return env_path;
out:
    free(env_path);
    return NULL;
}

int merge_env_target_file(oci_runtime_spec *oci_spec, const char *env_target_file)
{
    int ret = 0;
    char *env_path = NULL;
    json_map_string_string *env_map = NULL;

    if (oci_spec == NULL) {
        return -1;
    }

    if (env_target_file == NULL) {
        return 0;
    }
    env_path = get_env_abs_file_path(oci_spec, env_target_file);
    if (env_path == NULL) {
        ret = -1;
        goto out;
    }
    if (!util_file_exists(env_path)) {
        goto out;
    }
    env_map = parse_env_target_file(env_path);
    if (env_map == NULL) {
        ERROR("Failed to parse env target file");
        ret = -1;
        goto out;
    }
    ret = do_merge_env_target(oci_spec, (const json_map_string_string *)env_map);
    if (ret != 0) {
        ERROR("Failed to merge env target file");
        goto out;
    }
out:
    free(env_path);
    free_json_map_string_string(env_map);
    return ret;
}

int merge_env(oci_runtime_spec *oci_spec, const char **env, size_t env_len)
{
    int ret = 0;
    int nret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i;
    char **temp = NULL;
    // 10 is lenght of "HOSTNAME=" and '\0'
    char host_name_env[MAX_HOST_NAME_LEN + 10] = { 0 };

    nret = snprintf(host_name_env, sizeof(host_name_env), "HOSTNAME=%s", oci_spec->hostname);
    if (nret < 0 || (size_t)nret >= sizeof(host_name_env)) {
        ret = -1;
        ERROR("Sprint failed");
        goto out;
    }

    ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (env_len > LIST_ENV_SIZE_MAX - oci_spec->process->env_len - 1) {
        ERROR("The length of envionment variables is too long, the limit is %lld", LIST_ENV_SIZE_MAX);
        isulad_set_error_message("The length of envionment variables is too long, the limit is %d", LIST_ENV_SIZE_MAX);
        ret = -1;
        goto out;
    }
    // add 1 for hostname env
    new_size = (oci_spec->process->env_len + env_len + 1) * sizeof(char *);
    old_size = oci_spec->process->env_len * sizeof(char *);
    ret = util_mem_realloc((void **)&temp, new_size, oci_spec->process->env, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for envionment variables");
        ret = -1;
        goto out;
    }

    oci_spec->process->env = temp;

    // append hostname env into default oci spec env list
    oci_spec->process->env[oci_spec->process->env_len] = util_strdup_s(host_name_env);
    oci_spec->process->env_len++;

    for (i = 0; i < env_len && env != NULL; i++) {
        oci_spec->process->env[oci_spec->process->env_len] = util_strdup_s(env[i]);
        oci_spec->process->env_len++;
    }
out:
    return ret;
}

char *oci_container_get_env(const oci_runtime_spec *oci_spec, const char *key)
{
    const defs_process *op = NULL;

    if (oci_spec == NULL) {
        ERROR("nil oci_spec");
        return NULL;
    }
    if (oci_spec->process == NULL) {
        ERROR("nil oci_spec->process");
        return NULL;
    }

    op = oci_spec->process;
    return util_env_get_val(op->env, op->env_len, key, strlen(key));
}

int make_sure_oci_spec_linux(oci_runtime_spec *oci_spec)
{
    if (oci_spec == NULL) {
        return -1;
    }

    if (oci_spec->linux == NULL) {
        oci_spec->linux = util_common_calloc_s(sizeof(oci_runtime_config_linux));
        if (oci_spec->linux == NULL) {
            return -1;
        }
    }
    return 0;
}

int make_sure_oci_spec_process(oci_runtime_spec *oci_spec)
{
    if (oci_spec == NULL) {
        return -1;
    }

    if (oci_spec->process == NULL) {
        oci_spec->process = util_common_calloc_s(sizeof(defs_process));
        if (oci_spec->process == NULL) {
            return -1;
        }
    }
    return 0;
}

int make_sure_oci_spec_linux_resources(oci_runtime_spec *oci_spec)
{
    int ret = 0;

    if (oci_spec == NULL) {
        return -1;
    }

    ret = make_sure_oci_spec_linux(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->linux->resources == NULL) {
        oci_spec->linux->resources = util_common_calloc_s(sizeof(defs_resources));
        if (oci_spec->linux->resources == NULL) {
            return -1;
        }
    }
    return 0;
}

int make_sure_oci_spec_linux_resources_blkio(oci_runtime_spec *oci_spec)
{
    int ret;

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->linux->resources->block_io == NULL) {
        oci_spec->linux->resources->block_io = util_common_calloc_s(sizeof(defs_resources_block_io));
        if (oci_spec->linux->resources->block_io == NULL) {
            return -1;
        }
    }
    return 0;
}

int merge_ulimits_pre(oci_runtime_spec *oci_spec, size_t host_ulimits_len)
{
    int ret;
    size_t new_size, old_size, tmp;
    defs_process_rlimits_element **rlimits_temp = NULL;

    ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        goto out;
    }

    tmp = SIZE_MAX / sizeof(defs_process_rlimits_element *) - oci_spec->process->rlimits_len;
    if (host_ulimits_len > tmp) {
        ERROR("Too many rlimits to merge!");
        ret = -1;
        goto out;
    }
    old_size = oci_spec->process->rlimits_len * sizeof(defs_process_rlimits_element *);
    new_size = (oci_spec->process->rlimits_len + host_ulimits_len) * sizeof(defs_process_rlimits_element *);
    ret = util_mem_realloc((void **)&rlimits_temp, new_size, oci_spec->process->rlimits, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for rlimits");
        ret = -1;
        goto out;
    }
    oci_spec->process->rlimits = rlimits_temp;
out:
    return ret;
}

int trans_ulimit_to_rlimit(defs_process_rlimits_element **rlimit_dst, const host_config_ulimits_element *ulimit)
{
#define RLIMIT_PRE "RLIMIT_"
    int ret = 0;
    size_t j, namelen;
    char *typename = NULL;
    defs_process_rlimits_element *rlimit = NULL;

    // name + "RLIMIT_" + '\0'
    if (strlen(ulimit->name) > ((SIZE_MAX - strlen(RLIMIT_PRE)) - 1)) {
        ERROR("Invalid ulimit name");
        return -1;
    }
    namelen = strlen(ulimit->name) + strlen(RLIMIT_PRE) + 1;
    typename = util_common_calloc_s(namelen);
    if (typename == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    (void)strcat(typename, RLIMIT_PRE);

    for (j = 0; j < strlen(ulimit->name); j++) {
        typename[j + strlen(RLIMIT_PRE)] = (char)toupper((int)(ulimit->name[j]));
    }

    rlimit = util_common_calloc_s(sizeof(defs_process_rlimits_element));
    if (rlimit == NULL) {
        ERROR("Failed to malloc memory for rlimit");
        ret = -1;
        goto out;
    }
    rlimit->type = typename;
    rlimit->soft = (uint64_t)ulimit->soft;
    rlimit->hard = (uint64_t)ulimit->hard;

    *rlimit_dst = rlimit;
out:
    if (ret < 0) {
        free(typename);
    }
    return ret;
}

static bool rlimit_already_exists(const oci_runtime_spec *oci_spec, defs_process_rlimits_element *rlimit)
{
    size_t j;
    bool exists = false;

    for (j = 0; j < oci_spec->process->rlimits_len; j++) {
        if (oci_spec->process->rlimits[j]->type == NULL) {
            continue;
        }
        if (strcmp(oci_spec->process->rlimits[j]->type, rlimit->type) == 0) {
            exists = true;
            break;
        }
    }

    return exists;
}

static int append_one_ulimit(const oci_runtime_spec *oci_spec, const host_config_ulimits_element *ulimit)
{
    int ret = 0;
    defs_process_rlimits_element *rlimit = NULL;

    if (trans_ulimit_to_rlimit(&rlimit, ulimit) != 0) {
        ret = -1;
        goto out;
    }

    if (rlimit_already_exists(oci_spec, rlimit)) {
        ret = 0;
        goto out;
    }

    oci_spec->process->rlimits[oci_spec->process->rlimits_len] = rlimit;
    oci_spec->process->rlimits_len++;
    rlimit = NULL;

out:
    free_defs_process_rlimits_element(rlimit);
    return ret;
}

static int append_global_ulimits(oci_runtime_spec *oci_spec, host_config_ulimits_element **ulimits, size_t ulimits_len)
{
    int ret = 0;
    size_t i = 0;

    if (oci_spec == NULL || ulimits == NULL || ulimits_len == 0) {
        return -1;
    }

    ret = merge_ulimits_pre(oci_spec, ulimits_len);
    if (ret < 0) {
        goto out;
    }

    for (i = 0; i < ulimits_len; i++) {
        ret = append_one_ulimit(oci_spec, ulimits[i]);
        if (ret != 0) {
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

int merge_global_ulimit(oci_runtime_spec *oci_spec)
{
    int ret = 0;
    host_config_ulimits_element **ulimits = NULL;
    size_t ulimits_len;

    if (conf_get_isulad_default_ulimit(&ulimits) != 0) {
        ERROR("Failed to get isulad default ulimit");
        ret = -1;
        goto out;
    }

    if (ulimits != NULL) {
        ulimits_len = ulimit_array_len(ulimits);
        if (append_global_ulimits(oci_spec, ulimits, ulimits_len)) {
            ret = -1;
            goto out;
        }
    }

out:
    free_default_ulimit(ulimits);
    return ret;
}
