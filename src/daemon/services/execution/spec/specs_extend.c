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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <sched.h>
#include <ctype.h>

#include "error.h"
#include "isula_libutils/log.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/host_config.h"
#include "utils.h"
#include "config.h"
#include "path.h"
#include "isulad_config.h"
#include "specs_extend.h"

#define MINUID 0
#define MAXUID (((1LL << 31) - 1))
#define DEFAULT_UID 0

#define UnixPasswdPath "/etc/passwd"
#define UnixGroupPath "/etc/group"

#define MERGE_HOOKS_ITEM_DEF(item) \
    int merge_##item##_conf(oci_runtime_spec_hooks *dest, oci_runtime_spec_hooks * src) \
    {\
        size_t old_size = 0; \
        size_t new_size = 0; \
        int ret = 0; \
        size_t i = 0; \
        if (src->item##_len) { \
            defs_hook **item = NULL; \
            if (dest->item##_len > (LIST_SIZE_MAX - src->item##_len) - 1) { \
                ERROR("the length of item element is too long!"); \
                ret = -1; \
                goto out; \
            } \
            old_size = dest->item##_len * sizeof(defs_hook *); \
            new_size = (dest->item##_len + src->item##_len + 1) * sizeof(defs_hook *); \
            ret = mem_realloc((void **)&(item), new_size, dest->item, old_size); \
            if (ret != 0) { \
                ERROR("Failed to realloc memory for hooks_"#item" variables"); \
                ret = -1; \
                goto out; \
            }\
            dest->item = item; \
            for (; i < src->item##_len; i++) { \
                dest->item[dest->item##_len] = src->item[i]; \
                dest->item##_len++; \
                src->item[i] = NULL; \
            } \
            src->item##_len = 0; \
            free(src->item); \
            src->item = NULL; \
        } \
    out: \
        return ret; \
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

static int make_linux_uid_gid_mappings(oci_runtime_spec *container,
                                       unsigned int host_uid,
                                       unsigned int host_gid,
                                       unsigned int size)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux(container);
    if (ret < 0) {
        goto out;
    }

    if (container->linux->uid_mappings == NULL) {
        ret = make_one_id_mapping(&(container->linux->uid_mappings), host_uid, size);
        if (ret < 0) {
            goto out;
        }
        container->linux->uid_mappings_len++;
    }
    if (container->linux->gid_mappings == NULL) {
        ret = make_one_id_mapping(&(container->linux->gid_mappings), host_gid, size);
        if (ret < 0) {
            goto out;
        }
        container->linux->gid_mappings_len++;
    }

out:
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

    while (getline(&pline, &length, fp) != -1) {
        util_trim_newline(pline);
        pline = util_trim_space(pline);
        if (pline == NULL || pline[0] == '#') {
            continue;
        }
        key = strtok_r(pline, "=", &saveptr);
        value = strtok_r(NULL, "=", &saveptr);
        if (key != NULL && value != NULL) {
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
    char *value = NULL;
    char *saveptr = NULL;

    for (i = 0; i < oci_spec->process->env_len; i++) {
        char *tmp_env = NULL;
        tmp_env = util_strdup_s(oci_spec->process->env[i]);
        key = strtok_r(tmp_env, "=", &saveptr);
        value = strtok_r(NULL, "=", &saveptr);
        if (key == NULL || value == NULL) {
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
        if (do_append_env(&env, &env_len,
                          (const char *)env_map->keys[i],
                          (const char *)env_map->values[i]) < 0) {
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
    if (realpath_in_scope(oci_spec->root->path, env_target_file, &env_path) < 0) {
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
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    char **temp = NULL;

    if (env_len == 0 || env == NULL) {
        return 0;
    }

    ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (env_len > LIST_ENV_SIZE_MAX - oci_spec->process->env_len) {
        ERROR("The length of envionment variables is too long, the limit is %lld", LIST_ENV_SIZE_MAX);
        isulad_set_error_message("The length of envionment variables is too long, the limit is %d", LIST_ENV_SIZE_MAX);
        ret = -1;
        goto out;
    }
    new_size = (oci_spec->process->env_len + env_len) * sizeof(char *);
    old_size = oci_spec->process->env_len * sizeof(char *);
    ret = mem_realloc((void **)&temp, new_size, oci_spec->process->env, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for envionment variables");
        ret = -1;
        goto out;
    }

    oci_spec->process->env = temp;
    for (i = 0; i < env_len; i++) {
        oci_spec->process->env[oci_spec->process->env_len] = util_strdup_s(env[i]);
        oci_spec->process->env_len++;
    }
out:
    return ret;
}

static int read_user_file(const char *basefs, const char *user_path, FILE **stream)
{
    int ret = 0;
    int64_t filesize = 0;
    char *real_path = NULL;

    if (realpath_in_scope(basefs, user_path, &real_path) < 0) {
        ERROR("user target file '%s' real path must be under '%s'", user_path, basefs);
        isulad_set_error_message("user target file '%s' real path must be under '%s'", user_path, basefs);
        ret = -1;
        goto out;
    }

    filesize = util_file_size(real_path);
    if (filesize > REGULAR_FILE_SIZE) {
        ERROR("File %s is more than %lld", real_path, (long long)REGULAR_FILE_SIZE);
        isulad_set_error_message("File %s is more than %lld", real_path, (long long)REGULAR_FILE_SIZE);
        ret = -1;
        goto out;
    }

    *stream = util_fopen(real_path, "r");
    if (*stream == NULL) {
        ERROR("Failed to open %s: %s", real_path, strerror(errno));
        ret = 0;
        goto out;
    }

out:
    free(real_path);
    return ret;
}

static void parse_user_group(const char *username, char **user, char **group, char **tmp_dup)
{
    char *tmp = NULL;
    char *pdot = NULL;

    if (user == NULL || group == NULL || tmp_dup == NULL) {
        return;
    }

    if (username != NULL) {
        tmp = util_strdup_s(username);

        // for free tmp in caller
        *tmp_dup = tmp;

        pdot = strstr(tmp, ":");
        if (pdot != NULL) {
            *pdot = '\0';
            if (pdot != tmp) {
                // User found
                *user = tmp;
            }
            if (*(pdot + 1) != '\0') {
                // group found
                *group = pdot + 1;
            }
        } else {
            // No : found
            if (*tmp != '\0') {
                *user = tmp;
            }
        }
    }

    return;
}

static void uids_gids_range_err_log()
{
    ERROR("uids and gids must be in range 0-%lld", MAXUID);
    isulad_set_error_message("uids and gids must be in range 0-%d", MAXUID);
    return;
}

static bool b_user_found(const char *user, const struct passwd *pwbufp)
{
    int uret = -1;
    long long n_user = 0;
    bool userfound = false;

    if (pwbufp == NULL) {
        return false;
    }

    if (user != NULL) {
        uret = util_safe_llong(user, &n_user);
    }

    if (user == NULL && pwbufp->pw_uid == DEFAULT_UID) {
        userfound = true;
    }
    // Treat numeric usename as valid UID
    if (uret == 0 && (long long)pwbufp->pw_uid == n_user) {
        userfound = true;
    }
    if (uret != 0 && user != NULL && strcmp(user, pwbufp->pw_name) == 0) {
        userfound = true;
    }

    return userfound;
}


static int proc_by_fpasswd(FILE *f_passwd, const char *user, defs_process_user *puser,
                           char **matched_username)
{
    int ret = 0;
    int errval = 0;
    int uret = -1;
    bool userfound = false;
    long long n_user = 0;
    char buf[BUFSIZ];
    struct passwd pw, *pwbufp = NULL;

    if (f_passwd != NULL) {
        errval = fgetpwent_r(f_passwd, &pw, buf, sizeof(buf), &pwbufp);

        while (errval == 0 && pwbufp != NULL) {
            userfound = b_user_found(user, pwbufp);
            // Take the first match as valid user
            if (userfound) {
                // oci spec donot use username spec on linux
                free(puser->username);
                puser->username = NULL;
                puser->uid = pwbufp->pw_uid;
                puser->gid = pwbufp->pw_gid;
                *matched_username = util_strdup_s(pwbufp->pw_name);
                break;
            }
            errval = fgetpwent_r(f_passwd, &pw, buf, sizeof(buf), &pwbufp);
        }
    }

    if (errval != 0 && errval != ENOENT) {
        ERROR("Failed to parse passwd file: Insufficient buffer space supplied");
        isulad_set_error_message("Failed to parse passwd file: Insufficient buffer space supplied");
        ret = -1;
        goto out;
    }
    if (!userfound && user != NULL) {
        uret = util_safe_llong(user, &n_user);
        // user is not a valid numeric UID
        if (uret != 0) {
            ERROR("Unable to find user '%s'", user);
            isulad_set_error_message("Unable to find user '%s': no matching entries in passwd file", user);
            ret = -1;
            goto out;
        }
        if (n_user < MINUID || n_user > MAXUID) {
            uids_gids_range_err_log();
            ret = -1;
            goto out;
        }
        puser->uid = (uid_t)n_user;
    }

out:
    return ret;
}

static int append_additional_gids(gid_t gid, gid_t **additional_gids, size_t *len)
{
    int ret = 0;
    size_t new_len = 0;
    size_t i;
    gid_t *new_gids = NULL;

    if (*len > (SIZE_MAX / sizeof(gid_t)) - 1) {
        ERROR("Out of memory");
        return -1;
    }

    new_len = *len + 1;

    for (i = 0; i < *len; i++) {
        if ((*additional_gids)[i] == gid) {
            return 0;
        }
    }

    ret = mem_realloc((void **)&new_gids, new_len * sizeof(gid_t), *additional_gids, (*len) * sizeof(gid_t));
    if (ret != 0) {
        ERROR("Out of memory");
        return -1;
    }
    *additional_gids = new_gids;
    (*additional_gids)[*len] = gid;
    *len = new_len;
    return 0;
}

static int search_group_list(struct group *gbufp, const char *username, defs_process_user *puser)
{
    char **username_list = gbufp->gr_mem;
    while (username_list != NULL && *username_list != NULL) {
        if (strcmp(*username_list, username) == 0) {
            if (append_additional_gids(gbufp->gr_gid, &puser->additional_gids, &puser->additional_gids_len)) {
                ERROR("Failed to append additional groups");
                return -1;
            }
            break;
        }
        username_list++;
    }
    return 0;
}

static bool check_group_found(const char *group, const struct group *gbufp)
{
    int gret = -1;
    long long n_grp = 0;

    if (group != NULL) {
        gret = util_safe_llong(group, &n_grp);
    }

    if (gret == 0 && n_grp == (long long)gbufp->gr_gid) {
        return true;
    }
    if (gret != 0 && group != NULL && strcmp(group, gbufp->gr_name) == 0) {
        return true;
    }

    return false;
}

static int do_proc_by_froup(FILE *f_group, const char *group, defs_process_user *puser,
                            const char *matched_username, int *groupcnt)
{
    int errval = 0;
    char buf[BUFSIZ] = { 0 };
    bool groupfound = false;
    struct group grp, *gbufp = NULL;

    if (f_group == NULL) {
        return 0;
    }

    errval = fgetgrent_r(f_group, &grp, buf, sizeof(buf), &gbufp);
    while (errval == 0 && gbufp != NULL) {
        // Treat numeric group as valid GID
        if (group == NULL) {
            if (search_group_list(gbufp, matched_username, puser) != 0) {
                return -1;
            }
            errval = fgetgrent_r(f_group, &grp, buf, sizeof(buf), &gbufp);
            continue;
        }

        groupfound = check_group_found(group, gbufp);
        if (groupfound && *groupcnt != 1) {
            // Continue search group list, but only take first found group
            puser->gid = gbufp->gr_gid;
            *groupcnt = 1;
        }
        errval = fgetgrent_r(f_group, &grp, buf, sizeof(buf), &gbufp);
    }

    return 0;
}

static int proc_by_fgroup(FILE *f_group, const char *group, defs_process_user *puser,
                          const char *matched_username)
{
    int ret = 0;
    int gret = -1;
    int groupcnt = 0;
    long long n_grp = 0;

    if (group != NULL || matched_username != NULL) {
        if (do_proc_by_froup(f_group, group, puser, matched_username, &groupcnt) != 0) {
            goto out;
        }

        if (group != NULL && groupcnt == 0) {
            gret = util_safe_llong(group, &n_grp);
            // group is not a valid numeric GID
            if (gret != 0) {
                ERROR("Unable to find group '%s'", group);
                isulad_set_error_message("Unable to find group '%s': no matching entries in group file", group);
                ret = -1;
                goto out;
            }
            if (n_grp < MINUID || n_grp > MAXUID) {
                uids_gids_range_err_log();
                ret = -1;
                goto out;
            }
            puser->gid = (gid_t)n_grp;
        }
    }

out:
    return ret;
}

static int get_exec_user(const char *username, FILE *f_passwd, FILE *f_group, defs_process_user *puser)
{
    int ret = 0;
    char *tmp = NULL;
    char *user = NULL;
    char *group = NULL;
    char *matched_username = NULL;

    // parse user and group by username
    parse_user_group(username, &user, &group, &tmp);

    // proc by f_passwd
    ret = proc_by_fpasswd(f_passwd, user, puser, &matched_username);
    if (ret != 0) {
        ret = -1;
        goto cleanup;
    }

    // proc by f_group
    ret = proc_by_fgroup(f_group, group, puser, matched_username);
    if (ret != 0) {
        ret = -1;
        goto cleanup;
    }

cleanup:
    free(matched_username);
    free(tmp);
    return ret;
}

static int append_additional_groups(const struct group *grp, struct group **groups, size_t *len)
{
    int ret = 0;
    struct group *new_groups = NULL;
    size_t new_len = *len + 1;

    ret = mem_realloc((void **)&new_groups, new_len * sizeof(struct group), *groups, (*len) * sizeof(struct group));
    if (ret != 0) {
        ERROR("Out of memory");
        return -1;
    }
    *groups = new_groups;
    (*groups)[*len].gr_name = util_strdup_s(grp->gr_name);
    (*groups)[*len].gr_gid = grp->gr_gid;
    *len = new_len;
    return 0;
}

static bool group_matched(const char *group, const struct group *gbufp)
{
    bool matched = false;
    long long n_gid = 0;
    int gret = -1;

    if (group == NULL || gbufp == NULL) {
        return false;
    }

    gret = util_safe_llong(group, &n_gid);
    if (strcmp(group, gbufp->gr_name) == 0 || (gret == 0 && n_gid == gbufp->gr_gid)) {
        matched = true;
    }

    return matched;
}

static int get_one_additional_group(const char *additional_group, struct group *groups, size_t groups_len,
                                    defs_process_user *puser)
{
    int ret = 0;
    int gret = -1;
    long long n_gid = 0;
    bool found = false;
    size_t j;

    for (j = 0; groups != NULL && j < groups_len; j++) {
        // Only take the first founded group
        if (group_matched(additional_group, &groups[j])) {
            found = true;
            if (append_additional_gids(groups[j].gr_gid, &puser->additional_gids, &puser->additional_gids_len)) {
                ERROR("Failed to append additional groups");
                ret = -1;
                goto out;
            }
            break;
        }
    }

    if (!found) {
        gret = util_safe_llong(additional_group, &n_gid);
        if (gret != 0) {
            ERROR("Unable to find group %s", additional_group);
            isulad_set_error_message("Unable to find group %s", additional_group);
            ret = -1;
            goto out;
        }
        if (n_gid < MINUID || n_gid > MAXUID) {
            uids_gids_range_err_log();
            ret = -1;
            goto out;
        }
        if (append_additional_gids((gid_t)n_gid, &puser->additional_gids, &puser->additional_gids_len)) {
            ERROR("Failed to append additional groups");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}


int get_additional_groups(char **additional_groups, size_t additional_groups_len,
                          FILE *f_group, defs_process_user *puser)
{
    int ret = 0;
    size_t i;
    size_t groups_len = 0;
    char buf[BUFSIZ] = { 0 };
    struct group grp;
    struct group *gbufp = NULL;
    struct group *groups = NULL;

    while (f_group != NULL && fgetgrent_r(f_group, &grp, buf, sizeof(buf), &gbufp) == 0) {
        for (i = 0; i < additional_groups_len; i++) {
            if (!group_matched(additional_groups[i], gbufp)) {
                continue;
            }
            if (append_additional_groups(gbufp, &groups, &groups_len)) {
                ret = -1;
                goto cleanup;
            }
        }
    }

    for (i = 0; i < additional_groups_len; i++) {
        ret = get_one_additional_group(additional_groups[i], groups, groups_len, puser);
        if (ret != 0) {
            ret = -1;
            goto cleanup;
        }
    }


cleanup:
    for (i = 0; groups != NULL && i < groups_len; i++) {
        free(groups[i].gr_name);
    }
    free(groups);

    return ret;
}

static int resolve_basefs(const char *basefs, char **resolved_basefs)
{
    struct stat s;
    char real_path[PATH_MAX + 1] = { 0 };

    if (strlen(basefs) > PATH_MAX || !realpath(basefs, real_path)) {
        ERROR("invalid file path %s", basefs);
        return -1;
    }

    if (stat(real_path, &s) < 0) {
        ERROR("stat failed, error: %s", strerror(errno));
        return -1;
    }

    if ((s.st_mode & S_IFMT) == S_IFDIR) {
        *resolved_basefs = util_strdup_s(real_path);
    } else {
        *resolved_basefs = util_strdup_s("/");
    }

    return 0;
}

int get_user(const char *basefs, const host_config *hc, const char *userstr, defs_process_user *puser)
{
    int ret = 0;
    FILE *f_passwd = NULL;
    FILE *f_group = NULL;
    char *resolved_basefs = NULL;

    if (basefs == NULL || puser == NULL || hc == NULL) {
        return -1;
    }

    ret = resolve_basefs(basefs, &resolved_basefs);
    if (ret != 0) {
        goto cleanup;
    }

    ret = read_user_file(resolved_basefs, UnixPasswdPath, &f_passwd);
    if (ret != 0) {
        goto cleanup;
    }
    ret = read_user_file(resolved_basefs, UnixGroupPath, &f_group);
    if (ret != 0) {
        goto cleanup;
    }

    ret = get_exec_user(userstr, f_passwd, f_group, puser);
    if (ret != 0) {
        goto cleanup;
    }

    if (hc->group_add != NULL && hc->group_add_len > 0) {
        if (hc->group_add_len > LIST_SIZE_MAX) {
            ERROR("Too many groups to add, the limit is %lld", LIST_SIZE_MAX);
            isulad_set_error_message("Too many groups to add, the limit is %d", LIST_SIZE_MAX);
            ret = -1;
            goto cleanup;
        }
        // Rewind f_group to serach from beginning again.
        if (f_group != NULL) {
            rewind(f_group);
        }
        ret = get_additional_groups(hc->group_add, hc->group_add_len, f_group, puser);
        if (ret != 0) {
            goto cleanup;
        }
    }

cleanup:
    if (f_passwd != NULL) {
        fclose(f_passwd);
    }
    if (f_group != NULL) {
        fclose(f_group);
    }

    free(resolved_basefs);

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
    ret = mem_realloc((void **)&rlimits_temp, new_size, oci_spec->process->rlimits, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for rlimits");
        ret = -1;
        goto out;
    }
    oci_spec->process->rlimits = rlimits_temp;
out:
    return ret;
}

int trans_ulimit_to_rlimit(defs_process_rlimits_element **rlimit_dst,
                           const host_config_ulimits_element *ulimit)
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

static int do_merge_one_ulimit(const oci_runtime_spec *oci_spec, defs_process_rlimits_element *rlimit)
{
    size_t j;
    bool exists = false;

    for (j = 0; j < oci_spec->process->rlimits_len; j++) {
        if (oci_spec->process->rlimits[j]->type == NULL) {
            ERROR("rlimit type is empty");
            UTIL_FREE_AND_SET_NULL(rlimit->type);
            free(rlimit);
            return -1;
        }
        if (strcmp(oci_spec->process->rlimits[j]->type, rlimit->type) == 0) {
            exists = true;
            break;
        }
    }
    if (exists) {
        /* ulimit exist, discard default ulimit */
        UTIL_FREE_AND_SET_NULL(rlimit->type);
        free(rlimit);
    } else {
        oci_spec->process->rlimits[oci_spec->process->rlimits_len] = rlimit;
        oci_spec->process->rlimits_len++;
    }

    return 0;
}

static int merge_one_ulimit(const oci_runtime_spec *oci_spec, const host_config_ulimits_element *ulimit)
{
    defs_process_rlimits_element *rlimit = NULL;

    if (trans_ulimit_to_rlimit(&rlimit, ulimit) != 0) {
        return -1;
    }

    return do_merge_one_ulimit(oci_spec, rlimit);
}

static int merge_ulimits(oci_runtime_spec *oci_spec, host_config_ulimits_element **ulimits, size_t ulimits_len)
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
        ret = merge_one_ulimit(oci_spec, ulimits[i]);
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
        if (merge_ulimits(oci_spec, ulimits, ulimits_len)) {
            ret = -1;
            goto out;
        }
    }

out:
    free_default_ulimit(ulimits);
    return ret;
}


