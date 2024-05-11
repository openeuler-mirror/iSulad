/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide container utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_verify.h"

#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <strings.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_regex.h"
#include "utils_array.h"
#include "utils_string.h"

bool util_valid_cmd_arg(const char *arg)
{
    return (arg != NULL) && (strchr(arg, '|') == NULL) && (strchr(arg, '`') == NULL) && (strchr(arg, '&')) == NULL &&
           (strchr(arg, ';') == NULL);
}

bool util_valid_signal(int sig)
{
    size_t n = 0;
    const struct signame signames[] = SIGNAL_MAP_DEFAULT;

    for (n = 0; n < sizeof(signames) / sizeof(signames[0]); n++) {
        if (signames[n].num == sig) {
            return true;
        }
    }

    return false;
}

int util_validate_absolute_path(const char *path)
{
#define PATTEN_STR "^(/[^/ ]*)+/?$"
    int nret = 0;

    if (path == NULL) {
        return -1;
    }

    if (util_reg_match(PATTEN_STR, path) != 0) {
        nret = -1;
    }

    return nret;
}

#ifdef ENABLE_GRPC_REMOTE_CONNECT
static bool util_vaildate_tcp_socket(const char *socket)
{
    if (socket == NULL) {
        return false;
    }
    return util_reg_match("^(tcp://(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]).){3}"
                          "(25[0-5]|2[0-5][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])|localhost):"
                          "((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})"
                          "|([1-5][0-9]{4})|([1-9][0-9]{0,3})|0))$",
                          socket) == 0;
}
#endif

bool util_validate_unix_socket(const char *socket)
{
    int nret = 0;
    const char *name = NULL;

    if (socket == NULL) {
        return false;
    }

    if (strncmp("unix://", socket, strlen("unix://"))) {
        return false;
    }

    name = socket + strlen("unix://");

    if (name[0] == '\0') {
        return false;
    }

    nret = util_validate_absolute_path(name);
    if (nret != 0) {
        return false;
    }

    return true;
}

bool util_validate_socket(const char *socket)
{
#ifdef ENABLE_GRPC_REMOTE_CONNECT
    return util_validate_unix_socket(socket) || util_vaildate_tcp_socket(socket);
#else
    return util_validate_unix_socket(socket);
#endif
}

bool util_valid_device_mode(const char *mode)
{
    size_t i = 0;
    int r_count = 0;
    int w_count = 0;
    int m_count = 0;

    if (mode == NULL || strcmp(mode, "") == 0) {
        return false;
    }

    for (i = 0; i < strlen(mode); i++) {
        switch (mode[i]) {
            case 'r':
                if (r_count != 0) {
                    return false;
                }
                r_count++;
                break;
            case 'w':
                if (w_count != 0) {
                    return false;
                }
                w_count++;
                break;
            case 'm':
                if (m_count != 0) {
                    return false;
                }
                m_count++;
                break;
            default:
                return false;
        }
    }

    return true;
}

bool util_valid_str(const char *str)
{
    return (str != NULL && str[0] != '\0') ? true : false;
}

bool util_valid_container_id(const char *id)
{
    char *patten = "^[a-f0-9]{1,64}$";

    if (id == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    return util_reg_match(patten, id) == 0;
}

bool util_valid_container_name(const char *name)
{
    char *patten = "^/?[a-zA-Z0-9][a-zA-Z0-9_.-]+$";

    if (name == NULL) {
        ERROR("Invalid NULL param");
        return false;
    }

    if (strnlen(name, MAX_CONTAINER_NAME_LEN + 1) > MAX_CONTAINER_NAME_LEN) {
        ERROR("Container name '%s' too long, max length:%d", name, MAX_CONTAINER_NAME_LEN);
        return false;
    }

    return util_reg_match(patten, name) == 0;
}

bool util_valid_container_id_or_name(const char *id_or_name)
{
    if (util_valid_container_id(id_or_name)) {
        return true;
    }

    return util_valid_container_name(id_or_name);
}

bool util_valid_runtime_name(const char *name)
{
    if (name == NULL) {
        ERROR("Invalid NULL param");
        return false;
    }

    return true;
}

bool util_valid_host_name(const char *name)
{
    if (name == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    if (strnlen(name, MAX_HOST_NAME_LEN + 1) > MAX_HOST_NAME_LEN) {
        ERROR("Host name '%s' too long, max length:%d", name, MAX_HOST_NAME_LEN);
        return false;
    }

    return util_reg_match(HOST_NAME_REGEXP, name) == 0;
}

char *util_tag_pos(const char *ref)
{
    char *tag_pos = NULL;

    if (ref == NULL) {
        return NULL;
    }

    /* Tag can not contain "/", so if "/" is found after last ":",
     * it means this reference do not have a tag */
    tag_pos = strrchr(ref, ':');
    if (tag_pos != NULL) {
        if (strchr(tag_pos, '/') == NULL) {
            return tag_pos;
        }
    }

    return NULL;
}

bool util_valid_embedded_image_name(const char *name)
{
    char *copy_name = NULL;
    char *tag_pos = NULL;
    bool bret = false;

    if (name == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    if (strnlen(name, MAX_IMAGE_NAME_LEN + 1) > MAX_IMAGE_NAME_LEN) {
        return false;
    }

    copy_name = util_strdup_s(name);
    tag_pos = util_tag_pos(copy_name);
    if (tag_pos == NULL) {
        goto cleanup;
    }

    if (util_reg_match(__TagPattern, tag_pos)) {
        goto cleanup;
    }

    *tag_pos = '\0';

    if (util_reg_match(__NamePattern, copy_name)) {
        goto cleanup;
    }

    bret = true;
cleanup:
    free(copy_name);
    return bret;
}

bool util_valid_image_name(const char *name)
{
    char *copy = NULL;
    char *check_pos = NULL;
    bool bret = false;

    if (name == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    if (strnlen(name, MAX_IMAGE_NAME_LEN + 1) > MAX_IMAGE_NAME_LEN) {
        return false;
    }

    copy = util_strdup_s(name);

    // 1. first, check digest or not
    check_pos = strrchr(copy, '@');
    if (check_pos != NULL) {
        // image name with digest
        if (util_reg_match(__DIGESTPattern, check_pos)) {
            goto cleanup;
        }
        *check_pos = '\0';
    } else {
        // image name without digest
        // 2. check tag or not
        check_pos = util_tag_pos(copy);
        if (check_pos != NULL) {
            if (util_reg_match(__TagPattern, check_pos)) {
                goto cleanup;
            }

            *check_pos = '\0';
        }
    }

    // In name check phase, image name with both tag and digest is also allowed
    if (util_reg_match(__NamePattern, copy)) {
        goto cleanup;
    }

    bret = true;
cleanup:
    free(copy);
    return bret;
}

bool util_valid_time_tz(const char *time)
{
    char *patten = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$";

    if (time == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    return util_reg_match(patten, time) == 0;
}

bool util_valid_digest(const char *digest)
{
    char *patten = "^sha256:([a-f0-9]{64})$";

    if (digest == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    return util_reg_match(patten, digest) == 0;
}

bool util_valid_tag(const char *tag)
{
    char *patten = "^[a-f0-9]{64}$";

    if (tag == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    if (strlen(tag) >= strlen(SHA256_PREFIX) && !strncasecmp(tag, SHA256_PREFIX, strlen(SHA256_PREFIX))) {
        ERROR("tag must not prefixed with \"sha256:\"");
        return false;
    }

    // cannot specify 64-byte hexadecimal strings
    if (util_reg_match(patten, tag) == 0) {
        ERROR("cannot specify 64-byte hexadecimal strings");
        return false;
    }

    if (!util_valid_image_name(tag)) {
        ERROR("Not a valid image name");
        return false;
    }

    return true;
}

bool util_valid_file(const char *path, uint32_t fmod)
{
    struct stat s;
    int nret;

    if (path == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    nret = stat(path, &s);
    if (nret < 0) {
        SYSERROR("stat failed");
        return false;
    }

    return (s.st_mode & S_IFMT) == fmod;
}

bool util_valid_key_type(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return strcmp(key, "type") == 0;
}

bool util_valid_key_src(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return strcmp(key, "src") == 0 || strcmp(key, "source") == 0;
}

bool util_valid_key_dst(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return strcmp(key, "dst") == 0 || strcmp(key, "destination") == 0 || strcmp(key, "target") == 0;
}

bool util_valid_key_ro(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return strcmp(key, "ro") == 0 || strcmp(key, "readonly") == 0;
}

bool util_valid_key_propagation(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return strcmp(key, "bind-propagation") == 0;
}

bool util_valid_key_selinux(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return strcmp(key, "bind-selinux-opts") == 0 || strcmp(key, "selinux-opts") == 0;
}

bool util_valid_key_tmpfs_size(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return strcmp(key, "tmpfs-size") == 0;
}

bool util_valid_key_tmpfs_mode(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return strcmp(key, "tmpfs-mode") == 0;
}

bool util_valid_key_nocopy(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return strcmp(key, "volume-nocopy") == 0;
}

bool util_valid_value_true(const char *value)
{
    if (value == NULL) {
        return false;
    }

    return strcmp(value, "1") == 0 || strcmp(value, "true") == 0;
}

bool util_valid_value_false(const char *value)
{
    if (value == NULL) {
        return false;
    }

    return strcmp(value, "0") == 0 || strcmp(value, "false") == 0;
}

bool util_valid_bool_string(const char *val)
{
    if (val == NULL) {
        return false;
    }

    return strcmp(val, "true") == 0 || strcmp(val, "false") == 0;
}

bool util_valid_rw_mode(const char *mode)
{
    if (mode == NULL) {
        return false;
    }

    return strcmp(mode, "rw") == 0 || strcmp(mode, "ro") == 0;
}

bool util_valid_label_mode(const char *mode)
{
    if (mode == NULL) {
        return false;
    }

    return strcmp(mode, "z") == 0 || strcmp(mode, "Z") == 0;
}

bool util_valid_copy_mode(const char *mode)
{
    if (mode == NULL) {
        return false;
    }
    return strcmp(mode, "nocopy") == 0;
}

bool util_valid_propagation_mode(const char *mode)
{
    if (mode == NULL) {
        return false;
    }
    return strcmp(mode, "private") == 0 || strcmp(mode, "rprivate") == 0 || strcmp(mode, "slave") == 0 || strcmp(mode, "rslave") == 0 ||
           strcmp(mode, "shared") == 0 || strcmp(mode, "rshared") == 0;
}

bool util_valid_mount_mode(const char *mode)
{
    int rw_mode_cnt = 0;
    int pro_mode_cnt = 0;
    int label_mode_cnt = 0;
    int copy_mode_cnt = 0;
    size_t i, mlen;
    char **modes = NULL;
    bool nret = false;

    modes = util_string_split(mode, ',');
    if (modes == NULL) {
        ERROR("Out of memory");
        return false;
    }
    mlen = util_array_len((const char **)modes);

    for (i = 0; i < mlen; i++) {
        if (util_valid_rw_mode(modes[i])) {
            rw_mode_cnt++;
        } else if (util_valid_propagation_mode(modes[i])) {
            pro_mode_cnt++;
        } else if (util_valid_label_mode(modes[i])) {
            label_mode_cnt++;
        } else if (util_valid_copy_mode(modes[i])) {
            copy_mode_cnt++;
        } else {
            goto err_out;
        }
    }

    if (rw_mode_cnt > 1 || pro_mode_cnt > 1 || label_mode_cnt > 1 || copy_mode_cnt > 1) {
        goto err_out;
    }

    nret = true;
err_out:
    util_free_array(modes);
    return nret;
}

/* ShortIdentifierRegexp is the format used to represent a prefix
 * of an identifier. A prefix may be used to match a sha256 identifier
 * within a list of trusted identifiers.
 * minimumTruncatedIDLength = 3 maxTruncatedIDLength = 64
 */
bool util_valid_short_sha256_id(const char *id)
{
#define __ShortIdentifierRegexp "^[a-f0-9]{3,64}$"
    char *copy = NULL;
    bool bret = false;

    if (id == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    if (strnlen(id, MAX_SHA256_IDENTIFIER + 1) > MAX_SHA256_IDENTIFIER) {
        return false;
    }

    copy = util_strdup_s(id);

    if (util_reg_match(__ShortIdentifierRegexp, copy) != 0) {
        goto cleanup;
    }

    bret = true;
cleanup:
    free(copy);
    return bret;
}

bool util_valid_exec_suffix(const char *suffix)
{
    char *patten = "^[a-f0-9]{64}$";

    if (suffix == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    return util_reg_match(patten, suffix) == 0;
}

bool util_valid_positive_interger(const char *value)
{
    const char *patten = "^[0-9]*$";

    if (value == NULL || strcmp(value, "") == 0) {
        return false;
    }

    return util_reg_match(patten, value) == 0;
}

bool util_valid_device_cgroup_rule(const char *value)
{
    const char *patten = "^([acb]) ([0-9]+|\\*):([0-9]+|\\*) ([rwm]{1,3})$";

    if (value == NULL) {
        return false;
    }

    return util_reg_match(patten, value) == 0;
}

int util_valid_split_env(const char *env, char **key, char **value)
{
    __isula_auto_array_t char **arr = NULL;

    arr = util_string_split_n(env, '=', 2);
    if (arr == NULL) {
        ERROR("Failed to split env string");
        return -1;
    }

    if (strlen(arr[0]) == 0) {
        ERROR("Invalid environment variable: %s", env);
        return -1;
    }

    if (key != NULL) {
        *key = util_strdup_s(arr[0]);
    }
    if (value != NULL) {
        *value = util_strdup_s(util_array_len((const char **)arr) > 1 ? arr[1] : "");
    }

    return 0;
}

int util_valid_env(const char *env, char **dst)
{
    int ret = 0;
    char *value = NULL;

    if (dst == NULL) {
        ERROR("NULL dst");
        return -1;
    }

    char **arr = util_string_split_multi(env, '=');
    if (arr == NULL) {
        ERROR("Failed to split env string");
        return -1;
    }
    if (strlen(arr[0]) == 0) {
        ERROR("Invalid environment variable: %s", env);
        ret = -1;
        goto out;
    }

    if (util_array_len((const char **)arr) > 1) {
        *dst = util_strdup_s(env);
        goto out;
    }

    value = getenv(env);
    if (value == NULL) {
        *dst = NULL;
        goto out;
    } else {
        int sret;
        size_t len = strlen(env) + 1 + strlen(value) + 1;
        *dst = (char *)util_common_calloc_s(len);
        if (*dst == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        sret = snprintf(*dst, len, "%s=%s", env, value);
        if (sret < 0 || (size_t)sret >= len) {
            ERROR("Failed to compose env string");
            ret = -1;
            goto out;
        }
    }

out:
    util_free_array(arr);
    return ret;
}

bool util_valid_sysctl(const char *sysctl_key)
{
    size_t i = 0;
    size_t full_keys_len = 0;
    size_t key_prefixes_len = 0;
    const char *sysctl_full_keys[] = { "kernel.msgmax", "kernel.msgmnb", "kernel.msgmni", "kernel.sem",
                                       "kernel.shmall", "kernel.shmmax", "kernel.shmmni", "kernel.shm_rmid_forced"
                                     };
    const char *sysctl_key_prefixes[] = { "net.", "fs.mqueue." };

    if (sysctl_key == NULL) {
        return false;
    }

    full_keys_len = sizeof(sysctl_full_keys) / sizeof(char *);
    key_prefixes_len = sizeof(sysctl_key_prefixes) / sizeof(char *);

    for (i = 0; i < full_keys_len; i++) {
        if (strcmp(sysctl_full_keys[i], sysctl_key) == 0) {
            return true;
        }
    }
    for (i = 0; i < key_prefixes_len; i++) {
        if (strncmp(sysctl_key_prefixes[i], sysctl_key, strlen(sysctl_key_prefixes[i])) == 0) {
            return true;
        }
    }
    return false;
}

bool util_valid_volume_name(const char *name)
{
    char *patten = "^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,63}$";

    if (name == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    return util_reg_match(patten, name) == 0;
}

bool util_valid_isulad_tmpdir(const char *dir)
{
    return util_valid_str(dir) && strcmp(dir, "/tmp") != 0;
}

#ifdef ENABLE_IMAGE_SEARCH
bool util_valid_search_name(const char *name)
{
    bool ret = false;

    if (name == NULL || strcmp(name, "") == 0) {
        ERROR("invalid NULL param");
        return false;
    }

    ret = util_strings_contains_word(name, "://");
    if (ret == true) {
        ERROR("invalid repository name: repository name %s should not have a scheme", name);
        return false;
    }

    return true;
}
#endif
