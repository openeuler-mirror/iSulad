/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
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
#include <linux/capability.h>
#include <stdio.h>
#include <strings.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_regex.h"
#include "utils_array.h"
#include "utils_string.h"

const char *g_all_caps[] = {
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
#ifdef CAP_AUDIT_WRITE
    "CAP_AUDIT_WRITE",
#endif
#ifdef CAP_AUDIT_CONTROL
    "CAP_AUDIT_CONTROL",
#endif
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
#ifdef CAP_SYSLOG
    "CAP_SYSLOG",
#endif
#ifdef CAP_WAKE_ALARM
    "CAP_WAKE_ALARM",
#endif
#ifdef CAP_BLOCK_SUSPEND
    "CAP_BLOCK_SUSPEND",
#endif
#ifdef CAP_AUDIT_READ
    "CAP_AUDIT_READ",
#endif
};

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
    int nret = 0;
    regex_t preg;
    int status = 0;
    regmatch_t regmatch;

    if (path == NULL) {
        return -1;
    }

    (void)memset(&regmatch, 0, sizeof(regmatch_t));

    if (regcomp(&preg, "^(/[^/ ]*)+/?$", REG_NOSUB | REG_EXTENDED)) {
        ERROR("Failed to compile the regex");
        nret = -1;
        goto err_out;
    }

    status = regexec(&preg, path, 1, &regmatch, 0);
    regfree(&preg);
    if (status != 0) {
        nret = -1;
        goto err_out;
    }
err_out:
    return nret;
}

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

bool util_validate_unix_socket(const char *socket)
{
    int nret = 0;
    const char *name = NULL;

    if (socket == NULL) {
        return false;
    }

    if (strncmp("unix://", socket, strlen("unix://"))) {
        nret = -1;
        goto err_out;
    }

    name = socket + strlen("unix://");

    if (name[0] == '\0') {
        nret = -1;
        goto err_out;
    }

    nret = util_validate_absolute_path(name);
    if (nret != 0) {
        nret = -1;
        goto err_out;
    }
err_out:
    return nret == 0;
}

bool util_validate_socket(const char *socket)
{
    return util_validate_unix_socket(socket) || util_vaildate_tcp_socket(socket);
}

bool util_valid_device_mode(const char *mode)
{
    size_t i = 0;

    if (mode == NULL || !strcmp(mode, "")) {
        return false;
    }

    for (i = 0; i < strlen(mode); i++) {
        if (mode[i] != 'r' && mode[i] != 'w' && mode[i] != 'm') {
            return false;
        }
    }

    return true;
}

bool util_valid_str(const char *str)
{
    return (str != NULL && str[0] != '\0') ? true : false;
}

size_t util_get_all_caps_len()
{
    return sizeof(g_all_caps) / sizeof(char *);
}

bool util_valid_cap(const char *cap)
{
    bool cret = true;
    int nret = 0;
    char tmpcap[32] = { 0 };
    size_t all_caps_len = util_get_all_caps_len();

    if (cap == NULL) {
        return false;
    }

    nret = snprintf(tmpcap, sizeof(tmpcap), "CAP_%s", cap);
    if (nret < 0 || nret >= sizeof(tmpcap)) {
        ERROR("Failed to print string");
        cret = false;
        goto err_out;
    }
    if (!util_strings_in_slice(g_all_caps, all_caps_len, tmpcap)) {
        cret = false;
        goto err_out;
    }

err_out:
    return cret;
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
    char *tag_pos = NULL;
    bool bret = false;

    if (name == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    if (strnlen(name, MAX_IMAGE_NAME_LEN + 1) > MAX_IMAGE_NAME_LEN) {
        return false;
    }

    copy = util_strdup_s(name);
    tag_pos = util_tag_pos(copy);
    if (tag_pos != NULL) {
        if (util_reg_match(__TagPattern, tag_pos)) {
            goto cleanup;
        }

        *tag_pos = '\0';
    }

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
    char *patten = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(.[0-9]{2,9})?(Z|[+-][0-9]{2}:[0-9]{2})$";

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
        ERROR("stat failed, error: %s", strerror(errno));
        return false;
    }

    return (s.st_mode & S_IFMT) == fmod;
}

bool util_valid_key_type(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return !strcmp(key, "type");
}

bool util_valid_key_src(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return !strcmp(key, "src") || !strcmp(key, "source");
}

bool util_valid_key_dst(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return !strcmp(key, "dst") || !strcmp(key, "destination") || !strcmp(key, "target");
}

bool util_valid_key_ro(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return !strcmp(key, "ro") || !strcmp(key, "readonly");
}

bool util_valid_key_propagation(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return !strcmp(key, "bind-propagation");
}

bool util_valid_key_selinux(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return !strcmp(key, "bind-selinux-opts");
}

bool util_valid_key_nocopy(const char *key)
{
    if (key == NULL) {
        return false;
    }

    return !strcmp(key, "volume-nocopy");
}

bool util_valid_value_true(const char *value)
{
    if (value == NULL) {
        return false;
    }

    return !strcmp(value, "1") || !strcmp(value, "true");
}

bool util_valid_value_false(const char *value)
{
    if (value == NULL) {
        return false;
    }

    return !strcmp(value, "0") || !strcmp(value, "false");
}

bool util_valid_rw_mode(const char *mode)
{
    return !strcmp(mode, "rw") || !strcmp(mode, "ro");
}

bool util_valid_label_mode(const char *mode)
{
    return !strcmp(mode, "z") || !strcmp(mode, "Z");
}

bool util_valid_copy_mode(const char *mode)
{
    return !strcmp(mode, "nocopy");
}

bool util_valid_propagation_mode(const char *mode)
{
    if (mode == NULL) {
        return false;
    }
    return !strcmp(mode, "private") || !strcmp(mode, "rprivate") || !strcmp(mode, "slave") || !strcmp(mode, "rslave") ||
           !strcmp(mode, "shared") || !strcmp(mode, "rshared");
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

    if (value == NULL) {
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

int util_valid_env(const char *env, char **dst)
{
    int ret = 0;
    char *value = NULL;

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
    char *patten = "^[a-zA-Z0-9][a-zA-Z0-9_.-]+$";

    if (name == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    return util_reg_match(patten, name) == 0;
}
