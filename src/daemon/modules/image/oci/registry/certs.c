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
 * Author: wangfengtu
 * Create: 2020-03-20
 * Description: provide auths file process functions
 ******************************************************************************/

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "certs.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_file.h"
#include "utils_string.h"
#include "err_msg.h"

#define DEFAULT_ISULAD_CERTD "/etc/isulad/certs.d"
#define CLIENT_CERT_SUFFIX ".cert"
#define CLIENT_KEY_SUFFIX ".key"
#define CA_SUFFIX ".crt"

static char *g_certs_dir = DEFAULT_ISULAD_CERTD;

void certs_set_dir(char *certs_dir)
{
    if (certs_dir != NULL) {
        g_certs_dir = util_strdup_s(certs_dir);
    }
}

static char *corresponding_key_name(const char *cert_name)
{
    char *key_name = NULL;
    char *pos = NULL;

    if (cert_name == NULL) {
        ERROR("Invalid NULL pointer");
        return NULL;
    }

    if (strlen(cert_name) < strlen(CLIENT_CERT_SUFFIX)) {
        ERROR("Invalid cert name too short");
        return NULL;
    }

    key_name = util_strdup_s(cert_name);

    // Replace ".cert" to ".key"
    pos = key_name + strlen(key_name) - strlen(CLIENT_CERT_SUFFIX);
    pos[1] = 'k';
    pos[2] = 'e';
    pos[3] = 'y';
    pos[4] = 0;

    return key_name;
}

static char *corresponding_cert_name(const char *key_name)
{
    char cert_name[PATH_MAX] = { 0 };
    char *tmp_key_name = NULL;
    int sret = 0;

    if (key_name == NULL) {
        ERROR("Invalid NULL pointer");
        return NULL;
    }

    if (strlen(key_name) <= strlen(CLIENT_KEY_SUFFIX)) {
        ERROR("Invalid key name too short");
        return NULL;
    }

    tmp_key_name = util_strdup_s(key_name);
    tmp_key_name[strlen(tmp_key_name) - strlen(CLIENT_KEY_SUFFIX)] = 0; // strip suffix .key

    sret = snprintf(cert_name, sizeof(cert_name), "%s.cert", tmp_key_name);
    if (sret < 0 || (size_t)sret >= sizeof(cert_name)) {
        ERROR("Failed to sprintf cert name");
        free(tmp_key_name);
        return NULL;
    }

    return util_strdup_s(cert_name);
}

static int get_path_by_cert_name(const char *path, const char *cert_name, char **cert_path, char **key_path)
{
    int ret = 0;
    char *key_name = NULL;
    char *tmp_key_path = NULL;
    char *tmp_cert_path = NULL;

    key_name = corresponding_key_name(cert_name);
    if (key_name == NULL) {
        ERROR("find corresponding key name for cert failed");
        ret = -1;
        goto out;
    }
    tmp_key_path = util_path_join(path, key_name);
    tmp_cert_path = util_path_join(path, cert_name);
    if (tmp_cert_path == NULL || tmp_key_path == NULL) {
        ret = -1;
        ERROR("error join path");
        goto out;
    }

    *cert_path = util_strdup_s(tmp_cert_path);
    *key_path = util_strdup_s(tmp_key_path);

out:
    free(key_name);
    free(tmp_cert_path);
    free(tmp_key_path);

    return ret;
}

static int get_path_by_key_name(const char *path, const char *key_name, char **cert_path, char **key_path)
{
    int ret = 0;
    char *cert_name = NULL;
    char *tmp_key_path = NULL;
    char *tmp_cert_path = NULL;

    cert_name = corresponding_cert_name(key_name);
    if (cert_name == NULL) {
        ERROR("find corresponding key name for cert failed");
        ret = -1;
        goto out;
    }
    tmp_key_path = util_path_join(path, key_name);
    tmp_cert_path = util_path_join(path, cert_name);
    if (tmp_cert_path == NULL || tmp_key_path == NULL) {
        ret = -1;
        ERROR("error join path");
        goto out;
    }

    *cert_path = util_strdup_s(tmp_cert_path);
    *key_path = util_strdup_s(tmp_key_path);

out:
    free(cert_name);
    free(tmp_cert_path);
    free(tmp_key_path);

    return ret;
}

static int load_certs(const char *path, const char *name, bool use_decrypted_key, char **ca_file, char **cert_file,
                      char **key_file)
{
    int ret = 0;
    char *key_name = NULL;
    char *tmp_key_file = NULL;
    char *tmp_cert_file = NULL;

    if (path == NULL || ca_file == NULL || cert_file == NULL || key_file == NULL || name == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    if (util_has_suffix(name, CA_SUFFIX)) {
        if (*ca_file != NULL) {
            ERROR("more than one ca file found, support only one ca file currently, continue to try");
            goto out;
        }
        *ca_file = util_path_join(path, name);
        if (*ca_file == NULL) {
            ret = -1;
            ERROR("error join ca suffix");
            goto out;
        }
        goto out;
    } else if (util_has_suffix(name, CLIENT_CERT_SUFFIX)) {
        ret = get_path_by_cert_name(path, name, &tmp_cert_file, &tmp_key_file);
        if (ret != 0) {
            ERROR("get path of cert and key by cert name failed");
            isulad_try_set_error_message("get path of cert and key by cert name failed");
            goto out;
        }
        if (!util_file_exists(tmp_key_file)) {
            ret = -1;
            ERROR("lack corresponding key file for tls cert");
            isulad_try_set_error_message("lack corresponding key file for tls cert");
            goto out;
        }
        if (*cert_file != NULL) {
            ERROR("more than one cert file found, support only one cert file currently, continue to try");
            goto out;
        }
        *cert_file = util_strdup_s(tmp_cert_file);
        goto out;
    } else if (util_has_suffix(name, CLIENT_KEY_SUFFIX)) {
        ret = get_path_by_key_name(path, name, &tmp_cert_file, &tmp_key_file);
        if (ret != 0) {
            ERROR("get path of cert and key by key name failed");
            isulad_try_set_error_message("get path of cert and key by key name failed");
            goto out;
        }
        if (!util_file_exists(tmp_cert_file)) {
            ret = -1;
            ERROR("lack corresponding cert file for tls key");
            isulad_try_set_error_message("lack corresponding cert file for tls key");
            goto out;
        }
        if (*key_file != NULL) {
            ERROR("more than one key file found, support only one key file currently, continue to try");
            goto out;
        }
        *key_file = util_strdup_s(tmp_key_file);
        goto out;
    } else {
        goto out;
    }

out:
    free(key_name);
    key_name = NULL;
    free(tmp_cert_file);
    free(tmp_key_file);

    if (ret != 0) {
        free(*ca_file);
        *ca_file = NULL;
        free(*cert_file);
        *cert_file = NULL;
        free(*key_file);
        *key_file = NULL;
    }

    return ret;
}

static bool valid_certs(char *ca_file, char *cert_file, char *key_file)
{
    if ((ca_file == NULL && cert_file == NULL && key_file == NULL) ||
        (ca_file != NULL && cert_file != NULL && key_file != NULL)) {
        return true;
    }
    return false;
}

int certs_load(char *host, bool use_decrypted_key, char **ca_file, char **cert_file, char **key_file)
{
    int ret = 0;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char *path = NULL;

    if (host == NULL || ca_file == NULL || cert_file == NULL || key_file == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    path = util_path_join(g_certs_dir, host);
    if (path == NULL) {
        ERROR("failed to join certs dir when loading certs");
        return -1;
    }

    // If no certs exist, load nothing but not fail.
    if (!util_file_exists(path)) {
        ret = 0;
        goto out;
    }

    dir = opendir(path);
    if (dir == NULL) {
        ERROR("error open file for reading certs");
        ret = -1;
        goto out;
    }

    entry = readdir(dir);
    while (entry != 0) {
        if (strncmp(entry->d_name, ".", PATH_MAX - 1) == 0 || strncmp(entry->d_name, "..", PATH_MAX - 1) == 0) {
            entry = readdir(dir);
            continue;
        }

        ret = load_certs(path, entry->d_name, use_decrypted_key, ca_file, cert_file, key_file);
        if (ret != 0) {
            ERROR("error loading certs");
            ret = -1;
            goto out;
        }

        entry = readdir(dir);
    }

    if (!valid_certs(*ca_file, *cert_file, *key_file)) {
        ERROR("failed to load all certs");
        isulad_try_set_error_message("failed to load all certs");
        ret = -1;
    }

out:
    if (dir != NULL) {
        closedir(dir);
    }
    free(path);
    path = NULL;

    if (ret != 0) {
        free(*ca_file);
        *ca_file = NULL;
        free(*cert_file);
        *cert_file = NULL;
        free(*key_file);
        *key_file = NULL;
    }

    return ret;
}
