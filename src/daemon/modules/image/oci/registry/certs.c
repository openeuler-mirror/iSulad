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
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "certs.h"
#include "utils_file.h"
#include "utils_string.h"

#define DEFAULT_ISULAD_CERTD "/etc/isulad/certs.d"
#define CLIENT_CERT_SUFFIX ".cert"
#define CA_SUFFIX ".crt"

static char *g_certs_dir = DEFAULT_ISULAD_CERTD;

void certs_set_dir(char *certs_dir)
{
    if (certs_dir != NULL) {
        g_certs_dir = util_strdup_s(certs_dir);
    }
    return;
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

static int load_certs(const char *path, const char *name, bool use_decrypted_key, char **ca_file, char **cert_file,
                      char **key_file)
{
    int ret = 0;
    char *key_name = NULL;

    if (path == NULL || ca_file == NULL || cert_file == NULL || key_file == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    if (ca_file != NULL && util_has_suffix(name, CA_SUFFIX)) {
        *ca_file = util_path_join(path, name);
        if (*ca_file == NULL) {
            ret = -1;
            ERROR("error join %s and %s", path, name);
            goto out;
        }
        DEBUG("ca file: %s", *ca_file);
        goto out;
    } else if (cert_file != NULL && *cert_file == NULL && util_has_suffix(name, CLIENT_CERT_SUFFIX)) {
        key_name = corresponding_key_name(name);
        if (key_name == NULL) {
            ERROR("find corresponding key name for %s failed", name);
            ret = -1;
            goto out;
        }
        *key_file = util_path_join(path, key_name);
        *cert_file = util_path_join(path, name);
        if (*cert_file == NULL || *key_file == NULL) {
            ret = -1;
            ERROR("error join %s and %s, or error join %s and %s", path, name, path, key_name);
            goto out;
        }
        DEBUG("client cert file: %s", *cert_file);
        DEBUG("client key file: %s", *key_file);
        goto out;
    } else {
        goto out;
    }

out:
    free(key_name);
    key_name = NULL;

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
        ERROR("failed to join path %s and %s when loading certs", g_certs_dir, host);
        return -1;
    }

    // If no certs exist, load nothing but not fail.
    if (!util_file_exists(path)) {
        ret = 0;
        goto out;
    }

    dir = opendir(path);
    if (dir == NULL) {
        ERROR("error open %s for reading certs for %s: %s", path, host, strerror(errno));
        ret = -1;
        goto out;
    }

    entry = readdir(dir);
    while (entry != 0) {
        if (strncmp(entry->d_name, ".", PATH_MAX) == 0 || strncmp(entry->d_name, "..", PATH_MAX) == 0) {
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

    if (*ca_file == NULL || *cert_file == NULL || *key_file == NULL) {
        WARN("Loaded only part of certs, continue to try");
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
