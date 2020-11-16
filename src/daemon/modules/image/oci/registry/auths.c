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
#include "auths.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/json_common.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "aes.h"
#include "isula_libutils/registry_auths.h"
#include "err_msg.h"
#include "utils_aes.h"
#include "utils_array.h"
#include "utils_base64.h"
#include "utils_file.h"
#include "utils_string.h"

static char *g_auth_path = DEFAULT_AUTH_DIR "/" AUTH_FILE_NAME;

void auths_set_dir(char *auth_dir)
{
    int sret = 0;
    char path[PATH_MAX] = { 0 };

    if (auth_dir == NULL) {
        return;
    }

    sret = snprintf(path, sizeof(path), "%s/%s", auth_dir, AUTH_FILE_NAME);
    if (sret < 0 || (size_t)sret >= sizeof(path)) {
        ERROR("Failed to sprintf auths file");
        return;
    }

    g_auth_path = util_strdup_s(path);

    aes_set_key_dir(auth_dir);

    return;
}

static int decode_auth_aes(char *encoded, char **username, char **password)
{
    int nret = 0;
    int ret = 0;
    unsigned char *decoded = NULL;
    char **auth_parts = NULL;
    char *auth = NULL;
    size_t decoded_len = 0;

    if (encoded == NULL || username == NULL || password == NULL) {
        ERROR("invalid NULL pointer");
        return -1;
    }

    nret = util_base64_decode(encoded, strlen(encoded), &decoded, &decoded_len);
    if (nret < 0) {
        ERROR("decode auth from base64 failed");
        ret = -1;
        goto out;
    }

    ret = aes_decode(decoded, decoded_len, (unsigned char **)&auth);
    if (ret < 0) {
        ERROR("decode aes failed");
        ret = -1;
        goto out;
    }

    free(decoded);
    decoded = NULL;
    nret = util_base64_decode(auth, strlen(auth), &decoded, &decoded_len);
    if (nret < 0) {
        ERROR("decode auth from base64 failed");
        ret = -1;
        goto out;
    }

    auth_parts = util_string_split((char *)decoded, ':');
    if (auth_parts == NULL || util_array_len((const char **)auth_parts) != 2) {
        ERROR("Invalid auth format");
        ret = -1;
        goto out;
    }

    *username = util_strdup_s(auth_parts[0]);
    *password = util_strdup_s(auth_parts[1]);
    (void)memset(auth_parts[0], 0, strlen(auth_parts[0]));
    (void)memset(auth_parts[1], 0, strlen(auth_parts[1]));

out:
    util_free_sensitive_string((char *)auth);
    auth = NULL;
    util_free_sensitive_string((char *)decoded);
    decoded = NULL;
    util_free_array(auth_parts);
    auth_parts = NULL;

    return ret;
}

static char *encode_auth_aes(char *username, char *password)
{
    int ret = 0;
    int nret = 0;
    int sret = 0;
    size_t plain_text_base64_encode_len = 0;
    char *plain_text_base64 = NULL;
    char plain_text[PATH_MAX] = { 0 };
    unsigned char *aes = NULL;
    size_t aes_len = 0;
    char *aes_base64 = NULL;

    sret = snprintf(plain_text, sizeof(plain_text), "%s:%s", username, password);
    if (sret < 0 || (size_t)sret >= sizeof(plain_text)) {
        ERROR("Failed to sprintf username and password");
        ret = -1;
        goto out;
    }

    nret = util_base64_encode((unsigned char *)plain_text, strlen(plain_text), &plain_text_base64);
    if (nret < 0) {
        ERROR("encode plain text to auth failed");
        ret = -1;
        goto out;
    }

    // Do not encode char '\0'
    plain_text_base64_encode_len = strlen(plain_text_base64);
    aes_len = AES_256_CFB_IV_LEN + plain_text_base64_encode_len;
    ret = aes_encode((unsigned char *)plain_text_base64, plain_text_base64_encode_len, &aes);
    if (ret < 0) {
        ERROR("encode aes failed");
        ret = -1;
        goto out;
    }

    nret = util_base64_encode(aes, aes_len, &aes_base64);
    if (nret < 0) {
        ERROR("encode plain text to auth failed");
        ret = -1;
        goto out;
    }

out:
    (void)memset(plain_text, 0, strlen(plain_text));
    util_free_sensitive_string((char *)aes);
    aes = NULL;
    util_free_sensitive_string(plain_text_base64);
    plain_text_base64 = NULL;
    if (ret != 0) {
        util_free_sensitive_string(aes_base64);
        aes_base64 = NULL;
    }
    return aes_base64;
}

int auths_load(char *host, char **username, char **password)
{
    size_t i = 0;
    registry_auths *auths = NULL;
    parser_error err = NULL;
    int ret = 0;

    if (host == NULL) {
        ERROR("failed to delete auths, host is NULL");
        return -1;
    }

    if (!util_file_exists(g_auth_path)) {
        return 0;
    }

    auths = registry_auths_parse_file(g_auth_path, NULL, &err);
    if (auths == NULL) {
        ERROR("failed to parse file %s", g_auth_path);
        ret = -1;
        goto out;
    }

    if (auths->auths == NULL || auths->auths->len == 0) {
        goto out;
    }

    for (i = 0; i < auths->auths->len; i++) {
        if (!strcmp(host, auths->auths->keys[i])) {
            ret = decode_auth_aes(auths->auths->values[i]->auth, username, password);
            if (ret != 0) {
                ERROR("Decode auth with aes failed");
                goto out;
            }
        }
    }

out:
    free_registry_auths(auths);
    auths = NULL;
    free(err);
    err = NULL;

    return 0;
}

static int add_allocated_auth(registry_auths *auths, char *host, char *auth)
{
    int ret = 0;
    size_t result_len = 0;
    defs_map_string_object_auths_element *element = NULL;
    defs_map_string_object_auths_element **values = NULL;
    defs_map_string_object_auths_element **old_values = NULL;

    if (auths->auths->len >= MAX_AUTHS_LEN) {
        ERROR("too many auths exceeded max number");
        return -1;
    }

    result_len = auths->auths->len + 1;
    element = util_common_calloc_s(sizeof(defs_map_string_object_auths_element));
    values = util_common_calloc_s(sizeof(defs_map_string_object_auths_element *) * result_len);
    if (element == NULL || values == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    ret = util_array_append(&auths->auths->keys, host);
    if (ret != 0) {
        ERROR("append host to auths's key failed");
        ret = -1;
        goto out;
    }

    old_values = auths->auths->values;
    (void)memcpy(values, old_values, sizeof(defs_map_string_object_auths_element *) * auths->auths->len);
    element->auth = util_strdup_s(auth);
    values[auths->auths->len] = element;
    element = NULL;
    free(old_values);
    old_values = NULL;

    auths->auths->values = values;
    auths->auths->len = result_len;

out:

    if (ret != 0) {
        free(element);
        element = 0;
        free(values);
        values = 0;
    }

    return ret;
}

static int add_auth(registry_auths *auths, char *host, char *auth)
{
    size_t i = 0;
    int ret = 0;
    bool found = false;

    if (auths == NULL || auths->auths == NULL) {
        ERROR("Invalid NULL auths");
        return -1;
    }

    for (i = 0; i < auths->auths->len; i++) {
        if (!strcmp(host, auths->auths->keys[i])) {
            free(auths->auths->keys[i]);
            auths->auths->keys[i] = util_strdup_s(host);
            free(auths->auths->values[i]->auth);
            auths->auths->values[i]->auth = util_strdup_s(auth);
            found = true;
            break;
        }
    }
    if (!found) {
        ret = add_allocated_auth(auths, host, auth);
        if (ret != 0) {
            ERROR("add allocated auth failed");
            goto out;
        }
    }

out:

    return ret;
}

static int ensure_auth_dir_exist()
{
    int ret = 0;
    char *auths_dir = NULL;

    auths_dir = util_path_dir(g_auth_path);
    if (auths_dir == NULL) {
        ERROR("get dir for auths failed");
        ret = -1;
        goto out;
    }

    ret = util_mkdir_p(auths_dir, DEFAULT_AUTH_DIR_MODE);
    if (ret != 0) {
        ERROR("mkdir for auths failed");
        isulad_try_set_error_message("create directory for auths failed");
        goto out;
    }

out:
    free(auths_dir);
    auths_dir = NULL;

    return ret;
}

int auths_save(char *host, char *username, char *password)
{
    int ret = 0;
    char *auth = NULL;
    registry_auths *auths = NULL;
    defs_map_string_object_auths *element = NULL;
    parser_error err = NULL;
    char *json = NULL;

    if (host == NULL || username == NULL || password == NULL) {
        ERROR("failed to save auths, host or usernmae or password is NULL");
        return -1;
    }

    ret = ensure_auth_dir_exist();
    if (ret != 0) {
        goto out;
    }

    auths = registry_auths_parse_file(g_auth_path, NULL, &err);
    if (auths == NULL) {
        auths = util_common_calloc_s(sizeof(registry_auths));
        element = util_common_calloc_s(sizeof(defs_map_string_object_auths));
        if (auths == NULL || element == NULL) {
            ERROR("out of memory");
            ret = -1;
            goto out;
        }
        auths->auths = element;
        element = NULL;
    }

    auth = encode_auth_aes(username, password);
    if (auth == NULL) {
        ERROR("encode auth with aes failed");
        isulad_try_set_error_message("failed to encode auth");
        ret = -1;
        goto out;
    }

    ret = add_auth(auths, host, auth);
    if (ret != 0) {
        ERROR("add auth failed");
        isulad_try_set_error_message("failed to add auth");
        goto out;
    }

    free(err);
    err = NULL;
    json = registry_auths_generate_json(auths, NULL, &err);
    if (json == NULL) {
        ERROR("failed to generate auths to json");
        isulad_try_set_error_message("failed to generate auths to json");
        ret = -1;
        goto out;
    }

    ret = util_atomic_write_file(g_auth_path, json, strlen(json), AUTH_FILE_MODE);
    if (ret != 0) {
        ERROR("failed to write auths json to file");
        goto out;
    }

out:
    free(json);
    json = NULL;
    free_registry_auths(auths);
    auths = NULL;
    free_defs_map_string_object_auths(element);
    element = NULL;
    free(auth);
    auth = NULL;
    free(err);
    err = NULL;

    return ret;
}

static void delete_auth(registry_auths *auths, char *host)
{
    size_t i = 0;
    bool found = false;
    int count = 0;

    if (auths->auths == NULL || auths->auths->len == 0) {
        return;
    }

    for (i = 0; i < auths->auths->len; i++) {
        if (!strcmp(host, auths->auths->keys[i])) {
            // Free current position
            free(auths->auths->keys[i]);
            auths->auths->keys[i] = NULL;
            free_defs_map_string_object_auths_element(auths->auths->values[i]);
            auths->auths->values[i] = NULL;
            found = true;
            continue;
        }
    }

    if (!found) {
        return;
    }

    for (i = 0; i < auths->auths->len; i++) {
        if (auths->auths->keys[count] != NULL) {
            count++;
            continue;
        }
        if (auths->auths->keys[i] == NULL) {
            continue;
        }
        // Move to empty position
        auths->auths->keys[count] = auths->auths->keys[i];
        auths->auths->keys[i] = NULL;
        auths->auths->values[count] = auths->auths->values[i];
        auths->auths->values[i] = NULL;
        count++;
    }

    auths->auths->len = count;

    return;
}

int auths_delete(char *host)
{
    registry_auths *auths = NULL;
    parser_error err = NULL;
    int ret = 0;
    char *json = NULL;

    if (host == NULL) {
        ERROR("failed to delete auths, host is NULL");
        return -1;
    }

    if (!util_file_exists(g_auth_path)) {
        return 0;
    }

    auths = registry_auths_parse_file(g_auth_path, NULL, &err);
    if (auths == NULL) {
        ERROR("failed to parse file");
        isulad_try_set_error_message("failed to parse file");
        ret = -1;
        goto out;
    }

    delete_auth(auths, host);

    free(err);
    err = NULL;
    json = registry_auths_generate_json(auths, NULL, &err);
    if (json == NULL) {
        ERROR("failed to generate auths to json");
        isulad_try_set_error_message("failed to generate auths to json");
        ret = -1;
        goto out;
    }

    ret = util_atomic_write_file(g_auth_path, json, strlen(json), AUTH_FILE_MODE);
    if (ret != 0) {
        ERROR("failed to write auths json to file");
        isulad_try_set_error_message("failed to write auths json to file");
        goto out;
    }

out:
    free(json);
    json = NULL;
    free_registry_auths(auths);
    auths = NULL;
    free(err);
    err = NULL;

    return ret;
}
