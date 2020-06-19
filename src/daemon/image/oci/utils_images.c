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
 * Author: WuJing
 * Create: 2020-05-09
 * Description: provide isula image common functions
 *******************************************************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_images.h"
#include "sha256.h"

char *get_last_part(char **parts)
{
    char *last_part = NULL;
    char **p;

    for (p = parts; p != NULL && *p != NULL; p++) {
        last_part = *p;
    }

    return last_part;
}

char *oci_get_host(const char *name)
{
    char **parts = NULL;
    char *host = NULL;

    if (name == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    parts = util_string_split(name, '/');
    if ((parts != NULL && *parts != NULL && !strings_contains_any(*parts, ".:") && strcmp(*parts, "localhost")) ||
        (strstr(name, "/") == NULL)) {
        util_free_array(parts);
        return NULL;
    }

    if (parts != NULL) {
        host = util_strdup_s(parts[0]);
        util_free_array(parts);
    }

    return host;
}

char *oci_default_tag(const char *name)
{
    char temp[PATH_MAX] = { 0 };
    char **parts = NULL;
    char *last_part = NULL;
    char *add_default_tag = "";

    if (name == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    parts = util_string_split(name, '/');
    if (parts == NULL) {
        ERROR("split %s by '/' failed", name);
        return NULL;
    }

    last_part = get_last_part(parts);
    if (last_part != NULL && strrchr(last_part, ':') == NULL) {
        add_default_tag = DEFAULT_TAG;
    }

    util_free_array(parts);

    // Add image's default tag
    int nret = snprintf(temp, sizeof(temp), "%s%s", name, add_default_tag);
    if (nret < 0 || (size_t)nret >= sizeof(temp)) {
        ERROR("sprint temp image name failed");
        return NULL;
    }

    return util_strdup_s(temp);
}

char *oci_host_from_mirror(const char *mirror)
{
    const char *host = mirror;

    if (mirror == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    if (util_has_prefix(mirror, HTTPS_PREFIX)) {
        host = mirror + strlen(HTTPS_PREFIX);
    } else if (util_has_prefix(mirror, HTTP_PREFIX)) {
        host = mirror + strlen(HTTP_PREFIX);
    }

    return util_strdup_s(host);
}

char *oci_add_host(const char *host, const char *name)
{
    char *with_host = NULL;
    bool need_repo_prefix = false;

    if (host == NULL || name == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    if (strchr(name, '/') == NULL) {
        need_repo_prefix = true;
    }

    with_host = util_common_calloc_s(strlen(host) + strlen("/") + strlen(DEFAULT_REPO_PREFIX) + strlen(name) + 1);
    if (with_host == NULL) {
        ERROR("out of memory");
        return NULL;
    }
    (void)strcat(with_host, host);
    (void)strcat(with_host, "/");
    if (need_repo_prefix) {
        (void)strcat(with_host, DEFAULT_REPO_PREFIX);
    }
    (void)strcat(with_host, name);

    return with_host;
}

// normalize the unqualified image to be domain/repo/image...
char *oci_normalize_image_name(const char *name)
{
    char temp[PATH_MAX] = { 0 };
    char **parts = NULL;
    char *last_part = NULL;
    char *add_dockerio = "";
    char *add_library = "";
    char *add_default_tag = "";

    // Add prefix docker.io if necessary
    parts = util_string_split(name, '/');
    if ((parts != NULL && *parts != NULL && !strings_contains_any(*parts, ".:") && strcmp(*parts, "localhost")) ||
        (strstr(name, "/") == NULL)) {
        add_dockerio = DEFAULT_HOSTNAME;
    }

    // Add library if necessary
    if (strlen(add_dockerio) != 0 && strstr(name, "/") == NULL) {
        add_library = DEFAULT_REPO_PREFIX;
    }

    // Add default tag if necessary
    last_part = get_last_part(parts);
    if (last_part != NULL && strrchr(last_part, ':') == NULL) {
        add_default_tag = DEFAULT_TAG;
    }

    util_free_array(parts);

    // Normalize image name
    int nret = snprintf(temp, sizeof(temp), "%s%s%s%s", add_dockerio, add_library, name, add_default_tag);
    if (nret < 0 || (size_t)nret >= sizeof(temp)) {
        ERROR("sprint temp image name failed");
        return NULL;
    }

    return util_strdup_s(temp);
}

int oci_split_image_name(const char *image_name, char **host, char **name, char **tag)
{
    char *tag_pos = NULL;
    char *name_pos = NULL;
    char *tmp_image_name = NULL;

    if (!util_valid_image_name(image_name)) {
        ERROR("Invalid full image name %s", image_name);
        return -1;
    }

    tmp_image_name = util_strdup_s(image_name);
    tag_pos = util_tag_pos(tmp_image_name);
    if (tag_pos != NULL) {
        *tag_pos = 0;
        tag_pos++;
        if (tag != NULL) {
            *tag = util_strdup_s(tag_pos);
        }
    }

    name_pos = strchr(tmp_image_name, '/');
    if (name_pos != NULL) {
        *name_pos = 0;
        name_pos++;
        if (name != NULL) {
            *name = util_strdup_s(name_pos);
        }
        if (host != NULL) {
            *host = util_strdup_s(tmp_image_name);
        }
    }

    free(tmp_image_name);
    tmp_image_name = NULL;

    return 0;
}

char *oci_full_image_name(const char *host, const char *name, const char *tag)
{
    char temp[PATH_MAX] = { 0 };
    const char *tmp_host = "";
    const char *tmp_sep = "";
    const char *tmp_prefix = "";
    const char *tmp_colon = "";
    const char *tmp_tag = DEFAULT_TAG;

    if (name == NULL) {
        ERROR("Invalid NULL name found when getting full image name");
        return NULL;
    }

    if (host != NULL) {
        tmp_host = host;
        tmp_sep = "/";
    }
    if (strchr(name, '/') == NULL) {
        tmp_prefix = DEFAULT_REPO_PREFIX;
    }
    if (tag != NULL) {
        tmp_colon = ":";
        tmp_tag = tag;
    }
    int nret = snprintf(temp, sizeof(temp), "%s%s%s%s%s%s", tmp_host, tmp_sep, tmp_prefix, name, tmp_colon, tmp_tag);
    if (nret < 0 || (size_t)nret >= sizeof(temp)) {
        ERROR("sprint temp image name failed, host %s, name %s, tag %s", host, name, tag);
        return NULL;
    }

    if (!util_valid_image_name(temp)) {
        ERROR("Invalid full image name %s, host %s, name %s, tag %s", temp, host, name, tag);
        return NULL;
    }

    return util_strdup_s(temp);
}

char *oci_strip_dockerio_prefix(const char *name)
{
    char prefix[PATH_MAX] = { 0 };
    size_t size = 0;

    if (name == NULL) {
        ERROR("NULL image name");
        return NULL;
    }

    int nret = snprintf(prefix, sizeof(prefix), "%s%s", DEFAULT_HOSTNAME, DEFAULT_REPO_PREFIX);
    if (nret < 0 || (size_t)nret >= sizeof(prefix)) {
        ERROR("sprint prefix prefix failed");
        return NULL;
    }

    // Strip docker.io/library
    size = strlen(prefix);
    if (strncmp(name, prefix, size) == 0 && strlen(name) > size) {
        return util_strdup_s(name + size);
    }

    // Strip docker.io
    size = strlen(DEFAULT_HOSTNAME);
    if (strncmp(name, DEFAULT_HOSTNAME, size) == 0 && strlen(name) > size) {
        return util_strdup_s(name + size);
    }

    return util_strdup_s(name);
}

static bool should_use_origin_name(const char *name)
{
    size_t i;

    for (i = 0; i < strlen(name); i++) {
        char ch = name[i];
        if (ch != '.' && !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'z')) {
            return false;
        }
    }

    return true;
}

// Convert a BigData key name into an acceptable file name.
char *make_big_data_base_name(const char *key)
{
    int ret = 0;
    int nret = 0;
    char *b64_encode_name = NULL;
    size_t b64_encode_name_len = 0;
    char *base_name = NULL;
    size_t name_size;

    if (should_use_origin_name(key)) {
        return util_strdup_s(key);
    }

    b64_encode_name_len = util_base64_encode_len(strlen(key));
    b64_encode_name = util_common_calloc_s(b64_encode_name_len + 1);
    if (b64_encode_name == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    nret = util_base64_encode((unsigned char *)key, strlen(key), b64_encode_name, b64_encode_name_len);
    if (nret < 0) {
        ret = -1;
        ERROR("Encode auth to base64 failed");
        goto out;
    }
    name_size = 1 + strlen(b64_encode_name) + 1; // '=' + encode string + '\0'

    base_name = (char *)util_common_calloc_s(name_size * sizeof(char));
    if (base_name == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    nret = snprintf(base_name, name_size, "=%s", b64_encode_name);
    if (nret < 0 || (size_t)nret >= name_size) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    DEBUG("big data file name : %s", base_name);

out:
    if (ret != 0) {
        free(base_name);
        base_name = NULL;
    }
    free(b64_encode_name);

    return base_name;
}

char *oci_calc_diffid(const char *file)
{
    int ret = 0;
    char *diff_id = NULL;
    bool gzip = false;

    if (file == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    ret = util_gzip_compressed(file, &gzip);
    if (ret != 0) {
        ERROR("Get layer file %s gzip attribute failed", file);
        goto out;
    }

    if (gzip) {
        diff_id = sha256_full_gzip_digest(file);
    } else {
        diff_id = sha256_full_file_digest(file);
    }
    if (diff_id == NULL) {
        ERROR("calculate digest failed for file %s", file);
        ret = -1;
    }

out:
    if (ret != 0) {
        UTIL_FREE_AND_SET_NULL(diff_id);
    }
    return diff_id;
}
