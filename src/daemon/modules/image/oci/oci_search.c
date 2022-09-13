/******************************************************************************
 * Copyright (c) KylinSoft  Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.

 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: yangyucheng
 * Create: 2022-6-11
 * Description: isula search operator implement
 ********************************************************************************/
#include "oci_pull.h"
#include "registry.h"
#include "oci_image.h"
#include "utils_images.h"

#include <string.h>
#include "utils_string.h"
#include <stdlib.h>
#include "utils.h"
#include "err_msg.h"
#include "isula_libutils/log.h"
#include "utils_array.h"
#include "utils_base64.h"

static int decode_auth(const char *auth, char **username, char **password)
{
    int nret = 0;
    int ret = 0;
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    char **auth_parts = NULL;

    if (auth == NULL || username == NULL || password == NULL) {
        ERROR("invalid NULL pointer");
        return -1;
    }

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
    util_free_sensitive_string((char *)decoded);
    decoded = NULL;
    util_free_array(auth_parts);
    auth_parts = NULL;

    return ret;
}

static void update_option_insecure_registry(registry_search_options *options, char **insecure_registries, char *host)
{
    char **registry = NULL;

    if (insecure_registries == NULL || options == NULL || host == NULL) {
        return;
    }

    for (registry = insecure_registries; (registry != NULL) && (*registry != NULL); registry++) {
        if (!strcmp(*registry, host)) {
            options->insecure_registry = true;
        }
    }
}

static int search_image(const im_search_request *request, im_search_response *response)
{
    int ret = -1;
    registry_search_options *options = NULL;
    char **insecure_registries = NULL;
    char **registry_mirrors = NULL;
    char **mirror = NULL;
    struct oci_image_module_data *oci_image_data = NULL;

    char *output = (char *)util_common_calloc_s(1024 * sizeof(char));
    if (output == NULL) {
        ERROR("Out of memory");
        return ret;
    }

    options = (registry_search_options *)util_common_calloc_s(sizeof(registry_search_options));
    if (options == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    if (request->auth != NULL) {
        ret = decode_auth(request->auth, &options->auth.username, &options->auth.password);
        if (ret != 0) {
            ERROR("Decode auth failed");
            goto out;
        }
    } else {
        options->auth.username = util_strdup_s(request->username);
        options->auth.password = util_strdup_s(request->password);
    }

    oci_image_data = get_oci_image_data();
    options->skip_tls_verify = oci_image_data->insecure_skip_verify_enforce;
    insecure_registries = oci_image_data->insecure_registries;

    options->host = oci_get_host(request->image);
    if (options->host != NULL) {
        options->image_name = oci_get_imagename(request->image);
        update_option_insecure_registry(options, insecure_registries, options->host);
        ret = registry_search(options, &output);
        if (ret != 0) {
            ERROR("search %s failed", options->image_name);
            goto out;
        }
        response->image_tags_json = util_strdup_s(output);
    } else {
        registry_mirrors = oci_image_data->registry_mirrors;
        if (registry_mirrors == NULL) {
            ERROR("Invalid image name %s, no host found", request->image);
            isulad_try_set_error_message("Invalid image name, no host found");
            goto out;
        }

        for (mirror = registry_mirrors; (mirror != NULL) && (*mirror != NULL); mirror++) {
            if (util_has_prefix(*mirror, HTTP_PREFIX)) {
                options->insecure_registry = true;
            }
            options->host = oci_host_from_mirror(*mirror);
            update_option_insecure_registry(options, insecure_registries, options->host);
            options->image_name = oci_get_imagename(request->image);
            ret = registry_search(options, &output);
            if (ret != 0) {
                continue;
            }
            response->image_tags_json = util_strdup_s(output);
            goto out;
        }
    }

out:
    free_registry_search_options(options);
    options = NULL;
    free(output);
    output = NULL;

    return ret;
}

int oci_do_search_image(const im_search_request *request, im_search_response *response)
{
    int ret = 0;

    if (request == NULL || request->image == NULL || response == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = search_image(request, response);
    if (ret != 0) {
        ERROR("search image %s failed", request->image);
        isulad_set_error_message("Failed to search image %s with error: %s", request->image, g_isulad_errmsg);
        ret = -1;
        goto out;
    }

out:
    return ret;
}
