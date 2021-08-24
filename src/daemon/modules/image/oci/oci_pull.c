/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
* iSulad licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
* Author: wangfengtu
* Create: 2020-05-07
* Description: isula image pull operator implement
*******************************************************************************/
#include "oci_pull.h"

#include <isula_libutils/imagetool_image.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_images.h"
#include "registry.h"
#include "isulad_config.h"
#include "err_msg.h"
#include "storage.h"
#include "utils_array.h"
#include "utils_base64.h"
#include "utils_string.h"
#include "oci_image.h"

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

static void update_option_insecure_registry(registry_pull_options *options, char **insecure_registries, char *host)
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

static int pull_image(const im_pull_request *request, char **name)
{
    int ret = -1;
    registry_pull_options *options = NULL;
    char **insecure_registries = NULL;
    char **registry_mirrors = NULL;
    char **mirror = NULL;
    char *host = NULL;
    char *with_tag = NULL;
    struct oci_image_module_data *oci_image_data = NULL;

    options = (registry_pull_options *)util_common_calloc_s(sizeof(registry_pull_options));
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
    options->registry_transformation = oci_image_data->registry_transformation;
    insecure_registries = oci_image_data->insecure_registries;

    host = oci_get_host(request->image);
    if (host != NULL) {
        options->image_name = oci_default_tag(request->image);
        options->dest_image_name = oci_normalize_image_name(request->image);
        update_option_insecure_registry(options, insecure_registries, host);
        ret = registry_pull((const registry_pull_options *)options);
        if (ret != 0) {
            ERROR("pull image failed");
            goto out;
        }
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
            host = oci_host_from_mirror(*mirror);
            update_option_insecure_registry(options, insecure_registries, host);
            with_tag = oci_default_tag(request->image);
            options->image_name = oci_add_host(host, with_tag);
            free(with_tag);
            with_tag = NULL;
            free(host);
            host = NULL;
            options->dest_image_name = oci_normalize_image_name(request->image);
            ret = registry_pull((const registry_pull_options *)options);
            if (ret != 0) {
                continue;
            }
            break;
        }
    }

    *name = util_strdup_s(options->dest_image_name);

out:
    free(host);
    host = NULL;
    free_registry_pull_options(options);
    options = NULL;

    return ret;
}

int oci_do_pull_image(const im_pull_request *request, im_pull_response *response)
{
    int ret = 0;
    imagetool_image_summary *image = NULL;
    imagetool_image_summary *image2 = NULL;
    char *dest_image_name = NULL;

    if (request == NULL || request->image == NULL || response == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = pull_image(request, &dest_image_name);
    if (ret != 0) {
        ERROR("pull image %s failed", request->image);
        isulad_set_error_message("Failed to pull image %s with error: %s", request->image, g_isulad_errmsg);
        ret = -1;
        goto out;
    }

    image = storage_img_get_summary(dest_image_name);
    image2 = storage_img_get_summary(request->image);
    if (image == NULL || image2 == NULL) {
        ERROR("get image %s failed after pulling", request->image);
        isulad_set_error_message("Failed to pull image %s with error: image not found after pulling", request->image);
        ret = -1;
        goto out;
    }

    response->image_ref = util_strdup_s(image->id);

out:
    free_imagetool_image_summary(image);
    free_imagetool_image_summary(image2);
    free(dest_image_name);
    return ret;
}
