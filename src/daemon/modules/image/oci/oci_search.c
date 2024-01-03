/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
* iSulad licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
* Author: zhongtao
* Create: 2022-10-17
* Description: isula image search operator implement
*******************************************************************************/
#include "oci_search.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_images.h"
#include "registry.h"
#include "err_msg.h"
#include "storage.h"
#include "utils_array.h"
#include "utils_base64.h"
#include "utils_string.h"
#include "oci_image.h"
#include "filters.h"

static void update_search_option_insecure_registry(registry_search_options *options, char **insecure_registries,
                                                   char *host)
{
    char **registry = NULL;

    if (insecure_registries == NULL || options == NULL || host == NULL) {
        return;
    }

    for (registry = insecure_registries; (registry != NULL) && (*registry != NULL); registry++) {
        if (strcmp(*registry, host) == 0) {
            options->insecure_registry = true;
            break;
        }
    }
}

static int search_image_with_config_host(struct oci_image_module_data *oci_image_data, registry_search_options *options,
                                         char **insecure_registries, imagetool_search_result **result)
{
    int ret;
    char **registry_mirrors = NULL;
    char **mirror = NULL;
    char *host = NULL;
    char temp_search_name[PATH_MAX] = { 0 };

    registry_mirrors = oci_image_data->registry_mirrors;
    if (registry_mirrors == NULL) {
        ERROR("Maybe should add registry-mirror in /etc/isulad/daemon.json");
        isulad_try_set_error_message("Maybe should add registry-mirror in /etc/isulad/daemon.json");
        return -1;
    }

    for (mirror = registry_mirrors; (mirror != NULL) && (*mirror != NULL); mirror++) {
        if (util_has_prefix(*mirror, HTTP_PREFIX)) {
            options->insecure_registry = true;
        }
        host = oci_host_from_mirror(*mirror);
        if (host == NULL) {
            DEBUG("Get host from %s error", *mirror);
            continue;
        }

        ret = snprintf(temp_search_name, PATH_MAX, "%s/%s", host, options->search_name);
        if (ret < 0 || (size_t)ret >= PATH_MAX) {
            DEBUG("Get complete search name failed");
            free(host);
            continue;
        }

        free(options->search_name);
        options->search_name = util_strdup_s(temp_search_name);

        update_search_option_insecure_registry(options, insecure_registries, host);

        ret = registry_search(options, result);
        if (ret != 0) {
            DEBUG("Search %s error", host);
            free(host);
            continue;
        }
        free(host);
        break;
    }

    return 0;
}

static int search_image(const im_search_request *request, imagetool_search_result **result)
{
    int ret = 0;
    registry_search_options *options = NULL;
    char **insecure_registries = NULL;
    char *host = NULL;
    struct oci_image_module_data *oci_image_data = NULL;

    options = (registry_search_options *)util_common_calloc_s(sizeof(registry_search_options));
    if (options == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    oci_image_data = get_oci_image_data();
    options->skip_tls_verify = oci_image_data->insecure_skip_verify_enforce;
    insecure_registries = oci_image_data->insecure_registries;
    options->search_name = util_strdup_s(request->search_name);
    options->limit = request->limit;

    // If host is set in search name, use it to search.
    host = oci_get_host(request->search_name);
    if (host != NULL) {
        update_search_option_insecure_registry(options, insecure_registries, host);
        ret = registry_search(options, result);
        if (ret != 0) {
            ERROR("Search image failed");
            ret = -1;
        }
        goto out;
    }

    // If host is not set in search name, use 'registry-mirror' in 'daemon.json' as host to search.
    if (search_image_with_config_host(oci_image_data, options, insecure_registries, result) != 0) {
        ERROR("Search image with config host failed");
        ret = -1;
    }

out:
    free(host);
    free_registry_search_options(options);

    return ret;
}

int oci_do_search_image(const im_search_request *request, imagetool_search_result **result)
{
    int ret = 0;

    if (request == NULL || request->search_name == NULL || result == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = search_image(request, result);
    if (ret != 0) {
        ERROR("Search image %s failed", request->search_name);
        isulad_set_error_message("Failed to search image %s with error: %s", request->search_name, g_isulad_errmsg);
        return -1;
    }

    return ret;
}
