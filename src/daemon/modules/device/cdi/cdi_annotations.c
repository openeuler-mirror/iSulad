/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuxu
 * Create: 2024-03-06
 * Description: provide cdi annotations function
 ******************************************************************************/
#include "cdi_annotations.h"

#include <ctype.h>
#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/utils_string.h>

#include "error.h"
#include "utils.h"
#include "utils_array.h"
#include "cdi_parser.h"

#define CDI_ANNOTATIONS_PREFIX "cdi.k8s.io/"

static int parse_devices(string_array *devices, const char *value, char **error)
{
    __isula_auto_array_t char **parts = NULL;
    char **pos;

    parts = util_string_split(value, ',');
    if (parts == NULL) {
        ERROR("Invalid CDI device value %s", value);
        format_errorf(error, "Invalid CDI device value %s", value);
        return -1;
    }
    for (pos = parts; pos != NULL && *pos != NULL; pos++) {
        if (!cdi_parser_is_qualified_name(*pos)) {
            ERROR("Invalid CDI device name %s", *pos);
            format_errorf(error, "Invalid CDI device name %s", *pos);
            return -1;
        }
        if (util_append_string_array(devices, *pos) != 0) {
            ERROR("Out of memory");
            *error = util_strdup_s("Out of memory");
            return -1;
        }
    }

    return 0;
}

int cdi_parse_annotations(json_map_string_string *annotations, string_array **keys,
                          string_array **devices, char **error)
{
    char *key = NULL;
    char *value = NULL;
    size_t i;
    __isula_auto_string_array_t string_array *keys_array = NULL;
    __isula_auto_string_array_t string_array *devices_array = NULL;

    if (annotations == NULL || keys == NULL || devices == NULL || error == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    keys_array = util_common_calloc_s(sizeof(*keys_array));
    if (keys_array == NULL) {
        ERROR("Out of memory");
        *error = util_strdup_s("Out of memory");
        return -1;
    }
    devices_array = util_common_calloc_s(sizeof(*devices_array));
    if (devices_array == NULL) {
        ERROR("Out of memory");
        *error = util_strdup_s("Out of memory");
        return -1;
    }

    for (i = 0; i < annotations->len; i++) {
        key = annotations->keys[i];
        value = annotations->values[i];
        if (!util_has_prefix(key, CDI_ANNOTATIONS_PREFIX)) {
            continue;
        }
        if (parse_devices(devices_array, value, error) != 0) {
            return -1;
        }
        if (util_append_string_array(keys_array, key) != 0) {
            ERROR("Out of memory");
            *error = util_strdup_s("Out of memory");
            return -1;
        }
    }

    *keys = keys_array;
    keys_array = NULL;
    *devices = devices_array;
    devices_array = NULL;
    return 0;
}
