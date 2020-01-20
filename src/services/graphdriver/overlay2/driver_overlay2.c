/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2019-04-02
 * Description: provide overlay2 function definition
 ******************************************************************************/
#include "driver_overlay2.h"
#include <string.h>
#include <stdlib.h>

#include "libisulad.h"
#include "utils.h"

#define QUOTA_SIZE_OPTION "overlay2.size"
#define QUOTA_BASESIZE_OPTIONS "overlay2.basesize"

int overlay2_init(struct graphdriver *driver)
{
    return 0;
}

bool overlay2_is_quota_options(struct graphdriver *driver, const char *option)
{
    return strncmp(option, QUOTA_SIZE_OPTION, strlen(QUOTA_SIZE_OPTION)) == 0 ||
           strncmp(option, QUOTA_BASESIZE_OPTIONS, strlen(QUOTA_BASESIZE_OPTIONS)) == 0;
}

int overlay2_parse_options(struct graphdriver *driver, const char **options, size_t options_len)
{
    size_t i = 0;

    for (i = 0; options != NULL && i < options_len; i++) {
        char *dup = NULL;
        char *p = NULL;
        char *val = NULL;
        int ret = 0;

        dup = util_strdup_s(options[i]);
        if (dup == NULL) {
            isulad_set_error_message("Out of memory");
            return -1;
        }
        p = strchr(dup, '=');
        if (!p) {
            isulad_set_error_message("Unable to parse key/value option: '%s'", dup);
            free(dup);
            return -1;
        }
        *p = '\0';
        val = p + 1;
        if (strcasecmp(dup, QUOTA_SIZE_OPTION) == 0 || strcasecmp(dup, QUOTA_BASESIZE_OPTIONS) == 0) {
            int64_t converted = 0;
            ret = util_parse_byte_size_string(val, &converted);
            if (ret != 0) {
                isulad_set_error_message("Invalid size: '%s': %s", val, strerror(-ret));
            }
        } else if (strcasecmp(dup, "overlay2.override_kernel_check") == 0) {
            bool converted_bool = 0;
            ret = util_str_to_bool(val, &converted_bool);
            if (ret != 0) {
                isulad_set_error_message("Invalid bool: '%s': %s", val, strerror(-ret));
            }
        } else {
            isulad_set_error_message("Overlay2: unknown option: '%s'", dup);
            ret = -1;
        }
        free(dup);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

