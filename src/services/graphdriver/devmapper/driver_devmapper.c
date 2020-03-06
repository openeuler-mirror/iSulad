/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
* iSulad licensed under the Mulan PSL v1.
* You can use this software according to the terms and conditions of the Mulan PSL v1.
* You may obtain a copy of Mulan PSL v1 at:
*     http://license.coscl.org.cn/MulanPSL
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v1 for more details.
* Author: wangfengtu
* Create: 2020-01-19
* Description: provide devicemapper graphdriver function definition
******************************************************************************/
#include "driver_devmapper.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "libisulad.h"
#include "utils.h"

#define DM_LOG_FATAL 2
#define DM_LOG_DEBUG 7

int devmapper_init(struct graphdriver *driver)
{
    return 0;
}

bool devmapper_is_quota_options(struct graphdriver *driver, const char *option)
{
    return false;
}

int devmapper_parse_options(struct graphdriver *driver, const char **options, size_t options_len)
{
    size_t i = 0;

    if (driver == NULL) {
        return -1;
    }

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
        if (strcasecmp(dup, "dm.fs") == 0) {
            if (strcmp(val, "ext4")) {
                isulad_set_error_message("Invalid filesystem: '%s': not supported", val);
                ret = -1;
            }
        } else if (strcasecmp(dup, "dm.thinpooldev") == 0) {
            if (!strcmp(val, "")) {
                isulad_set_error_message("Invalid thinpool device, it must not be empty");
                ret = -1;
            }
        } else if (strcasecmp(dup, "dm.min_free_space") == 0) {
            long converted = 0;
            ret = util_parse_percent_string(val, &converted);
            if (ret != 0 || converted == 100) {
                isulad_set_error_message("Invalid min free space: '%s': %s", val, strerror(-ret));
                ret = -1;
            }
        } else if (strcasecmp(dup, "dm.basesize") == 0) {
            int64_t converted = 0;
            ret = util_parse_byte_size_string(val, &converted);
            if (ret != 0) {
                isulad_set_error_message("Invalid size: '%s': %s", val, strerror(-ret));
            }
        } else if (strcasecmp(dup, "dm.mkfsarg") == 0 || strcasecmp(dup, "dm.mountopt") == 0) {
            /* We have no way to check validation here, validation is checked when using them. */
        } else {
            isulad_set_error_message("devicemapper: unknown option: '%s'", dup);
            ret = -1;
        }
        free(dup);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}
