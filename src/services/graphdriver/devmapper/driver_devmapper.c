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
* Create: 2020-01-19
* Description: provide devicemapper graphdriver function definition
******************************************************************************/
#include "driver_devmapper.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "log.h"
#include "libisulad.h"
#include "utils.h"

#define DM_LOG_FATAL 2
#define DM_LOG_DEBUG 7

static int devmapper_parse_options(struct graphdriver *driver, const char **options, size_t options_len)
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
            ERROR("Out of memory");
            return -1;
        }
        p = strchr(dup, '=');
        if (!p) {
            ERROR("Unable to parse key/value option: '%s'", dup);
            free(dup);
            return -1;
        }
        *p = '\0';
        val = p + 1;
        if (strcasecmp(dup, "dm.fs") == 0) {
            if (strcmp(val, "ext4")) {
                ERROR("Invalid filesystem: '%s': not supported", val);
                ret = -1;
            }
        } else if (strcasecmp(dup, "dm.thinpooldev") == 0) {
            if (!strcmp(val, "")) {
                ERROR("Invalid thinpool device, it must not be empty");
                ret = -1;
            }
        } else if (strcasecmp(dup, "dm.min_free_space") == 0) {
            long converted = 0;
            ret = util_parse_percent_string(val, &converted);
            if (ret != 0 || converted == 100) {
                ERROR("Invalid min free space: '%s': %s", val, strerror(-ret));
                ret = -1;
            }
        } else if (strcasecmp(dup, "dm.basesize") == 0) {
            int64_t converted = 0;
            ret = util_parse_byte_size_string(val, &converted);
            if (ret != 0) {
                ERROR("Invalid size: '%s': %s", val, strerror(-ret));
            }
        } else if (strcasecmp(dup, "dm.mkfsarg") == 0 || strcasecmp(dup, "dm.mountopt") == 0) {
            /* We have no way to check validation here, validation is checked when using them. */
        } else {
            ERROR("devicemapper: unknown option: '%s'", dup);
            ret = -1;
        }
        free(dup);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

int devmapper_init(struct graphdriver *driver, const char *drvier_home, const char **options, size_t len)
{
    int ret = 0;

    if (driver == NULL || drvier_home == NULL || options == NULL) {
        return -1;
    }

    if (util_mkdir_p(drvier_home, 0700) != 0) {
        ERROR("Unable to create driver home directory %s.", drvier_home);
        ret = -1;
        goto out;
    }

    ret = devmapper_parse_options(driver, options, len);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

bool devmapper_is_quota_options(struct graphdriver *driver, const char *option)
{
    return false;
}
