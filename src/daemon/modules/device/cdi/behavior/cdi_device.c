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
 * Description: provide cdi device function
 ******************************************************************************/
#include "cdi_device.h"

#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "error.h"
#include "cdi_parser.h"
#include "cdi_spec.h"

static int cdi_device_validate(struct cdi_cache_device *d);

void free_cdi_cache_device(struct cdi_cache_device *d)
{
    if (d == NULL) {
        return;
    }
 
    /* 
     * free_cdi_cache_device should not be recursively free raw_device.
     * Otherwise, the function conflicts with the raw_spec free raw_device
     * when cdi_cache_spec free raw_spec, triggering double free. 
     */
    d->raw_device = NULL;
 
    /* 
     * free_cdi_cache_device should not be recursively free cache_spec.
     * Otherwise, the function conflicts with the cache free specs,
     * triggering double free. 
     */
    d->cache_spec = NULL;
 
    free(d);
}

struct cdi_cache_device *cdi_device_new_device(struct cdi_cache_spec *spec, cdi_device *d)
{
    struct cdi_cache_device *dev = NULL;

    if (spec == NULL || d == NULL) {
        ERROR("Invalid params");
        return NULL;
    }

    dev = util_common_calloc_s(sizeof(*dev));
    if (dev == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    dev->raw_device = d;
    dev->cache_spec = spec;

    if (cdi_device_validate(dev) != 0) {
        free_cdi_cache_device(dev);
        return NULL;
    }
    return dev;
}

const struct cdi_cache_spec *cdi_device_get_spec(const struct cdi_cache_device *d)
{
    if (d == NULL) {
        ERROR("Invalid params");
        return NULL;
    }
    return d->cache_spec;
}

char *cdi_device_get_qualified_name(const struct cdi_cache_device *d)
{
    if (d == NULL || d->raw_device == NULL) {
        ERROR("Invalid params");
        return NULL;
    }
    return cdi_parser_qualified_name(cdi_spec_get_vendor(d->cache_spec),
        cdi_spec_get_class(d->cache_spec), d->raw_device->name);
}

cdi_container_edits *cdi_device_get_edits(const struct cdi_cache_device *d)
{
    if (d == NULL || d->raw_device == NULL) {
        ERROR("Invalid params");
        return NULL;
    }
    return d->raw_device->container_edits;
}

static int cdi_device_validate(struct cdi_cache_device *d)
{
    cdi_container_edits *edits = NULL;

    if (cdi_parser_validate_device_name(d->raw_device->name) != 0) {
        ERROR("Failed to validate device name");
        return -1;
    }

    // ignore validate annotations

    edits = cdi_device_get_edits(d);
    if (cdi_container_edits_is_empty(edits)) {
        ERROR("Invalid device, empty device edits");
        return -1;
    }
    if (cdi_container_edits_validate(edits) != 0) {
        ERROR("Invalid device %s", d->raw_device->name);
        return -1;
    }
    return 0;
}
