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
 * Description: provide cdi spec function
 ******************************************************************************/
#include "cdi_spec.h"

#include <stdlib.h>
#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "utils.h"
#include "utils_version.h"
#include "error.h"
#include "path.h"
#include "cdi_version.h"
#include "cdi_parser.h"
#include "cdi_device.h"

static int cdi_spec_init(struct cdi_cache_spec *s);

void free_cdi_cache_spec(struct cdi_cache_spec *s)
{
    if (s == NULL) {
        return;
    }
 
    free_cdi_spec(s->raw_spec);
    s->raw_spec = NULL;
    free(s->vendor);
    s->vendor = NULL;
    free(s->class);
    s->class = NULL;
    free(s->path);
    s->path = NULL;
    map_free(s->devices);
    s->devices = NULL;
 
    free(s);
}

struct cdi_cache_spec *cdi_spec_read_spec(const char *path, int priority)
{
    cdi_spec *raw_spec = NULL;
    __isula_auto_free parser_error err = NULL;
    char cleanpath[PATH_MAX] = { 0 };

    if (util_clean_path(path, cleanpath, sizeof(cleanpath)) == NULL) {
        ERROR("Failed to get clean path %s", path);
        return NULL;
    }
    
    raw_spec = cdi_spec_parse_file(cleanpath, NULL, &err);
    if (raw_spec == NULL) {
        ERROR("Failed to read CDI Spec %s: %s", cleanpath, err);
        return NULL;
    }
    DEBUG("Read cdi spec %s", cleanpath);

    return cdi_spec_new_spec(raw_spec, cleanpath, priority);
}

struct cdi_cache_spec *cdi_spec_new_spec(cdi_spec *raw, const char *path, int priority)
{
    struct cdi_cache_spec *spec = NULL;
    __isula_auto_free char *checked_path = NULL;

    if (raw == NULL) {
        ERROR("Invalid param");
        return NULL;
    }

    if (!util_has_suffix(path, ".json")) {
        checked_path = util_string_append(path, CDI_DEFAULT_SPEC_EXT);
        if (checked_path == NULL) {
            ERROR("Failed to append %s to path %s", CDI_DEFAULT_SPEC_EXT, path);
            return NULL;
        }
    } else {
        checked_path = util_strdup_s(path);
    }
    spec = util_common_calloc_s(sizeof(*spec));
    if (spec == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    spec->raw_spec = raw;
    spec->path = checked_path;
    checked_path = NULL;
    spec->priority = priority;

    if (cdi_parser_parse_qualifier(raw->kind, &spec->vendor, &spec->class) != 0) {
        ERROR("Failed to parse kind %s", raw->kind);
        goto error_out;
    }
    if (cdi_spec_init(spec) != 0) {
        ERROR("Invalid CDI Spec");
        goto error_out;
    }
    
    return spec;

error_out:
    free_cdi_cache_spec(spec);
    return NULL;
}

const char *cdi_spec_get_vendor(const struct cdi_cache_spec *s)
{
    if (s == NULL) {
        ERROR("Invalid params");
        return NULL;
    }
    return s->vendor;
}

const char *cdi_spec_get_class(const struct cdi_cache_spec *s)
{
    if (s == NULL) {
        ERROR("Invalid params");
        return NULL;
    }
    return s->class;
}

struct cdi_cache_device *cdi_spec_get_cache_device(const struct cdi_cache_spec *s, const char *name)
{
    if (s == NULL) {
        ERROR("Invalid params");
        return NULL;
    }
    return map_search(s->devices, (void *)name);;
}

const char *cdi_spec_get_path(const struct cdi_cache_spec *s)
{
    if (s == NULL) {
        ERROR("Invalid params");
        return NULL;
    }
    return s->path;
}

int cdi_spec_get_priority(const struct cdi_cache_spec *s)
{
    if (s == NULL) {
        ERROR("Invalid params");
        return -1;
    }
    return s->priority;
}

cdi_container_edits *cdi_spec_get_edits(const struct cdi_cache_spec *s)
{
    if (s == NULL || s->raw_spec == NULL) {
        ERROR("Invalid params");
        return NULL;
    }
    return s->raw_spec->container_edits;
}

static void map_cdi_cache_device_kvfree(void *key, void *value)
{
    free(key);
    free_cdi_cache_device((struct cdi_cache_device *)value);
}

static int cdi_spec_init(struct cdi_cache_spec *s)
{
    const char *min_version = NULL;
    __isula_auto_free char *spec_version = NULL;
    cdi_container_edits *edits = NULL;
    struct cdi_cache_device *dev = NULL;
    cdi_device *d = NULL;
    size_t i;
    bool version_result = true;
    
    if (!cdi_is_valid_version(s->raw_spec->cdi_version)) {
        ERROR("Failed to validate cdi spec version: %s", s->raw_spec->cdi_version);
        return -1;
    }

    min_version = cdi_minimum_required_version(s->raw_spec);
    if (min_version == NULL) {
        ERROR("Could not determine minimum required version");
        return -1;
    }
    if (util_version_greater_than(min_version, s->raw_spec->cdi_version, &version_result) != 0) {
        ERROR("Failed to compare version %s and %s", min_version, s->raw_spec->cdi_version);
        return -1;
    }
    if (version_result) {
        ERROR("The %s spec version must be at least v%s", s->path, min_version);
        return -1;
    }

    if (cdi_parser_validate_vendor_name(s->vendor) != 0) {
        return -1;
    }
    if (cdi_parser_validate_class_name(s->class) != 0) {
        return -1;
    }

    // ignore validate annotations

    edits = cdi_spec_get_edits(s);
    if (cdi_container_edits_validate(edits) != 0) {
        return -1;
    }

    s->devices = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, map_cdi_cache_device_kvfree);
    if (s->devices == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < s->raw_spec->devices_len; i++) {
        d = s->raw_spec->devices[i];
        dev = cdi_device_new_device(s, d);
        if (dev == NULL) {
            ERROR("Could not determine minimum required version");
            goto error_out;
        }
        if (map_search(s->devices, (void *)d->name) != NULL) {
            ERROR("Invalid spec, multiple device %s", d->name);
            goto error_out;
        }
        if (!map_insert(s->devices, (void *)d->name, dev)) {
            ERROR("Failed to insert device %s", d->name);
            goto error_out;
        }
    }

    return 0;

error_out:
    map_free(s->devices);
    s->devices = NULL;
    return -1;
}
