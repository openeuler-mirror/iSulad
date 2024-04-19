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
 * Description: provide cdi spec function definition
 ******************************************************************************/
#ifndef CDI_SPEC_H
#define CDI_SPEC_H

#include <isula_libutils/cdi_spec.h>
#include <isula_libutils/oci_runtime_spec.h>

#include "map.h"
#include "cdi_container_edits.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cdi_cache_device;

struct cdi_cache_spec {
    cdi_spec *raw_spec;
    char *vendor;
    char *class;
    char *path;
    int priority;
    map_t *devices;  // MAP_STR_PTR  devices[cdi_device.name] = cdi_cache_device*
};

#define CDI_DEFAULT_SPEC_EXT ".json"
 
void free_cdi_cache_spec(struct cdi_cache_spec *s);

struct cdi_cache_spec *cdi_spec_read_spec(const char *path, int priority);
struct cdi_cache_spec *cdi_spec_new_spec(cdi_spec *raw, const char *path, int priority);
const char *cdi_spec_get_vendor(const struct cdi_cache_spec *s);
const char *cdi_spec_get_class(const struct cdi_cache_spec *s);
struct cdi_cache_device *cdi_spec_get_cache_device(const struct cdi_cache_spec *s, const char *name);
const char *cdi_spec_get_path(const struct cdi_cache_spec *s);
int cdi_spec_get_priority(const struct cdi_cache_spec *s);
cdi_container_edits *cdi_spec_get_edits(const struct cdi_cache_spec *s);

#ifdef __cplusplus
}
#endif

#endif