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
 * Description: provide cdi cache function definition
 ******************************************************************************/
#ifndef CDI_CACHE_H
#define CDI_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <isula_libutils/oci_runtime_spec.h>

#include "utils_array.h"
#include "map.h"
#include "cdi_device.h"
#include "cdi_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cdi_cache;

struct cdi_cache_ops {
    // injecting CDI devices into an OCI Spec.
    // Resolver
    string_array *(*inject_devices)(struct cdi_cache *c, oci_runtime_spec *spec, string_array *devices, char **error);
    
    // refreshing the cache of CDI Specs and devices.
    // Refresher
    char *(*configure)(struct cdi_cache *c, string_array *spec_dirs);
    char *(*refresh)(struct cdi_cache *c);
    map_t *(*get_errors)(struct cdi_cache *c);
    string_array *(*get_spec_directories)(struct cdi_cache *c);
    map_t *(*get_spec_dir_errors)(struct cdi_cache *c);
};

struct cdi_watch {
    int watcher_fd; // inotify fd
    map_t *tracked; // MAP_STR_BOOL     tracked[spec_dirs[i]] = bool
    map_t *wd_dirs; // MAP_INT_STR      wd_dirs[wd] = spec_dirs[i]
};

// Cache stores CDI Specs loaded from Spec directories.
struct cdi_cache {
    pthread_mutex_t mutex;
    string_array *spec_dirs; // cdi-spec-dirs will scan for CDI Spec files
    map_t *specs;        // MAP_STR_PTR     specs[vendor] = cdi_cache_spec**
    map_t *devices;      // MAP_STR_PTR     devices[cdi_device.name] = cdi_cache_device*
    map_t *errors;       // MAP_STR_PTR     errors[cdi_cache_spec.path] = string_array *errors
    map_t *dir_errors;   // MAP_STR_STR     dir_errors[spec_dirs[i]] = error

    bool auto_refresh; 
    struct cdi_watch *watch;
};

void free_cdi_cache(struct cdi_cache *c);
 
struct cdi_cache *cdi_new_cache(string_array *spec_dirs, char **error);
struct cdi_cache_ops *cdi_get_cache_ops(void);

#ifdef __cplusplus
}
#endif

#endif