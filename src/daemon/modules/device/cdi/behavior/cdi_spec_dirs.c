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
 * Description: provide cdi spec dirs function
 ******************************************************************************/
#include "cdi_spec_dirs.h"

#include <sys/stat.h>
#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "utils.h"
#include "path.h"
#include "error.h"
#include "utils_file.h"
#include "utils_array.h"
#include "cdi_spec.h"

#define DEFAULT_SPEC_DIRS_LEN   2
static char *default_spec_dirs_items[DEFAULT_SPEC_DIRS_LEN] = {CDI_DEFAULT_STATIC_DIR, CDI_DEFAULT_DYNAMIC_DIR};
 
string_array g_default_spec_dirs = {
    .items = default_spec_dirs_items,
    .len = DEFAULT_SPEC_DIRS_LEN,
    .cap = DEFAULT_SPEC_DIRS_LEN,
};
 
struct scan_spec_dir_cb_args {
    struct cdi_scan_fn_maps *scan_fn_maps;
    cdi_scan_spec_func scan_fn;
    int priority;
};

static bool scan_spec_dir_cb(const char *dir, const struct dirent *pdirent, void *context)
{
    struct scan_spec_dir_cb_args *args = (struct scan_spec_dir_cb_args *)context;
    struct cdi_scan_fn_maps *scan_fn_maps = args->scan_fn_maps;
    cdi_scan_spec_func scan_fn = args->scan_fn;
    int priority = args->priority;
    struct stat st = { 0 };
    __isula_auto_free char *file_path = NULL;
    struct cdi_cache_spec *cache_spec = NULL;

    file_path = util_path_join(dir, pdirent->d_name);
    if (file_path == NULL) {
        ERROR("Failed to get path %s/%s", dir, pdirent->d_name);
        goto error_out;
    }

    if (lstat(file_path, &st) != 0) {
        ERROR("Failed to lstat %s", file_path);
        goto error_out;
    }
    if (S_ISDIR(st.st_mode)) {
        DEBUG("Skip dir %s", file_path);
        return true;
    }
    
    if (!util_has_suffix(file_path, ".json")) {
        DEBUG("Skip file %s", file_path);
        return true;
    }

    cache_spec = cdi_spec_read_spec(file_path, priority);
    if (cache_spec == NULL) {
        ERROR("Failed to read spec %s", file_path);
        goto error_out;
    }
    scan_fn(scan_fn_maps, file_path, priority, cache_spec);
    return true;

error_out:
    *(scan_fn_maps->refresh_error_flag) = true;
    return true;
}

int cdi_scan_spec_dirs(string_array *dirs, struct cdi_scan_fn_maps *scan_fn_maps, cdi_scan_spec_func scan_fn)
{
    size_t i;
    int nret = 0;

    for (i = 0; i < dirs->len; i++) {
        struct scan_spec_dir_cb_args args = {
            .scan_fn_maps = scan_fn_maps,
            .scan_fn = scan_fn,
            .priority = i,
        };
        if (!util_dir_exists(dirs->items[i])) {
            WARN("Cdi dir %s not exists", dirs->items[i]);
            continue;
        }
        nret = util_scan_subdirs(dirs->items[i], scan_spec_dir_cb, &args);
        if (nret != 0) {
            ERROR("Failed to scan dir %s", dirs->items[i]);
            return -1;
        }
    }

    return 0;
}
