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
 * Description: provide cdi device manager function
 ******************************************************************************/
#include "cdi_operate_api.h"

#include <isula_libutils/log.h>

#include "utils.h"
#include "error.h"
#include "cdi_registry.h"
#include "cdi_annotations.h"
#include "cdi_spec_dirs.h"

int cdi_operate_registry_init(char **specs_dirs, size_t specs_dirs_len)
{
    string_array spec_dirs_array = {
        .items = specs_dirs,
        .len = specs_dirs_len,
        .cap = specs_dirs_len,
    };
    
    return cdi_registry_init(&spec_dirs_array);
}

int cdi_operate_refresh(void)
{
    struct cdi_registry *registry = cdi_get_registry();
    if (registry == NULL || registry->ops == NULL || registry->ops->refresh == NULL) {
        ERROR("Failed to get registry");
        return -1;
    }
    
    return registry->ops->refresh(registry->cdi_cache);
}

int cdi_operate_inject_devices(oci_runtime_spec *spec, string_array *devices)
{
    struct cdi_registry *registry = NULL;

    if (spec == NULL || devices == NULL) {
        ERROR("Invalid params");
        return -1;
    }
    
    registry = cdi_get_registry();
    if (registry == NULL || registry->ops == NULL || registry->ops->inject_devices == NULL) {
        ERROR("Failed to get registry");
        return -1;
    }
    
    return registry->ops->inject_devices(registry->cdi_cache, spec, devices);
}

int cdi_operate_parse_annotations(json_map_string_string *annotations, string_array **keys,
                                  string_array **devices, char **error)
{
    if (error == NULL) {
        ERROR("Invalid argument");
        return -1;
    }
    if (annotations == NULL || keys == NULL || devices == NULL) {
        ERROR("Invalid params");
        *error = util_strdup_s("Invalid params");
        return -1;
    }

    return cdi_parse_annotations(annotations, keys, devices, error);
}
