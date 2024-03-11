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

int cdi_operate_registry_init(char **specs_dirs, size_t specs_dirs_len)
{
    return 0;
}

char *cdi_operate_refresh(void)
{
    return NULL;
}

string_array *cdi_operate_inject_devices(oci_runtime_spec *spec, string_array *devices, char **error)
{
    return NULL;
}

char *cdi_operate_parse_annotations(json_map_string_string *annotations, string_array **keys, string_array **devices)
{
    return NULL;
}