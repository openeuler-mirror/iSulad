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
 * Description: provide cdi device manager function definition
 ******************************************************************************/
#ifndef CDI_OPERATE_API_H
#define CDI_OPERATE_API_H

#include <isula_libutils/oci_runtime_spec.h>
#include <isula_libutils/json_common.h>

#include "utils_array.h"

#ifdef __cplusplus
extern "C" {
#endif

int cdi_operate_registry_init(char **specs_dirs, size_t specs_dirs_len);

int cdi_operate_refresh(void);

int cdi_operate_inject_devices(oci_runtime_spec *spec, string_array *devices);

int cdi_operate_parse_annotations(json_map_string_string *annotations, string_array **keys,
                                  string_array **devices, char **error);

#ifdef __cplusplus
}
#endif

#endif
