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
 * Description: provide cdi annotations function definition
 ******************************************************************************/
#ifndef CDI_ANNOTATIONS_H
#define CDI_ANNOTATIONS_H

#include <isula_libutils/json_common.h>

#include "utils_array.h"

#ifdef __cplusplus
extern "C" {
#endif

int cdi_parse_annotations(json_map_string_string *annotations, string_array **keys,
                          string_array **devices, char **error);

#ifdef __cplusplus
}
#endif

#endif