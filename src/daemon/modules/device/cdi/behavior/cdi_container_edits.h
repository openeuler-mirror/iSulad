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
 * Description: provide cdi container edits function definition
 ******************************************************************************/
#ifndef CDI_CONTAINER_EDITS_H
#define CDI_CONTAINER_EDITS_H

#include <isula_libutils/cdi_container_edits.h>
#include <isula_libutils/cdi_device_node.h>
#include <isula_libutils/oci_runtime_spec.h>
#include <isula_libutils/cdi_hook.h>
#include <isula_libutils/cdi_mount.h>

#include "utils_array.h"

#ifdef __cplusplus
extern "C" {
#endif

int cdi_container_edits_apply(cdi_container_edits *e, oci_runtime_spec *spec);
int cdi_container_edits_validate(cdi_container_edits *e);
int cdi_container_edits_append(cdi_container_edits *e, cdi_container_edits *o);
bool cdi_container_edits_is_empty(cdi_container_edits *e);

#ifdef __cplusplus
}
#endif

#endif