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
 * Description: provide cdi version function definition
 ******************************************************************************/
#ifndef CDI_VERSION_H
#define CDI_VERSION_H

#include <isula_libutils/cdi_spec.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CDI_CURRENT_VERSION "0.6.0"

const char *cdi_minimum_required_version(cdi_spec *spec);
bool cdi_is_valid_version(const char *spec_version);

#ifdef __cplusplus
}
#endif

#endif