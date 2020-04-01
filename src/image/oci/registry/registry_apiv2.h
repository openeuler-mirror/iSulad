/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2020-03-05
 * Description: provide registry api v2 definition
 ******************************************************************************/
#ifndef __IMAGE_REGISTRY_APIV2_H
#define __IMAGE_REGISTRY_APIV2_H

#include "registry_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int fetch_manifest(pull_descriptor *desc);

int fetch_config(pull_descriptor *desc);

int fetch_layer(pull_descriptor *desc, size_t index);

#ifdef __cplusplus
}
#endif

#endif

