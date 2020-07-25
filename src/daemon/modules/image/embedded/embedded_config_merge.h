/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2018-11-07
 * Description: provide embedded image merge config definition
 ******************************************************************************/
#ifndef __EMBEDDED_IMAGE_MERGE_CONFIG_H_
#define __EMBEDDED_IMAGE_MERGE_CONFIG_H_

#include "isula_libutils/oci_image_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

int embedded_image_merge_config(const char *image_config, container_config *container_spec);

#ifdef __cplusplus
}
#endif

#endif

