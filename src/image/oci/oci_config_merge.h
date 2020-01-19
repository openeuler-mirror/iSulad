/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide oci config merge functions
 ******************************************************************************/

#ifndef __OCI_IMAGE_MERGE_CONFIG_H_
#define __OCI_IMAGE_MERGE_CONFIG_H_

#include "imagetool_image.h"
#include "oci_runtime_spec.h"
#include "container_config.h"

#ifdef __cplusplus
extern "C" {
#endif

int oci_image_merge_config(imagetool_image *image_conf, container_config *container_spec);

#ifdef __cplusplus
}
#endif

#endif

