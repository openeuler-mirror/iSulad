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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide oci config merge functions
 ******************************************************************************/

#ifndef DAEMON_MODULES_IMAGE_OCI_OCI_CONFIG_MERGE_H
#define DAEMON_MODULES_IMAGE_OCI_OCI_CONFIG_MERGE_H

#include "isula_libutils/imagetool_image.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/container_config.h"

#ifdef __cplusplus
extern "C" {
#endif

int oci_image_merge_config(imagetool_image *image_conf, container_config *container_spec);

#ifdef __cplusplus
}
#endif

#endif

