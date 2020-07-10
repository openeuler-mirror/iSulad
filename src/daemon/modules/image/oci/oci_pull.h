/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: isula image pull operator implement
*******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_OCI_PULL_H
#define DAEMON_MODULES_IMAGE_OCI_OCI_PULL_H

#include "image_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int oci_do_pull_image(const im_pull_request *request, im_pull_response *response);

#ifdef __cplusplus
}
#endif
#endif
