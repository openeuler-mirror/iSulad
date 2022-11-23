/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
* Author: zhongtao
* Create: 2022-10-17
* Description: isula image search operator implement
*******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_OCI_SEARCH_H
#define DAEMON_MODULES_IMAGE_OCI_OCI_SEARCH_H

#include "image_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int oci_do_search_image(const im_search_request *request, imagetool_search_result **result);

#ifdef __cplusplus
}
#endif
#endif
