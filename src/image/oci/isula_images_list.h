/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: isula images list operator implement
*******************************************************************************/
#ifndef __OCI_REMOTE_IMAGES_LIST_H
#define __OCI_REMOTE_IMAGES_LIST_H

#include "imagetool_images_list.h"
#include "image.h"

#ifdef __cplusplus
extern "C" {
#endif

int isula_list_images(const im_list_request *request, imagetool_images_list **images);

#ifdef __cplusplus
}
#endif

#endif
