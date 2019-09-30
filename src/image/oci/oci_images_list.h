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
 * Description: provide oci images list functions
 ******************************************************************************/

#ifndef __OCI_LIST_ALL_IMAGES_INFO_H_
#define __OCI_LIST_ALL_IMAGES_INFO_H_

#include "oci_image_type.h"
#include "imagetool_images_list.h"
#include "image.h"

#ifdef __cplusplus
extern "C" {
#endif

int do_list_oci_images(im_list_request *request, imagetool_images_list **images);

#ifdef __cplusplus
}
#endif

#endif

