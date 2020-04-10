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
* Description: isula image status operator implement
*******************************************************************************/
#ifndef __OCI_REMOTE_ISULA_IMAGE_STATUS_H
#define __OCI_REMOTE_ISULA_IMAGE_STATUS_H

#include "imagetool_image.h"

#ifdef __cplusplus
extern "C" {
#endif

imagetool_image *isula_image_get_image_info_by_name(const char *image_name);

#ifdef __cplusplus
}
#endif

#endif
