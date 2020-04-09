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
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide image function definition
 ********************************************************************************/

#ifndef __IMAGE_CB_H_
#define __IMAGE_CB_H_

#include "callback.h"

#ifdef __cplusplus
extern "C" {
#endif
int image_list_cb(const image_list_images_request *request,
                  image_list_images_response **response);

void image_callback_init(service_image_callback_t *cb);

#ifdef __cplusplus
}
#endif

#endif

