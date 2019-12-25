/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide container image rest definition
 ********************************************************************************/
#ifndef IMAGE_REST_H_
#define IMAGE_REST_H_

#include "image_load_image_request.h"
#include "image_load_image_response.h"
#include "image_list_images_request.h"
#include "image_list_images_response.h"
#include "image_delete_image_request.h"
#include "image_delete_image_response.h"
#include "image_inspect_request.h"
#include "image_inspect_response.h"

#ifndef RestHttpHead
#define RestHttpHead "http://localhost"
#endif

#define ImagesServiceLoad "/ImagesService/Load"
#define ImagesServiceList "/ImagesService/List"
#define ImagesServiceDelete "/ImagesService/Delete"
#define ImagesServiceInspect "/ImagesService/Inspect"

#endif

