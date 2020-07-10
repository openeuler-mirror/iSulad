/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide container image rest definition
 ********************************************************************************/
#ifndef API_SERVICES_IMAGES_REST_IMAGE_REST_H
#define API_SERVICES_IMAGES_REST_IMAGE_REST_H

#include "isula_libutils/image_load_image_request.h"
#include "isula_libutils/image_load_image_response.h"
#include "isula_libutils/image_list_images_request.h"
#include "isula_libutils/image_list_images_response.h"
#include "isula_libutils/image_delete_image_request.h"
#include "isula_libutils/image_delete_image_response.h"
#include "isula_libutils/image_inspect_request.h"
#include "isula_libutils/image_inspect_response.h"

#ifndef RestHttpHead
#define RestHttpHead "http://localhost"
#endif

#define ImagesServiceLoad "/ImagesService/Load"
#define ImagesServiceList "/ImagesService/List"
#define ImagesServiceDelete "/ImagesService/Delete"
#define ImagesServiceInspect "/ImagesService/Inspect"

#endif

