/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: WuJing
 * Create: 2020-04-26
 * Description: provide image function definition
 ******************************************************************************/
#ifndef __OCI_STORAGE_IMAGE_H
#define __OCI_STORAGE_IMAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include "storage_image.h"
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _image_t_ {
    storage_image *simage;
    uint64_t refcnt;
} image_t;

image_t *new_image(storage_image *simg);
void image_ref_inc(image_t *img);
void image_ref_dec(image_t *img);
void free_image_t(image_t *ptr);

#ifdef __cplusplus
}
#endif

#endif // __OCI_STORAGE_IMAGE_H
