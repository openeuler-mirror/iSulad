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
 * Description: provide container unix functions
 ******************************************************************************/
#ifndef __ISULAD_IMAGE_UNIX_H__
#define __ISULAD_IMAGE_UNIX_H__

#include <pthread.h>

#include "libisulad.h"
#include "util_atomic.h"
#include "imagetool_image_status.h"


#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

typedef struct _oci_image_t_ {
    pthread_mutex_t mutex;
    uint64_t refcnt;
    imagetool_image *info;
} oci_image_t;

void oci_image_refinc(oci_image_t *image);

void oci_image_unref(oci_image_t *image);

oci_image_t *oci_image_new(imagetool_image *image_info);

void oci_image_free(oci_image_t *image);

void oci_image_lock(oci_image_t *image);

void oci_image_unlock(oci_image_t *image);


#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __ISULAD_IMAGE_UNIX_H__ */

