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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

#include "oci_image_unix.h"
#include "log.h"
#include "utils.h"


oci_image_t *oci_image_new(imagetool_image *image_info)
{
    oci_image_t *image = NULL;

    if (image_info == NULL) {
        return NULL;
    }

    image = util_common_calloc_s(sizeof(oci_image_t));
    if (image == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    atomic_int_set_image(&image->refcnt, 1);

    image->info = image_info;

    return image;
}

/* oci_image free */
void oci_image_free(oci_image_t *image)
{
    if (image == NULL) {
        return;
    }
    if (image->info != NULL) {
        free_imagetool_image(image->info);
        image->info = NULL;
    }

    free(image);
}

/* oci_image refinc */
void oci_image_refinc(oci_image_t *image)
{
    if (image == NULL) {
        return;
    }
    atomic_int_inc_image(&image->refcnt);
}

/* oci_image unref */
void oci_image_unref(oci_image_t *image)
{
    bool is_zero = false;
    if (image == NULL) {
        return;
    }

    is_zero = atomic_int_dec_test_image(&image->refcnt);
    if (!is_zero) {
        return;
    }

    oci_image_free(image);
}

/* oci_image lock */
void oci_image_lock(oci_image_t *image)
{
    if (image == NULL) {
        return;
    }

    if (pthread_mutex_lock(&image->mutex) != 0) {
        ERROR("Failed to lock image '%s'", image->info->id);
    }
}

/* oci_image unlock */
void oci_image_unlock(oci_image_t *image)
{
    if (image == NULL) {
        return;
    }

    if (pthread_mutex_unlock(&image->mutex) != 0) {
        ERROR("Failed to unlock image '%s'", image->info->id);
    }
}

