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
#include "image.h"
#include "storage_image.h"
#include "constants.h"
#include "util_atomic.h"
#include "utils.h"
#include "log.h"

static image_t *create_empty_image()
{
    image_t *result = NULL;
    int nret = 0;

    result = (image_t *)util_smart_calloc_s(sizeof(image_t), 1);
    if (result == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    atomic_int_set(&result->refcnt, 1);

    nret = pthread_mutex_init(&(result->mutex), NULL);
    if (nret != 0) {
        ERROR("Failed to init mutex of image");
        goto err_out;
    }
    result->init_mutex = true;

    return result;
err_out:
    free_image_t(result);
    return NULL;
}

image_t *new_image(storage_image *simg)
{
    image_t *img = NULL;

    if (simg == NULL) {
        ERROR("Empty storage image");
        return NULL;
    }

    img = create_empty_image();
    if (img == NULL) {
        return NULL;
    }

    img->simage = simg;

    return img;

}

void image_ref_inc(image_t *img)
{
    if (img == NULL) {
        return;
    }
    atomic_int_inc(&img->refcnt);
}

void image_ref_dec(image_t *img)
{
    bool is_zero = false;

    if (img == NULL) {
        return;
    }

    is_zero = atomic_int_dec_test(&img->refcnt);
    if (!is_zero) {
        return;
    }

    free_image_t(img);
}

void free_image_t(image_t *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free_storage_image(ptr->simage);
    ptr->simage = NULL;
    if (ptr->init_mutex) {
        pthread_mutex_destroy(&ptr->mutex);
    }
    free(ptr);
}

