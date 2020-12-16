/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: WuJing
 * Create: 2020-04-26
 * Description: provide image function definition
 ******************************************************************************/
#define _GNU_SOURCE
#include "image_type.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "isula_libutils/storage_image.h"
#include "util_atomic.h"
#include "utils.h"
#include "isula_libutils/log.h"

#include "utils_images.h"

static image_t *create_empty_image()
{
    image_t *result = NULL;

    result = (image_t *)util_smart_calloc_s(sizeof(image_t), 1);
    if (result == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    atomic_int_set(&result->refcnt, 1);

    return result;

err_out:
    free_image_t(result);
    return NULL;
}

int try_fill_image_spec(image_t *img, const char *id, const char *image_store_dir)
{
    int ret = 0;
    int nret = 0;
    char *base_name = NULL;
    char *config_file = NULL;
    char *sha256_key = NULL;
    parser_error err = NULL;

    if (img == NULL || id == NULL || image_store_dir == NULL) {
        return -1;
    }

    sha256_key = util_full_digest(id);
    if (sha256_key == NULL) {
        ERROR("Failed to get sha256 key");
        return -1;
    }

    base_name = make_big_data_base_name(sha256_key);
    if (base_name == NULL) {
        ERROR("Failed to retrieve oci image spec file's base name");
        ret = -1;
        goto out;
    }

    nret = asprintf(&config_file, "%s/%s/%s", image_store_dir, id, base_name);
    if (nret < 0 || nret > PATH_MAX) {
        ERROR("Failed to retrieve oci image spac file");
        ret = -1;
        goto out;
    }

    img->spec = oci_image_spec_parse_file(config_file, NULL, &err);
    if (img->spec == NULL) {
        ERROR("Failed to parse oci image spec: %s", err);
        ret = -1;
        goto out;
    }

out:
    free(base_name);
    free(config_file);
    free(sha256_key);
    free(err);

    return ret;
}

image_t *new_image(storage_image *simg, const char *image_store_dir)
{
    image_t *img = NULL;

    if (simg == NULL || image_store_dir == NULL) {
        ERROR("Empty storage image");
        return NULL;
    }

    img = create_empty_image();
    if (img == NULL) {
        return NULL;
    }

    // try to load the oci image config, it may fail when load/pull/restore v1 image
    (void)try_fill_image_spec(img, simg->id, image_store_dir);

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
    free_oci_image_spec(ptr->spec);
    ptr->spec = NULL;

    free(ptr);
}
