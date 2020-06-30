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
 * Create: 2018-11-08
 * Description: provide image load functions
 ******************************************************************************/
#include <stdio.h>
#include <string.h>

#include "error.h"
#include "libisulad.h"
#include "embedded_image.h"
#include "lim.h"
#include "limits.h"
#include "isula_libutils/log.h"
#include "image_api.h"

#define RAW_DIGEST_LEN 64

/* return a new string which replace file's suffix to sgn */
static char *replace_suffix_to_sgn(const char *file)
{
    char *sgn_file = NULL;
    size_t i = 0;
    size_t len = 0;

    if (file == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }
    if (sizeof(".sgn") > SIZE_MAX - strlen(file)) {
        return NULL;
    }
    len = strlen(file) + sizeof(".sgn");
    sgn_file = util_common_calloc_s(len);
    if (sgn_file == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    /* dump chars to sgn_file */
    (void)strcat(sgn_file, file);

    /* strip file's suffix */
    for (i = strlen(sgn_file); i > 0; i--) {
        if (sgn_file[i] == '/') {
            break;
        }

        if (sgn_file[i] == '.') {
            sgn_file[i] = 0;
            break;
        }
    }

    /* add .sgn to tail as suffix */
    (void)strcat(sgn_file, ".sgn");

    return sgn_file;
}

/*
 * CloudRAN's file structure:
 * /xxx/.../container_name.manifest
 * /xxx/.../container_name.sgn
 * /xxx/.../platform.img
 * /xxx/.../app.img
 *
 * File container_name.sgn must exist.
 *
 * */
static char *get_digest(const char *file)
{
    char *sgn_file = NULL;
    char *digest = NULL;
    size_t digest_len = RAW_DIGEST_LEN + strlen(SHA256_PREFIX);
    char real_path[PATH_MAX] = { 0 };

    if (file == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    sgn_file = replace_suffix_to_sgn(file);
    if (sgn_file == NULL) {
        ERROR("replace suffix to sgn failed");
        return NULL;
    }

    if (strlen(sgn_file) > PATH_MAX || realpath(sgn_file, real_path) == NULL) {
        ERROR("get real path of %s failed", sgn_file);
        isulad_try_set_error_message("Manifest's signature file not exist");
        goto out;
    }

    if (!util_file_exists(real_path)) {
        isulad_try_set_error_message("Manifest's signature file not exist");
        goto out;
    }

    digest = util_read_text_file(real_path);
    if (digest == NULL) {
        ERROR("read digest from file %s failed", real_path);
        isulad_try_set_error_message("Invalid manifest: invalid digest");
        goto out;
    }

    if (strnlen(digest, digest_len + 1) != digest_len) {
        DEBUG("digest %s too short", digest);
        UTIL_FREE_AND_SET_NULL(digest);
        isulad_try_set_error_message("Invalid manifest: invalid digest");

        goto out;
    }

    digest[digest_len] = 0; /* strip '\n' or other chars if exists */

out:

    free(sgn_file);

    return digest;
}

/* embedded load image */
static int load_image(char *file)
{
    int ret = 0;
    struct image_creator *ic = NULL;
    char *digest = NULL;
    char real_path[PATH_MAX] = { 0 };

    if (file == NULL) {
        ERROR("invalid NULL param");
        return EINVALIDARGS;
    }

    if (strlen(file) > PATH_MAX || !realpath(file, real_path)) {
        ERROR("invalid file path %s", file);
        isulad_try_set_error_message("Invalid manifest: manifest not found");
        return EINVALIDARGS;
    }

    if (!util_file_exists(real_path)) {
        ERROR("file %s not exist", file);
        isulad_try_set_error_message("Invalid manifest: manifest not found");
        return EINVALIDARGS;
    }

    if (!util_valid_file(real_path, S_IFREG)) {
        ERROR("manifest file %s is not a regular file", real_path);
        isulad_try_set_error_message("Invalid manifest: manifest is not a regular file");
        return EINVALIDARGS;
    }

    ret = lim_create_image_start(NULL, IMAGE_TYPE_EMBEDDED, &ic);
    if (ret != 0) {
        goto out;
    }

    /* Manifest must have it's corresponding sigature file,
     * get digest from the sigature file */
    digest = get_digest(real_path);
    if (digest == NULL) {
        ret = EINVALIDARGS;
        goto out;
    }

    ret = lim_add_manifest(ic, real_path, digest, false);
    if (ret != 0) {
        goto out;
    }

out:
    free(digest);
    lim_create_image_end(ic);

    return ret;
}

int embedded_load_image(const im_load_request *request)
{
    if (request == NULL) {
        ERROR("invalid NULL param");
        return EINVALIDARGS;
    }

    return load_image(request->file);
}

