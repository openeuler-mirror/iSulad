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
 * Description: provide image list function definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_EMBEDDED_LIM_H
#define DAEMON_MODULES_IMAGE_EMBEDDED_LIM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define IMAGE_DATA_TYPE_CONFIG "config"
#define IMAGE_DATA_TYPE_CONFIG_PATH "config_path"

struct image_creator {
    char *name;
    char *type;
    char *media_type;
    char *config_digest;
    int64_t size;
};

struct image_info {
    char *image_name;           /* image name */
    char *image_type;           /* image type. docker or embedded */
    int64_t size;               /* image sieze */
    char *chain_id;             /* chain id of image's top layer */
    char *config_digest;        /* sha256 digest of image's config */
};

int lim_init(const char *rootpath);

int lim_create_image_start(char *name, char *type, struct image_creator **pic);

int lim_add_manifest(struct image_creator *ic, char *path, char *digest, bool mv);

int lim_create_image_end(struct image_creator *ic);

int lim_delete_image(char *name, bool force);

int lim_query_images(void *images_info);

int lim_query_image_data(const char *name, const char *type,
                         char **data, char **image_type);

int lim_create_rw_layer(char *name, const char *id, char **options,
                        char **mount_string);

#endif

