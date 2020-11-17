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
 * Author: maoweiyong
 * Create: 2018-11-07
 * Description: provide image function definition
 ******************************************************************************/
#ifndef __DB_ALL_H_
#define __DB_ALL_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "db_common.h"

struct db_sninfo {
    char *snid;
    char *parent_snid;
    int64_t size;
    uint32_t layer_attribute;
    /* If layer is RW layer, this represent the image create this layer */
    char *image_name;
    char *diffid;
    uint32_t driver_type;
    char *cacheid;
    char *config_digest;
    char *path_in_host;
    char *path_in_container;
};

struct db_image {
    char *image_name;
    char *image_type;
    int64_t size;
    size_t layer_num;
    char *top_chainid;
    char *top_cacheid;
    char *config_digest;
    char *config_cacheid;
    char *config_path;
    char *created;
    char *mount_string;
    char *config;
};

struct db_all_images {
    size_t imagesnum;
    struct db_image **images_info;
};

int db_all_init();

int db_add_name(char *image_name, char *digest, char *path);

int db_save_image(struct db_image *image);

int db_read_image(const char *name, struct db_image **image);

int db_delete_image(char *name, bool force);

void db_image_free(struct db_image **image);

int db_delete_dangling_images();

int db_read_all_images_info(struct db_all_images **image_info);

void db_all_imginfo_free(struct db_all_images *images_info);

#endif

