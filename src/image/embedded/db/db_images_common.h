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
 * Description: provide common functions for images
 ******************************************************************************/
#ifndef __DB_IMAGES_COMMON_H_
#define __DB_IMAGES_COMMON_H_

#include <stdint.h>

/* common interface definition for database */

struct db_single_image_info {
    char *imageref;
    char *type;
    char *digest;
    int64_t size; /* Bytes */
    char *chain_id;
};

struct db_all_images_info {
    int imagesnum;
    struct db_single_image_info **images_info;
};

#endif

