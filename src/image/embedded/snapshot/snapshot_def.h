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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container snapshot  definition
 ******************************************************************************/
#ifndef __SNAPSHOT_DEF_H
#define __SNAPSHOT_DEF_H

#include "db_all.h"

#define DRIVER_TYPE_EMBEDDED            0
#define DRIVER_TYPE_NUM                 1
#define DRIVER_TYPE_INVALID             1024

#define LAYER_ATTRIBUTE_RO 1
#define LAYER_ATTRIBUTE_RW 2

#define LAYER_NUM_MAX 125

typedef int(*create_layer_cb)(char *id, char *parent, uint32_t layer_attribute,
                              char **options, char **mount_string);

typedef int(*delete_layer_cb)(char *id);

typedef int(*apply_diff_cb)(char *id, char *parent, char *archive,
                            char *metadata);

typedef int(*generate_mount_string_cb)(struct db_image *imginfo,
                                       struct db_sninfo **sninfos, char **mount_string);

struct snapshot_plugin {
    create_layer_cb cl;
    delete_layer_cb dl;
    apply_diff_cb ad;
    generate_mount_string_cb gms;
};


#endif

