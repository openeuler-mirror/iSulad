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
 * Description: provide container embedded definition
 ******************************************************************************/

#ifndef _SN_EMBEDDED_H
#define _SN_EMBEDDED_H

#include "linked_list.h"
#include "snapshot_def.h"

struct snapshot_plugin ebd_plugin();

int ebd_create_layer(char *id, char *parent, uint32_t layer_attribute,
                     char **options, char **mount_string);

int ebd_delete_layer(char *id);

int ebd_apply_diff(char *id, char *parent, char *archive, char *metadata);

int ebd_generate_mount_string(struct db_image *imginfo,
                              struct db_sninfo **sninfos, char **mount_string);

#endif

