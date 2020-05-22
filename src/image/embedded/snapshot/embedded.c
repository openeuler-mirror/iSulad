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
 * Description: provide container embedded functions
 ******************************************************************************/


#include "utils.h"
#include "linked_list.h"
#include "isula_libutils/log.h"
#include "snapshot_def.h"
#include "embedded.h"

struct snapshot_plugin ebd_plugin()
{
    struct snapshot_plugin sp = {
        .cl = ebd_create_layer,
        .dl = ebd_delete_layer,
        .ad = ebd_apply_diff,
        .gms = ebd_generate_mount_string
    };

    return sp;
}

int ebd_create_layer(char *id, char *parent, uint32_t layer_attribute,
                     char **options, char **mount_string)
{
    /* nothing to do */
    return 0;
}

int ebd_delete_layer(char *id)
{
    /* nothing to do */
    return 0;
}

int ebd_apply_diff(char *id, char *parent, char *archive, char *metadata)
{
    /* nothing to do */
    return 0;
}

int ebd_generate_mount_string(struct db_image *imginfo,
                              struct db_sninfo **sninfos, char **mount_string)
{
    if (imginfo == NULL || mount_string == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    if (imginfo->mount_string == NULL) {
        ERROR("invalid NULL mount string");
        return -1;
    }

    *mount_string = util_strdup_s(imginfo->mount_string);

    return 0;
}

