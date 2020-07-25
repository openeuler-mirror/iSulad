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
 * Description: provide container snapshot functions
 *******************************************************************************/
#include "snapshot.h"

#include "embedded.h"
#include "utils.h"
#include "isula_libutils/log.h"

struct snapshot_drivers {
    struct snapshot_plugin plugins[DRIVER_TYPE_NUM];
};

static struct snapshot_drivers  *g_sd = NULL;

/* snapshot_ nit */
int snapshot_init(uint32_t driver_type)
{
    g_sd = (struct snapshot_drivers *) util_common_calloc_s(sizeof(struct snapshot_drivers));
    if (g_sd == NULL) {
        ERROR("out of memory");
        return -1;
    }

    g_sd->plugins[DRIVER_TYPE_EMBEDDED] = ebd_plugin();

    return 0;
}

/* check driver type valid */
int check_driver_type_valid(uint32_t driver_type)
{
    int ret = 0;

    if (driver_type >= DRIVER_TYPE_NUM) {
        ret = -1;
        goto out;
    }

    if (driver_type != DRIVER_TYPE_EMBEDDED) {
        ERROR("only support driver type embedded, got %d", driver_type);
        ret = -1;
        goto out;
    }

out:
    if (ret) {
        ERROR("invalid driver type %d", driver_type);
    }

    return ret;
}

/* snapshot generate mount string */
int snapshot_generate_mount_string(uint32_t driver_type,
                                   struct db_image *imginfo,
                                   struct db_sninfo **sninfos, char **mount_string)
{
    if (check_driver_type_valid(driver_type)) {
        return -1;
    }

    return g_sd->plugins[driver_type].gms(imginfo, sninfos, mount_string);
}

