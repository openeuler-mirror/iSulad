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
* Author: wangfengtu
* Create: 2020-01-19
* Description: provide devicemapper graphdriver function definition
******************************************************************************/
#include "driver_devmapper.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <libdevmapper.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>

#include "log.h"
#include "libisulad.h"
#include "utils.h"
#include "wrapper_devmapper.h"
#include "devices_constants.h"
#include "device_setup.h"
#include "deviceset.h"
#include "json_common.h"

int devmapper_init(struct graphdriver *driver, const char *drvier_home, const char **options, size_t len)
{
    return device_init(driver, drvier_home, options, len);
}

int do_create(const char *id, const char *parent, const struct driver_create_opts *create_opts)
{
    return add_device(id, parent, create_opts->storage_opt);
}

int devmapper_create_rw(const char *id, const char *parent, const struct graphdriver *driver,
                        const struct driver_create_opts *create_opts)
{
    if (id == NULL || parent == NULL || driver == NULL || create_opts == NULL) {
        return -1;
    }

    return do_create(id, parent, create_opts);
}

int devmapper_create_ro(const char *id, const char *parent, const struct graphdriver *driver,
                        const struct driver_create_opts *create_opts)
{
    return 0;
}

int devmapper_rm_layer(const char *id, const struct graphdriver *driver)
{
    return 0;
}

char *devmapper_mount_layer(const char *id, const struct graphdriver *driver,
                            const struct driver_mount_opts *mount_opts)
{
    return NULL;
}

int devmapper_umount_layer(const char *id, const struct graphdriver *driver)
{
    return 0;
}

bool devmapper_layer_exists(const char *id, const struct graphdriver *driver)
{
    return true;
}

int devmapper_apply_diff(const char *id, const struct graphdriver *driver, const struct io_read_wrapper *content,
                         int64_t *layer_size)
{
    return 0;
}

int devmapper_get_layer_metadata(const char *id, const struct graphdriver *driver, json_map_string_string *map_info)
{
    return 0;
}

int devmapper_get_driver_status(const struct graphdriver *driver, struct graphdriver_status *status)
{
    return 0;
}
