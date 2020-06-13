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
* Author: gaohuatao
* Create: 2020-01-19
* Description: provide devicemapper graphdriver function definition
******************************************************************************/
#ifndef __GRAPHDRIVER_DEVMAPPER_H
#define __GRAPHDRIVER_DEVMAPPER_H

#include <pthread.h>
#include "driver.h"
#include "map.h"
#include "isula_libutils/image_devmapper_transaction.h"
#include "isula_libutils/image_devmapper_deviceset_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STRING,
    UINT64_T,
} data_type;

int devmapper_init(struct graphdriver *driver, const char *drvier_home, const char **options, size_t len);

int devmapper_create_rw(const char *id, const char *parent, const struct graphdriver *driver,
                        struct driver_create_opts *create_opts);

int devmapper_create_ro(const char *id, const char *parent, const struct graphdriver *driver,
                        const struct driver_create_opts *create_opts);

int devmapper_rm_layer(const char *id, const struct graphdriver *driver);

char *devmapper_mount_layer(const char *id, const struct graphdriver *driver,
                            const struct driver_mount_opts *mount_opts);

int devmapper_umount_layer(const char *id, const struct graphdriver *driver);

bool devmapper_layer_exists(const char *id, const struct graphdriver *driver);

int devmapper_apply_diff(const char *id, const struct graphdriver *driver, const struct io_read_wrapper *content,
                         int64_t *layer_size);

int devmapper_get_layer_metadata(const char *id, const struct graphdriver *driver, json_map_string_string *map_info);

int devmapper_get_driver_status(const struct graphdriver *driver, struct graphdriver_status *status);

int devmapper_clean_up(const struct graphdriver *driver);

#ifdef __cplusplus
}
#endif

#endif
