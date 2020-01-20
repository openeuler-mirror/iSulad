/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2019-04-02
 * Description: provide graphdriver function definition
 ******************************************************************************/
#ifndef __GRAPHDRIVER_H
#define __GRAPHDRIVER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct graphdriver;

struct graphdriver_ops {
    int (*init)(struct graphdriver *driver);

    int (*parse_options)(struct graphdriver *driver, const char **options, size_t len);

    bool (*is_quota_options)(struct graphdriver *driver, const char *option);
};

struct graphdriver {
    const struct graphdriver_ops *ops;
    const char *name;
    char *backing_fs;
};

struct graphdriver_status {
    char *backing_fs;
    char *status;
};

struct graphdriver *graphdriver_init(const char *name, char **storage_opts, size_t storage_opts_len);

struct graphdriver *graphdriver_get(const char *name);

struct graphdriver_status *graphdriver_get_status(void);

int update_graphdriver_status(struct graphdriver **driver);

void graphdriver_umount_mntpoint(void);

void free_graphdriver_status(struct graphdriver_status *status);

#ifdef __cplusplus
}
#endif

#endif

