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
* Create: 2020-09-07
* Description: provide isula volume definition
*******************************************************************************/
#ifndef DAEMON_MODULES_API_VOLUME_API_H
#define DAEMON_MODULES_API_VOLUME_API_H

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#define VOLUME_DEFAULT_DRIVER_NAME "local"
#define VOLUME_DEFAULT_NAME_LEN 64
#define VOLUME_ERR_NOT_EXIST -2

typedef struct {
    struct volume * (*create)(char *name);

    struct volume * (*get)(char *name);

    int (*mount)(char *name);

    int (*umount)(char *name);

    struct volumes * (*list)(void);

    int (*remove)(char *name);
} volume_driver;

struct volume {
    char *driver;
    char *name;
    char *path;
    // volume mount point, valid only when mounted
    char *mount_point;
};

struct volumes {
    struct volume **vols;
    size_t vols_len;
};

struct volume_names {
    char **names;
    size_t names_len;
};

struct volume_options {
    char *ref;
};

int volume_init(char *root_dir);

int register_driver(char *name, volume_driver *driver);

struct volume * volume_create(char *driver_name, char *name, struct volume_options *opts);

int volume_mount(char *name);

int volume_umount(char *name);

struct volumes * volume_list(void);

int volume_add_ref(char *name, char *ref);

int volume_del_ref(char *name, char *ref);

int volume_remove(char *name);

int volume_prune(struct volume_names **pruned);

void free_volume_names(struct volume_names *pruned);

void free_volume(struct volume *vol);

void free_volumes(struct volumes *vols);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_API_VOLUME_API_H
