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
 * Author: liuhao
 * Create: 2020-03-24
 * Description: provide layer store function definition
 ******************************************************************************/
#ifndef __OCI_STORAGE_LAYER_STORE_H
#define __OCI_STORAGE_LAYER_STORE_H

#include <stdint.h>
#include <isula_libutils/imagetool_fs_info.h>
#include <isula_libutils/json_common.h>
#include <stdbool.h>
#include <stddef.h>

#include "storage.h"
#include "io_wrapper.h"

struct io_read_wrapper;
struct layer_list;
struct storage_module_init_options;

#ifdef __cplusplus
extern "C" {
#endif

struct layer_store_mount_opts {
    char *mount_label;
    json_map_string_string *mount_opts;
};

struct layer_opts {
    char *parent;
    char **names;
    size_t names_len;
    bool writable;

    char *uncompressed_digest;
    char *compressed_digest;

    // mount options
    struct layer_store_mount_opts *opts;
};

int layer_store_init(const struct storage_module_init_options *conf);
void layer_store_exit();

bool layer_store_check(const char *id);
int layer_store_create(const char *id, const struct layer_opts *opts, const struct io_read_wrapper *content,
                       char **new_id);
int layer_store_delete(const char *id);
bool layer_store_exists(const char *id);
int layer_store_list(struct layer_list *resp);
int layer_store_by_compress_digest(const char *digest, struct layer_list *resp);
int layer_store_by_uncompress_digest(const char *digest, struct layer_list *resp);
struct layer *layer_store_lookup(const char *name);
char *layer_store_mount(const char *id, const struct layer_store_mount_opts *opts);
int layer_store_umount(const char *id, bool force);
int layer_store_mounted(const char *id);
int layer_store_try_repair_lowers(const char *id);

void free_layer_store_mount_opts(struct layer_store_mount_opts *ptr);
void free_layer_opts(struct layer_opts *opts);

int layer_store_get_layer_fs_info(const char *layer_id, imagetool_fs_info *fs_info);

#ifdef __cplusplus
}
#endif

#endif
