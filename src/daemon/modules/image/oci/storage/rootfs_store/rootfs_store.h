/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-05-12
 * Description: provide containers module interface definition
 ******************************************************************************/
#ifndef __OCI_STORAGE_ROOTFS_STORE_H
#define __OCI_STORAGE_ROOTFS_STORE_H

#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <isula_libutils/storage_rootfs.h>
#include <stdint.h>

#include "storage.h"
#include "rootfs.h"

struct rootfs_list;
struct storage_module_init_options;
struct storage_rootfs_options;

#ifdef __cplusplus
extern "C" {
#endif

// Load the containers in the folder(${driver}-containers)
int rootfs_store_init(struct storage_module_init_options *opts);

// Creates a container that has a specified ID (or generates a random one if an empty value is supplied)
// and optional names, based on the specified image, using the specified layer as its read-write layer.
// return a new id, or NULL if failed.
char *rootfs_store_create(const char *id, const char **names, size_t names_len, const char *image, const char *layer,
                          const char *metadata, struct storage_rootfs_options *rootfs_opts);

// Attempt to translate a name to an ID.  Most methods do this implicitly.
char *rootfs_store_lookup(const char *id);

// Remove the record of the container.
int rootfs_store_delete(const char *id);

// Remove records of all containers
int rootfs_store_wipe();

// Stores a (potentially large) piece of data associated with this ID.
int rootfs_store_set_big_data(const char *id, const char *key, const char *data);

// Updates the metadata associated with the item with the specified ID.
int rootfs_store_set_metadata(const char *id, const char *metadata);

// Saves the contents of the store to disk.
int rootfs_store_save(cntrootfs_t *c);

// Check if there is a container with the given ID or name.
bool rootfs_store_exists(const char *id);

// Retrieve information about a container given an ID or name.
storage_rootfs *rootfs_store_get_rootfs(const char *id);

// Retrieves a (potentially large) piece of data associated with this ID, if it has previously been set.
char *rootfs_store_big_data(const char *id, const char *key);

// Retrieves the size of a (potentially large) piece of data associated with this ID, if it has previously been set.
int64_t rootfs_store_big_data_size(const char *id, const char *key);

// Retrieves the digest of a (potentially large) piece of data associated with this ID, if it has previously been set.
char *rootfs_store_big_data_digest(const char *id, const char *key);

// Returns a list of the names of previously-stored pieces of data.
int rootfs_store_big_data_names(const char *id, char ***names, size_t *names_len);

// Reads metadata associated with an item with the specified ID.
char *rootfs_store_metadata(const char *id);

// Return a slice enumerating the known containers.
int rootfs_store_get_all_rootfs(struct rootfs_list *all_rootfs);

// Free memory of container store, but will not delete the persisted files
void rootfs_store_free();

#ifdef __cplusplus
}
#endif

#endif /* __OCI_STORAGE_ROOTFS_STORE_H */
