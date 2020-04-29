/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wujing
 * Create: 2020-03-13
 * Description: provide images module interface definition
 ******************************************************************************/
#ifndef __OCI_STORAGE_IMAGES_H
#define __OCI_STORAGE_IMAGES_H

#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include "storage.h"
#include "types_def.h"
#include "map.h"

#ifdef __cplusplus
extern "C" {
#endif

// Load the image in the dir folder
int image_store_init(struct storage_module_init_options *opts);

// Create an image that has a specified ID (or a random one) and optional names, using the specified layer as
// its topmost (hopefully read-only) layer.  That layer can be referenced by multiple images.
storage_image *image_store_create(const char *id, const char **names, size_t names_len,
                                  const char *layer, const char *metadata,
                                  const types_timestamp_t *time, const char *searchable_digest);

// Attempt to translate a name to an ID.  Most methods do this implicitly.
char *image_store_lookup(const char *id);

// Remove the record of the image.
int image_store_delete(const char *id);

// Remove records of all images
int image_store_wipe();

// Stores a (potentially large) piece of data associated with this ID.
int image_store_set_big_data(const char *id, const char *key, const char *data);

// Add the name for an image. Duplicate names are removed from the list automatically.
int image_store_add_name(const char *id, const char *name);

// Replace the list of names associated with an image with the supplied values.
int image_store_set_names(const char *id, const char **names, size_t names_len);

// Updates the metadata associated with the item with the specified ID.
int image_store_set_metadata(const char *id, const char *metadata);

// Set the image pulled time
int image_store_set_load_time(const char *id,  const types_timestamp_t *time);

// Saves the contents of the store to disk.
int image_store_save(storage_image *image);

// Check if there is an image with the given ID or name.
bool image_store_exists(const char *id);

// Retrieve information about an image given an ID or name.
const storage_image *image_store_get_image(const char *id);

// Retrieves a (potentially large) piece of data associated with this ID, if it has previously been set.
char *image_store_big_data(const char *id, const char *key);

// Retrieves the size of a (potentially large) piece of data associated with this ID, if it has previously been set.
int64_t image_store_big_data_size(const char *id, const char *key);

// Retrieves the digest of a (potentially large) piece of data associated with this ID, if it has previously been set.
char *image_store_big_data_digest(const char *id, const char *key);

// Returns a list of the names of previously-stored pieces of data.
int image_store_big_data_names(const char *id, char ***names, size_t *names_len);

// Reads metadata associated with an item with the specified ID.
char *image_store_metadata(const char *id);

// Return a slice enumerating the known images.
int image_store_get_all_images(storage_image ***images, size_t *len);

// Return a slice enumerating the images which have a big data
// item with the name ImageDigestBigDataKey and the specified digest.
int image_store_get_images_by_digest(const char *digest, storage_image ***images, size_t *len);

int image_store_get_fs_info(imagetool_fs_info *fs_info);

#ifdef __cplusplus
}
#endif

#endif /* __OCI_STORAGE_IMAGES_H */

