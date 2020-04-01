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
#include "storage_image.h"
#include "timestamp.h"
#include "map.h"

#ifdef __cplusplus
extern "C" {
#endif

// the name of the big data item whose contents we consider useful for computing a "digest" of the
// image, by which we can locate the image later.
#define IMAGE_DIGEST_BIG_DATA_KEY "manifest"
#define IMAGE_NAME_LEN            64


typedef struct file_locker {
    // key: string  value: struct flock
    map_t *lock_files;
    pthread_mutex_t lock_files_lock;
} file_locker_t;

typedef struct digest_image {
    storage_image **images;
    size_t images_len;
} digest_image_t;

typedef struct image_store {
    file_locker_t lockfile;
    file_locker_t rolockfile;
    char *dir;
    storage_image **images;
    size_t images_len;
    map_t *idindex;
    map_t *byid;
    map_t *byname;
    map_t *bydigest;

    // flag for daemon
    bool daemon;
    bool loaded;
} image_store_t, *image_store_ptr;

// // ROImageStore interface: Provides bookkeeping for information about Images.
// typedef struct ro_image_store_ops {
// // TODO: ROFileBasedStore
// // TODO: ROMetadataStore
// // TODO: ROBigDataStore
//
// // Check if there is an image with the given ID or name.
// bool (*exists)(const char *id);
//
// // Retrieve information about an image given an ID or name.
// int (*get)(const char *id, storage_image *image);
//
// // Attempt to translate a name to an ID.  Most methods do this implicitly.
// int (*lookup)(const char *name, char **id);
//
// // Return a slice enumerating the known images.
// int (*images)(storage_image **images, size_t *len);
//
// // Return a slice enumerating the images which have a big data
// // item with the name ImageDigestBigDataKey and the specified digest.
// int (*by_digest)(storage_image **images, size_t *len);
// } ro_image_store_ops_t;
//
// // ImageStore interface: Provides bookkeeping for information about Images.
// typedef struct image_store_opt {
// // ROImageStore
// // RWFileBasedStore
// // RWMetadataStore
// // RWBigDataStore
// // FlaggableStore
//
// // Create an image that has a specified ID (or a random one) and
// // optional names, using the specified layer as its topmost (hopefully
// // read-only) layer.  That layer can be referenced by multiple images.
// int (*create)(const char *id, const char **names, size_t names_len, const char *layer, const char *metadata,
//         timestamp time, const char *searchable_digest, storage_image *image);
//
// // Replace the list of names associated with an image with the supplied values.
// int (*set_names)(const char *id, const char **names, size_t names_len);
//
// // Remove the record of the image.
// int (*delete)(const char *id);
//
// // Remove records of all images
// int (*wipe)();
//
// // Set the image pulled time
// int (*set_loaded_time)(const char *id, timestamp loaded);
//
// // Add the name for an image. Duplicate names are removed from the list automatically.
// int (*add_name)(const char *id, const char *name);
// } image_store_ops_t;
//
int new_image_store(bool daemon, bool readonly, const char *dir, image_store_t **image_store);
void free_image_store(image_store_t *image_store);
#ifdef __cplusplus
}
#endif

#endif /* __OCI_STORAGE_IMAGES_H */

