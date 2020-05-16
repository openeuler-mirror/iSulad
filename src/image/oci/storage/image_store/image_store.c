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
 * Create: 2020-03-13
 * Description: provide image store functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "image_store.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <libgen.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <libwebsockets.h>
#include <sha256.h>
#include "utils.h"
#include "log.h"
#include "constants.h"
#include "read_file.h"
#include "image.h"
#include "imagetool_image.h"
#include "docker_image_config_v2.h"
#include "utils_array.h"
#include "utils_string.h"
#include "utils_regex.h"
#include "oci_image_spec.h"
#include "defs.h"
#include "map.h"
#include "utils_convert.h"
#include "oci_image_spec.h"

// the name of the big data item whose contents we consider useful for computing a "digest" of the
// image, by which we can locate the image later.
#define IMAGE_DIGEST_BIG_DATA_KEY "manifest"
#define IMAGE_NAME_LEN 64
#define IMAGE_JSON "images.json"

#define MAX_IMAGE_NAME_LENGTH 72
#define DIGIST_PREFIX "@sha256:"
#define MAX_IMAGE_DIGST_LENGTH 64

typedef struct digest_image {
    struct linked_list images_list;
    size_t images_list_len;
} digest_image_t;

typedef struct image_store {
    pthread_rwlock_t rwlock;
    char *dir;
    struct linked_list images_list;
    size_t images_list_len;
    map_t *byid;
    map_t *byname;
    map_t *bydigest;

    bool loaded;
} image_store_t;

enum lock_type {
    SHARED = 0,
    EXCLUSIVE
};

image_store_t *g_image_store = NULL;

static inline bool image_store_lock(enum lock_type type)
{
    int nret = 0;

    if (type == SHARED) {
        nret = pthread_rwlock_rdlock(&g_image_store->rwlock);
    } else {
        nret = pthread_rwlock_wrlock(&g_image_store->rwlock);
    }
    if (nret != 0) {
        ERROR("Lock memory store failed: %s", strerror(nret));
        return false;
    }

    return true;
}

static inline void image_store_unlock()
{
    int nret = 0;

    nret = pthread_rwlock_unlock(&g_image_store->rwlock);
    if (nret != 0) {
        FATAL("Unlock memory store failed: %s", strerror(nret));
    }
}

static void free_image_store(image_store_t *store)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (store == NULL) {
        return;
    }

    free(store->dir);
    store->dir = NULL;

    (void)map_free(store->byid);
    store->byid = NULL;

    (void)map_free(store->byname);
    store->byname = NULL;

    (void)map_free(store->bydigest);
    store->bydigest = NULL;

    linked_list_for_each_safe(item, &(store->images_list), next) {
        linked_list_del(item);
        image_ref_dec((image_t *)item->elem);
        free(item);
        item = NULL;
    }

    store->images_list_len = 0;

    free(store);
}

void image_store_free()
{
    free_image_store(g_image_store);
    g_image_store = NULL;
}

static void image_store_field_kvfree(void *key, void *value)
{
    (void)value;
    free(key);
}

static void image_store_digest_field_kvfree(void *key, void *value)
{
    digest_image_t *val = (digest_image_t *)value;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    free(key);
    if (val != NULL) {
        linked_list_for_each_safe(item, &(val->images_list), next) {
            linked_list_del(item);
            free(item);
            item = NULL;
        }

        free(val);
    }
}

static int get_image_path(const char *id, char *path, size_t len)
{
    int nret = snprintf(path, len, "%s/%s/%s", g_image_store->dir, id, IMAGE_JSON);

    return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
}

static int do_append_image(storage_image *im)
{
    image_t *img = NULL;
    struct linked_list *item = NULL;

    img = new_image(im);
    if (img == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    item = util_smart_calloc_s(sizeof(struct linked_list), 1);
    if (item == NULL) {
        ERROR("Out of memory");
        free_image_t(img);
        return -1;
    }

    linked_list_add_elem(item, img);
    linked_list_add_tail(&g_image_store->images_list, item);
    g_image_store->images_list_len++;

    return 0;
}

static int append_image_by_directory(const char *image_dir)
{
    int ret = 0;
    int nret;
    char image_path[PATH_MAX] = { 0x00 };
    storage_image *im = NULL;
    parser_error err = NULL;

    nret = snprintf(image_path, sizeof(image_path), "%s/%s", image_dir, IMAGE_JSON);
    if (nret < 0 || (size_t)nret >= sizeof(image_path)) {
        ERROR("Failed to get image path");
        return -1;
    }

    im = storage_image_parse_file(image_path, NULL, &err);
    if (im == NULL) {
        ERROR("Failed to parse images path: %s", err);
        return -1;
    }

    if (do_append_image(im) != 0) {
        ERROR("Failed to append images");
        ret = -1;
        goto out;
    }

    im = NULL;

out:
    free_storage_image(im);
    free(err);
    return ret;
}

static int get_images_from_json()
{
    int ret = 0;
    int nret;
    char **image_dirs = NULL;
    size_t image_dirs_num = 0;
    size_t i;
    char *id_patten = "^[a-f0-9]{64}$";
    char image_path[PATH_MAX] = { 0x00 };

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to load images from json files");
        return -1;
    }

    ret = util_list_all_subdir(g_image_store->dir, &image_dirs);
    if (ret != 0) {
        ERROR("Failed to get images directory");
        goto out;
    }
    image_dirs_num = util_array_len((const char **)image_dirs);

    for (i = 0; i < image_dirs_num; i++) {
        if (util_reg_match(id_patten, image_dirs[i]) != 0) {
            DEBUG("Image's json is placed inside image's data directory, so skip any other file or directory: %s",
                  image_dirs[i]);
            continue;
        }

        DEBUG("Restore the images:%s", image_dirs[i]);
        nret = snprintf(image_path, sizeof(image_path), "%s/%s", g_image_store->dir, image_dirs[i]);
        if (nret < 0 || (size_t)nret >= sizeof(image_path)) {
            ERROR("Failed to get image path");
            ret = -1;
            goto out;
        }

        if (append_image_by_directory(image_path) != 0) {
            ERROR("Found image path but load json failed: %s", image_dirs[i]);
            ret = -1;
            goto out;
        }
    }

out:
    util_free_array(image_dirs);
    image_store_unlock();
    return ret;
}

static int remove_name(image_t *img, const char *name)
{
    size_t i;
    size_t new_size;
    size_t count = 0;
    size_t index = 0;
    char **tmp_names = NULL;

    if (img == NULL || name == NULL) {
        return 0;
    }

    for (i = 0; i < img->simage->names_len; i++) {
        if (strcmp(img->simage->names[i], name) == 0) {
            count++;
        }
    }

    new_size = (img->simage->names_len - count) * sizeof(char *);
    tmp_names = (char **)util_common_calloc_s(new_size);
    if (tmp_names == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < img->simage->names_len; i++) {
        if (strcmp(img->simage->names[i], name) != 0) {
            tmp_names[index++] = util_strdup_s(img->simage->names[i]);
        }
        free(img->simage->names[i]);
        img->simage->names[i] = NULL;
    }

    free(img->simage->names);
    img->simage->names = tmp_names;
    img->simage->names_len = index;
    tmp_names = NULL;

    return 0;
}

static int save_image(image_t *img)
{
    int ret = 0;
    char image_path[PATH_MAX] = { 0x00 };
    char image_dir[PATH_MAX] = { 0x00 };
    parser_error err = NULL;
    char *json_data = NULL;

    if (get_image_path(img->simage->id, image_path, sizeof(image_path)) != 0) {
        ERROR("Failed to get image path by id: %s", img->simage->id);
        return -1;
    }

    strcpy(image_dir, image_path);
    ret = util_mkdir_p(dirname(image_dir), IMAGE_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Failed to create image directory %s.", image_path);
        return -1;
    }

    json_data = storage_image_generate_json(img->simage, NULL, &err);
    if (json_data == NULL) {
        ERROR("Failed to generate image json path string:%s", err ? err : " ");
        ret = -1;
        goto out;
    }

    if (util_atomic_write_file(image_path, json_data, strlen(json_data), SECURE_CONFIG_FILE_MODE) != 0) {
        ERROR("Failed to save image json file");
        ret = -1;
        goto out;
    }

out:
    free(json_data);
    free(err);

    return ret;
}

int image_store_save(image_t *img)
{
    int ret = 0;

    if (img == NULL) {
        ERROR("Invalid parameter, image is NULL");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to save image");
        return -1;
    }

    ret = save_image(img);

    image_store_unlock();

    return ret;
}

static bool get_index_by_key(const char **items, size_t len, const char *target, size_t *index)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (strcmp(target, items[i]) == 0) {
            *index = i;
            return true;
        }
    }

    return false;
}

static digest_image_t *create_empty_digest_images()
{
    digest_image_t *digest_images = NULL;

    digest_images = (digest_image_t *)util_common_calloc_s(sizeof(digest_image_t));
    if (digest_images == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    digest_images->images_list_len = 0;
    linked_list_init(&digest_images->images_list);

    return digest_images;
}

static void free_digest_image(digest_image_t *ptr)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (ptr == NULL) {
        return;
    }

    linked_list_for_each_safe(item, &(ptr->images_list), next) {
        linked_list_del(item);
        free(item);
        item = NULL;
    }

    ptr->images_list_len = 0;
    free(ptr);
}

static int append_image_to_digest_images(digest_image_t *digest_images, image_t *img)
{
    struct linked_list *item = NULL;

    if (digest_images == NULL) {
        ERROR("Empty digest images");
        return -1;
    }

    if (img == NULL) {
        return 0;
    }

    item = util_smart_calloc_s(sizeof(struct linked_list), 1);
    if (item == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    linked_list_add_elem(item, img);
    linked_list_add_tail(&digest_images->images_list, item);
    digest_images->images_list_len++;

    return 0;
}

static int append_image_according_to_digest(map_t *digest, const char *searchable_digest, image_t *img)
{
    int ret = 0;
    digest_image_t *digest_images = NULL;

    if (searchable_digest == NULL) {
        return 0;
    }

    digest_images = (digest_image_t *)map_search(digest, (void *)searchable_digest);
    if (digest_images != NULL) {
        if (append_image_to_digest_images(digest_images, img) != 0) {
            ERROR("Failed to append image to digest images");
            return -1;
        }
    } else {
        digest_images = create_empty_digest_images();
        if (digest_images == NULL) {
            ERROR("Failed to create empty digest images");
            ret = -1;
            goto out;
        }

        if (append_image_to_digest_images(digest_images, img) != 0) {
            ERROR("Failed to append image to digest images");
            ret = -1;
            goto out;
        }

        if (!map_insert(digest, (void *)searchable_digest, digest_images)) {
            ERROR("Failed to append image to digest index");
            ret = -1;
            goto out;
        }
    }
    digest_images = NULL;

out:
    free_digest_image(digest_images);
    return ret;
}

static int implicit_digest(map_t *digests, image_t *img)
{
    size_t index = 0;

    if (img->simage->big_data_digests == NULL) {
        return 0;
    }

    if (get_index_by_key((const char **)img->simage->big_data_digests->keys, img->simage->big_data_digests->len,
                         IMAGE_DIGEST_BIG_DATA_KEY, &index)) {
        return 0;
    }

    if (append_image_according_to_digest(digests, img->simage->big_data_digests->values[index], img) != 0) {
        ERROR("Failed to appaned image to image store digest index");
        return -1;
    }

    return 0;
}

static int explicit_digest(map_t *digests, image_t *img)
{
    size_t index = 0;
    char *value = NULL;

    if (img->simage->big_data_digests == NULL) {
        return 0;
    }

    if (get_index_by_key((const char **)img->simage->big_data_digests->keys, img->simage->big_data_digests->len,
                         IMAGE_DIGEST_BIG_DATA_KEY, &index)) {
        value = img->simage->big_data_digests->values[index];
    }

    if (img->simage->digest == NULL) {
        img->simage->digest = (value != NULL ? util_strdup_s(value) : NULL);
    } else if (value == NULL || (value != NULL && strcmp(img->simage->digest, value) != 0)) {
        if (append_image_according_to_digest(digests, img->simage->digest, img) != 0) {
            ERROR("Failed to appaned image to image store digest index");
            return -1;
        }
    }

    return 0;
}

static int load_image_to_store_field(image_t *img)
{
    int ret = 0;
    bool should_save = false;
    size_t i;

    if (!map_replace(g_image_store->byid, (void *)img->simage->id, (void *)img)) {
        ERROR("Failed to insert image to ids");
        return -1;
    }

    for (i = 0; i < img->simage->names_len; i++) {
        image_t *conflict_image = (image_t *)map_search(g_image_store->byname, (void *)img->simage->names[i]);
        if (conflict_image != NULL) {
            if (remove_name(conflict_image, img->simage->names[i]) != 0) {
                ERROR("Failed to remove name from conflict image");
                ret = -1;
                goto out;
            }
            should_save = true;
        }
        if (!map_replace(g_image_store->byname, (void *)img->simage->names[i], (void *)img)) {
            ERROR("Failed to insert image to names");
            ret = -1;
            goto out;
        }
    }

    if (should_save && save_image(img) != 0) {
        ERROR("Failed to save image");
        ret = -1;
        goto out;
    }

    if (implicit_digest(g_image_store->bydigest, img) != 0) {
        ERROR("Implicit digest failed");
        ret = -1;
        goto out;
    }

    if (explicit_digest(g_image_store->bydigest, img) != 0) {
        ERROR("Explicit digest failed");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int image_store_load()
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (g_image_store->loaded) {
        DEBUG("Do not need reload if daemon");
        return 0;
    }

    if (get_images_from_json() != 0) {
        ERROR("Failed to get images from json");
        return -1;
    }

    linked_list_for_each_safe(item, &(g_image_store->images_list), next) {
        if (load_image_to_store_field((image_t *)item->elem) != 0) {
            ERROR("Failed to load image to image store");
            return -1;
        }
    }

    g_image_store->loaded = true;

    return 0;
}

static char *get_image_store_root_path(const struct storage_module_init_options *opts)
{
    int nret = 0;
    char *root_dir = NULL;

    if (opts == NULL) {
        return NULL;
    }

    if (opts->storage_root == NULL || opts->driver_name == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }

    nret = asprintf(&root_dir, "%s/%s-images", opts->storage_root, opts->driver_name);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create root path failed");
        free(root_dir);
        root_dir = NULL;
    }

    return root_dir;
}

int image_store_init(struct storage_module_init_options *opts)
{
    int ret = 0;
    char *root_dir = NULL;

    if (g_image_store != NULL) {
        ERROR("Image store has already been initialized");
        return -1;
    }

    root_dir = get_image_store_root_path(opts);
    if (root_dir == NULL) {
        return ret;
    }

    ret = util_mkdir_p(root_dir, IMAGE_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Unable to create image store directory %s.", root_dir);
        ret = -1;
        goto out;
    }

    g_image_store = (image_store_t *)util_common_calloc_s(sizeof(image_store_t));
    if (g_image_store == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = pthread_rwlock_init(&(g_image_store->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init image store rwlock");
        ret = -1;
        goto out;
    }

    g_image_store->dir = root_dir;
    root_dir = NULL;

    g_image_store->images_list_len = 0;
    linked_list_init(&g_image_store->images_list);

    g_image_store->byid = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_field_kvfree);
    if (g_image_store->byid == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    g_image_store->byname = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_field_kvfree);
    if (g_image_store->byname == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    g_image_store->bydigest = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_digest_field_kvfree);
    if (g_image_store->bydigest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = image_store_load();
    if (ret != 0) {
        ERROR("Failed to load image store");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free_image_store(g_image_store);
        g_image_store = NULL;
    }
    free(root_dir);
    return ret;
}

static int image_store_append_image(const char *id, const char *searchable_digest, image_t *img)
{
    int ret = 0;
    size_t i = 0;
    struct linked_list *item = NULL;

    item = util_smart_calloc_s(sizeof(struct linked_list), 1);
    if (item == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    linked_list_add_elem(item, img);
    linked_list_add_tail(&g_image_store->images_list, item);
    g_image_store->images_list_len++;

    if (!map_insert(g_image_store->byid, (void *)id, (void *)img)) {
        ERROR("Failed to insert image to image store");
        ret = -1;
        goto out;
    }

    if (append_image_according_to_digest(g_image_store->bydigest, searchable_digest, img) != 0) {
        ERROR("Failed to insert image to image store digest index");
        ret = -1;
        goto out;
    }

    for (i = 0; i < img->simage->names_len; i++) {
        if (!map_insert(g_image_store->byname, (void *)img->simage->names[i], (void *)img)) {
            ERROR("Failed to insert image to image store's byname");
            ret = -1;
            goto out;
        }
    }

out:
    if (ret != 0) {
        linked_list_del(item);
        free(item);
    }
    return ret;
}

static char *generate_random_image_id()
{
    char *id = NULL;
    const size_t max_image_id_len = 64;
    const size_t max_retry_cnt = 5;
    size_t i = 0;

    id = util_smart_calloc_s(sizeof(char), max_image_id_len + 1);
    if (id == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (; i < max_retry_cnt; i++) {
        if (util_generate_random_str(id, max_image_id_len) != 0) {
            ERROR("Generate random str failed");
            goto err_out;
        }
        image_t *image = map_search(g_image_store->byid, (void *)id);
        if (image == NULL) {
            break;
        }
    }
    if (i >= max_retry_cnt) {
        ERROR("Retry generate id too much");
        goto err_out;
    }

    return id;

err_out:
    free(id);
    return NULL;
}

static storage_image *new_storage_image(const char *id, const char *searchable_digest, char ***unique_names,
                                        size_t *unique_names_len, const types_timestamp_t *time, const char *layer,
                                        const char *metadata)
{
    int ret = 0;
    char timebuffer[TIME_STR_SIZE] = { 0x00 };
    storage_image *im = NULL;

    im = (storage_image *)util_common_calloc_s(sizeof(storage_image));
    if (im == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    im->id = util_strdup_s(id);
    im->digest = util_strdup_s(searchable_digest);

    im->names = *unique_names;
    im->names_len = *unique_names_len;
    *unique_names = NULL;
    *unique_names_len = 0;

    im->layer = util_strdup_s(layer);
    im->metadata = util_strdup_s(metadata);

    (void)get_now_time_buffer(timebuffer, sizeof(timebuffer));
    im->loaded = util_strdup_s(timebuffer);
    if (time != NULL && (time->has_seconds || time->has_nanos) &&
        !get_time_buffer(time, timebuffer, sizeof(timebuffer))) {
        ERROR("Failed to get time buffer");
        ret = -1;
        goto out;
    }
    im->created = util_strdup_s(timebuffer);

out:
    if (ret != 0) {
        free_storage_image(im);
        im = NULL;
    }
    return im;
}

char *image_store_create(const char *id, const char **names, size_t names_len, const char *layer, const char *metadata,
                         const types_timestamp_t *time, const char *searchable_digest)
{
    int ret = 0;
    char *dst_id = NULL;
    char **unique_names = NULL;
    size_t unique_names_len = 0;
    image_t *img = NULL;
    storage_image *im = NULL;

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return NULL;
    }

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to create new images");
        return NULL;
    }

    if (id == NULL) {
        dst_id = generate_random_image_id();
    } else {
        dst_id = util_strdup_s(id);
    }

    if (map_search(g_image_store->byid, (void *)dst_id) != NULL) {
        ERROR("ID is already in use: %s", dst_id);
        ret = -1;
        goto out;
    }

    if (util_string_array_unique(names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    im = new_storage_image(dst_id, searchable_digest, &unique_names, &unique_names_len, time, layer, metadata);
    if (im == NULL) {
        ERROR("Failed to generate new storage image");
        ret = -1;
        goto out;
    }

    img = new_image(im);
    if (img == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (image_store_append_image(dst_id, searchable_digest, img) != 0) {
        ERROR("Failed to append image to image store");
        ret = -1;
        goto out;
    }

    if (save_image(img) != 0) {
        ERROR("Failed to save image");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free(dst_id);
        dst_id = NULL;
        free_storage_image(im);
        im = NULL;
        free_image_t(img);
        img = NULL;
    }
    util_free_array_by_len(unique_names, unique_names_len);
    image_store_unlock();
    return dst_id;
}

static image_t *get_image_for_store_by_prefix(const char *id)
{
    bool ret = true;
    image_t *value = NULL;
    map_itor *itor = NULL;
    const char *key = NULL;

    itor = map_itor_new(g_image_store->byid);
    if (itor == NULL) {
        ERROR("Failed to get byid's iterator from image store");
        return NULL;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        key = map_itor_key(itor);
        if (key == NULL) {
            ERROR("Out of memory");
            ret = false;
            goto out;
        }
        if (strncmp(key, id, strlen(id)) == 0) {
            if (value != NULL) {
                ERROR("Multiple IDs found with provided prefix: %s", id);
                ret = false;
                goto out;
            } else {
                value = map_itor_value(itor);
            }
        }
    }

out:
    map_itor_free(itor);
    if (!ret) {
        value = NULL;
    }

    return value;
}

static image_t *lookup(const char *id)
{
    image_t *value = NULL;

    if (id == NULL) {
        ERROR("Invalid input parameter, id is NULL");
        return NULL;
    }

    value = map_search(g_image_store->byid, (void *)id);
    if (value != NULL) {
        goto found;
    }

    value = map_search(g_image_store->byname, (void *)id);
    if (value != NULL) {
        goto found;
    }

    value = get_image_for_store_by_prefix(id);
    if (value != NULL) {
        goto found;
    }

    return NULL;

found:
    image_ref_inc(value);
    return value;
}

char *image_store_lookup(const char *id)
{
    char *image_id = NULL;
    image_t *img = NULL;

    if (id == NULL) {
        ERROR("Invalid input parameter, id is NULL");
        return NULL;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return NULL;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image id assignments");
        return NULL;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        goto out;
    }

    image_id = util_strdup_s(img->simage->id);

out:
    image_ref_dec(img);
    image_store_unlock();
    return image_id;
}

static char *get_value_from_json_map_string_string(json_map_string_string *map, const char *key)
{
    size_t i;

    if (map == NULL) {
        return NULL;
    }

    for (i = 0; i < map->len; i++) {
        if (strcmp(key, map->keys[i]) == 0) {
            return util_strdup_s(map->values[i]);
        }
    }

    return NULL;
}

static void digest_image_slice_without_value(digest_image_t *digest_filter_images, image_t *img)
{
    image_t *tmp = NULL;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (digest_filter_images == NULL || img == NULL) {
        return;
    }

    linked_list_for_each_safe(item, &(digest_filter_images->images_list), next) {
        tmp = (image_t *)item->elem;
        if (strcmp(tmp->simage->id, img->simage->id) == 0) {
            linked_list_del(item);
            free(item);
            item = NULL;
            digest_filter_images->images_list_len--;
        }
    }
}

static int get_data_dir(const char *id, char *path, size_t len)
{
    int nret = snprintf(path, len, "%s/%s", g_image_store->dir, id);
    return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
}

static int remove_image_from_digest_index(image_t *image, const char *digest)
{
    digest_image_t *digest_filter_images = NULL;

    digest_filter_images = (digest_image_t *)map_search(g_image_store->bydigest, (void *)digest);
    if (digest_filter_images == NULL) {
        return 0;
    }

    digest_image_slice_without_value(digest_filter_images, image);

    if (digest_filter_images->images_list_len == 0) {
        if (!map_remove(g_image_store->bydigest, (void *)digest)) {
            ERROR("Failed to delete image for bydigest map in store");
            return -1;
        }
    }

    return 0;
}

static int remove_image_from_memory(const char *id)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    image_t *img = NULL;
    size_t i = 0;
    int ret = 0;
    char *digest = NULL;

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        ret = -1;
        goto out;
    }

    if (!map_remove(g_image_store->byid, (void *)id)) {
        ERROR("Failed to remove image from ids map in image store");
        ret = -1;
        goto out;
    }

    for (i = 0; i < img->simage->names_len; i++) {
        if (!map_remove(g_image_store->byname, (void *)img->simage->names[i])) {
            ERROR("Failed to remove image from names index in image store");
            ret = -1;
            goto out;
        }
    }

    digest = get_value_from_json_map_string_string(img->simage->big_data_digests, IMAGE_DIGEST_BIG_DATA_KEY);
    if (digest != NULL && remove_image_from_digest_index(img, digest) != 0) {
        ERROR("Failed to remove the image from the digest-based index");
        ret = -1;
        goto out;
    }

    if (img->simage->digest != NULL && remove_image_from_digest_index(img, img->simage->digest) != 0) {
        ERROR("Failed to remove the image from the digest-based index");
        ret = -1;
        goto out;
    }

    linked_list_for_each_safe(item, &(g_image_store->images_list), next) {
        image_t *tmp = (image_t *)item->elem;
        if (strcmp(tmp->simage->id, id) != 0) {
            continue;
        }
        linked_list_del(item);
        image_ref_dec(tmp);
        free(item);
        item = NULL;
        g_image_store->images_list_len--;
        break;
    }

out:
    free(digest);
    image_ref_dec(img);
    return ret;
}

static int remove_image_dir(const char *id)
{
    char image_path[PATH_MAX] = { 0x00 };

    if (get_data_dir(id, image_path, sizeof(image_path)) != 0) {
        ERROR("Failed to get image data dir: %s", id);
        return -1;
    }

    if (util_recursive_rmdir(image_path, 0) != 0) {
        ERROR("Failed to delete image directory : %s", image_path);
        return -1;
    }

    return 0;
}

int image_store_delete(const char *id)
{
    int ret = 0;
    image_t *img = NULL;

    if (id == NULL) {
        ERROR("Invalid input parameter: empty id");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not already");
        return -1;
    }

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to delete image from store");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        ret = -1;
        goto out;
    }

    if (remove_image_from_memory(img->simage->id) != 0) {
        ERROR("Failed to remove image from memory");
        ret = -1;
        goto out;
    }

    if (remove_image_dir(img->simage->id) != 0) {
        ERROR("Failed to delete image directory");
        ret = -1;
        goto out;
    }

out:
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

static int delete_image_from_store_without_lock(const char *id)
{
    int ret = 0;
    image_t *img = NULL;

    if (id == NULL) {
        ERROR("Invalid input parameter: empty id");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not already");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        return -1;
    }

    if (remove_image_from_memory(img->simage->id) != 0) {
        ERROR("Failed to remove image from memory");
        ret = -1;
        goto out;
    }

    if (remove_image_dir(img->simage->id) != 0) {
        ERROR("Failed to delete image directory");
        ret = -1;
        goto out;
    }

out:
    image_ref_dec(img);
    return ret;
}

int image_store_wipe()
{
    int ret = 0;
    char *id = NULL;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to delete images");
        return -1;
    }

    linked_list_for_each_safe(item, &(g_image_store->images_list), next) {
        id = util_strdup_s(((image_t *)item->elem)->simage->id);
        if (delete_image_from_store_without_lock(id) != 0) {
            ERROR("Failed to delete image: %s", id);
            ret = -1;
            goto out;
        }
        free(id);
        id = NULL;
    }

out:
    free(id);
    image_store_unlock();
    return ret;
}

static bool should_use_origin_name(const char *name)
{
    size_t i;

    for (i = 0; i < strlen(name); i++) {
        char ch = name[i];
        if (ch != '.' && !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'z')) {
            return false;
        }
    }

    return true;
}

// Convert a BigData key name into an acceptable file name.
static char *make_big_data_base_name(const char *key)
{
    int ret = 0;
    int nret = 0;
    char *b64_encode_name = NULL;
    size_t b64_encode_name_len = 0;
    char *base_name = NULL;
    size_t name_size;

    if (should_use_origin_name(key)) {
        return util_strdup_s(key);
    }

    b64_encode_name_len = util_base64_encode_len(strlen(key));
    b64_encode_name = util_common_calloc_s(b64_encode_name_len + 1);
    if (b64_encode_name == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    nret = util_base64_encode((unsigned char *)key, strlen(key), b64_encode_name, b64_encode_name_len);
    if (nret < 0) {
        ret = -1;
        ERROR("Encode auth to base64 failed");
        goto out;
    }
    name_size = 1 + strlen(b64_encode_name) + 1; // '=' + encode string + '\0'

    base_name = (char *)util_common_calloc_s(name_size * sizeof(char));
    if (base_name == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    nret = snprintf(base_name, name_size, "=%s", b64_encode_name);
    if (nret < 0 || (size_t)nret >= name_size) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    DEBUG("big data file name : %s", base_name);

out:
    if (ret != 0) {
        free(base_name);
        base_name = NULL;
    }
    free(b64_encode_name);

    return base_name;
}

static int get_data_path(const char *id, const char *key, char *path, size_t len)
{
    int ret = 0;
    int nret = 0;
    char *data_base_name = NULL;
    char data_dir[PATH_MAX] = { 0x00 };

    data_base_name = make_big_data_base_name(key);
    if (data_base_name == NULL) {
        ERROR("Failed to make big data base name");
        return -1;
    }

    if (get_data_dir(id, data_dir, sizeof(data_dir)) != 0) {
        ERROR("Failed to get image data dir: %s", id);
        ret = -1;
        goto out;
    }

    nret = snprintf(path, len, "%s/%s", data_dir, data_base_name);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Failed to get big data base path");
        ret = -1;
        goto out;
    }

out:
    free(data_base_name);
    return ret;
}

static bool get_value_from_json_map_string_int64(json_map_string_int64 *map, const char *key, int64_t *value)
{
    size_t i;

    for (i = 0; i < map->len; i++) {
        if (strcmp(key, map->keys[i]) == 0) {
            *value = map->values[i];
            return true;
        }
    }

    return false;
}

static void update_json_map_string_int64(json_map_string_int64 *map, const char *key, int64_t value)
{
    size_t i;

    for (i = 0; i < map->len; i++) {
        if (strcmp(key, map->keys[i]) == 0) {
            map->values[i] = value;
            return;
        }
    }
}

static void update_json_map_string_string(json_map_string_string *map, const char *key, const char *value)
{
    size_t i;

    for (i = 0; i < map->len; i++) {
        if (strcmp(key, map->keys[i]) == 0) {
            free(map->values[i]);
            map->values[i] = (void *)util_strdup_s(value);
        }
    }
}

static int append_big_data_name(storage_image *im, const char *name)
{
    size_t new_size, old_size;
    char **tmp_names = NULL;

    if (name == NULL) {
        return 0;
    }

    old_size = im->big_data_names_len * sizeof(char *);
    new_size = old_size + sizeof(char *);

    if (mem_realloc((void **)&tmp_names, new_size, (void *)im->big_data_names, old_size) != 0) {
        ERROR("Failed to realloc memory");
        return -1;
    }

    im->big_data_names = tmp_names;
    im->big_data_names[im->big_data_names_len++] = util_strdup_s(name);

    return 0;
}

static int update_image_with_big_data(image_t *img, const char *key, const char *data, bool *should_save)
{
    int ret = 0;
    bool size_found = false;
    int64_t old_size;
    char *old_digest = NULL;
    char *new_digest = NULL;
    char *full_digest = NULL;
    bool add_name = true;
    size_t i;
    digest_image_t *digest_filter_images = NULL;

    if (img->simage->big_data_sizes == NULL) {
        img->simage->big_data_sizes = (json_map_string_int64 *)util_common_calloc_s(sizeof(json_map_string_int64));
        if (img->simage->big_data_sizes == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }

    size_found = get_value_from_json_map_string_int64(img->simage->big_data_sizes, key, &old_size);
    if (size_found) {
        update_json_map_string_int64(img->simage->big_data_sizes, key, (int64_t)strlen(data));
    } else {
        append_json_map_string_int64(img->simage->big_data_sizes, key, (int64_t)strlen(data));
    }

    if (img->simage->big_data_digests == NULL) {
        img->simage->big_data_digests = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
        if (img->simage->big_data_digests == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }

    old_digest = get_value_from_json_map_string_string(img->simage->big_data_digests, key);
    new_digest = sha256_digest_str(data);
    full_digest = util_full_digest(new_digest);
    if (old_digest != NULL) {
        update_json_map_string_string(img->simage->big_data_digests, key, full_digest);
    } else {
        append_json_map_string_string(img->simage->big_data_digests, key, full_digest);
    }

    if (!size_found || old_size != (int64_t)strlen(data) ||
        old_digest == NULL || strcmp(old_digest, full_digest) != 0) {
        *should_save = true;
    }

    for (i = 0; i < img->simage->big_data_names_len; i++) {
        if (strcmp(img->simage->big_data_names[i], key) == 0) {
            add_name = false;
            break;
        }
    }

    if (add_name) {
        if (append_big_data_name(img->simage, key) != 0) {
            ERROR("Failed to append big data name");
            ret = -1;
            goto out;
        }
        *should_save = true;
    }

    if (strcmp(key, IMAGE_DIGEST_BIG_DATA_KEY) == 0) {
        if (old_digest != NULL && strcmp(old_digest, full_digest) != 0 && strcmp(old_digest, img->simage->digest) != 0) {
            if (remove_image_from_digest_index(img, old_digest) != 0) {
                ERROR("Failed to remove the image from the list of images in the digest-based "
                      "index which corresponds to the old digest for this item, unless it's also the hard-coded digest");
                ret = -1;
                goto out;
            }
        }

        // add the image to the list of images in the digest-based index which
        // corresponds to the new digest for this item, unless it's already there
        digest_filter_images = (digest_image_t *)map_search(g_image_store->bydigest, (void *)full_digest);
        if (digest_filter_images != NULL) {
            digest_image_slice_without_value(digest_filter_images, img);
            if (append_image_to_digest_images(digest_filter_images, img) != 0) {
                ERROR("Failed to append image to digest images");
                ret = -1;
                goto out;
            }
        }
    }

out:
    free(old_digest);
    free(new_digest);
    free(full_digest);
    return ret;
}

int image_store_set_big_data(const char *id, const char *key, const char *data)
{
    int ret = 0;
    image_t *img = NULL;
    const char *image_id = NULL;
    char image_dir[PATH_MAX] = { 0x00 };
    char big_data_file[PATH_MAX] = { 0x00 };
    bool save = false;

    if (key == NULL || strlen(key) == 0) {
        ERROR("Not a valid name for a big data item, can't set empty name for image big data item");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to change image big data assignments");
        ret = -1;
        goto out;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Failed to lookup image from store");
        ret = -1;
        goto out;
    }
    image_id = img->simage->id;

    if (get_data_dir(image_id, image_dir, sizeof(image_dir)) != 0) {
        ERROR("Failed to get image data dir: %s", id);
        ret = -1;
        goto out;
    }

    ret = util_mkdir_p(image_dir, IMAGE_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Unable to create directory %s.", image_dir);
        ret = -1;
        goto out;
    }

    if (get_data_path(image_id, key, big_data_file, sizeof(big_data_file)) != 0) {
        ERROR("Failed to get big data file path: %s.", key);
        ret = -1;
        goto out;
    }

    if (util_atomic_write_file(big_data_file, data, strlen(data), SECURE_CONFIG_FILE_MODE) != 0) {
        ERROR("Failed to save big data file: %s", big_data_file);
        ret = -1;
        goto out;
    }

    if (update_image_with_big_data(img, key, data, &save) != 0) {
        ERROR("Failed to update image big data");
        ret = -1;
        goto out;
    }

    if (save && save_image(img) != 0) {
        ERROR("Failed to complete persistence to disk");
        ret = -1;
        goto out;
    }

out:
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

static int append_name(char ***names, size_t *names_len, const char *name)
{
    size_t new_size, old_size;
    char **tmp_names = NULL;

    if (name == NULL) {
        return 0;
    }

    old_size = *names_len * sizeof(char *);
    new_size = old_size + sizeof(char *);

    if (mem_realloc((void **)&tmp_names, new_size, (void *)*names, old_size) != 0) {
        ERROR("Failed to realloc memory");
        return -1;
    }

    *names = tmp_names;
    (*names)[(*names_len)] = util_strdup_s(name);
    (*names_len)++;

    return 0;
}

int image_store_add_name(const char *id, const char *name)
{
    int ret = 0;
    image_t *img = NULL;
    image_t *other_image = NULL;
    char **names = NULL;
    size_t names_len = 0;
    char **unique_names = NULL;
    size_t unique_names_len = 0;
    size_t i;

    if (id == NULL || name == NULL) {
        ERROR("Invalid input paratemer: id(%s), name(%s)", id, name);
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to change image name assignments");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        ret = -1;
        goto out;
    }

    if (dup_array_of_strings((const char **)img->simage->names, img->simage->names_len, &names, &names_len) != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (append_name(&names, &names_len, name) != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (util_string_array_unique((const char **)names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    for (i = 0; i < img->simage->names_len; i++) {
        if (!map_remove(g_image_store->byname, (void *)names[i])) {
            ERROR("Failed to remove image from names index in image store");
            ret = -1;
            goto out;
        }
    }

    for (i = 0; i < unique_names_len; i++) {
        other_image = (image_t *)map_search(g_image_store->byname, (void *)unique_names[i]);
        if (other_image != NULL) {
            if (remove_name(other_image, unique_names[i]) != 0) {
                ERROR("Failed to remove name from other image");
                ret = -1;
                goto out;
            }
            if (save_image(other_image) != 0) {
                ERROR("Failed to save other image");
                ret = -1;
                goto out;
            }
        }

        if (!map_replace(g_image_store->byname, unique_names[i], (void *)img)) {
            ERROR("Failed to update byname map in image store");
            ret = -1;
            goto out;
        }
    }

    util_free_array_by_len(img->simage->names, img->simage->names_len);
    img->simage->names = unique_names;
    img->simage->names_len = unique_names_len;

    unique_names = NULL;
    unique_names_len = 0;

    if (save_image(img) != 0) {
        ERROR("Failed to update image");
        ret = -1;
        goto out;
    }

out:
    util_free_array_by_len(names, names_len);
    util_free_array_by_len(unique_names, unique_names_len);
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

int image_store_set_names(const char *id, const char **names, size_t names_len)
{
    int ret = 0;
    image_t *img = NULL;
    image_t *other_image = NULL;
    char **unique_names = NULL;
    size_t unique_names_len = 0;
    size_t i;

    if (id == NULL) {
        ERROR("Invalid paratemer, id is NULL");
        return -1;
    }

    if (names == NULL || names_len == 0) {
        ERROR("Cannot leave the image name empty");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to change image name assignments");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        ret = -1;
        goto out;
    }

    if (util_string_array_unique((const char **)names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    for (i = 0; i < img->simage->names_len; i++) {
        if (!map_remove(g_image_store->byname, (void *)img->simage->names[i])) {
            ERROR("Failed to remove image from ids map in image store : %s", img->simage->names[i]);
            ret = -1;
            goto out;
        }
    }

    for (i = 0; i < unique_names_len; i++) {
        other_image = (image_t *)map_search(g_image_store->byname, (void *)unique_names[i]);
        if (other_image != NULL && remove_name(other_image, unique_names[i]) != 0) {
            ERROR("Failed to remove name from other image");
            ret = -1;
            goto out;
        }
        if (!map_replace(g_image_store->byname, unique_names[i], (void *)img)) {
            ERROR("Failed to update byname map in image store");
            ret = -1;
            goto out;
        }
    }

    util_free_array_by_len(img->simage->names, img->simage->names_len);
    img->simage->names = unique_names;
    img->simage->names_len = unique_names_len;
    unique_names = NULL;
    unique_names_len = 0;

    if (save_image(img) != 0) {
        ERROR("Failed to update image");
        ret = -1;
        goto out;
    }

out:
    util_free_array_by_len(unique_names, unique_names_len);
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

int image_store_get_names(const char *id, char ***names, size_t *names_len)
{
    int ret = 0;
    image_t *img = NULL;
    char **tmp_names = NULL;
    size_t tmp_names_len = 0;

    if (id == NULL || names == NULL || names_len == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image names assignments");
        ret = -1;
        goto out;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image %s not known", id);
        ret = -1;
        goto out;
    }

    ret = dup_array_of_strings((const char **)img->simage->names, img->simage->names_len, &tmp_names, &tmp_names_len);
    if (ret != 0) {
        ERROR("Out of memory");
        goto out;
    }

    *names = tmp_names;
    *names_len = tmp_names_len;
    tmp_names = NULL;
    tmp_names_len = 0;

out:
    util_free_array_by_len(tmp_names, tmp_names_len);
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

int image_store_set_metadata(const char *id, const char *metadata)
{
    int ret = 0;
    image_t *img = NULL;

    if (id == NULL || metadata == NULL) {
        ERROR("Invalid paratemer: id(%s), metadata(%s)", id, metadata);
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to modify image metadata");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        ret = -1;
        goto out;
    }

    free(img->simage->metadata);
    img->simage->metadata = util_strdup_s(metadata);
    save_image(img);

out:
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

int image_store_set_load_time(const char *id, const types_timestamp_t *time)
{
#define MAX_TIMESTAMP_LEN 128
    int ret = 0;
    image_t *img = NULL;
    char timebuffer[MAX_TIMESTAMP_LEN] = { 0x00 };

    if (id == NULL || time == NULL) {
        ERROR("Invalid input paratemers");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to modify image metadata");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("image not known");
        ret = -1;
        goto out;
    }

    if (!get_time_buffer(time, timebuffer, sizeof(timebuffer))) {
        ERROR("Failed to get time buffer");
        ret = -1;
        goto out;
    }

    free(img->simage->loaded);
    img->simage->loaded = util_strdup_s(timebuffer);
    if (save_image(img) != 0) {
        ERROR("Failed to save image");
        ret = -1;
    }

out:
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

bool image_store_exists(const char *id)
{
    bool ret = true;
    image_t *img = NULL;

    if (id == NULL) {
        ERROR("Invalid paratemer, id is NULL");
        return false;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return false;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image exist info");
        return false;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        ret = false;
        goto out;
    }

out:
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

char *image_store_big_data(const char *id, const char *key)
{
    int ret = 0;
    image_t *img = NULL;
    size_t filesize;
    char filename[PATH_MAX] = { 0x00 };
    char *content = NULL;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return NULL;
    }

    if (key == NULL || strlen(key) == 0) {
        ERROR("Not a valid name for a big data item, can't retrieve image big data value for empty name");
        return NULL;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not read");
        return NULL;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image big data");
        return NULL;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        goto out;
    }

    ret = get_data_path(img->simage->id, key, filename, sizeof(filename));

    if (ret != 0) {
        ERROR("Failed to get big data file path: %s.", key);
        goto out;
    }

    content = read_file(filename, &filesize);

out:
    image_ref_dec(img);
    image_store_unlock();
    return content;
}

static int get_size_with_update_big_data(const char *id, const char *key, int64_t *size)
{
    int ret = 0;
    image_t *img = NULL;
    char *data = NULL;

    data = image_store_big_data(id, key);
    if (data == NULL) {
        return -1;
    }

    if (image_store_set_big_data(id, key, data) != 0) {
        free(data);
        return -1;
    }

    free(data);

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image big data size assignments");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        ret = -1;
        goto out;
    }

    (void)get_value_from_json_map_string_int64(img->simage->big_data_sizes, key, size);

out:
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

int64_t image_store_big_data_size(const char *id, const char *key)
{
    bool bret = false;
    image_t *img = NULL;
    int64_t size = -1;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return -1;
    }

    if (key == NULL || strlen(key) == 0) {
        ERROR("Not a valid name for a big data item, can't retrieve image big data value for empty name");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image big data size assignments");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        goto out;
    }

    bret = get_value_from_json_map_string_int64(img->simage->big_data_sizes, key, &size);

    image_ref_dec(img);

    if (bret || get_size_with_update_big_data(id, key, &size) == 0) {
        goto out;
    }

    ERROR("Size is not known");

out:
    image_store_unlock();
    return size;
}

static char *get_digest_with_update_big_data(const char *id, const char *key)
{
    image_t *img = NULL;
    char *data = NULL;
    char *digest = NULL;

    data = image_store_big_data(id, key);
    if (data == NULL) {
        return NULL;
    }

    if (image_store_set_big_data(id, key, data) != 0) {
        free(data);
        ERROR("Failed to set big data");
        return NULL;
    }

    free(data);
    data = NULL;

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image digest assignments");
        return NULL;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        goto out;
    }

    digest = get_value_from_json_map_string_string(img->simage->big_data_digests, key);

out:
    image_ref_dec(img);
    image_store_unlock();
    return digest;
}

char *image_store_big_data_digest(const char *id, const char *key)
{
    image_t *img = NULL;
    char *digest = NULL;

    if (key == NULL || strlen(key) == 0) {
        ERROR("Not a valid name for a big data item, can't retrieve image big data value for empty name");
        return NULL;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return NULL;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image big data digest assignments");
        return NULL;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        image_store_unlock();
        return NULL;
    }

    digest = get_value_from_json_map_string_string(img->simage->big_data_digests, key);

    image_ref_dec(img);
    image_store_unlock();

    if (digest != NULL) {
        return digest;
    }

    digest = get_digest_with_update_big_data(id, key);
    if (digest != NULL) {
        return digest;
    }

    ERROR("Could not compute digest of item");
    return NULL;
}

int image_store_big_data_names(const char *id, char ***names, size_t *names_len)
{
    int ret = 0;
    image_t *img = NULL;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image big data names assignments");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        ret = -1;
        goto out;
    }

    if (dup_array_of_strings((const char **)img->simage->big_data_names, img->simage->big_data_names_len, names,
                             names_len) != 0) {
        ERROR("Failed to dup image's names");
        ret = -1;
        goto out;
    }

out:
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

char *image_store_metadata(const char *id)
{
    image_t *img = NULL;
    char *metadata = NULL;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return NULL;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return NULL;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image metadata assignments");
        return NULL;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        goto out;
    }

    metadata = util_strdup_s(img->simage->metadata);

out:
    image_ref_dec(img);
    image_store_unlock();
    return metadata;
}

char *image_store_top_layer(const char *id)
{
    image_t *img = NULL;
    char *top_layer = NULL;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return NULL;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return NULL;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image top layer assignments");
        return NULL;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        goto out;
    }

    top_layer = util_strdup_s(img->simage->layer);

out:
    image_ref_dec(img);
    image_store_unlock();
    return top_layer;
}

int image_store_set_image_size(const char *id, uint64_t size)
{
    int ret = 0;
    image_t *img = NULL;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to modify image size");
        return -1;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        ret = -1;
        goto out;
    }

    img->simage->size = size;
    save_image(img);

out:
    image_ref_dec(img);
    image_store_unlock();
    return ret;
}

static int resort_image_names(const char **names, size_t names_len, char **first_name, char ***image_tags,
                              char ***image_digests)
{
    int ret = 0;
    size_t i;
    char *prefix = NULL;

    for (i = 0; i < names_len; i++) {
        size_t len = strlen(names[i]);
        if (strlen(names[i]) > MAX_IMAGE_NAME_LENGTH) {
            prefix = util_sub_string(names[i], len - MAX_IMAGE_NAME_LENGTH,
                                     MAX_IMAGE_NAME_LENGTH - MAX_IMAGE_DIGST_LENGTH);
        }

        if (prefix != NULL && strcmp(prefix, DIGIST_PREFIX) == 0) {
            if (util_array_append(image_digests, names[i]) != 0) {
                ERROR("Failed to append image to digest: %s", names[i]);
                ret = -1;
                goto out;
            }
        } else {
            if (util_array_append(image_tags, names[i]) != 0) {
                ERROR("Failed to append image to tags: %s", names[i]);
                ret = -1;
                goto out;
            }
        }
    }

    if (util_array_len((const char **)(*image_digests)) > 0) {
        free(*first_name);
        *first_name = util_strdup_s((*image_digests)[0]);
    }

    if (util_array_len((const char **)(*image_tags)) > 0) {
        free(*first_name);
        *first_name = util_strdup_s((*image_tags)[0]);
    }

out:
    if (ret != 0) {
        util_free_array(*image_digests);
        util_free_array(*image_tags);
        free(*first_name);
    }
    free(prefix);
    return ret;
}

// Validate checks that the contents is a valid digest
static bool validate_digest(const char *digest)
{
    bool ret = true;
    const char *digest_patten = "^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]+$";
    const char *sha256_encode_patten = "^[a-f0-9]{64}$";
    char *value = util_strdup_s(digest);
    char *index = strchr(value, ':');
    char *alg = NULL;
    char *encode = NULL;

    // contains ':' and is not the last character
    if (index == NULL && index - value + 1 == strlen(value)) {
        ERROR("Invalid checksum digest format");
        ret = false;
        goto out;
    }

    *index++ = '\0';

    alg = value;
    encode = index;
    // Currently only support SHA256 algorithm
    if (strcmp(alg, "sha256") != 0) {
        if (util_reg_match(digest_patten, digest) != 0) {
            ERROR("Invalid checksum digest format");
            ret = false;
            goto out;
        }
        ERROR("Unsupported digest algorithm");
        ret = false;
        goto out;
    }

    ret = util_reg_match(sha256_encode_patten, encode) == 0;

out:
    free(value);
    return ret;
}

// Parsing a reference string as a possible identifier, full digest, or familiar name.
static char *parse_digest_reference(const char *ref)
{
    char *indentfier_patten = "^[a-f0-9]{64}$";

    if (util_reg_match(indentfier_patten, ref) == 0) {
        return util_string_append(ref, "sha256:");
    }

    if (validate_digest(ref)) {
        return util_strdup_s(ref);
    }

    return oci_normalize_image_name(ref);
}

static int pack_repo_digest(char ***old_repo_digests, const char **image_tags, const char *digest, char ***repo_digests)
{
    int ret = 0;
    map_t *digest_map = NULL;
    char *tag_pos = NULL;
    char *ref = NULL;
    char *tmp_repo_digests = NULL;
    bool value = true;
    size_t i;

    *repo_digests = *old_repo_digests;
    *old_repo_digests = NULL;

    digest_map = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (digest_map == NULL) {
        ERROR("Failed to create empty digest map");
        ret = -1;
        goto out;
    }

    for (i = 0; i < util_array_len((const char **)*repo_digests); i++) {
        bool value = true;
        if (!map_replace(digest_map, (void *)(*repo_digests)[i], &value)) {
            ERROR("Failed to insert pair to digest map: %s", (*repo_digests)[i]);
            ret = -1;
            goto out;
        }
    }

    for (i = 0; i < util_array_len((const char **)image_tags); i++) {
        int nret = 0;

        ref = parse_digest_reference(image_tags[i]);
        if (ref == NULL) {
            continue;
        }
        tag_pos = util_tag_pos(ref);
        *tag_pos = '\0';

        nret = asprintf(&tmp_repo_digests, "%s@%s", ref, digest);
        if (nret < 0) {
            ERROR("Failed to receive repo digest");
            ret = -1;
            goto out;
        }
        if (map_search(digest_map, (void *)tmp_repo_digests) == NULL) {
            if (!map_replace(digest_map, (void *)tmp_repo_digests, (void *)&value)) {
                ERROR("Failed to insert repo digests");
                ret = -1;
                goto out;
            }

            if (util_array_append(repo_digests, tmp_repo_digests) != 0) {
                ERROR("Failed to append repo digest: %s", tmp_repo_digests);
                ret = -1;
                goto out;
            }
        }
        free(ref);
        ref = NULL;
        free(tmp_repo_digests);
        tmp_repo_digests = NULL;
    }

out:
    free(ref);
    free(tmp_repo_digests);
    map_free(digest_map);
    return ret;
}

static int get_image_repo_digests(char ***old_repo_digests, char **image_tags, image_t *img, char **image_digest,
                                  char ***repo_digests)
{
    int ret = 0;
    char *img_digest = NULL;
    char *digest = NULL;
    map_t *digest_map = NULL;

    digest = util_strdup_s(img->simage->digest);
    if (digest == NULL || strlen(digest) == 0) {
        img_digest = image_store_big_data_digest(img->simage->id, IMAGE_DIGEST_BIG_DATA_KEY);
        if (img_digest == NULL) {
            *repo_digests = *old_repo_digests;
            *old_repo_digests = NULL;
            ret = 0;
            goto out;
        }
        free(digest);
        digest = img_digest;
        img_digest = NULL;
    }

    if (util_array_len((const char **)image_tags) == 0) {
        *image_digest = util_strdup_s(digest);
        *repo_digests = *old_repo_digests;
        *old_repo_digests = NULL;
        ret = 0;
        goto out;
    }

    if (pack_repo_digest(old_repo_digests, (const char **)image_tags, digest, repo_digests) != 0) {
        ERROR("Failed to pack repo digest");
        ret = -1;
        goto out;
    }

out:
    free(img_digest);
    free(digest);
    map_free(digest_map);
    return ret;
}

static int pack_image_tags_and_repo_digest(image_t *img, imagetool_image *info)
{
    int ret = 0;
    char *name = NULL;
    char **tags = NULL;
    char **digests = NULL;
    char *image_digest = NULL;
    char **repo_digests = NULL;

    if (resort_image_names((const char **)img->simage->names, img->simage->names_len, &name, &tags, &digests) != 0) {
        ERROR("Failed to resort image names");
        ret = -1;
        goto out;
    }

    if (get_image_repo_digests(&digests, tags, img, &image_digest, &repo_digests) != 0) {
        ERROR("Failed to get image repo digests");
        ret = -1;
        goto out;
    }
    info->repo_tags = tags;
    info->repo_tags_len = util_array_len((const char **)tags);
    tags = NULL;
    info->repo_digests = repo_digests;
    info->repo_digests_len = util_array_len((const char **)repo_digests);
    repo_digests = NULL;

out:
    free(name);
    free(image_digest);
    util_free_array(tags);
    util_free_array(digests);
    util_free_array(repo_digests);
    return ret;
}

static int pack_oci_image_spec(const char *filename, imagetool_image *info)
{
    int ret = 0;
    parser_error err = NULL;

    info->spec = oci_image_spec_parse_file(filename, NULL, &err);
    if (info->spec == NULL) {
        ERROR("Failed to parse oci image spec file: %s", err);
        ret = -1;
        goto out;
    }

out:
    free(err);
    return ret;
}

static void parse_user_group(const char *username, char **user, char **group, char **tmp_dup)
{
    char *tmp = NULL;
    char *pdot = NULL;

    if (user == NULL || group == NULL || tmp_dup == NULL) {
        return;
    }

    if (username != NULL) {
        tmp = util_strdup_s(username);

        // for free tmp in caller
        *tmp_dup = tmp;

        pdot = strstr(tmp, ":");
        if (pdot != NULL) {
            *pdot = '\0';
            if (pdot != tmp) {
                // User found
                *user = tmp;
            }
            if (*(pdot + 1) != '\0') {
                // group found
                *group = pdot + 1;
            }
        } else {
            // No : found
            if (*tmp != '\0') {
                *user = tmp;
            }
        }
    }

    return;
}

static int pack_health_check_from_image(const docker_image_config_v2 *config_v2, imagetool_image *info)
{
    int ret = 0;
    size_t i;
    defs_health_check *healthcheck = NULL;

    if (config_v2->config->healthcheck == NULL || config_v2->config->healthcheck->test_len == 0) {
        return 0;
    }

    healthcheck = util_common_calloc_s(sizeof(defs_health_check));
    if (healthcheck == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    healthcheck->test = util_common_calloc_s(sizeof(char *) * config_v2->config->healthcheck->test_len);
    if (healthcheck->test == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    for (i = 0; i < config_v2->config->healthcheck->test_len; i++) {
        healthcheck->test[i] = util_strdup_s(config_v2->config->healthcheck->test[i]);
    }
    healthcheck->test_len = config_v2->config->healthcheck->test_len;
    healthcheck->interval = config_v2->config->healthcheck->interval;
    healthcheck->retries = config_v2->config->healthcheck->retries;
    healthcheck->start_period = config_v2->config->healthcheck->start_period;
    healthcheck->timeout = config_v2->config->healthcheck->timeout;
    healthcheck->exit_on_unhealthy = config_v2->config->healthcheck->exit_on_unhealthy;

    info->healthcheck = healthcheck;
    healthcheck = NULL;

out:
    free_defs_health_check(healthcheck);
    return ret;
}

static int pack_user_info_from_image(const docker_image_config_v2 *config_v2, imagetool_image *info)
{
    int ret = 0;
    char *tmp = NULL;
    char *user = NULL;
    char *group = NULL;
    long long converted;

    if (config_v2->config == NULL || config_v2->config->user == NULL || strlen(config_v2->config->user) == 0) {
        return 0;
    }

    // parse user and group by username
    parse_user_group(config_v2->config->user, &user, &group, &tmp);

    if (user == NULL) {
        ERROR("Failed to parse user");
        ret = -1;
        goto out;
    }
    if (util_safe_llong(user, &converted) == 0) {
        info->uid->value = (int64_t)converted;
    } else {
        info->username = util_strdup_s(user);
    }

out:
    free(tmp);
    return ret;
}

static int pack_image_summary_item(const char *filename, imagetool_image *info)
{
    int ret = 0;
    docker_image_config_v2 *config_v2 = NULL;
    parser_error err = NULL;

    config_v2 = docker_image_config_v2_parse_file(filename, NULL, &err);
    if (config_v2 == NULL) {
        ERROR("Failed to parse docker image config v2 : %s", filename);
        ret = -1;
        goto out;
    }

    if (pack_health_check_from_image(config_v2, info) != 0) {
        ERROR("Failed to pack health check config");
        ret = -1;
        goto out;
    }

    if (pack_user_info_from_image(config_v2, info) != 0) {
        ERROR("Failed to pack health check config");
        ret = -1;
        goto out;
    }

out:
    free_docker_image_config_v2(config_v2);
    free(err);
    return ret;
}

static imagetool_image *get_image_info(image_t *img)
{
    int ret = 0;
    int nret = 0;
    imagetool_image *info = NULL;
    char *base_name = NULL;
    char *config_file = NULL;
    char *sha256_key = NULL;

    sha256_key = util_full_digest(img->simage->id);
    if (sha256_key == NULL) {
        ERROR("Failed to get sha256 key");
        return NULL;
    }

    base_name = make_big_data_base_name(sha256_key);
    if (base_name == NULL) {
        ERROR("Failed to retrieve oci image spec file's base name");
        ret = -1;
        goto out;
    }

    nret = asprintf(&config_file, "%s/%s/%s", g_image_store->dir, img->simage->id, base_name);
    if (nret < 0 || nret > PATH_MAX) {
        ERROR("Failed to retrieve oci image spac file");
        ret = -1;
        goto out;
    }

    info = util_common_calloc_s(sizeof(imagetool_image));
    if (info == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (pack_oci_image_spec(config_file, info) != 0) {
        ERROR("Failed to pack oci image spec");
        ret = -1;
        goto out;
    }

    if (pack_image_summary_item(config_file, info) != 0) {
        ERROR("Failed to pack image summary item from image config");
        ret = -1;
        goto out;
    }

    info->id = util_strdup_s(img->simage->id);
    info->created = util_strdup_s(img->simage->created);
    info->loaded = util_strdup_s(img->simage->loaded);
    info->size = img->simage->size;
    info->top_layer = util_strdup_s(img->simage->layer);

    if (pack_image_tags_and_repo_digest(img, info) != 0) {
        ERROR("Failed to pack image tags and repo digest");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free_imagetool_image(info);
        info = NULL;
    }
    free(base_name);
    free(config_file);
    free(sha256_key);

    return info;
}

imagetool_image *image_store_get_image(const char *id)
{
    image_t *img = NULL;
    imagetool_image *imginfo = NULL;

    if (id == NULL) {
        ERROR("Invalid paratemer, id is NULL");
        return NULL;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not already");
        return NULL;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get the known image");
        return NULL;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Image not known");
        goto out;
    }

    imginfo = get_image_info(img);

out:
    image_ref_dec(img);
    image_store_unlock();
    return imginfo;
}

int image_store_get_all_images(imagetool_images_list *images_list)
{
    int ret = 0;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (images_list == NULL) {
        ERROR("Invalid input paratemer, memory should be allocated first");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not already!");
        return -1;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get all the known images");
        return -1;
    }

    if (g_image_store->images_list_len == 0) {
        goto out;
    }

    images_list->images = util_common_calloc_s(g_image_store->images_list_len * sizeof(imagetool_image));
    if (images_list->images == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    linked_list_for_each_safe(item, &(g_image_store->images_list), next) {
        imagetool_image *imginfo = NULL;
        image_t *img = (image_t *)item->elem;

        imginfo = get_image_info(img);
        if (imginfo == NULL) {
            ERROR("Failed to get image info");
            ret = -1;
            goto out;
        }
        images_list->images[images_list->images_len++] = imginfo;
        imginfo = NULL;
    }

out:
    image_store_unlock();
    return ret;
}

size_t image_store_get_images_number()
{
    size_t number = 0;

    if (g_image_store == NULL) {
        ERROR("Image store is not already!");
        return -1;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get the number of then known images");
        return -1;
    }

    number = g_image_store->images_list_len;

    image_store_unlock();
    return number;
}

int image_store_get_images_by_digest(const char *digest, imagetool_images_list *images_list)
{
    int ret = 0;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    digest_image_t *digest_imgs = NULL;

    if (digest == NULL) {
        return 0;
    }

    if (images_list == NULL) {
        ERROR("Invalid input paratemer, memory should be allocated first");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not already!");
        return -1;
    }

    if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get images by digest");
        return -1;
    }

    digest_imgs = (digest_image_t *)map_search(g_image_store->bydigest, (void *)digest);
    if (digest_imgs == NULL) {
        ERROR("Image not known");
        ret = -1;
        goto out;
    }

    if (digest_imgs->images_list_len == 0) {
        DEBUG("No images found related to the digest: %s", digest);
        goto out;
    }

    images_list->images = util_common_calloc_s(digest_imgs->images_list_len * sizeof(imagetool_image));
    if (images_list->images == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    linked_list_for_each_safe(item, &(digest_imgs->images_list), next) {
        imagetool_image *imginfo = NULL;
        image_t *img = (image_t *)item->elem;

        imginfo = get_image_info(img);
        if (imginfo == NULL) {
            ERROR("Failed to get image info");
            ret = -1;
            goto out;
        }
        images_list->images[images_list->images_len++] = imginfo;
        imginfo = NULL;
    }

out:
    image_store_unlock();
    return ret;
}

int image_store_get_fs_info(imagetool_fs_info *fs_info)
{
    int ret = 0;
    imagetool_fs_info_image_filesystems_element *fs_usage_tmp = NULL;
    int64_t total_size = 0;
    int64_t total_inodes = 0;

    if (fs_info == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (g_image_store == NULL) {
        ERROR("Image store is not ready");
        return -1;
    }

    fs_usage_tmp = util_common_calloc_s(sizeof(imagetool_fs_info_image_filesystems_element));
    if (fs_usage_tmp == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    fs_usage_tmp->timestamp = get_now_time_nanos();

    fs_usage_tmp->fs_id = util_common_calloc_s(sizeof(imagetool_fs_info_image_filesystems_fs_id));
    if (fs_usage_tmp->fs_id == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }
    fs_usage_tmp->fs_id->mountpoint = util_strdup_s(g_image_store->dir);

    util_calculate_dir_size(g_image_store->dir, 0, &total_size, &total_inodes);

    fs_usage_tmp->inodes_used = util_common_calloc_s(sizeof(imagetool_fs_info_image_filesystems_inodes_used));
    if (fs_usage_tmp->inodes_used == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }
    fs_usage_tmp->inodes_used->value = total_inodes;

    fs_usage_tmp->used_bytes = util_common_calloc_s(sizeof(imagetool_fs_info_image_filesystems_used_bytes));
    if (fs_usage_tmp->used_bytes == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }
    fs_usage_tmp->used_bytes->value = total_size;

    fs_info->image_filesystems = util_common_calloc_s(sizeof(imagetool_fs_info_image_filesystems_element *));
    if (fs_info->image_filesystems == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }
    fs_info->image_filesystems[0] = fs_usage_tmp;
    fs_usage_tmp = NULL;
    fs_info->image_filesystems_len = 1;

out:
    free_imagetool_fs_info_image_filesystems_element(fs_usage_tmp);
    return ret;
}

