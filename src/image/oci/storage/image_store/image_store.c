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
 * Description: provide image store functions
 ******************************************************************************/
#include "image_store.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <libgen.h>
#include <unistd.h>
#include <stddef.h>
#include <libwebsockets.h>
#include <sys/types.h>
#include <sha256.h>
#include "utils.h"
#include "log.h"
#include "constants.h"
#include "read_file.h"

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
    bool loaded;
} image_store_t;

image_store_t *g_image_store = NULL;

static void free_image_store(image_store_t *image_store)
{
    size_t i;

    if (image_store == NULL) {
        return;
    }

    free(image_store->dir);
    image_store->dir = NULL;

    for (i = 0; i < image_store->images_len; i++) {
        free_storage_image(image_store->images[i]);
        image_store->images[i] = NULL;
    }
    free(image_store->images);
    image_store->images = NULL;

    (void)map_free(image_store->byid);
    image_store->byid = NULL;

    (void)map_free(image_store->byname);
    image_store->byname = NULL;

    (void)map_free(image_store->bydigest);
    image_store->bydigest = NULL;

    free(image_store);
}

static void image_store_field_kvfree(void *key, void *value)
{
    (void)value;
    free(key);
}

static void image_store_digest_field_kvfree(void *key, void *value)
{
    digest_image_t *val = (digest_image_t *)value;
    size_t i;

    free(key);
    if (val != NULL) {
        for (i = 0; i < val->images_len; i++) {
            val->images[i] = NULL;
        }
        free(val);
    }
}

static int get_image_path(image_store_t *image_store, const char *id, char *path, size_t len)
{
    int nret = snprintf(path, len, "%s/%s/image.json", image_store->dir, id);

    return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
}

static int do_append_image(storage_image *src_image, storage_image ***new_images, size_t *len)
{
    int ret;
    storage_image **tmp_images = NULL;
    size_t old_size, new_size;

    if (*len > SIZE_MAX / sizeof(storage_image *) - 1) {
        ERROR("Too many storage images");
        return -1;
    }
    old_size = *len * sizeof(storage_image);
    new_size = old_size + sizeof(storage_image);
    ret = mem_realloc((void **)(&tmp_images), new_size, (void *)(*new_images), old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for append storage image");
        return -1;
    }
    *new_images = tmp_images;

    (*new_images)[*len] = src_image;
    (*len)++;

    return 0;
}

static int append_image_by_image_directory(const char *image_dir, storage_image ***images, size_t *images_size)
{
    int ret = 0;
    int nret;
    char image_path[PATH_MAX] = {0x00};
    storage_image *tmp_image = NULL;
    parser_error err = NULL;

    nret = snprintf(image_path, sizeof(image_path), "%s/%s", image_dir, "image.json");
    if (nret < 0 || (size_t)nret >= sizeof(image_path)) {
        ERROR("Failed to get image path");
        return -1;
    }

    tmp_image = storage_image_parse_file(image_path, NULL, &err);
    if (tmp_image == NULL) {
        ERROR("Failed to parse images path: %s", err);
        return -1;
    }

    if (do_append_image(tmp_image, images, images_size) != 0) {
        ERROR("Failed to append images");
        ret = -1;
        goto out;
    }

    tmp_image = NULL;

out:
    free_storage_image(tmp_image);
    free(err);
    return ret;
}

static int get_images_from_json(image_store_t *image_store, storage_image ***images, size_t *images_size)
{
    int ret = 0;
    int nret;
    char **image_dirs = NULL;
    size_t image_dirs_num = 0;
    size_t i;
    char *id_patten = "^[a-f0-9]{64}$";
    char image_path[PATH_MAX] = {0x00};

    ret = util_list_all_subdir(image_store->dir, &image_dirs);
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
        nret = snprintf(image_path, sizeof(image_path), "%s/%s", image_store->dir, image_dirs[i]);
        if (nret < 0 || (size_t)nret >= sizeof(image_path)) {
            ERROR("Failed to get image path");
            ret = -1;
            goto out;
        }

        if (append_image_by_image_directory(image_path, images, images_size) != 0) {
            ERROR("Found image path but load json failed: %s", image_dirs[i]);
            ret = -1;
            goto out;
        }
    }

out:
    util_free_array(image_dirs);
    return ret;
}

static int remove_name(storage_image *image, const char *name)
{
    char **tmp_names = NULL;
    size_t new_size;
    size_t count = 0;
    size_t i;
    size_t index = 0;

    if (image == NULL || name == NULL) {
        return 0;
    }

    for (i = 0; i < image->names_len; i++) {
        if (strcmp(image->names[i], name) == 0) {
            count++;
        }
    }

    new_size = (image->names_len - count) * sizeof(char *);
    tmp_names = (char **)util_common_calloc_s(new_size);
    if (tmp_names == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < image->names_len; i++) {
        if (strcmp(image->names[i], name) != 0) {
            tmp_names[index++] = util_strdup_s(image->names[i]);
        }
        free(image->names[i]);
        image->names[i] = NULL;
    }

    free(image->names);
    image->names = tmp_names;
    image->names_len = index;

    return 0;
}

static bool is_read_write()
{
    return true;
}

static bool is_locked()
{
    return true;
}

static int save_file(const char *file_path, const char *data, mode_t mode)
{
    int ret = 0;
    int fd = -1;
    ssize_t len = 0;

    if (data == NULL || strlen(data) == 0) {
        return 0;
    }

    fd = util_open(file_path, O_CREAT | O_TRUNC | O_CLOEXEC | O_WRONLY, mode);
    if (fd == -1) {
        ERROR("Create file %s failed: %s", file_path, strerror(errno));
        ret = -1;
        goto out;
    }

    len = util_write_nointr(fd, data, strlen(data));
    if (len < 0 || ((size_t)len) != strlen(data)) {
        ERROR("Write file %s failed: %s", file_path, strerror(errno));
        ret = -1;
    }
    close(fd);

out:
    return ret;
}

int save_image(image_store_t *image_store, storage_image *image)
{
    int ret = 0;
    char image_path[PATH_MAX] = {0x00};
    char image_dir[PATH_MAX] = {0x00};
    parser_error err = NULL;
    char *json_data = NULL;

    if (!is_read_write()) {
        ERROR("not allowed to modify the read-only image store at %s", image_store->dir);
        return -1;
    }

    if (!is_locked()) {
        ERROR("Image store is not locked");
        return -1;
    }

    if (get_image_path(image_store, image->id, image_path, sizeof(image_path)) != 0) {
        ERROR("Failed to get image path by id: %s", image->id);
        return -1;
    }

    strcpy(image_dir, image_path);
    ret = util_mkdir_p(dirname(image_dir), IMAGE_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Failed to create image directory %s.", image_path);
        return -1;
    }

    json_data = storage_image_generate_json(image, NULL, &err);
    if (json_data == NULL) {
        ERROR("Failed to generate images.json string:%s", err ? err : " ");
        ret = -1;
        goto out;
    }

    if (save_file(image_path, json_data, CONFIG_FILE_MODE) != 0) {
        ERROR("Failed to save images.json file");
        ret = -1;
        goto out;
    }

out:
    free(json_data);
    free(err);

    return ret;
}

int image_store_save(storage_image *image)
{
    if (g_image_store == NULL || image == NULL) {
        return -1;
    }

    return save_image(g_image_store, image);
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

static int append_image_to_digest_images(digest_image_t **digest_images, storage_image *image)
{
    size_t new_size, old_size;
    storage_image **tmp_images = NULL;

    if (image == NULL) {
        return 0;
    }

    if (*digest_images == NULL) {
        *digest_images = (digest_image_t *)util_common_calloc_s(sizeof(digest_image_t));
        if (*digest_images == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }

    old_size = (*digest_images)->images_len * sizeof(storage_image *);
    new_size = old_size + sizeof(storage_image *);

    if (mem_realloc((void **)&tmp_images, new_size, (void *)(*digest_images)->images, old_size) != 0) {
        ERROR("Failed to realloc memory");
        return -1;
    }

    (*digest_images)->images = tmp_images;
    (*digest_images)->images[(*digest_images)->images_len++] = image;

    return 0;
}

static int implicit_digest(storage_image *image, map_t *digests)
{
    size_t index = 0;
    digest_image_t *tmp_digest_images = NULL;
    if (image->big_data_digests == NULL) {
        return 0;
    }

    if (get_index_by_key((const char **)image->big_data_digests->keys,
                         image->big_data_digests->len, IMAGE_DIGEST_BIG_DATA_KEY, &index)) {
        return 0;
    }

    tmp_digest_images = map_search(digests, (void *)image->big_data_digests->values[index]);
    if (append_image_to_digest_images(&tmp_digest_images, image) != 0) {
        ERROR("Failed to append image to digests");
        return -1;
    }

    if (!map_replace(digests, (void *)image->big_data_digests->values[index], (void *)tmp_digest_images)) {
        ERROR("Failed to append image to digests");
        return -1;
    }

    return 0;
}

static int explicit_digest(storage_image *image, map_t *digests)
{
    size_t index = 0;
    digest_image_t *tmp_digest_images = NULL;
    char *value = NULL;

    if (image->big_data_digests == NULL) {
        return 0;
    }

    if (get_index_by_key((const char **)image->big_data_digests->keys,
                         image->big_data_digests->len, IMAGE_DIGEST_BIG_DATA_KEY, &index)) {
        value = image->big_data_digests->values[index];
    }

    if (image->digest == NULL) {
        image->digest = (value != NULL ? util_strdup_s(value) : NULL);
    } else if (value == NULL || (value != NULL && strcmp(image->digest, value) != 0)) {
        tmp_digest_images = map_search(digests, (void *)image->big_data_digests->values[index]);
        if (append_image_to_digest_images(&tmp_digest_images, image) != 0) {
            ERROR("Failed to append image to digests");
            return -1;
        }
        if (!map_replace(digests, (void *)image->digest, (void *)tmp_digest_images)) {
            ERROR("Failed to append image to digests");
            return -1;
        }
    }

    return 0;
}

static int load_image_to_image_store_field(image_store_t *image_store, storage_image *image,
                                           map_t *ids, map_t *names, map_t *digests)
{
    int ret = 0;
    bool should_save = false;
    size_t i;

    if (!map_replace(ids, (void *)image->id, (void *)image)) {
        ERROR("Failed to insert image to ids");
        return -1;
    }

    for (i = 0; i < image->names_len; i++) {
        storage_image *conflict_image = map_search(names, (void *)image->names[i]);
        if (conflict_image != NULL) {
            if (remove_name(conflict_image, image->names[i]) != 0) {
                ERROR("Failed to remove name from conflict image");
                ret = -1;
                goto out;
            }
            should_save = true;
        }
        if (!map_replace(names, (void *)image->names[i], (void *)image)) {
            ERROR("Failed to insert image to names");
            ret = -1;
            goto out;
        }
    }

    if (should_save && save_image(image_store, image) != 0) {
        ERROR("Failed to save image");
        ret = -1;
        goto out;
    }

    if (implicit_digest(image, digests) != 0) {
        ERROR("Implicit digest failed");
        ret = -1;
        goto out;
    }

    if (explicit_digest(image, digests) != 0) {
        ERROR("Explicit digest failed");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int load_helper(image_store_t *image_store)
{
    int ret = 0;
    storage_image **images = NULL;
    size_t images_size = 0;
    size_t i;
    map_t *ids = NULL;
    map_t *names = NULL;
    map_t *digests = NULL;

    if (image_store->loaded) {
        DEBUG("Do not need reload if daemon");
        return 0;
    }

    if (get_images_from_json(image_store, &images, &images_size) != 0) {
        ERROR("Failed to get images from json");
        ret = -1;
        goto err_out;
    }

    ids = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_field_kvfree);
    if (ids == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto err_out;
    }

    names = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_field_kvfree);
    if (names == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto err_out;
    }

    digests = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_digest_field_kvfree);
    if (digests == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto err_out;
    }

    for (i = 0; i < images_size; i++) {
        if (load_image_to_image_store_field(image_store, images[i], ids, names, digests) != 0) {
            ERROR("Failed to load image to image store");
            ret = -1;
            goto err_out;
        }
    }

    for (i = 0; i < image_store->images_len; i++) {
        free_storage_image(image_store->images[i]);
        image_store->images[i] = NULL;
    }
    free(image_store->images);
    image_store->images = images;
    image_store->images_len = images_size;

    map_free(image_store->byid);
    image_store->byid = ids;

    map_free(image_store->byname);
    image_store->byname = names;

    map_free(image_store->bydigest);
    image_store->bydigest = digests;

    image_store->loaded = true;

    return ret;

err_out:
    for (i = 0; i < images_size; i++) {
        free_storage_image(images[i]);
        images[i] = NULL;
    }
    free(images);
    map_free(ids);
    map_free(names);
    map_free(digests);

    return ret;
}

static int image_store_load(image_store_t *image_store)
{
    return load_helper(image_store);
}

int new_image_store(const char *dir)
{
    int ret = 0;
    image_store_t *store = NULL;

    ret = util_mkdir_p(dir, IMAGE_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Unable to create image store directory %s.", dir);
        return ret;
    }

    store = (image_store_t *)util_common_calloc_s(sizeof(image_store_t));
    if (store == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    store->dir = util_strdup_s(dir);
    store->images = NULL;
    store->images_len = 0;
    store->idindex = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_field_kvfree);
    if (store->idindex == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    store->byid = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_field_kvfree);
    if (store->byid == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    store->byname = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_field_kvfree);
    if (store->byname == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    store->bydigest = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, image_store_digest_field_kvfree);
    if (store->bydigest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    // TODO: set file lock value

    ret = image_store_load(store);
    if (ret != 0) {
        ERROR("Failed to load image store");
        ret = -1;
        goto out;
    }

    g_image_store = store;
    store = NULL;

out:
    free_image_store(store);
    return ret;
}

static int string_array_unique(const char **elements, size_t length, char ***unique_elements,
                               size_t *unique_elements_len)
{
    int ret = 0;
    size_t i;
    map_t *map = NULL;
    map_itor *itor = NULL;
    char **tmp_elements = NULL;
    size_t tmp_elements_len = 0;

    map = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (map == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < length; i++) {
        bool b = true;
        if (!map_replace(map, (void *)elements[i], (void *)(&b))) {
            ERROR("Failed to replace map element");
            ret = -1;
            goto out;
        }
    }

    tmp_elements_len = map_size(map);
    tmp_elements = (char **)util_common_calloc_s(tmp_elements_len * sizeof(char *));
    if (tmp_elements == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    itor = map_itor_new(map);
    if (itor == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    i = 0;
    for (; map_itor_valid(itor); map_itor_next(itor)) {
        tmp_elements[i++] = util_strdup_s(map_itor_key(itor));
    }

    *unique_elements = tmp_elements;
    *unique_elements_len = tmp_elements_len;
    tmp_elements = NULL;
    tmp_elements_len = 0;

out:
    map_free(map);
    map_itor_free(itor);
    util_free_array_by_len(tmp_elements, tmp_elements_len);
    return ret;
}

static int image_store_append_image(image_store_t *g_image_store, storage_image *image)
{
    storage_image **new_images = NULL;
    size_t new_size, old_size;

    old_size = g_image_store->images_len * sizeof(storage_image *);
    new_size = old_size + sizeof(storage_image *);

    int nret = mem_realloc((void **)(&new_images), new_size, (void *)g_image_store->images, old_size);
    if (nret != 0) {
        ERROR("Out of memory");
        return -1;
    }

    g_image_store->images = new_images;
    g_image_store->images[g_image_store->images_len++] = image;

    return 0;
}

static int dup_map_string_int64(const json_map_string_int64 *src, json_map_string_int64 **dst)
{
    size_t i;

    if (src == 0 || src->len == 0) {
        return 0;
    }

    if (*dst != NULL) {
        free_json_map_string_int64(*dst);
    }

    *dst = util_common_calloc_s(sizeof(json_map_string_int64));
    if (*dst == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < src->len; i++) {
        (void)append_json_map_string_int64(*dst, src->keys[i], src->values[i]);
    }

    return 0;
}

static int dup_map_string_string(const json_map_string_string *src, json_map_string_string **dst)
{
    size_t i;

    if (src == 0 || src->len == 0) {
        return 0;
    }

    if (*dst != NULL) {
        free_json_map_string_string(*dst);
    }

    *dst = util_common_calloc_s(sizeof(json_map_string_string));
    if (*dst == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < src->len; i++) {
        (void)append_json_map_string_string(*dst, src->keys[i], src->values[i]);
    }

    return 0;
}

static storage_image *copy_image(const storage_image *src)
{
    int ret = 0;
    storage_image *dst = NULL;

    if (src == NULL) {
        ERROR("Invalid input paratemer: empty image");
        return NULL;
    }

    dst = (storage_image *)util_common_calloc_s(sizeof(storage_image));
    if (dst == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    dst->id = util_strdup_s(src->id);
    if (src->digest != NULL) {
        dst->digest = util_strdup_s(src->digest);
    }

    if (src->names_len != 0) {
        if (dup_array_of_strings((const char **)src->names, src->names_len, &(dst->names), &(dst->names_len)) != 0) {
            ERROR("Failed to dup names");
            ret = -1;
            goto out;
        }
    }
    if (src->layer != NULL) {
        dst->layer = util_strdup_s(src->layer);
    }

    if (src->metadata != NULL) {
        dst->metadata = util_strdup_s(src->metadata);
    }

    if (dup_array_of_strings((const char **)src->big_data_names, src->big_data_names_len,
                             &(dst->big_data_names), &(dst->big_data_names_len)) != 0) {
        ERROR("Failed to dup big-data names");
        ret = -1;
        goto out;
    }

    if (dup_map_string_int64(src->big_data_sizes, &(dst->big_data_sizes)) != 0) {
        ERROR("Failed to dup big-data sizes: out of memory");
        ret = -1;
        goto out;
    }

    if (dup_map_string_string(src->big_data_digests, &(dst->big_data_digests)) != 0) {
        ERROR("Failed to dup big-data digests: out of memory");
        ret = -1;
        goto out;
    }

    if (src->created != NULL) {
        dst->created = util_strdup_s(src->created);
    }

    if (src->loaded != NULL) {
        dst->loaded = util_strdup_s(src->loaded);
    }

out:
    if (ret != 0) {
        free_storage_image(dst);
        dst = NULL;
    }

    return dst;
}

storage_image *image_store_create(const char *id, const char **names, size_t names_len, const char *layer,
                                  const char *metadata, const types_timestamp_t *time, const char *searchable_digest)
{
    int ret = 0;
    char *dst_id = NULL;
    char **unique_names = NULL;
    size_t unique_names_len = 0;
    char *created = NULL;
    char *loaded = NULL;
    char timebuffer[512] = { 0x00 };
    bool bret = false;
    storage_image *image = NULL;
    storage_image *duped_image = NULL;
    digest_image_t *digest_images = NULL;
    size_t i;

    if (g_image_store == NULL) {
        ERROR("Invalid input parameter");
        return NULL;
    }

    if (!is_read_write()) {
        ERROR("not allowed to create new images at %s/images.json", g_image_store->dir);
        return NULL;
    }

    if (id == NULL) {
        // TODO: generate random id
        // if (generate_random_id(&dst_id) != 0) {
        // ERROR("Failed to generate random id");
        // if (map_search(g_image_store->byid, (void *)des_id)) {
        //
        // }
        // }
    } else {
        dst_id = util_strdup_s(id);
    }

    if (map_search(g_image_store->byid, (void *)id) != NULL) {
        ERROR("ID is already in use: %s", id);
        ret = -1;
        goto out;
    }

    if (string_array_unique(names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    bret = (!time->has_seconds && !time->has_nanos) ?
           get_now_time_buffer(timebuffer, sizeof(timebuffer)) :
           get_time_buffer(time, timebuffer, sizeof(timebuffer));
    if (!bret) {
        ERROR("Failed to get time buffer");
        ret = -1;
        goto out;
    }
    created = util_strdup_s(timebuffer);

    (void)get_now_time_buffer(timebuffer, sizeof(timebuffer));
    loaded = util_strdup_s(timebuffer);

    image = (storage_image *)util_common_calloc_s(sizeof(storage_image));
    if (image == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    image->id = dst_id;
    dst_id = NULL;

    image->digest = util_strdup_s(searchable_digest);

    image->names = unique_names;
    image->names_len = unique_names_len;

    image->layer = util_strdup_s(layer);

    image->metadata = util_strdup_s(metadata);

    image->created = created;
    created = NULL;

    image->loaded = loaded;
    loaded = NULL;

    if (image_store_append_image(g_image_store, image) != 0) {
        ERROR("Failed to append image to image store");
        ret = -1;
        goto out;
    }

    if (!map_insert(g_image_store->byid, (void *)id, (void *)image)) {
        ERROR("Failed to insert image to image store");
        ret = -1;
        goto out;
    }

    if (searchable_digest != NULL) {
        // TODO: digest key: string   value:storage_image **
        digest_images = (digest_image_t *)map_search(g_image_store->bydigest, (void *)searchable_digest);
        if (append_image_to_digest_images(&digest_images, image) != 0) {
            ERROR("Failed to append image to digest images");
            ret = -1;
            goto out;
        }
    }

    for (i = 0; i < unique_names_len; i++) {
        if (!map_insert(g_image_store->byname, (void *)unique_names[i], (void *)image)) {
            ERROR("Failed to insert image to image store's byname");
            ret = -1;
            goto out;
        }
    }

    if (save_image(g_image_store, image) != 0) {
        ERROR("Failed to save image");
        ret = -1;
        goto out;
    }

    duped_image = copy_image(image);

out:
    free(dst_id);
    if (ret != 0) {
        free_storage_image(image);
        image = NULL;
    }
    return duped_image;
}

static storage_image *get_image_for_store_by_prefix(image_store_t *g_image_store, const char *id)
{
    bool ret = true;
    storage_image *value = NULL;
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

static storage_image *lookup(const char *id)
{
    storage_image *value = NULL;

    if (g_image_store == NULL || id == NULL) {
        ERROR("Invalid input parameter");
        return NULL;
    }

    value = map_search(g_image_store->byid, (void *)id);
    if (value != NULL) {
        return value;
    }

    value = map_search(g_image_store->byname, (void *)id);
    if (value != NULL) {
        return value;
    }

    value = get_image_for_store_by_prefix(g_image_store, id);
    if (value != NULL) {
        return value;
    }

    return NULL;
}

const char *image_store_lookup(const char *id)
{
    storage_image * image = NULL;

    if (g_image_store == NULL || id == NULL) {
        return NULL;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("Image not known");
        return NULL;
    }

    return image->id;
}

static const char *get_value_from_json_map_string_string(json_map_string_string *map, const char *key)
{
    size_t i;

    if (map == NULL) {
        return NULL;
    }
    for (i = 0; i < map->len; i++) {
        if (strcmp(key, map->keys[i]) == 0) {
            return map->values[i];
        }
    }

    return NULL;
}

static digest_image_t *digest_image_slice_without_value(digest_image_t *digest_filter_images,
                                                        storage_image *image)
{
    size_t i, index;
    digest_image_t *pruned_images = NULL;
    size_t count = 0;
    size_t pruned_size;

    if (digest_filter_images == NULL || image == NULL) {
        return NULL;
    }

    pruned_images = (digest_image_t *)util_common_calloc_s(sizeof(digest_image_t));
    if (pruned_images == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (i = 0; i < digest_filter_images->images_len; i++) {
        if (digest_filter_images->images[i] == image) {
            count++;
        }
    }

    pruned_size = (digest_filter_images->images_len - count) * sizeof(storage_image *);
    pruned_images->images = (storage_image **)util_common_calloc_s(pruned_size);
    if (pruned_images->images == NULL) {
        ERROR("Out of memory");
        free(pruned_images);
        return NULL;
    }

    index = 0;
    for (i = 0; i < digest_filter_images->images_len; i++) {
        if (digest_filter_images->images[i] == image) {
            continue;
        }
        pruned_images->images[index++] = digest_filter_images->images[i];
    }

    pruned_images->images_len = index;

    return pruned_images;
}

static int get_data_dir(image_store_t *g_image_store, const char *id, char *path, size_t len)
{
    int nret = snprintf(path, len, "%s/%s", g_image_store->dir, id);
    return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
}

static int remove_image_from_digest_index(image_store_t *g_image_store, storage_image *image, const char *digest)
{
    digest_image_t *digest_filter_images = NULL;
    digest_image_t *pruned_images = NULL;

    digest_filter_images = (digest_image_t *)map_search(g_image_store->bydigest, (void *)digest);
    if (digest_filter_images != NULL) {
        pruned_images = digest_image_slice_without_value(digest_filter_images, image);
        if (pruned_images != NULL && pruned_images->images_len == 0) {
            if (!map_remove(g_image_store->bydigest, (void *)digest)) {
                ERROR("Failed to delete image for bydigest map in store");
                return -1;
            }
            free(pruned_images);
        } else {
            if (!map_replace(g_image_store->bydigest, (void *)digest, (void *)pruned_images)) {
                ERROR("Failed to replace digest value");
                return -1;
            }
        }
    }

    return 0;
}

int image_store_delete(const char *id)
{
    storage_image *image = NULL;
    const char *image_id = NULL;
    size_t i;
    size_t to_delete_index = SIZE_MAX;
    size_t new_size, old_size;
    storage_image **tmp_images = NULL;
    const char *digest = NULL;
    char image_path[PATH_MAX] = { 0x00 };

    if (!is_read_write()) {
        ERROR("not allowed to create new images at %s/images.json", g_image_store->dir);
        return -1;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("image not known");
        return -1;
    }

    image_id = image->id;

    if (!map_remove(g_image_store->byid, (void *)image_id)) {
        ERROR("Failed to remove image from ids map in image store");
        return -1;
    }

    for (i = 0; i < image->names_len; i++) {
        if (!map_remove(g_image_store->byname, (void *)image->names[i])) {
            ERROR("Failed to remove image from ids map in image store");
            return -1;
        }
    }

    for (i = 0; i < g_image_store->images_len; i++) {
        if (strcmp(image_id, g_image_store->images[i]->id) == 0) {
            to_delete_index = i;
        }
    }

    if (to_delete_index != SIZE_MAX) {
        for (i = to_delete_index; i < g_image_store->images_len; i++) {
            if (i + 1 < g_image_store->images_len) {
                g_image_store->images[i] = g_image_store->images[i + 1];
            }
        }

        old_size = g_image_store->images_len * sizeof(storage_image *);
        new_size = old_size - sizeof(storage_image *);
        if (mem_realloc((void **)&tmp_images, new_size, (void *)g_image_store->images, old_size) != 0) {
            ERROR("Out of memory");
            return -1;
        }
        g_image_store->images = tmp_images;
        g_image_store->images_len--;
    }

    digest = get_value_from_json_map_string_string(image->big_data_digests, IMAGE_DIGEST_BIG_DATA_KEY);
    if (digest != NULL && remove_image_from_digest_index(g_image_store, image, digest) != 0) {
        ERROR("Failed to remove the image from the digest-based index");
        return -1;
    }

    if (image->digest != NULL && remove_image_from_digest_index(g_image_store, image, image->digest) != 0) {
        ERROR("Failed to remove the image from the digest-based index");
        return -1;
    }

    if (get_data_dir(g_image_store, id, image_path, sizeof(image_path)) != 0) {
        ERROR("Failed to get image data dir: %s", id);
        return -1;
    }

    if (util_recursive_rmdir(image_path, 0) != 0) {
        ERROR("Failed to delete image directory : %s", image_path);
        return -1;
    }

    return 0;
}

int image_store_wipe()
{
    int ret = 0;
    map_itor *itor = NULL;
    char *tmp_id = NULL;

    if (!is_read_write()) {
        ERROR("called a write method on a read-only store, not allowed to delete images at %s", g_image_store->dir);
        return -1;
    }

    itor = map_itor_new(g_image_store->byid);
    if (itor == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        const char *id = map_itor_key(itor);
        if (tmp_id == NULL) {
            ERROR("Failed to get key from map");
            ret = -1;
            goto out;
        }
        tmp_id = util_strdup_s(id);
        if (image_store_delete(tmp_id) != 0) {
            ERROR("Failed to delete image: %s", tmp_id);
            ret = -1;
            goto out;
        }
        free(tmp_id);
        tmp_id = NULL;
    }

out:
    free(tmp_id);
    return ret;
}

static bool should_use_origin_name(const char *name)
{
    size_t i;

    for (i = 0; i < strlen(name); i++) {
        char ch = name[i];
        if (ch != '.' && !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'z')) {
            return true;
        }
    }

    return false;
}

// Convert a BigData key name into an acceptable file name.
static char *make_big_data_base_name(const char *key)
{
#define MAX_BIG_DATA_BASE_NAME_LEN 100
    int ret = 0;
    char encode_name[MAX_BIG_DATA_BASE_NAME_LEN] = {0x00};
    char *base_name = NULL;
    size_t name_size;

    if (should_use_origin_name(key)) {
        return util_strdup_s(key);
    }

    (void)lws_b64_encode_string(key, (int)strlen(key), encode_name, (int)sizeof(encode_name));
    name_size = 1 + strlen(encode_name) + 1; // '=' + encode string + '\0'

    base_name = (char *)util_common_calloc_s(name_size * sizeof(char));
    if (base_name == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    ret = snprintf(base_name, name_size, "%s%s", "=", encode_name);
    if (ret < 0 || (size_t)ret >= name_size) {
        ERROR("Out of memory");
        goto out;
    }

out:
    if (ret != 0) {
        free(base_name);
        base_name = NULL;
    }

    return base_name;
}


static int get_data_path(image_store_t *g_image_store,
                         const char *id, const char *key, char *path, size_t len)
{
    int ret = 0;
    int nret = 0;
    char *data_base_name = NULL;
    char data_dir[PATH_MAX] = {0x00};

    data_base_name = make_big_data_base_name(key);

    if (get_data_dir(g_image_store, id, data_dir, sizeof(data_dir)) != 0) {
        ERROR("Failed to get image data dir: %s", id);
        return -1;
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

static char *calc_sha256_with_string(const char *val)
{
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH] = { 0x00 };
    char output_buffer[(SHA256_DIGEST_LENGTH * 2) + 1] = { 0x00 };
    int i;

    if (val == NULL) {
        return NULL;
    }

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, val, strlen(val));
    SHA256_Final(hash, &ctx);

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        int ret = snprintf(output_buffer + (i * 2), 3, "%02x", (unsigned int)hash[i]);
        if (ret >= 3 || ret < 0) {
            return "";
        }
    }
    output_buffer[SHA256_DIGEST_LENGTH * 2] = '\0';

    return util_strdup_s(output_buffer);
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

static int append_big_data_name(storage_image *image, const char *name)
{
    size_t new_size, old_size;
    char **tmp_names = NULL;

    if (name == NULL) {
        return 0;
    }

    old_size = image->big_data_names_len * sizeof(char *);
    new_size = old_size + sizeof(char *);

    if (mem_realloc((void **)&tmp_names, new_size, (void *)image->big_data_names, old_size) != 0) {
        ERROR("Failed to realloc memory");
        return -1;
    }

    image->big_data_names = tmp_names;
    image->big_data_names[image->big_data_names_len++] = util_strdup_s(name);

    return 0;
}

static int update_image_with_big_data(storage_image *image, const char *key, const char *data, bool *should_save)
{
    bool size_found = false;
    int64_t old_size;
    const char *old_digest = NULL;
    char *new_digest = NULL;
    bool add_name = true;
    size_t i;
    digest_image_t *digest_filter_images = NULL;
    digest_image_t *pruned_images = NULL;

    if (image->big_data_sizes == NULL) {
        image->big_data_sizes = (json_map_string_int64 *)util_common_calloc_s(sizeof(json_map_string_int64));
        if (image->big_data_sizes == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }

    size_found = get_value_from_json_map_string_int64(image->big_data_sizes, key, &old_size);
    if (size_found) {
        update_json_map_string_int64(image->big_data_sizes, key, (int64_t)strlen(data));
    } else {
        append_json_map_string_int64(image->big_data_sizes, key, (int64_t)strlen(data));
    }


    if (image->big_data_digests == NULL) {
        image->big_data_digests = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
        if (image->big_data_digests == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }

    old_digest = get_value_from_json_map_string_string(image->big_data_digests, key);
    new_digest = calc_sha256_with_string(data);
    if (old_digest != NULL) {
        update_json_map_string_string(image->big_data_digests, key, new_digest);
    } else {
        append_json_map_string_string(image->big_data_digests, key, new_digest);
    }

    if (!size_found || old_size != (int64_t)strlen(data) || old_digest == NULL || strcmp(old_digest, new_digest) != 0) {
        *should_save = true;
    }

    for (i = 0; i < image->big_data_names_len; i++) {
        if (strcmp(image->big_data_names[i], key) == 0) {
            add_name = false;
            break;
        }
    }

    if (add_name) {
        if (append_big_data_name(image, key) != 0) {
            ERROR("Failed to append big data name");
            return -1;
        }
        *should_save = true;
    }

    if (strcmp(key, IMAGE_DIGEST_BIG_DATA_KEY) == 0) {
        if (old_digest != NULL && strcmp(old_digest, new_digest) != 0 && strcmp(old_digest, image->digest) != 0) {
            if (remove_image_from_digest_index(g_image_store, image, old_digest) != 0) {
                ERROR("Failed to remove the image from the list of images in the digest-based "
                      "index which corresponds to the old digest for this item, unless it's also the hard-coded digest");
                return -1;
            }
        }

        // add the image to the list of images in the digest-based index which
        // corresponds to the new digest for this item, unless it's already there
        digest_filter_images = (digest_image_t *)map_search(g_image_store->bydigest, (void *)new_digest);
        if (digest_filter_images != NULL) {
            pruned_images = digest_image_slice_without_value(digest_filter_images, image);
            if (pruned_images != NULL && digest_filter_images->images_len == pruned_images->images_len) {
                if (append_image_to_digest_images(&digest_filter_images, image) != 0) {
                    ERROR("Failed to append image to digest images");
                    return -1;
                }
            }
        }
    }

    return 0;
}

int image_store_set_big_data(const char *id, const char *key, const char *data)
{
    int ret = 0;
    storage_image *image = NULL;
    const char *image_id = NULL;
    char image_dir[PATH_MAX] = {0x00};
    char big_data_file[PATH_MAX] = {0x00};
    bool save = false;

    if (key == NULL || strlen(key) == 0) {
        ERROR("not a valid name for a big data item, can't set empty name for image big data item");
        return -1;
    }

    if (!is_read_write()) {
        ERROR("called a write method on a read-only store, "
              "not allowed to save data items associated with images at %s", g_image_store->dir);
        return -1;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("Failed to lookup image from store");
        ret = -1;
        goto out;
    }
    image_id = image->id;

    if (get_data_dir(g_image_store, image_id, image_dir, sizeof(image_dir)) != 0) {
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

    if (get_data_path(g_image_store, image_id, key, big_data_file, sizeof(big_data_file)) != 0) {
        ERROR("Failed to get big data file path: %s.", key);
        ret = -1;
        goto out;
    }

    if (save_file(big_data_file, data, 0600) != 0) {
        ERROR("Failed to save big data file: %s", big_data_file);
        ret = -1;
        goto out;
    }

    if (update_image_with_big_data(image, key, data, &save) != 0) {
        ERROR("Failed to update image big data");
        ret = -1;
        goto out;
    }

    if (save && save_image(g_image_store, image) != 0) {
        ERROR("Failed to complete persistence to disk");
        ret = -1;
        goto out;
    }

out:
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
    storage_image *image = NULL;
    storage_image *other_image = NULL;
    char **names = NULL;
    size_t names_len = 0;
    char **unique_names = NULL;
    size_t unique_names_len = 0;
    size_t i;

    if (g_image_store == NULL || id == NULL || name == NULL) {
        ERROR("Invalid input paratemer");
        return -1;
    }

    if (!is_read_write()) {
        ERROR("called a write method on a read-only store, not allowed to change image name assignments at %s",
              g_image_store->dir);
        return -1;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("image not known");
        ret = -1;
        goto out;
    }

    if (dup_array_of_strings((const char **)image->names, image->names_len, &names, &names_len) != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (append_name(&names, &names_len, name) != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (string_array_unique((const char **)names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    for (i = 0; i < image->names_len; i++) {
        if (!map_remove(g_image_store->byname, (void *)names[i])) {
            ERROR("Failed to remove image from ids map in image store");
            ret = -1;
            goto out;
        }
    }

    for (i = 0; i < unique_names_len; i++) {
        other_image = (storage_image *)map_search(g_image_store->byname, (void *)unique_names[i]);
        if (other_image != NULL) {
            if (remove_name(other_image, unique_names[i]) != 0) {
                ERROR("Failed to remove name from other image");
                ret = -1;
                goto out;
            }
            if (save_image(g_image_store, other_image) != 0) {
                ERROR("Failed to save other image");
                ret = -1;
                goto out;
            }
            if (!map_replace(g_image_store->byname, unique_names[i], (void *)image)) {
                ERROR("Failed to update byname map in image store");
                ret = -1;
                goto out;
            }
        }
    }

    image->names = unique_names;
    image->names_len = unique_names_len;
    unique_names = NULL;
    unique_names_len = 0;

    if (save_image(g_image_store, image) != 0) {
        ERROR("Failed to update image");
        ret = -1;
        goto out;
    }

out:
    util_free_array_by_len(names, names_len);
    util_free_array_by_len(unique_names, unique_names_len);
    return ret;
}

int image_store_set_names(const char *id, const char **names, size_t names_len)
{
    int ret = 0;
    storage_image *image = NULL;
    storage_image *other_image = NULL;
    char **unique_names = NULL;
    size_t unique_names_len = 0;
    size_t i;

    if (g_image_store == NULL || names == NULL || names_len == 0) {
        ERROR("Invalid input paratemer");
        return -1;
    }

    if (!is_read_write()) {
        ERROR("called a write method on a read-only store, not allowed to change image name assignments at %s",
              g_image_store->dir);
        return -1;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("image not known");
        ret = -1;
        goto out;
    }

    if (string_array_unique((const char **)names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    for (i = 0; i < image->names_len; i++) {
        if (!map_remove(g_image_store->byname, (void *)names[i])) {
            ERROR("Failed to remove image from ids map in image store");
            ret = -1;
            goto out;
        }
    }

    for (i = 0; i < unique_names_len; i++) {
        other_image = (storage_image *)map_search(g_image_store->byname, (void *)unique_names[i]);
        if (other_image != NULL && remove_name(other_image, unique_names[i]) != 0) {
            ERROR("Failed to remove name from other image");
            ret = -1;
            goto out;
        }
        if (!map_replace(g_image_store->byname, unique_names[i], (void *)image)) {
            ERROR("Failed to update byname map in image store");
            ret = -1;
            goto out;
        }
    }

    image->names = unique_names;
    image->names_len = unique_names_len;
    unique_names = NULL;
    unique_names_len = 0;

    if (save_image(g_image_store, image) != 0) {
        ERROR("Failed to update image");
        ret = -1;
        goto out;
    }

out:
    util_free_array_by_len(unique_names, unique_names_len);
    return ret;
}

int image_store_set_metadata(const char *id, const char *metadata)
{
    int ret = 0;
    storage_image *image = NULL;

    if (!is_read_write()) {
        ERROR("called a write method on a read-only store, "
              "not allowed to modify image metadata at %s", g_image_store->dir);
        return -1;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("image not known");
        ret = -1;
        goto out;
    }

    free(image->metadata);
    image->metadata = util_strdup_s(metadata);
    save_image(g_image_store, image);

out:
    return ret;
}

int image_store_set_load_time(const char *id,  const types_timestamp_t *time)
{
    int ret = 0;
    storage_image *image = NULL;
    char timebuffer[512] = { 0x00 };

    if (!is_read_write()) {
        ERROR("called a write method on a read-only store, "
              "not allowed to modify image metadata at %s", g_image_store->dir);
        return -1;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("image not known");
        ret = -1;
        goto out;
    }

    if (!get_time_buffer(time, timebuffer, sizeof(timebuffer))) {
        ERROR("Failed to get time buffer");
        ret = -1;
        goto out;
    }

    free(image->loaded);
    image->loaded = util_strdup_s(timebuffer);
    save_image(g_image_store, image);

out:
    return ret;
}

bool image_store_exists(const char *id)
{
    if (g_image_store == NULL || id == NULL) {
        return false;
    }

    return lookup(id) != NULL;
}

const storage_image *image_store_get_image(const char *id)
{
    storage_image *image = NULL;

    if (g_image_store == NULL || id == NULL) {
        return false;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("Image not known");
        return NULL;
    }

    return image;
}

char *image_store_big_data(const char *id, const char *key)
{
    storage_image *image = NULL;
    const char *image_id = NULL;
    size_t filesize;
    char *content = NULL;
    char filename[PATH_MAX] = {0x00};

    if (key == NULL || strlen(key) == 0) {
        ERROR("not a valid name for a big data item, can't retrieve image big data value for empty name");
        return NULL;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("Image not known");
        return NULL;
    }

    image_id = image->id;

    if (get_data_path(g_image_store, image_id, key, filename, sizeof(filename)) != 0) {
        ERROR("Failed to get big data file path: %s.", key);
        return NULL;
    }

    content = read_file(filename, &filesize);
    if (content == NULL) {
        ERROR("cannot read the file: %s", filename);
        return NULL;
    }

    return content;
}

int64_t image_store_big_data_size(const char *id, const char *key)
{
    storage_image *image = NULL;
    int64_t size;
    char *data = NULL;

    if (key == NULL || strlen(key) == 0) {
        ERROR("not a valid name for a big data item, can't retrieve image big data value for empty name");
        goto out;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("Image not known");
        goto out;
    }

    if (get_value_from_json_map_string_int64(image->big_data_sizes, key, &size)) {
        return size;
    }

    data = image_store_big_data(id, key);
    if (data != NULL) {
        if (image_store_set_big_data(id, key, data) != 0) {
            ERROR("Failed to set big data");
            goto out;
        }

        image = lookup(id);
        if (image == NULL) {
            ERROR("Image not known");
            goto out;
        }

        if (get_value_from_json_map_string_int64(image->big_data_sizes, key, &size)) {
            return size;
        }
    }

out:
    free(data);
    ERROR("size is not known");
    return -1;
}

const char *image_store_big_data_digest(const char *id, const char *key)
{
    storage_image *image = NULL;
    const char *digest = NULL;
    char *data = NULL;

    if (key == NULL || strlen(key) == 0) {
        ERROR("not a valid name for a big data item, can't retrieve image big data value for empty name");
        return NULL;
    }

    image = lookup(id);
    if (image == NULL) {
        ERROR("Image not known");
        return NULL;
    }

    digest = get_value_from_json_map_string_string(image->big_data_digests, key);
    if (digest != NULL) {
        return digest;
    }

    data = image_store_big_data(id, key);
    if (data != NULL) {
        if (image_store_set_big_data(id, key, data) != 0) {
            ERROR("Failed to set big data");
            goto out;
        }

        image = lookup(id);
        if (image == NULL) {
            ERROR("Image not known");
            goto out;
        }

        digest = get_value_from_json_map_string_string(image->big_data_digests, key);
        if (digest != NULL) {
            return digest;
        }
    }

out:
    ERROR("could not compute digest of item");
    return NULL;
}

int image_store_big_data_names(const char *id, char ***names, size_t *names_len)
{
    storage_image *image = NULL;

    image = lookup(id);
    if (image == NULL) {
        ERROR("Image not known");
        return -1;
    }

    if (dup_array_of_strings((const char **)image->names, image->names_len, names, names_len) != 0) {
        ERROR("Out of memory");
        return -1;
    }

    return 0;
}

const char *image_store_metadata(const char *id)
{
    storage_image *image = NULL;

    image = lookup(id);
    if (image == NULL) {
        ERROR("Image not known");
        return NULL;
    }

    return image->metadata;
}

int image_store_get_all_images(storage_image ***images, size_t *len)
{
    int ret = 0;
    size_t i;
    storage_image **copy_images = NULL;
    size_t copy_images_len = 0;

    if (g_image_store == NULL) {
        return -1;
    }

    copy_images_len = g_image_store->images_len;
    copy_images = (storage_image **)util_common_calloc_s(sizeof(storage_image *) * copy_images_len);
    if (copy_images == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < copy_images_len; i++) {
        copy_images[i] = copy_image(g_image_store->images[i]);
        if (copy_images[i] == NULL) {
            ERROR("Failed to copy image");
            ret = -1;
            goto out;
        }
    }

    *images = copy_images;
    *len = copy_images_len;

    return ret;

out:
    for (i = 0; i < copy_images_len; i++) {
        free_storage_image(copy_images[i]);
        copy_images[i] = NULL;
    }
    free(copy_images);
    return ret;
}

int image_store_get_images_by_digest(const char *digest, storage_image ***images, size_t *len)
{
    const digest_image_t *digest_images = (const digest_image_t *)map_search(g_image_store->bydigest, (void *)digest);
    if (digest_images == NULL) {
        ERROR("image not known");
        return -1;
    }

    *images = digest_images->images;
    *len = digest_images->images_len;

    return 0;
}
