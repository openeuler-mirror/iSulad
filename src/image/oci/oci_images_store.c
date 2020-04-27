/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide containers store definition
 ******************************************************************************/
#include <stdlib.h>
#include <pthread.h>

#include "oci_images_store.h"

#include "isula_libutils/log.h"
#include "utils.h"
#include "isulad_config.h"
#include "constants.h"
#include "oci_common_operators.h"

pthread_rwlock_t g_image_memory_rwlock;

typedef struct image_memory_store_t {
    map_t *map; // map id oci_image_t
    pthread_rwlock_t rwlock;
} image_memory_store;

typedef struct image_name_id_t {
    map_t *map; // map name id
    pthread_rwlock_t rwlock;
} image_name_id;

static image_memory_store *g_images_store = NULL;

static image_name_id *g_images_ids = NULL;

/* image_name_id_add */
static bool image_name_id_add(const char *name, const char *id)
{
    bool ret = false;
    if (pthread_rwlock_wrlock(&g_images_ids->rwlock) != 0) {
        ERROR("lock name index failed");
        return false;
    }
    ret = map_replace(g_images_ids->map, (void *)name, (void *)id);
    if (pthread_rwlock_unlock(&g_images_ids->rwlock) != 0) {
        ERROR("unlock name index failed");
        return false;
    }
    return ret;
}

/* image_name_id_remove */
static bool image_name_id_remove(const char *name)
{
    bool ret = false;
    if (pthread_rwlock_wrlock(&g_images_ids->rwlock) != 0) {
        ERROR("lock name index failed");
        return false;
    }
    ret = map_remove(g_images_ids->map, (void *)name);
    if (pthread_rwlock_unlock(&g_images_ids->rwlock) != 0) {
        ERROR("unlock name index failed");
        return false;
    }
    return ret;
}

static int remove_all_names(oci_image_t *image)
{
    int ret = 0;
    size_t i = 0;

    for (i = 0; i < image->info->repo_tags_len; i++) {
        if (!image_name_id_remove(image->info->repo_tags[i])) {
            ERROR("Failed to remove image name %s", image->info->repo_tags[i]);
            ret = -1;
        }
    }

    return ret;
}

static int register_all_names(imagetool_image *image_info)
{
    int ret = 0;
    size_t i = 0;

    for (i = 0; i < image_info->repo_tags_len; i++) {
        if (!image_name_id_add(image_info->repo_tags[i], image_info->id)) {
            size_t j;
            for (j = 0; j < i; j++) {
                (void)image_name_id_remove(image_info->repo_tags[j]);
            }
            ERROR("Failed to register all names of image %s", image_info->id);
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

/* image name id free */
static void image_name_id_free(image_name_id *images_ids)
{
    if (images_ids == NULL) {
        return;
    }
    map_free(images_ids->map);
    images_ids->map = NULL;
    pthread_rwlock_destroy(&(images_ids->rwlock));
    free(images_ids);
}

/* image name id new */
static image_name_id *image_name_id_new(void)
{
    int ret;
    image_name_id *tmp = NULL;

    tmp = util_common_calloc_s(sizeof(image_name_id));
    if (tmp == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ret = pthread_rwlock_init(&(tmp->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init name image name id rwlock");
        free(tmp);
        return NULL;
    }
    tmp->map = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (tmp->map == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }
    return tmp;
error_out:
    image_name_id_free(tmp);
    return NULL;
}

/* get image id by name */
char *image_id_get_by_name(const char *name)
{
    char *id = NULL;
    if (name == NULL) {
        return id;
    }
    if (pthread_rwlock_rdlock(&g_images_ids->rwlock) != 0) {
        ERROR("lock name index failed");
        return id;
    }
    id = map_search(g_images_ids->map, (void *)name);
    if (pthread_rwlock_unlock(&g_images_ids->rwlock) != 0) {
        ERROR("unlock name index failed");
    }
    return id;
}

/* image_name_id init */
int image_name_id_init(void)
{
    g_images_ids = image_name_id_new();
    if (g_images_ids == NULL) {
        return -1;
    }
    return 0;
}

/* memory store map kvfree */
static void oci_image_memory_store_map_kvfree(void *key, void *value)
{
    free(key);

    oci_image_unref((oci_image_t *)value);
}

/* memory store free */
static void oci_images_memory_store_free(image_memory_store *store)
{
    if (store == NULL) {
        return;
    }
    map_free(store->map);
    store->map = NULL;
    pthread_rwlock_destroy(&(store->rwlock));
    free(store);
}

/* memory store new */
static image_memory_store *oci_images_memory_store_new(void)
{
    int ret;
    image_memory_store *store = NULL;

    store = util_common_calloc_s(sizeof(image_memory_store));
    if (store == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ret = pthread_rwlock_init(&(store->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init memory store rwlock");
        free(store);
        return NULL;
    }
    store->map = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, oci_image_memory_store_map_kvfree);
    if (store->map == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }
    return store;
error_out:
    oci_images_memory_store_free(store);
    return NULL;
}

/* oci image store add or update */
static bool oci_image_store_add_or_update(const char *id, imagetool_image *image_info)
{
    bool ret = false;
    oci_image_t *image = NULL;

    if (pthread_rwlock_wrlock(&g_images_store->rwlock)) {
        ERROR("lock memory store failed");
        free_imagetool_image(image_info);
        return false;
    }

    /* Replace only but not allocate a new one if exist.If allocate a
     * new object,locker will be invalid and cannot lock image anymore. */
    image = map_search(g_images_store->map, (void *)id);
    if (image == NULL) {
        image = oci_image_new(image_info);
        if (image == NULL) {
            free_imagetool_image(image_info);
            ERROR("oci image new failed");
            goto out;
        }
        ret = map_replace(g_images_store->map, (void *)id, (void *)image);
        if (!ret) {
            oci_image_free(image);
            ERROR("oci image new failed");
            goto out;
        }
    } else {
        free_imagetool_image(image->info);
        image->info = image_info;
        ret = true;
    }

out:

    if (pthread_rwlock_unlock(&g_images_store->rwlock)) {
        ERROR("unlock memory store failed");
        return false;
    }
    return ret;
}

/* oci images store remove */
static bool oci_images_store_remove(const char *id)
{
    bool ret = false;
    if (pthread_rwlock_wrlock(&g_images_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return false;
    }
    ret = map_remove(g_images_store->map, (void *)id);
    if (pthread_rwlock_unlock(&g_images_store->rwlock) != 0) {
        ERROR("unlock memory store failed");
        return false;
    }
    return ret;
}

static int register_new_oci_image(imagetool_image *image_info)
{
    int ret = 0;

    if (!oci_image_store_add_or_update(image_info->id, image_info)) {
        ret = -1;
        goto out;
    }

    ret = register_all_names(image_info);
    if (ret != 0) {
        oci_images_store_remove(image_info->id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int update_old_image_by_id(const char *id)
{
    int ret = 0;
    imagetool_image *image_info;

    image_info = oci_get_image_info_by_name(id);
    if (image_info == NULL) {
        WARN("Failed to status old oci image %s, may be remeved", id);
        ret = 0;
        goto out;
    }

    ret = register_new_oci_image(image_info);
out:
    return ret;
}

static void remove_graph_root()
{
    int ret = 0;
    char *graph_root = NULL;

    //TODO replce funtion with storge module uninstall
    //graph_root = conf_get_graph_rootpath();
    if (graph_root == NULL) {
        ERROR("Failed to get image graph root path");
        return;
    }

    ret = util_recursive_rmdir(graph_root, 0);
    if (ret != 0) {
        ERROR("Failed to delete image graph root directory %s: %s", graph_root, strerror(errno));
    }

    free(graph_root);
}

/* WARNING:This function may free all memory of *all_images if failed
 * or change value of *all_images if success. */
static int try_list_oci_images(const char *check_file, imagetool_images_list **all_images)
{
    int ret = 0;
    im_list_request *im_request = NULL;
    int retry_count = 0;
    int max_retry = 3;
    bool list_images_ok = false;
    bool need_check = false;

    if (util_file_exists(check_file) && conf_get_image_layer_check_flag()) {
        INFO("OCI image checked flag %s exist, need to check image integrity", check_file);
        need_check = true;
    }

    im_request = util_common_calloc_s(sizeof(im_list_request));
    if (im_request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    im_request->check = need_check;

    do {
        ret = storage_get_all_images(all_images);
        if (ret != 0 || *all_images == NULL) {
            list_images_ok = false;
            if (retry_count < max_retry) {
                remove_graph_root(); /* remove graph root */
                retry_count++;
                free_imagetool_images_list(*all_images);
                *all_images = NULL;
            }
        } else {
            list_images_ok = true;
        }
    } while (!list_images_ok && retry_count < max_retry);
    if (!list_images_ok) {
        ERROR("Failed to load all oci images and retry %d times", retry_count);
        ret = -1;
        goto out;
    }

out:
    free_im_list_request(im_request);

    return ret;
}

int load_all_oci_images()
{
    int ret = 0;
    int fd = -1;
    size_t i = 0;
    char *check_file = NULL;
    imagetool_images_list *all_images = NULL;
    imagetool_image *tmp = NULL;

    check_file = conf_get_graph_check_flag_file();
    if (check_file == NULL) {
        ERROR("Failed to get oci image checked flag");
        ret = -1;
        goto out;
    }

    ret = try_list_oci_images(check_file, &all_images);
    if (ret < 0) {
        goto out;
    }

    ret = util_build_dir(check_file);
    if (ret) {
        ERROR("Failed to create directory for checked flag file: %s", check_file);
        ret = -1;
        goto out;
    }

    fd = util_open(check_file, O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    if (fd < 0) {
        ERROR("Failed to create checked file: %s", check_file);
        ret = -1;
        goto out;
    }

    for (i = 0; i < all_images->images_len; i++) {
        tmp = all_images->images[i];
        all_images->images[i] = NULL;
        ret = register_new_oci_image(tmp);
        if (ret != 0) {
            ERROR("Failed to register oci image");
            ret = -1;
            goto out;
        }
    }

out:
    if (fd >= 0) {
        close(fd);
    }
    free(check_file);
    free_imagetool_images_list(all_images);
    return ret;
}

/* oci images store list */
int oci_images_store_list(oci_image_t ***out, size_t *size)
{
    int ret = -1;
    size_t i;
    oci_image_t **images = NULL;
    map_itor *itor = NULL;

    if (out == NULL || size == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (pthread_rwlock_rdlock(&g_images_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return -1;
    }

    *size = map_size(g_images_store->map);
    if (*size == 0) {
        ret = 0;
        goto unlock;
    }

    images = util_smart_calloc_s(sizeof(oci_image_t *), (*size));
    if (images == NULL) {
        ERROR("Out of memory");
        goto unlock;
    }

    itor = map_itor_new(g_images_store->map);
    if (itor == NULL) {
        ERROR("Out of memory");
        goto unlock;
    }

    for (i = 0; map_itor_valid(itor) && i < *size; map_itor_next(itor), i++) {
        images[i] = map_itor_value(itor);
        oci_image_refinc(images[i]);
    }
    ret = 0;
unlock:
    if (pthread_rwlock_unlock(&g_images_store->rwlock)) {
        ERROR("unlock memory store failed");
    }
    map_itor_free(itor);
    if (ret != 0) {
        free(images);
        *size = 0;
        images = NULL;
    }
    *out = images;
    return ret;
}

/* oci images store size */
size_t oci_images_store_size(void)
{
    size_t count = 0;
    if (pthread_rwlock_rdlock(&g_images_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return count;
    }
    count = map_size(g_images_store->map);
    if (pthread_rwlock_unlock(&g_images_store->rwlock) != 0) {
        ERROR("unlock memory store failed");
        return count;
    }
    return count;
}

/* oci images store init */
int oci_images_store_init(void)
{
    if (pthread_rwlock_init(&g_image_memory_rwlock, NULL) != 0) {
        ERROR("Failed to init image memory rwlock");
        return -1;
    }

    g_images_store = oci_images_memory_store_new();
    if (g_images_store == NULL) {
        pthread_rwlock_destroy(&g_image_memory_rwlock);
        return -1;
    }
    return 0;
}

/* oci images store get by image id */
oci_image_t *oci_images_store_get_by_id(const char *id)
{
    oci_image_t *image = NULL;
    if (id == NULL) {
        return NULL;
    }
    if (pthread_rwlock_rdlock(&g_images_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return image;
    }
    image = map_search(g_images_store->map, (void *)id);
    oci_image_refinc(image);
    if (pthread_rwlock_unlock(&g_images_store->rwlock) != 0) {
        ERROR("unlock memory store failed");
        return image;
    }
    return image;
}

/* oci images store get image by image name */
oci_image_t *oci_images_store_get_by_name(const char *name)
{
    char *id = NULL;

    if (name == NULL) {
        ERROR("No image name supplied");
        return NULL;
    }

    id = image_id_get_by_name(name);
    if (id == NULL) {
        INFO("Could not find entity for %s", name);
        return NULL;
    }

    return oci_images_store_get_by_id(id);
}

/* oci images store get image by prefix */
oci_image_t *oci_images_store_get_by_prefix(const char *prefix)
{
    oci_image_t *image = NULL;
    map_itor *itor = NULL;
    bool ret = false;
    char *id = NULL;

    if (prefix == NULL) {
        return NULL;
    }
    if (pthread_rwlock_rdlock(&g_images_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return NULL;
    }

    itor = map_itor_new(g_images_store->map);
    if (itor == NULL) {
        ERROR("Out of memory");
        ret = false;
        goto unlock;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        id = map_itor_key(itor);
        if (id == NULL) {
            ERROR("Out of memory");
            ret = false;
            goto unlock;
        }
        if (strncmp(id, prefix, strlen(prefix)) == 0) {
            if (image != NULL) {
                ERROR("Multiple IDs found with provided prefix: %s", prefix);
                ret = false;
                goto unlock;
            } else {
                image = map_itor_value(itor);
            }
        }
    }

    ret = true;
    oci_image_refinc(image);

unlock:
    if (pthread_rwlock_unlock(&g_images_store->rwlock) != 0) {
        ERROR("unlock memory store failed");
    }
    map_itor_free(itor);
    if (!ret) {
        image = NULL;
    }
    return image;
}

// oci_images_store_get_nolock looks for a image using the provided information, which could be
// one of the following inputs from the caller:
//  - A full image ID, which will exact match a image in daemon's list
//  - A image name, which will only exact match via the oci_images_store_get_by_name() function
//  - A partial image ID prefix (e.g. short ID) of any length that is
//    unique enough to only return a single container object
//  If none of these searches succeed, an error is returned
oci_image_t *oci_images_store_get_nolock(const char *id_or_name)
{
    oci_image_t *image = NULL;

    if (id_or_name == NULL) {
        ERROR("No container name or ID supplied");
        return NULL;
    }

    // A full image ID, which will exact match a container in daemon's list
    image = oci_images_store_get_by_id(id_or_name);
    if (image != NULL) {
        return image;
    }

    // A image name, which will only exact match via the oci_images_store_get_by_name() function
    image = oci_images_store_get_by_name(id_or_name);
    if (image != NULL) {
        return image;
    }

    // A partial container ID prefix
    image = oci_images_store_get_by_prefix(id_or_name);
    if (image != NULL) {
        return image;
    }

    return NULL;
}

/* Always do lock when get images from images store. */
oci_image_t *oci_images_store_get(const char *id_or_name)
{
    oci_image_t *img = NULL;

    if (id_or_name == NULL) {
        ERROR("No container name or ID supplied");
        return NULL;
    }

    if (pthread_rwlock_wrlock(&g_image_memory_rwlock) != 0) {
        ERROR("lock image memory failed");
        return NULL;
    }

    img = oci_images_store_get_nolock(id_or_name);

    if (pthread_rwlock_unlock(&g_image_memory_rwlock) != 0) {
        ERROR("unlock memory store failed");
    }

    return img;
}

int register_new_oci_image_into_memory(const char *name)
{
    int ret = 0;
    imagetool_image *image_info = NULL;
    oci_image_t *old_image = NULL;

    if (name == NULL) {
        ERROR("Empty image name");
        return -1;
    }

    if (pthread_rwlock_wrlock(&g_image_memory_rwlock) != 0) {
        ERROR("lock image memory failed");
        return -1;
    }

    image_info = oci_get_image_info_by_name(name);
    if (image_info == NULL) {
        ERROR("Failed to get oci image %s informations", name);
        ret = -1;
        goto out;
    }

    old_image = oci_images_store_get_nolock(name);
    if (old_image == NULL) {
        ret = register_new_oci_image(image_info);
        if (ret != 0) {
            ERROR("Failed to register oci image %s", name);
            ret = -1;
        }
        goto out;
    }

    if (strcmp(old_image->info->id, image_info->id) != 0) {
        ret = register_new_oci_image(image_info);
        if (ret != 0) {
            ERROR("Failed to register oci image %s", name);
            ret = -1;
            goto out;
        }

        ret = update_old_image_by_id(old_image->info->id);
        if (ret != 0) {
            ERROR("Failed to update old oci image %s", old_image->info->id);
            ret = -1;
            goto out;
        }
    } else {
        /* we have the same image already, just free the image_info memory */
        free_imagetool_image(image_info);
    }

out:
    oci_image_unref(old_image);

    if (pthread_rwlock_unlock(&g_image_memory_rwlock) != 0) {
        ERROR("unlock memory store failed");
        ret = -1;
    }

    return ret;
}

int remove_oci_image_from_memory(const char *name_or_id)
{
    int ret = 0;
    oci_image_t *image = NULL;
    imagetool_image *image_info = NULL;

    if (name_or_id == NULL) {
        ERROR("No container name or ID supplied");
        return -1;
    }

    if (pthread_rwlock_wrlock(&g_image_memory_rwlock) != 0) {
        ERROR("lock image memory failed");
        return -1;
    }

    image = oci_images_store_get_nolock(name_or_id);
    if (image == NULL) {
        INFO("No such image exist %s", name_or_id);
        ret = 0;
        goto free_out;
    }

    ret = remove_all_names(image);
    if (ret != 0) {
        ERROR("Failed to remove all names of image %s from name-id store", image->info->id);
        ret = -1;
        goto free_out;
    }

    image_info = oci_get_image_info_by_name(image->info->id);
    if (image_info == NULL) {
        WARN("Failed to status old oci image %s, may be remeved", image->info->id);

        if (oci_images_store_remove(image->info->id) != true) {
            ERROR("Failed to remove image %s from store", image->info->id);
            ret = -1;
            goto free_out;
        }

        ret = 0;
        goto free_out;
    }

    ret = register_new_oci_image(image_info);

free_out:
    oci_image_unref(image);

    if (pthread_rwlock_unlock(&g_image_memory_rwlock) != 0) {
        ERROR("unlock memory store failed");
        ret = -1;
    }

    return ret;
}

int oci_image_store_init()
{
    int ret = 0;

    ret = oci_images_store_init();
    if (ret != 0) {
        ERROR("Failed to init oci images store");
        goto out;
    }

    ret = image_name_id_init();
    if (ret != 0) {
        ERROR("Failed to init oci name id store");
        goto out;
    }

    ret = load_all_oci_images();

out:
    return ret;
}
