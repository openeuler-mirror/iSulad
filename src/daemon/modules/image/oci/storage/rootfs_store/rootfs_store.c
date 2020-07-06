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
 * Description: provide container rootfs store functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "rootfs_store.h"

#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sha256.h>
#include <isula_libutils/json_common.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>

#include "utils.h"
#include "utils_images.h"
#include "isula_libutils/log.h"
#include "constants.h"
#include "map.h"
#include "linked_list.h"
#include "rootfs.h"
#include "storage.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_regex.h"
#include "utils_string.h"
#include "utils_timestamp.h"

#define CONTAINER_JSON "container.json"

typedef struct rootfs_store {
    pthread_rwlock_t rwlock;
    char *dir;
    struct linked_list rootfs_list;
    size_t rootfs_list_len;
    map_t *byid;
    map_t *bylayer;
    map_t *byname;

    bool loaded;
} rootfs_store_t;

enum lock_type { SHARED = 0, EXCLUSIVE };

rootfs_store_t *g_rootfs_store = NULL;

static inline bool rootfs_store_lock(enum lock_type type)
{
    int nret = 0;

    if (type == SHARED) {
        nret = pthread_rwlock_rdlock(&g_rootfs_store->rwlock);
    } else {
        nret = pthread_rwlock_wrlock(&g_rootfs_store->rwlock);
    }

    if (nret != 0) {
        ERROR("Lock memory store failed: %s", strerror(nret));
        return false;
    }

    return true;
}

static inline void rootfs_store_unlock()
{
    int nret = 0;

    nret = pthread_rwlock_unlock(&g_rootfs_store->rwlock);
    if (nret != 0) {
        FATAL("Unlock memory store failed: %s", strerror(nret));
    }
}

static void free_rootfs_store(rootfs_store_t *store)
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

    (void)map_free(store->bylayer);
    store->bylayer = NULL;

    (void)map_free(store->byname);
    store->byname = NULL;

    linked_list_for_each_safe(item, &(store->rootfs_list), next) {
        linked_list_del(item);
        rootfs_ref_dec((cntrootfs_t *)item->elem);
        free(item);
        item = NULL;
    }

    store->rootfs_list_len = 0;

    free(store);
}

void rootfs_store_free()
{
    free_rootfs_store(g_rootfs_store);
    g_rootfs_store = NULL;
}

static void rootfs_store_field_kvfree(void *key, void *value)
{
    (void)value;
    free(key);
}

static inline int get_data_dir(const char *id, char *path, size_t len)
{
    int nret = snprintf(path, len, "%s/%s", g_rootfs_store->dir, id);
    return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
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
        ERROR("Failed to get rootfs data dir: %s", id);
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

static int do_append_container(storage_rootfs *c)
{
    cntrootfs_t *cntr = NULL;
    struct linked_list *item = NULL;

    cntr = new_rootfs(c);
    if (cntr == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    item = util_smart_calloc_s(sizeof(struct linked_list), 1);
    if (item == NULL) {
        ERROR("Out of memory");
        free_rootfs_t(cntr);
        return -1;
    }

    linked_list_add_elem(item, cntr);
    linked_list_add_tail(&g_rootfs_store->rootfs_list, item);
    g_rootfs_store->rootfs_list_len++;

    return 0;
}

static int append_container_by_directory(const char *container_dir)
{
    int ret = 0;
    int nret;
    char container_path[PATH_MAX] = { 0x00 };
    storage_rootfs *c = NULL;
    parser_error err = NULL;

    nret = snprintf(container_path, sizeof(container_path), "%s/%s", container_dir, CONTAINER_JSON);
    if (nret < 0 || (size_t)nret >= sizeof(container_path)) {
        ERROR("Failed to get container path");
        return -1;
    }

    c = storage_rootfs_parse_file(container_path, NULL, &err);
    if (c == NULL) {
        ERROR("Failed to parse container path: %s", err);
        return -1;
    }

    if (do_append_container(c) != 0) {
        ERROR("Failed to append container");
        ret = -1;
        goto out;
    }

    c = NULL;

out:
    free_storage_rootfs(c);
    free(err);
    return ret;
}

static int get_containers_from_json()
{
    int ret = 0;
    int nret;
    char **container_dirs = NULL;
    size_t container_dirs_num = 0;
    size_t i;
    char *id_patten = "^[a-f0-9]{64}$";
    char container_path[PATH_MAX] = { 0x00 };

    if (!rootfs_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock container store");
        return -1;
    }

    ret = util_list_all_subdir(g_rootfs_store->dir, &container_dirs);
    if (ret != 0) {
        ERROR("Failed to get container directorys");
        goto out;
    }
    container_dirs_num = util_array_len((const char **)container_dirs);

    for (i = 0; i < container_dirs_num; i++) {
        if (util_reg_match(id_patten, container_dirs[i]) != 0) {
            DEBUG("Container's json is placed inside container's data directory, so skip any other file or directory: %s",
                  container_dirs[i]);
            continue;
        }

        DEBUG("Restore the containers:%s", container_dirs[i]);
        nret = snprintf(container_path, sizeof(container_path), "%s/%s", g_rootfs_store->dir, container_dirs[i]);
        if (nret < 0 || (size_t)nret >= sizeof(container_path)) {
            ERROR("Failed to get container path");
            ret = -1;
            goto out;
        }

        if (append_container_by_directory(container_path) != 0) {
            ERROR("Found container path but load json failed: %s", container_dirs[i]);
            ret = -1;
            goto out;
        }
    }

out:
    util_free_array(container_dirs);
    rootfs_store_unlock();
    return ret;
}

static int remove_name(cntrootfs_t *cntr, const char *name)
{
    size_t i;
    size_t new_size;
    size_t count = 0;
    size_t index = 0;
    char **tmp_names = NULL;

    if (cntr == NULL || name == NULL) {
        return 0;
    }

    for (i = 0; i < cntr->srootfs->names_len; i++) {
        if (strcmp(cntr->srootfs->names[i], name) == 0) {
            count++;
        }
    }

    if (cntr->srootfs->names_len == count) {
        util_free_array_by_len(cntr->srootfs->names, cntr->srootfs->names_len);
        cntr->srootfs->names = NULL;
        cntr->srootfs->names_len = 0;
        return 0;
    }

    new_size = (cntr->srootfs->names_len - count) * sizeof(char *);
    tmp_names = (char **)util_common_calloc_s(new_size);
    if (tmp_names == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < cntr->srootfs->names_len; i++) {
        if (strcmp(cntr->srootfs->names[i], name) != 0) {
            tmp_names[index++] = util_strdup_s(cntr->srootfs->names[i]);
        }
        free(cntr->srootfs->names[i]);
        cntr->srootfs->names[i] = NULL;
    }

    free(cntr->srootfs->names);
    cntr->srootfs->names = tmp_names;
    cntr->srootfs->names_len = index;
    tmp_names = NULL;

    return 0;
}

static int get_container_path(const char *id, char *path, size_t len)
{
    int nret = snprintf(path, len, "%s/%s/%s", g_rootfs_store->dir, id, CONTAINER_JSON);

    return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
}

static int save_rootfs(cntrootfs_t *cntr)
{
    int ret = 0;
    char container_path[PATH_MAX] = { 0x00 };
    char container_dir[PATH_MAX] = { 0x00 };
    parser_error err = NULL;
    char *json_data = NULL;

    if (get_container_path(cntr->srootfs->id, container_path, sizeof(container_path)) != 0) {
        ERROR("Failed to get container path by id: %s", cntr->srootfs->id);
        return -1;
    }

    strcpy(container_dir, container_path);
    ret = util_mkdir_p(dirname(container_dir), ROOTFS_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Failed to create container directory %s.", container_path);
        return -1;
    }

    json_data = storage_rootfs_generate_json(cntr->srootfs, NULL, &err);
    if (json_data == NULL) {
        ERROR("Failed to generate container json path string:%s", err ? err : " ");
        ret = -1;
        goto out;
    }

    if (util_atomic_write_file(container_path, json_data, strlen(json_data), SECURE_CONFIG_FILE_MODE) != 0) {
        ERROR("Failed to save container json file");
        ret = -1;
        goto out;
    }

out:
    free(json_data);
    free(err);

    return ret;
}

static int load_container_to_store_field(cntrootfs_t *cntr)
{
    int ret = 0;
    bool should_save = false;
    size_t i;

    if (!map_replace(g_rootfs_store->byid, (void *)cntr->srootfs->id, (void *)cntr)) {
        ERROR("Failed to insert container to id index");
        return -1;
    }

    if (!map_replace(g_rootfs_store->bylayer, (void *)cntr->srootfs->layer, (void *)cntr)) {
        ERROR("Failed to insert container to layer index");
        return -1;
    }

    for (i = 0; i < cntr->srootfs->names_len; i++) {
        cntrootfs_t *conflict_container =
            (cntrootfs_t *)map_search(g_rootfs_store->byname, (void *)cntr->srootfs->names[i]);
        if (conflict_container != NULL) {
            if (remove_name(conflict_container, cntr->srootfs->names[i]) != 0) {
                ERROR("Failed to remove name from conflict container");
                ret = -1;
                goto out;
            }
            should_save = true;
        }
        if (!map_replace(g_rootfs_store->byname, (void *)cntr->srootfs->names[i], (void *)cntr)) {
            ERROR("Failed to insert containes to name index");
            ret = -1;
            goto out;
        }
    }

    if (should_save && save_rootfs(cntr) != 0) {
        ERROR("Failed to save container");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int rootfs_store_load()
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (g_rootfs_store->loaded) {
        DEBUG("Do not need reload if daemon");
        return 0;
    }

    if (get_containers_from_json() != 0) {
        ERROR("Failed to get containers from json");
        return -1;
    }

    linked_list_for_each_safe(item, &(g_rootfs_store->rootfs_list), next) {
        if (load_container_to_store_field((cntrootfs_t *)item->elem) != 0) {
            ERROR("Failed to load container to container store");
            return -1;
        }
    }

    g_rootfs_store->loaded = true;

    return 0;
}

static char *get_rootfs_store_root_path(const struct storage_module_init_options *opts)
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

    nret = asprintf(&root_dir, "%s/%s-containers", opts->storage_root, opts->driver_name);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create root path failed");
        free(root_dir);
        root_dir = NULL;
    }

    return root_dir;
}

int rootfs_store_init(struct storage_module_init_options *opts)
{
    int ret = 0;
    char *root_dir = NULL;

    if (g_rootfs_store != NULL) {
        ERROR("Container store has already been initialized");
        return -1;
    }

    root_dir = get_rootfs_store_root_path(opts);
    if (root_dir == NULL) {
        return ret;
    }

    ret = util_mkdir_p(root_dir, ROOTFS_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Unable to create container store directory %s.", root_dir);
        ret = -1;
        goto out;
    }

    g_rootfs_store = (rootfs_store_t *)util_common_calloc_s(sizeof(rootfs_store_t));
    if (g_rootfs_store == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = pthread_rwlock_init(&(g_rootfs_store->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init container store rwlock");
        ret = -1;
        goto out;
    }

    g_rootfs_store->dir = root_dir;
    root_dir = NULL;

    g_rootfs_store->rootfs_list_len = 0;
    linked_list_init(&g_rootfs_store->rootfs_list);

    g_rootfs_store->byid = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, rootfs_store_field_kvfree);
    if (g_rootfs_store->byid == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    g_rootfs_store->bylayer = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, rootfs_store_field_kvfree);
    if (g_rootfs_store->bylayer == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    g_rootfs_store->byname = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, rootfs_store_field_kvfree);
    if (g_rootfs_store->byname == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = rootfs_store_load();
    if (ret != 0) {
        ERROR("Failed to load container store");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free_rootfs_store(g_rootfs_store);
        g_rootfs_store = NULL;
    }
    free(root_dir);
    return ret;
}

static char *generate_random_container_id()
{
    char *id = NULL;
    const size_t max_container_id_len = 64;
    const size_t max_retry_cnt = 5;
    size_t i = 0;

    id = util_smart_calloc_s(sizeof(char), max_container_id_len + 1);
    if (id == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (; i < max_retry_cnt; i++) {
        if (util_generate_random_str(id, max_container_id_len) != 0) {
            ERROR("Generate random str failed");
            goto err_out;
        }
        cntrootfs_t *cntr = map_search(g_rootfs_store->byid, (void *)id);
        if (cntr == NULL) {
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

static int copy_id_map(storage_rootfs *c, const struct storage_rootfs_options *rootfs_opts)
{
    int ret = 0;
    size_t i;
    storage_rootfs_uidmap_element **uid_map = NULL;
    size_t uid_map_len = 0;
    storage_rootfs_gidmap_element **gid_map = NULL;
    size_t gid_map_len = 0;

    if (rootfs_opts == NULL) {
        return 0;
    }

    if (rootfs_opts->id_mapping_opts.uid_map_len != 0) {
        if (rootfs_opts->id_mapping_opts.uid_map_len >= SIZE_MAX / sizeof(storage_rootfs_uidmap_element *)) {
            ERROR("Too many id map");
            return -1;
        }
        uid_map = (storage_rootfs_uidmap_element **)util_common_calloc_s(sizeof(storage_rootfs_uidmap_element *) *
                                                                         rootfs_opts->id_mapping_opts.uid_map_len);
        if (uid_map == NULL) {
            ERROR("Out of memory");
            return -1;
        }

        for (i = 0; i < rootfs_opts->id_mapping_opts.uid_map_len; i++) {
            uid_map[i] = (storage_rootfs_uidmap_element *)util_common_calloc_s(sizeof(storage_rootfs_uidmap_element));
            if (uid_map[i] == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
            uid_map[i]->container_id = rootfs_opts->id_mapping_opts.uid_map->container_id;
            uid_map[i]->host_id = rootfs_opts->id_mapping_opts.uid_map->host_id;
            uid_map[i]->size = rootfs_opts->id_mapping_opts.uid_map->size;
            uid_map_len++;
        }
    }

    if (rootfs_opts->id_mapping_opts.gid_map_len != 0) {
        if (rootfs_opts->id_mapping_opts.gid_map_len >= SIZE_MAX / sizeof(storage_rootfs_gidmap_element *)) {
            ERROR("Too many id map");
            return -1;
        }
        gid_map = (storage_rootfs_gidmap_element **)util_common_calloc_s(sizeof(storage_rootfs_gidmap_element *) *
                                                                         rootfs_opts->id_mapping_opts.gid_map_len);
        if (gid_map == NULL) {
            ERROR("Out of memory");
            return -1;
        }

        for (i = 0; i < rootfs_opts->id_mapping_opts.gid_map_len; i++) {
            gid_map[i] = (storage_rootfs_gidmap_element *)util_common_calloc_s(sizeof(storage_rootfs_gidmap_element));
            if (gid_map[i] == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
            gid_map[i]->container_id = rootfs_opts->id_mapping_opts.gid_map->container_id;
            gid_map[i]->host_id = rootfs_opts->id_mapping_opts.gid_map->host_id;
            gid_map[i]->size = rootfs_opts->id_mapping_opts.gid_map->size;
            gid_map_len++;
        }
    }

    c->uidmap = uid_map;
    c->uidmap_len = gid_map_len;
    uid_map = NULL;

    c->gidmap = gid_map;
    c->gidmap_len = gid_map_len;
    gid_map = NULL;

    return 0;

out:
    for (i = 0; i < uid_map_len; i++) {
        free(uid_map[i]);
        uid_map[i] = NULL;
    }
    free(uid_map);

    for (i = 0; i < gid_map_len; i++) {
        free(gid_map[i]);
        gid_map[i] = NULL;
    }
    free(gid_map);

    return ret;
}

static storage_rootfs *new_storage_rootfs(const char *id, const char *image, char **unique_names,
                                          size_t unique_names_len, const char *layer, const char *metadata,
                                          struct storage_rootfs_options *rootfs_opts)
{
    int ret = 0;
    char timebuffer[TIME_STR_SIZE] = { 0x00 };
    storage_rootfs *c = NULL;

    c = (storage_rootfs *)util_common_calloc_s(sizeof(storage_rootfs));
    if (c == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    c->id = util_strdup_s(id);

    c->names = unique_names;
    c->names_len = unique_names_len;

    c->image = util_strdup_s(image);
    c->layer = util_strdup_s(layer);
    c->metadata = util_strdup_s(metadata);

    if (!get_now_time_buffer(timebuffer, sizeof(timebuffer))) {
        ERROR("Failed to get now time string");
        ret = -1;
        goto out;
    }
    c->created = util_strdup_s(timebuffer);

    if (copy_id_map(c, rootfs_opts) != 0) {
        ERROR("Failed to copy UID&GID map");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free_storage_rootfs(c);
        c = NULL;
    }
    return c;
}

static int rootfs_store_append_container_rootfs(const char *id, const char *layer, const char **unique_names,
                                                size_t unique_names_len, cntrootfs_t *cntr)
{
    int ret = 0;
    size_t i = 0;
    struct linked_list *item = NULL;

    item = util_smart_calloc_s(sizeof(struct linked_list), 1);
    if (item == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    linked_list_add_elem(item, cntr);
    linked_list_add_tail(&g_rootfs_store->rootfs_list, item);
    g_rootfs_store->rootfs_list_len++;

    if (!map_insert(g_rootfs_store->byid, (void *)id, (void *)cntr)) {
        ERROR("Failed to insert container to container store");
        ret = -1;
        goto out;
    }

    if (!map_insert(g_rootfs_store->bylayer, (void *)layer, (void *)cntr)) {
        ERROR("Failed to insert container to container store");
        ret = -1;
        goto out;
    }

    for (i = 0; i < unique_names_len; i++) {
        if (!map_insert(g_rootfs_store->byname, (void *)unique_names[i], (void *)cntr)) {
            ERROR("Failed to insert container to container store's name index");
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

char *rootfs_store_create(const char *id, const char **names, size_t names_len, const char *image, const char *layer,
                          const char *metadata, struct storage_rootfs_options *rootfs_opts)
{
    int ret = 0;
    char *dst_id = NULL;
    char **unique_names = NULL;
    size_t unique_names_len = 0;
    cntrootfs_t *cntr = NULL;
    storage_rootfs *c = NULL;

    if (g_rootfs_store == NULL) {
        ERROR("Container store is not ready");
        return NULL;
    }

    if (!rootfs_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock container store, not allowed to create new containers");
        return NULL;
    }

    if (id == NULL) {
        dst_id = generate_random_container_id();
    } else {
        dst_id = util_strdup_s(id);
    }

    if (dst_id == NULL) {
        ERROR("Out of memory or generate random container id failed");
        ret = -1;
        goto out;
    }

    if (map_search(g_rootfs_store->byid, (void *)dst_id) != NULL) {
        ERROR("ID is already in use: %s", dst_id);
        ret = -1;
        goto out;
    }

    if (util_string_array_unique(names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    c = new_storage_rootfs(dst_id, image, unique_names, unique_names_len, layer, metadata, rootfs_opts);
    if (c == NULL) {
        ERROR("Failed to generate new storage container");
        ret = -1;
        goto out;
    }

    cntr = new_rootfs(c);
    if (cntr == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (rootfs_store_append_container_rootfs(dst_id, layer, (const char **)unique_names, unique_names_len, cntr) != 0) {
        ERROR("Failed to append container to container store");
        ret = -1;
        goto out;
    }

    if (save_rootfs(cntr) != 0) {
        ERROR("Failed to save container");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free(dst_id);
        dst_id = NULL;
        free_storage_rootfs(c);
        c = NULL;
        free_rootfs_t(cntr);
        cntr = NULL;
    }
    rootfs_store_unlock();
    return dst_id;
}

static cntrootfs_t *get_rootfs_for_store_by_prefix(const char *id)
{
    bool ret = true;
    cntrootfs_t *value = NULL;
    map_itor *itor = NULL;
    const char *key = NULL;

    itor = map_itor_new(g_rootfs_store->byid);
    if (itor == NULL) {
        ERROR("Failed to get byid's iterator from container store");
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

static cntrootfs_t *lookup(const char *id)
{
    cntrootfs_t *value = NULL;

    if (id == NULL) {
        ERROR("Invalid input parameter, id is NULL");
        return NULL;
    }

    value = map_search(g_rootfs_store->byid, (void *)id);
    if (value != NULL) {
        goto found;
    }

    value = map_search(g_rootfs_store->bylayer, (void *)id);
    if (value != NULL) {
        goto found;
    }

    value = get_rootfs_for_store_by_prefix(id);
    if (value != NULL) {
        goto found;
    }

    return NULL;

found:
    rootfs_ref_inc(value);
    return value;
}

char *rootfs_store_lookup(const char *id)
{
    char *container_id = NULL;
    cntrootfs_t *cntr = NULL;

    if (id == NULL) {
        ERROR("Invalid input parameter, id is NULL");
        return NULL;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Container store is not ready");
        return NULL;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store, not allowed to lookup rootfs id assginments");
        return NULL;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Container not known");
        return NULL;
    }

    container_id = util_strdup_s(cntr->srootfs->id);
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();

    return container_id;
}

static int remove_rootfs_from_memory(const char *id)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    cntrootfs_t *cntr = NULL;
    size_t i = 0;
    int ret = 0;

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs %s not known", id);
        ret = -1;
        goto out;
    }
    if (!map_remove(g_rootfs_store->byid, (void *)id)) {
        ERROR("Failed to remove rootfs from ids map in rootfs store");
        ret = -1;
        goto out;
    }

    if (!map_remove(g_rootfs_store->bylayer, cntr->srootfs->layer)) {
        ERROR("Failed to remove rootfs from layers map in rootfs store");
        ret = -1;
        goto out;
    }

    for (; i < cntr->srootfs->names_len; i++) {
        if (!map_remove(g_rootfs_store->byname, (void *)cntr->srootfs->names[i])) {
            ERROR("Failed to remove rootfs from names index in rootfs store");
            ret = -1;
            goto out;
        }
    }

    linked_list_for_each_safe(item, &(g_rootfs_store->rootfs_list), next) {
        cntrootfs_t *tmp = (cntrootfs_t *)item->elem;
        if (strcmp(tmp->srootfs->id, id) != 0) {
            continue;
        }
        linked_list_del(item);
        rootfs_ref_dec(tmp);
        free(item);
        item = NULL;
        g_rootfs_store->rootfs_list_len--;
        break;
    }

out:
    rootfs_ref_dec(cntr);
    return ret;
}

static int remove_rootfs_dir(const char *id)
{
    char rootfs_path[PATH_MAX] = { 0x00 };

    if (get_data_dir(id, rootfs_path, sizeof(rootfs_path)) != 0) {
        ERROR("Failed to get rootfs data dir: %s", id);
        return -1;
    }

    if (util_recursive_rmdir(rootfs_path, 0) != 0) {
        ERROR("Failed to delete rootfs directory : %s", rootfs_path);
        return -1;
    }

    return 0;
}

int rootfs_store_delete(const char *id)
{
    cntrootfs_t *cntr = NULL;
    int ret = 0;

    if (id == NULL) {
        ERROR("Invalid input parameter, id is NULL");
        return -1;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return -1;
    }

    if (!rootfs_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock rootfs store");
        ret = -1;
        goto out;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs %s not known", id);
        ret = -1;
        goto out;
    }

    if (remove_rootfs_from_memory(cntr->srootfs->id) != 0) {
        ERROR("Failed to remove rootfs from memory");
        ret = -1;
        goto out;
    }

    if (remove_rootfs_dir(cntr->srootfs->id) != 0) {
        ERROR("Failed to delete rootfs directory");
        ret = -1;
        goto out;
    }

out:
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();
    return ret;
}

static int delete_rootfs_from_store_without_lock(const char *id)
{
    int ret = 0;
    cntrootfs_t *cntr = NULL;

    if (id == NULL) {
        ERROR("Invalid input parameter: empty id");
        return -1;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return -1;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs %s not known", id);
        return -1;
    }

    if (remove_rootfs_from_memory(cntr->srootfs->id) != 0) {
        ERROR("Failed to remove rootfs from memory");
        ret = -1;
        goto out;
    }

    if (remove_rootfs_dir(cntr->srootfs->id) != 0) {
        ERROR("Failed to delete rootfs directory");
        ret = -1;
        goto out;
    }

out:
    rootfs_ref_dec(cntr);
    return ret;
}

int rootfs_store_wipe()
{
    int ret = 0;
    char *id = NULL;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return -1;
    }

    if (!rootfs_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock rootfs store, not allowed to delete rootfs");
        ret = -1;
    }

    linked_list_for_each_safe(item, &(g_rootfs_store->rootfs_list), next) {
        id = util_strdup_s(((cntrootfs_t *)item->elem)->srootfs->id);
        if (delete_rootfs_from_store_without_lock(id) != 0) {
            ERROR("Failed to delete rootfs: %s", id);
            ret = -1;
            goto out;
        }
        free(id);
        id = NULL;
    }

out:
    free(id);
    rootfs_store_unlock();
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

static int append_big_data_name(storage_rootfs *rootfs, const char *name)
{
    size_t new_size, old_size;
    char **tmp_names = NULL;

    if (name == NULL) {
        return 0;
    }

    old_size = rootfs->big_data_names_len * sizeof(char *);
    new_size = old_size + sizeof(char *);

    if (mem_realloc((void **)&tmp_names, new_size, (void *)rootfs->big_data_names, old_size) != 0) {
        ERROR("Failed to realloc memory");
        return -1;
    }

    rootfs->big_data_names = tmp_names;
    rootfs->big_data_names[rootfs->big_data_names_len++] = util_strdup_s(name);

    return 0;
}

static int update_rootfs_with_big_data(cntrootfs_t *img, const char *key, const char *data, bool *should_save)
{
    int ret = 0;
    size_t i;
    bool size_found = false;
    bool add_name = true;
    int64_t old_size;
    char *old_digest = NULL;
    char *new_digest = NULL;
    char *full_digest = NULL;

    if (img->srootfs->big_data_sizes == NULL) {
        img->srootfs->big_data_sizes = (json_map_string_int64 *)util_common_calloc_s(sizeof(json_map_string_int64));
        if (img->srootfs->big_data_sizes == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }

    size_found = get_value_from_json_map_string_int64(img->srootfs->big_data_sizes, key, &old_size);
    append_json_map_string_int64(img->srootfs->big_data_sizes, key, (int64_t)strlen(data));

    if (img->srootfs->big_data_digests == NULL) {
        img->srootfs->big_data_digests = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
        if (img->srootfs->big_data_digests == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }

    old_digest = get_value_from_json_map_string_string(img->srootfs->big_data_digests, key);
    new_digest = sha256_digest_str(data);
    full_digest = util_full_digest(new_digest);
    append_json_map_string_string(img->srootfs->big_data_digests, key, full_digest);

    if (!size_found || old_size != (int64_t)strlen(data) || old_digest == NULL ||
        strcmp(old_digest, full_digest) != 0) {
        *should_save = true;
    }

    for (i = 0; i < img->srootfs->big_data_names_len; i++) {
        if (strcmp(img->srootfs->big_data_names[i], key) == 0) {
            add_name = false;
            break;
        }
    }

    if (add_name) {
        if (append_big_data_name(img->srootfs, key) != 0) {
            ERROR("Failed to append big data name");
            ret = -1;
            goto out;
        }
        *should_save = true;
    }

out:
    free(old_digest);
    free(new_digest);
    free(full_digest);
    return ret;
}

int rootfs_store_set_big_data(const char *id, const char *key, const char *data)
{
    int ret = 0;
    cntrootfs_t *cntr = NULL;
    const char *rootfs_id = NULL;
    char rootfs_dir[PATH_MAX] = { 0x00 };
    char big_data_file[PATH_MAX] = { 0x00 };
    bool save = false;

    if (key == NULL || strlen(key) == 0) {
        ERROR("Not a valid name for a big data item, can't set empty name for rootfs big data item");
        return -1;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return -1;
    }

    if (!rootfs_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock rootfs store with exclusive lock, not allowed to change rootfs big data assignments");
        ret = -1;
        goto out;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Failed to lookup rootfs from store");
        ret = -1;
        goto out;
    }
    rootfs_id = cntr->srootfs->id;

    if (get_data_dir(rootfs_id, rootfs_dir, sizeof(rootfs_dir)) != 0) {
        ERROR("Failed to get rootfs data dir: %s", id);
        ret = -1;
        goto out;
    }

    ret = util_mkdir_p(rootfs_dir, IMAGE_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Unable to create directory %s.", rootfs_dir);
        ret = -1;
        goto out;
    }

    if (get_data_path(rootfs_id, key, big_data_file, sizeof(big_data_file)) != 0) {
        ERROR("Failed to get big data file path: %s.", key);
        ret = -1;
        goto out;
    }

    if (util_atomic_write_file(big_data_file, data, strlen(data), SECURE_CONFIG_FILE_MODE) != 0) {
        ERROR("Failed to save big data file: %s", big_data_file);
        ret = -1;
        goto out;
    }

    if (update_rootfs_with_big_data(cntr, key, data, &save) != 0) {
        ERROR("Failed to update rootfs big data");
        ret = -1;
        goto out;
    }

    if (save && save_rootfs(cntr) != 0) {
        ERROR("Failed to complete persistence to disk");
        ret = -1;
        goto out;
    }

out:
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();
    return ret;
}

int rootfs_store_set_metadata(const char *id, const char *metadata)
{
    int ret = 0;
    cntrootfs_t *cntr = NULL;

    if (id == NULL || metadata == NULL) {
        ERROR("Invalid paratemer: id(%s), metadata(%s)", id, metadata);
        return -1;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Container store is not ready");
        return -1;
    }

    if (!rootfs_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock rootfs store with exclusive lock, not allowed to modify rootfs metadata");
        return -1;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs not known");
        ret = -1;
        goto out;
    }

    free(cntr->srootfs->metadata);
    cntr->srootfs->metadata = util_strdup_s(metadata);
    if (save_rootfs(cntr) != 0) {
        ERROR("Failed to save container rootfs");
        ret = -1;
        goto out;
    }

out:
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();
    return ret;
}

int rootfs_store_save(cntrootfs_t *c)
{
    int ret = 0;

    if (c == NULL) {
        ERROR("Invalid parameter, container rootfs is NULL");
        return -1;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return -1;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to save rootfs");
        return -1;
    }

    ret = save_rootfs(c);

    rootfs_store_unlock();

    return ret;
}

bool rootfs_store_exists(const char *id)
{
    bool ret = true;
    cntrootfs_t *cntr = NULL;

    if (id == NULL) {
        ERROR("Invalid paratemer, id is NULL");
        return false;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return false;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to get rootfs exist info");
        return false;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs not known");
        ret = false;
        goto out;
    }

out:
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();
    return ret;
}

static storage_rootfs *copy_rootfs(const storage_rootfs *rootfs)
{
    char *json = NULL;
    parser_error err = NULL;
    storage_rootfs *ans = NULL;

    if (rootfs == NULL) {
        return NULL;
    }

    json = storage_rootfs_generate_json(rootfs, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    ans = storage_rootfs_parse_data(json, NULL, &err);
    if (ans == NULL) {
        ERROR("Failed to parse json: %s", err);
        goto out;
    }

out:
    free(err);
    free(json);
    return ans;
}

storage_rootfs *rootfs_store_get_rootfs(const char *id)
{
    cntrootfs_t *cntr = NULL;
    storage_rootfs *dup_rootfs = NULL;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return NULL;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return NULL;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to rootfs store with shared lock, not allowed to get rootfs from store");
        return NULL;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs not known");
        goto out;
    }

    dup_rootfs = copy_rootfs(cntr->srootfs);

out:
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();
    return dup_rootfs;
}

char *rootfs_store_big_data(const char *id, const char *key)
{
    int ret = 0;
    cntrootfs_t *cntr = NULL;
    char filename[PATH_MAX] = { 0x00 };
    char *content = NULL;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return NULL;
    }

    if (key == NULL || strlen(key) == 0) {
        ERROR("Not a valid name for a big data item, can't retrieve rootfs big data value for empty name");
        return NULL;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not read");
        return NULL;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to get rootfs big data");
        return NULL;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs not known");
        goto out;
    }

    ret = get_data_path(cntr->srootfs->id, key, filename, sizeof(filename));

    if (ret != 0) {
        ERROR("Failed to get big data file path: %s.", key);
        goto out;
    }

    content = isula_utils_read_file(filename);

out:
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();
    return content;
}

static int get_size_with_update_big_data(const char *id, const char *key, int64_t *size)
{
    int ret = 0;
    cntrootfs_t *cntr = NULL;
    char *data = NULL;

    data = rootfs_store_big_data(id, key);
    if (data == NULL) {
        return -1;
    }

    if (rootfs_store_set_big_data(id, key, data) != 0) {
        free(data);
        return -1;
    }

    free(data);

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to get rootfs big data size assignments");
        return -1;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs not known");
        ret = -1;
        goto out;
    }

    (void)get_value_from_json_map_string_int64(cntr->srootfs->big_data_sizes, key, size);

out:
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();
    return ret;
}

int64_t rootfs_store_big_data_size(const char *id, const char *key)
{
    bool bret = false;
    cntrootfs_t *cntr = NULL;
    int64_t size = -1;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return -1;
    }

    if (key == NULL || strlen(key) == 0) {
        ERROR("Not a valid name for a big data item, can't retrieve rootfs big data value for empty name");
        return -1;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return -1;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to get rootfs big data size assignments");
        return -1;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs not known");
        goto out;
    }

    bret = get_value_from_json_map_string_int64(cntr->srootfs->big_data_sizes, key, &size);

    rootfs_ref_dec(cntr);

    if (bret || get_size_with_update_big_data(id, key, &size) == 0) {
        goto out;
    }

    ERROR("Size is not known");

out:
    rootfs_store_unlock();
    return size;
}

static char *get_digest_with_update_big_data(const char *id, const char *key)
{
    cntrootfs_t *cntr = NULL;
    char *data = NULL;
    char *digest = NULL;

    data = rootfs_store_big_data(id, key);
    if (data == NULL) {
        return NULL;
    }

    if (rootfs_store_set_big_data(id, key, data) != 0) {
        ERROR("Failed to set big data");
        goto out;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to get container digest assignments");
        goto out_unlock;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs %s not known", id);
        goto out_unlock;
    }

    digest = get_value_from_json_map_string_string(cntr->srootfs->big_data_digests, key);

out_unlock:
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();
out:
    free(data);
    return digest;
}

char *rootfs_store_big_data_digest(const char *id, const char *key)
{
    cntrootfs_t *cntr = NULL;
    char *digest = NULL;

    if (key == NULL || strlen(key) == 0) {
        ERROR("Not a valid name for a big data item, can't retrieve rootfs big data value for empty name");
        return NULL;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return NULL;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to get rootfs big data digest assignments");
        return NULL;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs not known");
        rootfs_store_unlock();
        return NULL;
    }

    digest = get_value_from_json_map_string_string(cntr->srootfs->big_data_digests, key);

    rootfs_ref_dec(cntr);
    rootfs_store_unlock();

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

int rootfs_store_big_data_names(const char *id, char ***names, size_t *names_len)
{
    int ret = 0;
    cntrootfs_t *cntr = NULL;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return -1;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return -1;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to get rootfs big data names assignments");
        return -1;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs not known");
        ret = -1;
        goto out;
    }

    if (dup_array_of_strings((const char **)cntr->srootfs->big_data_names, cntr->srootfs->big_data_names_len, names,
                             names_len) != 0) {
        ERROR("Failed to dup rootfs's names");
        ret = -1;
        goto out;
    }

out:
    rootfs_ref_dec(cntr);
    rootfs_store_unlock();
    return ret;
}

char *rootfs_store_metadata(const char *id)
{
    cntrootfs_t *img = NULL;
    char *metadata = NULL;

    if (id == NULL) {
        ERROR("Invalid parameter, id is NULL");
        return NULL;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready");
        return NULL;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to get rootfs metadata assignments");
        return NULL;
    }

    img = lookup(id);
    if (img == NULL) {
        ERROR("Rootfs not known");
        goto out;
    }

    metadata = util_strdup_s(img->srootfs->metadata);

out:
    rootfs_ref_dec(img);
    rootfs_store_unlock();
    return metadata;
}

int rootfs_store_get_all_rootfs(struct rootfs_list *all_rootfs)
{
    int ret = 0;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (all_rootfs == NULL) {
        ERROR("Invalid input paratemer, memory should be allocated first");
        return -1;
    }

    if (g_rootfs_store == NULL) {
        ERROR("Rootfs store is not ready!");
        return -1;
    }

    if (!rootfs_store_lock(SHARED)) {
        ERROR("Failed to lock rootfs store with shared lock, not allowed to get all the known rootfss");
        return -1;
    }

    if (g_rootfs_store->rootfs_list_len == 0) {
        goto out;
    }

    all_rootfs->rootfs = util_common_calloc_s(g_rootfs_store->rootfs_list_len * sizeof(storage_rootfs *));
    if (all_rootfs->rootfs == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    linked_list_for_each_safe(item, &(g_rootfs_store->rootfs_list), next) {
        storage_rootfs *tmp_rootfs = NULL;
        cntrootfs_t *img = (cntrootfs_t *)item->elem;
        tmp_rootfs = copy_rootfs(img->srootfs);
        if (tmp_rootfs == NULL) {
            ERROR("Failed to copy container rootfs");
            ret = -1;
            goto out;
        }

        all_rootfs->rootfs[all_rootfs->rootfs_len++] = tmp_rootfs;
        tmp_rootfs = NULL;
    }

out:
    rootfs_store_unlock();
    return ret;
}
