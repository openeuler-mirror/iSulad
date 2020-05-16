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
 * Description: provide image store functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "rootfs_store.h"
#include <sys/stat.h>
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
#include "defs.h"
#include "map.h"
#include "linked_list.h"
#include "rootfs.h"

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

rootfs_store_t *g_rootfs_store = NULL;

static inline bool rootfs_store_lock(bool writable)
{
    int nret = 0;

    if (writable) {
        nret = pthread_rwlock_wrlock(&g_rootfs_store->rwlock);
    } else {
        nret = pthread_rwlock_rdlock(&g_rootfs_store->rwlock);
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

    if (!rootfs_store_lock(true)) {
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

    for (i = 0; i < cntr->scontainer->names_len; i++) {
        if (strcmp(cntr->scontainer->names[i], name) == 0) {
            count++;
        }
    }

    new_size = (cntr->scontainer->names_len - count) * sizeof(char *);
    tmp_names = (char **)util_common_calloc_s(new_size);
    if (tmp_names == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < cntr->scontainer->names_len; i++) {
        if (strcmp(cntr->scontainer->names[i], name) != 0) {
            tmp_names[index++] = util_strdup_s(cntr->scontainer->names[i]);
        }
        free(cntr->scontainer->names[i]);
        cntr->scontainer->names[i] = NULL;
    }

    free(cntr->scontainer->names);
    cntr->scontainer->names = tmp_names;
    cntr->scontainer->names_len = index;
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

    if (get_container_path(cntr->scontainer->id, container_path, sizeof(container_path)) != 0) {
        ERROR("Failed to get container path by id: %s", cntr->scontainer->id);
        return -1;
    }

    strcpy(container_dir, container_path);
    ret = util_mkdir_p(dirname(container_dir), ROOTFS_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Failed to create container directory %s.", container_path);
        return -1;
    }

    json_data = storage_rootfs_generate_json(cntr->scontainer, NULL, &err);
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

    if (!map_replace(g_rootfs_store->byid, (void *)cntr->scontainer->id, (void *)cntr)) {
        ERROR("Failed to insert container to id index");
        return -1;
    }

    if (!map_replace(g_rootfs_store->bylayer, (void *)cntr->scontainer->layer, (void *)cntr)) {
        ERROR("Failed to insert container to layer index");
        return -1;
    }

    for (i = 0; i < cntr->scontainer->names_len; i++) {
        cntrootfs_t *conflict_container = (cntrootfs_t *)map_search(g_rootfs_store->byname, (void *)cntr->scontainer->names[i]);
        if (conflict_container != NULL) {
            if (remove_name(conflict_container, cntr->scontainer->names[i]) != 0) {
                ERROR("Failed to remove name from conflict container");
                ret = -1;
                goto out;
            }
            should_save = true;
        }
        if (!map_replace(g_rootfs_store->byname, (void *)cntr->scontainer->names[i], (void *)cntr)) {
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
        uid_map = (storage_rootfs_uidmap_element **)util_common_calloc_s(
                      sizeof(storage_rootfs_uidmap_element *) * rootfs_opts->id_mapping_opts.uid_map_len);
        if (uid_map == NULL) {
            ERROR("Out of memory");
            return -1;
        }

        for (i = 0; i < rootfs_opts->id_mapping_opts.uid_map_len; i++) {
            uid_map[i] = (storage_rootfs_uidmap_element *)util_common_calloc_s(
                             sizeof(storage_rootfs_uidmap_element));
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
        gid_map = (storage_rootfs_gidmap_element **)util_common_calloc_s(
                      sizeof(storage_rootfs_gidmap_element *) * rootfs_opts->id_mapping_opts.gid_map_len);
        if (gid_map == NULL) {
            ERROR("Out of memory");
            return -1;
        }

        for (i = 0; i < rootfs_opts->id_mapping_opts.gid_map_len; i++) {
            gid_map[i] = (storage_rootfs_gidmap_element *)util_common_calloc_s(
                             sizeof(storage_rootfs_gidmap_element));
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

static storage_rootfs *new_storage_rootfs(const char *id, const char *image,
                                          char **unique_names, size_t unique_names_len, const char *layer,
                                          const char *metadata, struct storage_rootfs_options *rootfs_opts)
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
    rootfs_ref_inc(cntr);

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

    if (!rootfs_store_lock(true)) {
        ERROR("Failed to lock container store, not allowed to create new containers");
        return NULL;
    }

    if (id == NULL) {
        dst_id = generate_random_container_id();
    } else {
        dst_id = util_strdup_s(id);
    }

    if (map_search(g_rootfs_store->byid, (void *)dst_id) != NULL) {
        ERROR("ID is already in use: %s", id);
        ret = -1;
        goto out;
    }

    if (util_string_array_unique(names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    c = new_storage_rootfs(id, image, unique_names, unique_names_len, layer, metadata, rootfs_opts);
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

    if (rootfs_store_append_container_rootfs(id, layer, (const char **)unique_names, unique_names_len, cntr) != 0) {
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

static inline cntrootfs_t *lookup_with_lock(const char *id)
{
    cntrootfs_t *cntr = NULL;

    if (!rootfs_store_lock(false)) {
        return NULL;
    }

    cntr = lookup(id);
    rootfs_store_unlock();
    return cntr;
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

    cntr = lookup_with_lock(id);
    if (cntr == NULL) {
        ERROR("Container not known");
        return NULL;
    }

    container_id = util_strdup_s(cntr->scontainer->id);
    rootfs_ref_dec(cntr);

    return container_id;
}

static inline int get_data_dir(const char *id, char *path, size_t len)
{
    int nret = snprintf(path, len, "%s/%s", g_rootfs_store->dir, id);
    return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
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

    if (!map_remove(g_rootfs_store->bylayer, cntr->scontainer->layer)) {
        ERROR("Failed to remove rootfs from layers map in rootfs store");
        ret = -1;
        goto out;
    }

    for (; i < cntr->scontainer->names_len; i++) {
        if (!map_remove(g_rootfs_store->byname, (void *)cntr->scontainer->names[i])) {
            ERROR("Failed to remove rootfs from names index in rootfs store");
            ret = -1;
            goto out;
        }
    }

    linked_list_for_each_safe(item, &(g_rootfs_store->rootfs_list), next) {
        cntrootfs_t *tmp = (cntrootfs_t *)item->elem;
        if (strcmp(tmp->scontainer->id, id) != 0) {
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

    if (!rootfs_store_lock(true)) {
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

    if (remove_rootfs_from_memory(cntr->scontainer->id) != 0) {
        ERROR("Failed to remove rootfs from memory");
        ret = -1;
        goto out;
    }

    if (remove_rootfs_dir(cntr->scontainer->id) != 0) {
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
        ERROR("Rootfs store is not already");
        return -1;
    }

    cntr = lookup(id);
    if (cntr == NULL) {
        ERROR("Rootfs %s not known", id);
        return -1;
    }

    if (remove_rootfs_from_memory(cntr->scontainer->id) != 0) {
        ERROR("Failed to remove rootfs from memory");
        ret = -1;
        goto out;
    }

    if (remove_rootfs_dir(cntr->scontainer->id) != 0) {
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

    if (!rootfs_store_lock(true)) {
        ERROR("Failed to lock rootfs store, not allowed to delete rootfs");
        ret = -1;
    }

    linked_list_for_each_safe(item, &(g_rootfs_store->rootfs_list), next) {
        id = util_strdup_s(((cntrootfs_t *)item->elem)->scontainer->id);
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

int rootfs_store_set_big_data(const char *id, const char *key, const char *data)
{
    return 0;
}

int rootfs_store_set_names(const char *id, const char **names, size_t names_len)
{
    return 0;
}

int rootfs_store_set_metadata(const char *id, const char *metadata)
{
    return 0;
}

int rootfs_store_save(cntrootfs_t *c)
{
    return 0;
}

bool rootfs_store_exists(const char *id)
{
    return false;
}

storage_rootfs *rootfs_store_get_rootfs(const char *id)
{
    return NULL;
}

char *rootfs_store_big_data(const char *id, const char *key)
{
    return NULL;
}

int64_t rootfs_store_big_data_size(const char *id, const char *key)
{
    return -1;
}

char *rootfs_store_big_data_digest(const char *id, const char *key)
{
    return NULL;
}

int rootfs_store_big_data_names(const char *id, char ***names, size_t *names_len)
{
    return 0;
}

char *rootfs_store_metadata(const char *id)
{
    return NULL;
}

int rootfs_store_get_all_rootfs(struct rootfs_list *all_rootfs)
{
    return 0;
}

