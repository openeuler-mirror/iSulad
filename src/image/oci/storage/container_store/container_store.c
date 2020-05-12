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
 * Create: 2020-05-12
 * Description: provide image store functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "container_store.h"
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
#include "container.h"

#define CONTAINER_JSON "container.json"

typedef struct container_store {
    pthread_rwlock_t rwlock;
    char *dir;
    struct linked_list containers_list;
    size_t containers_list_len;
    map_t *byid;
    map_t *bylayer;
    map_t *byname;

    bool loaded;
} container_store_t;

container_store_t *g_container_store = NULL;

static inline bool container_store_lock(bool writable)
{
    int nret = 0;

    if (writable) {
        nret = pthread_rwlock_wrlock(&g_container_store->rwlock);
    } else {
        nret = pthread_rwlock_rdlock(&g_container_store->rwlock);
    }
    if (nret != 0) {
        ERROR("Lock memory store failed: %s", strerror(nret));
        return false;
    }

    return true;
}

static inline void container_store_unlock()
{
    int nret = 0;

    nret = pthread_rwlock_unlock(&g_container_store->rwlock);
    if (nret != 0) {
        FATAL("Unlock memory store failed: %s", strerror(nret));
    }
}

static void free_container_store(container_store_t *store)
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

    linked_list_for_each_safe(item, &(store->containers_list), next) {
        linked_list_del(item);
        container_ref_dec((cntr_t *)item->elem);
        free(item);
        item = NULL;
    }

    store->containers_list_len = 0;

    free(store);
}

void container_store_free()
{
    free_container_store(g_container_store);
    g_container_store = NULL;
}

static void container_store_field_kvfree(void *key, void *value)
{
    (void)value;
    free(key);
}

static int do_append_container(storage_container *c)
{
    cntr_t *cntr = NULL;
    struct linked_list *item = NULL;

    cntr = new_container(c);
    if (cntr == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    item = util_smart_calloc_s(sizeof(struct linked_list), 1);
    if (item == NULL) {
        ERROR("Out of memory");
        free_container_t(cntr);
        return -1;
    }

    linked_list_add_elem(item, cntr);
    linked_list_add_tail(&g_container_store->containers_list, item);
    g_container_store->containers_list_len++;

    return 0;
}

static int append_container_by_directory(const char *container_dir)
{
    int ret = 0;
    int nret;
    char container_path[PATH_MAX] = { 0x00 };
    storage_container *c = NULL;
    parser_error err = NULL;

    nret = snprintf(container_path, sizeof(container_path), "%s/%s", container_dir, CONTAINER_JSON);
    if (nret < 0 || (size_t)nret >= sizeof(container_path)) {
        ERROR("Failed to get container path");
        return -1;
    }

    c = storage_container_parse_file(container_path, NULL, &err);
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
    free_storage_container(c);
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

    if (!container_store_lock(true)) {
        ERROR("Failed to lock container store");
        return -1;
    }

    ret = util_list_all_subdir(g_container_store->dir, &container_dirs);
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
        nret = snprintf(container_path, sizeof(container_path), "%s/%s", g_container_store->dir, container_dirs[i]);
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
    container_store_unlock();
    return ret;
}

static int remove_name(cntr_t *cntr, const char *name)
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
    int nret = snprintf(path, len, "%s/%s/%s", g_container_store->dir, id, CONTAINER_JSON);

    return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
}

static int save_container(cntr_t *cntr)
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
    ret = util_mkdir_p(dirname(container_dir), CONTAINER_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Failed to create container directory %s.", container_path);
        return -1;
    }

    json_data = storage_container_generate_json(cntr->scontainer, NULL, &err);
    if (json_data == NULL) {
        ERROR("Failed to generate container json path string:%s", err ? err : " ");
        ret = -1;
        goto out;
    }

    if (util_atomic_write_file(container_path, json_data, strlen(json_data), SECURE_CONFIG_FILE_MODE) != 0) {
        ERROR("Failed to save image json file");
        ret = -1;
        goto out;
    }

out:
    free(json_data);
    free(err);

    return ret;
}

static int load_container_to_store_field(cntr_t *cntr)
{
    int ret = 0;
    bool should_save = false;
    size_t i;

    if (!map_replace(g_container_store->byid, (void *)cntr->scontainer->id, (void *)cntr)) {
        ERROR("Failed to insert container to id index");
        return -1;
    }

    if (!map_replace(g_container_store->bylayer, (void *)cntr->scontainer->layer, (void *)cntr)) {
        ERROR("Failed to insert container to layer index");
        return -1;
    }

    for (i = 0; i < cntr->scontainer->names_len; i++) {
        cntr_t *conflict_container = (cntr_t *)map_search(g_container_store->byname, (void *)cntr->scontainer->names[i]);
        if (conflict_container != NULL) {
            if (remove_name(conflict_container, cntr->scontainer->names[i]) != 0) {
                ERROR("Failed to remove name from conflict container");
                ret = -1;
                goto out;
            }
            should_save = true;
        }
        if (!map_replace(g_container_store->byname, (void *)cntr->scontainer->names[i], (void *)cntr)) {
            ERROR("Failed to insert containes to name index");
            ret = -1;
            goto out;
        }
    }

    if (should_save && save_container(cntr) != 0) {
        ERROR("Failed to save container");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int container_store_load()
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (g_container_store->loaded) {
        DEBUG("Do not need reload if daemon");
        return 0;
    }

    if (get_containers_from_json() != 0) {
        ERROR("Failed to get images from json");
        return -1;
    }

    linked_list_for_each_safe(item, &(g_container_store->containers_list), next) {
        if (load_container_to_store_field((cntr_t *)item->elem) != 0) {
            ERROR("Failed to load image to container store");
            return -1;
        }
    }

    g_container_store->loaded = true;

    return 0;
}

static char *get_container_store_root_path(const struct storage_module_init_options *opts)
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

int container_store_init(struct storage_module_init_options *opts)
{
    int ret = 0;
    char *root_dir = NULL;

    if (g_container_store != NULL) {
        ERROR("Container store has already been initialized");
        return -1;
    }

    root_dir = get_container_store_root_path(opts);
    if (root_dir == NULL) {
        return ret;
    }

    ret = util_mkdir_p(root_dir, CONTAINER_STORE_PATH_MODE);
    if (ret < 0) {
        ERROR("Unable to create container store directory %s.", root_dir);
        ret = -1;
        goto out;
    }

    g_container_store = (container_store_t *)util_common_calloc_s(sizeof(container_store_t));
    if (g_container_store == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = pthread_rwlock_init(&(g_container_store->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init container store rwlock");
        ret = -1;
        goto out;
    }

    g_container_store->dir = root_dir;
    root_dir = NULL;

    g_container_store->containers_list_len = 0;
    linked_list_init(&g_container_store->containers_list);

    g_container_store->byid = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, container_store_field_kvfree);
    if (g_container_store->byid == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    g_container_store->bylayer = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, container_store_field_kvfree);
    if (g_container_store->byname == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    g_container_store->byname = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, container_store_field_kvfree);
    if (g_container_store->byname == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = container_store_load();
    if (ret != 0) {
        ERROR("Failed to load container store");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free_container_store(g_container_store);
        g_container_store = NULL;
    }
    free(root_dir);
    return ret;
}

char *container_store_create(const char *id, const char **names, size_t names_len, const char *image, const char *layer,
                             const char *metadata, struct storage_container_options *container_opts)
{
    return NULL;
}

char *container_store_lookup(const char *id)
{
    return NULL;
}

int container_store_delete(const char *id)
{
    return 0;
}

int container_store_wipe()
{
    return 0;
}

int container_store_set_big_data(const char *id, const char *key, const char *data)
{
    return 0;
}

int container_store_set_names(const char *id, const char **names, size_t names_len)
{
    return 0;
}

int container_store_set_metadata(const char *id, const char *metadata)
{
    return 0;
}

int container_store_save(cntr_t *c)
{
    return 0;
}

bool container_store_exists(const char *id)
{
    return false;
}

cntr_t *container_store_get_container(const char *id)
{
    return NULL;
}

char *container_store_big_data(const char *id, const char *key)
{
    return NULL;
}

int64_t container_store_big_data_size(const char *id, const char *key)
{
    return -1;
}

char *container_store_big_data_digest(const char *id, const char *key)
{
    return NULL;
}

int container_store_big_data_names(const char *id, char ***names, size_t *names_len)
{
    return 0;
}

char *container_store_metadata(const char *id)
{
    return NULL;
}

int container_store_get_all_containers(cntr_t *containers, size_t *len)
{
    return 0;
}

