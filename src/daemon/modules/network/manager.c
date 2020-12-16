/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: gaohuatao
 * Create: 2020-11-09
 * Description: provide CNI network manager function definition
 ******************************************************************************/
#include "manager.h"

#include <pthread.h>
#include <sys/types.h>
#include <sys/inotify.h>

#include "isula_libutils/log.h"
#include "isula_libutils/cni_net_conf.h"
#include "isula_libutils/cni_net_conf_list.h"
#include "isula_libutils/cni_anno_port_mappings.h"
#include "utils.h"
#include "libcni_utils.h"
#include "libcni_types.h"

#define LO_IFNAME "lo"
#define MAC_ADDR_VALID_CHARS "^([a-f0-9A-F]{2}[:-]){5}(a-f0-9A-F]{2})$"

typedef int (*annotation_add_cap_t)(const char *value, struct runtime_conf *);
typedef int (*annotation_add_json_t)(const char *value, char **bytes);

struct anno_registry_conf_rt {
    char *name;
    annotation_add_cap_t ops;
};

struct anno_registry_conf_json {
    char *name;
    annotation_add_json_t ops;
};

typedef struct cni_manager_store_t {
    char *conf_path;
    char *loopback_conf_str;
} cni_manager_store_t;

typedef struct cni_manager_network_conf_list_t {
    struct cni_network_list_conf **conflist;
    size_t conflist_len;
    // MAP_STR_STR, key:file name, value:bytes
    map_t *map_isula_net_conf;

    pthread_rwlock_t rwlock;
} cni_manager_network_conf_list_t;

static cni_manager_store_t g_cni_manager = {
    .loopback_conf_str = "{\"cniVersion\": \"0.3.0\", \"name\": \"cni-loopback\","
    "\"plugins\":[{\"type\": \"loopback\" }]}",
};

static cni_manager_network_conf_list_t g_conflists;


static int bandwidth_inject(const char *value, struct runtime_conf *rt)
{
    int ret = -1;
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    cni_bandwidth_entry *bwith = NULL;

    if (value == NULL || rt == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    bwith = cni_bandwidth_entry_parse_data(value, &ctx, &err);
    if (bwith == NULL) {
        ERROR("Failed to parse bandwidth datas from value:%s, err:%s", value, err);
        ret = -1;
        goto out;
    }

    rt->bandwidth = bwith;
    bwith = NULL;

out:
    free(err);
    return ret;
}

static int copy_port_mapping_from_anno(const cni_anno_port_mappings_element *src, struct cni_port_mapping *dst)
{
    if (src == NULL) {
        ERROR("Invalid param");
        return -1;
    }

    if (src->protocol != NULL) {
        dst->protocol = util_strdup_s(src->protocol);
    }
    if (src->host_ip != NULL) {
        dst->host_ip = util_strdup_s(src->host_ip);
    }
    dst->container_port = src->container_port;
    dst->host_port = src->host_port;

    return 0;
}

static int port_mappings_inject(const char *value, struct runtime_conf *rt)
{
    int ret = 0;
    size_t i = 0;
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    cni_anno_port_mappings_container *anno_p = NULL;
    struct cni_port_mapping **new_p = NULL;
    size_t new_len = 0;

    if (value == NULL || rt == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    anno_p = cni_anno_port_mappings_container_parse_data(value, &ctx, &err);
    if (anno_p == NULL) {
        ERROR("Failed to parse port mapping datas from value:%s, err:%s", value, err);
        ret = -1;
        goto out;
    }

    if (anno_p->len == 0) {
        WARN("No port mapping found, just do nothing");
        goto out;
    }

    new_p = (struct cni_port_mapping **)util_smart_calloc_s(sizeof(struct cni_port_mapping*), anno_p->len);
    if (new_p == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < anno_p->len; i++) {
        new_p[i] = (struct cni_port_mapping *)util_smart_calloc_s(sizeof(struct cni_port_mapping), 1);
        if (new_p[i] == NULL) {
            ERROR("Out of memory, calloc failed");
            ret = -1;
            goto free_out;
        }
        new_len++;

        if (copy_port_mapping_from_anno(anno_p->items[i], new_p[i]) != 0) {
            ERROR("Copy port mapping from annotations failed");
            ret = -1;
            goto free_out;
        }
    }

    rt->p_mapping = new_p;
    new_p = NULL;
    rt->p_mapping_len = new_len;
    new_len = 0;

free_out:
    for (i = 0; i < new_len; i++) {
        free_cni_port_mapping(new_p[i]);
        new_p[i] = NULL;
    }
    free(new_p);

out:
    free(err);
    free_cni_anno_port_mappings_container(anno_p);
    return ret;
}

static int ip_ranges_inject(const char *value, struct runtime_conf *rt)
{
    if (value == NULL || rt == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    return 0;
}

static struct anno_registry_conf_rt g_registrant_rt[] = {
    {.name = CNI_ARGS_BANDWIDTH_KEY, .ops = bandwidth_inject},
    {.name = CNI_ARGS_PORTMAPPING_KEY, .ops = port_mappings_inject},
    {.name = CNI_ARGS_IPRANGES_KEY, .ops = ip_ranges_inject}
};

static struct anno_registry_conf_json g_registrant_json[] = {
    // Whitelist of appending to net_list_conf_str
};

static const size_t g_numregistrants_rt = sizeof(g_registrant_rt) / sizeof(struct anno_registry_conf_rt);
static const size_t g_numregistrants_json = sizeof(g_registrant_json) / sizeof(struct anno_registry_conf_json);

static inline bool conflists_wrlock()
{
    int nret = 0;

    nret = pthread_rwlock_wrlock(&g_conflists.rwlock);
    if (nret != 0) {
        ERROR("Lock conflists memory store failed: %s", strerror(nret));
        return false;
    }

    return true;
}

static inline bool conflists_rdlock()
{
    int nret = 0;

    nret = pthread_rwlock_rdlock(&g_conflists.rwlock);
    if (nret != 0) {
        ERROR("Lock conflists memory store failed: %s", strerror(nret));
        return false;
    }

    return true;
}

static inline void conflists_unlock()
{
    int nret = 0;

    nret = pthread_rwlock_unlock(&g_conflists.rwlock);
    if (nret != 0) {
        FATAL("Unlock driver memory store failed: %s", strerror(nret));
    }
}

static int load_cni_config_file_list(const char *fname, struct cni_network_list_conf **n_list)
{
    int ret = 0;
    struct cni_network_conf *n_conf = NULL;

    if (fname == NULL || n_list == NULL) {
        ERROR("Invalid NULL params");
        return -1;
    }

    if (util_has_suffix(fname, ".conflist")) {
        if (cni_conflist_from_file(fname, n_list) != 0) {
            ERROR("Error loading CNI config list file %s", fname);
            ret = -1;
            goto out;
        }
    } else {
        if (cni_conf_from_file(fname, &n_conf) != 0) {
            ERROR("Error loading CNI config file %s", fname);
            ret = -1;
            goto out;
        }

        if (!util_valid_str(n_conf->type)) {
            ERROR("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", fname);
            ret = -1;
            goto out;
        }

        if (cni_conflist_from_conf(n_conf, n_list) != 0) {
            ERROR("Error converting CNI config file %s to list", fname);
            ret = -1;
            goto out;
        }
    }

out:
    if (n_conf != NULL) {
        free_cni_network_conf(n_conf);
    }

    return ret;
}

// Try my best to load file, when error occured, just skip and continue
static int update_cri_conflist_from_files(cni_manager_network_conf_list_t *store, const char **files,
                                          size_t length)
{
    size_t i = 0;
    int ret = 0;
    char *fname = NULL;

    if (g_cni_manager.conf_path == NULL) {
        ERROR("CNI conf path is null");
        return -1;
    }

    for (i = 0; i < length; i++) {
        struct cni_network_list_conf *n_list = NULL;

        UTIL_FREE_AND_SET_NULL(fname);
        fname = util_path_base(files[i]);
        if (fname == NULL) {
            ERROR("Get file name from full path:%s failed", files[i]);
            ret = -1;
            goto out;
        }

        if (util_has_prefix(fname, ISULAD_CNI_NETWORK_CONF_FILE_PRE)) {
            continue;
        }

        if (load_cni_config_file_list(files[i], &n_list) != 0) {
            WARN("Load cni network conflist from file:%s failed", files[i]);
            continue;
        }

        if (n_list == NULL || n_list->plugin_len == 0) {
            WARN("CNI config list %s has no networks, skipping", files[i]);
            free_cni_network_list_conf(n_list);
            n_list = NULL;
            continue;
        }

        store->conflist[i] = n_list;
        n_list = NULL;
        store->conflist_len++;
    }

out:
    free(fname);
    return ret;
}

static void free_conflists_data(struct cni_network_list_conf **conflist, size_t len)
{
    size_t i = 0;

    if (conflist == NULL) {
        return;
    }

    for (i = 0; i < len; i++) {
        free_cni_network_list_conf(conflist[i]);
        conflist[i] = NULL;
    }
    free(conflist);
}

static int update_cri_conflist_with_lock(size_t new_length, const char **files)
{
    int ret = 0;
    size_t i = 0;
    cni_manager_network_conf_list_t tmp_conflists = { 0 };

    tmp_conflists.conflist = (struct cni_network_list_conf **)util_smart_calloc_s(sizeof(
                                                                                      struct cni_network_list_conf *), new_length);
    if (tmp_conflists.conflist == NULL) {
        ERROR("Out of memory, cannot allocate mem to store conflists");
        return -1;
    }

    tmp_conflists.conflist_len = 0;
    if (update_cri_conflist_from_files(&tmp_conflists, files, new_length) != 0) {
        ERROR("Update conflist from files failed");
        ret = -1;
        goto out;
    }

    if (!conflists_wrlock()) {
        ERROR("Lock conflists store failed");
        ret = -1;
        goto out;
    }

    for (i = 0; i < g_conflists.conflist_len; i++) {
        free_cni_network_list_conf(g_conflists.conflist[i]);
    }
    free(g_conflists.conflist);

    g_conflists.conflist = tmp_conflists.conflist;
    g_conflists.conflist_len = tmp_conflists.conflist_len;
    conflists_unlock();

    tmp_conflists.conflist = NULL;
    tmp_conflists.conflist_len = 0;

out:
    free_conflists_data(tmp_conflists.conflist, tmp_conflists.conflist_len);
    return ret;
}

static int judge_cri_conf(const char *fpath, bool *res)
{
    char *name = NULL;

    name = util_path_base(fpath);
    if (name == NULL) {
        ERROR("Get file name from full path:%s failed", fpath);
        return -1;
    }

    *res = util_has_prefix(name, ISULAD_CNI_NETWORK_CONF_FILE_PRE);

    free(name);
    return 0;
}

static int replace_map_value(map_t *map, const char *fpath)
{
    int ret = 0;
    struct cni_network_list_conf *n_list = NULL;

    if (load_cni_config_file_list(fpath, &n_list) != 0) {
        WARN("Load cni network conflist from file:%s failed", fpath);
    }

    if (n_list == NULL || n_list->plugin_len == 0) {
        WARN("CNI config list %s has no networks, skipping", fpath);
    }

    if (!map_replace(map, (void *)n_list->name, (void *)n_list->bytes)) {
        ERROR("Failed to replace cni config file:%s json to map", fpath);
        ret = -1;
    }

    free_cni_network_list_conf(n_list);
    return ret;
}

static map_t *new_isula_conflist_map(size_t length, const char **files)
{
    int ret = 0;
    size_t i = 0;
    map_t *map_net = NULL;

    map_net = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (map_net == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (i = 0; i < length; i++) {
        bool is_isula = false;

        if (judge_cri_conf(files[i], &is_isula) != 0) {
            ERROR("Judge cri conf err");
            ret = -1;
            goto out;
        }

        if (!is_isula) {
            continue;
        }

        if (replace_map_value(map_net, files[i]) != 0) {
            ERROR("Replace map value for cni conf failed");
            ret = -1;
            goto out;
        }
    }

out:
    if (ret != 0) {
        map_free(map_net);
        map_net = NULL;
    }
    return map_net;
}

static int update_isula_conflist_with_lock(size_t length, const char **files)
{
    int ret = 0;
    map_t *map = NULL;

    map = new_isula_conflist_map(length, files);
    if (map == NULL) {
        ERROR("New allocate isula conflist map failed");
        ret = -1;
        goto out;
    }

    if (!conflists_wrlock()) {
        ERROR("Lock conflists store failed");
        ret = -1;
        goto out;
    }

    map_free(g_conflists.map_isula_net_conf);
    g_conflists.map_isula_net_conf = map;
    conflists_unlock();

out:
    if (ret != 0) {
        map_free(map);
        map = NULL;
    }
    return ret;
}

// Lexicographical order in ascending order
static int cmpstr(const void *a, const void *b)
{
    return strcmp(*((const char **)a), *((const char **)b));
}

static int get_conf_files(char ***files, size_t *length)
{
    int ret = 0;
    const char *exts[] = { ".conf", ".conflist", ".json" };

    if (g_cni_manager.conf_path == NULL || files == NULL || length == NULL) {
        ERROR("Input params");
        return -1;
    }

    if (cni_conf_files(g_cni_manager.conf_path, exts, sizeof(exts) / sizeof(char *), files) != 0) {
        ERROR("Get conf files from dir:%s failed", g_cni_manager.conf_path);
        ret = -1;
        goto out;
    }

    *length = util_array_len((const char **)*files);
    if (*length == 0) {
        ERROR("No network conf files found");
        ret = -1;
        goto out;
    }

    qsort(*files, *length, sizeof(char *), cmpstr);

out:
    return ret;
}

int cri_update_confist_from_dir()
{
    int ret = 0;
    size_t length = 0;
    char **files = NULL;

    if (get_conf_files(&files, &length) != 0) {
        ERROR("Get cni conf files in ascending order failed");
        ret = -1;
        goto out;
    }

    if (update_cri_conflist_with_lock(length, (const char **)files) != 0) {
        ERROR("Reload conflists data from conf dir failed");
        ret = -1;
        goto out;
    }

out:
    util_free_array_by_len(files, length);
    return ret;
}

int isula_update_confist_from_dir()
{
    int ret = 0;
    size_t length = 0;
    char **files = NULL;

    if (get_conf_files(&files, &length) != 0) {
        ERROR("Get cni conf files in ascending order failed");
        ret = -1;
        goto out;
    }

    if (update_isula_conflist_with_lock(length, (const char **)files) != 0) {
        ERROR("Reload conflists data from conf dir failed");
        ret = -1;
        goto out;
    }

out:
    util_free_array_by_len(files, length);
    return ret;
}

static int get_cri_net_conflist_nolock(struct cni_network_list_conf ***store, size_t *res_len)
{
    size_t i = 0;
    int ret = 0;

    *res_len = 0;
    *store = (struct cni_network_list_conf **)util_smart_calloc_s(sizeof(struct cni_network_list_conf *),
                                                                  g_conflists.conflist_len);
    if (*store == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < g_conflists.conflist_len; i++) {
        struct cni_network_list_conf *list = NULL;
        list = util_smart_calloc_s(sizeof(struct cni_network_list_conf), 1);
        if (list == NULL) {
            ERROR("Out of momory, cannot allocate conflist store");
            ret = -1;
            goto out;
        }

        list->plugin_len = g_conflists.conflist[i]->plugin_len;
        list->name = util_strdup_s(g_conflists.conflist[i]->name);
        list->first_plugin_type = util_strdup_s(g_conflists.conflist[i]->first_plugin_type);
        list->first_plugin_name = util_strdup_s(g_conflists.conflist[i]->first_plugin_name);
        list->bytes = util_strdup_s(g_conflists.conflist[i]->bytes);
        (*store)[i] = list;
        (*res_len)++;
    }

out:
    if (ret != 0) {
        free_conflists_data(*store, *res_len);
        *store = NULL;
        *res_len = 0;
    }
    return ret;
}

int cri_get_conflist_from_dir(struct cni_network_list_conf ***store, size_t *res_len)
{
    int ret = 0;

    if (store == NULL || res_len == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    if (!conflists_rdlock()) {
        ERROR("Lock conflist data failed");
        return -1;
    }

    if (get_cri_net_conflist_nolock(store, res_len) != 0) {
        ERROR("Get cni network conflist failed");
        ret = -1;
        goto out;
    }

out:
    conflists_unlock();
    return ret;
}

static struct runtime_conf *build_loopback_runtime_conf(const char *cid, const char *netns_path)
{
    struct runtime_conf *rt = NULL;

    if (cid == NULL || netns_path == NULL) {
        ERROR("Invalid input params");
        return NULL;
    }

    rt = util_smart_calloc_s(sizeof(struct runtime_conf), 1);
    if (rt == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    rt->container_id = util_strdup_s(cid);
    rt->netns = util_strdup_s(netns_path);
    rt->ifname = util_strdup_s(LO_IFNAME);

out:
    return rt;
}

// inject runtime_conf args from annotation
static int inject_annotations_runtime_conf(map_t *annotations, struct runtime_conf *rt)
{
    int ret = 0;
    size_t i = 0;
    char *value = NULL;

    if (rt == NULL) {
        ERROR("Invalid input param");
        return -1;
    }
    if (annotations == NULL) {
        DEBUG("No annotations data to parse");
        goto out;
    }

    for (i = 0; i < g_numregistrants_rt; i++) {
        value = map_search(annotations, (void *)g_registrant_rt[i].name);
        if (value == NULL) {
            DEBUG("This key:%s is not found", g_registrant_rt[i].name);
            continue;
        }

        if (g_registrant_rt[i].ops(value, rt) != 0) {
            ERROR("The format of annotation is not right with key:%s, value:%s", g_registrant_rt[i].name, value);
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

// inject cni net conflist json from annotation
static int inject_annotations_json(map_t *annotations, char **net_list_conf_str)
{
    int ret = 0;
    size_t i = 0;
    char *value = NULL;

    if (annotations == NULL || net_list_conf_str == NULL) {
        ERROR("Invalid input param");
        return -1;
    }

    for (i = 0; i < g_numregistrants_json; i++) {
        value = map_search(annotations, (void *)g_registrant_json[i].name);
        if (value == NULL) {
            DEBUG("This key:%s is not surpported", g_registrant_json[i].name);
            continue;
        }

        if (g_registrant_json[i].ops(value, net_list_conf_str) != 0) {
            ERROR("The format of annotation is not right with key:%s, value:%s", g_registrant_json[i].name, value);
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static struct runtime_conf *build_cni_runtime_conf(const struct cni_manager *manager)
{
    int ret = 0;
    struct runtime_conf *rt = NULL;
    size_t i = 0;

    if (manager->cni_args == NULL || manager->cni_args->len == 0) {
        ERROR("No cni args found");
        return NULL;
    }

    rt = (struct runtime_conf *)util_smart_calloc_s(sizeof(struct runtime_conf), 1);
    if (rt == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    rt->container_id = util_strdup_s(manager->id);
    rt->netns = util_strdup_s(manager->netns_path);
    rt->ifname = util_strdup_s(manager->ifname);

    rt->args = (char *(*)[2])util_smart_calloc_s(sizeof(char *) * 2, manager->cni_args->len);
    if (rt->args == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    rt->args_len = manager->cni_args->len;
    for (i = 0; i < manager->cni_args->len; i++) {
        rt->args[i][0] = util_strdup_s(manager->cni_args->keys[i]);
        rt->args[i][1] = util_strdup_s(manager->cni_args->values[i]);
    }

    if (inject_annotations_runtime_conf(manager->annotations, rt) != 0) {
        ERROR("Inject annotations to runtime conf failed");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free_runtime_conf(rt);
        rt = NULL;
    }
    return rt;
}

// setup container loopback
int attach_loopback(const char *id, const char *netns)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    struct result *lo_result = NULL;
    char *net_conf_str = NULL;

    if (id == NULL || netns == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    net_conf_str = util_strdup_s(g_cni_manager.loopback_conf_str);
    rc = build_loopback_runtime_conf(id, netns);
    if (rc == NULL) {
        ERROR("Error building loopback runtime config");
        ret = -1;
        goto out;
    }

    if (cni_add_network_list(net_conf_str, rc, &lo_result) != 0) {
        ERROR("Add loopback network failed");
        ret = -1;
        goto out;
    }

out:
    free(net_conf_str);
    free_result(lo_result);
    free_runtime_conf(rc);
    return ret;
}

int cri_attach_network_plane(const struct cni_manager *manager, const char *net_list_conf_str, struct result **result)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    char *net_list_conf_str_var = NULL;

    if (manager == NULL || result == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    net_list_conf_str_var = util_strdup_s(net_list_conf_str);
    if (net_list_conf_str_var == NULL) {
        ERROR("Dup net list conf str failed");
        ret = -1;
        goto out;
    }

    rc = build_cni_runtime_conf(manager);
    if (rc == NULL) {
        ERROR("Error building CNI runtime config");
        ret = -1;
        goto out;
    }

    if (inject_annotations_json(manager->annotations, &net_list_conf_str_var) != 0) {
        ERROR("Inject annotations to net conf json failed");
        ret = -1;
        goto out;
    }

    if (cni_add_network_list(net_list_conf_str_var, rc, result) != 0) {
        ERROR("Add CNI network failed");
        ret = -1;
        goto out;
    }

out:
    free(net_list_conf_str_var);
    free_runtime_conf(rc);
    return ret;
}

int isula_attach_network_plane(const struct cni_manager *manager, const char *net_name, struct result **result)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    char *net_list_conf_str = NULL;

    if (manager == NULL || net_name == NULL || result == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    net_list_conf_str = map_search(g_conflists.map_isula_net_conf, (void *)net_name);
    if (net_list_conf_str == NULL) {
        ERROR("Invalid network name:%s, search cni network conflist NULL", net_name);
        ret = -1;
        goto out;
    }

    rc = build_cni_runtime_conf(manager);
    if (rc == NULL) {
        ERROR("Error building CNI runtime config");
        ret = -1;
        goto out;
    }

    if (inject_annotations_json(manager->annotations, &net_list_conf_str) != 0) {
        ERROR("Inject annotations to net conf json failed");
        ret = -1;
        goto out;
    }

    if (cni_add_network_list(net_list_conf_str, rc, result) != 0) {
        ERROR("Add CNI network failed");
        ret = -1;
        goto out;
    }

out:
    free(net_list_conf_str);
    free_runtime_conf(rc);
    return ret;

}

int cri_detach_network_plane(const struct cni_manager *manager, const char *net_list_conf_str, struct result **result)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    char *net_list_conf_str_var = NULL;

    if (manager == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    net_list_conf_str_var = util_strdup_s(net_list_conf_str);
    if (net_list_conf_str_var == NULL) {
        ERROR("Dup net list conf str failed");
        ret = -1;
        goto out;
    }

    rc = build_cni_runtime_conf(manager);
    if (rc == NULL) {
        ERROR("Error building CNI runtime config");
        ret = -1;
        goto out;
    }

    if (inject_annotations_json(manager->annotations, &net_list_conf_str_var) != 0) {
        ERROR("Inject annotations to net conf json failed");
        ret = -1;
        goto out;
    }

    if (cni_del_network_list(net_list_conf_str, rc) != 0) {
        ERROR("Error deleting network: %s", manager->name);
        ret = -1;
        goto out;
    }

out:
    free(net_list_conf_str_var);
    free_runtime_conf(rc);
    return ret;
}

int isula_detach_network_plane(const struct cni_manager *manager, const char *net_name, struct result **result)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    char *net_list_conf_str = NULL;

    if (manager == NULL || net_name == NULL || result == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    net_list_conf_str = map_search(g_conflists.map_isula_net_conf, (void *)net_name);
    if (net_list_conf_str == NULL) {
        ERROR("Invalid network name:%s, search cni network conflist NULL", net_name);
        ret = -1;
        goto out;
    }

    rc = build_cni_runtime_conf(manager);
    if (rc == NULL) {
        ERROR("Error building CNI runtime config");
        ret = -1;
        goto out;
    }

    if (inject_annotations_json(manager->annotations, &net_list_conf_str) != 0) {
        ERROR("Inject annotations to net conf json failed");
        ret = -1;
        goto out;
    }

    if (cni_del_network_list(net_list_conf_str, rc) != 0) {
        ERROR("Error deleting network: %s", manager->name);
        ret = -1;
        goto out;
    }

out:
    free(net_list_conf_str);
    free_runtime_conf(rc);
    return ret;

}

int detach_loopback(const char *id, const char *netns)
{
    int ret = 0;
    struct runtime_conf *rc = NULL;
    char *net_list_conf_str = NULL;

    net_list_conf_str = util_strdup_s(g_cni_manager.loopback_conf_str);
    rc = build_loopback_runtime_conf(id, netns);
    if (rc == NULL) {
        ERROR("Error building loopback runtime config");
        ret = -1;
        goto out;
    }

    if (cni_del_network_list(net_list_conf_str, rc) != 0) {
        ERROR("Error delete loopback network");
        ret = -1;
        goto out;
    }

out:
    free(net_list_conf_str);
    free_runtime_conf(rc);
    return ret;
}

void free_cni_manager(struct cni_manager *manager)
{
    if (manager == NULL) {
        return;
    }

    UTIL_FREE_AND_SET_NULL(manager->id);
    UTIL_FREE_AND_SET_NULL(manager->ifname);
    UTIL_FREE_AND_SET_NULL(manager->name);
    UTIL_FREE_AND_SET_NULL(manager->namespace);
    UTIL_FREE_AND_SET_NULL(manager->netns_path);
    map_free(manager->annotations);
    manager->annotations = NULL;
    free_json_map_string_string(manager->cni_args);
    manager->cni_args = NULL;

    free(manager);
}

int cni_manager_store_init(const char *cache_dir, const char *conf_path, const char* const *bin_paths,
                           size_t bin_paths_len)
{
    int ret = 0;

    if (conf_path == NULL) {
        ERROR("Invalid input param");
        return -1;
    }

    if (!cni_module_init(cache_dir, bin_paths, bin_paths_len)) {
        ERROR("Init libcni module failed");
        ret = -1;
        goto out;
    }

    if (pthread_rwlock_init(&(g_conflists.rwlock), NULL) != 0) {
        ERROR("Failed to init global conflists rwlock");
        ret = -1;
        goto out;
    }

    g_conflists.map_isula_net_conf = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (g_conflists.map_isula_net_conf == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    g_cni_manager.conf_path = util_strdup_s(conf_path);

out:
    return ret;
}