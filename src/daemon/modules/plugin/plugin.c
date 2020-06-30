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
 * Author: jingrui
 * Create: 2018-12-01
 * Description: provide plugin definition
 ******************************************************************************/

#include <dirent.h>
#include <stddef.h>
#include <sys/inotify.h>
#include <linux/limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "isula_libutils/log.h"
#include "plugin.h"
#include "pspec.h"
#include "utils.h"
#include "parser.h"
#include "buffer.h"
#include "isulad_config.h"
#include "specs.h"
#include "specs_extend.h"
#include "rest_common.h"
#include "container_api.h"
#include "constants.h"

#include "isula_libutils/plugin_activate_plugin_request.h"
#include "isula_libutils/plugin_activate_plugin_response.h"
#include "isula_libutils/plugin_init_plugin_request.h"
#include "isula_libutils/plugin_init_plugin_response.h"
#include "isula_libutils/plugin_event_pre_create_request.h"
#include "isula_libutils/plugin_event_pre_create_response.h"
#include "isula_libutils/plugin_event_pre_start_request.h"
#include "isula_libutils/plugin_event_pre_start_response.h"
#include "isula_libutils/plugin_event_post_stop_request.h"
#include "isula_libutils/plugin_event_post_stop_response.h"
#include "isula_libutils/plugin_event_post_remove_request.h"
#include "isula_libutils/plugin_event_post_remove_response.h"

#define plugin_socket_path "/run/isulad/plugins"
#define plugin_socket_file_regex ".*.sock$"

// suffix is '.sock'
#define PLUGIN_SOCKET_FILE_SUFFIX_LEN 5

#define PLUGIN_ACTIVATE_MAX_RETRY 3

#ifndef RestHttpHead
#define RestHttpHead "http://localhost"
#endif
#define PluginServiceActivate "/PluginService/Activate"
#define PluginServiceInit "/PluginService/Init"
#define PluginServicePreCreate "/PluginService/PreCreate"
#define PluginServicePreStart "/PluginService/PreStart"
#define PluginServicePostStop "/PluginService/PostStop"
#define PluginServicePostRemove "/PluginService/PostRemove"

static plugin_manager_t *g_plugin_manager;

static int pm_init_plugin(const plugin_t *plugin);

static int plugin_event_pre_start_handle(const plugin_t *plugin, const char *cid);
static int plugin_event_post_stop_handle(const plugin_t *plugin, const char *cid);
static int plugin_event_post_remove_handle(const plugin_t *plugin, const char *cid);

enum plugin_action { ACTIVE_PLUGIN, DEACTIVE_PLUGIN };

static inline int check_err(int err, const char *msg)
{
    if (err) {
        return -1;
    }
    if (msg != NULL && strlen(msg) > 0) {
        return -1;
    }
    return 0;
}

static char *dup_cid(const container_t *cont)
{
    return util_strdup_s(cont->common_config->id);
}

/*
 * return container status, defined by Container_Status.
 */
static int get_status(const container_t *cont)
{
    return (int)state_get_status(cont->state);
}

/*
 * join , seperated string into one.
 */
static char *join_enable_plugins(const char *plugins)
{
    char *default_plugins = NULL;
    char *tmp = NULL;
    char *ep = NULL;

    default_plugins = conf_get_enable_plugins();

    if ((default_plugins == NULL) && (plugins == NULL)) {
        return NULL;
    }

    if (plugins == NULL) {
        return default_plugins;
    }

    if (default_plugins == NULL) {
        return util_strdup_s(plugins);
    }

    tmp = util_string_append(ISULAD_ENABLE_PLUGINS_SEPERATOR, default_plugins);
    if (tmp == NULL) {
        ERROR("string append failed %s -> %s", ISULAD_ENABLE_PLUGINS_SEPERATOR, default_plugins);
        goto out;
    }

    ep = util_string_append(plugins, tmp);
    if (ep == NULL) {
        ERROR("string append failed %s -> %s", plugins, tmp);
        goto out;
    }

out:
    free(default_plugins);
    free(tmp);
    return ep;
}

static char *get_uniq_enable_plugins(const oci_runtime_spec *oci)
{
    char *names = NULL;
    char *full = NULL;
    char **raw = NULL;
    char **arr = NULL;
    size_t i = 0;

    if (oci == NULL) {
        goto failed;
    }

    names = oci_container_get_env(oci, ISULAD_ENABLE_PLUGINS);
    full = join_enable_plugins(names);
    if (full == NULL) {
        INFO("no plugins enabled");
        goto failed;
    }

    raw = util_string_split(full, ISULAD_ENABLE_PLUGINS_SEPERATOR_CHAR);
    if (raw == NULL) {
        ERROR("split plugin name failed");
        goto failed;
    }
    UTIL_FREE_AND_SET_NULL(names);
    UTIL_FREE_AND_SET_NULL(full);

    for (i = 0; i < util_array_len((const char **)raw); i++) {
        if (strings_in_slice((const char **)arr, util_array_len((const char **)arr), raw[i])) {
            continue;
        }
        if (util_array_append(&arr, raw[i]) != 0) {
            ERROR("append uniq plugin name failed");
            goto failed;
        }
    }

    names = util_string_join(ISULAD_ENABLE_PLUGINS_SEPERATOR, (const char **)arr, util_array_len((const char **)arr));
    if (names == NULL) {
        ERROR("join uniq plugin name failed");
        goto failed;
    }

    full = util_string_append(names, ISULAD_ENABLE_PLUGINS "=");
    if (full == NULL) {
        ERROR("init uniq enable plugins env failed");
        goto failed;
    }

    util_free_array(raw);
    util_free_array(arr);
    free(names);
    return full;

failed:
    util_free_array(raw);
    util_free_array(arr);
    free(names);
    free(full);
    return NULL;
}

static int set_env_enable_plugins(oci_runtime_spec *oci)
{
    char *uniq = NULL;

    if (oci == NULL) {
        ERROR("BUG oci should not be nil");
        goto failed;
    }

    if (oci->process == NULL) {
        ERROR("BUG oci->process should not be nil");
        oci->process = util_common_calloc_s(sizeof(defs_process));
        if (oci->process == NULL) {
            ERROR("out of memory");
            goto failed;
        }
    }

    uniq = get_uniq_enable_plugins(oci);
    if (uniq == NULL) {
        goto failed;
    }

    if (util_env_insert(&oci->process->env, &oci->process->env_len, ISULAD_ENABLE_PLUGINS,
                        strlen(ISULAD_ENABLE_PLUGINS), uniq)) {
        WARN("set env %s failed", uniq);
    }

    free(uniq);
    return 0;

failed:
    free(uniq);
    return -1;
}

static char **get_enable_plugins(const char *plugins)
{
    char **arr = NULL;
    size_t i, arr_len;
    char **dst = NULL;
    size_t dst_len = 0;

    if (plugins == NULL) {
        return dst;
    }

    arr = util_string_split(plugins, ISULAD_ENABLE_PLUGINS_SEPERATOR_CHAR);
    if (arr == NULL) {
        ERROR("Out of memory");
        goto out;
    }
    arr_len = util_array_len((const char **)arr);

    for (i = 0; i < arr_len; i++) {
        if (strings_in_slice((const char **)dst, dst_len, arr[i])) {
            continue;
        }
        if (util_array_append(&dst, arr[i]) != 0) {
            util_free_array(dst);
            dst = NULL;
            goto out;
        }
        dst_len = util_array_len((const char **)dst);
    }

    if (arr_len != dst_len) {
        ERROR("enable plugins not unique: %s", plugins);
    }

out:
    util_free_array(arr);
    return dst;
}

static uint64_t plugin_get_init_type(const plugin_t *p)
{
    if (p == NULL) {
        return 0;
    }

    if (p->manifest == NULL) {
        return 0;
    }

    return p->manifest->init_type;
}

static int get_plugin_dir(char *plugin_dir)
{
    int ret = 0;
    char *statedir = NULL;

    if (plugin_dir == NULL) {
        return -1;
    }

    statedir = conf_get_isulad_statedir();
    if (statedir == NULL) {
        ERROR("failed get statedir");
        return -1;
    }

    ret = snprintf(plugin_dir, PATH_MAX, "%s/plugins", statedir);
    if (ret < 0 || (size_t)ret >= PATH_MAX) {
        goto failed;
    }

    ret = util_mkdir_p(plugin_dir, DEFAULT_SECURE_FILE_MODE);
    if (ret < 0) {
        goto failed;
    }

    free(statedir);
    return 0;

failed:
    free(statedir);
    return -1;
}

// wait_events wait until inotify
static int wait_events(int inotify_fd)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(inotify_fd, &rfds);
    return select(FD_SETSIZE, &rfds, NULL, NULL, NULL);
}

static int verify_plugin_address(const char *plugin_addr)
{
    struct stat fileStat = { 0 };
    // add file permission check??
    // only owner root mode 600 is allowed
    //
    // check weather it is socket file
    if (!stat(plugin_addr, &fileStat)) {
        if (S_ISSOCK(fileStat.st_mode)) {
            return 0;
        } else {
            INFO("Skip %s, mode(%o).", plugin_addr, fileStat.st_mode & S_IFMT);
            return -1;
        }
    } else {
        ERROR("Failed to get(%s) file stat.", plugin_addr);
        return -1;
    }
}

static int get_plugin_addr_and_name(char *plugin_addr, char *plugin_name, const char *filename, const char *plugin_dir,
                                    int action)
{
    size_t str_length = 0;
    int nret = 0;

    if (filename == NULL) {
        return -1;
    }
    str_length = strlen(filename);

    if (util_reg_match(plugin_socket_file_regex, filename)) {
        ERROR("not plugin filename %s", filename);
        goto out;
    }
    (void)strcpy(plugin_name, filename);

    plugin_name[str_length - PLUGIN_SOCKET_FILE_SUFFIX_LEN] = 0;
    nret = snprintf(plugin_addr, PATH_MAX, "%s/%s", plugin_dir, filename);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("get plugin addr failed %s", filename);
        goto out;
    }

    if (action == DEACTIVE_PLUGIN) {
        return 0;
    }
    return verify_plugin_address(plugin_addr);
out:
    ERROR("invalid plugin socket(%s), skipping..", filename);
    return -1;
}

static int pm_activate_plugin_with_retry(plugin_t *plugin, size_t retry)
{
    size_t i = 0;
    int err = 0;

    for (i = 0; i < retry; i++) {
        err = pm_activate_plugin(plugin);
        if (!err) {
            return 0;
        }
        sleep((unsigned int)i + 1);
    }

    return err;
}

static void pm_rdlock(void)
{
    int errcode;

    errcode = pthread_rwlock_rdlock(&g_plugin_manager->pm_rwlock);
    if (errcode != 0) {
        ERROR("Read lock failed: %s", strerror(errcode));
    }
}

static void pm_wrlock(void)
{
    int errcode;

    errcode = pthread_rwlock_wrlock(&g_plugin_manager->pm_rwlock);
    if (errcode != 0) {
        ERROR("Write lock failed: %s", strerror(errcode));
    }
}

static void pm_unlock(void)
{
    int errcode;

    errcode = pthread_rwlock_unlock(&g_plugin_manager->pm_rwlock);
    if (errcode != 0) {
        ERROR("Unlock failed: %s", strerror(errcode));
    }
}

static void free_plugin(plugin_t *plugin)
{
    if (plugin == NULL) {
        return;
    }
    UTIL_FREE_AND_SET_NULL(plugin->name);
    UTIL_FREE_AND_SET_NULL(plugin->addr);
    UTIL_FREE_AND_SET_NULL(plugin->manifest);
    UTIL_FREE_AND_SET_NULL(plugin->activated_errmsg);
    free(plugin);
}

static int do_get_plugin(const char *name, plugin_t **rplugin)
{
    plugin_t *plugin = NULL;

    pm_rdlock();
    plugin = map_search(g_plugin_manager->np, (void *)name);
    plugin_get(plugin);
    pm_unlock();

    *rplugin = plugin;

    if (plugin == NULL) {
        return -1;
    }

    return 0;
}

static int pm_register_plugin(const char *name, const char *addr)
{
    int err;
    plugin_t *plugin = NULL;

    /*
     * this function called in reload_plugin, remember dont call reload_plugin
     * agaim.
     */
    err = do_get_plugin(name, &plugin);
    if (err == 0) { /* plugin already exist */
        pm_put_plugin(plugin);
        DEBUG("skip register exist plugin %s", name);
        return 0;
    }

    plugin = plugin_new(name, addr);
    if (plugin == NULL) {
        ERROR("alloc plugin failed");
        goto failed;
    }
    err = pm_activate_plugin_with_retry(plugin, PLUGIN_ACTIVATE_MAX_RETRY);
    if (err != 0) {
        ERROR("active plugin failed");
        goto failed;
    }

    if (plugin_get_init_type(plugin) != PLUGIN_INIT_SKIP) {
        err = pm_init_plugin(plugin);
        if (err != 0) {
            ERROR("init plugin failed");
            goto failed;
        }
    }

    err = pm_add_plugin(plugin);
    if (err != 0) {
        ERROR("add plugin to map failed");
        goto failed;
    }

    INFO("add activated plugin %s 0x%lx", plugin->name, plugin->manifest->watch_event);
    return 0;

failed:
    free_plugin(plugin);
    return -1;
}

static int pm_unregister_plugin(const char *name, const char *addr)
{
    int err = 0;
    plugin_t *plugin = NULL;

    err = pm_get_plugin(name, &plugin);
    if (err != 0) {
        ERROR("plugin %s not exist in manager", name);
        return -1;
    }

    err = pm_deactivate_plugin(plugin);
    if (err != 0) { /* ignore errors */
        ERROR("deactivate plugin %s failed", name);
    }

    pm_put_plugin(plugin);

    err = pm_del_plugin(plugin);
    if (err != 0) {
        ERROR("can not del plugin %s", name);
        return -1;
    }

    return 0;
}

static int handle_plugin_event(const char *event_name, const char *plugin_dir, int action)
{
    char addr[PATH_MAX] = { 0 };
    char name[PATH_MAX] = { 0 };

    if (get_plugin_addr_and_name(addr, name, event_name, plugin_dir, action) < 0) {
        return -1;
    }
    switch (action) {
        case ACTIVE_PLUGIN:
            INFO("Activate plugin: %s...", name);
            pm_register_plugin(name, addr);
            break;
        case DEACTIVE_PLUGIN:
            INFO("Deactivate plugin: %s...", name);
            pm_unregister_plugin(name, addr);
            break;
        default:
            INFO("Unsupport action, skip...");
    }
    return 0;
}

static int reload_plugin(const char *name)
{
    char plugin_dir[PATH_MAX] = { 0 };
    char filename[PATH_MAX] = { 0 };
    int ret = 0;

    INFO("reload plugin %s ...", name);

    if (get_plugin_dir(plugin_dir) < 0) {
        ERROR("get plugin dir failed");
        return -1;
    }

    ret = snprintf(filename, PATH_MAX, "%s.sock", name);
    if (ret < 0 || ret >= PATH_MAX) {
        ERROR("get plugin addr failed %s", filename);
        return -1;
    }

    return handle_plugin_event(filename, plugin_dir, ACTIVE_PLUGIN);
}

static int scan_existing_plugins(const char *dir)
{
    DIR *midir = NULL;
    struct dirent *info_archivo = NULL;

    midir = opendir(dir);
    if (midir == NULL) {
        ERROR("scan_existing_plugins : Error in opendir");
        return -1;
    }

    info_archivo = readdir(midir);
    while (info_archivo != 0) {
        // skip . ..
        if (strncmp(info_archivo->d_name, ".", PATH_MAX) == 0 || strncmp(info_archivo->d_name, "..", PATH_MAX) == 0) {
            info_archivo = readdir(midir);
            continue;
        }

        handle_plugin_event(info_archivo->d_name, dir, ACTIVE_PLUGIN);
        info_archivo = readdir(midir);
    }
    closedir(midir);
    return 0;
}

static int process_plugin_events(int inotify_fd, const char *plugin_dir)
{
    ssize_t events_length = 0;
    ssize_t events_index = 0;
    struct inotify_event *plugin_event = NULL;
    char buffer[8192 + 1] = { 0 };
    int action = 0;
    events_length = read(inotify_fd, buffer, 8192);

    if (events_length <= 0) {
        ERROR("Failed to wait events");
        return -1;
    }

    while (events_index < events_length) {
        plugin_event = (struct inotify_event *)(&buffer[events_index]);
        ssize_t event_size = (ssize_t)(plugin_event->len) + (ssize_t)offsetof(struct inotify_event, name);
        // should deal with events_index > events_length??
        if (event_size == 0 || event_size > (events_length - events_index)) {
            break;
        }
        events_index += event_size;
        if (plugin_event->mask & IN_CREATE) {
            action = ACTIVE_PLUGIN;
        } else if (plugin_event->mask & IN_DELETE) {
            action = DEACTIVE_PLUGIN;
        } else {
            continue;
        }

        handle_plugin_event(plugin_event->name, plugin_dir, action);
    }
    return 0;
}

/*
 * plugin_manager_routine manages the lifecycles of plugins
 * include: discovery, active and deactive
 * */
static void *plugin_manager_routine(void *arg)
{
    int inotify_fd = 0;
    int wd = 0;
    char plugin_dir[PATH_MAX] = { 0 };
    int errcode = 0;

    errcode = pthread_detach(pthread_self());
    if (errcode != 0) {
        ERROR("Detach thread failed: %s", strerror(errcode));
        return NULL;
    }
    if (pm_init() < 0) {
        ERROR("init pm failed");
        return NULL;
    }
    if (get_plugin_dir(plugin_dir) < 0) {
        ERROR("Failed to create plugin dir");
        return NULL;
    }
    if (scan_existing_plugins(plugin_dir) < 0) {
        ERROR("Failed to scan existing plugins");
        return NULL;
    }
    // initilize inotify instance
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        ERROR("Failed to initalize inotify instance");
        return NULL;
    }
    // add plugin_dir to watch
    wd = inotify_add_watch(inotify_fd, plugin_dir, IN_CREATE | IN_DELETE);
    if (wd < 0) {
        ERROR("Failed to watch plugin dir");
        return NULL;
    }
    DEBUG("Watching %s for plugin disovery", plugin_dir);
    for (;;) {
        if (wait_events(inotify_fd) < 0) {
            ERROR("Failed to wait events");
            // something abnormal occurs, wait for 1 second and continue
            sleep(1);
            continue;
        }
        process_plugin_events(inotify_fd, plugin_dir);
    }
}

int start_plugin_manager(void)
{
    pthread_t thread = 0;
    int ret = 0;
    ret = pthread_create(&thread, NULL, plugin_manager_routine, NULL);
    if (ret) {
        ERROR("Thread creation failed");
        return -1;
    }
    return 0;
}

static void plugin_rdlock(plugin_t *plugin)
{
    int errcode;

    errcode = pthread_rwlock_rdlock(&plugin->lock);
    if (errcode != 0) {
        ERROR("Plugin read lock failed: %s", strerror(errcode));
    }
}

static void plugin_wrlock(plugin_t *plugin)
{
    int errcode;

    errcode = pthread_rwlock_wrlock(&plugin->lock);
    if (errcode != 0) {
        ERROR("Plugin write lock failed: %s", strerror(errcode));
    }
}

static void plugin_unlock(plugin_t *plugin)
{
    int errcode;

    errcode = pthread_rwlock_unlock(&plugin->lock);
    if (errcode != 0) {
        ERROR("Plugin unlock failed: %s", strerror(errcode));
    }
}

plugin_t *plugin_new(const char *name, const char *addr)
{
    plugin_t *plugin = NULL;
    int errcode = 0;

    plugin = util_common_calloc_s(sizeof(plugin_t));
    if (plugin == NULL) {
        goto bad;
    }

    errcode = pthread_rwlock_init(&plugin->lock, NULL);
    if (errcode != 0) {
        ERROR("Plugin init lock failed: %s", strerror(errcode));
        goto bad;
    }
    plugin->name = util_strdup_s(name);
    plugin->addr = util_strdup_s(addr);

    plugin->manifest = util_common_calloc_s(sizeof(plugin_manifest_t));
    if (plugin->manifest == NULL) {
        goto bad;
    }

    return plugin;

bad:
    free_plugin(plugin);
    return NULL;
}

int plugin_set_activated(plugin_t *plugin, bool activated, const char *errmsg)
{
    plugin_wrlock(plugin);
    plugin->activated = activated;
    if (errmsg != NULL) {
        plugin->activated_errcnt++;
        UTIL_FREE_AND_SET_NULL(plugin->activated_errmsg);
        plugin->activated_errmsg = util_strdup_s(errmsg);
    } else {
        plugin->activated_errcnt = 0;
        UTIL_FREE_AND_SET_NULL(plugin->activated_errmsg);
    }
    plugin_unlock(plugin);
    return 0;
}

int plugin_set_manifest(plugin_t *plugin, const plugin_manifest_t *manifest)
{
    if (manifest == NULL) {
        return -1;
    }

    plugin_wrlock(plugin);
    plugin->manifest->init_type = manifest->init_type;
    plugin->manifest->watch_event = manifest->watch_event;
    plugin_unlock(plugin);
    return 0;
}

void plugin_get(plugin_t *plugin)
{
    if (plugin == NULL) {
        return;
    }

    atomic_int_inc(&plugin->ref);
}

void plugin_put(plugin_t *plugin)
{
    if (plugin == NULL) {
        return;
    }

    if (!atomic_int_dec_test(&plugin->ref)) {
        return;
    }

    free_plugin(plugin);
    return;
}

bool plugin_is_watching(plugin_t *plugin, uint64_t pe)
{
    bool ok = 0;

    if (plugin == NULL) {
        ERROR("nil plugin");
        return 0;
    }

    plugin_rdlock(plugin);
    if (plugin->manifest == NULL) {
        ERROR("nil manifest");
        ok = 0;
    } else {
        ok = plugin->manifest->watch_event & pe;
    }
    plugin_unlock(plugin);

    INFO("plugin %s watching=%s for event 0x%lx", plugin->name, (ok ? "true" : "false"), pe);

    return ok;
}

static int unpack_activate_response(const struct parsed_http_message *message, void *arg)
{
    int ret = 0;
    plugin_manifest_t *manifest = arg;
    plugin_activate_plugin_response *resp = NULL;
    parser_error err = NULL;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    resp = plugin_activate_plugin_response_parse_data(message->body, NULL, &err);
    if (resp == NULL) {
        ERROR("parse activate response failed: %s", err);
        ret = -1;
        goto out;
    }

    if (check_err(resp->err_code, resp->err_message) != 0) {
        ERROR("activate response error: code = %d, message = %s", resp->err_code, resp->err_message);
        ret = -1;
        goto out;
    }

    INFO("get resp 0x%lx", resp->watch_event);
    manifest->init_type = resp->init_type;
    manifest->watch_event = resp->watch_event;

out:
    free(err);
    free_plugin_activate_plugin_response(resp);

    return ret;
}

int pm_activate_plugin(plugin_t *plugin)
{
    int ret = 0;
    int nret = 0;
    plugin_activate_plugin_request reqs = { 0 };
    char *body = NULL;
    size_t body_len = 0;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;
    Buffer *output = NULL;
    char *errmsg = NULL;
    plugin_manifest_t manifest = { 0 };
    char socket[PATH_MAX] = { 0 };

    body = plugin_activate_plugin_request_generate_json(&reqs, &ctx, &err);
    if (body == NULL) {
        ERROR("marshal activate request to %s failed", plugin->addr);
        ret = -1;
        goto out;
    }

    body_len = strlen(body) + 1;
    nret = snprintf(socket, PATH_MAX, "unix://%s", plugin->addr);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("get plugin socket failed");
        ret = -1;
        goto out;
    }

    ret = rest_send_requst(socket, RestHttpHead PluginServiceActivate, body, body_len, &output);
    if (ret != 0) {
        ERROR("send activate request to %s failed", plugin->addr);
        goto out;
    }

    ret = get_response(output, unpack_activate_response, (void *)(&manifest));
    if (ret != 0) {
        ERROR("unpack activate response from %s failed", plugin->addr);
        goto out;
    }

out:
    plugin_set_activated(plugin, ret == 0, errmsg);
    plugin_set_manifest(plugin, &manifest);

    buffer_free(output);
    free(err);
    free(body);

    return ret;
}

int pm_deactivate_plugin(plugin_t *plugin)
{
    return 0;
}

static bool plugin_useby_container(const plugin_t *plugin, const container_t *cont)
{
    bool ok = false;
    char *plugin_names = NULL;
    char **pnames = NULL;
    size_t i = 0;

    if (plugin == NULL || cont == NULL) {
        return ok;
    }

    if (plugin->name == NULL) {
        return ok;
    }

    plugin_names = container_get_env_nolock(cont, ISULAD_ENABLE_PLUGINS);
    pnames = get_enable_plugins(plugin_names);

    for (i = 0; i < util_array_len((const char **)pnames); i++) {
        if (strcmp(pnames[i], plugin->name) == 0) {
            ok = true;
            break;
        }
    }

    free(plugin_names);
    free(pnames);
    return ok;
}

static int unpack_init_response(const struct parsed_http_message *message, void *arg)
{
    int ret = 0;
    plugin_init_plugin_response *resp = NULL;
    parser_error err = NULL;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    resp = plugin_init_plugin_response_parse_data(message->body, NULL, &err);
    if (resp == NULL) {
        ret = -1;
        ERROR("parse init response failed");
        goto out;
    }

    ret = check_err(resp->err_code, resp->err_message);
    if (ret != 0) {
        isulad_set_error_message(resp->err_message);
        ERROR("init response error massge (%d)%s", resp->err_code, resp->err_message);
        goto out;
    }

    INFO("plugin init ok");
out:
    free(err);
    free_plugin_init_plugin_response(resp);

    return ret;
}

/*
 * add container info into reqs.elem.
 */
static int pm_prepare_init_reqs(const plugin_t *plugin, plugin_init_plugin_request *reqs, const char *cid)
{
    int ret = 0;
    container_t *cont = NULL;
    oci_runtime_spec *ocic = NULL;
    plugin_init_plugin_request_containers_element *elem = NULL;

    cont = containers_store_get(cid);
    if (cont == NULL) { /* container not exist, nothing to do */
        return 0;
    }

    if (!plugin_useby_container(plugin, cont)) {
        goto out;
    }

    if (plugin_get_init_type(plugin) == PLUGIN_INIT_SKIP) {
        goto out;
    }

    if (plugin_get_init_type(plugin) == PLUGIN_INIT_WITH_CONTAINER_RUNNING &&
        get_status(cont) != CONTAINER_STATUS_RUNNING) {
        goto out;
    }

    elem = util_common_calloc_s(sizeof(plugin_init_plugin_request_containers_element));
    if (elem == NULL) {
        ret = -1;
        ERROR("Out of memory");
        goto out;
    }

    elem->id = dup_cid(cont);
    if (elem->id == NULL) {
        ret = -1;
        ERROR("Out of memory");
        goto out;
    }

    elem->status = get_status(cont);

    ocic = load_oci_config(cont->root_path, elem->id);
    if (ocic == NULL) {
        ret = -1;
        ERROR("read oci config failed");
        goto out;
    }

    elem->pspec = get_pspec(ocic);
    if (elem->pspec == NULL) {
        ret = -1;
        ERROR("marshal pspec failed");
        goto out;
    }

    reqs->containers[reqs->containers_len] = elem;
    elem = NULL;
    reqs->containers_len++;

out:
    free_plugin_init_plugin_request_containers_element(elem);
    container_unref(cont);

    free_oci_runtime_spec(ocic);
    return ret;
}

static int pm_init_plugin(const plugin_t *plugin)
{
    int ret = 0;
    int nret = 0;
    char **cnames = NULL;
    size_t container_num = 0;
    plugin_init_plugin_request reqs = { 0 };
    char *body = NULL;
    size_t body_len = 0;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;
    Buffer *output = NULL;
    char socket[PATH_MAX] = { 0 };
    size_t i = 0;

    cnames = containers_store_list_ids();
    container_num = util_array_len((const char **)cnames);

    /*
     * send init request no matter containers exist or not, plugin should
     * prepare or delete dirty resource.
     */
    if (container_num) {
        if (container_num > SIZE_MAX / sizeof(plugin_init_plugin_request_containers_element *)) {
            ERROR("Invalid container nums");
            ret = -1;
            goto out;
        }
        reqs.containers = util_common_calloc_s(container_num * sizeof(plugin_init_plugin_request_containers_element *));
        if (reqs.containers == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
    }
    /*
     * add elem to reqs, if no containers availabe add no elem.
     */
    for (i = 0; i < container_num; i++) {
        ret = pm_prepare_init_reqs(plugin, &reqs, cnames[i]);
        if (ret != 0) {
            ret = -1;
            ERROR("failed prepare init reqs");
            goto out;
        }
    }

    body = plugin_init_plugin_request_generate_json(&reqs, &ctx, &err);
    if (body == NULL) {
        ERROR("marshal plugin init request to %s failed %s", plugin->addr, err);
        ret = -1;
        goto out;
    }

    body_len = strlen(body) + 1;
    nret = snprintf(socket, PATH_MAX, "unix://%s", plugin->addr);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("get plugin socket failed %s", plugin->addr);
        ret = -1;
        goto out;
    }
    ret = rest_send_requst(socket, RestHttpHead PluginServiceInit, body, body_len, &output);
    if (ret != 0) {
        ret = -1;
        ERROR("plugin init request to %s failed", plugin->addr);
        goto out;
    }

    ret = get_response(output, unpack_init_response, NULL);
    if (ret != 0) {
        ret = -1;
        ERROR("unpack plugin init response from %s failed", plugin->addr);
        goto out;
    }

out:
    util_free_array(cnames);
    cnames = NULL;
    for (i = 0; i < reqs.containers_len; i++) {
        UTIL_FREE_AND_SET_NULL(reqs.containers[i]->id);
        UTIL_FREE_AND_SET_NULL(reqs.containers[i]->pspec);
        UTIL_FREE_AND_SET_NULL(reqs.containers[i]);
    }
    UTIL_FREE_AND_SET_NULL(reqs.containers);

    buffer_free(output);

    free(err);
    free(body);
    return ret;
}

int pm_add_plugin(plugin_t *plugin)
{
    int ok = 0;
    pm_wrlock();
    ok = map_insert(g_plugin_manager->np, (void *)plugin->name, plugin);
    pm_unlock();

    if (!ok) {
        return -1;
    }

    /* plugin_put() called in pm_del_plugin() */
    plugin_get(plugin);
    return 0;
}

int pm_del_plugin(const plugin_t *plugin)
{
    int ok;
    pm_wrlock();
    /* plugin_put() called in map_remove() by pm_np_item_free() */
    ok = map_remove(g_plugin_manager->np, (void *)plugin->name);
    pm_unlock();
    if (!ok) {
        return -1;
    }

    return 0;
}

int pm_get_plugin(const char *name, plugin_t **rplugin)
{
    if (do_get_plugin(name, rplugin) == 0) {
        return 0;
    }

    if (reload_plugin(name)) {
        return -1;
    }

    return do_get_plugin(name, rplugin);
}

void pm_put_plugin(plugin_t *plugin)
{
    plugin_put(plugin);
}

int pm_get_plugins_nolock(uint64_t pe, plugin_t ***rplugins, size_t *count)
{
    int ret = 0;
    int i = 0;
    size_t size = 0;
    plugin_t **plugins = NULL;
    map_itor *itor = NULL;

    size = map_size(g_plugin_manager->np);
    if (size == 0) { /* empty */
        return 0;
    }
    if (size > SIZE_MAX / sizeof(plugin_t *)) {
        ret = -1;
        ERROR("Invalid plugins size");
        goto out;
    }

    plugins = util_common_calloc_s(sizeof(plugin_t *) * size);
    if (plugins == NULL) {
        ret = -1;
        ERROR("Out of memory");
        goto out;
    }

    itor = map_itor_new(g_plugin_manager->np);
    if (itor == NULL) {
        ret = -1;
        ERROR("Out of memory");
        goto out;
    }

    for (i = 0; i < (int)size && map_itor_valid(itor); i++, map_itor_next(itor)) {
        plugins[i] = map_itor_value(itor);
        /* plugin_put() called in pm_put_plugins() */
        plugin_get(plugins[i]);
    }

    *rplugins = plugins;
    *count = (size_t)i;

out:
    map_itor_free(itor);
    itor = NULL;

    if (ret < 0) {
        UTIL_FREE_AND_SET_NULL(plugins);
    }

    return ret;
}

static void pm_np_item_free(void *key, void *val)
{
    plugin_t *plugin = val;
    free(key);
    plugin_put(plugin);
}

static void pm_free(plugin_manager_t *gpm)
{
    if (gpm == NULL) {
        return;
    }
    map_free(gpm->np);
    pthread_rwlock_destroy(&gpm->pm_rwlock);
    free(gpm);
}

int pm_init(void)
{
    int ret = 0;
    plugin_manager_t *gpm = NULL;

    if (g_plugin_manager != NULL) {
        return 0;
    }

    gpm = util_common_calloc_s(sizeof(plugin_manager_t));
    if (gpm == NULL) {
        return -1;
    }

    ret = pthread_rwlock_init(&gpm->pm_rwlock, NULL);
    if (ret != 0) {
        ret = -1;
        goto bad;
    }

    gpm->np = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, pm_np_item_free);
    if (gpm->np == NULL) {
        goto bad;
    }

    g_plugin_manager = gpm;

    return 0;
bad:
    pm_free(gpm);
    gpm = NULL;

    return -1;
}

static int plugin_event_handle_dispath_impl(const char *cid, const char *plugins, uint64_t pe)
{
    int ret = 0;
    plugin_t *plugin = NULL;
    char **pnames = NULL;
    size_t i = 0;

    pnames = get_enable_plugins(plugins);
    if (pnames == NULL) {
        goto out;
    }

    for (i = 0; i < util_array_len((const char **)pnames); i++) {
        if (pm_get_plugin(pnames[i], &plugin)) { /* plugin not found */
            ERROR("plugin %s not registered.", pnames[i]);
            ret = -1;
            continue;
        }
        if (!plugin_is_watching(plugin, pe)) {
            pm_put_plugin(plugin);
            continue;
        }

        switch (pe) {
            case PLUGIN_EVENT_CONTAINER_PRE_START:
                ret = plugin_event_pre_start_handle(plugin, cid);
                break;
            case PLUGIN_EVENT_CONTAINER_POST_STOP:
                ret = plugin_event_post_stop_handle(plugin, cid);
                break;
            case PLUGIN_EVENT_CONTAINER_POST_REMOVE:
                ret = plugin_event_post_remove_handle(plugin, cid);
                break;
            default:
                ERROR("plugin event %ld not support.", pe);
                ret = -1;
                break;
        }

        pm_put_plugin(plugin);
        plugin = NULL;
        if (ret != 0) {
            ret = -1;
            continue;
        }
    }

out:
    util_free_array(pnames);
    return ret;
}

static int plugin_event_handle_dispath(const container_t *cont, uint64_t pe)
{
    int ret = 0;
    char *cid = NULL;
    char *plugins = NULL;

    cid = dup_cid(cont);
    if (cid == NULL) {
        return 0;
    }

    plugins = container_get_env_nolock(cont, ISULAD_ENABLE_PLUGINS);
    ret = plugin_event_handle_dispath_impl(cid, plugins, pe);
    free(cid);
    free(plugins);
    return ret;
}

static int unpack_event_pre_create_response(const struct parsed_http_message *message, void *arg)
{
    int ret = 0;
    char **pspec = arg;
    char *dst = NULL;
    plugin_event_pre_create_response *resp = NULL;
    parser_error err = NULL;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    resp = plugin_event_pre_create_response_parse_data(message->body, NULL, &err);
    if (resp == NULL) {
        ERROR("parse pre-create response failed");
        ret = -1;
        goto out;
    }

    ret = check_err(resp->err_code, resp->err_message);
    if (ret) {
        isulad_set_error_message(resp->err_message);
        ret = -1;
        ERROR("pre-create response error massge (%d)%s", resp->err_code, resp->err_message);
        goto out;
    }

    INFO("pre-create %s ok", resp->id);

    if (resp->pspec == NULL) {
        ret = -1;
        ERROR("plugin pre-create response missing pspec");
        goto out;
    }

    dst = merge_pspec(*pspec, resp->pspec);
    if (dst == NULL) {
        ERROR("plugin pre-create failed to merge pspec");
        goto out;
    }

    *pspec = dst;
    dst = NULL;

out:
    free(dst);
    free(err);
    free_plugin_event_pre_create_response(resp);
    return ret;
}

static int plugin_event_pre_create_handle(const plugin_t *plugin, const char *cid, char **base)
{
    int ret = 0;
    int nret = 0;
    char *body = NULL;
    size_t body_len = 0;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;
    Buffer *output = NULL;
    char *dst = NULL;
    char *new = NULL;
    char socket[PATH_MAX] = { 0 };
    plugin_event_pre_create_request reqs = { 0 };

    reqs.id = (char *)cid;
    reqs.pspec = *base;

    body = plugin_event_pre_create_request_generate_json(&reqs, &ctx, &err);
    if (body == NULL) {
        ERROR("marshal event precreate request to %s failed", plugin->addr);
        ret = -1;
        goto out;
    }

    body_len = strlen(body) + 1;
    nret = snprintf(socket, sizeof(socket), "unix://%s", plugin->addr);
    if (nret < 0 || (size_t)nret >= sizeof(socket)) {
        ERROR("get plugin socket failed %s", plugin->addr);
        ret = -1;
        goto out;
    }

    ret = rest_send_requst(socket, RestHttpHead PluginServicePreCreate, body, body_len, &output);
    if (ret != 0) {
        ret = -1;
        ERROR("send event precreate request to %s failed", plugin->addr);
        goto out;
    }

    ret = get_response(output, unpack_event_pre_create_response, (void *)(&new));
    if (ret != 0) {
        ret = -1;
        ERROR("unpack event precreate response from %s failed", plugin->addr);
        goto out;
    }

    dst = merge_pspec(*base, new);
    if (dst == NULL) {
        ret = -1;
        ERROR("update pspec json failed");
        goto out;
    }

    free(*base);
    *base = dst;
    dst = NULL;

out:
    free(dst);
    free(new);
    buffer_free(output);
    free(err);
    free(body);
    return ret;
}

int plugin_event_container_pre_create(const char *cid, oci_runtime_spec *ocic)
{
    int ret = 0;
    plugin_t *plugin = NULL;
    char **pnames = NULL;
    size_t i = 0;
    char *plugin_names = NULL;
    char *pspec = NULL;

    if (cid == NULL) {
        ERROR("cid is nil pointer");
        return -1;
    }

    if (ocic == NULL) {
        ERROR("oci spec nil pointer");
        return -1;
    }

    if (ocic->process == NULL) {
        ERROR("oci spec missing process field");
        return -1;
    }

    set_env_enable_plugins(ocic);
    plugin_names = oci_container_get_env(ocic, ISULAD_ENABLE_PLUGINS);
    pnames = get_enable_plugins(plugin_names);
    if (pnames == NULL) {
        goto out;
    }

    pspec = get_pspec(ocic);
    if (pspec == NULL) {
        ret = -1;
        ERROR("failed generate json for pspec");
        goto out;
    }
    for (i = 0; i < util_array_len((const char **)pnames); i++) {
        if (pm_get_plugin(pnames[i], &plugin)) { /* plugin not found */
            ERROR("plugin %s not registered.", pnames[i]);
            ret = -1;
            break;
        }
        if (!plugin_is_watching(plugin, (uint64_t)PLUGIN_EVENT_CONTAINER_PRE_CREATE)) {
            pm_put_plugin(plugin);
            continue;
        }
        ret = plugin_event_pre_create_handle(plugin, cid, &pspec);
        pm_put_plugin(plugin);
        plugin = NULL;
        if (ret != 0) {
            ret = -1;
            break;
        }
    }

    if (ret == 0) { /* all plugins works fine */
        ret = set_pspec(ocic, pspec);
        if (ret != 0) {
            ERROR("plugin pre-create failed to set pspec into oci");
        }
    } else {
        ERROR("plugin pre-create failed");
    }

out:
    free(pspec);
    free(plugin_names);
    util_free_array(pnames);
    return ret;
}

static int unpack_event_pre_start_response(const struct parsed_http_message *message, void *arg)
{
    int ret = 0;
    plugin_event_pre_start_response *resp = NULL;
    parser_error err = NULL;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    resp = plugin_event_pre_start_response_parse_data(message->body, NULL, &err);
    if (resp == NULL) {
        ret = -1;
        ERROR("parse pre-start response failed");
        goto out;
    }

    ret = check_err(resp->err_code, resp->err_message);
    if (ret != 0) {
        isulad_set_error_message(resp->err_message);
        ERROR("pre-start response error massge (%d)%s", resp->err_code, resp->err_message);
        goto out;
    }

    INFO("pre-start %s ok", resp->id);

out:
    free(err);
    free_plugin_event_pre_start_response(resp);
    return ret;
}

static int plugin_event_pre_start_handle(const plugin_t *plugin, const char *cid)
{
    int ret = 0;
    int nret = 0;
    char *body = NULL;
    size_t body_len = 0;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;
    Buffer *output = NULL;
    char socket[PATH_MAX] = { 0 };
    plugin_event_pre_start_request reqs = { 0 };

    reqs.id = (char *)cid;

    body = plugin_event_pre_start_request_generate_json(&reqs, &ctx, &err);
    if (body == NULL) {
        ERROR("marshal event prestart request to %s failed", plugin->addr);
        ret = -1;
        goto out;
    }

    body_len = strlen(body) + 1;
    nret = snprintf(socket, sizeof(socket), "unix://%s", plugin->addr);
    if (nret < 0 || (size_t)nret >= sizeof(socket)) {
        ERROR("get plugin socket failed %s", plugin->addr);
        ret = -1;
        goto out;
    }

    ret = rest_send_requst(socket, RestHttpHead PluginServicePreStart, body, body_len, &output);
    if (ret != 0) {
        ret = -1;
        ERROR("send event prestart request to %s failed", plugin->addr);
        goto out;
    }

    ret = get_response(output, unpack_event_pre_start_response, NULL);
    if (ret != 0) {
        ret = -1;
        ERROR("unpack event prestart response from %s failed", plugin->addr);
        goto out;
    }

out:
    buffer_free(output);

    free(err);
    free(body);
    return ret;
}

int plugin_event_container_pre_start(const container_t *cont)
{
    if (cont == NULL) {
        ERROR("container nil pointer");
        return 0;
    }

    return plugin_event_handle_dispath(cont, (uint64_t)PLUGIN_EVENT_CONTAINER_PRE_START);
}

static int unpack_event_post_stop_response(const struct parsed_http_message *message, void *arg)
{
    int ret = 0;
    plugin_event_post_stop_response *resp = NULL;
    parser_error err = NULL;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    resp = plugin_event_post_stop_response_parse_data(message->body, NULL, &err);
    if (resp == NULL) {
        ret = -1;
        ERROR("plugin event post_stop response parse failed");
        goto out;
    }

    ret = check_err(resp->err_code, resp->err_message);
    if (ret != 0) {
        isulad_set_error_message(resp->err_message);
        ERROR("post-stop response error massge (%d)%s", resp->err_code, resp->err_message);
        goto out;
    }

    INFO("post-stop %s ok", resp->id);

out:
    free(err);

    free_plugin_event_post_stop_response(resp);

    return ret;
}

static int plugin_event_post_stop_handle(const plugin_t *plugin, const char *cid)
{
    int ret = 0;
    int nret = 0;
    char *body = NULL;
    size_t body_len = 0;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;
    Buffer *output = NULL;
    char socket[PATH_MAX] = { 0 };
    plugin_event_post_stop_request reqs = { 0 };

    reqs.id = (char *)cid;

    body = plugin_event_post_stop_request_generate_json(&reqs, &ctx, &err);
    if (body == NULL) {
        ERROR("marshal event post_stop request to %s failed", plugin->addr);
        ret = -1;
        goto out;
    }

    body_len = strlen(body) + 1;
    nret = snprintf(socket, sizeof(socket), "unix://%s", plugin->addr);
    if (nret < 0 || (size_t)nret >= sizeof(socket)) {
        ERROR("get plugin socket failed %s", plugin->addr);
        ret = -1;
        goto out;
    }

    ret = rest_send_requst(socket, RestHttpHead PluginServicePostStop, body, body_len, &output);
    if (ret != 0) {
        ret = -1;
        ERROR("send event post_stop request to %s failed", plugin->addr);
        goto out;
    }

    ret = get_response(output, unpack_event_post_stop_response, NULL);
    if (ret != 0) {
        ret = -1;
        ERROR("unpack event post_stop response from %s failed", plugin->addr);
        goto out;
    }

out:
    buffer_free(output);
    free(err);
    free(body);
    return ret;
}

int plugin_event_container_post_stop(const container_t *cont)
{
    if (cont == NULL) {
        ERROR("container nil pointer");
        return 0;
    }

    return plugin_event_handle_dispath(cont, (uint64_t)PLUGIN_EVENT_CONTAINER_POST_STOP);
}

static int unpack_event_post_remove_response(const struct parsed_http_message *message, void *arg)
{
    int ret = 0;
    plugin_event_post_remove_response *resp = NULL;
    parser_error err = NULL;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    resp = plugin_event_post_remove_response_parse_data(message->body, NULL, &err);
    if (resp == NULL) {
        ret = -1;
        ERROR("plugin event post_remove response parse failed");
        goto out;
    }

    ret = check_err(resp->err_code, resp->err_message);
    if (ret != 0) {
        isulad_set_error_message(resp->err_message);
        ERROR("post-remove response error massge (%d)%s", resp->err_code, resp->err_message);
        goto out;
    }

    INFO("post-remove %s ok", resp->id);

out:
    free(err);

    free_plugin_event_post_remove_response(resp);

    return ret;
}

static int plugin_event_post_remove_handle(const plugin_t *plugin, const char *cid)
{
    int ret = 0;
    int nret = 0;
    char *body = NULL;
    size_t body_len = 0;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;
    Buffer *output = NULL;
    char socket[PATH_MAX] = { 0 };
    plugin_event_post_remove_request reqs = { 0 };

    reqs.id = (char *)cid;

    body = plugin_event_post_remove_request_generate_json(&reqs, &ctx, &err);
    if (body == NULL) {
        ERROR("marshal event post_remove request to %s failed", plugin->addr);
        ret = -1;
        goto out;
    }

    body_len = strlen(body) + 1;
    nret = snprintf(socket, sizeof(socket), "unix://%s", plugin->addr);
    if (nret < 0 || (size_t)nret >= sizeof(socket)) {
        ERROR("get plugin socket failed %s", plugin->addr);
        ret = -1;
        goto out;
    }

    ret = rest_send_requst(socket, RestHttpHead PluginServicePostRemove, body, body_len, &output);
    if (ret != 0) {
        ret = -1;
        ERROR("send event post_remove request to %s failed", plugin->addr);
        goto out;
    }

    ret = get_response(output, unpack_event_post_remove_response, NULL);
    if (ret != 0) {
        ret = -1;
        ERROR("unpack event post_remove response from %s failed", plugin->addr);
        goto out;
    }

out:
    buffer_free(output);
    free(err);
    free(body);
    return ret;
}

int plugin_event_container_post_remove(const container_t *cont)
{
    if (cont == NULL) {
        ERROR("container nil pointer");
        return 0;
    }

    return plugin_event_handle_dispath(cont, (uint64_t)PLUGIN_EVENT_CONTAINER_POST_REMOVE);
}

int plugin_event_container_post_remove2(const char *cid, const oci_runtime_spec *oci)
{
    char *plugins = NULL;
    char *cidx = NULL;
    int ret = 0;

    if (cid == NULL) {
        ERROR("cid nil pointer");
        return 0;
    }

    if (oci == NULL) {
        ERROR("oci nil pointer");
        return 0;
    }

    if (oci->process == NULL) {
        ERROR("oci->process nil pointer");
        return 0;
    }

    plugins = oci_container_get_env(oci, ISULAD_ENABLE_PLUGINS);
    cidx = util_strdup_s(cid);
    if (cidx == NULL) {
        ERROR("out of memory");
        goto out;
    }

    ret = plugin_event_handle_dispath_impl(cidx, plugins, (uint64_t)PLUGIN_EVENT_CONTAINER_POST_REMOVE);

out:
    free(cidx);
    free(plugins);
    return ret;
}
