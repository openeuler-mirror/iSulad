/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuxu
 * Create: 2024-03-06
 * Description: provide cdi cache function
 ******************************************************************************/
#include "cdi_cache.h"

#include <stdlib.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/utils_array.h>

#include "utils.h"
#include "utils_file.h"
#include "path.h"
#include "error.h"
#include "cdi_device.h"
#include "cdi_spec.h"
#include "cdi_spec_dirs.h"
#include "cdi_container_edits.h"

// cache
static int cdi_set_spec_dirs(struct cdi_cache *c, string_array *spec_dirs);
static int configure(struct cdi_cache *c, string_array *spec_dirs);
static int refresh(struct cdi_cache *c);
static bool refresh_if_required(struct cdi_cache *c, bool force, int *ret);

// watch
static void free_cdi_watch(struct cdi_watch *watch);
static void watch_setup(struct cdi_watch *watch, string_array *dirs);
static void watch_start(struct cdi_cache *c);
static void watch_stop(struct cdi_watch *w);
static void *watch_thread_func(void *arg);
static bool watch_update(struct cdi_watch *w, const char *removed, int wd);

static int cdi_set_spec_dirs(struct cdi_cache *c, string_array *spec_dirs)
{
    __isula_auto_string_array_t string_array *new_spec_dirs = NULL;
    char clean_path[PATH_MAX] = { 0 };
    size_t i;

    if (c == NULL || spec_dirs == NULL) {
        ERROR("Invalid argument");
        return -1;
    }
    if (spec_dirs->len == 0) {
        return 0;
    }

    new_spec_dirs = util_string_array_new(spec_dirs->len);
    if (new_spec_dirs == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < spec_dirs->len; i++) {
        if (util_clean_path(spec_dirs->items[i], clean_path, sizeof(clean_path)) == NULL) {
            ERROR("Failed to get clean path %s", spec_dirs->items[i]);
            return -1;
        }
        if (util_append_string_array(new_spec_dirs, clean_path) != 0) {
            ERROR("Out of memory");
            return -1;
        }
    }
    util_free_string_array(c->spec_dirs);
    c->spec_dirs = new_spec_dirs;
    new_spec_dirs = NULL;

    return 0;
}

void free_cdi_cache(struct cdi_cache *c)
{
    if (c == NULL) {
        return;
    }

    util_free_string_array(c->spec_dirs);
    c->spec_dirs = NULL;
    map_free(c->specs);
    c->specs = NULL;
    map_free(c->devices);
    c->devices = NULL;
    free_cdi_watch(c->watch);
    c->watch = NULL;

    free(c);
}

struct cdi_cache *cdi_new_cache(string_array *spec_dirs)
{
    struct cdi_cache *c = NULL;
    int ret = 0;

    c = util_common_calloc_s(sizeof(*c));
    if (c == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    c->refresh_error_flag = false;
    c->auto_refresh = true;
    c->watch = util_common_calloc_s(sizeof(struct cdi_watch));
    if (c->watch == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    c->watch->watcher_fd = -1;

    if (cdi_set_spec_dirs(c, &g_default_spec_dirs) != 0) {
        ERROR("Failed to set spec dirs by default");
        goto free_out;
    }

    (void)pthread_mutex_lock(&c->mutex);
    ret = configure(c, spec_dirs);
    (void)pthread_mutex_unlock(&c->mutex);
    if (ret != 0) {
        ERROR("Failed to configure");
        goto free_out;
    }

    return c;

free_out:
    free_cdi_cache(c);
    return NULL;
}

static int cdi_configure(struct cdi_cache *c, string_array *spec_dirs)
{
    int ret = 0;

    if (c == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    (void)pthread_mutex_lock(&c->mutex);
    ret = configure(c, spec_dirs);
    (void)pthread_mutex_unlock(&c->mutex);

    return ret;
}

static int configure(struct cdi_cache *c, string_array *spec_dirs)
{
    int ret = 0;

    if (spec_dirs != NULL) {
        ret = cdi_set_spec_dirs(c, spec_dirs);
        if (ret != 0) {
            ERROR("Failed to apply cache spec dirs");
            return -1;
        }
    }

    watch_stop(c->watch);
    if (c->auto_refresh) {
        watch_setup(c->watch, c->spec_dirs);
        watch_start(c);
    }
    (void)refresh(c);
    return 0;
}

static int cdi_refresh(struct cdi_cache *c)
{
    bool refreshed;
    int ret = 0;
    
    if (c == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    (void)pthread_mutex_lock(&c->mutex);
    refreshed = refresh_if_required(c, !c->auto_refresh, &ret);
    if (refreshed) {
        goto unlock_out;
    }

    ret = c->refresh_error_flag ? -1 : 0;
unlock_out:
    (void)pthread_mutex_unlock(&c->mutex);
    return ret;
}

static void map_cdi_cache_specs_kvfree(void *key, void *value)
{
    free(key);
    util_free_common_array((common_array *)value);
}

static void map_cdi_cache_device_kvfree(void *key, void *value)
{
    free(key);
    /* 
     * map_cdi_cache_device_kvfree should not be recursively free cdi_cache_device.
     * Otherwise, the function conflicts with the cdi_cache_specs free devices,
     * triggering double free. 
     */
    (void)value;
}

static bool resolve_conflict(struct cdi_scan_fn_maps *scan_fn_maps, const char *name,
                             struct cdi_cache_device *dev, struct cdi_cache_device *old)
{
    map_t *conflicts = scan_fn_maps->conflicts;
    bool *refresh_error_flag = scan_fn_maps->refresh_error_flag;
    const struct cdi_cache_spec *dev_spec = NULL;
    const struct cdi_cache_spec *old_spec = NULL;
    int dev_prio;
    int old_prio;
    bool val = true;
    const char *dev_path = NULL;
    const char *old_path = NULL;

    dev_spec = cdi_device_get_spec(dev);
    old_spec = cdi_device_get_spec(old);
    dev_prio = cdi_spec_get_priority(dev_spec);
    old_prio = cdi_spec_get_priority(old_spec);
    if (dev_prio > old_prio) {
        return false;
    } else if (dev_prio == old_prio) {
        dev_path = cdi_spec_get_path(dev_spec);
        old_path = cdi_spec_get_path(old_spec);
        *refresh_error_flag = true;
        ERROR("Conflicting device %s (specs %s, %s)", name, dev_path, old_path);
        if (!map_replace(conflicts, (void *)name, (void *)&val)) {
            ERROR("Failed to insert bool to conflicts by name %s", name);
            return true;
        }
    } else {
        // do nothing
    }

    return true;
}

static void refresh_scan_spec_func(struct cdi_scan_fn_maps *scan_fn_maps, const char *path, 
                                    int priority, struct cdi_cache_spec *spec)
{
    map_t *specs = scan_fn_maps->specs;
    map_t *devices = scan_fn_maps->devices;
    bool *refresh_error_flag = scan_fn_maps->refresh_error_flag;
    char clean_path[PATH_MAX] = { 0 };
    __isula_auto_free char *tmp_error = NULL;
    const char *vendor = NULL;
    __isula_auto_common_array_t common_array *spec_array = NULL;
    map_itor *itor = NULL;
    __isula_auto_free char *qualified = NULL;
    struct cdi_cache_device *dev = NULL;
    struct cdi_cache_device *other = NULL;

    if (util_clean_path(path, clean_path, sizeof(clean_path)) == NULL) {
        ERROR("Failed to get clean path %s", path);
        goto error_out;
    }

    vendor = cdi_spec_get_vendor(spec);
    spec_array = map_search(specs, (void *)vendor);
    if (spec_array == NULL) {
        spec_array = util_common_array_new(1, (free_common_array_item_cb)free_cdi_cache_spec, util_clone_ptr);
        if (spec_array == NULL) {
            ERROR("Out of memory");
            goto error_out;
        }
        if (!map_insert(specs, (void *)vendor, spec_array)) {
            ERROR("Failed to insert spec array to specs");
            goto error_out;
        }
    }
    if (util_append_common_array(spec_array, spec) != 0) {
        ERROR("Failed to append spec");
        goto error_out;
    }
    spec_array = NULL;

    itor = map_itor_new(spec->devices);
    if (itor == NULL) {
        ERROR("Out of memory, create new map itor failed");
        goto error_out;
    }
    for (; map_itor_valid(itor); map_itor_next(itor)) {
        dev = map_itor_value(itor);
        qualified = cdi_device_get_qualified_name(dev);
        other = map_search(devices, (void *)qualified);
        if (other != NULL) {
            if (resolve_conflict(scan_fn_maps, qualified, dev, other)) {
                continue;
            }
        }
        if (!map_replace(devices, (void *)qualified, dev)) {
            ERROR("Failed to insert device to devices by name %s", qualified);
            goto error_out;
        }
        free(qualified);
        qualified = NULL;
    }
    goto out;

error_out:
    *refresh_error_flag = true;
out:
    map_itor_free(itor);
    return;
}

static int refresh(struct cdi_cache *c)
{
    int ret = 0;
    map_t *specs = NULL;
    map_t *devices = NULL;
    map_t *conflicts = NULL;
    struct cdi_scan_fn_maps scan_fn_maps = { 0 };
    map_itor *itor = NULL;
    char *conflict = NULL;

    c->refresh_error_flag = false;
    specs = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, map_cdi_cache_specs_kvfree);
    if (specs == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }
    devices = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, map_cdi_cache_device_kvfree);
    if (devices == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }
    conflicts = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (conflicts == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }

    scan_fn_maps.specs = specs;
    scan_fn_maps.devices = devices;
    scan_fn_maps.conflicts = conflicts;
    scan_fn_maps.refresh_error_flag = &c->refresh_error_flag;
    // ignore error when scan spec dirs
    (void)cdi_scan_spec_dirs(c->spec_dirs, &scan_fn_maps, refresh_scan_spec_func);

    itor = map_itor_new(conflicts);
    if (itor == NULL) {
        ERROR("Out of memory, create new map itor failed");
        ret = -1;
        goto free_out;
    }
    for (; map_itor_valid(itor); map_itor_next(itor)) {
        conflict = map_itor_key(itor);
        if ((map_search(devices, conflict) != NULL) &&
            !map_remove(devices, conflict)) {
            ERROR("Failed to remove conflict device from devices");
            ret = -1;
            goto free_out;
        }
    }

    util_swap_ptr((void **)&c->specs, (void **)&specs);
    util_swap_ptr((void **)&c->devices, (void **)&devices);

    ret = c->refresh_error_flag ? -1 : 0;
    
free_out:
    map_itor_free(itor);
    map_free(specs);
    map_free(devices);
    map_free(conflicts);
    return ret;
}

static bool refresh_if_required(struct cdi_cache *c, bool force, int *ret)
{
    if (force || (c->auto_refresh && watch_update(c->watch, NULL, -1))) {
        *ret = refresh(c);
        return true;
    }
    return false;
}

static void map_spec_ptr_kvfree(void *key, void *value)
{
    // do not need free spec*
    (void)key;
    free(value);
}

static int cdi_inject_devices(struct cdi_cache *c, oci_runtime_spec *oci_spec, string_array *devices)
{
    int ret = 0;
    __isula_auto_string_array_t string_array *unresolved = NULL;
    cdi_container_edits *edits = NULL;
    map_t *specs = NULL;
    size_t i;
    const char *device = NULL;
    struct cdi_cache_device *d = NULL;
    int tmp_val = 0;
    __isula_auto_free char *unresolved_str = NULL;

    if (c == NULL || devices == NULL) {
        ERROR("Can't inject devices");
        return -1;
    }
    if (oci_spec == NULL) {
        ERROR("Can't inject devices, nil OCI Spec");
        return -1;
    }

    unresolved = util_common_calloc_s(sizeof(*unresolved));
    if (unresolved == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    specs = map_new(MAP_PTR_INT, MAP_DEFAULT_CMP_FUNC, map_spec_ptr_kvfree);
    if (specs == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    edits = util_common_calloc_s(sizeof(*edits));
    if (edits == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    (void)pthread_mutex_lock(&c->mutex);

    (void)refresh_if_required(c, false, &ret);

    for(i = 0; i < devices->len; i++) {
        device = devices->items[i];
        d = map_search(c->devices, (void *)device);
        if (d == NULL) {
            if (util_append_string_array(unresolved, device) != 0) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
            continue;
        }
        if (map_search(specs, (void *)cdi_device_get_spec(d)) == NULL) {
            if (!map_insert(specs, (void *)cdi_device_get_spec(d), (void *)&tmp_val)) {
                ERROR("Failed to insert spec ptr to specs when find device %s", device);
                ret = -1;
                goto out;
            }
            if (cdi_container_edits_append(edits, cdi_spec_get_edits(cdi_device_get_spec(d))) != 0) {
                ERROR("Failed to append edits when find device %s", device);
                ret = -1;
                goto out;
            }
        }
        if (cdi_container_edits_append(edits, cdi_device_get_edits(d)) != 0) {
            ERROR("Failed to append edits when find device %s", device);
            ret = -1;
            goto out;
        }
    }

    if (unresolved->len != 0) {
        unresolved_str = util_string_join(", ", (const char **)unresolved->items, unresolved->len);
        ERROR("Unresolvable CDI devices %s", unresolved_str);
        ret = -1;
        goto out;
    }

    ret = cdi_container_edits_apply(edits, oci_spec);
    if (ret != 0) {
        ERROR("Failed to apply edits when inject devices");
        ret = -1;
    }

out:
    (void)pthread_mutex_unlock(&c->mutex);
    map_free(specs);
    free_cdi_container_edits(edits);
    return ret;
}

static struct cdi_cache_ops g_cdi_cache_ops = {
    .inject_devices = cdi_inject_devices,
    .configure = cdi_configure,
    .refresh = cdi_refresh
};

struct cdi_cache_ops *cdi_get_cache_ops(void)
{
    return &g_cdi_cache_ops;
}

static void free_cdi_watch(struct cdi_watch *w)
{
    if (w == NULL) {
        return;
    }

    watch_stop(w);
    free(w);
}

static int init_tracked(struct cdi_watch *w, string_array *dirs)
{
    size_t i;
    bool tmp_value = false;

    w->tracked = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (w->tracked == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for(i = 0; i < dirs->len; i++) {
        if (!map_replace(w->tracked, (void *)dirs->items[i], (void *)&tmp_value)) {
            ERROR("Failed to insert tracked by dir %s", dirs->items[i]);
            goto error_out;
        }
    }
    w->wd_dirs = map_new(MAP_INT_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (w->wd_dirs == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }

    return 0;

error_out:
    map_free(w->tracked);
    w->tracked = NULL;
    return -1;
}

static void watch_setup(struct cdi_watch *w, string_array *dirs)
{
    if (w == NULL || dirs == NULL || dirs->len == 0) {
        ERROR("Invalid param");
        return;
    }

    if (init_tracked(w, dirs) != 0) {
        ERROR("Failed to initialize tracked");
        return;
    }

    w->watcher_fd = inotify_init();
    if (w->watcher_fd < 0) {
        ERROR("Failed to initialize inotify fd");
        map_free(w->tracked);
        w->tracked = NULL;
        map_free(w->wd_dirs);
        w->wd_dirs = NULL;
        return;
    }

    (void)watch_update(w, NULL, -1);
}

static void watch_start(struct cdi_cache *c)
{
    pthread_t thread = 0;
    int ret = 0;

    ret = pthread_create(&thread, NULL, watch_thread_func, c);
    if (ret != 0) {
        ERROR("Cdi watch thread create failed");
        return;
    }
}

static void watch_stop(struct cdi_watch *w)
{
    if (w == NULL) {
        return;
    }

    if (w->watcher_fd >= 0) {
        close(w->watcher_fd);
        w->watcher_fd = -1;
    }
    map_free(w->tracked);
    w->tracked = NULL;
    map_free(w->wd_dirs);
    w->wd_dirs = NULL;
}

// wait_events wait until inotify
static int wait_events(int watcher_fd)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(watcher_fd, &rfds);
    return select(FD_SETSIZE, &rfds, NULL, NULL, NULL);
}

#define CDI_WATCH_EVENTS    (IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE | IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF)

static int process_cdi_events(int watcher_fd, struct cdi_cache *c)
{
    ssize_t events_length = 0;
    ssize_t events_index = 0;
    struct inotify_event *cdi_event = NULL;
    char buffer[MAXLINE] __attribute__((aligned(__alignof__(struct inotify_event)))) = { 0 };
    int update_cnt = 0;
    __isula_auto_free char *event_dir = NULL;

    events_length = util_read_nointr(watcher_fd, buffer, sizeof(buffer));
    if (events_length <= 0) {
        ERROR("Failed to wait events");
        return -1;
    }

    (void)pthread_mutex_lock(&c->mutex);
    
    while (events_index < events_length) {
        cdi_event = (struct inotify_event *)(&buffer[events_index]);
        ssize_t event_size = (ssize_t)(cdi_event->len) + (ssize_t)offsetof(struct inotify_event, name);
        if (event_size == 0 || event_size > (events_length - events_index)) {
            break;
        }
        events_index += event_size;

        /*  
         *  file: 
         *      Rename:  mask == IN_MOVED_TO | IN_MOVED_FROM
         *      Remove:  mask == IN_MOVED_FROM || mask == IN_DELETE
         *      Write:   mask == IN_MODIFY
         *  dir:
         *      Remove: mask == IN_MOVE_SELF || mask == IN_DELETE_SELF
         */
        if ((cdi_event->mask & CDI_WATCH_EVENTS) == 0) {
            continue;
        }
        DEBUG("Cdi spec file %s is changed", cdi_event->name);
        if (cdi_event->mask == IN_MODIFY) {
            if (!util_has_suffix(cdi_event->name, ".json")) {
                WARN("Invalid spec %s ext", cdi_event->name);
                continue;
            }
        }
        event_dir = util_strdup_s(map_search(c->watch->wd_dirs, &(cdi_event->wd)));
        if (!(cdi_event->mask == IN_DELETE_SELF || cdi_event->mask == IN_MOVE_SELF)) {
            free(event_dir);
            event_dir = NULL;
        }
        watch_update(c->watch, event_dir, cdi_event->wd);
        update_cnt++;
    }
    if (update_cnt > 0) {
        (void)refresh(c);
    }

    (void)pthread_mutex_unlock(&c->mutex);
    return 0;
}

// Watch Spec directory changes, triggering a refresh if necessary.
static void *watch_thread_func(void *arg)
{
    struct cdi_cache *c = (struct cdi_cache *)arg;
    int errcode = 0;
    int watcher_fd = -1;

    errcode = pthread_detach(pthread_self());
    if (errcode != 0) {
        errno = errcode;
        SYSERROR("Detach thread failed");
        return NULL;
    }

    prctl(PR_SET_NAME, "cdi-watcher");

    watcher_fd = c->watch->watcher_fd;
    if (watcher_fd < 0) {
        ERROR("Invalid inotify fd");
        return NULL;
    }

    for (;;) {
        if (wait_events(watcher_fd) < 0) {
            ERROR("Failed to wait events");
            break;
        }
        if (process_cdi_events(watcher_fd, c) != 0) {
            break;
        }
    }
    return NULL;
}

static void update_remove_watch_dir(struct cdi_watch *w, const char *dir, int wd)
{
    bool tmp_value = false;
    if (wd >= 0) {
        (void)inotify_rm_watch(w->watcher_fd, wd);
        if ((map_search(w->wd_dirs, &wd) != NULL) &&
            !map_remove(w->wd_dirs, &wd)) {
            ERROR("Failed to remove watch fd of %s", dir);
        }
    }
    if (!map_replace(w->tracked, (void *)dir, (void *)&tmp_value)) {
        ERROR("Failed to insert tracked by dir %s", dir);
    }
}

static void update_add_watch_dir(struct cdi_watch *w, const char *dir, bool *update)
{
    int wd = -1;
    bool tmp_value = true;

    wd = inotify_add_watch(w->watcher_fd, dir, CDI_WATCH_EVENTS);
    if (wd < 0) {
        if (errno == ENOENT) {
            SYSINFO("Watch device dir %s", dir);
        } else {
            SYSERROR("Failed to watch device dir %s", dir);
        }
        return;
    } else {
        DEBUG("Watching %s for device disovery", dir);
        tmp_value = true;
        if (!map_replace(w->tracked, (void *)dir, (void *)&tmp_value)) {
            ERROR("Failed to insert tracked by dir %s", dir);
            goto error_out;
        }
        if (!map_replace(w->wd_dirs, (void *)&wd, (void *)dir)) {
            ERROR("Failed to insert dir %s by wd", dir);
            goto error_out;
        }
        *update = true;
    }
    return;

error_out:
    update_remove_watch_dir(w, dir, wd);
}

static bool watch_update(struct cdi_watch *w, const char *removed, int wd)
{
    const char *dir = NULL;
    bool *ok = NULL;
    bool update = false;
    map_itor *itor = NULL;

    itor = map_itor_new(w->tracked);
    if (itor == NULL) {
        ERROR("Out of memory, create new map itor failed");
        return false;
    }
    for (; map_itor_valid(itor); map_itor_next(itor)) {
        dir = map_itor_key(itor);
        ok = map_itor_value(itor);
        if (ok == NULL || *ok) {
            continue;
        }
        update_add_watch_dir(w, dir, &update);
    }

    if (removed != NULL) {
        update_remove_watch_dir(w, removed, wd);
        WARN("Directory removed: %s", removed);
        update = true;
    }

    map_itor_free(itor);
    return update;
}
