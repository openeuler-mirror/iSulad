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

#ifndef DAEMON_MODULES_API_PLUGIN_API_H
#define DAEMON_MODULES_API_PLUGIN_API_H /* _PLUGIN_H_ */

#include <pthread.h>

#include "map.h"
#include "specs_api.h" /* oci_runtime_spec */
#include "container_api.h" /* container_t */

/*
 * returned int should means:
 *      0       success
 *     -1       failed
 * if not or has other values, please add comment to the function prototype.
 *
 * when check return value, if want to ingore err, please reset err=0 and add
 * comment.
 */

#define PLUGIN_INIT_SKIP 0
#define PLUGIN_INIT_WITH_CONTAINER_RUNNING 1
#define PLUGIN_INIT_WITH_CONTAINER_ALL 2

#define PLUGIN_EVENT_CONTAINER_PRE_CREATE 1UL
#define PLUGIN_EVENT_CONTAINER_PRE_START (1UL << 1)
#define PLUGIN_EVENT_CONTAINER_POST_STOP (1UL << 2)
#define PLUGIN_EVENT_CONTAINER_POST_REMOVE (1UL << 3)

typedef struct plugin_manifest {
    uint64_t init_type;
    uint64_t watch_event;
} plugin_manifest_t;

typedef struct plugin {
    pthread_rwlock_t lock;

    const char *name;
    const char *addr;
    plugin_manifest_t *manifest;

    bool activated;
    size_t activated_errcnt;
    char *activated_errmsg;

    uint64_t ref;
} plugin_t;

/*
 * plugin_new() will take initial get. when the plugin should free, one
 * more plugint_put() shall be called.
 */
plugin_t *plugin_new(const char *name, const char *addr);
void plugin_get(plugin_t *plugin); /* ref++ */
void plugin_put(plugin_t *plugin); /* ref-- */

int plugin_set_activated(plugin_t *plugin, bool activated, const char *errmsg);
int plugin_set_manifest(plugin_t *plugin, const plugin_manifest_t *manifest);
bool plugin_is_watching(plugin_t *plugin, uint64_t pe);

typedef struct plugin_manager {
    pthread_rwlock_t pm_rwlock;
    map_t *np; /* name:plugin */
    map_t *eps; /* watch_event:plugins */
} plugin_manager_t;

/*
 * init at isulad start, scan and init/sync all plugins
 */
int pm_init(void);
int pm_scan(void);
/*
 * destroy at isulad exit
 */
int pm_destroy();
/*
 * init plugin manifest
 */
int pm_activate_plugin(plugin_t *plugin);
int pm_deactivate_plugin(plugin_t *plugin);

int pm_add_plugin(plugin_t *plugin);
int pm_del_plugin(const plugin_t *plugin);

/*
 * make sure get and put called in-pairs.
 * if not, please add comment.
 */
int pm_get_plugin(const char *name, plugin_t **rplugin);
void pm_put_plugin(plugin_t *plugin);
int pm_get_plugins_nolock(uint64_t pe, plugin_t ***rplugins, size_t *count);

int start_plugin_manager(void);
int plugin_event_container_pre_create(const char *cid, oci_runtime_spec *ocic);
int plugin_event_container_pre_start(const container_t *cont);
int plugin_event_container_post_stop(const container_t *cont);
int plugin_event_container_post_remove(const container_t *cont);
int plugin_event_container_post_remove2(const char *cid, const oci_runtime_spec *oci);

#endif // DAEMON_MODULES_API_PLUGIN_API_H
