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
 * Description: provide cdi container edits function
 ******************************************************************************/
#include "cdi_container_edits.h"

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/log.h>
#include <isula_libutils/utils_array.h>

#include "error.h"
#include "path.h"
#include "specs_extend.h"
#include "utils.h"
#include "utils_array.h"
#include "specs_api.h"

/* 
 * The OCI being used by the iSulad not supportes 
 * createRuntime/createContainer/startContainer currently.
 */
// PRESTART_HOOK is the name of the OCI "prestart" hook.
#define PRESTART_HOOK "prestart"
// POSTSTART_HOOK is the name of the OCI "poststart" hook.
#define POSTSTART_HOOK "poststart"
// POSTSTOP_HOOK is the name of the OCI "poststop" hook.
#define POSTSTOP_HOOK "poststop"

#define VALID_HOOK_NAME_LEN     3
static const char* g_valid_hook_names[VALID_HOOK_NAME_LEN] = {
    PRESTART_HOOK, POSTSTART_HOOK, POSTSTOP_HOOK
};

static int cdi_validate_env(char **envs, size_t envs_len);
static int cdi_validate_device_node(cdi_device_node *d);
static int cdi_validate_hook(cdi_hook *h);
static int cdi_validate_mount(cdi_mount *m);

#define BLOCK_DEVICE    "b"
#define CHAR_DEVICE     "c"
#define FIFO_DEVICE     "p"
static int device_info_from_path(const char *path, char **dev_type, int64_t *major, int64_t *minor)
{
    struct stat stat = { 0 };
    int ret = 0;

    ret = lstat(path, &stat);
    if (ret != 0) {
        ERROR("Failed to stat %s", path);
        return -1;
    }

    if (S_ISBLK(stat.st_mode)) {
        *dev_type = util_strdup_s(BLOCK_DEVICE);
    } else if (S_ISCHR(stat.st_mode)) {
        *dev_type = util_strdup_s(CHAR_DEVICE);
    } else if (S_ISFIFO(stat.st_mode)) {
        *dev_type = util_strdup_s(FIFO_DEVICE);
    } else {
        *dev_type = NULL;
        *major = 0;
        *minor = 0;
        ERROR("Not a device node");
        return -1;
    }

    *major = (int64_t)major(stat.st_rdev);
    *minor = (int64_t)minor(stat.st_rdev);
    return 0;
}

static int fill_device_node_info(cdi_device_node *d)
{
    __isula_auto_free char *dev_type = NULL;
    int64_t major;
    int64_t minor;

    if (d->host_path == NULL) {
        d->host_path = util_strdup_s(d->path);
    }

    if (d->type != NULL && (d->major != 0 || strcmp(d->type, FIFO_DEVICE) == 0)) {
        return 0;
    }

    if (device_info_from_path(d->host_path, &dev_type, &major, &minor) != 0) {
        ERROR("Failed to stat CDI host device %s", d->host_path);
        return -1;
    }

    if (d->type == NULL) {
        d->type = dev_type;
        dev_type = NULL;
    } else {
        if (strcmp(d->type, dev_type) != 0) {
            ERROR("CDI device (%s, %s), host type mismatch (%s, %s)", 
                d->path, d->host_path, d->type, dev_type);
            return -1;
        }
    }
    if (d->major == 0 && strcmp(d->type, FIFO_DEVICE) != 0) {
        d->major = major;
        d->minor = minor;
    }
    return 0;
}

static cdi_device_node *clone_cdi_device_node(cdi_device_node *d)
{
    cdi_device_node *device_node = NULL;

    device_node = util_common_calloc_s(sizeof(*device_node));
    if (device_node == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    device_node->path = util_strdup_s(d->path);
    device_node->host_path = util_strdup_s(d->host_path);
    device_node->type = util_strdup_s(d->type);
    device_node->major = d->major;
    device_node->minor = d->minor;
    device_node->file_mode = d->file_mode;
    device_node->permissions = util_strdup_s(d->permissions);
    device_node->uid = d->uid;
    device_node->gid = d->gid;
    return device_node;
}

static cdi_hook *clone_cdi_hook(cdi_hook *h)
{
    cdi_hook *hook = NULL;

    hook = util_common_calloc_s(sizeof(*hook));
    if (hook == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    hook->hook_name = util_strdup_s(h->hook_name);
    hook->path = util_strdup_s(h->path);
    if (h->args_len != 0) {
        hook->args = util_copy_array_by_len(h->args, h->args_len);
        if (hook->args == NULL) {
            ERROR("Failed to copy args");
            goto error_out;
        }
        hook->args_len = h->args_len;
    }
    if (h->env_len != 0) {
        hook->env = util_copy_array_by_len(h->env, h->env_len);
        if (hook->env == NULL) {
            ERROR("Failed to copy env");
            goto error_out;
        }
        hook->env_len = h->env_len;
    }
    hook->timeout = h->timeout;
   
    return hook;

error_out:
    free_cdi_hook(hook);
    return NULL;
}

static cdi_mount *clone_cdi_mount(cdi_mount *m)
{
    cdi_mount *mount = NULL;

    mount = util_common_calloc_s(sizeof(*mount));
    if (mount == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    mount->host_path = util_strdup_s(m->host_path);
    mount->container_path = util_strdup_s(m->container_path);
    if (m->options_len != 0) {
        mount->options = util_copy_array_by_len(m->options, m->options_len);
        if (mount->options == NULL) {
            ERROR("Failed to copy options");
            free_cdi_mount(mount);
            return NULL;
        }
        mount->options_len = m->options_len;
    }
    mount->type = util_strdup_s(m->type);

    return mount;
}

static defs_hook *cdi_hook_to_oci(cdi_hook *h)
{
    defs_hook *oci_hook = NULL;

    oci_hook = util_common_calloc_s(sizeof(*oci_hook));
    if (oci_hook == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    oci_hook->path = util_strdup_s(h->path);
    if (h->args_len != 0) {
        oci_hook->args = util_copy_array_by_len(h->args, h->args_len);
        if (oci_hook->args == NULL) {
            ERROR("Failed to copy args");
            goto error_out;
        }
        oci_hook->args_len = h->args_len;
    }
    if (h->env_len != 0) {
        oci_hook->env = util_copy_array_by_len(h->env, h->env_len);
        if (oci_hook->env == NULL) {
            ERROR("Failed to copy env");
            goto error_out;
        }
        oci_hook->env_len = h->env_len;
    }
    oci_hook->timeout = h->timeout;
    return oci_hook;

error_out:
    free_defs_hook(oci_hook);
    return NULL;
}

static defs_mount *cdi_mount_to_oci(cdi_mount *m)
{
    defs_mount *oci_mount = NULL;

    oci_mount = util_common_calloc_s(sizeof(*oci_mount));
    if (oci_mount == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    oci_mount->source = util_strdup_s(m->host_path);
    oci_mount->destination = util_strdup_s(m->container_path);
    if (m->options_len != 0) {
        oci_mount->options = util_copy_array_by_len(m->options, m->options_len);
        if (oci_mount->options == NULL) {
            ERROR("Failed to copy options");
            free_defs_mount(oci_mount);
            return NULL;
        }
        oci_mount->options_len = m->options_len;
    }
    oci_mount->type = util_strdup_s(m->type);

    return oci_mount;
}

static defs_device *cdi_device_node_to_oci(cdi_device_node *d)
{
    defs_device *oci_device = NULL;

    oci_device = util_common_calloc_s(sizeof(*oci_device));
    if (oci_device == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    oci_device->path = util_strdup_s(d->path);
    oci_device->type = util_strdup_s(d->type);
    oci_device->major = d->major;
    oci_device->minor = d->minor;
    oci_device->file_mode = d->file_mode;
    oci_device->uid = d->uid;
    oci_device->gid = d->gid;
    
    return oci_device;
}

static int apply_cdi_device_nodes(cdi_container_edits *e, oci_runtime_spec *spec)
{
    size_t i;
    defs_device *dev = NULL;
    cdi_device_node *dn = NULL;
    const char *access = NULL;

    for (i = 0; i < e->device_nodes_len; i++) {
        dn = clone_cdi_device_node(e->device_nodes[i]);
        if (dn == NULL) {
            ERROR("Failed to copy device node");
            goto error_out;
        }

        if (fill_device_node_info(dn) != 0) {
            goto error_out;
        }
        dev = cdi_device_node_to_oci(dn);
        if (dev == NULL) {
            ERROR("Failed to generate oci device");
            goto error_out;
        }
        /* Currently, for uid and gid, isulad cannot distinguish
         * 0 and unspecified. Here, 0 is processed as unspecified.
         */
        if (dev->uid == 0 && spec->process != NULL) {
            if (spec->process->user->uid > 0) {
                dev->uid = spec->process->user->uid;
            }
        }
        if (dev->gid == 0 && spec->process != NULL) {
            if (spec->process->user->gid > 0) {
                dev->gid = spec->process->user->gid;
            }
        }

        if (spec_add_device(spec, dev) != 0) {
            goto error_out;
        }

        if (strcmp(dev->type, BLOCK_DEVICE) == 0 || strcmp(dev->type, CHAR_DEVICE) == 0) {
            if (e->device_nodes[i]->permissions != NULL) {
                access = e->device_nodes[i]->permissions;
            } else {
                access = "rwm";
            }
            if (spec_add_linux_resources_device(spec, true, dev->type,
                dev->major, dev->minor, access)) {
                dev = NULL;
                goto error_out;
            }
        }
        free_cdi_device_node(dn);
        dn = NULL;
        dev = NULL;
    }

    return 0;

error_out:
    free_cdi_device_node(dn);
    free_defs_device(dev);
    return -1;
}

static int defs_mount_parts(defs_mount *m)
{
    char cleanpath[PATH_MAX] = { 0 };
    if (util_clean_path(m->destination, cleanpath, sizeof(cleanpath)) == NULL) {
        return -1;
    }

    return util_strings_count(cleanpath, '/');
}

static inline int defs_mount_cmp(defs_mount **first, defs_mount **second)
{
    int first_part = defs_mount_parts(*first);
    int second_part = defs_mount_parts(*second);

    if (first_part < second_part) {
        return -1;
    }
    if (first_part > second_part) {
        return 1;
    }

    return strcmp((*first)->destination, (*second)->destination);
}

static int apply_cdi_mounts(cdi_container_edits *e, oci_runtime_spec *spec)
{
    size_t i;
    defs_mount *mnt = NULL;

    if (e->mounts_len == 0) {
        return 0;
    }

    for (i = 0; i < e->mounts_len; i++) {
        spec_remove_mount(spec, e->mounts[i]->container_path);
        mnt = cdi_mount_to_oci(e->mounts[i]);
        if (spec_add_mount(spec, mnt) != 0) {
            free_defs_mount(mnt);
            return -1;
        }
    }
        
    qsort(spec->mounts, spec->mounts_len,
              sizeof(defs_mount *), (int (*)(const void *, const void *))defs_mount_cmp);
    return 0;
}

static int apply_cdi_hooks(cdi_container_edits *e, oci_runtime_spec *spec)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < e->hooks_len; i++) {
        defs_hook *oci_hook = cdi_hook_to_oci(e->hooks[i]);
        if (strcmp(e->hooks[i]->hook_name, PRESTART_HOOK)) {
            ret = spec_add_prestart_hook(spec, oci_hook);
        } else if (strcmp(e->hooks[i]->hook_name, POSTSTART_HOOK)) {
            ret = spec_add_poststart_hook(spec, oci_hook);
        } else if (strcmp(e->hooks[i]->hook_name, POSTSTOP_HOOK)) {
            ret = spec_add_poststop_hook(spec, oci_hook);
        } else {
            /* 
            * The OCI being used by the iSulad not supportes 
            * createRuntime/createContainer/startContainer currently.
            */
            ERROR("Unknown hook name %s", e->hooks[i]->hook_name);
            free_defs_hook(oci_hook);
            return -1;
        }
        if (ret != 0) {
            ERROR("Failed add hook %s", e->hooks[i]->hook_name);
            free_defs_hook(oci_hook);
            return -1;
        }
    }
    return ret;
}

int cdi_container_edits_apply(cdi_container_edits *e, oci_runtime_spec *spec)
{
    if (spec == NULL) {
        ERROR("Can't edit nil OCI Spec");
        return -1;
    }
    if (e == NULL) {
        WARN("Cdi container edits is nil");
        return 0;
    }

    if (e->env_len > 0) {
        if (spec_add_multiple_process_env(spec, (const char **)e->env, e->env_len) != 0) {
            ERROR("Failed to merge envs");
            return -1;
        }
    }

    if (apply_cdi_device_nodes(e, spec) != 0) {
        ERROR("Failed to apply device nodes");
        return -1;
    }

    if (apply_cdi_mounts(e, spec) != 0) {
        ERROR("Failed to apply mounts");
        return -1;
    }

    if (apply_cdi_hooks(e, spec) != 0) {
        ERROR("Failed to apply hooks");
        return -1;
    }

    return 0;
}

int cdi_container_edits_validate(cdi_container_edits *e)
{
    size_t i;

    if (e == NULL) {
        WARN("Cdi container edits is nil");
        return 0;
    }

    if (cdi_validate_env(e->env, e->env_len) != 0) {
        ERROR("Invalid container edits");
        return -1;
    }
    for (i = 0; i < e->device_nodes_len; i++) {
        if (cdi_validate_device_node(e->device_nodes[i]) != 0) {
            ERROR("Invalid container device node");
            return -1;
        }
    }
    for (i = 0; i < e->hooks_len; i++) {
        if (cdi_validate_hook(e->hooks[i]) != 0) {
            ERROR("Invalid container hook");
            return -1;
        }
    }
    for (i = 0; i < e->mounts_len; i++) {
        if (cdi_validate_mount(e->mounts[i]) != 0) {
            ERROR("Invalid container mount");
            return -1;
        }
    }

    return 0;
}

#define EDITS_APPEND_ITEM_DEF(item)                                                                     \
    static int append_##item(cdi_container_edits *e, cdi_container_edits *o, clone_common_array_item_cb cb) \
    {                                                                                                   \
        common_array e_array = {                                                                        \
            .items = (void **)e->item,                                                                  \
            .len = e->item##_len,                                                                       \
            .cap = e->item##_len,                                                                       \
            .free_item_cb = NULL,                                                                       \
            .clone_item_cb = cb                                                                         \
        };                                                                                              \
        common_array o_array = {                                                                        \
            .items = (void **)o->item,                                                                  \
            .len = o->item##_len,                                                                       \
            .cap = o->item##_len,                                                                       \
            .free_item_cb = NULL,                                                                       \
            .clone_item_cb = cb                                                                         \
        };                                                                                              \
        if (util_merge_common_array(&e_array, &o_array) != 0) {                                         \
            ERROR("Out of memory");                                                                     \
            return -1;                                                                                  \
        }                                                                                               \
        e->item = (void *)e_array.items;                                                                \
        e->item##_len += o->item##_len;                                                                 \
        return 0;                                                                                       \
    }

EDITS_APPEND_ITEM_DEF(env)
EDITS_APPEND_ITEM_DEF(device_nodes)
EDITS_APPEND_ITEM_DEF(hooks)
EDITS_APPEND_ITEM_DEF(mounts)

int cdi_container_edits_append(cdi_container_edits *e, cdi_container_edits *o)
{
    if (o == NULL) {
        return 0;
    }
    if (e == NULL) {
        ERROR("Invalid params");
        return -1;
    }

    if (append_env(e, o, (clone_common_array_item_cb)util_strdup_s) != 0) {
        return -1;
    }
    if (append_device_nodes(e, o, (clone_common_array_item_cb)clone_cdi_device_node) != 0) {
        return -1;
    }
    if (append_hooks(e, o, (clone_common_array_item_cb)clone_cdi_hook) != 0) {
        return -1;
    }
    if (append_mounts(e, o, (clone_common_array_item_cb)clone_cdi_mount) != 0) {
        return -1;
    }

    return 0;
}

bool cdi_container_edits_is_empty(cdi_container_edits *e)
{
    if (e == NULL) {
        return false;
    }
    return e->env_len + e->device_nodes_len + e->hooks_len + e->mounts_len == 0;
}

static int cdi_validate_env(char **envs, size_t envs_len)
{
    size_t i;
    char *ptr = NULL;

    for (i = 0; i < envs_len; i++) {
        ptr = strchr(envs[i], '=');
        if (ptr == NULL || ptr == envs[i]) {
            ERROR("Invalid environment variable %s", envs[i]);
            return -1;
        }
    }
    return 0;
}

static int cdi_validate_device_node(cdi_device_node *d)
{
    char *p = NULL;

    if (d == NULL) {
        ERROR("Device node is nil");
        return -1;
    }

    if (d->path == NULL) {
        ERROR("Invalid (empty) device path");
        return -1;
    }
    if (d->type != NULL && strcmp(d->type, BLOCK_DEVICE) != 0 &&
        strcmp(d->type, CHAR_DEVICE) != 0 && strcmp(d->type, FIFO_DEVICE) != 0) {
        ERROR("Device %s: invalid type %s", d->path, d->type);
        return -1;
    }
    for (p = d->permissions; p != NULL && *p != '\0'; p++) {
        if (*p != 'r' && *p != 'w' && *p != 'm') {
            ERROR("Device %s: invalid permissions %s", d->path, d->permissions);
            return -1;
        }
    }

    return 0;
}

static int cdi_validate_hook(cdi_hook *h)
{
    size_t i;

    if (h == NULL) {
        ERROR("Hook is nil");
        return -1;
    }

    for (i = 0; i < VALID_HOOK_NAME_LEN; i++) {
        if (strcmp(h->hook_name, g_valid_hook_names[i]) == 0) {
            break;
        }
    }
    if (i == VALID_HOOK_NAME_LEN) {
        ERROR("Invalid hook name %s", h->hook_name);
        return -1;
    }
    if (h->path == NULL) {
        ERROR("Invalid hook %s with empty path", h->hook_name);
        return -1;
    }
    if (cdi_validate_env(h->env, h->env_len) != 0) {
        ERROR("Invalid hook %s", h->hook_name);
        return -1;
    }
    return 0;
}

static int cdi_validate_mount(cdi_mount *m)
{
    if (m == NULL) {
        ERROR("Mount is nil");
        return -1;
    }

    if (m->host_path == NULL) {
        ERROR("Invalid mount, empty host path");
        return -1;
    }
    if (m->container_path == NULL) {
        ERROR("Invalid mount, empty container path");
        return -1;
    }
    return 0;
}
