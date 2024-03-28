/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2023-03-29
 * Description: provide cgroup v1 functions
 ******************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cgroup.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>

#include "utils.h"
#include "sysinfo.h"
#include "err_msg.h"
#include "events_sender_api.h"

#define CGROUP_HUGETLB_LIMIT "hugetlb.%s.limit_in_bytes"
#define CGROUP_MOUNT_PATH_PREFIX "/sys/fs/cgroup/"


static int get_value_ll(const char *content, const char *match, void *result)
{
    long long ll_result = 0;

    if (util_safe_llong(content, &ll_result) != 0) {
        ERROR("Failed to convert %s to long long", content);
        return -1;
    }

    *(int64_t *)result = (int64_t)ll_result;
    return 0;
}

static int get_value_string(const char *content, const char *match, void *result)
{
    *(char **)result = util_strdup_s(content);
    return 0;
}

typedef enum {
    // CPU subsystem
    CPU_RT_PERIOD, CPU_RT_RUNTIME, CPU_SHARES, CPU_CFS_PERIOD, CPU_CFS_QUOTA,
    // CPUSET subsystem
    CPUSET_CPUS, CPUSET_MEMS,
    // CPUACCT subsystem
    CPUACCT_USE_NANOS, CPUACCT_USE_USER, CPUACCT_USE_SYS,
    // MEMORY subsystem
    MEMORY_LIMIT, MEMORY_USAGE, MEMORY_SOFT_LIMIT,
    MEMORY_KMEM_LIMIT, MEMORY_KMEM_USAGE,
    MEMORY_SWAPPINESS, MEMORY_SW_LIMIT, MEMORY_SW_USAGE,
    MEMORY_CACHE, MEMORY_CACHE_TOTAL,
    MEMORY_TOTAL_RSS,
    MEMORY_TOTAL_PGFAULT, MEMORY_TOTAL_PGMAJFAULT,
    MEMORY_TOTAL_INACTIVE_FILE, MEMORY_OOM_CONTROL,
    // BLKIO subsystem
    BLKIO_WEIGTH, BLKIO_WEIGTH_DEVICE, BLKIO_READ_BPS, BLKIO_WRITE_BPS, BLKIO_READ_IOPS, BLKIO_WRITE_IOPS,
    // PIDS subsystem
    PIDS_CURRENT,
    // MAX
    CGROUP_V1_FILES_INDEX_MAXS
} cgroup_v1_files_index;

static struct cgfile_t g_cgroup_v1_files[] = {
    // CPU subsystem
    [CPU_RT_PERIOD]               = {"cpu_rt_period",         "cpu.rt_period_us",                 NULL,                    get_match_value_ull},
    [CPU_RT_RUNTIME]              = {"cpu_rt_runtime",        "cpu.rt_runtime_us",                NULL,                    get_match_value_ull},
    [CPU_SHARES]                  = {"cpu_shares",            "cpu.shares",                       NULL,                    get_match_value_ull},
    [CPU_CFS_PERIOD]              = {"cpu_cfs_period",        "cpu.cfs_period_us",                NULL,                    get_match_value_ull},
    [CPU_CFS_QUOTA]               = {"cpu_cfs_quota",         "cpu.cfs_quota_us",                 NULL,                    get_value_ll},
    // CPUSET subsystem
    [CPUSET_CPUS]                 = {"cpuset_cpus",           "cpuset.cpus",                      NULL,                    get_value_string},
    [CPUSET_MEMS]                 = {"cpuset_mems",           "cpuset.mems",                      NULL,                    get_value_string},
    // CPUACCT subsystem
    [CPUACCT_USE_NANOS]           = {"cpu_use_nanos",         "cpuacct.usage",                    NULL,                    get_match_value_ull},
    [CPUACCT_USE_USER]            = {"cpu_use_user",          "cpuacct.stat",                     NULL,                    get_match_value_ull},
    [CPUACCT_USE_SYS]             = {"cpu_use_sys",           "cpuacct.stat",                     NULL,                    get_match_value_ull},
    // MEMORY subsystem
    [MEMORY_LIMIT]                = {"mem_limit",             "memory.limit_in_bytes",            NULL,                    get_match_value_ull},
    [MEMORY_USAGE]                = {"mem_usage",             "memory.usage_in_bytes",            NULL,                    get_match_value_ull},
    [MEMORY_SOFT_LIMIT]           = {"mem_soft_limit",        "memory.soft_limit_in_bytes",       NULL,                    get_match_value_ull},
    [MEMORY_KMEM_LIMIT]           = {"kmem_limit",            "memory.kmem.limit_in_bytes",       NULL,                    get_match_value_ull},
    [MEMORY_KMEM_USAGE]           = {"kmem_usage",            "memory.kmem.usage_in_bytes",       NULL,                    get_match_value_ull},
    [MEMORY_SWAPPINESS]           = {"swappiness",            "memory.swappiness",                NULL,                    NULL},
    [MEMORY_SW_LIMIT]             = {"memsw_limit",           "memory.memsw.limit_in_bytes",      NULL,                    get_match_value_ull},
    [MEMORY_SW_USAGE]             = {"memsw_usage",           "memory.memsw.usage_in_bytes",      NULL,                    get_match_value_ull},
    [MEMORY_CACHE]                = {"cache",                 "memory.stat",                      NULL,                    get_match_value_ull},
    [MEMORY_CACHE_TOTAL]          = {"cache_total",           "memory.stat",                      NULL,                    get_match_value_ull},
    [MEMORY_TOTAL_RSS]            = {"total_rss",             "memory.stat",                      "total_rss",             get_match_value_ull},
    [MEMORY_TOTAL_PGFAULT]        = {"total_page_fault",      "memory.stat",                      "total_pgfault",         get_match_value_ull},
    [MEMORY_TOTAL_PGMAJFAULT]     = {"total_page_majfault",   "memory.stat",                      "total_pgmajfault",      get_match_value_ull},
    [MEMORY_TOTAL_INACTIVE_FILE]  = {"total_inactive_file",   "memory.stat",                      "total_inactive_file",   get_match_value_ull},
    [MEMORY_OOM_CONTROL]          = {"oom_control",           "memory.oom_control",               NULL,                    NULL},
    // BLKIO subsystem
    [BLKIO_WEIGTH]                = {"blkio_weigth",          "blkio.weight",                     NULL,                    NULL},
    [BLKIO_WEIGTH_DEVICE]         = {"blkio_weigth_device",   "blkio.weight_device",              NULL,                    NULL},
    [BLKIO_READ_BPS]              = {"blkio_read_bps",        "blkio.throttle.read_bps_device",   NULL,                    NULL},
    [BLKIO_WRITE_BPS]             = {"blkio_write_bps",       "blkio.throttle.write_bps_device",  NULL,                    NULL},
    [BLKIO_READ_IOPS]             = {"blkio_read_iops",       "blkio.throttle.read_iops_device",  NULL,                    NULL},
    [BLKIO_WRITE_IOPS]            = {"blkio_write_iops",      "blkio.throttle.write_iops_device", NULL,                    NULL},
    // PIDS subsystem
    [PIDS_CURRENT]                = {"pids_current",          "pids.current",                     NULL,                    get_match_value_ull},
};

typedef struct {
    char **controllers;
    char *mountpoint;
} cgroup_layers_item;

typedef struct {
    cgroup_layers_item **items;
    size_t len;
    size_t cap;
} cgroup_layer_t;

static char *common_find_cgroup_subsystem_mountpoint(const cgroup_layer_t *layers, const char *subsystem)
{
    size_t i;

    for (i = 0; i < layers->len && layers->items[i]; i++) {
        char **cit = NULL;

        for (cit = layers->items[i]->controllers; cit && *cit; cit++) {
            if (strcmp(*cit, subsystem) == 0) {
                return layers->items[i]->mountpoint;
            }
        }
    }
    return NULL;
}


static cgroup_layer_t *new_cgroup_layer(size_t len)
{
    cgroup_layer_t *layers = NULL;

    if (len == 0) {
        return NULL;
    }

    layers = (cgroup_layer_t *)util_common_calloc_s(sizeof(cgroup_layer_t));
    if (layers == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    layers->items = (cgroup_layers_item **)util_smart_calloc_s(sizeof(cgroup_layers_item *), len);
    if (layers->items == NULL) {
        ERROR("Out of memory");
        free(layers);
        return NULL;
    }

    layers->len = 0;
    layers->cap = len;

    return layers;
}

static int add_cgroup_layer(cgroup_layer_t *layers, char **clist, char *mountpoint)
{
#define CGROUP_LAYER_MAX_CAPABILITY 1024
    size_t new_size;
    cgroup_layers_item *newh = NULL;
    cgroup_layers_item **tmp = NULL;

    if (layers->len >= CGROUP_LAYER_MAX_CAPABILITY) {
        ERROR("Too many cgroup layers");
        return -1;
    }

    newh = util_common_calloc_s(sizeof(cgroup_layers_item));
    if (newh == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    newh->controllers = clist;
    newh->mountpoint = mountpoint;

    if (layers->len < layers->cap) {
        goto out;
    }

    if (layers->cap > CGROUP_LAYER_MAX_CAPABILITY / 2) {
        new_size = CGROUP_LAYER_MAX_CAPABILITY;
    } else {
        new_size = layers->cap * 2;
    }

    if (util_mem_realloc((void **)&tmp, new_size * sizeof(cgroup_layers_item *),
                         layers->items, layers->cap * sizeof(cgroup_layers_item *)) != 0) {
        ERROR("Failed to realloc memory");
        free(newh);
        return -1;
    }

    layers->items = tmp;
    tmp = NULL;
    layers->cap = new_size;

out:
    layers->items[layers->len] = newh;
    layers->len++;
    return 0;
}

static void common_free_cgroup_layer(cgroup_layer_t *layers)
{
    size_t i;

    if (layers == NULL) {
        return;
    }

    for (i = 0; i < layers->len && layers->items[i]; i++) {
        free(layers->items[i]->mountpoint);
        layers->items[i]->mountpoint = NULL;
        util_free_array(layers->items[i]->controllers);
        layers->items[i]->controllers = NULL;
        free(layers->items[i]);
        layers->items[i] = NULL;
    }

    free(layers->items);
    layers->items = NULL;
    layers->len = 0;
    layers->cap = 0;

    free(layers);
}

static int append_subsystem_to_list(char ***klist, char ***nlist, const char *ptoken)
{
    int ret = 0;

    if (strncmp(ptoken, "name=", strlen("name=")) == 0) {
        ret = util_array_append(nlist, ptoken);
        if (ret != 0) {
            ERROR("Failed to append string");
            return -1;
        }
    } else {
        ret = util_array_append(klist, ptoken);
        if (ret != 0) {
            ERROR("Failed to append string");
            return -1;
        }
    }

    return 0;
}

static int get_cgroup_subsystems(char ***klist, char ***nlist)
{
    int ret = 0;
    size_t length = 0;
    FILE *fp = NULL;
    char *pline = NULL;

    fp = util_fopen("/proc/self/cgroup", "r");
    if (fp == NULL) {
        return -1;
    }

    while (getline(&pline, &length, fp) != -1) {
        char *pos = NULL;
        char *pos2 = NULL;
        char *ptoken = NULL;
        char *psave = NULL;
        pos = strchr(pline, ':');
        if (pos == NULL) {
            ERROR("Invalid cgroup entry: must contain at least two colons: %s", pline);
            ret = -1;
            goto out;
        }
        pos++;
        pos2 = strchr(pos, ':');
        if (pos2 == NULL) {
            ERROR("Invalid cgroup entry: must contain at least two colons: %s", pline);
            ret = -1;
            goto out;
        }
        *pos2 = '\0';

        if ((pos2 - pos) == 0) {
            INFO("Not supported cgroup entry: %s", pline);
            continue;
        }

        for (ptoken = strtok_r(pos, ",", &psave); ptoken; ptoken = strtok_r(NULL, ",", &psave)) {
            if (append_subsystem_to_list(klist, nlist, ptoken)) {
                goto out;
            }
        }
    }

out:
    free(pline);
    fclose(fp);
    if (ret != 0) {
        util_free_array(*klist);
        *klist = NULL;
        util_free_array(*nlist);
        *nlist = NULL;
    }
    return ret;
}

static int append_controller(const char **klist, const char **nlist, char ***clist, const char *entry)
{
    int ret = 0;
    char *dup_entry = NULL;

    if (util_array_contain(klist, entry) && util_array_contain(nlist, entry)) {
        ERROR("Refusing to use ambiguous controller \"%s\"", entry);
        ERROR("It is both a named and kernel subsystem");
        return -1;
    }

    if (strncmp(entry, "name=", 5) == 0) {
        dup_entry = util_strdup_s(entry);
    } else if (util_array_contain(klist, entry)) {
        dup_entry = util_strdup_s(entry);
    } else {
        dup_entry = util_string_append(entry, "name=");
    }
    if (dup_entry == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ret = util_array_append(clist, dup_entry);
    if (ret != 0) {
        ERROR("Failed to append array");
    }

    free(dup_entry);
    return ret;
}

static inline bool is_cgroup_mountpoint(const char *mp)
{
    return strncmp(mp, CGROUP_MOUNT_PATH_PREFIX, strlen(CGROUP_MOUNT_PATH_PREFIX)) == 0;
}

static char **cgroup_get_controllers(const char **klist, const char **nlist, const char *line)
{
    int index;
    char *dup = NULL;
    char *pos2 = NULL;
    char *tok = NULL;
    const char *pos = line;
    char *psave = NULL;
    char *sep = ",";
    char **pret = NULL;

    // line example
    // 108 99 0:55 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755
    for (index = 0; index < 4; index++) {
        pos = strchr(pos, ' ');
        if (pos == NULL) {
            ERROR("Invalid mountinfo format \"%s\"", line);
            return NULL;
        }
        pos++;
    }

    if (!is_cgroup_mountpoint(pos)) {
        return NULL;
    }

    pos += strlen(CGROUP_MOUNT_PATH_PREFIX);
    pos2 = strchr(pos, ' ');
    if (pos2 == NULL) {
        ERROR("Invalid mountinfo format \"%s\"", line);
        return NULL;
    }

    *pos2 = '\0';
    dup = util_strdup_s(pos);
    *pos2 = ' ';

    for (tok = strtok_r(dup, sep, &psave); tok; tok = strtok_r(NULL, sep, &psave)) {
        if (append_controller(klist, nlist, &pret, tok)) {
            ERROR("Failed to append controller");
            util_free_array(pret);
            pret = NULL;
            break;
        }
    }

    free(dup);

    return pret;
}

static bool lists_intersect(const char **controllers, const char **list)
{
    int index;

    if (controllers == NULL || list == NULL) {
        return false;
    }

    for (index = 0; controllers[index]; index++) {
        if (util_array_contain(list, controllers[index])) {
            return true;
        }
    }

    return false;
}

static bool controller_list_is_dup(const cgroup_layer_t *llist, const char **clist)
{
    size_t index;

    if (llist == NULL) {
        return false;
    }

    for (index = 0; index < llist->len && llist->items[index]; index++) {
        if (lists_intersect((const char **)llist->items[index]->controllers, (const char **)clist)) {
            return true;
        }
    }

    return false;
}

static int cgroup_get_mountpoint_and_root(char *pline, char **mountpoint, char **root)
{
    int index;
    char *posmp = NULL;
    char *posrt = NULL;
    char *pos = pline;

    // find root
    // line example
    // 108 99 0:55 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755
    for (index = 0; index < 3; index++) {
        pos = strchr(pos, ' ');
        if (pos == NULL) {
            return -1;
        }
        pos++;
    }
    posrt = pos;

    // find mountpoint
    pos = strchr(pos, ' ');
    if (pos == NULL) {
        return -1;
    }

    *pos = '\0';
    if (root != NULL) {
        *root = util_strdup_s(posrt);
    }

    pos++;
    posmp = pos;

    if (!is_cgroup_mountpoint(posmp)) {
        return -1;
    }

    pos = strchr(pos + strlen(CGROUP_MOUNT_PATH_PREFIX), ' ');
    if (pos == NULL) {
        return -1;
    }
    *pos = '\0';

    if (mountpoint != NULL) {
        *mountpoint = util_strdup_s(posmp);
    }

    return 0;
}

/* find cgroup mountpoint and root */
static int get_cgroup_mnt_and_root_path_v1(const char *subsystem, char **mountpoint, char **root)
{
    int ret = 0;
    FILE *fp = NULL;
    size_t length = 0;
    char *pline = NULL;

    if (subsystem == NULL) {
        ERROR("Empty subsystem");
        return -1;
    }

    fp = util_fopen("/proc/self/mountinfo", "r");
    if (fp == NULL) {
        ERROR("Failed to open \"/proc/self/mountinfo\"\n");
        ret = -1;
        goto free_out;
    }

    while (getline(&pline, &length, fp) != -1) {
        char *dup = NULL;
        char *p = NULL;
        char *tok = NULL;
        char *mp = NULL;
        char *rt = NULL;
        char *saveptr = NULL;
        char *sep = ",";
        int mret;

        mret = cgroup_get_mountpoint_and_root(pline, &mp, &rt);
        if (mret != 0 || mp == NULL || rt == NULL) {
            goto mp_out;
        }

        p = mp;
        p += strlen(CGROUP_MOUNT_PATH_PREFIX);
        dup = util_strdup_s(p);
        if (dup == NULL) {
            ERROR("Out of memory");
            free(mp);
            ret = -1;
            goto free_out;
        }

        for (tok = strtok_r(dup, sep, &saveptr); tok; tok = strtok_r(NULL, sep, &saveptr)) {
            if (strcmp(tok, subsystem) != 0) {
                continue;
            }
            if (mountpoint != NULL) {
                *mountpoint = mp;
            } else {
                free(mp);
            }
            if (root != NULL) {
                *root = rt;
            } else {
                free(rt);
            }
            free(dup);
            goto free_out;
        }
        free(dup);
mp_out:
        free(mp);
        free(rt);
        continue;
    }
free_out:
    if (fp != NULL) {
        fclose(fp);
    }
    free(pline);
    return ret;
}

static cgroup_layer_t *common_cgroup_layers_find(void)
{
    int nret;
    int ret = 0;
    FILE *fp = NULL;
    size_t length = 0;
    const size_t cgroup_layer_item_num = 10;
    char *pline = NULL;
    char **klist = NULL;
    char **nlist = NULL;
    cgroup_layer_t *layers = NULL;

    layers = new_cgroup_layer(cgroup_layer_item_num);
    if (layers == NULL) {
        ERROR("Failed to new cgroup layer");
        return NULL;
    }

    ret = get_cgroup_subsystems(&klist, &nlist);
    if (ret != 0) {
        ERROR("Failed to retrieve available legacy cgroup controllers\n");
        goto out;
    }

    fp = util_fopen("/proc/self/mountinfo", "r");
    if (fp == NULL) {
        ERROR("Failed to open \"/proc/self/mountinfo\"\n");
        ret = -1;
        goto out;
    }

    while (getline(&pline, &length, fp) != -1) {
        char *mountpoint = NULL;
        char **clist = NULL;
        int mret;

        clist = cgroup_get_controllers((const char **)klist, (const char **)nlist, pline);
        if (clist == NULL) {
            goto list_out;
        }

        if (controller_list_is_dup(layers, (const char **)clist)) {
            goto list_out;
        }

        mret = cgroup_get_mountpoint_and_root(pline, &mountpoint, NULL);
        if (mret != 0 || mountpoint == NULL) {
            ERROR("Failed parsing mountpoint from \"%s\"\n", pline);
            goto list_out;
        }

        nret = add_cgroup_layer(layers, clist, mountpoint);
        if (nret != 0) {
            ERROR("Failed to add hierarchies");
            goto list_out;
        }

        continue;
list_out:
        util_free_array(clist);
        free(mountpoint);
    }
out:
    util_free_array(klist);
    util_free_array(nlist);
    if (fp != NULL) {
        fclose(fp);
    }
    free(pline);

    if (ret != 0) {
        common_free_cgroup_layer(layers);
        return NULL;
    }

    return layers;
}

static int get_cgroup_v1_value_helper(const char *path, const cgroup_v1_files_index index, void *result)
{
    if (index >= CGROUP_V1_FILES_INDEX_MAXS) {
        ERROR("Index out of range");
        return false;
    }

    return get_cgroup_value_helper(path, &g_cgroup_v1_files[index], result);
}

static bool check_cgroup_v1_file_exists(const char *mountpoint, const cgroup_v1_files_index index, const bool quiet)
{
    int nret = 0;
    char path[PATH_MAX] = { 0 };

    if (index >= CGROUP_V1_FILES_INDEX_MAXS) {
        ERROR("Index out of range");
        return false;
    }

    if (mountpoint == NULL) {
        ERROR("%s: invalid arguments", g_cgroup_v1_files[index].name);
        return false;
    }

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, g_cgroup_v1_files[index].file);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("%s: failed to snprintf", g_cgroup_v1_files[index].name);
        return false;
    }

    if (util_file_exists(path)) {
        return true;
    }

    if (!quiet) {
        WARN("Your kernel does not support cgroup %s", g_cgroup_v1_files[index].name);
    }

    return false;
}

static void get_cgroup_v1_cpu_info(const cgroup_layer_t *layers, const bool quiet, cgroup_cpu_info_t *cpuinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "cpu");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find cpu cgroup in mounts");
        return;
    }

    cpuinfo->cpu_rt_period = check_cgroup_v1_file_exists(mountpoint, CPU_RT_PERIOD, quiet);
    cpuinfo->cpu_rt_runtime = check_cgroup_v1_file_exists(mountpoint, CPU_RT_RUNTIME, quiet);
    cpuinfo->cpu_shares = check_cgroup_v1_file_exists(mountpoint, CPU_SHARES, quiet);
    cpuinfo->cpu_cfs_period = check_cgroup_v1_file_exists(mountpoint, CPU_CFS_PERIOD, quiet);
    cpuinfo->cpu_cfs_quota = check_cgroup_v1_file_exists(mountpoint, CPU_CFS_QUOTA, quiet);
}

static void get_cgroup_v1_cpuset_info(const cgroup_layer_t *layers, const bool quiet, cgroup_cpuset_info_t *cpusetinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "cpuset");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, ("Unable to find cpuset cgroup in mounts"));
        return;
    }

    if (!check_cgroup_v1_file_exists(mountpoint, CPUSET_CPUS, quiet)) {
        return;
    }
    if (!check_cgroup_v1_file_exists(mountpoint, CPUSET_MEMS, quiet)) {
        return;
    }

    if (get_cgroup_v1_value_helper(mountpoint, CPUSET_CPUS, (void *)&cpusetinfo->cpus) != 0) {
        ERROR("Failed to get cgroup cpuset.cpus data");
        return;
    }
    if (get_cgroup_v1_value_helper(mountpoint, CPUSET_MEMS, (void *)&cpusetinfo->mems) != 0) {
        free(cpusetinfo->cpus);
        cpusetinfo->cpus = NULL;
        ERROR("Failed to get cgroup cpuset.cpus data");
        return;
    }

    cpusetinfo->cpus = util_trim_space(cpusetinfo->cpus);
    cpusetinfo->mems = util_trim_space(cpusetinfo->mems);
    cpusetinfo->cpuset = true;
}

static void get_cgroup_v1_mem_info(const cgroup_layer_t *layers, const bool quiet, cgroup_mem_info_t *meminfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "memory");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find memory cgroup in mounts");
        return;
    }

    meminfo->limit = check_cgroup_v1_file_exists(mountpoint, MEMORY_LIMIT, quiet);
    meminfo->swap = check_cgroup_v1_file_exists(mountpoint, MEMORY_SW_LIMIT, quiet);
    meminfo->reservation = check_cgroup_v1_file_exists(mountpoint, MEMORY_SOFT_LIMIT, quiet);
    meminfo->oomkilldisable = check_cgroup_v1_file_exists(mountpoint, MEMORY_OOM_CONTROL, quiet);
    meminfo->swappiness = check_cgroup_v1_file_exists(mountpoint, MEMORY_SWAPPINESS, quiet);
    meminfo->kernel = check_cgroup_v1_file_exists(mountpoint, MEMORY_KMEM_LIMIT, quiet);
}

static void get_cgroup_v1_blkio_info(const cgroup_layer_t *layers, const bool quiet, cgroup_blkio_info_t *blkioinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "blkio");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find blkio cgroup in mounts");
        return;
    }

    blkioinfo->blkio_weight = check_cgroup_v1_file_exists(mountpoint, BLKIO_WEIGTH, quiet);
    blkioinfo->blkio_weight_device = check_cgroup_v1_file_exists(mountpoint, BLKIO_WEIGTH_DEVICE, quiet);
    blkioinfo->blkio_read_bps_device = check_cgroup_v1_file_exists(mountpoint, BLKIO_READ_BPS, quiet);
    blkioinfo->blkio_write_bps_device = check_cgroup_v1_file_exists(mountpoint, BLKIO_WRITE_BPS, quiet);
    blkioinfo->blkio_read_iops_device = check_cgroup_v1_file_exists(mountpoint, BLKIO_READ_IOPS, quiet);
    blkioinfo->blkio_write_iops_device = check_cgroup_v1_file_exists(mountpoint, BLKIO_WRITE_IOPS, quiet);
}

static void get_cgroup_v1_hugetlb_info(const cgroup_layer_t *layers, const bool quiet, cgroup_hugetlb_info_t *hugetlbinfo)
{
    int nret;
    char *mountpoint = NULL;
    char *defaultpagesize = NULL;
    char hugetlbpath[PATH_MAX] = { 0x00 };

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "hugetlb");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Your kernel does not support cgroup hugetlb limit");
        return;
    }

    defaultpagesize = get_default_huge_page_size();
    if (defaultpagesize == NULL) {
        common_cgroup_do_log(quiet, true, "Your kernel does not support cgroup hugetlb limit");
        return;
    }

    nret = snprintf(hugetlbpath, sizeof(hugetlbpath), "%s/"CGROUP_HUGETLB_LIMIT, mountpoint, defaultpagesize);
    if (nret < 0 || (size_t)nret >= sizeof(hugetlbpath)) {
        ERROR("Failed to snprintf hugetlb path");
        goto free_out;
    }

    hugetlbinfo->hugetlblimit = util_file_exists(hugetlbpath);
    common_cgroup_do_log(quiet, !hugetlbinfo->hugetlblimit, ("Your kernel does not support hugetlb limit"));

free_out:
    free(defaultpagesize);
}

static void get_cgroup_v1_pids_info(const cgroup_layer_t *layers, const bool quiet, cgroup_pids_info_t *pidsinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "pids");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find pids cgroup in mounts");
        return;
    }

    pidsinfo->pidslimit = true;
}

static void get_cgroup_v1_files_info(const cgroup_layer_t *layers, const bool quiet, cgroup_files_info_t *filesinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "files");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find files cgroup in mounts");
        return;
    }

    filesinfo->fileslimit = true;
}

static int get_cgroup_info_v1(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo,
                              cgroup_hugetlb_info_t *hugetlbinfo, cgroup_blkio_info_t *blkioinfo,
                              cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                              cgroup_files_info_t *filesinfo, bool quiet)
{
    cgroup_layer_t *layers = NULL;

    layers = common_cgroup_layers_find();
    if (layers == NULL) {
        ERROR("Failed to parse cgroup information");
        return -1;
    }

    get_cgroup_v1_cpu_info(layers, quiet, cpuinfo);
    get_cgroup_v1_cpuset_info(layers, quiet, cpusetinfo);
    get_cgroup_v1_mem_info(layers, quiet, meminfo);
    get_cgroup_v1_blkio_info(layers, quiet, blkioinfo);
    get_cgroup_v1_hugetlb_info(layers, quiet, hugetlbinfo);
    get_cgroup_v1_pids_info(layers, quiet, pidsinfo);
    get_cgroup_v1_files_info(layers, quiet, filesinfo);

    common_free_cgroup_layer(layers);

    return 0;
}

static void get_cgroup_v1_metrics_cpu(const cgroup_layer_t *layers, const char *cgroup_path,
                                      cgroup_cpu_metrics_t *cgroup_cpu_metrics)
{
    int nret = 0;
    char *mountpoint = NULL;
    char path[PATH_MAX] = { 0 };

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "cpuacct");
    if (mountpoint == NULL) {
        ERROR("Unable to find cpu cgroup in mounts");
        return;
    }

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, cgroup_path);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Failed to snprintf");
        return;
    }

    get_cgroup_v1_value_helper(path, CPUACCT_USE_NANOS, (void *)&cgroup_cpu_metrics->cpu_use_nanos);
}

static void get_cgroup_v1_metrics_memory(const cgroup_layer_t *layers, const char *cgroup_path,
                                         cgroup_mem_metrics_t *cgroup_mem_metrics)
{
    int nret = 0;
    char *mountpoint = NULL;
    char path[PATH_MAX] = { 0 };

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "memory");
    if (mountpoint == NULL) {
        ERROR("Unable to find cpu cgroup in mounts");
        return;
    }

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, cgroup_path);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Failed to snprintf");
        return;
    }

    get_cgroup_v1_value_helper(path, MEMORY_LIMIT, (void *)&cgroup_mem_metrics->mem_limit);
    get_cgroup_v1_value_helper(path, MEMORY_USAGE, (void *)&cgroup_mem_metrics->mem_used);
    get_cgroup_v1_value_helper(path, MEMORY_TOTAL_RSS, (void *)&cgroup_mem_metrics->total_rss);
    get_cgroup_v1_value_helper(path, MEMORY_TOTAL_PGFAULT,
                               (void *)&cgroup_mem_metrics->total_pgfault);
    get_cgroup_v1_value_helper(path, MEMORY_TOTAL_PGMAJFAULT,
                               (void *)&cgroup_mem_metrics->total_pgmajfault);
    get_cgroup_v1_value_helper(path, MEMORY_TOTAL_INACTIVE_FILE,
                               (void *)&cgroup_mem_metrics->total_inactive_file);
}

static void get_cgroup_v1_metrics_pid(const cgroup_layer_t *layers, const char *cgroup_path,
                                      cgroup_pids_metrics_t *cgroup_pids_metrics)
{
    int nret = 0;
    char *mountpoint = NULL;
    char path[PATH_MAX] = { 0 };

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "pids");
    if (mountpoint == NULL) {
        ERROR("Unable to find cpu cgroup in mounts");
        return;
    }

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, cgroup_path);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Failed to snprintf");
        return;
    }

    get_cgroup_v1_value_helper(path, PIDS_CURRENT, (void *)&cgroup_pids_metrics->pid_current);
}

static int get_cgroup_metrics_v1(const char *cgroup_path, cgroup_metrics_t *cgroup_metrics)
{
    cgroup_layer_t *layers = NULL;

    if (cgroup_path == NULL || strlen(cgroup_path) == 0 || cgroup_metrics == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    layers = common_cgroup_layers_find();
    if (layers == NULL) {
        ERROR("Failed to parse cgroup information");
        return -1;
    }

    get_cgroup_v1_metrics_cpu(layers, cgroup_path, &cgroup_metrics->cgcpu_metrics);
    get_cgroup_v1_metrics_memory(layers, cgroup_path, &cgroup_metrics->cgmem_metrics);
    get_cgroup_v1_metrics_pid(layers, cgroup_path, &cgroup_metrics->cgpids_metrics);

    common_free_cgroup_layer(layers);

    return 0;
}

/* parse cgroup files, such as /proc/self/cgroup or /proc/1/cgroup */
static int parse_cgroup_file(const char *path, char ***nlist, char ***plist)
{
    int ret = 0;
    size_t length = 0;
    __isula_auto_file FILE *fp = NULL;
    __isula_auto_free char *pline = NULL;

    fp = util_fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    while (getline(&pline, &length, fp) != -1) {
        char *pos = NULL;
        char *pos2 = NULL;
        char *pos3 = NULL;
        char *ptoken = NULL;
        char *psave = NULL;
        pos = strchr(pline, ':');
        if (pos == NULL) {
            ERROR("Invalid cgroup entry: must contain at least two colons: %s", pline);
            ret = -1;
            goto out;
        }
        pos++;
        pos2 = strchr(pos, ':');
        if (pos2 == NULL) {
            ERROR("Invalid cgroup entry: must contain at least two colons: %s", pline);
            ret = -1;
            goto out;
        }
        pos3 = strchr(pos2, '\n');
        if (pos3 != NULL) {
            *pos3 = '\0';
        }
        *pos2 = '\0';

        if ((pos2 - pos) == 0) {
            INFO("Cgroup entry: %s not supported by cgroup v1", pline);
            continue;
        }

        for (ptoken = strtok_r(pos, ",", &psave); ptoken; ptoken = strtok_r(NULL, ",", &psave)) {
            ret = util_array_append(nlist, ptoken);
            if (ret != 0) {
                ERROR("Failed to append string");
                goto out;
            }

            ret = util_array_append(plist, pos2 + 1);
            if (ret != 0) {
                ERROR("Failed to append string");
                goto out;
            }
        }
    }

out:
    if (ret != 0) {
        util_free_array(*nlist);
        *nlist = NULL;
        util_free_array(*plist);
        *plist = NULL;
    }
    return ret;
}

static char *common_get_cgroup_path(const char *path, const char *subsystem)
{
    char **nlist = NULL, **plist = NULL;
    size_t i = 0;
    char *res = NULL;
    if (path == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    if (parse_cgroup_file(path, &nlist, &plist) < 0) {
        return NULL;
    }

    for (i = 0; i < util_array_len((const char **)nlist); i++) {
        const char *prefix = "name=";
        bool find_sub = (strcmp(nlist[i], subsystem) == 0 || (strncmp(nlist[i], prefix, strlen(prefix)) == 0
                        && strcmp(nlist[i]+strlen(prefix), subsystem) == 0));
        if (find_sub) {
            res = util_strdup_s(plist[i]);
            break;
        }
    }

    util_free_array(nlist);
    util_free_array(plist);
    return res;
}

static bool oom_cb_cgroup_v1(int fd, void *cbdata)
{
    cgroup_oom_handler_info_t *info = (cgroup_oom_handler_info_t *)cbdata;
    /* Try to read cgroup.event_control and known if the cgroup was removed
     * if the cgroup was removed and only one event received,
     * we know that it is a cgroup removal event rather than an oom event
     */
    bool cgroup_removed = false;
    if (info == NULL) {
        ERROR("Invalide callback data");
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    if (access(info->cgroup_memory_event_path, F_OK) < 0) {
        DEBUG("Cgroup event path was removed");
        cgroup_removed = true;
    }

    uint64_t event_count;
    ssize_t num_read = util_read_nointr(fd, &event_count, sizeof(uint64_t));
    if (num_read < 0) {
        ERROR("Failed to read oom event from eventfd");
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    if (num_read == 0) {
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    if (num_read != sizeof(uint64_t)) {
        ERROR("Failed to read full oom event from eventfd");
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    if (event_count == 0) {
        ERROR("Unexpected event count when reading for oom event");
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    if (event_count == 1 && cgroup_removed) {
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    INFO("OOM event detected");
    (void)isulad_monitor_send_container_event(info->name, OOM, -1, 0, NULL, NULL);

    return CGROUP_OOM_HANDLE_CLOSE;
}

static char *get_memory_cgroup_path_v1(const char *cgroup_path)
{
    int nret = 0;
    __isula_auto_free char *converted_cgroup_path = NULL;
    __isula_auto_free char *mnt = NULL;
    __isula_auto_free char *root = NULL;
    char fpath[PATH_MAX] = { 0 };

    converted_cgroup_path = common_convert_cgroup_path(cgroup_path);
    if (converted_cgroup_path == NULL) {
        ERROR("Failed to transfer cgroup path");
        return NULL;
    }

    nret = get_cgroup_mnt_and_root_path_v1("memory", &mnt, &root);
    if (nret != 0 || mnt == NULL || root == NULL) {
        ERROR("Can not find cgroup mnt and root path for subsystem 'memory'");
        return NULL;
    }

    // When iSulad is run inside docker, the root is based of the host cgroup.
    // Replace root to "/"
    if (strncmp(root, "/docker/", strlen("/docker/")) == 0) {
        root[1] = '\0';
    }

    nret = snprintf(fpath, sizeof(fpath), "%s/%s", mnt, root);
    if (nret < 0 || (size_t)nret >= sizeof(fpath)) {
        ERROR("Failed to print string");
        return NULL;
    }

    return util_path_join(fpath, converted_cgroup_path);
}

static cgroup_oom_handler_info_t *get_cgroup_oom_handler_v1(int fd, const char *name, const char *cgroup_path, const char *exit_fifo)
{
    __isula_auto_free char *memory_cgroup_path = NULL;
    __isula_auto_free char *memory_cgroup_oom_control_path = NULL;
    __isula_auto_free char *data = NULL;
    __isula_auto_close int cgroup_event_control_fd = -1;
    if (name == NULL || cgroup_path == NULL || exit_fifo == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    cgroup_oom_handler_info_t *info = util_common_calloc_s(sizeof(cgroup_oom_handler_info_t));
    if (info == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    info->name = util_strdup_s(name);
    info->cgroup_file_fd =  -1;
    info->oom_event_fd = -1;
    info->oom_event_handler = oom_cb_cgroup_v1;

    memory_cgroup_path = get_memory_cgroup_path_v1(cgroup_path);
    if (memory_cgroup_path == NULL) {
        ERROR("Failed to get memory cgroup path");
        goto cleanup;
    }

    info->cgroup_memory_event_path = util_path_join(memory_cgroup_path, "cgroup.event_control");
    if (info->cgroup_memory_event_path == NULL) {
        ERROR("Failed to join memory cgroup file path");
        goto cleanup;
    }

    cgroup_event_control_fd = util_open(info->cgroup_memory_event_path, O_WRONLY | O_CLOEXEC, 0);
    if (cgroup_event_control_fd < 0) {
        ERROR("Failed to open %s", info->cgroup_memory_event_path);
        goto cleanup;
    }

    memory_cgroup_oom_control_path = util_path_join(memory_cgroup_path, "memory.oom_control");
    if (memory_cgroup_oom_control_path == NULL) {
        ERROR("Failed to join memory cgroup file path");
        goto cleanup;
    }

    info->cgroup_file_fd = util_open(memory_cgroup_oom_control_path, O_RDONLY | O_CLOEXEC, 0);
    if (info->cgroup_file_fd < 0) {
        ERROR("Failed to open %s", memory_cgroup_oom_control_path);
        goto cleanup;
    }

    info->oom_event_fd = eventfd(0, EFD_CLOEXEC);
    if (info->oom_event_fd < 0) {
        ERROR("Failed to create oom eventfd");
        goto cleanup;
    }

    if (asprintf(&data, "%d %d", info->oom_event_fd, info->cgroup_file_fd) < 0 ||
        util_write_nointr(cgroup_event_control_fd, data, strlen(data)) < 0) {
        ERROR("Failed to write to cgroup.event_control");
        goto cleanup;
    }

    return info;
cleanup:
    common_free_cgroup_oom_handler_info(info);
    return NULL;
}

char *get_init_cgroup_path_v1(const char *subsystem)
{
    return common_get_cgroup_path("/proc/1/cgroup", subsystem);
}

char *get_own_cgroup_v1(const char *subsystem)
{
    return common_get_cgroup_path("/proc/self/cgroup", subsystem);
}

int get_cgroup_version_v1()
{
    return CGROUP_VERSION_1;
}

int cgroup_v1_ops_init(cgroup_ops *ops)
{
    if (ops == NULL) {
        return -1;
    }
    ops->get_cgroup_version = get_cgroup_version_v1;
    ops->get_cgroup_info = get_cgroup_info_v1;
    ops->get_cgroup_metrics = get_cgroup_metrics_v1;
    ops->get_cgroup_mnt_and_root_path = get_cgroup_mnt_and_root_path_v1;
    ops->get_init_cgroup_path = get_init_cgroup_path_v1;
    ops->get_own_cgroup_path = get_own_cgroup_v1;
    ops->get_cgroup_oom_handler = get_cgroup_oom_handler_v1;
    return 0;
}