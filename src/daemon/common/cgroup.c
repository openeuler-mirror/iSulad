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
 * Description: provide cgroup functions
 ******************************************************************************/
#include "cgroup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <sys/stat.h>

#include <isula_libutils/auto_cleanup.h>

#include "err_msg.h"
#include "utils.h"
#include "utils_array.h"
#include "sysinfo.h"

// Cgroup V2 Item Definition
#define CGROUP2_CPU_WEIGHT "cpu.weight"
#define CGROUP2_CPU_MAX "cpu.max"
#define CGROUP2_CPUSET_CPUS_EFFECTIVE "cpuset.cpus.effective"
#define CGROUP2_CPUSET_MEMS_EFFECTIVE "cpuset.mems.effective"
#define CGROUP2_CPUSET_CPUS "cpuset.cpus"
#define CGROUP2_CPUSET_MEMS "cpuset.mems"
#define CGROUP2_IO_WEIGHT "io.weight"
#define CGROUP2_IO_BFQ_WEIGHT "io.bfq.weight"
#define CGROUP2_IO_MAX "io.max"
#define CGROUP2_MEMORY_MAX "memory.max"
#define CGROUP2_MEMORY_LOW "memory.low"
#define CGROUP2_MEMORY_SWAP_MAX "memory.swap.max"
#define CGROUP2_HUGETLB_MAX "hugetlb.%s.max"
#define CGROUP2_PIDS_MAX "pids.max"
#define CGROUP2_FILES_LIMIT "files.limit"

#define CGROUP2_CONTROLLERS_PATH CGROUP_MOUNTPOINT"/cgroup.controllers"
#define CGROUP2_SUBTREE_CONTROLLER_PATH CGROUP_MOUNTPOINT"/cgroup.subtree_control"
#define CGROUP2_CPUSET_CPUS_EFFECTIVE_PATH CGROUP_MOUNTPOINT"/cpuset.cpus.effective"
#define CGROUP2_CPUSET_MEMS_EFFECTIVE_PATH CGROUP_MOUNTPOINT"/cpuset.mems.effective"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif

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

void common_free_cgroup_layer(cgroup_layer_t *layers)
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
    return strncmp(mp, "/sys/fs/cgroup/", strlen("/sys/fs/cgroup/")) == 0;
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

    pos += strlen("/sys/fs/cgroup/");
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

int cgroup_get_mountpoint_and_root(char *pline, char **mountpoint, char **root)
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

    pos = strchr(pos + strlen("/sys/fs/cgroup/"), ' ');
    if (pos == NULL) {
        return -1;
    }
    *pos = '\0';

    if (mountpoint != NULL) {
        *mountpoint = util_strdup_s(posmp);
    }

    return 0;
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

cgroup_layer_t *common_cgroup_layers_find(void)
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

/* cgroup enabled */
static bool cgroup_enabled(const char *mountpoint, const char *name)
{
    char path[PATH_MAX] = { 0 };
    int nret;

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, name);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Path is too long");
        return false;
    }
    return util_file_exists(path);
}

char *common_find_cgroup_subsystem_mountpoint(const cgroup_layer_t *layers, const char *subsystem)
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

/* find cgroup mountpoint and root */
int common_find_cgroup_mnt_and_root(const char *subsystem, char **mountpoint, char **root)
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
        p += strlen("/sys/fs/cgroup/");
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

int common_get_cgroup_version(void)
{
    struct statfs fs = { 0 };

    if (statfs(CGROUP_MOUNTPOINT, &fs) != 0) {
        ERROR("failed to statfs %s: %s", CGROUP_MOUNTPOINT, strerror(errno));
        return -1;
    }

    if (fs.f_type == CGROUP2_SUPER_MAGIC) {
        return CGROUP_VERSION_2;
    }

    return CGROUP_VERSION_1;
}

static int cgroup2_enable_all()
{
    int ret = 0;
    int nret = 0;
    int n = 0;
    size_t i = 0;
    const char *space = "";
    char *controllers_str = NULL;
    char *subtree_controller_str = NULL;
    char **controllers = NULL;
    char enable_controllers[PATH_MAX] = { 0 };

    controllers_str = util_read_content_from_file(CGROUP2_CONTROLLERS_PATH);
    if (controllers_str == NULL || strlen(controllers_str) == 0 || strcmp(controllers_str, "\n") == 0) {
        WARN("no cgroup controller found");
        goto out;
    }

    subtree_controller_str = util_read_content_from_file(CGROUP2_SUBTREE_CONTROLLER_PATH);
    if (subtree_controller_str != NULL && strcmp(controllers_str, subtree_controller_str) == 0) {
        goto out;
    }

    controllers = util_string_split(controllers_str, ' ');
    if (controllers == NULL) {
        ERROR("split %s failed", controllers_str);
        ret = -1;
        goto out;
    }

    for (i = 0; i < util_array_len((const char **)controllers); i++) {
        nret = snprintf(enable_controllers + n, PATH_MAX - n, "%s+%s", space, controllers[i]);
        if (nret < 0 || (size_t)nret >= PATH_MAX - n) {
            ERROR("Path is too long");
            goto out;
        }
        n += nret;
        space = " ";
    }
    ret = util_write_file(CGROUP2_SUBTREE_CONTROLLER_PATH, enable_controllers, strlen(enable_controllers),
                          DEFAULT_CGROUP_FILE_MODE);
    if (ret != 0) {
        ERROR("write %s to %s failed: %s", enable_controllers, CGROUP2_SUBTREE_CONTROLLER_PATH, strerror(errno));
        goto out;
    }

out:
    util_free_array(controllers);
    free(controllers_str);
    free(subtree_controller_str);

    return ret;
}

#if defined (__ANDROID__) || defined(__MUSL__)
static bool cgroup2_no_controller()
{
    char *controllers_str = NULL;

    controllers_str = util_read_content_from_file(CGROUP2_CONTROLLERS_PATH);
    if (controllers_str == NULL || strlen(controllers_str) == 0 || strcmp(controllers_str, "\n") == 0) {
        free(controllers_str);
        return true;
    }

    free(controllers_str);
    return false;
}
#endif

static int make_sure_cgroup2_isulad_path_exist()
{
    int ret = 0;

    if (util_dir_exists(CGROUP_ISULAD_PATH)) {
        return 0;
    }

    if (cgroup2_enable_all() != 0) {
        return -1;
    }

#if defined (__ANDROID__) || defined(__MUSL__)
    if (cgroup2_no_controller()) {
        DEBUG("no cgroup controller found");
        return 0;
    }
#endif

    ret = mkdir(CGROUP_ISULAD_PATH, DEFAULT_CGROUP_DIR_MODE);
    if (ret != 0 && (errno != EEXIST || !util_dir_exists(CGROUP_ISULAD_PATH))) {
        return -1;
    }

    return ret;
}

int common_get_cgroup_info_v2(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo,
                              cgroup_hugetlb_info_t *hugetlbinfo, cgroup_blkio_info_t *blkioinfo,
                              cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                              cgroup_files_info_t *filesinfo, bool quiet)
{
    int ret = 0;
    int nret = 0;
    char *size = NULL;
    char path[PATH_MAX] = { 0 };

    if (make_sure_cgroup2_isulad_path_exist() != 0) {
        return -1;
    }

    // cpu cgroup
    cpuinfo->cpu_shares = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPU_WEIGHT);
    common_cgroup_do_log(quiet, !(cpuinfo->cpu_shares), "Your kernel does not support cgroup2 cpu weight");

    cpuinfo->cpu_cfs_period = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPU_MAX);
    cpuinfo->cpu_cfs_quota = cpuinfo->cpu_cfs_period;
    common_cgroup_do_log(quiet, !(cpuinfo->cpu_cfs_period), "Your kernel does not support cgroup2 cpu max");

    cpusetinfo->cpuset = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_CPUS_EFFECTIVE) &&
                         cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_CPUS) &&
                         cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_MEMS_EFFECTIVE) &&
                         cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_MEMS);
    common_cgroup_do_log(quiet, !(cpusetinfo->cpuset), "Your kernel does not support cpuset");
    if (cpusetinfo->cpuset) {
        cpusetinfo->cpus = util_read_content_from_file(CGROUP2_CPUSET_CPUS_EFFECTIVE_PATH);
        cpusetinfo->mems = util_read_content_from_file(CGROUP2_CPUSET_MEMS_EFFECTIVE_PATH);
        if (cpusetinfo->cpus == NULL || cpusetinfo->mems == NULL) {
            ERROR("read cpus or mems failed");
            return -1;
        }
        cpusetinfo->cpus = util_trim_space(cpusetinfo->cpus);
        cpusetinfo->mems = util_trim_space(cpusetinfo->mems);
    }

    // io cgroup
    blkioinfo->blkio_weight = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_IO_BFQ_WEIGHT) ||
                              cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_IO_WEIGHT);
    blkioinfo->blkio_weight_device = blkioinfo->blkio_weight;
    common_cgroup_do_log(quiet, !(blkioinfo->blkio_weight), "Your kernel does not support cgroup2 io weight");

    blkioinfo->blkio_read_bps_device = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_IO_MAX);
    blkioinfo->blkio_write_bps_device = blkioinfo->blkio_read_bps_device;
    blkioinfo->blkio_read_iops_device = blkioinfo->blkio_read_bps_device;
    blkioinfo->blkio_write_iops_device = blkioinfo->blkio_read_bps_device;
    common_cgroup_do_log(quiet, !(blkioinfo->blkio_read_bps_device), "Your kernel does not support cgroup2 io max");

    // memory cgroup
    meminfo->limit = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_MEMORY_MAX);
    common_cgroup_do_log(quiet, !(meminfo->limit), "Your kernel does not support cgroup2 memory max");

    meminfo->reservation = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_MEMORY_LOW);
    common_cgroup_do_log(quiet, !(meminfo->reservation), "Your kernel does not support cgroup2 memory low");

    meminfo->swap = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_MEMORY_SWAP_MAX);
    common_cgroup_do_log(quiet, !(meminfo->swap), "Your kernel does not support cgroup2 memory swap max");

    // pids cgroup
    pidsinfo->pidslimit = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_PIDS_MAX);
    common_cgroup_do_log(quiet, !(pidsinfo->pidslimit), "Your kernel does not support cgroup2 pids max");

    // hugetlb cgroup
    size = get_default_huge_page_size();
    if (size != NULL) {
        nret = snprintf(path, sizeof(path), CGROUP2_HUGETLB_MAX, size);
        if (nret < 0 || (size_t)nret >= sizeof(path)) {
            WARN("Failed to print hugetlb path");
            ret = -1;
            goto out;
        }
        hugetlbinfo->hugetlblimit = cgroup_enabled(CGROUP_ISULAD_PATH, path);
        common_cgroup_do_log(quiet, !hugetlbinfo->hugetlblimit, "Your kernel does not support cgroup2 hugetlb limit");
    } else {
        WARN("Your kernel does not support cgroup2 hugetlb limit");
    }

    // files cgroup
    filesinfo->fileslimit = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_FILES_LIMIT);
    common_cgroup_do_log(quiet, !(filesinfo->fileslimit), "Your kernel does not support cgroup2 files limit");

out:
    free(size);

    return ret;
}
