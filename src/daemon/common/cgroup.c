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
#include <limits.h>
#include <dirent.h>
#include <errno.h>
#include <sys/sysinfo.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <sys/stat.h>

#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/log.h>

#include "constants.h"
#include "err_msg.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"
#include "sysinfo.h"

// Cgroup V1 Item Definition
#define CGROUP_BLKIO_WEIGHT "blkio.weight"
#define CGROUP_BLKIO_WEIGHT_DEVICE "blkio.weight_device"
#define CGROUP_BLKIO_READ_BPS_DEVICE "blkio.throttle.read_bps_device"
#define CGROUP_BLKIO_WRITE_BPS_DEVICE "blkio.throttle.write_bps_device"
#define CGROUP_BLKIO_READ_IOPS_DEVICE "blkio.throttle.read_iops_device"
#define CGROUP_BLKIO_WRITE_IOPS_DEVICE "blkio.throttle.write_iops_device"
#define CGROUP_CPU_SHARES "cpu.shares"
#define CGROUP_CPU_PERIOD "cpu.cfs_period_us"
#define CGROUP_CPU_QUOTA "cpu.cfs_quota_us"
#define CGROUP_CPU_RT_PERIOD "cpu.rt_period_us"
#define CGROUP_CPU_RT_RUNTIME "cpu.rt_runtime_us"
#define CGROUP_CPUSET_CPUS "cpuset.cpus"
#define CGROUP_CPUSET_MEMS "cpuset.mems"
#define CGROUP_MEMORY_LIMIT "memory.limit_in_bytes"
#define CGROUP_MEMORY_SWAP "memory.memsw.limit_in_bytes"
#define CGROUP_MEMORY_SWAPPINESS "memory.swappiness"
#define CGROUP_MEMORY_RESERVATION "memory.soft_limit_in_bytes"
#define CGROUP_KENEL_MEMORY_LIMIT "memory.kmem.limit_in_bytes"
#define CGROUP_MEMORY_OOM_CONTROL "memory.oom_control"

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

struct layer {
    char **controllers;
    char *mountpoint;
};

static void free_layer(struct layer **layers)
{
    struct layer **it = NULL;

    if (layers == NULL) {
        return;
    }

    for (it = layers; it && *it; it++) {
        free((*it)->mountpoint);
        (*it)->mountpoint = NULL;
        free_list((*it)->controllers);
        (*it)->controllers = NULL;
        free(*it);
        *it = NULL;
    }
    free(layers);
}

static int append_string(char ***list, const char *entry)
{
    int index;
    char *dup_entry = NULL;

    index = add_null_to_list((void ***)list);
    if (index < 0) {
        return -1;
    }
    dup_entry = util_strdup_s(entry);
    if (dup_entry == NULL) {
        return -1;
    }
    (*list)[index] = dup_entry;
    return 0;
}

static int append_subsystem_to_list(char ***klist, char ***nlist, const char *ptoken)
{
    int ret = 0;

    if (strncmp(ptoken, "name=", 5) == 0) {
        ret = append_string(nlist, ptoken);
        if (ret != 0) {
            ERROR("Failed to append string");
            return -1;
        }
    } else {
        ret = append_string(klist, ptoken);
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
        free_list(*klist);
        *klist = NULL;
        free_list(*nlist);
        *nlist = NULL;
    }
    return ret;
}

static bool list_contain_string(const char **a_list, const char *str)
{
    int i;

    if (a_list == NULL) {
        return false;
    }

    for (i = 0; a_list[i]; i++) {
        if (strcmp(a_list[i], str) == 0) {
            return true;
        }
    }

    return false;
}

static char *cgroup_legacy_must_prefix_named(const char *entry)
{
    size_t len;
    char *prefixed = NULL;
    const char *prefix = "name=";

    len = strlen(entry);

    if (((SIZE_MAX - len) - 1) < strlen(prefix)) {
        ERROR("Out of memory");
        return NULL;
    }

    prefixed = util_common_calloc_s(len + strlen(prefix) + 1);
    if (prefixed == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    (void)memcpy(prefixed, prefix, strlen(prefix));
    (void)memcpy(prefixed + strlen(prefix), entry, len);

    prefixed[len + strlen(prefix)] = '\0';
    return prefixed;
}

static int append_controller(const char **klist, const char **nlist, char ***clist, const char *entry)
{
    int index;
    char *dup_entry = NULL;

    if (list_contain_string(klist, entry) && list_contain_string(nlist, entry)) {
        ERROR("Refusing to use ambiguous controller \"%s\"", entry);
        ERROR("It is both a named and kernel subsystem");
        return -1;
    }

    index = add_null_to_list((void ***)clist);
    if (index < 0) {
        return -1;
    }

    if (strncmp(entry, "name=", 5) == 0) {
        dup_entry = util_strdup_s(entry);
    } else if (list_contain_string(klist, entry)) {
        dup_entry = util_strdup_s(entry);
    } else {
        dup_entry = cgroup_legacy_must_prefix_named(entry);
    }
    if (dup_entry == NULL) {
        return -1;
    }
    (*clist)[index] = dup_entry;
    return 0;
}

static inline bool is_cgroup_mountpoint(const char *mp)
{
    return strncmp(mp, "/sys/fs/cgroup/", strlen("/sys/fs/cgroup/")) == 0;
}

static void set_char_to_terminator(char *p)
{
    *p = '\0';
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
    set_char_to_terminator(pos2);

    dup = util_strdup_s(pos);
    *pos2 = ' ';

    for (tok = strtok_r(dup, sep, &psave); tok; tok = strtok_r(NULL, sep, &psave)) {
        if (append_controller(klist, nlist, &pret, tok)) {
            ERROR("Failed to append controller");
            free_list(pret);
            pret = NULL;
            break;
        }
    }

    free(dup);

    return pret;
}

/* add hierarchy */
static int cgroup_add_layer(struct layer ***layers, char **clist, char *mountpoint)
{
    int index;
    struct layer *newh = NULL;

    newh = util_common_calloc_s(sizeof(struct layer));
    if (newh == NULL) {
        return -1;
    }

    newh->controllers = clist;
    newh->mountpoint = mountpoint;
    index = add_null_to_list((void ***)layers);
    if (index < 0) {
        free(newh);
        return -1;
    }
    (*layers)[index] = newh;
    return 0;
}

int cgroup_get_mountpoint_and_root(char *pline, char **mountpoint, char **root)
{
    int index;
    char *posmp = NULL;
    char *posrt = NULL;
    char *pos = pline;

    // find root
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
        if (list_contain_string(list, controllers[index])) {
            return true;
        }
    }

    return false;
}

static bool controller_list_is_dup(struct layer **llist, const char **clist)
{
    int index;

    if (llist == NULL) {
        return false;
    }

    for (index = 0; llist[index]; index++) {
        if (lists_intersect((const char **)llist[index]->controllers, (const char **)clist)) {
            return true;
        }
    }

    return false;
}

static struct layer **cgroup_layers_find(void)
{
    int nret;
    FILE *fp = NULL;
    size_t length = 0;
    char *pline = NULL;
    char **klist = NULL;
    char **nlist = NULL;
    struct layer **layers = NULL;

    nret = get_cgroup_subsystems(&klist, &nlist);
    if (nret < 0) {
        ERROR("Failed to retrieve available legacy cgroup controllers\n");
        return NULL;
    }

    fp = util_fopen("/proc/self/mountinfo", "r");
    if (fp == NULL) {
        ERROR("Failed to open \"/proc/self/mountinfo\"\n");
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

        nret = cgroup_add_layer(&layers, clist, mountpoint);
        if (nret != 0) {
            ERROR("Failed to add hierarchies");
            goto list_out;
        }

        continue;
list_out:
        free_list(clist);
        free(mountpoint);
    }
out:
    free_list(klist);
    free_list(nlist);
    if (fp != NULL) {
        fclose(fp);
    }
    free(pline);
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

static void cgroup_do_log(bool quiet, bool do_log, const char *msg)
{
    if (!quiet && do_log) {
        WARN("%s", msg);
    }
}

static char *find_cgroup_subsystem_mountpoint(struct layer **layers, const char *subsystem)
{
    struct layer **it = NULL;

    for (it = layers; it && *it; it++) {
        char **cit = NULL;

        for (cit = (*it)->controllers; cit && *cit; cit++) {
            if (strcmp(*cit, subsystem) == 0) {
                return (*it)->mountpoint;
            }
        }
    }
    return NULL;
}

/* check cgroup mem */
static void check_cgroup_mem(struct layer **layers, bool quiet, cgroup_mem_info_t *meminfo)
{
    char *mountpoint = NULL;

    mountpoint = find_cgroup_subsystem_mountpoint(layers, "memory");
    if (mountpoint == NULL) {
        cgroup_do_log(quiet, true, "Your kernel does not support cgroup memory limit");
        return;
    }

    meminfo->limit = cgroup_enabled(mountpoint, CGROUP_MEMORY_LIMIT);
    cgroup_do_log(quiet, !(meminfo->limit), "Your kernel does not support memory limit");

    meminfo->swap = cgroup_enabled(mountpoint, CGROUP_MEMORY_SWAP);
    cgroup_do_log(quiet, !(meminfo->swap), "Your kernel does not support swap memory limit");

    meminfo->reservation = cgroup_enabled(mountpoint, CGROUP_MEMORY_RESERVATION);
    cgroup_do_log(quiet, !(meminfo->reservation), "Your kernel does not support memory reservation");

    meminfo->oomkilldisable = cgroup_enabled(mountpoint, CGROUP_MEMORY_OOM_CONTROL);
    cgroup_do_log(quiet, !(meminfo->oomkilldisable), "Your kernel does not support oom control");

    meminfo->swappiness = cgroup_enabled(mountpoint, CGROUP_MEMORY_SWAPPINESS);
    cgroup_do_log(quiet, !(meminfo->swappiness), "Your kernel does not support memory swappiness");

    meminfo->kernel = cgroup_enabled(mountpoint, CGROUP_KENEL_MEMORY_LIMIT);
    cgroup_do_log(quiet, !(meminfo->kernel), "Your kernel does not support kernel memory limit");
}

/* check cgroup cpu */
static void check_cgroup_cpu(struct layer **layers, bool quiet, cgroup_cpu_info_t *cpuinfo)
{
    char *mountpoint = NULL;

    mountpoint = find_cgroup_subsystem_mountpoint(layers, "cpu");
    if (mountpoint == NULL) {
        cgroup_do_log(quiet, true, "Unable to find cpu cgroup in mounts");
        return;
    }

    cpuinfo->cpu_rt_period = cgroup_enabled(mountpoint, CGROUP_CPU_RT_PERIOD);
    cgroup_do_log(quiet, !(cpuinfo->cpu_rt_period), "Your kernel does not support cgroup rt period");

    cpuinfo->cpu_rt_runtime = cgroup_enabled(mountpoint, CGROUP_CPU_RT_RUNTIME);
    cgroup_do_log(quiet, !(cpuinfo->cpu_rt_runtime), "Your kernel does not support cgroup rt runtime");

    cpuinfo->cpu_shares = cgroup_enabled(mountpoint, CGROUP_CPU_SHARES);
    cgroup_do_log(quiet, !(cpuinfo->cpu_shares), "Your kernel does not support cgroup cpu shares");

    cpuinfo->cpu_cfs_period = cgroup_enabled(mountpoint, CGROUP_CPU_PERIOD);
    cgroup_do_log(quiet, !(cpuinfo->cpu_cfs_period), "Your kernel does not support cgroup cfs period");

    cpuinfo->cpu_cfs_quota = cgroup_enabled(mountpoint, CGROUP_CPU_QUOTA);
    cgroup_do_log(quiet, !(cpuinfo->cpu_cfs_quota), "Your kernel does not support cgroup cfs quota");
}

/* check cgroup blkio info */
static void check_cgroup_blkio_info(struct layer **layers, bool quiet, cgroup_blkio_info_t *blkioinfo)
{
    char *mountpoint = NULL;

    mountpoint = find_cgroup_subsystem_mountpoint(layers, "blkio");
    if (mountpoint == NULL) {
        cgroup_do_log(quiet, true, "Unable to find blkio cgroup in mounts");
        return;
    }

    blkioinfo->blkio_weight = cgroup_enabled(mountpoint, CGROUP_BLKIO_WEIGHT);
    cgroup_do_log(quiet, !(blkioinfo->blkio_weight), "Your kernel does not support cgroup blkio weight");

    blkioinfo->blkio_weight_device = cgroup_enabled(mountpoint, CGROUP_BLKIO_WEIGHT_DEVICE);
    cgroup_do_log(quiet, !(blkioinfo->blkio_weight_device), "Your kernel does not support cgroup blkio weight_device");

    blkioinfo->blkio_read_bps_device = cgroup_enabled(mountpoint, CGROUP_BLKIO_READ_BPS_DEVICE);
    cgroup_do_log(quiet, !(blkioinfo->blkio_read_bps_device),
                  "Your kernel does not support cgroup blkio throttle.read_bps_device");

    blkioinfo->blkio_write_bps_device = cgroup_enabled(mountpoint, CGROUP_BLKIO_WRITE_BPS_DEVICE);
    cgroup_do_log(quiet, !(blkioinfo->blkio_write_bps_device),
                  "Your kernel does not support cgroup blkio throttle.write_bps_device");

    blkioinfo->blkio_read_iops_device = cgroup_enabled(mountpoint, CGROUP_BLKIO_READ_IOPS_DEVICE);
    cgroup_do_log(quiet, !(blkioinfo->blkio_read_iops_device),
                  "Your kernel does not support cgroup blkio throttle.read_iops_device");

    blkioinfo->blkio_write_iops_device = cgroup_enabled(mountpoint, CGROUP_BLKIO_WRITE_IOPS_DEVICE);
    cgroup_do_log(quiet, !(blkioinfo->blkio_write_iops_device),
                  "Your kernel does not support cgroup blkio throttle.write_iops_device");
}

/* check cgroup cpuset info */
static void check_cgroup_cpuset_info(struct layer **layers, bool quiet, cgroup_cpuset_info_t *cpusetinfo)
{
    char *mountpoint = NULL;
    char cpuset_cpus_path[PATH_MAX] = { 0 };
    char cpuset_mems_path[PATH_MAX] = { 0 };

    mountpoint = find_cgroup_subsystem_mountpoint(layers, "cpuset");
    if (mountpoint == NULL) {
        cgroup_do_log(quiet, true, ("Unable to find cpuset cgroup in mounts"));
        return;
    }

    int nret = snprintf(cpuset_cpus_path, sizeof(cpuset_cpus_path), "%s/%s", mountpoint, CGROUP_CPUSET_CPUS);
    if (nret < 0 || (size_t)nret >= sizeof(cpuset_cpus_path)) {
        ERROR("Path is too long");
        goto error;
    }

    cpusetinfo->cpus = util_read_content_from_file(cpuset_cpus_path);
    if (cpusetinfo->cpus == NULL) {
        ERROR("Failed to read the file: %s", cpuset_cpus_path);
        goto error;
    }

    nret = snprintf(cpuset_mems_path, sizeof(cpuset_mems_path), "%s/%s", mountpoint, CGROUP_CPUSET_MEMS);
    if (nret < 0 || (size_t)nret >= sizeof(cpuset_mems_path)) {
        ERROR("Path is too long");
        goto error;
    }

    cpusetinfo->mems = util_read_content_from_file(cpuset_mems_path);
    if (cpusetinfo->mems == NULL) {
        ERROR("Failed to read the file: %s", cpuset_mems_path);
        goto error;
    }
    cpusetinfo->cpus = util_trim_space(cpusetinfo->cpus);
    cpusetinfo->mems = util_trim_space(cpusetinfo->mems);
    cpusetinfo->cpuset = true;
    return;
error:
    free(cpusetinfo->cpus);
    cpusetinfo->cpus = NULL;
    free(cpusetinfo->mems);
    cpusetinfo->mems = NULL;
}

/* check cgroup pids */
static void check_cgroup_pids(bool quiet, cgroup_pids_info_t *pidsinfo)
{
    int ret = 0;
    char *pidsmp = NULL;

    ret = find_cgroup_mountpoint_and_root("pids", &pidsmp, NULL);
    if (ret != 0 || pidsmp == NULL) {
        if (!quiet) {
            WARN("Unable to find pids cgroup in mounts");
        }
        goto out;
    }

    pidsinfo->pidslimit = true;
out:
    free(pidsmp);
}

/* check cgroup files */
static void check_cgroup_files(bool quiet, cgroup_files_info_t *filesinfo)
{
    int ret = 0;
    char *filesmp = NULL;

    ret = find_cgroup_mountpoint_and_root("files", &filesmp, NULL);
    if (ret != 0 || filesmp == NULL) {
        if (!quiet) {
            WARN("Unable to find pids cgroup in mounts");
        }
        goto out;
    }

    filesinfo->fileslimit = true;
out:
    free(filesmp);
}

/* find cgroup mountpoint and root */
int find_cgroup_mountpoint_and_root(const char *subsystem, char **mountpoint, char **root)
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

/* check cgroup hugetlb */
static void check_cgroup_hugetlb(struct layer **layers, bool quiet, cgroup_hugetlb_info_t *hugetlbinfo)
{
    int nret;
    char *mountpoint = NULL;
    char *defaultpagesize = NULL;
    char hugetlbpath[64] = { 0x00 };

    mountpoint = find_cgroup_subsystem_mountpoint(layers, "hugetlb");
    if (mountpoint == NULL) {
        cgroup_do_log(quiet, true, "Your kernel does not support cgroup hugetlb limit");
        return;
    }
    defaultpagesize = get_default_huge_page_size();
    if (defaultpagesize == NULL) {
        WARN("Your kernel does not support cgroup hugetlb limit");
        return;
    }
    nret = snprintf(hugetlbpath, sizeof(hugetlbpath), "hugetlb.%s.limit_in_bytes", defaultpagesize);
    if (nret < 0 || (size_t)nret >= sizeof(hugetlbpath)) {
        WARN("Failed to print hugetlb path");
        goto free_out;
    }
    hugetlbinfo->hugetlblimit = cgroup_enabled(mountpoint, hugetlbpath);
    cgroup_do_log(quiet, !hugetlbinfo->hugetlblimit, ("Your kernel does not support hugetlb limit"));

free_out:
    free(defaultpagesize);
}

int get_cgroup_version(void)
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

int get_cgroup_info_v1(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo, cgroup_hugetlb_info_t *hugetlbinfo,
                       cgroup_blkio_info_t *blkioinfo, cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                       cgroup_files_info_t *filesinfo, bool quiet)
{
    struct layer **layers = NULL;

    layers = cgroup_layers_find();
    if (layers == NULL) {
        ERROR("Failed to parse cgroup information");
        return -1;
    }

    check_cgroup_mem(layers, quiet, meminfo);
    check_cgroup_cpu(layers, quiet, cpuinfo);
    check_cgroup_hugetlb(layers, quiet, hugetlbinfo);
    check_cgroup_blkio_info(layers, quiet, blkioinfo);
    check_cgroup_cpuset_info(layers, quiet, cpusetinfo);
    check_cgroup_pids(quiet, pidsinfo);
    check_cgroup_files(quiet, filesinfo);

    free_layer(layers);

    return 0;
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

int get_cgroup_info_v2(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo, cgroup_hugetlb_info_t *hugetlbinfo,
                       cgroup_blkio_info_t *blkioinfo, cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
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
    cgroup_do_log(quiet, !(cpuinfo->cpu_shares), "Your kernel does not support cgroup2 cpu weight");

    cpuinfo->cpu_cfs_period = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPU_MAX);
    cpuinfo->cpu_cfs_quota = cpuinfo->cpu_cfs_period;
    cgroup_do_log(quiet, !(cpuinfo->cpu_cfs_period), "Your kernel does not support cgroup2 cpu max");

    cpusetinfo->cpuset = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_CPUS_EFFECTIVE) &&
                         cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_CPUS) &&
                         cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_MEMS_EFFECTIVE) &&
                         cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_MEMS);
    cgroup_do_log(quiet, !(cpusetinfo->cpuset), "Your kernel does not support cpuset");
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
    cgroup_do_log(quiet, !(blkioinfo->blkio_weight), "Your kernel does not support cgroup2 io weight");

    blkioinfo->blkio_read_bps_device = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_IO_MAX);
    blkioinfo->blkio_write_bps_device = blkioinfo->blkio_read_bps_device;
    blkioinfo->blkio_read_iops_device = blkioinfo->blkio_read_bps_device;
    blkioinfo->blkio_write_iops_device = blkioinfo->blkio_read_bps_device;
    cgroup_do_log(quiet, !(blkioinfo->blkio_read_bps_device), "Your kernel does not support cgroup2 io max");

    // memory cgroup
    meminfo->limit = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_MEMORY_MAX);
    cgroup_do_log(quiet, !(meminfo->limit), "Your kernel does not support cgroup2 memory max");

    meminfo->reservation = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_MEMORY_LOW);
    cgroup_do_log(quiet, !(meminfo->reservation), "Your kernel does not support cgroup2 memory low");

    meminfo->swap = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_MEMORY_SWAP_MAX);
    cgroup_do_log(quiet, !(meminfo->swap), "Your kernel does not support cgroup2 memory swap max");

    // pids cgroup
    pidsinfo->pidslimit = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_PIDS_MAX);
    cgroup_do_log(quiet, !(pidsinfo->pidslimit), "Your kernel does not support cgroup2 pids max");

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
        cgroup_do_log(quiet, !hugetlbinfo->hugetlblimit, "Your kernel does not support cgroup2 hugetlb limit");
    } else {
        WARN("Your kernel does not support cgroup2 hugetlb limit");
    }

    // files cgroup
    filesinfo->fileslimit = cgroup_enabled(CGROUP_ISULAD_PATH, CGROUP2_FILES_LIMIT);
    cgroup_do_log(quiet, !(filesinfo->fileslimit), "Your kernel does not support cgroup2 files limit");

out:
    free(size);

    return ret;
}
