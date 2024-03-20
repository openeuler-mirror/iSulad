/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide system information functions
 ******************************************************************************/
#include "sysinfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/sysinfo.h>

#include <isula_libutils/log.h>

#include "err_msg.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_file.h"

#define etcOsRelease "/etc/os-release"
#define altOsRelease "/usr/lib/os-release"

static char *get_pagesize(const char *pline)
{
    size_t headlen;
    char *pos2 = NULL;
    const char *pos = pline;

    headlen = strlen("Hugepagesize");
    if (strncmp(pos, "Hugepagesize", headlen) != 0) {
        return NULL;
    }

    pos2 = strchr(pos + headlen, ':');
    if (pos2 == NULL) {
        ERROR("Invalid Hugepagesize format \"%s\"", pline);
        return NULL;
    }
    *pos2 = '\0';
    pos2++;
    return util_string_delchar(pos2, ' ');
}

/* get default huge page size */
char *get_default_huge_page_size(void)
{
    int ret = 0;
    int64_t sizenum = 0;
    size_t length = 0;
    FILE *fp = NULL;
    char *pagesize = NULL;
    char *humansize = NULL;
    char *pline = NULL;

    fp = util_fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        ERROR("Failed to open \"/proc/meminfo\"\n");
        return NULL;
    }

    while (getline(&pline, &length, fp) != -1) {
        pagesize = get_pagesize(pline);
        if (pagesize != NULL) {
            break;
        }
    }
    if (pagesize == NULL) {
        ERROR("Failed to get hugepage size");
        goto out;
    }

    util_trim_newline(pagesize);

    ret = util_parse_byte_size_string(pagesize, &sizenum);
    if (ret != 0) {
        ERROR("Invalid page size: %s", pagesize);
        goto out;
    }

    humansize = util_human_size((uint64_t)sizenum);
out:
    fclose(fp);
    free(pagesize);
    free(pline);
    return humansize;
}

/* get default total mem size */
uint64_t get_default_total_mem_size(void)
{
    FILE *fp = NULL;
    size_t len = 0;
    char *line = NULL;
    char *p = NULL;
    uint64_t sysmem_limit = 0;

    fp = util_fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        SYSERROR("Failed to open /proc/meminfo.");
        return sysmem_limit;
    }

    while (getline(&line, &len, fp) != -1) {
        p = strchr(line, ' ');
        if (p == NULL) {
            goto out;
        }
        *p = '\0';
        p++;
        if (strcmp(line, "MemTotal:") == 0) {
            while (*p == ' ' || *p == '\t') {
                p++;
            }
            if (*p == '\0') {
                goto out;
            }
            sysmem_limit = strtoull(p, NULL, 0);
            break;
        }
    }

out:
    fclose(fp);
    free(line);
    return sysmem_limit * SIZE_KB;
}

/* get default operating system */
char *get_operating_system(void)
{
    size_t len = 0;
    FILE *fp;
    char *prettyname = NULL;
    char *pretty_name = "PRETTY_NAME=";
    char *line = NULL;

    fp = fopen(etcOsRelease, "r");
    if (fp == NULL) {
        SYSINFO("Failed to open %s.", etcOsRelease);
        fp = fopen(altOsRelease, "r");
        if (fp == NULL) {
            SYSERROR("Failed to open %s.", altOsRelease);
            goto out;
        }
    }

    while (getline(&line, &len, fp) != -1) {
        if ((strncmp(line, pretty_name, strlen(pretty_name))) == 0) {
            prettyname = util_strdup_s(line + strlen(pretty_name));
            break;
        }
    }

    prettyname = util_trim_quotation(prettyname);

out:
    if (fp != NULL) {
        fclose(fp);
    }
    free(line);
    if (prettyname != NULL) {
        return prettyname;
    }
    return util_strdup_s("Linux");
}

static bool is_hugetlb_max(const char *name)
{
    return util_has_prefix(name, "hugetlb.") && util_has_suffix(name, ".max");
}

/* get huge page sizes */
static char **get_huge_page_sizes()
{
    int ret = 0;
    char *hugetlbmp = NULL;
    char **hps = NULL;
    DIR *dir = NULL;
    struct dirent *info_archivo = NULL;
    int cgroup_version = 0;

    ret = common_get_cgroup_mnt_and_root_path("hugetlb", &hugetlbmp, NULL);
    if (ret != 0 || hugetlbmp == NULL) {
        ERROR("Hugetlb cgroup not supported");
        return NULL;
    }

    dir = opendir(hugetlbmp);
    if (dir == NULL) {
        ERROR("Failed to open hugetlb cgroup directory: %s", hugetlbmp);
        goto free_out;
    }
    info_archivo = readdir(dir);
    for (; info_archivo != NULL; info_archivo = readdir(dir)) {
        char *contain = NULL;
        char *dup = NULL;
        char *pos = NULL;
        char *dot2 = NULL;

        cgroup_version = common_get_cgroup_version();
        if (cgroup_version == CGROUP_VERSION_2) {
            if (!is_hugetlb_max(info_archivo->d_name)) {
                continue;
            }
        } else {
            contain = strstr(info_archivo->d_name, "limit_in_bytes");
            if (contain == NULL) {
                continue;
            }
        }

        dup = util_strdup_s(info_archivo->d_name);
        if (dup == NULL) {
            goto free_out;
        }

        pos = dup;
        pos = strchr(pos, '.');
        if (pos == NULL) {
            goto dup_free;
        }
        *pos = '\0';
        pos++;
        dot2 = strchr(pos, '.');
        if (dot2 == NULL) {
            goto dup_free;
        }
        *dot2 = '\0';

        if (util_array_append(&hps, pos) != 0) {
            ERROR("Failed to append array");
            free(dup);
            util_free_array(hps);
            hps = NULL;
            goto free_out;
        }

dup_free:
        free(dup);
    }
free_out:
    free(hugetlbmp);
    if (dir != NULL) {
        closedir(dir);
    }
    return hps;
}

/* is huge pagesize valid */
static bool is_huge_pagesize_valid(const char *pagesize)
{
    int nret;
    bool bret = false;
    size_t hps_len;
    char **hps = NULL;
    char **it = NULL;
    char hpsbuf[BUFSIZ] = { 0 };

    hps = get_huge_page_sizes();
    if (hps == NULL) {
        ERROR("Hugetlb cgroup not supported");
        goto free_out;
    }
    hps_len = util_array_len((const char **)hps);
    if (hps_len == 0) {
        ERROR("Hugetlb cgroup not supported");
        goto free_out;
    }

    for (it = hps; *it; it++) {
        nret = snprintf(hpsbuf, sizeof(hpsbuf), "%s ", *it);
        if (nret < 0 || (size_t)nret >= sizeof(hpsbuf)) {
            ERROR("hps buf is too short");
            goto free_out;
        }
        if (strcmp(*it, pagesize) == 0) {
            bret = true;
        }
    }
    hpsbuf[strlen(hpsbuf) - 1] = '\0';
free_out:
    if (!bret) {
        ERROR("Invalid hugepage size: %s, should be one of [%s]", pagesize, hpsbuf);
        isulad_set_error_message("Invalid hugepage size: %s, should be one of [%s]", pagesize, hpsbuf);
        if (g_isulad_errmsg == NULL) {
            ERROR("Out of memory");
        }
    }
    util_free_array(hps);
    return bret;
}

// isHugeLimitValid check whether input hugetlb limit legal
// it will check whether the limit size is times of size
static void is_hugelimit_valid(const char *pagesize, uint64_t limit)
{
    int ret;
    int64_t sizeint = 0;

    ret = util_parse_byte_size_string(pagesize, &sizeint);
    if (ret < 0 || sizeint == 0) {
        WARN("Invalid pagesize: %s", pagesize);
        return;
    }
    if (limit % (uint64_t)sizeint != 0) {
        WARN("HugeTlb limit should be times of hugepage size. "
             "cgroup will down round to the nearest multiple");
    }
}

// check whether hugetlb pagesize and limit legal
char *validate_hugetlb(const char *pagesize, uint64_t limit)
{
    char *newpagesize = NULL;
    int64_t sizeint = 0;

    if (pagesize != NULL && strlen(pagesize) != 0) {
        int nret = util_parse_byte_size_string(pagesize, &sizeint);
        if (nret < 0) {
            ERROR("Invalid pagesize: %s", pagesize);
            return NULL;
        }
        newpagesize = util_human_size((uint64_t)sizeint);
        if (newpagesize == NULL) {
            ERROR("Invalid pagesize: %s", pagesize);
            return NULL;
        }
        bool valid = is_huge_pagesize_valid(newpagesize);
        if (!valid) {
            free(newpagesize);
            return NULL;
        }
    } else {
        newpagesize = get_default_huge_page_size();
        if (newpagesize == NULL) {
            ERROR("Failed to get system hugepage size");
            return NULL;
        }
    }

    is_hugelimit_valid(newpagesize, limit);

    return newpagesize;
}

/* free sysinfo */
void free_sysinfo(sysinfo_t *sysinfo)
{
    if (sysinfo == NULL) {
        return;
    }

    free(sysinfo->cpusetinfo.cpus);
    sysinfo->cpusetinfo.cpus = NULL;

    free(sysinfo->cpusetinfo.mems);
    sysinfo->cpusetinfo.mems = NULL;

    free(sysinfo);
}

/* get sys info */
sysinfo_t *get_sys_info(bool quiet)
{
    sysinfo_t *sysinfo = NULL;
    int ret = 0;

    sysinfo = util_common_calloc_s(sizeof(sysinfo_t));
    if (sysinfo == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    sysinfo->ncpus = get_nprocs();
    sysinfo->ncpus_conf = get_nprocs_conf();

    ret = common_get_cgroup_info(&sysinfo->cgmeminfo, &sysinfo->cgcpuinfo, &sysinfo->hugetlbinfo,
                                        &sysinfo->blkioinfo, &sysinfo->cpusetinfo, &sysinfo->pidsinfo,
                                        &sysinfo->filesinfo, quiet);
    if (ret != 0) {
        goto out;
    }
out:
    if (ret != 0) {
        free_sysinfo(sysinfo);
        sysinfo = NULL;
    }
    return sysinfo;
}

/* free mount info */
void free_mount_info(mountinfo_t *info)
{
    if (info == NULL) {
        return;
    }

    free(info->root);
    info->root = NULL;

    free(info->mountpoint);
    info->mountpoint = NULL;

    free(info->opts);
    info->opts = NULL;

    free(info->optional);
    info->optional = NULL;

    free(info->fstype);
    info->fstype = NULL;

    free(info->source);
    info->source = NULL;

    free(info->vfsopts);
    info->vfsopts = NULL;

    free(info);
}

// line example
// 108 99 0:55 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755
mountinfo_t *get_mount_info(const char *pline)
{
    size_t length;
    int ret = 0;
    mountinfo_t *info = NULL;
    char **list = NULL;

    info = util_common_calloc_s(sizeof(mountinfo_t));
    if (info == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    list = util_string_split(pline, ' ');
    if (list == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }
    length = util_array_len((const char **)list);
    if (length < 8) {
        ERROR("Invalid mountinfo '%s'", pline);
        ret = -1;
        goto free_out;
    }

    info->mountpoint = util_strdup_s(list[4]);

    if (strcmp(list[6], "-") != 0) {
        info->optional = util_strdup_s(list[6]);
    }

free_out:
    util_free_array(list);
    if (ret != 0) {
        free_mount_info(info);
        info = NULL;
    }
    return info;
}

/* free mounts info */
void free_mounts_info(mountinfo_t **minfos)
{
    mountinfo_t **it = NULL;

    if (minfos == NULL) {
        return;
    }

    for (it = minfos; it && *it; it++) {
        free_mount_info(*it);
        *it = NULL;
    }
    free(minfos);
}

/* find mount info */
mountinfo_t *find_mount_info(mountinfo_t **minfos, const char *dir)
{
    mountinfo_t **it = NULL;

    if (dir == NULL) {
        return NULL;
    }

    for (it = minfos; it && *it; it++) {
        if ((*it)->mountpoint && strcmp((*it)->mountpoint, dir) == 0) {
            return *it;
        }
    }
    return NULL;
}

/* getmountsinfo */
mountinfo_t **getmountsinfo(void)
{
    mountinfo_t **minfos = NULL;
    int ret = 0;
    FILE *fp = NULL;
    size_t length;
    char *pline = NULL;

    fp = util_fopen("/proc/self/mountinfo", "r");
    if (fp == NULL) {
        ERROR("Failed to open \"/proc/self/mountinfo\"\n");
        return NULL;
    }

    while (getline(&pline, &length, fp) != -1) {
        mountinfo_t *info = NULL;

        info = get_mount_info(pline);
        if (info == NULL) {
            ret = -1;
            goto free_out;
        }

        if (util_common_array_append_pointer((void ***)&minfos, info) != 0) {
            ERROR("Failed to append pointer to array");
            free_mount_info(info);
            ret = -1;
            goto free_out;
        }
    }

free_out:
    fclose(fp);
    free(pline);
    if (ret != 0) {
        free_mounts_info(minfos);
        minfos = NULL;
    }
    return minfos;
}

char *sysinfo_get_cpurt_mnt_path(void)
{
    int nret = 0;
    __isula_auto_free char *mnt = NULL;
    __isula_auto_free char *root = NULL;
    char fpath[PATH_MAX] = { 0 };
    __isula_auto_sysinfo_t sysinfo_t *sysinfo = NULL;

    sysinfo = get_sys_info(true);
    if (sysinfo == NULL) {
        ERROR("Can not get system info");
        return NULL;
    }

    if (!(sysinfo->cgcpuinfo.cpu_rt_period)) {
        ERROR("Daemon-scoped cpu-rt-period and cpu-rt-runtime are not supported by kernel");
        isulad_set_error_message("Daemon-scoped cpu-rt-period and cpu-rt-runtime are not supported by kernel");
        return NULL;
    }

    nret = common_get_cgroup_mnt_and_root_path("cpu", &mnt, &root);
    if (nret != 0 || mnt == NULL || root == NULL) {
        ERROR("Can not find cgroup mnt and root path for subsystem 'cpu'");
        isulad_set_error_message("Can not find cgroup mnt and root path for subsystem 'cpu'");
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

    return util_strdup_s(fpath);
}
