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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container sysinfo definition
 ******************************************************************************/
#ifndef DAEMON_COMMON_SYSINFO_H
#define DAEMON_COMMON_SYSINFO_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/utsname.h>

#define etcOsRelease "/etc/os-release"
#define altOsRelease "/usr/lib/os-release"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool limit;
    bool swap;
    bool reservation;
    bool oomkilldisable;
    bool swappiness;
    bool kernel;
} cgroup_mem_info_t;

typedef struct {
    bool cpu_rt_period;
    bool cpu_rt_runtime;
    bool cpu_shares;
    bool cpu_cfs_period;
    bool cpu_cfs_quota;
} cgroup_cpu_info_t;

typedef struct {
    bool hugetlblimit;
} cgroup_hugetlb_info_t;

typedef struct {
    bool blkio_weight;
    bool blkio_weight_device;
    bool blkio_read_bps_device;
    bool blkio_write_bps_device;
    bool blkio_read_iops_device;
    bool blkio_write_iops_device;
} cgroup_blkio_info_t;

typedef struct {
    bool cpuset;
    char *cpus;
    char *mems;
} cgroup_cpuset_info_t;

typedef struct {
    bool pidslimit;
} cgroup_pids_info_t;

typedef struct {
    bool fileslimit;
} cgroup_files_info_t;

typedef struct {
    int ncpus;
    cgroup_mem_info_t cgmeminfo;
    cgroup_cpu_info_t cgcpuinfo;
    cgroup_hugetlb_info_t hugetlbinfo;
    cgroup_blkio_info_t blkioinfo;
    cgroup_cpuset_info_t cpusetinfo;
    cgroup_pids_info_t pidsinfo;
    cgroup_files_info_t filesinfo;
} sysinfo_t;

typedef struct {
    // ID is a unique identifier of the mount (may be reused after umount).
    int id;

    // Parent indicates the ID of the mount parent (or of self for the top of the
    // mount tree).
    int parent;

    // Major indicates one half of the device ID which identifies the device class.
    int major;

    // Minor indicates one half of the device ID which identifies a specific
    // instance of device.
    int minor;

    // Root of the mount within the filesystem.
    char *root;

    // Mountpoint indicates the mount point relative to the process's root.
    char *mountpoint;

    // Opts represents mount-specific options.
    char *opts;

    // Optional represents optional fields.
    char *optional;

    // Fstype indicates the type of filesystem, such as EXT3.
    char *fstype;

    // Source indicates filesystem specific information or "none".
    char *source;

    // VfsOpts represents per super block options.
    char *vfsopts;
} mountinfo_t;

void free_sysinfo(sysinfo_t *sysinfo);

// check whether hugetlb pagesize and limit legal
char *validate_hugetlb(const char *pagesize, uint64_t limit);

int find_cgroup_mountpoint_and_root(const char *subsystem, char **mountpoint, char **root);

sysinfo_t *get_sys_info(bool quiet);

char *get_default_huge_page_size(void);

uint64_t get_default_total_mem_size(void);

char *get_operating_system(void);

mountinfo_t **getmountsinfo(void);

mountinfo_t *find_mount_info(mountinfo_t **minfos, const char *dir);

void free_mounts_info(mountinfo_t **minfos);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_COMMON_SYSINFO_H
