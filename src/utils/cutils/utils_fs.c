/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-02-27
 * Description: provide file system utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_fs.h"

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/mount.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"

#ifndef JFS_SUPER_MAGIC
#define JFS_SUPER_MAGIC 0x3153464a
#endif

#ifndef VXFS_SUPER_MAGIC
#define VXFS_SUPER_MAGIC 0xa501fcf5
#endif

#ifndef OVERLAY_SUPER_MAGIC
#define OVERLAY_SUPER_MAGIC 0x794c7630
#endif

#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif

#ifndef AUFS_SUPER_MAGIC
#define AUFS_SUPER_MAGIC 0x61756673
#endif

#ifndef GPFS_SUPER_MAGIC
#define GPFS_SUPER_MAGIC 0x47504653
#endif

#ifndef UNSUPPORTED_MAGIC
#define UNSUPPORTED_MAGIC 0x00000000
#endif

#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif

#ifndef ZFS_SUPER_MAGIC
#define ZFS_SUPER_MAGIC 0x2fc12fc1
#endif

// PROPAGATION_TYPES is the set propagation types.
#define PROPAGATION_TYPES (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)

// PROPAGATION_FLAGS is the full set valid flags for a change propagation call.
#define PROPAGATION_FLAGS (PROPAGATION_TYPES | MS_REC | MS_SILENT)

// BRO_FLAGS is the combination of bind and read only
#define BRO_FLAGS (MS_BIND | MS_RDONLY)

struct fs_element {
    const char *fs_name;
    uint32_t fs_magic;
};

static struct fs_element const g_fs_names[] = {
    { "aufs", AUFS_SUPER_MAGIC },
    { "btrfs", BTRFS_SUPER_MAGIC },
    { "cramfs", CRAMFS_MAGIC },
    { "ecryptfs", ECRYPTFS_SUPER_MAGIC },
    { "extfs", EXT2_SUPER_MAGIC },
    { "f2fs", F2FS_SUPER_MAGIC },
    { "gpfs", GPFS_SUPER_MAGIC },
    { "jffs2", JFFS2_SUPER_MAGIC },
    { "jfs", JFS_SUPER_MAGIC },
    { "nfs", NFS_SUPER_MAGIC },
    { "overlayfs", OVERLAYFS_SUPER_MAGIC },
    { "ramfs", RAMFS_MAGIC },
    { "reiserfs", REISERFS_SUPER_MAGIC },
    { "smb", SMB_SUPER_MAGIC },
    { "squashfs", SQUASHFS_MAGIC },
    { "tmpfs", TMPFS_MAGIC },
    { "unsupported", UNSUPPORTED_MAGIC },
    { "vxfs", VXFS_SUPER_MAGIC },
    { "xfs", XFS_SUPER_MAGIC },
    { "zfs", ZFS_SUPER_MAGIC },
};

struct mount_option_element {
    const char *option;
    bool clear;
    int flag;
};

static struct mount_option_element const g_mount_options[] = {
    { "defaults", false, 0 },
    { "ro", false, MS_RDONLY },
    { "rw", true, MS_RDONLY },
    { "suid", true, MS_NOSUID },
    { "nosuid", false, MS_NOSUID },
    { "dev", true, MS_NODEV },
    { "nodev", false, MS_NODEV },
    { "exec", true, MS_NOEXEC },
    { "noexec", false, MS_NOEXEC },
    { "sync", false, MS_SYNCHRONOUS },
    { "async", true, MS_SYNCHRONOUS },
    { "dirsync", false, MS_DIRSYNC },
    { "remount", false, MS_REMOUNT },
    { "mand", false, MS_MANDLOCK },
    { "nomand", true, MS_MANDLOCK },
    { "atime", true, MS_NOATIME },
    { "noatime", false, MS_NOATIME },
    { "diratime", true, MS_NODIRATIME },
    { "nodiratime", false, MS_NODIRATIME },
    { "bind", false, MS_BIND },
    { "rbind", false, MS_BIND | MS_REC },
    { "unbindable", false, MS_UNBINDABLE },
    { "runbindable", false, MS_UNBINDABLE | MS_REC },
    { "private", false, MS_PRIVATE },
    { "rprivate", false, MS_PRIVATE | MS_REC },
    { "shared", false, MS_SHARED },
    { "rshared", false, MS_SHARED | MS_REC },
    { "slave", false, MS_SLAVE },
    { "rslave", false, MS_SLAVE | MS_REC },
    { "relatime", false, MS_RELATIME },
    { "norelatime", true, MS_RELATIME },
    { "strictatime", false, MS_STRICTATIME },
    { "nostrictatime", true, MS_STRICTATIME },
};

char *util_get_fs_name(const char *path)
{
    int ret = 0;
    size_t i = 0;
    struct statfs fs_state;

    if (path == NULL) {
        return NULL;
    }

    ret = statfs(path, &fs_state);
    if (ret < 0) {
        return NULL;
    }

    for (i = 0; i < sizeof(g_fs_names) / sizeof(g_fs_names[0]); i++) {
        if (g_fs_names[i].fs_magic == fs_state.f_type) {
            return util_strdup_s((g_fs_names[i].fs_name));
        }
    }

    return NULL;
}

static void run_modprobe_overlay(void *args)
{
    execlp("modprobe", "modprobe", "overlay", NULL);
}

static void try_probe_overlay_module()
{
    char *stdout_str = NULL;
    char *stderr_str = NULL;

    if (!util_exec_cmd(run_modprobe_overlay, NULL, NULL, &stdout_str, &stderr_str)) {
        ERROR("modprobe overlay exec failed: [%s], [%s]", stdout_str, stderr_str);
    }

    free(stdout_str);
    free(stderr_str);
}

bool util_support_overlay(void)
{
    bool is_support = false;
    FILE *f = NULL;
    char *line = NULL;
    size_t len = 0;

    try_probe_overlay_module();

    f = util_fopen("/proc/filesystems", "r");
    if (f == NULL) {
        return false;
    }

    while (getline(&line, &len, f) != -1) {
        if (strcmp(line, "nodev\toverlay\n") == 0) {
            is_support = true;
            break;
        }
    }

    fclose(f);
    free(line);
    return is_support;
}

bool util_support_d_type(const char *path)
{
    bool is_support_d_type = true;
    DIR *dir = NULL;
    struct dirent *entry = NULL;

    if (path == NULL) {
        return false;
    }

    dir = opendir(path);
    if (dir == NULL) {
        ERROR("opendir %s failed.\n", path);
        return false;
    }

    entry = readdir(dir);
    for (; entry != NULL; entry = readdir(dir)) {
        if (entry->d_type == DT_UNKNOWN) {
            ERROR("d_type found to be DT_UNKNOWN\n");
            is_support_d_type = false;
            break;
        }
    }
    closedir(dir);

    return is_support_d_type;
}

static void do_parse_mntopt(const char *opt, unsigned long *mflags, char **data)
{
    size_t i = 0;

    for (i = 0; i < sizeof(g_mount_options) / sizeof(g_mount_options[0]); i++) {
        if (strncmp(opt, g_mount_options[i].option, strlen(g_mount_options[i].option)) == 0) {
            if (g_mount_options[i].clear) {
                *mflags &= ~g_mount_options[i].flag;
            } else {
                *mflags |= g_mount_options[i].flag;
            }
            return;
        }
    }
    /* If opt is not found in g_mount_options append it to data. */
    if (strlen(*data) > 0) {
        (void)strcat(*data, ",");
    }

    (void)strcat(*data, opt);
}

int util_parse_mntopts(const char *mntopts, unsigned long *mntflags, char **mntdata)
{
    int ret = 0;
    size_t i, mlen, size_data;
    char **opts = NULL;
    char *data = NULL;

    *mntdata = NULL;
    *mntflags = 0L;

    if (mntopts == NULL) {
        return 0;
    }

    size_data = strlen(mntopts) + 1;
    data = util_common_calloc_s(size_data);
    if (data == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    *data = 0;

    opts = util_string_split(mntopts, ',');
    if (opts == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    mlen = util_array_len((const char **)opts);

    for (i = 0; i < mlen; i++) {
        do_parse_mntopt(opts[i], mntflags, &data);
    }

    if (strlen(data) > 0) {
        *mntdata = data;
        data = NULL;
    }

out:
    util_free_array(opts);
    free(data);
    return ret;
}

static char *get_mtpoint(const char *line)
{
    int i;
    const char *tmp = NULL;
    char *pend = NULL;
    char *sret = NULL;
    size_t len;

    if (line == NULL) {
        goto err_out;
    }

    tmp = line;

    for (i = 0; i < 4; i++) {
        tmp = strchr(tmp, ' ');
        if (tmp == NULL) {
            goto err_out;
        }
        tmp++;
    }
    pend = strchr(tmp, ' ');
    if ((pend == NULL) || pend == tmp) {
        goto err_out;
    }

    /* stuck a \0 after the mountpoint */
    len = (size_t)(pend - tmp);
    sret = util_common_calloc_s(len + 1);
    if (sret == NULL) {
        goto err_out;
    }
    (void)memcpy(sret, tmp, len);
    sret[len] = '\0';

err_out:
    return sret;
}

bool util_detect_mounted(const char *path)
{
    FILE *fp = NULL;
    char *line = NULL;
    char *mountpoint = NULL;
    size_t length = 0;
    bool bret = false;

    fp = util_fopen("/proc/self/mountinfo", "r");
    if (fp == NULL) {
        ERROR("Failed opening /proc/self/mountinfo");
        return false;
    }

    while (getline(&line, &length, fp) != -1) {
        mountpoint = get_mtpoint(line);
        if (mountpoint == NULL) {
            INFO("Error reading mountinfo: bad line '%s'", line);
            continue;
        }
        if (strcmp(mountpoint, path) == 0) {
            free(mountpoint);
            bret = true;
            goto out;
        }
        free(mountpoint);
    }
out:
    fclose(fp);
    free(line);
    return bret;
}

// is_remount returns true if either device name or flags identify a remount request, false otherwise.
static bool is_remount(const char *src, unsigned long mntflags)
{
    if ((mntflags & MS_REMOUNT) != 0 || strcmp(src, "") == 0 || strcmp(src, "none") == 0) {
        return true;
    }

    return false;
}

static int do_real_mount(const char *src, const char *dst, const char *mtype, unsigned long mntflags,
                         const char *mntdata)
{
    int ret = 0;
    unsigned long oflags = mntflags & (~PROPAGATION_TYPES);

    if (!is_remount(src, mntflags) || (mntdata != NULL && strcmp(mntdata, "") != 0)) {
        ret = mount(src, dst, mtype, oflags, mntdata);
        if (ret < 0) {
            ERROR("Failed to mount from %s to %s:%s", src, dst, strerror(errno));
            goto out;
        }
    }

    if ((mntflags & PROPAGATION_TYPES) != 0) {
        // Change the propagation type.
        ret = mount("", dst, "", mntflags & PROPAGATION_FLAGS, "");
        if (ret < 0) {
            ERROR("Failed to change the propagation type of dst %s:%s", dst, strerror(errno));
            goto out;
        }
    }

    if ((oflags & BRO_FLAGS) == BRO_FLAGS) {
        // Remount the bind to apply read only.
        ret = mount("", dst, "", oflags | MS_REMOUNT, "");
        if (ret < 0) {
            ERROR("Failed to remount the bind to apply read only of dst %s:%s", dst, strerror(errno));
            goto out;
        }
    }

out:
    return ret;
}

// ForceMount will mount a filesystem according to the specified configuration,
// *regardless* if the target path is not already mounted. Options must be
// specified like the mount or fstab unix commands: "opt1=val1,opt2=val2".
int util_force_mount(const char *src, const char *dst, const char *mtype, const char *mntopts)
{
    int ret = 0;
    unsigned long mntflags = 0L;
    char *mntdata = NULL;

    if (src == NULL || dst == NULL || mtype == NULL) {
        return -1;
    }

    ret = util_parse_mntopts(mntopts, &mntflags, &mntdata);
    if (ret != 0) {
        ERROR("Failed to parse mount options:%s", mntopts);
        ret = -1;
        goto out;
    }

    ret = do_real_mount(src, dst, mtype, mntflags, mntdata);
out:
    free(mntdata);
    return ret;
}

// util_mount will mount filesystem according to the specified configuration, on the
// condition that the target path is *not* already mounted. Options must be
// specified like the mount or fstab unix commands: "opt1=val1,opt2=val2".
int util_mount(const char *src, const char *dst, const char *mtype, const char *mntopts)
{
    int ret = 0;
    unsigned long mntflags = 0L;
    char *mntdata = NULL;

    if (src == NULL || dst == NULL || mtype == NULL) {
        return -1;
    }

    ret = util_parse_mntopts(mntopts, &mntflags, &mntdata);
    if (ret != 0) {
        ERROR("Failed to parse mount options:%s", mntopts);
        ret = -1;
        goto out;
    }

    if ((mntflags & MS_REMOUNT) != MS_REMOUNT) {
        if (util_detect_mounted(dst)) {
            ERROR("mount dst %s had been mounted, skip mount", dst);
            ret = 0;
            goto out;
        }
    }

    ret = util_force_mount(src, dst, mtype, mntopts);

out:
    free(mntdata);
    return ret;
}

int util_ensure_mounted_as(const char *dst, const char *mntopts)
{
    int ret = 0;
    bool mounted = false;

    if (dst == NULL || mntopts == NULL) {
        return -1;
    }

    mounted = util_detect_mounted(dst);

    if (!mounted) {
        ret = util_mount(dst, dst, "none", "bind,rw");
        if (ret != 0) {
            goto out;
        }
    }

    ret = util_force_mount("", dst, "none", mntopts);

out:
    return ret;
}

static int util_mount_from_handler(const char *src, const char *dst, const char *mtype, const char *mntopts)
{
    int ret = 0;
    unsigned long mntflags = 0L;
    char *mntdata = NULL;

    ret = util_parse_mntopts(mntopts, &mntflags, &mntdata);
    if (ret != 0) {
        ERROR("Failed to parse mount options:%s", mntopts);
        ret = -1;
        goto out;
    }

    ret = mount(src, dst, mtype, mntflags, mntdata);
    if (ret < 0) {
        ERROR("Failed to mount from %s to %s:%s", src, dst, strerror(errno));
        goto out;
    }
out:
    free(mntdata);
    return ret;
}

int util_mount_from(const char *base, const char *src, const char *dst, const char *mtype, const char *mntopts)
{
    int ret = 0;
    pid_t pid = -1;
    int keepfds[] = { -1 };

    pid = fork();
    if (pid == (pid_t) -1) {
        ERROR("Failed to fork: %s", strerror(errno));
        goto cleanup;
    }

    if (pid == (pid_t)0) {
        keepfds[0] = isula_libutils_get_log_fd();
        ret = util_check_inherited_exclude_fds(true, keepfds, 1);
        if (ret != 0) {
            ERROR("Failed to close fds.");
            ret = -1;
            goto child_out;
        }

        if (chdir(base) != 0) {
            SYSERROR("Failed to chroot to %s", base);
            ret = -1;
            goto child_out;
        }

        ret = util_mount_from_handler(src, dst, mtype, mntopts);

child_out:
        if (ret != 0) {
            exit(EXIT_FAILURE);
        } else {
            exit(EXIT_SUCCESS);
        }
    }

    ret = wait_for_pid(pid);
    if (ret != 0) {
        ERROR("Wait util_mount_from failed");
    }

cleanup:
    return ret;
}