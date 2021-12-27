/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2021-03-09
 * Description: provide network namespace functions
 ******************************************************************************/
#define _GNU_SOURCE

#include "network_namespace.h"

#include <unistd.h>
#include <sys/mount.h>
#include <sched.h>
#include <pthread.h>
#include <isula_libutils/log.h>

#include "utils.h"
#include "utils_network.h"
#include "utils_fs.h"
#include "path.h"

struct mount_netns {
    int pid;
    bool use_proc_ns;
    const char *netns_path;
};

static void *mount_netns(void *mnt_netns)
{
    int nret = 0;
    int *ecode = (int *)malloc(sizeof(int));
    char fullpath[PATH_MAX] = { 0 };

    bool use_proc_ns = ((struct mount_netns *)mnt_netns)->use_proc_ns;
    int pid = ((struct mount_netns *)mnt_netns)->pid;
    const char *netns_path = ((struct mount_netns *)mnt_netns)->netns_path;

    if (use_proc_ns) {
        // use process network namespace when isolate container with a user namespace
        if (pid == 0) {
            ERROR("Invalid pid");
            goto err_out;
        }

        nret = snprintf(fullpath, sizeof(fullpath), "/proc/%d/ns/net", pid);
        if (nret < 0 || (size_t)nret >= sizeof(fullpath)) {
            ERROR("Snprint nspath failed");
            goto err_out;
        }
    } else {
        if (unshare(CLONE_NEWNET) != 0) {
            ERROR("Failed to unshare");
            goto err_out;
        }

        nret = snprintf(fullpath, sizeof(fullpath), "/proc/%d/task/%ld/ns/net", getpid(), (long int)syscall(__NR_gettid));
        if (nret < 0 || (size_t)nret >= sizeof(fullpath)) {
            ERROR("Failed to get full path");
            goto err_out;
        }
    }

    if (util_mount(fullpath, netns_path, "none", "bind") != 0) {
        ERROR("Failed to mount %s to %s", fullpath, netns_path);
        goto err_out;
    }

    *ecode = EXIT_SUCCESS;
    pthread_exit((void *)ecode);

err_out:
    *ecode = EXIT_FAILURE;
    pthread_exit((void *)ecode);
}

// this function mounts netns path to /proc/%d/task/%d/ns/net
static int mount_network_namespace(const struct mount_netns *mnt_netns)
{
    pthread_t newns_thread = 0;
    int ret = 0;
    void *status = NULL;

    ret = pthread_create(&newns_thread, NULL, (void *)&mount_netns, (void *)mnt_netns);
    if (ret != 0) {
        ERROR("Failed to create thread");
        return -1;
    }

    ret = pthread_join(newns_thread, &status);
    if (ret != 0) {
        ERROR("Failed to join thread");
        ret = -1;
        goto out;
    }

    if (status == NULL) {
        ERROR("Failed set exit status");
        return -1;
    }

    if (*(int *)status != 0) {
        ERROR("Failed to initialize network namespace, status code is %d", *(int *)status);
        ret = -1;
    } else {
        ret = 0;
    }

out:
    free(status);
    return ret;
}

static int umount_network_namespace(const char *netns_path)
{
    int i;

    for (i = 0; i < 50; i++) {
        if (umount2(netns_path, MNT_DETACH) < 0) {
            switch (errno) {
                case EBUSY:
                    usleep(50);
                    continue;
                case EINVAL:
                    return 0;
                default:
                    continue;
            }
        }
    }
    ERROR("Failed to umount target %s", netns_path);
    return -1;
}

int prepare_network_namespace(const char *netns_path, const bool post_setup_network, const int pid)
{
    struct mount_netns mnt_netns;

    if (netns_path == NULL) {
        ERROR("Invalid network namespace path");
        return -1;
    }

    if (!util_file_exists(netns_path) && create_network_namespace_file(netns_path) != 0) {
        ERROR("Failed to prepare network namespace file");
        return -1;
    }

    mnt_netns.netns_path = netns_path;
    mnt_netns.use_proc_ns = post_setup_network;
    mnt_netns.pid = pid;
    if (mount_network_namespace(&mnt_netns) != 0) {
        ERROR("Failed to mount network namespace");
        return -1;
    }

    return 0;
}

int remove_network_namespace(const char *netns_path)
{
    if (netns_path == NULL) {
        ERROR("Invalid network namespace path");
        return -1;
    }

    if (!util_file_exists(netns_path)) {
        WARN("Namespace file does not exist");
        return 0;
    }

    if (umount_network_namespace(netns_path) != 0) {
        ERROR("Failed to umount directory %s:%s", netns_path, strerror(errno));
        return -1;
    }

    return 0;
}

int create_network_namespace_file(const char *netns_path)
{
    int ret = 0;
    int fd = -1;
    char *netns_dir = NULL;

    if (netns_path == NULL) {
        ERROR("Invalid netns path");
        return -1;
    }

    if (util_file_exists(netns_path)) {
        ERROR("Namespace file %s exists", netns_path);
        return -1;
    }
    netns_dir = util_path_dir(netns_path);
    if (netns_dir == NULL) {
        ERROR("Failed to get path dir for %s", netns_path);
        return -1;
    }
    if (!util_dir_exists(netns_dir) && util_mkdir_p(netns_dir, DEFAULT_HIGHEST_DIRECTORY_MODE) != 0) {
        ERROR("Failed to create directory for %s", netns_path);
        ret = -1;
        goto out;
    }

    fd = util_open(netns_path, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_SECURE_FILE_MODE);
    if (fd < 0) {
        ERROR("Failed to create namespace file: %s", netns_path);
        ret = -1;
        goto out;
    }
    close(fd);

out:
    free(netns_dir);
    return ret;
}

int remove_network_namespace_file(const char *netns_path)
{
    int get_err = 0;

    if (netns_path == NULL) {
        ERROR("Invalid netns path");
        return -1;
    }

    if (!util_force_remove_file(netns_path, &get_err)) {
        ERROR("Failed to remove file %s, error: %s", netns_path, strerror(get_err));
        return -1;
    }

    return 0;
}
