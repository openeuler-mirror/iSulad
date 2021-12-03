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
 * Author: chengzeruizhi
 * Create: 2021-11-17
 * Description: provide common network functions
 ********************************************************************************/

#define _GNU_SOURCE

#include "utils_network.h"

#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/mount.h>
#include <linux/fs.h>
#include <syscall.h>
#include <isula_libutils/log.h>
#include <fcntl.h>

#include "utils_fs.h"
#include "utils_file.h"
#include "constants.h"

int util_create_netns_file(const char *netns_path)
{
    int ret = 0;
    int fd = -1;
    char *netns_dir = NULL;

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

static void* mount_netns(void *netns_path)
{
    int *ecode = (int *)malloc(sizeof(int));
    char fullpath[PATH_MAX] = { 0x00 };
    int ret = 0;

    if (unshare(CLONE_NEWNET) != 0) {
        ERROR("Failed to unshare");
        goto err_out;
    }

    ret = snprintf(fullpath, sizeof(fullpath), "/proc/%d/task/%ld/ns/net", getpid(), (long int)syscall(__NR_gettid));
    if (ret < 0 || (size_t)ret >= sizeof(fullpath)) {
        ERROR("Failed to get full path");
        goto err_out;
    }

    if (util_mount(fullpath, (char *)netns_path, "none", "bind") != 0) {
        ERROR("Failed to mount %s", fullpath);
        goto err_out;
    }

    *ecode = EXIT_SUCCESS;
    pthread_exit((void *)ecode);

err_out:
    *ecode = EXIT_FAILURE;
    pthread_exit((void *)ecode);
}

// this function mounts netns path to /proc/%d/task/%d/ns/net
int util_mount_namespace(const char *netns_path)
{
    pthread_t newns_thread = 0;
    int ret = 0;
    void *status = NULL;

    ret = pthread_create(&newns_thread, NULL, (void *)&mount_netns, (void *)netns_path);
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

int util_umount_namespace(const char *netns_path)
{
    int i = 0;
    if (netns_path == NULL) {
        WARN("Invalid path to umount");
    }

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
