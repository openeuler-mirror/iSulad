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
 * Author: zhangxiaoyu
 * Create: 2021-03-09
 * Description: provide network namespace functions
 ******************************************************************************/
#define _GNU_SOURCE

#include "network_namespace_api.h"

#include <unistd.h>
#include <sys/mount.h>
#include <sched.h>
#include <isula_libutils/log.h>

#include "utils.h"
#include "utils_network.h"
#include "utils_fs.h"
#include "err_msg.h"
#include "path.h"

#define RUN_DIR_MODE 0755

static int prepare_network_namespace_file(const char *netns_path)
{
    int ret = 0;
    int fd = -1;
    char *netns_dir = NULL;

    if (util_file_exists(netns_path)) {
        WARN("network namespace file %s exists", netns_path);
        return 0;
    }

    netns_dir = util_path_dir(netns_path);
    if (netns_dir == NULL) {
        ERROR("Failed to get path dir for %s", netns_path);
        return -1;
    }

    if (!util_dir_exists(netns_dir) && util_mkdir_p(netns_dir, RUN_DIR_MODE) != 0) {
        ERROR("Failed to create directory for %s", netns_path);
        ret = -1;
        goto out;
    }

    fd = util_open(netns_path, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_SECURE_FILE_MODE);
    if (fd < 0) {
        ERROR("Failed to create netns file: %s", netns_path);
        ret = -1;
        goto out;
    }
    close(fd);

out:
    free(netns_dir);
    return ret;
}

static int new_network_namespace(const char *netns_path)
{
    pid_t child_pid = -1;

    child_pid = fork();
    if (child_pid == (pid_t) -1) {
        ERROR("Failed to clone child process");
        return -1;
    }

    // child
    if (child_pid == (pid_t)0) {
        if (unshare(CLONE_NEWNET) != 0) {
            exit(EXIT_FAILURE);
        }

        if (util_mount("/proc/self/ns/net", netns_path, "none", "bind") != 0) {
            exit(EXIT_FAILURE);
        }

        exit(0);
    }

    if (util_wait_for_pid(child_pid) != 0) {
        ERROR("Failed to wait pid %lu", (unsigned long)child_pid);
        return -1;
    }

    return 0;
}

// use process network namespace when isolate container with a user namespace
static int use_process_network_namespace(const int pid, const char *netns_path)
{
    int nret = 0;
    char fullpath[PATH_MAX] = { 0 };
    const char *netns_fmt = "/proc/%d/ns/net";

    if (pid == 0) {
        ERROR("Invalid pid");
        return -1;
    }

    nret = snprintf(fullpath, sizeof(fullpath), netns_fmt, pid);
    if ((size_t)nret >= sizeof(fullpath) || nret < 0) {
        ERROR("Snprint nspath failed");
        return -1;
    }

    if (util_mount(fullpath, netns_path, "none", "bind") != 0) {
        ERROR("Failed to mount %s to %s", fullpath, netns_path);
        return -1;
    }

    return 0;
}

int prepare_network_namespace(const bool post_prepare_network, const int pid, const char *netns_path)
{
    int get_err = 0;

    if (netns_path == NULL) {
        ERROR("Invalid netns_path");
        return -1;
    }

    if (prepare_network_namespace_file(netns_path) != 0) {
        ERROR("Failed to prepare network namespace file");
        return -1;
    }

    if (post_prepare_network) {
        if (use_process_network_namespace(pid, netns_path) != 0) {
            ERROR("Failed to user process network namespace");
            goto err_out;
        }

        return 0;
    }

    if (new_network_namespace(netns_path) != 0) {
        ERROR("Failed to new network namespace");
        goto err_out;
    }

    return 0;

err_out:
    if (!util_remove_file(netns_path, &get_err)) {
        ERROR("Failed to remove file %s, error: %s", netns_path, strerror(get_err));
    }

    return -1;
}

int remove_net_namspace(const char *netns_path)
{
    int get_err = 0;

    if (netns_path == NULL) {
        ERROR("Invalid netns_path");
        return -1;
    }

    if (!util_file_exists(netns_path)) {
        return 0;
    }

    if (umount2(netns_path, MNT_DETACH) != 0 && errno != EINVAL) {
        ERROR("Failed to umount directory %s:%s", netns_path, strerror(errno));
        return -1;
    }

    if (!util_remove_file(netns_path, &get_err)) {
        ERROR("Failed to remove file %s, error: %s", netns_path, strerror(get_err));
        return -1;
    }

    return 0;
}

char *get_netns_path(const char *sandbox_key, const bool attach)
{
    char real_path[PATH_MAX] = { 0 };

    if (sandbox_key == NULL) {
        ERROR("Invalid sandbox_key");
        return NULL;
    }

    if (attach) {
        return util_strdup_s(sandbox_key);
    }

    if (realpath(sandbox_key, real_path) == NULL) {
        WARN("Failed to get %s realpath", sandbox_key);
        return util_strdup_s("");
    }

    if (util_detect_mounted(real_path)) {
        return util_strdup_s(sandbox_key);
    }

    return util_strdup_s("");
}
