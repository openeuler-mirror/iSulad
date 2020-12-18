/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide tools functions
 **********************************************************************************/
#define _GNU_SOURCE
#include "libcni_tools.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "utils.h"
#include "libcni_errno.h"
#include "isula_libutils/log.h"

static int do_check_file(const char *plugin, const char *path, char **find_path, int *save_errno)
{
    int nret = 0;
    char tmp_path[PATH_MAX] = { 0 };
    struct stat rt_stat = { 0 };

    nret = snprintf(tmp_path, PATH_MAX, "%s/%s", path, plugin);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Sprint failed");
        *save_errno = INK_ERR_SPRINT_FAILED;
        return -1;
    }
    nret = stat(tmp_path, &rt_stat);
    if (nret == 0 && S_ISREG(rt_stat.st_mode)) {
        *find_path = util_strdup_s(tmp_path);
        *save_errno = 0;
        return 0;
    } else {
        *save_errno = ENOENT;
        return -1;
    }
}

static inline bool check_find_in_path_args(const char *plugin, const char * const *paths, size_t len,
                                           char * const *find_path)
{
    return (plugin == NULL || strlen(plugin) == 0 || paths == NULL || len == 0 || find_path == NULL);
}

int find_in_path(const char *plugin, const char * const *paths, size_t len, char **find_path, int *save_errno)
{
    int ret = -1;
    size_t i = 0;

    if (check_find_in_path_args(plugin, paths, len, find_path)) {
        ERROR("Invalid arguments");
        return -1;
    }
    for (i = 0; i < len; i++) {
        if (do_check_file(plugin, paths[i], find_path, save_errno) == 0) {
            ret = 0;
            break;
        }
    }

    if (ret != 0) {
        ERROR("Can not find plugin: %s", plugin);
    }

    return ret;
}

