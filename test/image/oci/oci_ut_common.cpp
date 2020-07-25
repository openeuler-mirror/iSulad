/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: oci_rootfs_remove unit test
 * Author: wangfengtu
 * Create: 2019-08-29
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include "utils.h"
#include "oci_ut_common.h"

int execvp_success(const char *file, char * const argv[])
{
    execlp("echo", "echo");
    return -1;
}

char **single_array_from_string(const char *value)
{
    char **arr = NULL;
    int ret = 0;

    ret = util_array_append(&arr, value);
    if (ret != 0) {
        util_free_array(arr);
        return NULL;
    }

    return arr;
}

char *conf_get_graph_rootpath_success()
{
    return util_strdup_s("/var/lib/isulad/storage");
}

char *conf_get_graph_run_path_success()
{
    return util_strdup_s("/var/run/isulad/storage");
}

char *conf_get_isulad_storage_driver_success()
{
    return util_strdup_s("overlay");
}

char **conf_get_registry_list_success()
{
    return single_array_from_string("docker.io");
}

char **conf_get_insecure_registry_list_success()
{
    return single_array_from_string("isulad");
}

char *json_path(const char *file)
{
    char base_path[PATH_MAX] = { 0 };
    char *json_file = NULL;

    if (getcwd(base_path, PATH_MAX) == NULL) {
        return NULL;
    }

    json_file = util_path_join(base_path, file);
    if (json_file == NULL) {
        return NULL;
    }

    return json_file;
}
