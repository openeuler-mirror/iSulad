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

#ifndef __OCI_UT_COMMON_H
#define __OCI_UT_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include "oci_ut_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DECLARE_OCI_UT_COMMON_WRAPPER                                                   \
    extern "C" {                                                                         \
        DECLARE_WRAPPER_V(conf_get_graph_rootpath, char *, ());                              \
        DEFINE_WRAPPER_V(conf_get_graph_rootpath, char *, (), ());                           \
        \
        DECLARE_WRAPPER_V(conf_get_graph_run_path, char *, ());                              \
        DEFINE_WRAPPER_V(conf_get_graph_run_path, char *, (), ());                           \
        \
        DECLARE_WRAPPER_V(conf_get_isulad_storage_driver, char *, ());                       \
        DEFINE_WRAPPER_V(conf_get_isulad_storage_driver, char *, (), ());                    \
        \
        DECLARE_WRAPPER_V(conf_get_registry_list, char **, ());                              \
        DEFINE_WRAPPER_V(conf_get_registry_list, char **, (), ());                           \
        \
        DECLARE_WRAPPER_V(conf_get_insecure_registry_list, char **, ());                     \
        DEFINE_WRAPPER_V(conf_get_insecure_registry_list, char **, (), ());                  \
        \
        DECLARE_WRAPPER(conf_get_im_opt_timeout, unsigned int, ());                          \
        DEFINE_WRAPPER(conf_get_im_opt_timeout, unsigned int, (), ());                       \
        \
        DECLARE_WRAPPER_V(execvp, int, (const char *file, char * const argv[]));              \
        DEFINE_WRAPPER_V(execvp, int, (const char *file, char * const argv[]), (file, argv)); \
    }

#define MOCK_SET_DEFAULT_ISULAD_KIT_OPTS                                                      \
    {                                                                                         \
        MOCK_SET_V(conf_get_graph_rootpath, conf_get_graph_rootpath_success);                 \
        MOCK_SET_V(conf_get_graph_run_path, conf_get_graph_run_path_success);                 \
        MOCK_SET_V(conf_get_isulad_storage_driver, conf_get_isulad_storage_driver_success);   \
        MOCK_SET_V(conf_get_registry_list, conf_get_registry_list_success);                   \
        MOCK_SET_V(conf_get_insecure_registry_list, conf_get_insecure_registry_list_success); \
        MOCK_SET(conf_get_im_opt_timeout, 300);                                               \
    }                                                                                         \
    while (0)                                                                                 \
        ;

#define MOCK_CLEAR_DEFAULT_ISULAD_KIT_OPTS           \
    {                                                \
        MOCK_CLEAR(conf_get_graph_rootpath);         \
        MOCK_CLEAR(conf_get_graph_run_path);         \
        MOCK_CLEAR(conf_get_isulad_storage_driver);  \
        MOCK_CLEAR(conf_get_registry_list);          \
        MOCK_CLEAR(conf_get_insecure_registry_list); \
        MOCK_CLEAR(conf_get_im_opt_timeout);         \
    }                                                \
    while (0)                                        \
        ;

char *json_path(const char *file);
int execvp_success(const char *file, char * const argv[]);
char *conf_get_graph_rootpath_success();
char *conf_get_graph_run_path_success();
char *conf_get_isulad_storage_driver_success();
char **conf_get_registry_list_success();
char **conf_get_insecure_registry_list_success();
char **single_array_from_string(const char *value);

#ifdef __cplusplus
}
#endif

#endif
