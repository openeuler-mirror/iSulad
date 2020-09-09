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
 * Description: provide cni args function definition
 *********************************************************************************/

#ifndef CLIBCNI_INVOKE_ARGS_H
#define CLIBCNI_INVOKE_ARGS_H

#include <stddef.h>

#define CNI_ENVS_LEN 6
#define ENV_CNI_COMMAND "CNI_COMMAND"
#define ENV_CNI_CONTAINERID "CNI_CONTAINERID"
#define ENV_CNI_NETNS "CNI_NETNS"
#define ENV_CNI_ARGS "CNI_ARGS"
#define ENV_CNI_IFNAME "CNI_IFNAME"
#define ENV_CNI_PATH "CNI_PATH"

struct cni_args {
    char *command;
    char *container_id;
    char *netns;
    char *(*plugin_args)[2];
    size_t plugin_args_len;
    char *plugin_args_str;
    char *ifname;
    char *path;
};

char **as_env(const struct cni_args *cniargs);

void free_cni_args(struct cni_args *cargs);

#endif
