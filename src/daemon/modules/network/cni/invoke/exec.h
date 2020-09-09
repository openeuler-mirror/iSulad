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
 * Description: provide exec function definition
 ********************************************************************************/

#ifndef CLIBCNI_INVOKE_EXEC_H
#define CLIBCNI_INVOKE_EXEC_H

#include "args.h"
#include "types.h"
#include "version.h"
#include "isula_libutils/cni_exec_error.h"

#ifdef __cplusplus
extern "C" {
#endif

int exec_plugin_with_result(const char *plugin_path, const char *cni_net_conf_json, const struct cni_args *cniargs,
                            struct result **ret, char **err);

int exec_plugin_without_result(const char *plugin_path, const char *cni_net_conf_json, const struct cni_args *cniargs,
                               char **err);

int raw_get_version_info(const char *plugin_path, struct plugin_info **result, char **err);

#ifdef __cplusplus
}
#endif
#endif
