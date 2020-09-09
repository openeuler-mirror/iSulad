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
 * Description: provide some tool function definition
 *********************************************************************************/
#ifndef CLIBCNI_INVOKE_TOOLS_H
#define CLIBCNI_INVOKE_TOOLS_H

#include "isula_libutils/cni_exec_error.h"

#ifdef __cplusplus
extern "C" {
#endif

int find_in_path(const char *plugin, const char * const *paths, size_t len, char **find_path, int *save_errno);

#ifdef __cplusplus
}
#endif
#endif
