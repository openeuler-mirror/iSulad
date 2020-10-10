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
* Create: 2020-10-10
* Description: provide isula image rootfs handler definition
*******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_SPEC_MERGE_H
#define DAEMON_MODULES_IMAGE_SPEC_MERGE_H

#include "isula_libutils/container_config.h"

#ifdef __cplusplus
extern "C" {
#endif

int image_spec_merge_env(const char **env, size_t env_len, container_config *container_spec);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_IMAGE_SPEC_MERGE_H
