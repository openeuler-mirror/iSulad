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
 * Author: wangfengtu
 * Create: 2020-11-04
 * Description: provide parse volume definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_SPEC_PARSE_VOLUME_H
#define DAEMON_MODULES_SPEC_PARSE_VOLUME_H

#include "isula_libutils/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DefaultMountType "volume"

defs_mount *parse_volume(const char *volume);
int append_default_mount_options(defs_mount *m, bool has_ro, bool has_pro, bool has_sel);

#ifdef __cplusplus
}
#endif

#endif
