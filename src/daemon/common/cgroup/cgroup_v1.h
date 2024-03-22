/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2024-02-19
 * Description: provide cgroup v1 definition
 ******************************************************************************/
#ifndef DAEMON_COMMON_CGROUP_CGROUP_V1_H
#define DAEMON_COMMON_CGROUP_CGROUP_V1_H

#include "cgroup.h"

#ifdef __cplusplus
extern "C" {
#endif

int cgroup_v1_ops_init(cgroup_ops *ops);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_COMMON_CGROUP_CGROUP_V1_H
