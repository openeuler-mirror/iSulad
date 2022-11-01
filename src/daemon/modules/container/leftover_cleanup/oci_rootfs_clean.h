/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2022-10-31
 * Description: provide rootfs cleaner definition
 *********************************************************************************/
#ifndef DAEMON_MODULES_CONTAINER_ROOTFS_CLEAN_H
#define DAEMON_MODULES_CONTAINER_ROOTFS_CLEAN_H

#include "cleanup.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

int oci_rootfs_cleaner(void);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif