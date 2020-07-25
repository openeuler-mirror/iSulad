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
* Author: liuhao
* Create: 2020-06-15
* Description: provide isula image rootfs handler definition
*******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_IMAGE_ROOTFS_HANDLER_H
#define DAEMON_MODULES_IMAGE_IMAGE_ROOTFS_HANDLER_H

#include <isula_libutils/defs.h>

#include "isula_libutils/oci_image_spec.h"
#include "isula_libutils/host_config.h"
#ifdef __cplusplus
extern "C" {
#endif

int get_user_from_image_roofs(const char *basefs, const host_config *hc, const char *userstr, defs_process_user *puser);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_IMAGE_IMAGE_ROOTFS_HANDLER_H
