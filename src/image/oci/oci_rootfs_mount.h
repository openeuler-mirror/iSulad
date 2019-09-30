/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: 李峰
 * Create: 2018-11-08
 * Description: provide oci mount rootfs functions
 ******************************************************************************/

#ifndef __OCI_MOUNT_ROOTFS_H_
#define __OCI_MOUNT_ROOTFS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *name_id;
} rootfs_mount_request;

typedef struct {
    char *errmsg;
} rootfs_mount_response;

int mount_rootfs(rootfs_mount_request *request,
                 rootfs_mount_response **response);

void free_rootfs_mount_request(rootfs_mount_request *ptr);

void free_rootfs_mount_response(rootfs_mount_response *ptr);

#ifdef __cplusplus
}
#endif

#endif
