/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2019-04-06
 * Description: provide oci export rootfs functions
 ******************************************************************************/

#ifndef __OCI_EXPORT_ROOTFS_H_
#define __OCI_EXPORT_ROOTFS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *file;
    char *id;
} rootfs_export_request;

typedef struct {
    char *errmsg;
} rootfs_export_response;

int export_rootfs(rootfs_export_request *request,
                  rootfs_export_response **response);

void free_rootfs_export_request(rootfs_export_request *ptr);

void free_rootfs_export_response(rootfs_export_response *ptr);

#ifdef __cplusplus
}
#endif

#endif
