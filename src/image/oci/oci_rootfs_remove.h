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
 * Description: provide oci remove rootfs functions
 ******************************************************************************/

#ifndef __OCI_REMOVE_ROOTFS_H_
#define __OCI_REMOVE_ROOTFS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *name_id;
} rootfs_remove_request;

typedef struct {
    char *errmsg;
} rootfs_remove_response;

int remove_rootfs(rootfs_remove_request *request,
                  rootfs_remove_response **response);

void free_rootfs_remove_request(rootfs_remove_request *ptr);

void free_rootfs_remove_response(rootfs_remove_response *ptr);

#ifdef __cplusplus
}
#endif

#endif
