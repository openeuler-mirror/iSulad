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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide imtool interface
 ******************************************************************************/

#ifndef __ISULA_IMTOOL_INTERFACE_H_
#define __ISULA_IMTOOL_INTERFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

void execute_pull_image(void *args);

void execute_status_image(void *args);

void execute_remove_image(void *args);

void execute_list_images(void *args);

void execute_fs_info(void *args);

void execute_prepare_rootfs(void *args);

void execute_mount_rootfs(void *args);

void execute_umount_rootfs(void *args);

void execute_remove_rootfs(void *args);

void execute_storage_status(void *args);

void execute_container_fs_info(void *args);

void execute_export_rootfs(void *args);

void execute_load_image(void *args);

void execute_login(void *args);

void execute_logout(void *args);


#ifdef __cplusplus
}
#endif

#endif
