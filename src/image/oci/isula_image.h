/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: provide isula image operator definition
*******************************************************************************/
#ifndef __IMAGE_ISULA_IMAGE_H
#define __IMAGE_ISULA_IMAGE_H

#include "image.h"
#include "isula_libutils/oci_image_spec.h"
#include "oci_common_operators.h"

#ifdef __cplusplus
extern "C" {
#endif

int isula_init(const struct im_configs *conf);

int isula_pull_rf(const im_pull_request *request, im_pull_response **response);
int isula_rmi(const im_remove_request *request);
int isula_tag(const im_tag_request *request);
int isula_get_filesystem_info(im_fs_info_response **response);
int isual_load_image(const im_load_request *request);
int isula_import(const im_import_request *request, char **id);

int isula_prepare_rf(const im_prepare_request *request, char **real_rootfs);
int isula_merge_conf_rf(const host_config *host_spec, container_config *container_spec,
                        const im_prepare_request *request, char **real_rootfs);
int isula_mount_rf(const im_mount_request *request);
int isula_umount_rf(const im_umount_request *request);
int isula_delete_rf(const im_delete_request *request);
int isula_export_rf(const im_export_request *request);
int isula_container_filesystem_usage(const im_container_fs_usage_request *request, imagetool_fs_info **fs_usage);

int isula_get_storage_status(im_storage_status_response **response);
int isula_get_storage_metadata(char *id, im_storage_metadata_response **response);

int isula_login(const im_login_request *request);
int isula_logout(const im_logout_request *request);

int isula_health_check(void);

int isula_sync_images(void);

int isula_sync_containers(void);
#ifdef __cplusplus
}
#endif

#endif /* __IMAGE_ISULA_IMAGE_H */
