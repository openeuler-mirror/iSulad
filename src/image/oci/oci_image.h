/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: provide isula image operator definition
*******************************************************************************/
#ifndef __IMAGE_OCI_IMAGE_H
#define __IMAGE_OCI_IMAGE_H

#include "image.h"
#include "oci_image_spec.h"
#include "oci_common_operators.h"

#ifdef __cplusplus
extern "C" {
#endif

int oci_init(const struct service_arguments *args);
void oci_exit();

int oci_pull_rf(const im_pull_request *request, im_pull_response *response);
int oci_rmi(const im_rmi_request *request);
int oci_get_filesystem_info(im_fs_info_response **response);
int oci_load_image(const im_load_request *request);

int oci_prepare_rf(const im_prepare_request *request, char **real_rootfs);
int oci_merge_conf_rf(const char *img_name, container_config *container_spec);
int oci_mount_rf(const im_mount_request *request);
int oci_umount_rf(const im_umount_request *request);
int oci_delete_rf(const im_delete_rootfs_request *request);
int oci_export_rf(const im_export_request *request);
int oci_container_filesystem_usage(const im_container_fs_usage_request *request, imagetool_fs_info **fs_usage);
int oci_login(const im_login_request *request);
int oci_logout(const im_logout_request *request);

int oci_tag(const im_tag_request *request);
#ifdef __cplusplus
}
#endif

#endif /* __IMAGE_OCI_IMAGE_H */
