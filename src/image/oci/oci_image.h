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
 * Description: provide image function definition
 ******************************************************************************/
#ifndef __OCI_IMAGE_H
#define __OCI_IMAGE_H

#include <stdint.h>
#include "image.h"
#include "oci_image_spec.h"
#include "oci_image_status.h"

#ifdef __cplusplus
extern "C" {
#endif

bool oci_detect(const char *image_name);
int oci_filesystem_usage(struct bim *bim, imagetool_fs_info **fs_usage);

int oci_prepare_rf(struct bim *bim, const json_map_string_string *storage_opt, char **real_rootfs);
int oci_mount_rf(struct bim *bim);
int oci_umount_rf(struct bim *bim);
int oci_delete_rf(struct bim *bim);
char *oci_resolve_image_name(const char *name);
char *oci_normalize_image_name(const char *name);

int oci_merge_conf(oci_runtime_spec *oci_spec, const host_config *host_spec, container_custom_config *custom_spec,
                   struct bim *bim, char **real_rootfs);
int oci_get_user_conf(const char *basefs, host_config *hc, const char *userstr, oci_runtime_spec_process_user *puser);
int oci_list_images(im_list_request *request, imagetool_images_list **images);
int oci_remove_image(im_remove_request *request);
int oci_status_image(oci_image_status_request *request, oci_image_status_response **response);
int oci_inspect_image(struct bim *bim, char **inspected_json);
int oci_pull_image(const im_pull_request *request, im_pull_response **response);

int oci_init(const char *rootpath);


#ifdef __cplusplus
}
#endif

#endif
