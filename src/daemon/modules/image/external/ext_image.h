/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Explanation: provide image function definition
 ******************************************************************************/
#ifndef __EXT_IMAGE_H
#define __EXT_IMAGE_H

#include <stdint.h>
#include "image_api.h"

bool ext_detect(const char *image_name);
int ext_filesystem_usage(const im_container_fs_usage_request *request, imagetool_fs_info **fs_usage);

int ext_prepare_rf(const im_prepare_request *request, char **real_rootfs);
int ext_mount_rf(const im_mount_request *request);
int ext_umount_rf(const im_umount_request *request);
int ext_delete_rf(const im_delete_rootfs_request *request);
char *ext_resolve_image_name(const char *image_name);

int ext_merge_conf(const char *img_name, container_config *container_spec);
int ext_get_user_conf(const char *basefs, host_config *hc, const char *userstr, defs_process_user *puser);
int ext_list_images(const im_list_request *request, imagetool_images_list **list);
int ext_remove_image(const im_rmi_request *request);
int ext_inspect_image(const im_inspect_request *request, char **inspected_json);
int ext_load_image(const im_load_request *request);
int ext_login(const im_login_request *request);
int ext_logout(const im_logout_request *request);

int ext_init(const isulad_daemon_configs *args);

#endif
