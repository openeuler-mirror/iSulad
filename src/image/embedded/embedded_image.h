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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Explanation: provide image function definition
 ******************************************************************************/
#ifndef __EMBEDDED_IMAGE_H
#define __EMBEDDED_IMAGE_H

#include <stdint.h>
#include "image.h"

bool embedded_detect(const char *image_name);

int embedded_prepare_rf(struct bim *bim, const json_map_string_string *storage_opt, char **real_rootfs);

int embedded_filesystem_usage(struct bim *bim, imagetool_fs_info **fs_usage);

int embedded_mount_rf(struct bim *bim);

int embedded_umount_rf(struct bim *bim);

int embedded_delete_rf(struct bim *bim);

char *embedded_resolve_image_name(const char *image_name);

int embedded_merge_conf(oci_runtime_spec *oci_spec, const host_config *host_spec, container_custom_config *custom_spec,
                        struct bim *bim, char **real_rootfs);

int embedded_get_user_conf(const char *basefs, host_config *hc, const char *userstr,
                           oci_runtime_spec_process_user *puser);

int embedded_list_images(im_list_request *request,
                         imagetool_images_list **list);

int embedded_remove_image(im_remove_request *request);

int embedded_inspect_image(struct bim *bim, char **inspected_json);

int embedded_load_image(im_load_request *request);

int embedded_init(const char *rootpath);

#endif
