/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide specs definition
 ******************************************************************************/
#ifndef __SPECS_H__
#define __SPECS_H__

#include <stdint.h>
#include "libisulad.h"
#include "host_config.h"
#include "container_custom_config.h"
#include "container_config_v2.h"
#include "oci_runtime_hooks.h"
#include "oci_runtime_spec.h"

oci_runtime_spec *merge_container_config(const char *id, const char *image_type, const char *image_name,
                                         const char *ext_image_name, host_config *host_spec,
                                         container_custom_config *custom_spec,
                                         container_config_v2_common_config *v2_spec, char **real_rootfs);
int merge_global_config(oci_runtime_spec *oci_spec);
oci_runtime_spec *read_oci_config(const char *rootpath, const char *name);

#endif

