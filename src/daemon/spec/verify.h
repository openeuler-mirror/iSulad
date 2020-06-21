/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container verify definition
 ******************************************************************************/
#ifndef __VERIFY_H
#define __VERIFY_H

#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config.h"

#ifdef __cplusplus
extern "C" {
#endif

int verify_container_settings(const oci_runtime_spec *container);

int verify_oci_hook(const oci_runtime_spec_hooks *h);

int verify_container_settings_start(const oci_runtime_spec *oci_spec);

int verify_host_config_settings(host_config *hostconfig, bool update);

int verify_health_check_parameter(const container_config *container_spec);

#ifdef __cplusplus
}
#endif

#endif /* __VERIFY_H */

