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
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide specs definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_API_SPECS_API_H
#define DAEMON_MODULES_API_SPECS_API_H

#include <stdint.h>
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config_v2.h"
#include "isula_libutils/oci_runtime_hooks.h"
#include "isula_libutils/oci_runtime_spec.h"
#include <isula_libutils/container_network_settings.h>

#ifdef __cplusplus
extern "C" {
#endif

int merge_all_specs(host_config *host_spec, const char *real_rootfs, container_config_v2_common_config *v2_spec,
                    oci_runtime_spec *oci_spec);
int merge_oci_cgroups_path(const char *id, oci_runtime_spec *oci_spec, const host_config *host_spec);
int merge_global_config(oci_runtime_spec *oci_spec);
oci_runtime_spec *load_oci_config(const char *rootpath, const char *name);
oci_runtime_spec *default_spec(bool system_container);
int merge_conf_cgroup(oci_runtime_spec *oci_spec, const host_config *host_spec);
int save_oci_config(const char *id, const char *rootpath, const oci_runtime_spec *oci_spec);

int parse_security_opt(const host_config *host_spec, bool *no_new_privileges, char ***label_opts,
                       size_t *label_opts_len, char **seccomp_profile);

int merge_share_namespace(oci_runtime_spec *oci_spec, const host_config *host_spec,
                          const container_network_settings *network_settings);
#ifdef __cplusplus
}
#endif

#endif
