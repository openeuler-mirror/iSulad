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
#ifndef DAEMON_MODULES_SPEC_SPECS_EXTEND_H
#define DAEMON_MODULES_SPEC_SPECS_EXTEND_H

#include <stdint.h>
#include <isula_libutils/defs.h>
#include <stddef.h>

#include "err_msg.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config_v2.h"
#include "isula_libutils/oci_runtime_hooks.h"
#include "isula_libutils/oci_runtime_spec.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

int make_sure_oci_spec_linux(oci_runtime_spec *oci_spec);

int make_sure_oci_spec_process(oci_runtime_spec *oci_spec);

int make_sure_oci_spec_linux_resources(oci_runtime_spec *oci_spec);

int make_sure_oci_spec_linux_resources_blkio(oci_runtime_spec *oci_spec);

int merge_hooks(oci_runtime_spec_hooks *dest, oci_runtime_spec_hooks *src);

int merge_global_hook(oci_runtime_spec *oci_spec);

int merge_global_ulimit(oci_runtime_spec *oci_spec);

int merge_ulimits_pre(oci_runtime_spec *oci_spec, size_t host_ulimits_len);

int trans_ulimit_to_rlimit(defs_process_rlimits_element **rlimit_dst, const host_config_ulimits_element *ulimit);

int make_userns_remap(oci_runtime_spec *container, const char *user_remap);

int merge_env(oci_runtime_spec *oci_spec, const char **env, size_t env_len);

int merge_env_target_file(oci_runtime_spec *oci_spec, const char *env_target_file);

char *oci_container_get_env(const oci_runtime_spec *oci_spec, const char *key);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
