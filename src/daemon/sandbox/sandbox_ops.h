/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jikai
 * Create: 2023-08-09
 * Description: provide sandbox api definition
 ******************************************************************************/

#ifndef DAEMON_SANDBOX_SANDBOX_OPS_H
#define DAEMON_SANDBOX_SANDBOX_OPS_H

#include <isula_libutils/container_config_v2.h>
#include <isula_libutils/defs_process.h>
#include <isula_libutils/oci_runtime_spec.h>

#ifdef __cplusplus
extern "C" {
#endif

int sandbox_prepare_container(const container_config_v2_common_config *config,
                              const oci_runtime_spec *oci_spec,
                              const char *console_fifos[], bool tty);

int sandbox_prepare_exec(const container_config_v2_common_config *config,
                         const char *exec_id, defs_process *process_spec,
                         const char *console_fifos[], bool tty);

int sandbox_purge_container(const container_config_v2_common_config *config);

int sandbox_purge_exec(const container_config_v2_common_config *config, const char *exec_id);

int sandbox_on_sandbox_exit(const char *sandbox_id, int exit_code);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_API_SANDBOX_API_H
