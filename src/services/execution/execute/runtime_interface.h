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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container list callback function definition
 *******************************************************************************/

#ifndef __EXECUTION_RUNTIME_INTERFACE_H_
#define __EXECUTION_RUNTIME_INTERFACE_H_

#include "engine.h"
#include "oci_runtime_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

int runtime_rm(const char *name, const char *runtime, const char *rootpath);
int runtime_clean_resource(const char *name, const char *runtime, const char *rootpath,
                           const char *engine_log_path, const char *loglevel, pid_t pid);
int runtime_restart(const char *name, const char *runtime, const char *rootpath);

int runtime_start(const char *name, const char *runtime, const char *rootpath, bool tty, bool interactive,
                  const char *engine_log_path, const char *loglevel, const char *console_fifos[],
                  const char *share_ns[], unsigned int start_timeout, const char *pidfile, const char *exit_fifo,
                  const oci_runtime_spec_process_user *puser);
int runtime_create(const char *name, const char *runtime, const char *rootfs, void *oci_config_data);
int runtime_get_console_config(const char *name, const char *runtime, const char *rootpath,
                               struct engine_console_config *config);

#ifdef __cplusplus
}
#endif

#endif
