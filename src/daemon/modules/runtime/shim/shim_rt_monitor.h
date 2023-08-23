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
 * Author: xuxuepeng
 * Create: 2023-08-17
 * Description: shim v2 runtime monitor definition
 ******************************************************************************/

#ifndef DAEMON_MODULES_RUNTIME_SHIM_SHIM_RT_MONITOR_H
#define DAEMON_MODULES_RUNTIME_SHIM_SHIM_RT_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

// This function is used to monitor the container lifecycle in async mode.
// It is not used to monitor exec, which calls shim_v2_wait in rt_shim_exec.
int shim_rt_monitor(const char *id, const char *exit_fifo);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_RUNTIME_SHIM_SHIM_RT_MONITOR_H
