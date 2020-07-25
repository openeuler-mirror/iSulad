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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container update definition
 ******************************************************************************/
#ifndef CMD_ISULA_EXTEND_UPDATE_H
#define CMD_ISULA_EXTEND_UPDATE_H

#include <stdbool.h>
#include <stddef.h>

#include "client_arguments.h"
#include "command_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UPDATE_OPTIONS(cmdargs)                                                                                \
    { CMD_OPT_TYPE_CALLBACK, false, "cpu-shares", 0, &(cmdargs).cr.cpu_shares, "CPU shares (relative weight)", \
        command_convert_llong },                                                                                 \
    { CMD_OPT_TYPE_CALLBACK,                                                                           \
      false,                                                                                           \
      "cpu-period",                                                                                    \
      0,                                                                                               \
      &(cmdargs).cr.cpu_period,                                                                        \
      "Limit CPU CFS (Completely Fair Scheduler) period",                                              \
      command_convert_llong },                                                                         \
    { CMD_OPT_TYPE_CALLBACK,                                                                           \
      false,                                                                                           \
      "cpu-quota",                                                                                     \
      0,                                                                                               \
      &(cmdargs).cr.cpu_quota,                                                                         \
      "Limit CPU CFS (Completely Fair Scheduler) quota",                                               \
      command_convert_llong },                                                                         \
    { CMD_OPT_TYPE_STRING,                                                                             \
      false,                                                                                           \
      "cpuset-cpus",                                                                                   \
      0,                                                                                               \
      &(cmdargs).cr.cpuset_cpus,                                                                       \
      "CPUs in which to allow execution (0-3, 0,1)",                                                   \
      NULL },                                                                                          \
    { CMD_OPT_TYPE_STRING,                                                                             \
      false,                                                                                           \
      "cpuset-mems",                                                                                   \
      0,                                                                                               \
      &(cmdargs).cr.cpuset_mems,                                                                       \
      "MEMs in which to allow execution (0-3, 0,1)",                                                   \
      NULL },                                                                                          \
    { CMD_OPT_TYPE_CALLBACK,                                                                           \
      false,                                                                                           \
      "kernel-memory",                                                                                 \
      0,                                                                                               \
      &(cmdargs).cr.kernel_memory_limit,                                                               \
      "Kernel memory limit",                                                                           \
      command_convert_membytes },                                                                      \
    { CMD_OPT_TYPE_CALLBACK,   false, "memory", 'm', &(cmdargs).cr.memory_limit, "Memory limit",       \
      command_convert_membytes },                                                                      \
    { CMD_OPT_TYPE_CALLBACK,                                                                           \
      false,                                                                                           \
      "memory-reservation",                                                                            \
      0,                                                                                               \
      &(cmdargs).cr.memory_reservation,                                                                \
      "Memory soft limit",                                                                             \
      command_convert_membytes },                                                                      \
    { CMD_OPT_TYPE_CALLBACK,                                                                           \
      false,                                                                                           \
      "memory-swap",                                                                                   \
      0,                                                                                               \
      &(cmdargs).cr.memory_swap,                                                                       \
      "Swap limit equal to memory plus swap: '-1' to enable unlimited swap",                           \
      command_convert_memswapbytes },                                                                  \
    {                                                                                                          \
                                                                                                               CMD_OPT_TYPE_STRING, false, "restart", 0, &(cmdargs).restart,                                          \
                                                                                                               "Restart policy to apply when a container exits", NULL                                         \
    }

extern const char g_cmd_update_desc[];
extern const char g_cmd_update_usage[];
extern struct client_arguments g_cmd_update_args;
int cmd_update_main(int argc, const char **argv);
int update_checker(const struct client_arguments *args);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_EXTEND_UPDATE_H
