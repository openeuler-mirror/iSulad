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
 * Create: 2020-09-28
 * Description: provide generate container spec in client
 ******************************************************************************/
#ifndef CMD_ISULA_GENERATE_CONTAINER_SPEC_H
#define CMD_ISULA_GENERATE_CONTAINER_SPEC_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "isula_libutils/json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct isula_container_config {
    char **env;
    size_t env_len;

    char **label;
    size_t label_len;

    char *hostname;

    char *user;

    bool attach_stdin;

    bool attach_stdout;

    bool attach_stderr;

    bool open_stdin;

    bool tty;

    bool readonly;

    bool all_devices;

    bool system_container;
    char *ns_change_opt;

    char *entrypoint;

    char **cmd;
    size_t cmd_len;

    char *log_driver;

    json_map_string_string *annotations;

    char *workdir;

    char *health_cmd;

    int64_t health_interval;

    int health_retries;

    int64_t health_timeout;

    int64_t health_start_period;

    bool no_healthcheck;

    bool exit_on_unhealthy;

} isula_container_config_t;

int generate_container_config(const isula_container_config_t *custom_conf, char **container_config_str);

void isula_container_config_free(isula_container_config_t *config);
#ifdef __cplusplus
}
#endif

#endif
