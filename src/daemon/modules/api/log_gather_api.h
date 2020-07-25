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
 * Description: provide log gather definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_API_LOG_GATHER_API_H
#define DAEMON_MODULES_API_LOG_GATHER_API_H

#include "utils.h"
#include "isula_libutils/log.h"

#define LOG_FIFO_SIZE (1024 * 1024)

#define REV_BUF_SIZE 4096

struct log_gather_conf {
    const char *fifo_path;
    int *exitcode;
    const char *g_log_driver;
    const char *log_path;
    unsigned int log_file_mode;
    int64_t max_size;
    int max_file;
};

enum log_gather_driver {
    LOG_GATHER_DRIVER_STDOUT,
    LOG_GATHER_DRIVER_FILE,
    LOG_GATHER_DRIVER_NOSET
};

void *log_gather(void *arg);

#endif

