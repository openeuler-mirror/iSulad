/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: leizhongkai
 * Create: 2020-1-20
 * Description: common definition of isulad-shim
 ******************************************************************************/

#ifndef __COMMON_H_
#define __COMMON_H_

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// error code
#define SHIM_ERR_BASE (-10000)
#define SHIM_SYS_ERR(err) (SHIM_ERR_BASE-err)
#define SHIM_OK    0
#define SHIM_ERR  -1
#define SHIM_ERR_WAIT -2
#define SHIM_ERR_NOT_REQUIRED -3

#define INFO_MSG "info"
#define WARN_MSG "warn"
#define ERR_MSG "error"

#define DEFAULT_TIMEOUT   120 // sec
#define CONTAINER_ID_LEN  64
#define MAX_RT_NAME_LEN   64
#define MAX_CONSOLE_SOCK_LEN 32

#define MAX_RUNTIME_ARGS 20

#define SHIM_BINARY "isulad-shim"
#define SHIM_LOG_NAME "shim-log.json"

#define CONTAINER_ACTION_REBOOT 129
#define CONTAINER_ACTION_SHUTDOWN 130

ssize_t read_nointr(int fd, void *buf, size_t count);
ssize_t write_nointr(int fd, const void *buf, size_t count);

char *read_text_file(const char *path);

bool file_exists(const char *f);

int cmd_combined_output(const char *binary, const char *params[], void *output, int *output_len);

void write_message(int fd, const char *level, const char *fmt, ...);

int generate_random_str(char *id, size_t len);

void close_fd(int *pfd);

int open_no_inherit(const char *path, int flag, mode_t mode);

#ifdef __cplusplus
}
#endif

#endif

