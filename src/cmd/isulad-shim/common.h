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

#ifndef CMD_ISULAD_SHIM_COMMON_H
#define CMD_ISULAD_SHIM_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>
#include <isula_libutils/utils.h>
#include <isula_libutils/utils_linked_list.h>

#ifdef __cplusplus
extern "C" {
#endif

// error code
#define SHIM_ERR_BASE (-10000)
#define SHIM_SYS_ERR(err) (SHIM_ERR_BASE - err)
#define SHIM_OK 0
#define SHIM_ERR (-1)
#define SHIM_ERR_WAIT (-2)
#define SHIM_ERR_NOT_REQUIRED (-3)
#define SHIM_ERR_TIMEOUT (-4)

#define INFO_MSG "info"
#define WARN_MSG "warn"
#define ERR_MSG "error"

#define DEFAULT_TIMEOUT 120 // sec
#define CONTAINER_ID_LEN 64
#define MAX_RT_NAME_LEN 64
#define MAX_CONSOLE_SOCK_LEN 32

#define MAX_RUNTIME_ARGS 100

#define SHIM_BINARY "isulad-shim"

#define CONTAINER_ACTION_REBOOT 129
#define CONTAINER_ACTION_SHUTDOWN 130

#define ATTACH_LOG_NAME "attach-log.json"
#define ATTACH_DETACH_MSG "read escape sequence"
#define MAX_ATTACH_NUM 16

#define CTRL_Q 0x11  // ASCII code control character ctrl + Q

#define LOG_FILE_MODE 0600

#define SOCKET_DIRECTORY_MODE 0600
#define ATTACH_FIFOPATH_MODE 0600

int isulad_shim_log_init(const char *file, const char *priority);

void signal_routine(int sig);

/**
 * retry_cnt: max count of call cb;
 * interval_us: how many us to sleep, after call cb;
 * cb: retry call function;
 * return:
 *  0 is cb successful at least once;
 *  1 is all cb are failure;
*/
#define DO_RETRY_CALL(retry_cnt, interval_us, ret, cb, ...) do {    \
        size_t i = 0;                                               \
        for(; i < retry_cnt; i++) {                                 \
            ret = cb(##__VA_ARGS__);                                  \
            if (ret == 0) {                                         \
                break;                                              \
            }                                                       \
            isula_usleep_nointerupt(interval_us);                    \
        }                                                           \
    } while(0)

#define UTIL_FREE_AND_SET_NULL(p) \
    do {                          \
        if ((p) != NULL) {        \
            free((void *)(p));    \
            (p) = NULL;           \
        }                         \
    } while (0)

struct shim_fifos_fd {
    char *in_fifo;
    char *out_fifo;
    char *err_fifo;
    int in_fd;
    int out_fd;
    int err_fd;
};

void set_log_to_stderr(bool flag);

void shim_set_error_message(const char *format, ...);

void shim_append_error_message(const char *format, ...);

void error_exit(int exit_code);

char *read_text_file(const char *path);

int cmd_combined_output(const char *binary, const char *params[], void *output, int *output_len);

int generate_random_str(char *id, size_t len);

void close_fd(int *pfd);

int open_no_inherit(const char *path, int flag, mode_t mode);

struct isula_linked_list *get_attach_fifo_item(int fd, struct isula_linked_list *list);

void free_shim_fifos_fd(struct shim_fifos_fd *item);

#ifdef __cplusplus
}
#endif

#endif
