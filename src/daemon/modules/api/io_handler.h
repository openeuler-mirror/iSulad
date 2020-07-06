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
 * Author: lifeng
 * Create: 2020-06-28
 * Description: provide container io handler function definition
 *********************************************************************************/

#ifndef __IO_HANDLER_H_
#define __IO_HANDLER_H_

#include <pthread.h>
#include <stdbool.h>

#include "io_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

int create_daemon_fifos(const char *id, const char *runtime, bool attach_stdin, bool attach_stdout, bool attach_stderr,
                        const char *operation, char *fifos[], char **fifopath);

void delete_daemon_fifos(const char *fifopath, const char *fifos[]);

int ready_copy_io_data(int sync_fd, bool detach, const char *fifoin, const char *fifoout, const char *fifoerr,
                       int stdin_fd, struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                       const char *fifos[], pthread_t *tid);

#ifdef __cplusplus
}
#endif

#endif
