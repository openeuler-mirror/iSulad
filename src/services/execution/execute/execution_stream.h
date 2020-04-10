#ifndef __EXECUTION_STREAM_H_
#define __EXECUTION_STREAM_H_

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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container list callback function definition
 *********************************************************************************/

#include "callback.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

void container_stream_callback_init(service_container_callback_t *cb);

int create_daemon_fifos(const char *id, const char *runtime, bool attach_stdin, bool attach_stdout,
                        bool attach_stderr, const char *operation, char *fifos[], char **fifopath);

void delete_daemon_fifos(const char *fifopath, const char *fifos[]);

int ready_copy_io_data(int sync_fd, bool detach, const char *fifoin, const char *fifoout, const char *fifoerr,
                       int stdin_fd, struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                       const char *fifos[], pthread_t *tid);

#ifdef __cplusplus
}
#endif

#endif

