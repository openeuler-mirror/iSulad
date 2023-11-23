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
 * Create: 2023-09-04
 * Description: provide vsock io functions
 ********************************************************************************/

#ifndef DAEMON_MODULES_SERVICE_VSOCK_IO_H
#define DAEMON_MODULES_SERVICE_VSOCK_IO_H

#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

bool is_vsock_path(const char *path);

bool parse_vsock_path(const char *vsock_path, uint32_t *cid, uint32_t *port);

int vsock_open(const char *vsock_path, int *fdout, int flags);

int create_daemon_vsockpaths(const char *sandbox_id, uint32_t cid, bool attach_stdin, bool attach_stdout,
                             bool attach_stderr, char *vsockpaths[]);

void delete_daemon_vsockpaths(const char *sandbox_id, const char *vsockpaths[]);

int start_vsock_io_copy(const char *exec_id, int sync_fd, bool detach, const char *fifoin, const char *fifoout,
                        const char *fifoerr,
                        int stdin_fd, struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                        const char *vsocks[], pthread_t *tid);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_SERVICE_VSOCK_IO_H
