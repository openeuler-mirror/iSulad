/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide console definition
 ******************************************************************************/
#ifndef _CONSOLE_H
#define _CONSOLE_H

#include <unistd.h>
#include <stdbool.h>
#include <termios.h>
#include <semaphore.h>
#include "constants.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef ssize_t (*io_write_func_t)(void *context, const void *data, size_t len);
typedef int (*io_close_func_t)(void *context, char **err);

struct io_write_wrapper {
    void *context;
    io_write_func_t write_func;
    io_close_func_t close_func;
};

typedef ssize_t (*io_read_func_t)(void *context, void *buf, size_t len);

struct io_read_wrapper {
    void *context;
    io_read_func_t read;
    io_close_func_t close;
};

struct tty_state {
    int sync_fd;
    int stdin_reader;
    struct io_write_wrapper stdin_writer;
    int stdout_reader;
    struct io_write_wrapper stdout_writer;
    int stderr_reader;
    struct io_write_wrapper stderr_writer;
    /* Escape sequence for quiting from tty. Exiteing by : Ctrl + specified_char + q */
    int tty_exit;
    /* Flag to mark whether detected escape sequence. */
    int saw_tty_exit;
};

typedef enum {
    IO_FD,
    IO_FIFO,
    IO_FUNC,
    IO_MAX
} io_type;

struct io_copy_arg {
    io_type srctype;
    void *src;
    io_type dsttype;
    void *dst;
};

int console_fifo_name(const char *rundir, const char *subpath,
                      const char *stdflag,
                      char *fifo_name, size_t fifo_name_sz,
                      char *fifo_path, size_t fifo_path_sz, bool do_mkdirp);

int console_fifo_create(const char *fifo_path);

int console_fifo_delete(const char *fifo_path);

int console_fifo_open(const char *fifo_path, int *fdout, int flags);

int console_fifo_open_withlock(const char *fifo_path, int *fdout, int flags);

void console_fifo_close(int fd);

int client_console_loop(int stdinfd, int stdoutfd, int stderrfd,
                        int fifoinfd, int fifooutfd, int fifoerrfd, int tty_exit, bool tty);

int start_io_copy_thread(int sync_fd, bool detach, struct io_copy_arg *copy_arg, size_t len, pthread_t *tid);

int setup_tios(int fd, struct termios *curr_tios);

#ifdef __cplusplus
}
#endif

#endif

