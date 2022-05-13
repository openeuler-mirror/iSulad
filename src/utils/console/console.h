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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide console definition
 ******************************************************************************/
#ifndef UTILS_CONSOLE_CONSOLE_H
#define UTILS_CONSOLE_CONSOLE_H

#include <unistd.h>
#include <stdbool.h>
#include <termios.h>
#include <semaphore.h>
#include <stddef.h>

#include "io_wrapper.h"
#include "constants.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    bool ignore_stdin_close;
};

typedef enum { STDIN_CHANNEL, STDOUT_CHANNEL, STDERR_CHANNEL, MAX_CHANNEL } transfer_channel_type;

int console_fifo_name(const char *rundir, const char *subpath, const char *stdflag, char *fifo_name,
                      size_t fifo_name_sz, char *fifo_path, size_t fifo_path_sz, bool do_mkdirp);

int console_fifo_create(const char *fifo_path);

int console_fifo_delete(const char *fifo_path);

int console_fifo_open(const char *fifo_path, int *fdout, int flags);

int console_fifo_open_withlock(const char *fifo_path, int *fdout, int flags);

void console_fifo_close(int fd);

int console_loop_with_std_fd(int stdinfd, int stdoutfd, int stderrfd, int fifoinfd, int fifooutfd, int fifoerrfd,
                             int tty_exit, bool tty);

int console_loop_io_copy(int sync_fd, const int *srcfds, struct io_write_wrapper *writers,
                         const transfer_channel_type *channels, size_t len);

int setup_tios(int fd, struct termios *curr_tios);

#ifdef __cplusplus
}
#endif

#endif
