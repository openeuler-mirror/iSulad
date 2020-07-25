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
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h> // IWYU pragma: keep
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>

#include "console.h"
#include "mainloop.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "constants.h"
#include "utils_file.h"

static ssize_t fd_write_function(void *context, const void *data, size_t len)
{
    ssize_t ret;
    ret = util_write_nointr(*(int *)context, data, len);
    if ((ret <= 0) || (ret != (ssize_t)len)) {
        ERROR("Failed to write: %s", strerror(errno));
        return -1;
    }
    return ret;
}

/* console cb tty fifoin */
static int console_cb_tty_stdin_with_escape(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    struct tty_state *ts = cbdata;
    char c;
    int ret = 0;
    ssize_t r_ret, w_ret;

    if (fd != ts->stdin_reader) {
        ret = 1;
        goto out;
    }

    r_ret = util_read_nointr(ts->stdin_reader, &c, 1);
    if (r_ret <= 0) {
        ret = 1;
        goto out;
    }

    if (ts->tty_exit != -1) {
        if (c == ts->tty_exit && !(ts->saw_tty_exit)) {
            ts->saw_tty_exit = 1;
            goto out;
        }

        if (c == 'q' && ts->saw_tty_exit) {
            ret = 1;
            goto out;
        }

        ts->saw_tty_exit = 0;
    }

    if (ts->stdin_writer.context && ts->stdin_writer.write_func) {
        w_ret = ts->stdin_writer.write_func(ts->stdin_writer.context, &c, 1);
        if ((w_ret <= 0) || (w_ret != r_ret)) {
            ret = 1;
            goto out;
        }
    }

out:
    return ret;
}

static int console_writer_write_data(const struct io_write_wrapper *writer, const char *buf, ssize_t len)
{
    ssize_t ret;

    if (writer == NULL || writer->context == NULL || writer->write_func == NULL || len <= 0) {
        return 0;
    }
    ret = writer->write_func(writer->context, buf, (size_t)len);
    if (ret <= 0 || ret != len) {
        ERROR("failed to write, error:%s", strerror(errno));
        return -1;
    }
    return 0;
}

/* console cb tty fifoin */
static int console_cb_stdio_copy(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    struct tty_state *ts = cbdata;
    char *buf = NULL;
    size_t buf_len = MAX_MSG_BUFFER_SIZE;
    int ret = 0;
    ssize_t r_ret;

    buf = util_common_calloc_s(buf_len);
    if (buf == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (fd == ts->sync_fd) {
        ret = 1;
        goto out;
    }

    if (fd != ts->stdin_reader && fd != ts->stdout_reader && fd != ts->stderr_reader) {
        ret = 1;
        goto out;
    }

    r_ret = util_read_nointr(fd, buf, buf_len - 1);
    if (r_ret <= 0) {
        ret = 1;
        goto out;
    }

    if (fd == ts->stdin_reader) {
        if (console_writer_write_data(&ts->stdin_writer, buf, r_ret) != 0) {
            ret = 1;
            goto out;
        }
    }

    if (fd == ts->stdout_reader) {
        if (console_writer_write_data(&ts->stdout_writer, buf, r_ret) != 0) {
            ret = 1;
            goto out;
        }
    }

    if (fd == ts->stderr_reader) {
        if (console_writer_write_data(&ts->stderr_writer, buf, r_ret) != 0) {
            ret = 1;
            goto out;
        }
    }

out:
    free(buf);
    return ret;
}

/* console fifo name */
int console_fifo_name(const char *rundir, const char *subpath, const char *stdflag, char *fifo_name,
                      size_t fifo_name_sz, char *fifo_path, size_t fifo_path_sz, bool do_mkdirp)
{
    int ret = 0;
    int nret = 0;

    nret = snprintf(fifo_path, fifo_path_sz, "%s/%s/", rundir, subpath);
    if (nret < 0 || (size_t)nret >= fifo_path_sz) {
        ERROR("FIFO path:%s/%s/ is too long.", rundir, subpath);
        ret = -1;
        goto out;
    }

    if (do_mkdirp) {
        ret = util_mkdir_p(fifo_path, CONSOLE_FIFO_DIRECTORY_MODE);
        if (ret < 0) {
            COMMAND_ERROR("Unable to create console fifo directory %s: %s.", fifo_path, strerror(errno));
            goto out;
        }
    }

    nret = snprintf(fifo_name, fifo_name_sz, "%s/%s/%s-fifo", rundir, subpath, stdflag);
    if (nret < 0 || (size_t)nret >= fifo_name_sz) {
        ERROR("FIFO name %s/%s/%s-fifo is too long.", rundir, subpath, stdflag);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* console fifo create */
int console_fifo_create(const char *fifo_path)
{
    int ret;

    ret = mknod(fifo_path, S_IFIFO | S_IRUSR | S_IWUSR, (dev_t)0);
    if (ret < 0 && errno != EEXIST) {
        ERROR("Failed to mknod monitor fifo %s: %s.", fifo_path, strerror(errno));
        return -1;
    }

    return 0;
}

/* console fifo delete */
int console_fifo_delete(const char *fifo_path)
{
    char *ret = NULL;
    char real_path[PATH_MAX + 1] = { 0x00 };

    if (fifo_path == NULL || strlen(fifo_path) > PATH_MAX) {
        ERROR("Invalid input!");
        return -1;
    }

    if (strlen(fifo_path) == 0) {
        return 0;
    }

    ret = realpath(fifo_path, real_path);
    if (ret == NULL) {
        if (errno != ENOENT) {
            ERROR("Failed to get real path: %s", fifo_path);
            return -1;
        }
        return 0;
    }

    if (unlink(real_path) && errno != ENOENT) {
        WARN("Unlink %s failed", real_path);
        return -1;
    }
    return 0;
}

/* console fifo open */
int console_fifo_open(const char *fifo_path, int *fdout, int flags)
{
    int fd = 0;

    fd = util_open(fifo_path, O_RDONLY | O_NONBLOCK, (mode_t)0);
    if (fd < 0) {
        ERROR("Failed to open fifo %s to send message: %s.", fifo_path, strerror(errno));
        return -1;
    }

    *fdout = fd;
    return 0;
}

/* console fifo open withlock */
int console_fifo_open_withlock(const char *fifo_path, int *fdout, int flags)
{
    int fd = 0;
    struct flock lk;

    fd = util_open(fifo_path, flags, 0);
    if (fd < 0) {
        WARN("Failed to open fifo %s to send message: %s.", fifo_path, strerror(errno));
        return -1;
    }

    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = 0;
    lk.l_len = 0;
    if (fcntl(fd, F_SETLK, &lk) != 0) {
        /* another console instance is already running, don't start up */
        DEBUG("Another console instance already running with path : %s.", fifo_path);
        close(fd);
        return -1;
    }

    *fdout = fd;
    return 0;
}

/* console fifo close */
void console_fifo_close(int fd)
{
    close(fd);
}

/* setup tios */
int setup_tios(int fd, struct termios *curr_tios)
{
    struct termios tmptios;
    int ret = 0;

    if (!isatty(fd)) {
        ERROR("Specified fd: '%d' is not a tty", fd);
        return -1;
    }

    if (tcgetattr(fd, curr_tios)) {
        ERROR("Failed to get current terminal settings");
        ret = -1;
        goto out;
    }

    tmptios = *curr_tios;

    cfmakeraw(&tmptios);
    tmptios.c_oflag |= OPOST;

    if (tcsetattr(fd, TCSAFLUSH, &tmptios)) {
        ERROR("Set terminal settings failed");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static void client_console_tty_state_close(struct epoll_descr *descr, const struct tty_state *ts)
{
    if (ts->stdin_reader >= 0) {
        epoll_loop_del_handler(descr, ts->stdin_reader);
    }
    if (ts->stdout_reader >= 0) {
        epoll_loop_del_handler(descr, ts->stdout_reader);
    }
    if (ts->stderr_reader >= 0) {
        epoll_loop_del_handler(descr, ts->stderr_reader);
    }
}

/* console loop */
/* data direction: */
/* read stdinfd, write fifoinfd */
/* read fifooutfd, write stdoutfd */
/* read stderrfd, write stderrfd */
int console_loop_with_std_fd(int stdinfd, int stdoutfd, int stderrfd, int fifoinfd, int fifooutfd, int fifoerrfd,
                             int tty_exit, bool tty)
{
    int ret;
    struct epoll_descr descr;
    struct tty_state ts;

    ret = epoll_loop_open(&descr);
    if (ret) {
        ERROR("Create epoll_loop error");
        return ret;
    }

    ts.tty_exit = tty_exit;
    ts.saw_tty_exit = 0;
    ts.sync_fd = -1;
    ts.stdin_reader = -1;
    ts.stdout_reader = -1;
    ts.stderr_reader = -1;

    if (fifoinfd >= 0) {
        ts.stdin_reader = stdinfd;
        ts.stdin_writer.context = &fifoinfd;
        ts.stdin_writer.write_func = fd_write_function;
        if (tty) {
            ret = epoll_loop_add_handler(&descr, ts.stdin_reader, console_cb_tty_stdin_with_escape, &ts);
            if (ret) {
                INFO("Add handler for stdinfd faied. with error %s", strerror(errno));
            }
        } else {
            ret = epoll_loop_add_handler(&descr, ts.stdin_reader, console_cb_stdio_copy, &ts);
            if (ret) {
                INFO("Add handler for stdinfd faied. with error %s", strerror(errno));
            }
        }
    }

    if (fifooutfd >= 0) {
        ts.stdout_reader = fifooutfd;
        ts.stdout_writer.context = &stdoutfd;
        ts.stdout_writer.write_func = fd_write_function;
        ret = epoll_loop_add_handler(&descr, ts.stdout_reader, console_cb_stdio_copy, &ts);
        if (ret) {
            ERROR("Add handler for masterfd failed");
            goto err_out;
        }
    }

    if (fifoerrfd >= 0) {
        ts.stderr_reader = fifoerrfd;
        ts.stderr_writer.context = &stderrfd;
        ts.stderr_writer.write_func = fd_write_function;
        ret = epoll_loop_add_handler(&descr, ts.stderr_reader, console_cb_stdio_copy, &ts);
        if (ret) {
            ERROR("Add handler for masterfd failed");
            goto err_out;
        }
    }

    ret = epoll_loop(&descr, -1);
    if (ret) {
        ERROR("Epoll_loop error");
        goto err_out;
    }

    ret = 0;

err_out:
    client_console_tty_state_close(&descr, &ts);
    epoll_loop_close(&descr);
    return ret;
}

/* console loop copy */
int console_loop_io_copy(int sync_fd, const int *srcfds, struct io_write_wrapper *writers, size_t len)
{
    int ret = 0;
    size_t i = 0;
    struct epoll_descr descr;
    struct tty_state *ts = NULL;
    if (len > (SIZE_MAX / sizeof(struct tty_state)) - 1) {
        ERROR("Invalid io size");
        return -1;
    }
    ts = util_common_calloc_s(sizeof(struct tty_state) * (len + 1));
    if (ts == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ret = epoll_loop_open(&descr);
    if (ret) {
        ERROR("Create epoll_loop error");
        free(ts);
        return ret;
    }

    for (i = 0; i < len; i++) {
        // Reusing ts.stdout_reader and ts.stdout_writer for coping io
        ts[i].stdout_reader = srcfds[i];
        ts[i].stdout_writer.context = writers[i].context;
        ts[i].stdout_writer.write_func = writers[i].write_func;
        ts[i].sync_fd = -1;
        ret = epoll_loop_add_handler(&descr, ts[i].stdout_reader, console_cb_stdio_copy, &ts[i]);
        if (ret != 0) {
            ERROR("Add handler for masterfd failed");
            goto err_out;
        }
    }
    if (sync_fd >= 0) {
        ts[i].sync_fd = sync_fd;
        epoll_loop_add_handler(&descr, ts[i].sync_fd, console_cb_stdio_copy, &ts[i]);
        if (ret) {
            ERROR("Add handler for syncfd failed");
            goto err_out;
        }
    }

    ret = epoll_loop(&descr, -1);
    if (ret != 0) {
        ERROR("Epoll_loop error");
        goto err_out;
    }

err_out:

    for (i = 0; i < (len + 1); i++) {
        epoll_loop_del_handler(&descr, ts[i].stdout_reader);
    }
    epoll_loop_close(&descr);
    free(ts);
    return ret;
}
