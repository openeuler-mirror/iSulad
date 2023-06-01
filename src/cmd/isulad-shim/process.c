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
 * Description: process operation encapsulation
 ******************************************************************************/

#define _GNU_SOURCE
#include "process.h"
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/wait.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <termios.h> // IWYU pragma: keep
#include <sys/resource.h> // IWYU pragma: keep
#include <isula_libutils/json_common.h>
#include <isula_libutils/shim_client_process_state.h>
#include <stdint.h>
#include <stdio.h>

#include "common.h"
#include "terminal.h"
#include "mainloop.h"

#define MAX_EVENTS 100
#define DEFAULT_IO_COPY_BUF (16 * 1024)
#define DEFAULT_LOG_FILE_SIZE (4 * 1024)

static shim_client_process_state *load_process()
{
    parser_error err = NULL;
    shim_client_process_state *p_state = NULL;

    p_state = shim_client_process_state_parse_file("process.json", NULL, &err);
    if (p_state == NULL) {
        write_message(ERR_MSG, "parse process state failed");
    }
    /* "err" will definitely be allocated memory in the function above */
    free(err);

    return p_state;
}

static int open_fifo_noblock(const char *path, mode_t mode)
{
    int fd = -1;

    /* By default, We consider that the file has been created by isulad */
    fd = open_no_inherit(path, mode | O_NONBLOCK, -1);
    if (fd < 0) {
        write_message(ERR_MSG, "open fifo file failed:%d", SHIM_SYS_ERR(errno));
        return -1;
    }

    return fd;
}

static int receive_fd(int sock)
{
    u_char *pfd = NULL;
    int fd = -1;
    int cmsgsize = CMSG_LEN(sizeof(int));
    struct cmsghdr *cmptr = (struct cmsghdr *)util_common_calloc_s(cmsgsize);
    if (cmptr == NULL) {
        return -1;
    }

    char buf[32] = { 0 };
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);

    struct msghdr msg;
    (void)memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = cmptr;
    msg.msg_controllen = cmsgsize;

    /*
     * return value:
     *  0: the peer has performed an orderly shutdown
     * -1: an error occurred
     * >0: the number of bytes received
     */
    int ret = recvmsg(sock, &msg, 0);
    if (ret <= 0) {
        write_message(ERR_MSG, "get console fd failed:%d", SHIM_SYS_ERR(errno));
        free(cmptr);
        return -1;
    }

    pfd = CMSG_DATA(cmptr);
    fd = *(int *)pfd;
    free(cmptr);

    return fd;
}

static bool check_fd(int fd)
{
    struct termios term;
    int ret = ioctl(fd, TCGETS, &term);
    if (ret != 0) {
        return false;
    }

    return true;
}

static int get_exec_winsize(const char *buf, struct winsize *wsize)
{
    char **array = NULL;
    int width = 0;
    int height = 0;
    int ret = 0;

    array = util_string_split_multi(buf, ' ');
    if (array == NULL) {
        return -1;
    }

    if (util_array_len((const char **)array) != 2) {
        ret = -1;
        goto out;
    }

    width = atoi(array[0]);
    height = atoi(array[1]);

    if (width < 0 || width > USHRT_MAX || height < 0 || height > USHRT_MAX) {
        ret = -1;
        goto out;
    }
    wsize->ws_row = (unsigned short)height;
    wsize->ws_col = (unsigned short)width;

out:
    util_free_array(array);
    return ret;
}

static int sync_exit_cb(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    return EPOLL_LOOP_HANDLE_CLOSE;
}

static int stdin_cb(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    process_t *p = (process_t *)cbdata;
    int r_count = 0;
    int w_count = 0;
    int *fd_to = NULL;

    if (events & EPOLLHUP) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }

    if (!(events & EPOLLIN)) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    (void)memset(p->buf, 0, DEFAULT_IO_COPY_BUF);

    r_count = read_nointr(fd, p->buf, DEFAULT_IO_COPY_BUF);
    if (r_count <= 0) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }

    if (p->state->terminal) {
        fd_to = &(p->recv_fd);
    } else {
        fd_to = &(p->shim_io->in);
    }

    if (fd_to == NULL || *fd_to == -1) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }
    w_count = write_nointr_in_total(*fd_to, p->buf, r_count);
    if (w_count < 0) {
        /* When any error occurs, set the write fd -1  */
        write_message(WARN_MSG, "write in_fd %d error:%d", *fd_to, SHIM_SYS_ERR(errno));
        close(*fd_to);
        *fd_to = -1;
    }

    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int stdout_cb(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    process_t *p = (process_t *)cbdata;
    int r_count = 0;
    int w_count = 0;

    if (events & EPOLLHUP) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }

    if (!(events & EPOLLIN)) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    (void)memset(p->buf, 0, DEFAULT_IO_COPY_BUF);

    if (p->block_read) {
        r_count = read_nointr(fd, p->buf, DEFAULT_IO_COPY_BUF);
    } else {
        r_count = read(fd, p->buf, DEFAULT_IO_COPY_BUF);
    }
    if (r_count <= 0) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }

    shim_write_container_log_file(p->terminal, STDID_OUT, p->buf, r_count);

    if (p->isulad_io->out == -1) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    w_count = write_nointr_in_total(p->isulad_io->out, p->buf, r_count);
    if (w_count < 0) {
        /* When any error occurs, set the write fd -1  */
        write_message(WARN_MSG, "write out_fd %d error:%d", p->isulad_io->out, SHIM_SYS_ERR(errno));
        close(p->isulad_io->out);
        p->isulad_io->out = -1;
    }

    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int stderr_cb(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    process_t *p = (process_t *)cbdata;
    int r_count = 0;
    int w_count = 0;

    if (events & EPOLLHUP) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }

    if (!(events & EPOLLIN)) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    (void)memset(p->buf, 0, DEFAULT_IO_COPY_BUF);

    if (p->block_read) {
        r_count = read_nointr(fd, p->buf, DEFAULT_IO_COPY_BUF);
    } else {
        r_count = read(fd, p->buf, DEFAULT_IO_COPY_BUF);
    }
    if (r_count <= 0) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }

    shim_write_container_log_file(p->terminal, STDID_ERR, p->buf, r_count);

    if (p->isulad_io->err == -1) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    w_count = write_nointr_in_total(p->isulad_io->err, p->buf, r_count);
    if (w_count < 0) {
        /* When any error occurs, set the write fd -1  */
        write_message(WARN_MSG, "write err_fd %d error:%d", p->isulad_io->err, SHIM_SYS_ERR(errno));
        close(p->isulad_io->err);
        p->isulad_io->err = -1;
    }

    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int resize_cb(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    process_t *p = (process_t *)cbdata;
    int r_count = 0;
    int resize_fd = -1;

    if (events & EPOLLHUP) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }

    if (!(events & EPOLLIN)) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    (void)memset(p->buf, 0, DEFAULT_IO_COPY_BUF);
    r_count = read_nointr(fd, p->buf, DEFAULT_IO_COPY_BUF);
    if (r_count <= 0) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }

    resize_fd = p->recv_fd;
    struct winsize wsize = { 0x00 };
    if (get_exec_winsize(p->buf, &wsize) < 0) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }
    if (ioctl(resize_fd, TIOCSWINSZ, &wsize) < 0) {
        return EPOLL_LOOP_HANDLE_CLOSE;
    }

    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int task_console_accept(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    process_t *p = (process_t *)cbdata;
    int conn_fd = -1;
    int ret = SHIM_ERR;

    conn_fd = accept(p->listen_fd, NULL, NULL);
    if (conn_fd < 0) {
        write_message(ERR_MSG, "accept from fd %d failed:%d", p->listen_fd, SHIM_SYS_ERR(errno));
        goto out;
    }

    p->recv_fd = receive_fd(conn_fd);
    if (check_fd(p->recv_fd) != true) {
        write_message(ERR_MSG, "check console fd failed");
        goto out;
    }

    /* do console io copy */

    // p->isulad_io->in ----> p->recv_fd
    ret = epoll_loop_add_handler(descr, p->isulad_io->in, stdin_cb, p);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "add in fd %d to epoll loop failed:%d", p->isulad_io->in, SHIM_SYS_ERR(errno));
        goto out;
    }
    // p->recv_fd ----> p->isulad_io->out
    ret = epoll_loop_add_handler(descr, p->recv_fd, stdout_cb, p);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "add recv_fd fd %d to epoll loop failed:%d", p->recv_fd, SHIM_SYS_ERR(errno));
        goto out;
    }
    // p->isulad_io->resize ----> p->recv_fd
    ret = epoll_loop_add_handler(descr, p->isulad_io->resize, resize_cb, p);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "add resize fd %d to epoll loop failed:%d", p->isulad_io->resize, SHIM_SYS_ERR(errno));
        goto out;
    }

out:
    /* release listen socket at the first time */
    close_fd(&p->listen_fd);
    if (p->console_sock_path != NULL) {
        (void)unlink(p->console_sock_path);
        free(p->console_sock_path);
        p->console_sock_path = NULL;
    }
    return ret;
}

static int stdio_chown(int (*stdio_fd)[2], int uid, int gid)
{
    int i, j;

    for (i = 0; i < 3; i++) {
        for (j = 0; j < 2; j++) {
            int ret = fchown(stdio_fd[i][j], uid, gid);
            if (ret != SHIM_OK) {
                return SHIM_ERR;
            }
        }
    }
    return SHIM_OK;
}

static void stdio_release(int (*stdio_fd)[2])
{
    int i, j;

    for (i = 0; i < 3; i++) {
        for (j = 0; j < 2; j++) {
            if (stdio_fd[i][j] > 0) {
                close(stdio_fd[i][j]);
            }
        }
    }
}

static stdio_t *initialize_io(process_t *p)
{
    int stdio_fd[4][2] = { { -1, -1 }, { -1, -1 }, { -1, -1 }, { -1, -1 } };

    stdio_t *stdio = (stdio_t *)util_common_calloc_s(sizeof(stdio_t));
    p->stdio = (stdio_t *)util_common_calloc_s(sizeof(stdio_t));
    if (p->stdio == NULL || stdio == NULL) {
        goto failure;
    }

    /* don't open resize pipe */
    if ((pipe2(stdio_fd[0], O_CLOEXEC | O_NONBLOCK) != 0) || (pipe2(stdio_fd[1], O_CLOEXEC | O_NONBLOCK) != 0) ||
        (pipe2(stdio_fd[2], O_CLOEXEC | O_NONBLOCK) != 0)) {
        write_message(ERR_MSG, "open pipe failed when init io:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    p->stdio->in = stdio_fd[0][0]; // r
    stdio->in = stdio_fd[0][1]; // w
    p->stdio->out = stdio_fd[1][1]; // w
    stdio->out = stdio_fd[1][0]; // r
    p->stdio->err = stdio_fd[2][1]; // w
    stdio->err = stdio_fd[2][0]; // r
    p->stdio->resize = stdio_fd[3][0]; // r
    stdio->resize = stdio_fd[3][1]; // w

    if (stdio_chown(stdio_fd, p->state->root_uid, p->state->root_gid) != SHIM_OK) {
        goto failure;
    }

    return stdio;

failure:
    if (stdio != NULL) {
        free(stdio);
        stdio = NULL;
    }
    if (p->stdio != NULL) {
        free(p->stdio);
        p->stdio = NULL;
    }
    stdio_release(stdio_fd);

    return NULL;
}

static int new_temp_console_path(process_t *p)
{
#define RAND_NUM_LEN 9
    int ret = SHIM_ERR;
    char str_rand[RAND_NUM_LEN + 1] = { 0 };

    ret = generate_random_str(str_rand, RAND_NUM_LEN);
    if (ret != SHIM_OK) {
        return SHIM_ERR;
    }
    p->console_sock_path = (char *)util_common_calloc_s(MAX_CONSOLE_SOCK_LEN + 1);
    if (p->console_sock_path == NULL) {
        return SHIM_ERR;
    }
    int nret = snprintf(p->console_sock_path, MAX_CONSOLE_SOCK_LEN, "/run/isulad%s-pty.sock", str_rand);
    if (nret < 0 || nret >= MAX_CONSOLE_SOCK_LEN) {
        free(p->console_sock_path);
        p->console_sock_path = NULL;
        return SHIM_ERR;
    }

    return SHIM_OK;
}

static int console_init(process_t *p, struct epoll_descr *descr)
{
    int ret = SHIM_ERR;
    int fd = -1;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        write_message(ERR_MSG, "create socket failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    (void)memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)strcpy(addr.sun_path, p->console_sock_path);

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        write_message(ERR_MSG, "bind console fd failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    ret = listen(fd, 2);
    if (ret < 0) {
        write_message(ERR_MSG, "listen console fd failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    p->listen_fd = fd;

    ret = epoll_loop_add_handler(descr, p->listen_fd, task_console_accept, p);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "add listen_fd fd %d to epoll loop failed:%d",  p->listen_fd, SHIM_SYS_ERR(errno));
        goto failure;
    }

    return SHIM_OK;
failure:
    close_fd(&fd);
    (void)unlink(p->console_sock_path);

    return SHIM_ERR;
}

static int open_terminal_io(process_t *p, struct epoll_descr *descr)
{
    int ret = SHIM_ERR;

    ret = new_temp_console_path(p);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "get temp console sock path failed");
        return SHIM_ERR;
    }

    /* begin listen from p->console_sock_path */
    return console_init(p, descr);
}

static int open_generic_io(process_t *p, struct epoll_descr *descr)
{
    int ret = SHIM_ERR;

    // io: in: w  out/err: r
    stdio_t *io = initialize_io(p);
    if (io == NULL) {
        return SHIM_ERR;
    }
    p->shim_io = io;

    // p->isulad_io->in ----> p->shim_io->in
    ret = epoll_loop_add_handler(descr, p->isulad_io->in, stdin_cb, p);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "add in fd %d to epoll loop failed:%d", p->isulad_io->in, SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }
    // p->shim_io->out ----> p->isulad_io->out
    ret = epoll_loop_add_handler(descr, p->shim_io->out, stdout_cb, p);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "add  out fd %d to epoll loop failed:%d", p->shim_io->out, SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }
    // p->shim_io->err ----> p->isulad_io->err
    ret = epoll_loop_add_handler(descr, p->shim_io->err, stderr_cb, p);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "add err fd %d to epoll loop failed:%d", p->shim_io->err, SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }

    return SHIM_OK;
}

static int set_non_block(int fd)
{
    int flag = -1;
    int ret = SHIM_ERR;

    flag = fcntl(fd, F_GETFL, 0);
    if (flag < 0) {
        return SHIM_ERR;
    }

    ret = fcntl(fd, F_SETFL, flag | O_NONBLOCK);
    if (ret != 0) {
        return SHIM_ERR;
    }

    return SHIM_OK;
}

/*
    std_id: channel type
    isulad_stdio: one side of the isulad fifo file
    fd: one side of the shim io pipe
    ---------------------------------------------------------------
    | CHANNEL |    iSulad Fifo Side     | Flow Direction |   fd   |
    ---------------------------------------------------------------
    |  STDIN  |        READ             |      -->       |  WRITE |
    ---------------------------------------------------------------
    |  STDOUT |        WRITE            |      <--       |  READ  |
    ---------------------------------------------------------------
    |  STDERR |        WRITE            |      <--       |  READ  |
    ---------------------------------------------------------------
    |  RESIZE |        READ             |      -->       |  WRITE |
    ---------------------------------------------------------------
*/
static void *io_epoll_loop(void *data)
{
    int ret = 0;
    int fd_out = -1;
    int fd_err = -1;
    process_t *p = (process_t *)data;
    struct epoll_descr descr;

    ret = epoll_loop_open(&descr);
    if (ret != 0) {
        write_message(ERR_MSG, "epoll loop open failed:%d", SHIM_SYS_ERR(errno));
        exit(EXIT_FAILURE);
    }

    // sync fd: epoll loop will exit when recive sync fd event.
    ret = epoll_loop_add_handler(&descr, p->sync_fd, sync_exit_cb, p);
    if (ret != 0) {
        write_message(ERR_MSG, "add sync_fd %d to epoll loop failed:%d", p->sync_fd, SHIM_SYS_ERR(errno));
        exit(EXIT_FAILURE);
    }

    if (p->state->terminal) {
        ret = open_terminal_io(p, &descr);
    } else {
        ret = open_generic_io(p, &descr);
    }
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "open io failed:%d", SHIM_SYS_ERR(errno));
        exit(EXIT_FAILURE);
    }

    (void)sem_post(&p->sem_mainloop);

    ret = epoll_loop(&descr, -1);
    if (ret != 0) {
        write_message(ERR_MSG, "epoll loop failed");
        exit(EXIT_FAILURE);
    }

    // in order to avoid data loss, set fd non-block and read it
    p->block_read = false;
    if (p->state->terminal) {
        fd_out = p->recv_fd;
    } else {
        fd_out = p->shim_io->out;
        fd_err = p->shim_io->err;
    }

    if (fd_out > 0) {
        ret = set_non_block(fd_out);
        if (ret != SHIM_OK) {
            write_message(ERR_MSG, "set fd %d non_block failed:%d", fd_out, SHIM_SYS_ERR(errno));
            exit(EXIT_FAILURE);
        }

        for (;;) {
            ret = stdout_cb(fd_out, EPOLLIN, p, &descr);
            if (ret == EPOLL_LOOP_HANDLE_CLOSE) {
                break;
            }
        }
    }

    if (fd_err > 0) {
        ret = set_non_block(fd_err);
        if (ret != SHIM_OK) {
            write_message(ERR_MSG, "set fd %d non_block failed:%d", fd_err, SHIM_SYS_ERR(errno));
            exit(EXIT_FAILURE);
        }

        for (;;) {
            ret = stderr_cb(fd_err, EPOLLIN, p, &descr);
            if (ret == EPOLL_LOOP_HANDLE_CLOSE) {
                break;
            }
        }
    }

    return NULL;
}

static void adapt_for_isulad_stdin(process_t *p)
{
    /* iSulad: close stdin pipe if we do not want open_stdin with container stdin just like lxc */
    if (!p->state->open_stdin && !file_exists(p->state->isulad_stdin)) {
        if (p->shim_io != NULL && p->shim_io->in != -1) {
            close(p->shim_io->in);
            p->shim_io->in = -1;
        }
    }
}

static int terminal_init(log_terminal **terminal, shim_client_process_state *p_state)
{
    log_terminal *log_term = NULL;

    log_term = util_common_calloc_s(sizeof(log_terminal));
    if (log_term == NULL) {
        write_message(ERR_MSG, "Failed to calloc log_terminal");
        goto clean_out;
    }

    if (pthread_rwlock_init(&log_term->log_terminal_rwlock, NULL) != 0) {
        write_message(ERR_MSG, "Failed to init isulad conf rwlock");
        goto clean_out;
    }

    if (p_state == NULL) {
        goto clean_out;
    }

    log_term->log_path = p_state->log_path;
    /* Default to disable log. */
    log_term->fd = -1;
    log_term->log_maxfile = 1;
    /* Default value 4k, the min size of a single log file */
    log_term->log_maxsize = DEFAULT_LOG_FILE_SIZE;

    if (p_state->log_maxfile > log_term->log_maxfile) {
        log_term->log_maxfile = (unsigned int)p_state->log_maxfile;
    }

    if (p_state->log_maxsize > log_term->log_maxsize) {
        log_term->log_maxsize = (uint64_t)p_state->log_maxsize;
    }

    if (log_term->log_path != NULL) {
        if (shim_create_container_log_file(log_term)) {
            goto clean_out;
        }
    }

    *terminal = log_term;

    return SHIM_OK;
clean_out:
    free(log_term);
    *terminal = NULL;
    return SHIM_ERR;
}

static int open_isulad_fd(int std_id, const char *isulad_stdio, int *fd)
{
    mode_t mode = O_WRONLY;

    if (std_id == STDID_IN || std_id == EXEC_RESIZE) {
        mode = O_RDONLY;
    }

    if (isulad_stdio != NULL && file_exists(isulad_stdio)) {
        *(fd) = open_fifo_noblock(isulad_stdio, mode);
        if (*(fd) < 0) {
            return -1;
        }
        /* open dummy fd to avoid resize epoll hub */
        if (std_id == EXEC_RESIZE && open_fifo_noblock(isulad_stdio, O_WRONLY) < 0) {
            return -1;
        }
    }

    return 0;
}


static int init_isulad_stdio(process_t *p)
{
    int ret = SHIM_OK;
    p->isulad_io = (stdio_t *)util_common_calloc_s(sizeof(stdio_t));
    if (p->isulad_io == NULL) {
        return SHIM_ERR;
    }

    p->isulad_io->in = -1;
    p->isulad_io->out = -1;
    p->isulad_io->err = -1;
    p->isulad_io->resize = -1;

    ret = open_isulad_fd(STDID_IN, p->state->isulad_stdin, &p->isulad_io->in);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "Failed to open in isulad fd: %s",  p->state->isulad_stdin);
        goto failure;
    }

    ret = open_isulad_fd(STDID_OUT, p->state->isulad_stdout, &p->isulad_io->out);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "Failed to open out isulad fd: %s",  p->state->isulad_stdout);
        goto failure;
    }

    ret = open_isulad_fd(STDID_ERR, p->state->isulad_stderr, &p->isulad_io->err);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "Failed to open err isulad fd: %s",  p->state->isulad_stderr);
        goto failure;
    }

    ret = open_isulad_fd(EXEC_RESIZE, p->state->resize_fifo, &p->isulad_io->resize);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "Failed to open resize isulad fd: %s",  p->state->resize_fifo);
        goto failure;
    }
    return SHIM_OK;
failure:
    if (p->isulad_io != NULL) {
        if (p->isulad_io->in > 0) {
            close(p->isulad_io->in);
        }
        if (p->isulad_io->out > 0) {
            close(p->isulad_io->out);
        }
        if (p->isulad_io->err > 0) {
            close(p->isulad_io->err);
        }
        if (p->isulad_io->resize > 0) {
            close(p->isulad_io->resize);
        }
        free(p->isulad_io);
        p->isulad_io = NULL;
    }
    return SHIM_ERR;
}

process_t *new_process(char *id, char *bundle, char *runtime)
{
    shim_client_process_state *p_state;
    process_t *p = NULL;
    int ret;

    p_state = load_process();
    if (p_state == NULL) {
        return NULL;
    }

    p = (process_t *)util_common_calloc_s(sizeof(process_t));
    if (p == NULL) {
        return NULL;
    }

    ret = sem_init(&p->sem_mainloop, 0, 0);
    if (ret != 0) {
        goto failure;
    }

    ret = terminal_init(&(p->terminal), p_state);
    if (ret != SHIM_OK) {
        goto failure;
    }

    p->id = id;
    p->bundle = bundle;
    p->runtime = runtime;
    p->state = p_state;
    p->block_read = true;
    p->console_sock_path = NULL;
    p->exit_fd = -1;
    p->io_loop_fd = -1;
    p->ctr_pid = -1;
    p->listen_fd = -1;
    p->recv_fd = -1;
    p->stdio = NULL;
    p->shim_io = NULL;
    p->isulad_io = NULL;

    p->sync_fd = eventfd(0, EFD_CLOEXEC);
    if (p->sync_fd < 0) {
        write_message(ERR_MSG, "Failed to create eventfd: %s", strerror(errno));
        goto failure;
    }

    ret = init_isulad_stdio(p);
    if (ret != SHIM_OK) {
        goto failure;
    }

    p->buf = util_common_calloc_s(DEFAULT_IO_COPY_BUF + 1);
    if (p->buf == NULL) {
        goto failure;
    }

    return p;

failure:
    free(p);
    p = NULL;
    return NULL;
}

int process_io_start(process_t *p, pthread_t *tid_epoll)
{
    int ret = SHIM_ERR;

    ret = pthread_create(tid_epoll, NULL, io_epoll_loop, p);
    if (ret != SHIM_OK) {
        return SHIM_SYS_ERR(errno);
    }
    (void)sem_wait(&p->sem_mainloop);
    (void)sem_destroy(&p->sem_mainloop);

    return SHIM_OK;
}

static void get_runtime_cmd(process_t *p, const char *log_path, const char *pid_path, const char *process_desc,
                            const char *params[])
{
    int i = 0;
    int j;
    params[i++] = p->runtime;
    for (j = 0; j < p->state->runtime_args_len; j++) {
        params[i++] = p->state->runtime_args[j];
    }
    params[i++] = "--log";

    params[i++] = log_path;
    params[i++] = "--log-format";
    params[i++] = "json";
    if (p->state->exec && process_desc != NULL) {
        params[i++] = "exec";
#ifdef ENABLE_GVISOR
        /* gvisor runtime runsc do not support -d option */
        params[i++] = "--detach";
#else
        params[i++] = "-d";
#endif
        params[i++] = "--process";
        params[i++] = process_desc;
    } else {
        params[i++] = "create";
        params[i++] = "--bundle";
        params[i++] = p->bundle;
    }
    params[i++] = "--pid-file";
    params[i++] = pid_path;
    if (p->console_sock_path != NULL) {
        params[i++] = "--console-socket";
        params[i++] = p->console_sock_path;
    }
    params[i++] = p->id;
}

static int reap_container(int ctr_pid, int *status)
{
#define EXIT_SIGNAL_OFFSET 128
    int st;
    struct rusage rus;

    // block wait
    int pid = wait4(-1, &st, 0, &rus);
    if (pid <= 0) {
        return SHIM_ERR_WAIT;
    } else if (pid != ctr_pid) {
        return SHIM_ERR;
    }

    if (WIFSIGNALED(st)) {
        *status = EXIT_SIGNAL_OFFSET + WTERMSIG(st);
    } else {
        *status = WEXITSTATUS(st);
    }

    return SHIM_OK;
}

static void process_kill_all(process_t *p)
{
    if (p->state->exec) {
        return;
    }

    const char *params[MAX_RUNTIME_ARGS] = { NULL };
    char output[BUFSIZ] = { 0 };
    int output_len = BUFSIZ;
    int i = 0;
    int j;

    params[i++] = p->runtime;
    for (j = 0; j < p->state->runtime_args_len; j++) {
        params[i++] = p->state->runtime_args[j];
    }
    params[i++] = "kill";
    params[i++] = "--all";
    params[i++] = p->id;
    params[i++] = "SIGKILL";

    (void)cmd_combined_output(p->runtime, params, output, &output_len);

    return;
}

static void process_delete(process_t *p)
{
    if (p->state->exec) {
        return;
    }

    const char *params[MAX_RUNTIME_ARGS] = { NULL };
    char output[BUFSIZ] = { 0 };
    int output_len = BUFSIZ;
    int i = 0;
    int j;
    char log_path[PATH_MAX] = { 0 };
    char *cwd = NULL;

    cwd = getcwd(NULL, 0);
    if (cwd == NULL) {
        write_message(ERR_MSG, "get cwd failed when do process delete");
        return;
    }
    int nret = snprintf(log_path, PATH_MAX, "%s/log.json", cwd);
    if (nret < 0 || nret >= PATH_MAX) {
        free(cwd);
        return;
    }

    params[i++] = p->runtime;
    for (j = 0; j < p->state->runtime_args_len; j++) {
        params[i++] = p->state->runtime_args[j];
    }
    params[i++] = "--log";
    params[i++] = log_path;
    params[i++] = "--log-format";
    params[i++] = "json";

    params[i++] = "delete";
    params[i++] = "--force";
    params[i++] = p->id;

    (void)cmd_combined_output(p->runtime, params, output, &output_len);
    free(cwd);

    return;
}

static void exec_runtime_process(process_t *p, int exec_fd)
{
    if (p->shim_io != NULL) {
        if (p->shim_io->in != -1) {
            close(p->shim_io->in);
            p->shim_io->in = -1;
            dup2(p->stdio->in, 0);
        }
        if (p->shim_io->out != -1) {
            close(p->shim_io->out);
            p->shim_io->out = -1;
            dup2(p->stdio->out, 1);
        }
        if (p->shim_io->err != -1) {
            close(p->shim_io->err);
            p->shim_io->err = -1;
            dup2(p->stdio->err, 2);
        }
        if (p->shim_io->resize != -1) {
            close(p->shim_io->resize);
            p->shim_io->resize = -1;
        }
    }

    char *cwd = getcwd(NULL, 0);
    char *log_path = (char *)util_common_calloc_s(PATH_MAX);
    char *pid_path = (char *)util_common_calloc_s(PATH_MAX);
    if (cwd == NULL || log_path == NULL || pid_path == NULL) {
        (void)dprintf(exec_fd, "memory error: %s", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    int nret = snprintf(log_path, PATH_MAX, "%s/log.json", cwd);
    if (nret < 0 || nret >= PATH_MAX) {
        _exit(EXIT_FAILURE);
    }
    nret = snprintf(pid_path, PATH_MAX, "%s/pid", cwd);
    if (nret < 0 || nret >= PATH_MAX) {
        _exit(EXIT_FAILURE);
    }

    char *process_desc = NULL;
    if (p->state->exec) {
        process_desc = (char *)calloc(1, PATH_MAX);
        if (process_desc == NULL) {
            (void)dprintf(exec_fd, "memory error: %s", strerror(errno));
            _exit(EXIT_FAILURE);
        }
        nret = snprintf(process_desc, PATH_MAX, "%s/process.json", cwd);
        if (nret < 0 || nret >= PATH_MAX) {
            _exit(EXIT_FAILURE);
        }
    }

    const char *params[MAX_RUNTIME_ARGS] = { 0 };
    get_runtime_cmd(p, log_path, pid_path, process_desc, params);
    execvp(p->runtime, (char * const *)params);
    (void)dprintf(exec_fd, "fork/exec error: %s", strerror(errno));
    _exit(EXIT_FAILURE);
}

int create_process(process_t *p)
{
    int ret = SHIM_ERR;
    char *data = NULL;
    int exec_fd[2] = { -1, -1 };
    char exec_buff[BUFSIZ + 1] = { 0 };
    int nread = -1;

    if (pipe2(exec_fd, O_CLOEXEC) != 0) {
        write_message(ERR_MSG, "create pipe failed when create process:%d", SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }

    pid_t pid = fork();
    if (pid == (pid_t) -1) {
        write_message(ERR_MSG, "fork failed when create process:%d", SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }

    /* child:runtime process */
    if (pid == (pid_t)0) {
        close_fd(&exec_fd[0]);
        exec_runtime_process(p, exec_fd[1]);
    }

    /* parent:isulad-shim process */
    close_fd(&exec_fd[1]);
    if (p->stdio != NULL) {
        close_fd(&p->stdio->in);
        close_fd(&p->stdio->out);
        close_fd(&p->stdio->err);
        close_fd(&p->stdio->resize);
    }
    nread = read_nointr(exec_fd[0], exec_buff, sizeof(exec_buff) - 1);
    if (nread > 0) {
        write_message(ERR_MSG, "runtime error");
        ret = SHIM_ERR;
        goto out;
    }

    /* block to wait runtime pid exit */
    ret = waitpid(pid, NULL, 0);
    if (ret != pid) {
        write_message(ERR_MSG, "wait runtime failed:%d", SHIM_SYS_ERR(errno));
        ret = SHIM_ERR;
        goto out;
    }

    /* save runtime pid */
    data = read_text_file("pid");
    if (data == NULL) {
        write_message(ERR_MSG, "read pid of runtime failed");
        goto out;
    }
    int ctr_pid = atoi(data);
    if (ctr_pid <= 0) {
        goto out;
    }

    p->ctr_pid = ctr_pid;
    adapt_for_isulad_stdin(p);
    ret = SHIM_OK;

out:
    close_fd(&exec_fd[0]);
    if (data != NULL) {
        free(data);
        data = NULL;
    }

    return ret;
}

static int try_wait_all_child(void)
{
    if (waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD) {
        // all child handled
        return 0;
    }

    return 1;
}

static int waitpid_with_timeout(int ctr_pid,  int *status, const uint64_t timeout)
{
    int nret = 0;
    time_t start_time = time(NULL);
    time_t end_time;
    double interval;
    int st;

    for (;;) {
        nret = waitpid(-1, &st, WNOHANG);
        if (nret == ctr_pid) {
            break;
        }
        end_time = time(NULL);
        interval = difftime(end_time, start_time);
        if (nret == 0 && interval >= timeout) {
            return SHIM_ERR_TIMEOUT;
        }
        // sleep some time instead to avoid cpu full running and then retry.
        usleep(1000);
    }

    if (WIFSIGNALED(st)) {
        *status = EXIT_SIGNAL_OFFSET + WTERMSIG(st);
    } else {
        *status = WEXITSTATUS(st);
    }

    if (*status == CONTAINER_ACTION_REBOOT) {
        nret = setenv("CONTAINER_ACTION", "reboot", 1);
        if (nret != SHIM_OK) {
            write_message(WARN_MSG, "set reboot action failed:%d", SHIM_SYS_ERR(errno));
        }
    } else if (*status == CONTAINER_ACTION_SHUTDOWN) {
        nret = setenv("CONTAINER_ACTION", "shutdown", 1);
        if (nret != SHIM_OK) {
            write_message(WARN_MSG, "set shutdown action failed:%d", SHIM_SYS_ERR(errno));
        }
    }
    return SHIM_OK;
}

/*
 * If timeout <= 0, blocking wait in reap_container.
 * If timeout > 0, non-blocking wait pid with timeout.
 */
static int wait_container_process_with_timeout(process_t *p, const uint64_t timeout, int *status)
{
    int ret = SHIM_ERR;

    if (timeout > 0) {
        return waitpid_with_timeout(p->ctr_pid, status, timeout);
    }

    for (;;) {
        ret = reap_container(p->ctr_pid, status);
        if (ret == SHIM_OK) {
            if (*status == CONTAINER_ACTION_REBOOT) {
                ret = setenv("CONTAINER_ACTION", "reboot", 1);
                if (ret != SHIM_OK) {
                    write_message(WARN_MSG, "set reboot action failed:%d", SHIM_SYS_ERR(errno));
                }
            } else if (*status == CONTAINER_ACTION_SHUTDOWN) {
                ret = setenv("CONTAINER_ACTION", "shutdown", 1);
                if (ret != SHIM_OK) {
                    write_message(WARN_MSG, "set shutdown action failed:%d", SHIM_SYS_ERR(errno));
                }
            }
            return SHIM_OK;
        }

        if (ret == SHIM_ERR_WAIT) {
            /* avoid thread entering the infinite loop */
            usleep(1000);
        }

        if (ret == SHIM_ERR) {
            // if the child process is not expected, retry.
            continue;
        }
    }

}

int process_signal_handle_routine(process_t *p, const pthread_t tid_epoll, const uint64_t timeout)
{
    int nret = 0;
    int ret = 0;
    int status = 0;

    ret = wait_container_process_with_timeout(p, timeout, &status);
    if (ret == SHIM_ERR_TIMEOUT) {
        // kill container process to ensure process_kill_all effective
        nret = kill(p->ctr_pid, SIGKILL);
        if (nret < 0 && errno != ESRCH) {
            write_message(ERR_MSG, "Can not kill process (pid=%d) with SIGKILL", p->ctr_pid);
            return SHIM_ERR;
        }
    }

    process_kill_all(p);

    // wait atmost 120 seconds
    DO_RETRY_CALL(120, 1000000, nret, try_wait_all_child);
    if (nret != 0) {
        write_message(ERR_MSG, "Failed to wait all child after 120 seconds");
    }

    process_delete(p);
    if (p->exit_fd > 0) {
        (void)write_nointr(p->exit_fd, &status, sizeof(int));
    }

    if (p->sync_fd > 0) {
        if (eventfd_write(p->sync_fd, 1)) {
            write_message(ERR_MSG, "Failed to write sync fd");
        }
    }

    nret = pthread_join(tid_epoll, NULL);
    if (nret != 0) {
        write_message(ERR_MSG, "Failed to join epoll loop thread");
    }

    close(p->sync_fd);

    if (!p->state->exec) {
        // if log did not contain "/n", print remaind container log when exit isulad-shim
        shim_write_container_log_file(p->terminal, STDID_OUT, NULL, 0);
        shim_write_container_log_file(p->terminal, STDID_ERR, NULL, 0);
    }

    if (ret == SHIM_ERR_TIMEOUT) {
        write_message(INFO_MSG, "Wait %d timeout", p->ctr_pid);
        return SHIM_ERR_TIMEOUT;
    }

    // write container process exit_code in stdout
    (void)write_nointr(STDOUT_FILENO, &status, sizeof(int));
    return SHIM_OK;
}
