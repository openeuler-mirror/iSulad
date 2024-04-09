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
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/resource.h> // IWYU pragma: keep
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <termios.h> // IWYU pragma: keep
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#include <isula_libutils/json_common.h>
#include <isula_libutils/shim_client_process_state.h>
#include <isula_libutils/utils_memory.h>
#include <isula_libutils/utils_string.h>
#include <isula_libutils/utils_file.h>
#include <isula_libutils/utils_mainloop.h>
#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/utils_buffer.h>
#include <isula_libutils/utils_linked_list.h>
#include <isula_libutils/utils_array.h>
#include <isula_libutils/utils.h>
#include <isula_libutils/log.h>

#include "common.h"
#include "terminal.h"

#define MAX_EVENTS 100
#define DEFAULT_IO_COPY_BUF (16 * 1024)
#define DEFAULT_LOG_FILE_SIZE (4 * 1024)

static shim_client_process_state *load_process()
{
    parser_error err = NULL;
    shim_client_process_state *p_state = NULL;

    p_state = shim_client_process_state_parse_file("process.json", NULL, &err);
    if (p_state == NULL) {
        ERROR("parse process state failed: %s", err);
        shim_set_error_message("parse process state failed: %s", err);
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
        ERROR("open fifo file failed:%d", SHIM_SYS_ERR(errno));
        return -1;
    }

    return fd;
}

static int receive_fd(int sock)
{
    u_char *pfd = NULL;
    int fd = -1;
    int cmsgsize = CMSG_LEN(sizeof(int));
    struct cmsghdr *cmptr = (struct cmsghdr *)isula_common_calloc_s(cmsgsize);
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
        ERROR("get console fd failed:%d", SHIM_SYS_ERR(errno));
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
    isula_string_array *array = NULL;
    int width = 0;
    int height = 0;

    array = isula_string_split_to_multi(buf, ' ');
    if (array == NULL) {
        return -1;
    }

    if (array->len != 2) {
        isula_string_array_free(array);
        return -1;
    }

    width = atoi(array->items[0]);
    height = atoi(array->items[1]);
    isula_string_array_free(array);

    if (width < 0 || width > USHRT_MAX || height < 0 || height > USHRT_MAX) {
        return -1;
    }
    wsize->ws_row = (unsigned short)height;
    wsize->ws_col = (unsigned short)width;

    return 0;
}

static int sync_exit_cb(int fd, uint32_t events, void *cbdata, isula_epoll_descr_t *descr)
{
    isula_epoll_remove_handler(descr, fd);
    return EPOLL_LOOP_HANDLE_CLOSE;
}

static bool fifo_exists(const char *path)
{
    struct stat sb;
    int ret;

    ret = stat(path, &sb);
    if (ret < 0) {
        // could be something other than exist, just return false
        return false;
    }

    return S_ISFIFO(sb.st_mode);
}

static int add_attach_terminal_fifos(const char *in, const char *out, const char *err, int *input_fd, process_t *p)
{
    __isula_auto_close int fifofd_in = -1;
    __isula_auto_close int fifofd_out = -1;
    __isula_auto_close int fifofd_err = -1;
    struct shim_fifos_fd *fifos = NULL;
    struct isula_linked_list *node = NULL;

    bool invalid = (in != NULL && !fifo_exists(in)) || (out != NULL && !fifo_exists(out)) || (err != NULL &&
                                                                                             !fifo_exists(err));
    if (invalid) {
        ERROR("File %s or %s or %s does not refer to a FIFO", in, out, err);
        return -1;
    }

    if (in != NULL) {
        fifofd_in = isula_file_open(in, O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);
        if (fifofd_in < 0) {
            ERROR("Failed to open FIFO: %s", in);
            return -1;
        }
    }

    if (out != NULL) {
        fifofd_out = isula_file_open(out, O_WRONLY | O_NONBLOCK | O_CLOEXEC, 0);
        if (fifofd_out < 0) {
            ERROR("Failed to open FIFO: %s", out);
            return -1;
        }
    }

    if (err != NULL) {
        fifofd_err = isula_file_open(err, O_WRONLY | O_NONBLOCK | O_CLOEXEC, 0);
        if (fifofd_err < 0) {
            ERROR("Failed to open FIFO: %s", err);
            return -1;
        }
    }

    fifos = isula_common_calloc_s(sizeof(*fifos));
    if (fifos == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    fifos->in_fifo = isula_strdup_s(in);
    fifos->out_fifo = isula_strdup_s(out);
    fifos->err_fifo = isula_strdup_s(err);

    fifos->in_fd = isula_transfer_fd(fifofd_in);
    fifos->out_fd = isula_transfer_fd(fifofd_out);
    fifos->err_fd = isula_transfer_fd(fifofd_err);
    node = isula_common_calloc_s(sizeof(struct isula_linked_list));
    if (node == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    node->elem = fifos;
    isula_linked_list_add(p->attach_fifos, node);

    if (input_fd != NULL) {
        *input_fd = fifos->in_fd;
    }

    return 0;
err_out:
    free_shim_fifos_fd(fifos);
    return -1;
}

static void remove_attach_terminal_fifos(isula_epoll_descr_t *descr, struct isula_linked_list *item)
{
    struct shim_fifos_fd *elem = (struct shim_fifos_fd *)item->elem;
    isula_epoll_remove_handler(descr, elem->in_fd);
    isula_linked_list_del(item);
    free_shim_fifos_fd(elem);
}

static int stdin_cb(int fd, uint32_t events, void *cbdata, isula_epoll_descr_t *descr)
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

    r_count = isula_file_read_nointr(fd, p->buf, DEFAULT_IO_COPY_BUF);
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
    w_count = isula_file_total_write_nointr(*fd_to, p->buf, r_count);
    if (w_count < 0) {
        /* When any error occurs, set the write fd -1  */
        WARN("write in_fd %d error:%d", *fd_to, SHIM_SYS_ERR(errno));
        close(*fd_to);
        *fd_to = -1;
    }

    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int attach_stdin_cb(int fd, uint32_t events, void *cbdata, isula_epoll_descr_t *descr)
{
    process_t *p = (process_t *)cbdata;
    int r_count = 0;
    int w_count = 0;
    int *fd_to = NULL;
    struct isula_linked_list *item;

    if (events & EPOLLHUP) {
        ERROR("attach stdin %d received the EPOLLHUP event", fd);
        goto err_out;
    }

    if (!(events & EPOLLIN)) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    (void)memset(p->buf, 0, DEFAULT_IO_COPY_BUF);

    r_count = isula_file_read_nointr(fd, p->buf, DEFAULT_IO_COPY_BUF);
    if (r_count <= 0) {
        ERROR("failed to read from attach stdin %d, error:%d", fd, SHIM_SYS_ERR(errno));
        goto err_out;
    }

    if (p->state->terminal) {
        fd_to = &(p->recv_fd);
    } else {
        fd_to = &(p->shim_io->in);
    }

    if (fd_to == NULL || *fd_to == -1) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }
    w_count = isula_file_total_write_nointr(*fd_to, p->buf, r_count);
    if (w_count < 0) {
        /* When any error occurs, set the write fd -1  */
        WARN("write in_fd %d error:%d", *fd_to, SHIM_SYS_ERR(errno));
        close(*fd_to);
        *fd_to = -1;
    }

    return EPOLL_LOOP_HANDLE_CONTINUE;
err_out:
    item = get_attach_fifo_item(fd, p->attach_fifos);
    if (item != NULL && item->elem != NULL) {
        remove_attach_terminal_fifos(descr, item);
    }
    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int stdout_cb(int fd, uint32_t events, void *cbdata, isula_epoll_descr_t *descr)
{
    process_t *p = (process_t *)cbdata;
    int r_count = 0;
    int w_count = 0;

    (void)memset(p->buf, 0, DEFAULT_IO_COPY_BUF);

    r_count = isula_file_read_nointr(fd, p->buf, DEFAULT_IO_COPY_BUF);
    if (r_count <= 0 ) {
        isula_epoll_remove_handler(descr, fd);
        // fd cannot be closed here, which will cause the container process to exit abnormally
        // due to terminal fd receiving the sighup signal.
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    shim_write_container_log_file(p->terminal, STDID_OUT, p->buf, r_count);

    if (p->isulad_io->out != -1) {
        w_count = isula_file_total_write_nointr(p->isulad_io->out, p->buf, r_count);
        if (w_count < 0) {
            /* When any error occurs, set the write fd -1  */
            WARN("write out_fd %d error:%d", p->isulad_io->out, SHIM_SYS_ERR(errno));
            close(p->isulad_io->out);
            p->isulad_io->out = -1;
        }
    }

    if (isula_linked_list_empty(p->attach_fifos)) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    struct isula_linked_list *it = NULL;
    struct isula_linked_list *next = NULL;

    isula_linked_list_for_each_safe(it, p->attach_fifos, next) {
        struct shim_fifos_fd *elem = (struct shim_fifos_fd *)it->elem;
        w_count = isula_file_total_write_nointr(elem->out_fd, p->buf, r_count);
        if (w_count < 0) {
            remove_attach_terminal_fifos(descr, it);
        }
    }

    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int stderr_cb(int fd, uint32_t events, void *cbdata, isula_epoll_descr_t *descr)
{
    process_t *p = (process_t *)cbdata;
    int r_count = 0;
    int w_count = 0;

    (void)memset(p->buf, 0, DEFAULT_IO_COPY_BUF);

    r_count = isula_file_read_nointr(fd, p->buf, DEFAULT_IO_COPY_BUF);
    if (r_count <= 0 ) {
        isula_epoll_remove_handler(descr, fd);
        // fd cannot be closed here, which will cause the container process to exit abnormally
        // due to terminal fd receiving the sighup signal.
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    shim_write_container_log_file(p->terminal, STDID_ERR, p->buf, r_count);

    if (p->isulad_io->err != -1) {
        w_count = isula_file_total_write_nointr(p->isulad_io->err, p->buf, r_count);
        if (w_count < 0) {
            /* When any error occurs, set the write fd -1  */
            WARN("write err_fd %d error:%d", p->isulad_io->err, SHIM_SYS_ERR(errno));
            close(p->isulad_io->err);
            p->isulad_io->err = -1;
        }
    }

    if (isula_linked_list_empty(p->attach_fifos)) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    struct isula_linked_list *it = NULL;
    struct isula_linked_list *next = NULL;

    isula_linked_list_for_each_safe(it, p->attach_fifos, next) {
        struct shim_fifos_fd *elem = (struct shim_fifos_fd *)it->elem;
        w_count = isula_file_total_write_nointr(elem->out_fd, p->buf, r_count);
        if (w_count < 0) {
            remove_attach_terminal_fifos(descr, it);
        }
    }

    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int resize_cb(int fd, uint32_t events, void *cbdata, isula_epoll_descr_t *descr)
{
    process_t *p = (process_t *)cbdata;
    int r_count = 0;
    int resize_fd = -1;

    (void)memset(p->buf, 0, DEFAULT_IO_COPY_BUF);
    r_count = isula_file_read_nointr(fd, p->buf, DEFAULT_IO_COPY_BUF);
    if (r_count <= 0) {
        close(fd);
        return EPOLL_LOOP_HANDLE_CONTINUE;
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

static bool attach_fifopath_security_check(process_t *p, const char *fifopath)
{
    struct stat st = { 0 };
    char real_path[PATH_MAX] = { 0 };

    if (isula_validate_absolute_path(fifopath) != 0) {
        ERROR("attach fifo path \"%s\" must be an valid absolute path", fifopath);
        return false;
    }

    if (realpath(fifopath, real_path) == NULL) {
        ERROR("Failed to get realpath for '%s': %d.", real_path, SHIM_SYS_ERR(errno));
        return false;
    }

    if (!isula_has_prefix(real_path, p->workdir)) {
        ERROR("attach fifo path \"%s\" must be under the state path: %s", real_path, p->workdir);
        return false;
    }

    if (lstat(real_path, &st) != 0) {
        ERROR("Failed to lstat %s : %d", real_path, SHIM_SYS_ERR(errno));
        return false;
    }

    if (!S_ISFIFO(st.st_mode)) {
        ERROR("attach fifo path \"%s\" must be an FIFO", real_path);
        return false;
    }

    if ((st.st_mode & 0777) != ATTACH_FIFOPATH_MODE) {
        ERROR("attach fifo path \"%s\" permission invalid", real_path);
        return false;
    }

    if (st.st_uid != 0) {
        ERROR("attach fifo path \"%s\" uid invalid", real_path);
        return false;
    }

    return true;
}

// attach_cb needs to read the content from communication fd and parse it.
// at the same time, it also needs to establish a connection between the attach fd and the container fd.
// 1. if it fails, it needs to write an error message to attach log file,
// and write -1 to connection fd to let isulad know that it has failed.
// 2. if it succeeds, write 0 to let isulad know that it is ready.
// attach_cb returns EPOLL_LOOP_HANDLE_CONTINUE regardless of success or failure,
// because whether the attach operation is successful or not does not affect the first process of the container.
static int attach_cb(int fd, uint32_t events, void *cbdata, isula_epoll_descr_t *descr)
{
    process_t *p = (process_t *)cbdata;
    int r_count = 0;
    char tmp_buf[BUFSIZ + 1] = { 0 };
    char *in = NULL, *out = NULL, *err = NULL;
    int fifofd_in = -1;
    isula_string_array *tmp_str_array = NULL;
    int ret = 0;
    // attach execution return value
    int status = -1;
    bool valid = true;

    // after receiving the event that isulad closes the connection,
    // close the communication fd and remove it from epoll.
    if (events & EPOLLHUP) {
        close(fd);
        isula_epoll_remove_handler(descr, fd);
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    if (!(events & EPOLLIN)) {
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    r_count = isula_file_read_nointr(fd, tmp_buf, sizeof(tmp_buf) - 1);
    if (r_count <= 0) {
        ERROR("Failed to read msg from attach conn fd");
        goto out;
    }

    // limit the number of attach connections to MAX_ATTACH_NUM
    if (isula_linked_list_len(p->attach_fifos) >= MAX_ATTACH_NUM) {
        ERROR("The number of attach connections exceeds the limit:%d, and this connection is rejected.",
                             MAX_ATTACH_NUM);
        goto out;
    }

    tmp_str_array = isula_string_split_to_multi(tmp_buf, ' ');
    if (tmp_str_array->len != 3) {
        ERROR("Invalid attach msg from isulad");
        goto out;
    }

    for (int i = 0; i < tmp_str_array->len; i++) {
        valid = valid && attach_fifopath_security_check(p, tmp_str_array->items[i]);
    }

    if (!valid) {
        ERROR("Invalid attach fifo path from isulad");
        goto out;
    }

    in = tmp_str_array->items[0];
    out = tmp_str_array->items[1];
    err = tmp_str_array->items[2];

    if (add_attach_terminal_fifos(in, out, err, &fifofd_in, p) < 0) {
        ERROR("Failed to add attach terminal fifos");
        goto out;
    }

    // attach stdin --> container stdin
    ret = isula_epoll_add_handler(descr, fifofd_in, attach_stdin_cb, p);
    if (ret != SHIM_OK) {
        ERROR("add fifofd_in fd %d to epoll loop failed:%d", fifofd_in, SHIM_SYS_ERR(errno));
        struct isula_linked_list *item = get_attach_fifo_item(fd, p->attach_fifos);
        if (item != NULL && item->elem != NULL) {
            remove_attach_terminal_fifos(descr, item);
        }
        goto out;
    }

    status = 0;
out:
    isula_string_array_free(tmp_str_array);
    (void)isula_file_write_nointr(fd, &status, sizeof(int));
    return EPOLL_LOOP_HANDLE_CONTINUE;
}

// do_attach_socket_accept returns EPOLL_LOOP_HANDLE_CONTINUE regardless of success or failure,
// because whether the attach operation is successful or not does not affect the first process of the container.
static int do_attach_socket_accept(int fd, uint32_t events, void *cbdata, isula_epoll_descr_t *descr)
{
    process_t *p = (process_t *)cbdata;
    int conn_fd = -1;
    int ret = SHIM_ERR;

    conn_fd = accept(p->attach_socket_fd, NULL, NULL);
    if (conn_fd < 0) {
        ERROR("accept from fd %d failed:%d", p->attach_socket_fd, SHIM_SYS_ERR(errno));
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }

    ret = isula_epoll_add_handler(descr, conn_fd, attach_cb, p);
    if (ret != SHIM_OK) {
        ERROR("add recv_fd %d to epoll loop failed:%d", conn_fd, SHIM_SYS_ERR(errno));
        close(conn_fd);
        return EPOLL_LOOP_HANDLE_CONTINUE;
    }
    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int task_console_accept(int fd, uint32_t events, void *cbdata, isula_epoll_descr_t *descr)
{
    process_t *p = (process_t *)cbdata;
    int conn_fd = -1;
    int ret = SHIM_ERR;

    conn_fd = accept(p->listen_fd, NULL, NULL);
    if (conn_fd < 0) {
        ERROR("accept from fd %d failed:%d", p->listen_fd, SHIM_SYS_ERR(errno));
        goto out;
    }

    p->recv_fd = receive_fd(conn_fd);
    if (check_fd(p->recv_fd) != true) {
        ERROR("check console fd failed");
        goto out;
    }

    /* do console io copy */

    // p->isulad_io->in ----> p->recv_fd
    ret = isula_epoll_add_handler(descr, p->isulad_io->in, stdin_cb, p);
    if (ret != SHIM_OK) {
        ERROR("add in fd %d to epoll loop failed:%d", p->isulad_io->in, SHIM_SYS_ERR(errno));
        goto out;
    }
    // p->recv_fd ----> p->isulad_io->out
    ret = isula_epoll_add_handler(descr, p->recv_fd, stdout_cb, p);
    if (ret != SHIM_OK) {
        ERROR("add recv_fd fd %d to epoll loop failed:%d", p->recv_fd, SHIM_SYS_ERR(errno));
        goto out;
    }
    // p->isulad_io->resize ----> p->recv_fd
    ret = isula_epoll_add_handler(descr, p->isulad_io->resize, resize_cb, p);
    if (ret != SHIM_OK) {
        ERROR("add resize fd %d to epoll loop failed:%d", p->isulad_io->resize, SHIM_SYS_ERR(errno));
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
                stdio_fd[i][j] = -1;
            }
        }
    }
}

static stdio_t *initialize_io(process_t *p)
{
    int stdio_fd[4][2] = { { -1, -1 }, { -1, -1 }, { -1, -1 }, { -1, -1 } };

    stdio_t *stdio = (stdio_t *)isula_common_calloc_s(sizeof(stdio_t));
    p->stdio = (stdio_t *)isula_common_calloc_s(sizeof(stdio_t));
    if (p->stdio == NULL || stdio == NULL) {
        goto failure;
    }

    /*
     * don't open resize pipe;
     * stdio pipes must not set to non-block, because 'cat big-file' will failed;
     */
    if ((pipe2(stdio_fd[0], O_CLOEXEC) != 0) || (pipe2(stdio_fd[1], O_CLOEXEC) != 0) ||
        (pipe2(stdio_fd[2], O_CLOEXEC) != 0)) {
        ERROR("open pipe failed when init io:%d", SHIM_SYS_ERR(errno));
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
    p->console_sock_path = (char *)isula_common_calloc_s(MAX_CONSOLE_SOCK_LEN + 1);
    if (p->console_sock_path == NULL) {
        return SHIM_ERR;
    }
    int nret = snprintf(p->console_sock_path, MAX_CONSOLE_SOCK_LEN, "/run/isulad%s-pty.sock", str_rand);
    if (nret < 0 || (size_t)nret >= MAX_CONSOLE_SOCK_LEN) {
        free(p->console_sock_path);
        p->console_sock_path = NULL;
        return SHIM_ERR;
    }

    return SHIM_OK;
}

static int console_init(process_t *p, isula_epoll_descr_t *descr)
{
    int ret = SHIM_ERR;
    int fd = -1;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        ERROR("create socket failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    (void)memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)strcpy(addr.sun_path, p->console_sock_path);

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        ERROR("bind console fd failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    ret = listen(fd, 2);
    if (ret < 0) {
        ERROR("listen console fd failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    p->listen_fd = fd;

    ret = isula_epoll_add_handler(descr, p->listen_fd, task_console_accept, p);
    if (ret != SHIM_OK) {
        ERROR("add listen_fd fd %d to epoll loop failed:%d",  p->listen_fd, SHIM_SYS_ERR(errno));
        goto failure;
    }

    return SHIM_OK;
failure:
    close_fd(&fd);
    (void)unlink(p->console_sock_path);

    return SHIM_ERR;
}

static int open_terminal_io(process_t *p, isula_epoll_descr_t *descr)
{
    int ret = SHIM_ERR;

    ret = new_temp_console_path(p);
    if (ret != SHIM_OK) {
        ERROR("get temp console sock path failed");
        return SHIM_ERR;
    }

    /* begin listen from p->console_sock_path */
    return console_init(p, descr);
}

static int open_generic_io(process_t *p, isula_epoll_descr_t *descr)
{
    int ret = SHIM_ERR;

    // io: in: w  out/err: r
    stdio_t *io = initialize_io(p);
    if (io == NULL) {
        return SHIM_ERR;
    }
    p->shim_io = io;

    // p->isulad_io->in ----> p->shim_io->in
    ret = isula_epoll_add_handler(descr, p->isulad_io->in, stdin_cb, p);
    if (ret != SHIM_OK) {
        ERROR("add in fd %d to epoll loop failed:%d", p->isulad_io->in, SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }
    // p->shim_io->out ----> p->isulad_io->out
    ret = isula_epoll_add_handler(descr, p->shim_io->out, stdout_cb, p);
    if (ret != SHIM_OK) {
        ERROR("add  out fd %d to epoll loop failed:%d", p->shim_io->out, SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }
    // p->shim_io->err ----> p->isulad_io->err
    ret = isula_epoll_add_handler(descr, p->shim_io->err, stderr_cb, p);
    if (ret != SHIM_OK) {
        ERROR("add err fd %d to epoll loop failed:%d", p->shim_io->err, SHIM_SYS_ERR(errno));
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
    process_t *p = (process_t *)data;
    isula_epoll_descr_t descr;

    ret = isula_epoll_open(&descr);
    if (ret != 0) {
        ERROR("epoll loop open failed:%d", SHIM_SYS_ERR(errno));
        shim_set_error_message("epoll loop open failed:%d", SHIM_SYS_ERR(errno));
        error_exit(EXIT_FAILURE);
    }

    // sync fd: epoll loop will exit when recive sync fd event.
    ret = isula_epoll_add_handler(&descr, p->sync_fd, sync_exit_cb, p);
    if (ret != 0) {
        ERROR("add sync_fd %d to epoll loop failed:%d", p->sync_fd, SHIM_SYS_ERR(errno));
        shim_set_error_message("add sync_fd %d to epoll loop failed:%d", p->sync_fd, SHIM_SYS_ERR(errno));
        error_exit(EXIT_FAILURE);
    }

    if (p->state->attach_socket != NULL) {
        ret = isula_epoll_add_handler(&descr, p->attach_socket_fd, do_attach_socket_accept, p);
        if (ret != SHIM_OK) {
            ERROR("add attach_socket_fd %d to epoll loop failed:%d", p->attach_socket_fd, SHIM_SYS_ERR(errno));
            shim_set_error_message("add attach_socket_fd %d to epoll loop failed:%d", p->attach_socket_fd, SHIM_SYS_ERR(errno));
            error_exit(EXIT_FAILURE);
        }
    }

    if (p->state->terminal) {
        ret = open_terminal_io(p, &descr);
    } else {
        ret = open_generic_io(p, &descr);
    }
    if (ret != SHIM_OK) {
        ERROR("open io failed:%d", SHIM_SYS_ERR(errno));
        shim_append_error_message("open io failed:%d", SHIM_SYS_ERR(errno));
        error_exit(EXIT_FAILURE);
    }

    (void)sem_post(&p->sem_mainloop);

    // th frist epoll_loop will exit in the following scenarios: 
    // 1. Receive sync fd event 
    // 2. stdin fd receive EPOLLHUP event
    // 3. stdin fd read failed
    ret = isula_epoll_loop(&descr, -1);
    if (ret != 0) {
        ERROR("epoll loop failed");
        shim_set_error_message("epoll loop failed");
        error_exit(EXIT_FAILURE);
    }

    // use a timeout epoll loop to ensure complete data reception 
    // th second epoll_loop will exit in the following scenarios: 
    // 1. both stdout fd and stderr fd failed to read
    // 2. no event received within 100 milliseconds
    ret = isula_epoll_loop(&descr, 100);
    if (ret != 0) {
        ERROR("Repeat the epoll loop to ensure that all data is transferred");
    }

    return NULL;
}

static void adapt_for_isulad_stdin(process_t *p)
{
    /* iSulad: close stdin pipe if we do not want open_stdin with container stdin just like lxc */
    if (!p->state->open_stdin && !isula_file_exists(p->state->isulad_stdin)) {
        if (p->shim_io != NULL && p->shim_io->in != -1) {
            close(p->shim_io->in);
            p->shim_io->in = -1;
        }
    }
}

static int terminal_init(log_terminal **terminal, shim_client_process_state *p_state)
{
    log_terminal *log_term = NULL;

    log_term = isula_common_calloc_s(sizeof(log_terminal));
    if (log_term == NULL) {
        ERROR("Failed to calloc log_terminal");
        goto clean_out;
    }

    if (pthread_rwlock_init(&log_term->log_terminal_rwlock, NULL) != 0) {
        ERROR("Failed to init isulad conf rwlock");
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

    if (isulad_stdio != NULL && isula_file_exists(isulad_stdio)) {
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
    p->isulad_io = (stdio_t *)isula_common_calloc_s(sizeof(stdio_t));
    if (p->isulad_io == NULL) {
        return SHIM_ERR;
    }

    p->isulad_io->in = -1;
    p->isulad_io->out = -1;
    p->isulad_io->err = -1;
    p->isulad_io->resize = -1;

    ret = open_isulad_fd(STDID_IN, p->state->isulad_stdin, &p->isulad_io->in);
    if (ret != SHIM_OK) {
        ERROR("Failed to open in isulad fd: %s",  p->state->isulad_stdin);
        goto failure;
    }

    ret = open_isulad_fd(STDID_OUT, p->state->isulad_stdout, &p->isulad_io->out);
    if (ret != SHIM_OK) {
        ERROR("Failed to open out isulad fd: %s",  p->state->isulad_stdout);
        goto failure;
    }

    ret = open_isulad_fd(STDID_ERR, p->state->isulad_stderr, &p->isulad_io->err);
    if (ret != SHIM_OK) {
        ERROR("Failed to open err isulad fd: %s",  p->state->isulad_stderr);
        goto failure;
    }

    ret = open_isulad_fd(EXEC_RESIZE, p->state->resize_fifo, &p->isulad_io->resize);
    if (ret != SHIM_OK) {
        ERROR("Failed to open resize isulad fd: %s",  p->state->resize_fifo);
        goto failure;
    }
    return SHIM_OK;
failure:
    if (p->isulad_io != NULL) {
        if (p->isulad_io->in > 0) {
            close(p->isulad_io->in);
            p->isulad_io->in = -1;
        }
        if (p->isulad_io->out > 0) {
            close(p->isulad_io->out);
            p->isulad_io->out = -1;
        }
        if (p->isulad_io->err > 0) {
            close(p->isulad_io->err);
            p->isulad_io->err = -1;
        }
        if (p->isulad_io->resize > 0) {
            close(p->isulad_io->resize);
            p->isulad_io->resize = -1;
        }
        free(p->isulad_io);
        p->isulad_io = NULL;
    }
    return SHIM_ERR;
}

static int init_root_path(process_t *p)
{
    __isula_auto_free char *state_path = NULL;

    state_path = isula_strdup_s(p->workdir);

    if (p->state != NULL && p->state->exec) {
        // get the grandfather directory of workdir
        // workdir: /run/isulad/runc/{container_id}/exec/{exec_id}
        // state_path: /run/isulad/runc/{container_id}
        char *tmp_dir = strrchr(state_path, '/');
        if (tmp_dir == NULL) {
            ERROR("Invalid exec workdir");
            return SHIM_ERR;
        }
        *tmp_dir = '\0';
        tmp_dir = strrchr(state_path, '/');
        if (tmp_dir == NULL) {
            ERROR("Invalid exec workdir");
            return SHIM_ERR;
        }
        *tmp_dir = '\0';
    }

    isula_buffer *buffer = isula_buffer_alloc(PATH_MAX);
    if (buffer == NULL) {
        ERROR("Failed to malloc buffer\n");
        return SHIM_ERR;
    }

    if (buffer->nappend(buffer, PATH_MAX, "%s/%s", state_path, p->state->runtime) < 0) {
        ERROR("Failed to append state_path\n");
        isula_buffer_free(buffer);
        return SHIM_ERR;
    }

    p->root_path = buffer->to_str(buffer);
    isula_buffer_free(buffer);
    if (strlen(p->root_path) > PATH_MAX) {
        ERROR("Root_path is too long\n");
        return SHIM_ERR;
    }
    return SHIM_OK;
}

process_t *new_process(char *id, char *bundle, char *runtime_cmd)
{
    shim_client_process_state *p_state;
    process_t *p = NULL;
    int ret;

    p_state = load_process();
    if (p_state == NULL) {
        return NULL;
    }

    p = (process_t *)isula_common_calloc_s(sizeof(process_t));
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
    p->runtime_cmd = runtime_cmd;
    p->state = p_state;
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
        ERROR("Failed to create eventfd: %s", strerror(errno));
        goto failure;
    }

    ret = init_isulad_stdio(p);
    if (ret != SHIM_OK) {
        goto failure;
    }

    p->buf = isula_common_calloc_s(DEFAULT_IO_COPY_BUF + 1);
    if (p->buf == NULL) {
        goto failure;
    }

    // during the execution of isulad-shim, the current working directory will not change.
    p->workdir = getcwd(NULL, 0);
    if (p->workdir == NULL) {
        ERROR("get cwd failed when do create process");
        goto failure;
    }

    ret = init_root_path(p);
    if (ret != SHIM_OK) {
        goto failure;
    }

    p->attach_fifos = isula_common_calloc_s(sizeof(struct isula_linked_list));
    if (p->attach_fifos == NULL) {
        goto failure;
    }

    isula_linked_list_init(p->attach_fifos);

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

static void set_common_params(process_t *p, const char *params[], int *index, const char* log_path)
{
    int j;

    params[(*index)++]  = p->runtime_cmd;
    for (j = 0; j < p->state->runtime_args_len; j++) {
        params[(*index)++]  = p->state->runtime_args[j];
    }

    if (log_path != NULL) {
        params[(*index)++] = "--log";
        params[(*index)++] = log_path;
        params[(*index)++] = "--log-format";
        params[(*index)++] = "json";
    }

    // In addition to kata, other commonly used oci runtimes (runc, crun, youki, gvisor)
    // need to set the --root option
    if (strcasecmp(p->state->runtime, "kata-runtime") != 0) {
        params[(*index)++] = "--root";
        params[(*index)++] = p->root_path;
    }
}

static void get_runtime_cmd(process_t *p, const char *log_path, const char *pid_path, const char *process_desc,
                            const char *params[])
{
    int i = 0;
    set_common_params(p, params, &i, log_path);
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
        if (p->state->cwd != NULL) {
            params[i++] = "--cwd";
            params[i++] = p->state->cwd;
        }
    } else {
        // the --systemd-cgroup argument is not in oci spec, but up to now,
        // the latest version of runc, crun, youki, runsc, kata-runtime all support this argument
        // should ensure that this is supported for oci runtime
        if (p->state->systemd_cgroup) {
            params[i++] = "--systemd-cgroup";
        }
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

    set_common_params(p, params, &i, NULL);

    params[i++] = "kill";
    params[i++] = "--all";
    params[i++] = p->id;
    params[i++] = "SIGKILL";

    (void)cmd_combined_output(p->runtime_cmd, params, output, &output_len);

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
    char log_path[PATH_MAX] = { 0 };

    int nret = snprintf(log_path, PATH_MAX, "%s/log.json", p->workdir);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        return;
    }

    set_common_params(p, params, &i, log_path);

    params[i++] = "delete";
    params[i++] = "--force";
    params[i++] = p->id;

    (void)cmd_combined_output(p->runtime_cmd, params, output, &output_len);

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
    } else {
        // When the terminal parameter is set, since the container's standard streams are pseudo-terminals
        // and the container's log can be obtained through log.json,
        // the standard streams of the child process are set to /dev/null to prevent incorrect information acquisition.
        if (isula_null_stdfds() != 0) {
            (void)dprintf(exec_fd, "failed to set std console to /dev/null");
            exit(EXIT_FAILURE);           
        }
    }

    char *cwd = getcwd(NULL, 0);
    char *log_path = (char *)isula_common_calloc_s(PATH_MAX);
    char *pid_path = (char *)isula_common_calloc_s(PATH_MAX);
    if (cwd == NULL || log_path == NULL || pid_path == NULL) {
        (void)dprintf(exec_fd, "memory error: %s", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    int nret = snprintf(log_path, PATH_MAX, "%s/log.json", p->workdir);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        _exit(EXIT_FAILURE);
    }
    nret = snprintf(pid_path, PATH_MAX, "%s/pid", p->workdir);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        _exit(EXIT_FAILURE);
    }

    char *process_desc = NULL;
    if (p->state->exec) {
        process_desc = (char *)isula_common_calloc_s(PATH_MAX);
        if (process_desc == NULL) {
            (void)dprintf(exec_fd, "memory error: %s", strerror(errno));
            _exit(EXIT_FAILURE);
        }
        nret = snprintf(process_desc, PATH_MAX, "%s/process.json", p->workdir);
        if (nret < 0 || (size_t)nret >= PATH_MAX) {
            _exit(EXIT_FAILURE);
        }
    }

    const char *params[MAX_RUNTIME_ARGS] = { 0 };
    get_runtime_cmd(p, log_path, pid_path, process_desc, params);
    execvp(p->runtime_cmd, (char * const *)params);
    (void)dprintf(exec_fd, "run process: %s error: %s", p->runtime_cmd, strerror(errno));
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
        ERROR("create pipe failed when create process:%d", SHIM_SYS_ERR(errno));
        shim_set_error_message("create pipe failed when create process:%d", SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }

    pid_t pid = fork();
    if (pid == (pid_t) -1) {
        ERROR("fork failed when create process:%d", SHIM_SYS_ERR(errno));
        shim_set_error_message("fork failed when create process:%d", SHIM_SYS_ERR(errno));
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
    nread = isula_file_read_nointr(exec_fd[0], exec_buff, sizeof(exec_buff) - 1);

    /* block to wait runtime pid exit */
    ret = waitpid(pid, NULL, 0);
    if (ret != pid) {
        ERROR("wait runtime failed:%d", SHIM_SYS_ERR(errno));
        shim_set_error_message("wait runtime failed:%d", SHIM_SYS_ERR(errno));
        ret = SHIM_ERR;
        goto out;
    }

    // if an error occurs in exec_runtime_process, jump directly to the out branch after waitpid.
    if (nread > 0) {
        ERROR("%s", exec_buff);
        shim_set_error_message("%s", exec_buff);
        ret = SHIM_ERR;
        goto out;
    }

    /* save runtime pid */
    data = read_text_file("pid");
    if (data == NULL) {
        ERROR("read pid of runtime failed");

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
    int st;

    for (;;) {
        nret = waitpid(-1, &st, WNOHANG);
        if (nret == ctr_pid) {
            break;
        }
        time_t end_time = time(NULL);
        double interval = difftime(end_time, start_time);
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
            WARN("set reboot action failed:%d", SHIM_SYS_ERR(errno));
        }
    } else if (*status == CONTAINER_ACTION_SHUTDOWN) {
        nret = setenv("CONTAINER_ACTION", "shutdown", 1);
        if (nret != SHIM_OK) {
            WARN("set shutdown action failed:%d", SHIM_SYS_ERR(errno));
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
    // currently, kata runtime does not support setting timeout during exec
    if (strcasecmp(p->state->runtime, "kata-runtime") != 0 && timeout > 0) {
        return waitpid_with_timeout(p->ctr_pid, status, timeout);
    }

    for (;;) {
        int ret = reap_container(p->ctr_pid, status);
        if (ret == SHIM_OK) {
            if (*status == CONTAINER_ACTION_REBOOT) {
                ret = setenv("CONTAINER_ACTION", "reboot", 1);
                if (ret != SHIM_OK) {
                    WARN("set reboot action failed:%d", SHIM_SYS_ERR(errno));
                }
            } else if (*status == CONTAINER_ACTION_SHUTDOWN) {
                ret = setenv("CONTAINER_ACTION", "shutdown", 1);
                if (ret != SHIM_OK) {
                    WARN("set shutdown action failed:%d", SHIM_SYS_ERR(errno));
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
            ERROR("Can not kill process (pid=%d) with SIGKILL, %d", p->ctr_pid, SHIM_SYS_ERR(errno));
            return SHIM_ERR;
        }
    }

    process_kill_all(p);

    // wait atmost 120 seconds
    DO_RETRY_CALL(120, 1000000, nret, try_wait_all_child);
    if (nret != 0) {
        ERROR("Failed to wait all child after 120 seconds");
    }

    process_delete(p);
    if (p->exit_fd > 0) {
        (void)isula_file_write_nointr(p->exit_fd, &status, sizeof(int));
    }

    if (p->sync_fd > 0) {
        if (eventfd_write(p->sync_fd, 1)) {
            ERROR("Failed to write sync fd");
        }
    }

    nret = pthread_join(tid_epoll, NULL);
    if (nret != 0) {
        ERROR("Failed to join epoll loop thread");
    }

    close(p->sync_fd);

    if (!p->state->exec) {
        // if log did not contain "/n", print remaind container log when exit isulad-shim
        shim_write_container_log_file(p->terminal, STDID_OUT, NULL, 0);
        shim_write_container_log_file(p->terminal, STDID_ERR, NULL, 0);
    }

    if (ret == SHIM_ERR_TIMEOUT) {
        ERROR("Wait %d timeout", p->ctr_pid);
        shim_set_error_message("Wait %d timeout", p->ctr_pid);
        return SHIM_ERR_TIMEOUT;
    }

    // write container process exit_code in stdout
    (void)isula_file_write_nointr(STDOUT_FILENO, &status, sizeof(int));
    return SHIM_OK;
}

int prepare_attach_socket(process_t *p)
{
    struct sockaddr_un addr;
    int ret = -1;

    if (strlen(p->state->attach_socket) >= sizeof(addr.sun_path)) {
        ERROR("Invalid attach socket path: %s", p->state->attach_socket);
        shim_set_error_message("Invalid attach socket path: %s", p->state->attach_socket);
        return SHIM_ERR;
    }

    p->attach_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (p->attach_socket_fd < 0) {
        ERROR("Failed to create socket:%d", SHIM_SYS_ERR(errno));
        shim_set_error_message("Failed to create socket:%d", SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }

    (void)memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)strncpy(addr.sun_path, p->state->attach_socket, sizeof(addr.sun_path) - 1);

    ret = bind(p->attach_socket_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        ERROR("bind console fd failed:%d", SHIM_SYS_ERR(errno));
        shim_set_error_message("bind console fd failed:%d", SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }

    ret = chmod(p->state->attach_socket, SOCKET_DIRECTORY_MODE);
    if (ret != 0) {
        ERROR("Failed to chmod for socket: %s", p->state->attach_socket);
        shim_set_error_message("Failed to chmod for socket: %s", p->state->attach_socket);
        return SHIM_ERR;
    }

    //If the backlog argument is greater than the value in
    // /proc/sys/net/core/somaxconn, then it is silently capped to that
    // value.  Since Linux 5.4, the default in this file is 4096; in
    // earlier kernels, the default value is 128.  Before Linux 2.4.25,
    // this limit was a hard coded value, SOMAXCONN, with the value 128.
    // The maximum number of attach we allow here is MAX_ATTACH_NUM, so just use it directly
    ret = listen(p->attach_socket_fd, MAX_ATTACH_NUM);
    if (ret < 0) {
        ERROR("listen console fd failed:%d", SHIM_SYS_ERR(errno));
        shim_set_error_message("listen console fd failed:%d", SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }
    return SHIM_OK;
}