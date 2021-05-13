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
#include <termios.h> // IWYU pragma: keep
#include <sys/resource.h> // IWYU pragma: keep
#include <isula_libutils/json_common.h>
#include <isula_libutils/shim_client_process_state.h>
#include <stdint.h>
#include <stdio.h>

#include "common.h"
#include "terminal.h"
#include "utils_array.h"
#include "utils_string.h"

#define MAX_EVENTS 100
#define DEFAULT_IO_COPY_BUF (16 * 1024)
#define DEFAULT_LOG_FILE_SIZE (4 * 1024)

extern int g_log_fd;

static shim_client_process_state *load_process()
{
    parser_error err = NULL;
    shim_client_process_state *p_state = NULL;

    p_state = shim_client_process_state_parse_file("process.json", NULL, &err);
    if (p_state == NULL) {
        write_message(g_log_fd, ERR_MSG, "parse process state failed");
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
        write_message(g_log_fd, ERR_MSG, "open fifo file failed:%d", SHIM_SYS_ERR(errno));
        return -1;
    }

    return fd;
}

static int receive_fd(int sock)
{
    u_char *pfd = NULL;
    int fd = -1;
    int cmsgsize = CMSG_LEN(sizeof(int));
    struct cmsghdr *cmptr = (struct cmsghdr *)calloc(1, cmsgsize);
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
        write_message(g_log_fd, ERR_MSG, "get console fd failed:%d", SHIM_SYS_ERR(errno));
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

static int add_io_dispatch(int epfd, io_thread_t *io_thd, int from, int to)
{
    int ret = SHIM_ERR;

    if (io_thd == NULL || io_thd->ioc == NULL) {
        return SHIM_ERR;
    }

    io_copy_t *ioc = io_thd->ioc;

    if (pthread_mutex_lock(&(ioc->mutex)) != 0) {
        return SHIM_ERR;
    }
    /* add src fd */
    if (from != -1 && ioc->fd_from == -1) {
        ioc->fd_from = from;
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = io_thd;

        ret = epoll_ctl(epfd, EPOLL_CTL_ADD, from, &ev);
        if (ret != SHIM_OK) {
            write_message(g_log_fd, ERR_MSG, "add fd %d to epoll loop failed:%d", from, SHIM_SYS_ERR(errno));
            pthread_mutex_unlock(&(ioc->mutex));
            return SHIM_ERR;
        }
    }

    /* add dest fd */
    if (to != -1) {
        /* new fd_node_t for dest fd */
        fd_node_t *fn = (fd_node_t *)calloc(1, sizeof(fd_node_t));
        if (fn == NULL) {
            pthread_mutex_unlock(&(ioc->mutex));
            return SHIM_ERR;
        }
        fn->fd = to;
        fn->is_log = false;
        if (io_thd->terminal != NULL && to == io_thd->terminal->fd) {
            fn->is_log = true;
        }
        fn->next = NULL;

        if (ioc->fd_to == NULL) {
            ioc->fd_to = fn;
        } else {
            fd_node_t *tmp = ioc->fd_to;
            while (tmp->next != NULL) {
                tmp = tmp->next;
            }
            tmp->next = fn;
        }
    }
    pthread_mutex_unlock(&(ioc->mutex));

    return SHIM_OK;
}

static void remove_io_dispatch(io_thread_t *io_thd, int from, int to)
{
    if (io_thd == NULL || io_thd->ioc == NULL) {
        return;
    }
    io_copy_t *ioc = io_thd->ioc;

    if (pthread_mutex_lock(&(ioc->mutex))) {
        return;
    }

    fd_node_t *tmp = NULL;
    do {
        /* remove src fd */
        if (from != -1 && from == ioc->fd_from) {
            struct epoll_event ev;
            ev.events = EPOLLIN;
            ev.data.fd = ioc->fd_from;
            (void)epoll_ctl(io_thd->epfd, EPOLL_CTL_DEL, ioc->fd_from, &ev);
        }

        /* remove dest fd */
        if (ioc->fd_to == NULL) {
            break;
        }
        if (ioc->fd_to->fd == to) {
            /* remove the first fd node */
            tmp = ioc->fd_to;
            ioc->fd_to = ioc->fd_to->next;
            break;
        }
        fd_node_t *pre = ioc->fd_to;
        tmp = ioc->fd_to->next;
        while (tmp != NULL && tmp->fd != to) {
            pre = tmp;
            tmp = tmp->next;
        }
        if (tmp != NULL) {
            pre->next = tmp->next;
        }
    } while (0);
    if (tmp != NULL) {
        free(tmp);
        tmp = NULL;
    }
    pthread_mutex_unlock(&(ioc->mutex));
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

static void *do_io_copy(void *data)
{
    io_thread_t *io_thd = (io_thread_t *)data;
    if (io_thd == NULL || io_thd->ioc == NULL) {
        return NULL;
    }
    io_copy_t *ioc = io_thd->ioc;
    char *buf = calloc(1, DEFAULT_IO_COPY_BUF + 1);
    if (buf == NULL) {
        return NULL;
    }

    for (;;) {
        memset(buf, 0, DEFAULT_IO_COPY_BUF);
        (void)sem_wait(&(io_thd->sem_thd));
        if (io_thd->is_stdin && io_thd->shutdown) {
            break;
        }

        int r_count = read(ioc->fd_from, buf, DEFAULT_IO_COPY_BUF);
        if (r_count == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            break;
        } else if (r_count == 0) {
            /* End of file. The remote has closed the connection */
            break;
        } else if (ioc->id != EXEC_RESIZE) {
            fd_node_t *fn = ioc->fd_to;
            for (; fn != NULL; fn = fn->next) {
                if (fn->is_log) {
                    shim_write_container_log_file(io_thd->terminal, ioc->id, buf, r_count);
                } else {
                    int w_count = write_nointr_in_total(fn->fd, buf, r_count);
                    if (w_count < 0) {
                        /* When any error occurs, remove the write fd */
                        remove_io_dispatch(io_thd, -1, fn->fd);
                    }
                }
            }
        } else {
            int resize_fd = ioc->fd_to->fd;
            struct winsize wsize = { 0x00 };
            if (get_exec_winsize(buf, &wsize) < 0) {
                break;
            }
            if (ioctl(resize_fd, TIOCSWINSZ, &wsize) < 0) {
                break;
            }
        }

        /*
         In the case of stdout and stderr, maybe numbers of read bytes are not the last msg in pipe.
         So, when the value of r_count is larger than zero, we need to try reading again to avoid loss msgs.
        */
        if (io_thd->shutdown && r_count <= 0) {
            break;
        }
    }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = ioc->fd_from;
    (void)epoll_ctl(io_thd->epfd, EPOLL_CTL_DEL, ioc->fd_from, &ev);

    free(buf);

    return NULL;
}

static void sem_post_inotify_io_copy(int fd, uint32_t event, void *data)
{
    io_thread_t *thd = (io_thread_t *)data;
    if (thd->ioc == NULL || fd != thd->ioc->fd_from) {
        return;
    }

    if (event & EPOLLIN) {
        (void)sem_post(&thd->sem_thd);
    } else if (event & EPOLLHUP) {
        thd->shutdown = true;
        (void)sem_post(&thd->sem_thd);
    }

    return;
}

static int create_io_copy_thread(process_t *p, int std_id)
{
    int ret = SHIM_ERR;
    io_thread_t *io_thd = NULL;
    io_copy_t *ioc = NULL;

    ioc = (io_copy_t *)calloc(1, sizeof(io_copy_t));
    if (ioc == NULL) {
        goto failure;
    }
    ioc->id = std_id;
    ioc->fd_from = -1;
    ioc->fd_to = NULL;
    if (pthread_mutex_init(&(ioc->mutex), NULL) != 0) {
        goto failure;
    }

    io_thd = (io_thread_t *)calloc(1, sizeof(io_thread_t));
    if (io_thd == NULL) {
        goto failure;
    }
    if (sem_init(&io_thd->sem_thd, 0, 0) != 0) {
        write_message(g_log_fd, ERR_MSG, "sem init failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }
    io_thd->epfd = p->io_loop_fd;
    io_thd->ioc = ioc;
    io_thd->shutdown = false;
    io_thd->is_stdin = std_id == STDID_IN ? true : false;
    io_thd->terminal = std_id != STDID_IN ? p->terminal : NULL;

    p->io_threads[std_id] = io_thd;

    ret = pthread_create(&(io_thd->tid), NULL, do_io_copy, io_thd);
    if (ret != SHIM_OK) {
        write_message(g_log_fd, ERR_MSG, "thread io copy create failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    ret = SHIM_OK;

    return ret;

failure:
    if (ioc != NULL) {
        pthread_mutex_destroy(&(ioc->mutex));
        free(ioc);
    }
    if (io_thd != NULL) {
        free(io_thd);
    }

    return SHIM_ERR;
}

static int start_io_copy_threads(process_t *p)
{
    int ret = SHIM_ERR;
    int i;

    /* 4 threads for stdin, stdout, stderr and exec resize */
    for (i = 0; i < 4; i++) {
        ret = create_io_copy_thread(p, i);
        if (ret != SHIM_OK) {
            return SHIM_ERR;
        }
    }
    return SHIM_OK;
}

static void destroy_io_thread(process_t *p, int std_id)
{
    io_thread_t *io_thd = p->io_threads[std_id];
    if (io_thd == NULL) {
        return;
    }

    io_thd->shutdown = true;
    (void)sem_post(&io_thd->sem_thd);
    pthread_join(io_thd->tid, NULL);
    if (io_thd->ioc != NULL) {
        free(io_thd->ioc);
    }
    free(io_thd);
    p->io_threads[std_id] = NULL;
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
static int connect_to_isulad(process_t *p, int std_id, const char *isulad_stdio, int fd)
{
    mode_t mode;
    int fd_isulad = -1;
    int *fd_from = NULL;
    int *fd_to = NULL;

    if (std_id == STDID_IN || std_id == EXEC_RESIZE) {
        mode = O_RDONLY;
        fd_from = &fd_isulad;
        fd_to = &fd;
    } else {
        mode = O_WRONLY;
        fd_from = &fd;
        fd_to = &fd_isulad;
    }

    if (isulad_stdio != NULL && file_exists(isulad_stdio)) {
        fd_isulad = open_fifo_noblock(isulad_stdio, mode);
        if (fd_isulad < 0) {
            return SHIM_ERR;
        }
        /* open dummy fd to avoid resize epoll hub */
        if (std_id == EXEC_RESIZE && open_fifo_noblock(isulad_stdio, O_WRONLY) < 0) {
            return SHIM_ERR;
        }
    }

    if (*fd_from != -1) {
        if (std_id != STDID_IN && std_id != EXEC_RESIZE && p->io_threads[std_id]->terminal != NULL) {
            (void)add_io_dispatch(p->io_loop_fd, p->io_threads[std_id], *fd_from, p->terminal->fd);
        }
        return add_io_dispatch(p->io_loop_fd, p->io_threads[std_id], *fd_from, *fd_to);
    }

    /* if no I/O source is available, the I/O thread nead to be destroyed */
    destroy_io_thread(p, std_id);

    return SHIM_OK;
}

static void *task_console_accept(void *data)
{
    int conn_fd = -1;
    int recv_fd = -1;
    int ret = SHIM_ERR;
    console_accept_t *ac = (console_accept_t *)data;

    conn_fd = accept(ac->listen_fd, NULL, NULL);
    if (conn_fd < 0) {
        write_message(g_log_fd, ERR_MSG, "accept from fd %d failed:%d", ac->listen_fd, SHIM_SYS_ERR(errno));
        goto out;
    }

    recv_fd = receive_fd(conn_fd);
    if (check_fd(recv_fd) != true) {
        write_message(g_log_fd, ERR_MSG, "check console fd failed");
        goto out;
    }

    /* do console io copy */

    /* p.state.stdin---->runtime.console */
    ret = connect_to_isulad(ac->p, STDID_IN, ac->p->state->isulad_stdin, recv_fd);
    if (ret != SHIM_OK) {
        goto out;
    }

    /* p.state.stdout<------runtime.console */
    ret = connect_to_isulad(ac->p, STDID_OUT, ac->p->state->isulad_stdout, recv_fd);
    if (ret != SHIM_OK) {
        goto out;
    }

    /* p.state.resize_fifo------>runtime.console */
    ret = connect_to_isulad(ac->p, EXEC_RESIZE, ac->p->state->resize_fifo, recv_fd);
    if (ret != SHIM_OK) {
        goto out;
    }

    /*
     * if the terminal is used, we do not need to active the io copy of stderr pipe,
     * for stderr and stdout are mixed together
     */
    destroy_io_thread(ac->p, STDID_ERR);

out:
    /* release listen socket at the first time */
    close_fd(&ac->listen_fd);
    if (ac->p->console_sock_path != NULL) {
        (void)unlink(ac->p->console_sock_path);
        free(ac->p->console_sock_path);
        ac->p->console_sock_path = NULL;
    }
    free(ac);
    if (ret != SHIM_OK) {
        /*
         * When an error occurs during the receiving of the fd , the process
         * exits directly. The files created in the working directory will be
         * deleted by its parent process isulad
         */
        exit(EXIT_FAILURE);
    }
    return NULL;
}

static void *io_epoll_loop(void *data)
{
    process_t *p = (process_t *)data;
    int wait_fds = 0;
    struct epoll_event evs[MAX_EVENTS];
    int i;

    p->io_loop_fd = epoll_create1(EPOLL_CLOEXEC);
    if (p->io_loop_fd < 0) {
        write_message(g_log_fd, ERR_MSG, "epoll create failed:%d", SHIM_SYS_ERR(errno));
        exit(EXIT_FAILURE);
    }
    (void)sem_post(&p->sem_mainloop);

    for (;;) {
        wait_fds = epoll_wait(p->io_loop_fd, evs, MAX_EVENTS, -1);
        if (wait_fds < 0) {
            if (errno == EINTR) {
                continue;
            }
            _exit(EXIT_FAILURE);
        }

        for (i = 0; i < wait_fds; i++) {
            io_thread_t *thd_io = (io_thread_t *)evs[i].data.ptr;
            sem_post_inotify_io_copy(thd_io->ioc->fd_from, evs[i].events, thd_io);
        }
    }
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
    p->console_sock_path = (char *)calloc(1, MAX_CONSOLE_SOCK_LEN + 1);
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

static int console_init(process_t *p)
{
    int ret = SHIM_ERR;
    int fd = -1;
    struct sockaddr_un addr;
    console_accept_t *ac = NULL;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        write_message(g_log_fd, ERR_MSG, "create socket failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    (void)memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)strcpy(addr.sun_path, p->console_sock_path);

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        write_message(g_log_fd, ERR_MSG, "bind console fd failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    ret = listen(fd, 2);
    if (ret < 0) {
        write_message(g_log_fd, ERR_MSG, "listen console fd failed:%d", SHIM_SYS_ERR(errno));
        goto failure;
    }

    ac = (console_accept_t *)calloc(1, sizeof(console_accept_t));
    if (ac == NULL) {
        goto failure;
    }
    ac->p = p;
    ac->listen_fd = fd;

    pthread_t tid_accept;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&tid_accept, &attr, task_console_accept, ac);
    pthread_attr_destroy(&attr);
    if (ret != SHIM_OK) {
        goto failure;
    }

    return SHIM_OK;
failure:
    close_fd(&fd);
    if (ac != NULL) {
        free(ac);
        ac = NULL;
    }
    (void)unlink(p->console_sock_path);

    return SHIM_ERR;
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

    stdio_t *stdio = (stdio_t *)calloc(1, sizeof(stdio_t));
    p->stdio = (stdio_t *)calloc(1, sizeof(stdio_t));
    if (p->stdio == NULL || stdio == NULL) {
        goto failure;
    }

    /* don't open resize pipe */
    if ((pipe2(stdio_fd[0], O_CLOEXEC | O_NONBLOCK) != 0) || (pipe2(stdio_fd[1], O_CLOEXEC | O_NONBLOCK) != 0) ||
        (pipe2(stdio_fd[2], O_CLOEXEC | O_NONBLOCK) != 0)) {
        write_message(g_log_fd, ERR_MSG, "open pipe failed when init io:%d", SHIM_SYS_ERR(errno));
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

static int open_terminal_io(process_t *p)
{
    int ret = SHIM_ERR;

    ret = new_temp_console_path(p);
    if (ret != SHIM_OK) {
        write_message(g_log_fd, ERR_MSG, "get temp console sock path failed");
        return SHIM_ERR;
    }

    /* begin listen and accept fd from p->console_sock_path */
    return console_init(p);
}

static int open_generic_io(process_t *p)
{
    int ret = SHIM_ERR;

    // io: in: w  out/err: r
    stdio_t *io = initialize_io(p);
    if (io == NULL) {
        return SHIM_ERR;
    }
    p->shim_io = io;
    /* stdin */
    ret = connect_to_isulad(p, STDID_IN, p->state->isulad_stdin, io->in);
    if (ret != SHIM_OK) {
        return SHIM_ERR;
    }
    /* stdout */
    ret = connect_to_isulad(p, STDID_OUT, p->state->isulad_stdout, io->out);
    if (ret != SHIM_OK) {
        return SHIM_ERR;
    }
    /* stderr */
    ret = connect_to_isulad(p, STDID_ERR, p->state->isulad_stderr, io->err);
    if (ret != SHIM_OK) {
        return SHIM_ERR;
    }

    return SHIM_OK;
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

    log_term = calloc(1, sizeof(log_terminal));
    if (log_term == NULL) {
        write_message(g_log_fd, ERR_MSG, "Failed to calloc log_terminal");
        goto clean_out;
    }

    if (pthread_rwlock_init(&log_term->log_terminal_rwlock, NULL) != 0) {
        write_message(g_log_fd, ERR_MSG, "Failed to init isulad conf rwlock");
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

process_t *new_process(char *id, char *bundle, char *runtime)
{
    shim_client_process_state *p_state;
    process_t *p = NULL;
    int i;
    int ret;

    p_state = load_process();
    if (p_state == NULL) {
        return NULL;
    }

    p = (process_t *)calloc(1, sizeof(process_t));
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

    p->console_sock_path = NULL;
    p->exit_fd = -1;
    p->io_loop_fd = -1;
    p->ctr_pid = -1;
    p->stdio = NULL;
    p->shim_io = NULL;

    for (i = 0; i < 3; i++) {
        p->io_threads[i] = NULL;
    }

    return p;

failure:
    free(p);
    p = NULL;
    return NULL;
}

int open_io(process_t *p)
{
    int ret = SHIM_ERR;

    ret = start_io_copy_threads(p);
    if (ret != SHIM_OK) {
        return SHIM_ERR;
    }

    if (p->state->terminal) {
        return open_terminal_io(p);
    }

    return open_generic_io(p);
}

int process_io_init(process_t *p)
{
    int ret = SHIM_ERR;

    pthread_t tid_loop;
    ret = pthread_create(&tid_loop, NULL, io_epoll_loop, p);
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
        params[i++] = "-d";
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
    char *cwd;

    cwd = getcwd(NULL, 0);
    if (cwd == NULL) {
        write_message(g_log_fd, ERR_MSG, "get cwd failed when do process delete");
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
    char *log_path = (char *)calloc(1, PATH_MAX);
    char *pid_path = (char *)calloc(1, PATH_MAX);
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
        write_message(g_log_fd, ERR_MSG, "create pipe failed when create process:%d", SHIM_SYS_ERR(errno));
        return SHIM_ERR;
    }

    pid_t pid = fork();
    if (pid == (pid_t) -1) {
        write_message(g_log_fd, ERR_MSG, "fork failed when create process:%d", SHIM_SYS_ERR(errno));
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
    nread = read_nointr(exec_fd[0], exec_buff, sizeof(exec_buff));
    if (nread > 0) {
        write_message(g_log_fd, ERR_MSG, "runtime error");
        ret = SHIM_ERR;
        goto out;
    }

    /* block to wait runtime pid exit */
    ret = waitpid(pid, NULL, 0);
    if (ret != pid) {
        write_message(g_log_fd, ERR_MSG, "wait runtime failed:%d", SHIM_SYS_ERR(errno));
        ret = SHIM_ERR;
        goto out;
    }

    /* save runtime pid */
    data = read_text_file("pid");
    if (data == NULL) {
        write_message(g_log_fd, ERR_MSG, "read pid of runtime failed");
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

int process_signal_handle_routine(process_t *p)
{
    int ret = SHIM_ERR;
    bool exit_shim = false;
    int i;

    for (;;) {
        int status;
        ret = reap_container(p->ctr_pid, &status);
        if (ret == SHIM_OK) {
            exit_shim = true;
            if (status == CONTAINER_ACTION_REBOOT) {
                ret = setenv("CONTAINER_ACTION", "reboot", 1);
                if (ret != SHIM_OK) {
                    write_message(g_log_fd, WARN_MSG, "set reboot action failed:%d", SHIM_SYS_ERR(errno));
                }
            } else if (status == CONTAINER_ACTION_SHUTDOWN) {
                ret = setenv("CONTAINER_ACTION", "shutdown", 1);
                if (ret != SHIM_OK) {
                    write_message(g_log_fd, WARN_MSG, "set shutdown action failed:%d", SHIM_SYS_ERR(errno));
                }
            }
        } else if (ret == SHIM_ERR_WAIT) {
            /* avoid thread entering the infinite loop */
            usleep(1000);
            continue;
        }
        if (exit_shim) {
            process_kill_all(p);
            process_delete(p);
            if (p->exit_fd > 0) {
                (void)write_nointr(p->exit_fd, &status, sizeof(int));
            }
            for (i = 0; i < 3; i++) {
                destroy_io_thread(p, i);
            }
            return status;
        }
    }
}
