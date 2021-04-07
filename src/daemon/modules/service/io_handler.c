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
 * Create: 2020
 * Description: provide container stream callback function definition
 ********************************************************************************/
#define _GNU_SOURCE
#include "io_handler.h"

#include <stdio.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>

#include "isula_libutils/log.h"
#include "console.h"
#include "isulad_config.h"
#include "io_wrapper.h"
#include "utils.h"
#include "utils_file.h"
#include "err_msg.h"

static char *create_single_fifo(const char *statepath, const char *subpath, const char *stdflag)
{
    int nret = 0;
    char *fifo_name = NULL;
    char fifo_path[PATH_MAX] = { 0 };

    fifo_name = util_common_calloc_s(PATH_MAX);
    if (fifo_name == NULL) {
        return NULL;
    }

    nret = console_fifo_name(statepath, subpath, stdflag, fifo_name, PATH_MAX, fifo_path, sizeof(fifo_path), true);
    if (nret != 0) {
        ERROR("Failed to get console fifo name.");
        free(fifo_name);
        fifo_name = NULL;
        goto out;
    }
    if (console_fifo_create(fifo_name)) {
        ERROR("Failed to create console fifo.");
        free(fifo_name);
        fifo_name = NULL;
        goto out;
    }
out:
    return fifo_name;
}

static int do_create_daemon_fifos(const char *statepath, const char *subpath, bool attach_stdin, bool attach_stdout,
                                  bool attach_stderr, char *fifos[])
{
    int ret = -1;

    if (attach_stdin) {
        fifos[0] = create_single_fifo(statepath, subpath, "in");
        if (fifos[0] == NULL) {
            goto cleanup;
        }
    }

    if (attach_stdout) {
        fifos[1] = create_single_fifo(statepath, subpath, "out");
        if (fifos[1] == NULL) {
            goto cleanup;
        }
    }

    if (attach_stderr) {
        fifos[2] = create_single_fifo(statepath, subpath, "err");
        if (fifos[2] == NULL) {
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    if (ret != 0) {
        console_fifo_delete(fifos[0]);
        free(fifos[0]);
        fifos[0] = NULL;
        console_fifo_delete(fifos[1]);
        free(fifos[1]);
        fifos[1] = NULL;
        console_fifo_delete(fifos[2]);
        free(fifos[2]);
        fifos[2] = NULL;
    }
    return ret;
}

int create_daemon_fifos(const char *id, const char *runtime, bool attach_stdin, bool attach_stdout, bool attach_stderr,
                        const char *operation, char *fifos[], char **fifopath)
{
    int nret;
    int ret = -1;
    char *statepath = NULL;
    char subpath[PATH_MAX] = { 0 };
    char fifodir[PATH_MAX] = { 0 };
    struct timespec now;
    pthread_t tid;

    nret = clock_gettime(CLOCK_REALTIME, &now);
    if (nret != 0) {
        ERROR("Failed to get time");
        goto cleanup;
    }

    tid = pthread_self();

    statepath = conf_get_routine_statedir(runtime);
    if (statepath == NULL) {
        ERROR("State path is NULL");
        goto cleanup;
    }

    nret = snprintf(subpath, PATH_MAX, "%s/%s/%u_%u_%u", id, operation, (unsigned int)tid, (unsigned int)now.tv_sec,
                    (unsigned int)(now.tv_nsec));
    if (nret >= PATH_MAX || nret < 0) {
        ERROR("Failed to print string");
        goto cleanup;
    }

    nret = snprintf(fifodir, PATH_MAX, "%s/%s", statepath, subpath);
    if (nret >= PATH_MAX || nret < 0) {
        ERROR("Failed to print string");
        goto cleanup;
    }
    *fifopath = util_strdup_s(fifodir);

    if (do_create_daemon_fifos(statepath, subpath, attach_stdin, attach_stdout, attach_stderr, fifos) != 0) {
        goto cleanup;
    }

    ret = 0;
cleanup:
    free(statepath);
    return ret;
}

void delete_daemon_fifos(const char *fifopath, const char *fifos[])
{
    if (fifopath == NULL || fifos == NULL) {
        return;
    }
    if (fifos[0] != NULL) {
        console_fifo_delete(fifos[0]);
    }
    if (fifos[1] != NULL) {
        console_fifo_delete(fifos[1]);
    }
    if (fifos[2] != NULL) {
        console_fifo_delete(fifos[2]);
    }
    if (util_recursive_rmdir(fifopath, 0)) {
        WARN("Failed to rmdir:%s", fifopath);
    }
}

typedef enum { IO_FD = 0, IO_FIFO, IO_FUNC, IO_MAX } io_type;

struct io_copy_arg {
    io_type srctype;
    void *src;
    io_type dsttype;
    void *dst;
    int dstfifoflag;
    transfer_channel_type channel;
};

struct io_copy_thread_arg {
    struct io_copy_arg *copy_arg;
    bool detach;
    size_t len;
    int sync_fd;
    sem_t wait_sem;
};

static void io_copy_thread_cleanup(struct io_write_wrapper *writers, struct io_copy_thread_arg *thread_arg, int *infds,
                                   int *outfds, int *srcfds, transfer_channel_type *channels, size_t len)
{
    size_t i = 0;
    for (i = 0; i < len; i++) {
        if (writers != NULL && writers[i].close_func != NULL) {
            (void)writers[i].close_func(writers[i].context, NULL);
        }
    }
    free(srcfds);
    for (i = 0; i < len; i++) {
        if ((infds != NULL) && (infds[i] >= 0)) {
            console_fifo_close(infds[i]);
        }
        if ((outfds != NULL) && (outfds[i] >= 0)) {
            console_fifo_close(outfds[i]);
        }
    }
    free(infds);
    free(outfds);
    free(writers);
    free(channels);
}

static int io_copy_init_fds(size_t len, int **infds, int **outfds, int **srcfds,
                            struct io_write_wrapper **writers, transfer_channel_type **channels)
{
    size_t i;

    if (len > SIZE_MAX / sizeof(struct io_write_wrapper)) {
        ERROR("Invalid arguments");
        return -1;
    }
    *srcfds = util_common_calloc_s(sizeof(int) * len);
    if (*srcfds == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    *infds = util_common_calloc_s(sizeof(int) * len);
    if (*infds == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < len; i++) {
        (*infds)[i] = -1;
    }
    *outfds = util_common_calloc_s(sizeof(int) * len);
    if (*outfds == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < len; i++) {
        (*outfds)[i] = -1;
    }

    *writers = util_common_calloc_s(sizeof(struct io_write_wrapper) * len);
    if (*writers == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    *channels = util_common_calloc_s(sizeof(transfer_channel_type) * len);
    if (*channels == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < len; i++) {
        (*channels)[i] = MAX_CHANNEL;
    }
    return 0;

}
typedef int (*src_io_type_handle)(int index, struct io_copy_arg *copy_arg, int *infds, int *srcfds);

struct src_io_copy_handler {
    io_type type;
    src_io_type_handle handle;
};

static int handle_src_io_fd(int index, struct io_copy_arg *copy_arg, int *infds, int *srcfds)
{
    srcfds[index] = *(int *)(copy_arg[index].src);

    return 0;
}

static int handle_src_io_fifo(int index, struct io_copy_arg *copy_arg, int *infds, int *srcfds)
{
    if (console_fifo_open((const char *)copy_arg[index].src, &(infds[index]), O_RDONLY | O_NONBLOCK)) {
        ERROR("failed to open console fifo.");
        return -1;
    }
    srcfds[index] = infds[index];

    return 0;
}

static int handle_src_io_fun(int index, struct io_copy_arg *copy_arg, int *infds, int *srcfds)
{
    ERROR("Got invalid src fd type");
    return -1;
}

static int handle_src_io_max(int index, struct io_copy_arg *copy_arg, int *infds, int *srcfds)
{
    ERROR("Got invalid src fd type");
    return -1;
}

static int io_copy_make_srcfds(size_t len, struct io_copy_arg *copy_arg, int *infds,
                               int *srcfds, transfer_channel_type *channels)
{
    size_t i;

    struct src_io_copy_handler src_handler_jump_table[] = {
        { IO_FD, handle_src_io_fd },
        { IO_FIFO, handle_src_io_fifo },
        { IO_FUNC, handle_src_io_fun },
        { IO_MAX, handle_src_io_max },
    };

    for (i = 0; i < len; i++) {
        if (src_handler_jump_table[(int)(copy_arg[i].srctype)].handle(i, copy_arg, infds, srcfds) != 0) {
            return -1;
        }
        channels[i] = copy_arg[i].channel;
    }

    return 0;
}

static ssize_t write_to_fifo(void *context, const void *data, size_t len)
{
    ssize_t ret;
    int fd;

    fd = *(int *)context;
    ret = util_write_nointr_in_total(fd, data, len);
    if ((ret <= 0) || (ret != (ssize_t)len)) {
        ERROR("Failed to write %d: %s", fd, strerror(errno));
        return -1;
    }
    return ret;
}

static ssize_t write_to_fd(void *context, const void *data, size_t len)
{
    ssize_t ret;
    ret = util_write_nointr(*(int *)context, data, len);
    if ((ret <= 0) || (ret != (ssize_t)len)) {
        ERROR("Failed to write: %s", strerror(errno));
        return -1;
    }
    return ret;
}

typedef int (*dst_io_type_handle)(int index, struct io_copy_arg *copy_arg, int *outfds,
                                  struct io_write_wrapper *writers);

struct dst_io_copy_handler {
    io_type type;
    dst_io_type_handle handle;
};

static int handle_dst_io_fd(int index, struct io_copy_arg *copy_arg, int *outfds, struct io_write_wrapper *writers)
{
    writers[index].context = copy_arg[index].dst;
    writers[index].write_func = write_to_fd;

    return 0;
}

static int handle_dst_io_fifo(int index, struct io_copy_arg *copy_arg, int *outfds, struct io_write_wrapper *writers)
{
    if (console_fifo_open_withlock((const char *)copy_arg[index].dst, &outfds[index],
                                   copy_arg[index].dstfifoflag | O_NONBLOCK)) {
        ERROR("Failed to open console fifo.");
        return -1;
    }
    writers[index].context = &outfds[index];
    writers[index].write_func = write_to_fifo;

    return 0;
}

static int handle_dst_io_fun(int index, struct io_copy_arg *copy_arg, int *outfds, struct io_write_wrapper *writers)
{
    struct io_write_wrapper *io_write = copy_arg[index].dst;
    writers[index].context = io_write->context;
    writers[index].write_func = io_write->write_func;
    writers[index].close_func = io_write->close_func;

    return 0;
}

static int handle_dst_io_max(int index, struct io_copy_arg *copy_arg, int *outfds, struct io_write_wrapper *writers)
{
    ERROR("Got invalid dst fd type");
    return -1;
}

static int io_copy_make_dstfds(size_t len, struct io_copy_arg *copy_arg, int *outfds, struct io_write_wrapper *writers)
{
    size_t i;

    struct dst_io_copy_handler dst_handler_jump_table[] = {
        { IO_FD, handle_dst_io_fd },
        { IO_FIFO, handle_dst_io_fifo },
        { IO_FUNC, handle_dst_io_fun },
        { IO_MAX, handle_dst_io_max },
    };

    for (i = 0; i < len; i++) {
        if (dst_handler_jump_table[(int)(copy_arg[i].dsttype)].handle(i, copy_arg, outfds, writers) != 0) {
            return -1;
        }
    }

    return 0;
}

static void *io_copy_thread_main(void *arg)
{
    int ret = -1;
    struct io_copy_thread_arg *thread_arg = (struct io_copy_thread_arg *)arg;
    struct io_copy_arg *copy_arg = thread_arg->copy_arg;
    size_t len = 0;
    int *infds = NULL;
    int *outfds = NULL; // recored fds to close
    int *srcfds = NULL;
    struct io_write_wrapper *writers = NULL;
    transfer_channel_type *channels = NULL;
    int sync_fd = thread_arg->sync_fd;
    bool posted = false;

    if (thread_arg->detach) {
        ret = pthread_detach(pthread_self());
        if (ret != 0) {
            CRIT("Set thread detach fail");
            goto err;
        }
    }

    (void)prctl(PR_SET_NAME, "IoCopy");

    len = thread_arg->len;
    if (io_copy_init_fds(len, &infds, &outfds, &srcfds, &writers, &channels) != 0) {
        goto err;
    }

    if (io_copy_make_srcfds(len, copy_arg, infds, srcfds, channels) != 0) {
        goto err;
    }

    if (io_copy_make_dstfds(len, copy_arg, outfds, writers) != 0) {
        goto err;
    }

    sem_post(&thread_arg->wait_sem);
    posted = true;
    (void)console_loop_io_copy(sync_fd, srcfds, writers, channels, len);
err:
    if (!posted) {
        sem_post(&thread_arg->wait_sem);
    }
    io_copy_thread_cleanup(writers, thread_arg, infds, outfds, srcfds, channels, len);
    DAEMON_CLEAR_ERRMSG();
    return NULL;
}

static int start_io_copy_thread(int sync_fd, bool detach, struct io_copy_arg *copy_arg, size_t len, pthread_t *tid)
{
    int res = 0;
    struct io_copy_thread_arg thread_arg;

    if (copy_arg == NULL || len == 0) {
        return 0;
    }

    thread_arg.detach = detach;
    thread_arg.copy_arg = copy_arg;
    thread_arg.len = len;
    thread_arg.sync_fd = sync_fd;
    if (sem_init(&thread_arg.wait_sem, 0, 0)) {
        ERROR("Failed to init start semaphore");
        return -1;
    }

    res = pthread_create(tid, NULL, io_copy_thread_main, (void *)(&thread_arg));
    if (res != 0) {
        CRIT("Thread creation failed");
        return -1;
    }

    sem_wait(&thread_arg.wait_sem);
    sem_destroy(&thread_arg.wait_sem);
    return 0;
}

static void add_io_copy_element(struct io_copy_arg *element, io_type srctype, void *src, io_type dsttype, void *dst,
                                int dstfifoflag, transfer_channel_type channel)
{
    element->srctype = srctype;
    element->src = src;
    element->dsttype = dsttype;
    element->dst = dst;
    element->dstfifoflag = dstfifoflag;
    element->channel = channel;
}

/*
    -----------------------------------------------------------------------------------
    |  CHANNEL |      iSula                          iSulad                    lxc    |
    -----------------------------------------------------------------------------------
    |          |                fifoin | stdin_fd                  fifos[0]           |
    |    IN    |       RDWR       -------->       RD      RDWR     -------->      RD  |
    -----------------------------------------------------------------------------------
    |          |             fifoout | stdout_handler              fifos[1]           |
    |    OUT   |       RD         <--------       WR       RD      <--------      WR  |
    -----------------------------------------------------------------------------------
    |          |             fifoerr stderr_handler                fifos[2]           |
    |    ERR   |       RD         <--------       WR       RD      <--------     WR   |
    -----------------------------------------------------------------------------------
*/
int ready_copy_io_data(int sync_fd, bool detach, const char *fifoin, const char *fifoout, const char *fifoerr,
                       int stdin_fd, struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                       const char *fifos[], pthread_t *tid)
{
    size_t len = 0;
    struct io_copy_arg io_copy[6];

    if (fifoin != NULL) {
        // fifoin   : iSula -> iSulad read
        // fifos[0] : iSulad -> lxc write
        add_io_copy_element(&io_copy[len++], IO_FIFO, (void *)fifoin, IO_FIFO, (void *)fifos[0], O_RDWR, STDIN_CHANNEL);
    }

    if (fifoout != NULL) {
        // fifos[1]  : lxc -> iSulad read
        // fifoout   : iSulad -> iSula write
        add_io_copy_element(&io_copy[len++], IO_FIFO, (void *)fifos[1], IO_FIFO, (void *)fifoout, O_WRONLY, STDOUT_CHANNEL);
    }

    if (fifoerr != NULL) {
        add_io_copy_element(&io_copy[len++], IO_FIFO, (void *)fifos[2], IO_FIFO, (void *)fifoerr, O_WRONLY, STDERR_CHANNEL);
    }

    if (stdin_fd > 0) {
        add_io_copy_element(&io_copy[len++], IO_FD, &stdin_fd, IO_FIFO, (void *)fifos[0], O_RDWR, STDIN_CHANNEL);
    }

    if (stdout_handler != NULL) {
        add_io_copy_element(&io_copy[len++], IO_FIFO, (void *)fifos[1], IO_FUNC, stdout_handler, O_WRONLY, STDOUT_CHANNEL);
    }

    if (stderr_handler != NULL) {
        add_io_copy_element(&io_copy[len++], IO_FIFO, (void *)fifos[2], IO_FUNC, stderr_handler, O_WRONLY, STDERR_CHANNEL);
    }

    if (start_io_copy_thread(sync_fd, detach, io_copy, len, tid) != 0) {
        return -1;
    }

    return 0;
}
