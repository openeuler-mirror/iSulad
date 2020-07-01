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
#include <unistd.h>
#include <sys/time.h>
#include <lcr/lcrcontainer.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/stat.h>
#include <malloc.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <libgen.h>

#include "isula_libutils/log.h"
#include "console.h"
#include "isulad_config.h"
#include "config.h"
#include "image_api.h"
#include "path.h"
#include "isulad_tar.h"
#include "isula_libutils/container_inspect.h"
#include "container_api.h"
#include "error.h"
#include "isula_libutils/logger_json_file.h"
#include "constants.h"
#include "runtime_api.h"
#include "events_sender_api.h"
#include "service_container_api.h"

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

typedef enum { IO_FD, IO_FIFO, IO_FUNC, IO_MAX } io_type;

struct io_copy_arg {
    io_type srctype;
    void *src;
    io_type dsttype;
    void *dst;
};

struct io_copy_thread_arg {
    struct io_copy_arg *copy_arg;
    bool detach;
    size_t len;
    int sync_fd;
    sem_t wait_sem;
};

static void io_copy_thread_cleanup(struct io_write_wrapper *writers, struct io_copy_thread_arg *thread_arg, int *infds,
                                   int *outfds, int *srcfds, size_t len)
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
}

static int io_copy_init_fds(size_t len, int **infds, int **outfds, int **srcfds, struct io_write_wrapper **writers)
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
    return 0;
}

static int io_copy_make_srcfds(size_t len, struct io_copy_arg *copy_arg, int *infds, int *srcfds)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (copy_arg[i].srctype == IO_FIFO) {
            if (console_fifo_open((const char *)copy_arg[i].src, &(infds[i]), O_RDONLY | O_NONBLOCK)) {
                ERROR("failed to open console fifo.");
                return -1;
            }
            srcfds[i] = infds[i];
        } else if (copy_arg[i].srctype == IO_FD) {
            srcfds[i] = *(int *)(copy_arg[i].src);
        } else {
            ERROR("Got invalid src fd type");
            return -1;
        }
    }
    return 0;
}

static ssize_t write_to_fifo(void *context, const void *data, size_t len)
{
    ssize_t ret;
    int fd;

    fd = *(int *)context;
    ret = util_write_nointr(fd, data, len);
    // Ignore EAGAIN to prevent hang, do not report error
    if (errno == EAGAIN) {
        return (ssize_t)len;
    }

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

static int io_copy_make_dstfds(size_t len, struct io_copy_arg *copy_arg, int *outfds, struct io_write_wrapper *writers)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (copy_arg[i].dsttype == IO_FIFO) {
            if (console_fifo_open_withlock((const char *)copy_arg[i].dst, &outfds[i], O_RDWR | O_NONBLOCK)) {
                ERROR("Failed to open console fifo.");
                return -1;
            }
            writers[i].context = &outfds[i];
            writers[i].write_func = write_to_fifo;
        } else if (copy_arg[i].dsttype == IO_FD) {
            writers[i].context = copy_arg[i].dst;
            writers[i].write_func = write_to_fd;
        } else if (copy_arg[i].dsttype == IO_FUNC) {
            struct io_write_wrapper *io_write = copy_arg[i].dst;
            writers[i].context = io_write->context;
            writers[i].write_func = io_write->write_func;
            writers[i].close_func = io_write->close_func;
        } else {
            ERROR("Got invalid dst fd type");
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
    if (io_copy_init_fds(len, &infds, &outfds, &srcfds, &writers) != 0) {
        goto err;
    }

    if (io_copy_make_srcfds(len, copy_arg, infds, srcfds) != 0) {
        goto err;
    }

    if (io_copy_make_dstfds(len, copy_arg, outfds, writers) != 0) {
        goto err;
    }

    sem_post(&thread_arg->wait_sem);
    posted = true;
    (void)console_loop_io_copy(sync_fd, srcfds, writers, len);
err:
    if (!posted) {
        sem_post(&thread_arg->wait_sem);
    }
    io_copy_thread_cleanup(writers, thread_arg, infds, outfds, srcfds, len);
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

int ready_copy_io_data(int sync_fd, bool detach, const char *fifoin, const char *fifoout, const char *fifoerr,
                       int stdin_fd, struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                       const char *fifos[], pthread_t *tid)
{
    int ret = 0;
    size_t len = 0;
    struct io_copy_arg io_copy[6];

    if (fifoin != NULL) {
        io_copy[len].srctype = IO_FIFO;
        io_copy[len].src = (void *)fifoin;
        io_copy[len].dsttype = IO_FIFO;
        io_copy[len].dst = (void *)fifos[0];
        len++;
    }
    if (fifoout != NULL) {
        io_copy[len].srctype = IO_FIFO;
        io_copy[len].src = (void *)fifos[1];
        io_copy[len].dsttype = IO_FIFO;
        io_copy[len].dst = (void *)fifoout;
        len++;
    }
    if (fifoerr != NULL) {
        io_copy[len].srctype = IO_FIFO;
        io_copy[len].src = (void *)fifos[2];
        io_copy[len].dsttype = IO_FIFO;
        io_copy[len].dst = (void *)fifoerr;
        len++;
    }

    if (stdin_fd > 0) {
        io_copy[len].srctype = IO_FD;
        io_copy[len].src = &stdin_fd;
        io_copy[len].dsttype = IO_FIFO;
        io_copy[len].dst = (void *)fifos[0];
        len++;
    }

    if (stdout_handler != NULL) {
        io_copy[len].srctype = IO_FIFO;
        io_copy[len].src = (void *)fifos[1];
        io_copy[len].dsttype = IO_FUNC;
        io_copy[len].dst = stdout_handler;
        len++;
    }

    if (stderr_handler != NULL) {
        io_copy[len].srctype = IO_FIFO;
        io_copy[len].src = (void *)fifos[2];
        io_copy[len].dsttype = IO_FUNC;
        io_copy[len].dst = stderr_handler;
        len++;
    }

    if (start_io_copy_thread(sync_fd, detach, io_copy, len, tid)) {
        ret = -1;
        goto out;
    }
out:
    return ret;
}
