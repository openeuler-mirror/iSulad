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
 * Description: provide container monitord functions
 ******************************************************************************/
#define _GNU_SOURCE

#include <sys/stat.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#include "isula_libutils/log.h"
#include "monitord.h"
#include "mainloop.h"
#include "isulad_config.h"
#include "events_collector_api.h"
#include "event_type.h"
#include "utils_file.h"

struct monitord_handler {
    struct epoll_descr *pdescr;
    int fifo_fd;
    char *fifo_path;
};

/* monitor event cb */
static int monitor_event_cb(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    ssize_t len;
    struct monitord_msg mmsg = { 0 };

    /* first, read message from container monitor. */
    len = util_read_nointr(fd, &mmsg, sizeof(mmsg));
    if ((unsigned int)len != sizeof(mmsg)) {
        ERROR("Invalid message");
        goto out;
    }

    /* second, handle events */
    events_handler(&mmsg);
    if (malloc_trim(0) == 0) {
        DEBUG("Malloc trim failed");
    }
out:
    return 0;
}

/* free monitord */
static void free_monitord(struct monitord_handler *mhandler)
{
    if (mhandler->fifo_fd != -1) {
        epoll_loop_del_handler(mhandler->pdescr, mhandler->fifo_fd);
        close(mhandler->fifo_fd);
    }
    if (mhandler->fifo_path != NULL) {
        if (unlink(mhandler->fifo_path) < 0) {
            WARN("Failed to unlink fifo_path");
        }
        free(mhandler->fifo_path);
        mhandler->fifo_path = NULL;
    }

    DEBUG("Clean monitord data...");
}

#define EVENTS_FIFO_SIZE (1024 * 1024)
/* monitord */
static void *monitord(void *arg)
{
    int ret = 0;
    char *fifo_file_path = NULL;
    struct monitord_handler mhandler = { 0 };
    struct flock mlock;
    struct monitord_sync_data *msync = arg;
    struct epoll_descr descr;

    mhandler.fifo_fd = -1;
    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Set thread detach fail");
        goto pexit;
    }

    prctl(PR_SET_NAME, "Monitord");

    ret = epoll_loop_open(&descr);
    if (ret != 0) {
        ERROR("Failed to create epoll_loop");
        goto pexit;
    }
    mhandler.pdescr = &descr;

    /* 1. monitor fifo: to wait container monitor message */
    fifo_file_path = conf_get_isulad_monitor_fifo_path();
    if (fifo_file_path == NULL) {
        goto err;
    }
    mhandler.fifo_path = fifo_file_path;

    if (mknod(fifo_file_path, S_IFIFO | S_IRUSR | S_IWUSR, (dev_t)0) && errno != EEXIST) {
        ERROR("Create monitord fifo file failed: %s", strerror(errno));
        goto err;
    }

    mhandler.fifo_fd = util_open(fifo_file_path, O_RDWR | O_NONBLOCK | O_CLOEXEC, 0);
    if (mhandler.fifo_fd == -1) {
        ERROR("Open monitord fifo file failed: %s", strerror(errno));
        goto err;
    }

    if (fcntl(mhandler.fifo_fd, F_SETPIPE_SZ, EVENTS_FIFO_SIZE) == -1) {
        ERROR("Set events fifo buffer size failed: %s\n", strerror(errno));
        goto err;
    }

    mlock.l_type = F_WRLCK;
    mlock.l_whence = SEEK_SET;
    mlock.l_start = 0;
    mlock.l_len = 0;
    if (fcntl(mhandler.fifo_fd, F_SETLK, &mlock)) {
        INFO("Monitord already running on path: %s", fifo_file_path);
        goto err;
    }

    ret = epoll_loop_add_handler(&descr, mhandler.fifo_fd, monitor_event_cb, NULL);
    if (ret != 0) {
        ERROR("Failed to add handler for fifo");
        goto err;
    }

    sem_post(msync->monitord_sem);

    /* loop forever except error occured */
    do {
        ret = epoll_loop(&descr, -1);
    } while (ret == 0);

    ERROR("Mainloop returned an error: %s", strerror(errno));
    goto err2;

err:
    *(msync->exit_code) = -1;
    sem_post(msync->monitord_sem);
err2:
    free_monitord(&mhandler);
    epoll_loop_close(&descr);

pexit:
    return NULL;
}

/* new monitord */
int new_monitord(struct monitord_sync_data *msync)
{
    int ret = 0;
    char *statedir = NULL;
    pthread_t monitord_thread;

    if (msync == NULL || msync->monitord_sem == NULL) {
        ERROR("Monitord sem is NULL");
        ret = -1;
        goto out;
    }

    statedir = conf_get_isulad_statedir();
    if (statedir == NULL) {
        ERROR("isulad root path is NULL");
        ret = -1;
        goto out;
    }

    if (setenv("ISULAD_MONITORD_PATH", statedir, 1)) {
        ERROR("Setenv monitord path failed");
        ret = -1;
        goto out;
    }

    INFO("Starting monitord...");
    if (pthread_create(&monitord_thread, NULL, monitord, msync) != 0) {
        ERROR("Create monitord thread failed");
        ret = -1;
    }

out:
    free(statedir);
    return ret;
}
