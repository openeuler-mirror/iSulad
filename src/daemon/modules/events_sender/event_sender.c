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
 * Create: 2020-06-23
 * Description: provide container collector definition
 ******************************************************************************/
#define _GNU_SOURCE
#include "events_sender_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <poll.h>
#include <sys/prctl.h>
#include <regex.h>
#include <errno.h>

#include "error.h"
#include "isula_libutils/log.h"
#include "isulad_config.h"

/* isulad monitor fifo send */
static void isulad_monitor_fifo_send(const struct monitord_msg *msg)
{
    int fd = -1;
    ssize_t ret = 0;
    char *fifo_path = NULL;

    fifo_path = conf_get_isulad_monitor_fifo_path();
    if (fifo_path == NULL) {
        return;
    }

    /* Open the fifo nonblock in case the monitor is dead, we don't want the
     * open to wait for a reader since it may never come.
     */
    fd = util_open(fifo_path, O_WRONLY | O_NONBLOCK, 0);
    if (fd < 0) {
        /* It is normal for this open() to fail with ENXIO when there is
         * no monitor running, so we don't log it.
         */
        if (errno == ENXIO || errno == ENOENT) {
            goto out;
        }

        ERROR("Failed to open fifo to send message: %s.", strerror(errno));
        goto out;
    }

    do {
        ret = util_write_nointr(fd, msg, sizeof(struct monitord_msg));
        if (ret != sizeof(struct monitord_msg)) {
            usleep_nointerupt(1000);
        }
    } while (ret != sizeof(struct monitord_msg));

out:
    free(fifo_path);
    if (fd >= 0) {
        close(fd);
    }
}

/* isulad monitor send container event */
int isulad_monitor_send_container_event(const char *name, runtime_state_t state, int pid, int exit_code,
                                        const char *args, const char *extra_annations)
{
    int ret = 0;
    struct monitord_msg msg = { .type = MONITORD_MSG_STATE,
                                .event_type = CONTAINER_EVENT,
                                .value = state,
                                .pid = -1,
                                .exit_code = -1,
                                .args = { 0x00 },
                                .extra_annations = { 0x00 } };

    if (name == NULL) {
        CRIT("Invalid input arguments");
        ret = -1;
        goto out;
    }

    (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
    msg.name[sizeof(msg.name) - 1] = '\0';

    if (args != NULL) {
        (void)strncpy(msg.args, args, sizeof(msg.args) - 1);
        msg.args[sizeof(msg.args) - 1] = '\0';
    }

    if (extra_annations != NULL) {
        (void)strncpy(msg.extra_annations, extra_annations, sizeof(msg.extra_annations) - 1);
        msg.extra_annations[sizeof(msg.extra_annations) - 1] = '\0';
    }

    if (pid > 0) {
        msg.pid = pid;
    }
    if (exit_code >= 0) {
        msg.exit_code = exit_code;
    }

    isulad_monitor_fifo_send(&msg);

out:
    return ret;
}

/* isulad monitor send image event */
int isulad_monitor_send_image_event(const char *name, image_state_t state)
{
    int ret = 0;

    struct monitord_msg msg = { .type = MONITORD_MSG_STATE,
                                .event_type = IMAGE_EVENT,
                                .value = state,
                                .args = { 0x00 },
                                .extra_annations = { 0x00 } };

    if (name == NULL) {
        CRIT("Invalid input arguments");
        ret = -1;
        goto out;
    }

    (void)strncpy(msg.name, name, sizeof(msg.name) - 1);
    msg.name[sizeof(msg.name) - 1] = '\0';

    isulad_monitor_fifo_send(&msg);

out:
    return ret;
}
