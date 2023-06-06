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
 * Description: main process of isulad-shim
 ******************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <isula_libutils/shim_client_process_state.h>
#include <stdlib.h>

#include "common.h"
#include "process.h"

static void set_timeout_exit(unsigned int timeout)
{
    signal(SIGALRM, signal_routine);
    (void)alarm(timeout);
}

static void released_timeout_exit()
{
    (void)alarm(0);
    signal(SIGALRM, SIG_IGN);
}

static int set_subreaper()
{
    int ret = SHIM_ERR;
    ret = prctl(PR_SET_CHILD_SUBREAPER, 1);
    if (ret != SHIM_OK) {
        return SHIM_SYS_ERR(errno);
    }

    return SHIM_OK;
}

static int parse_args(int argc, char **argv, char **cid, char **bundle, char **rt_name, char **log_level,
                      uint64_t *timeout)
{
    if (argc < 4) {
        return SHIM_ERR;
    }

    *cid = strdup(argv[1]);
    *bundle = strdup(argv[2]);
    *rt_name = strdup(argv[3]);
    if (*cid == NULL || *bundle == NULL || *rt_name == NULL) {
        return SHIM_ERR;
    }

    if (argc > 4) {
        *log_level = strdup(argv[4]);
        if (*log_level == NULL) {
            return SHIM_ERR;
        }
    }

    if (argc > 5) {
        if (shim_util_safe_uint64(strdup(argv[5]), timeout) != 0) {
            return SHIM_ERR;
        }
    }

    return SHIM_OK;
}

/*
 * Note:
 * All files created in the working directory are cleared by the parent process isulad
 */
int main(int argc, char **argv)
{
    char *container_id = NULL;
    char *bundle = NULL;
    char *rt_name = NULL;
    char *log_level = NULL;
    int ret = SHIM_ERR;
    int efd = -1;
    process_t *p = NULL;
    // execSync timeout
    uint64_t timeout = 0;
    pthread_t tid_epoll;

    ret = init_shim_log();
    if (ret != SHIM_OK) {
        // because shim log init error, print error msg to stderr.
        // isulad can obtain the reason why shim exits.
        dprintf(STDERR_FILENO, "failed to init shim log");
        _exit(EXIT_FAILURE);
    }

    /*
     * The default value of DEFAULT_TIME is 120 seconds,
     * which is the same as the default value of containerd
     */
    set_timeout_exit(DEFAULT_TIMEOUT);

    ret = set_subreaper();
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "set subreaper failed:%d", ret);
        exit(EXIT_FAILURE);
    }

    ret = parse_args(argc, argv, &container_id, &bundle, &rt_name, &log_level, &timeout);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "parse args failed:%d", ret);
        exit(EXIT_FAILURE);
    }

    p = new_process(container_id, bundle, rt_name);
    if (p == NULL) {
        write_message(ERR_MSG, "new process failed");
        exit(EXIT_FAILURE);
    }

    /*
     * Open exit pipe
     * The exit pipe exists only when the container is started,
     * and the exec operation does not contain the exit pipe.
     */
    if (!p->state->exec) {
        if (p->state->exit_fifo != NULL) {
            efd = open_no_inherit("exit_fifo", O_WRONLY, -1);
            if (efd < 0) {
                write_message(ERR_MSG, "open exit pipe failed:%d", SHIM_SYS_ERR(errno));
                exit(EXIT_FAILURE);
            }
            p->exit_fd = efd;
        }
    }

    /* start epoll for io copy */
    ret = process_io_start(p, &tid_epoll);
    if (ret != SHIM_OK) {
        write_message(ERR_MSG, "process io init failed:%d", ret);
        exit(EXIT_FAILURE);
    }

    ret = create_process(p);
    if (ret != SHIM_OK) {
        if (p->console_sock_path != NULL) {
            (void)unlink(p->console_sock_path);
        }
        exit(EXIT_FAILURE);
    }

    released_timeout_exit();

    ret = process_signal_handle_routine(p, tid_epoll, timeout);
    if (ret == SHIM_ERR) {
        exit(EXIT_FAILURE);
    }
    if (ret == SHIM_ERR_TIMEOUT) {
        exit(SHIM_EXIT_TIMEOUT);
    }

    exit(EXIT_SUCCESS);
}
