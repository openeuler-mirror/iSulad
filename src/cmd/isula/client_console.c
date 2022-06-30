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
 * Author: lifeng
 * Create: 2020-10-20
 * Description: provide container command functions
 ******************************************************************************/
#include "client_console.h"

#include <stdio.h>
#include <limits.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "console.h"
#include "utils_file.h"

/* free command fifo names */
void free_command_fifo_config(struct command_fifo_config *fifos)
{
    if (fifos != NULL) {
        if (fifos->stdin_path != NULL) {
            free(fifos->stdin_path);
            fifos->stdin_path = NULL;
        }
        if (fifos->stdout_path != NULL) {
            free(fifos->stdout_path);
            fifos->stdout_path = NULL;
        }
        if (fifos->stderr_path != NULL) {
            free(fifos->stderr_path);
            fifos->stderr_path = NULL;
        }
        if (fifos->stdin_name != NULL) {
            free(fifos->stdin_name);
            fifos->stdin_name = NULL;
        }
        if (fifos->stdout_name != NULL) {
            free(fifos->stdout_name);
            fifos->stdout_name = NULL;
        }
        if (fifos->stderr_name != NULL) {
            free(fifos->stderr_name);
            fifos->stderr_name = NULL;
        }
        free(fifos);
    }
}

/* delete command fifo */
void delete_command_fifo(struct command_fifo_config *fifos)
{
    int ret;

    if (fifos == NULL) {
        return;
    }

    ret = console_fifo_delete(fifos->stdin_name);
    if (ret) {
        WARN("Delete fifo failed: %s", fifos->stdin_name);
    }
    ret = console_fifo_delete(fifos->stdout_name);
    if (ret) {
        WARN("Delete fifo failed: %s", fifos->stdout_name);
    }
    ret = console_fifo_delete(fifos->stderr_name);
    if (ret) {
        WARN("Delete fifo failed: %s", fifos->stderr_name);
    }
    ret = util_recursive_rmdir(fifos->stdin_path, 0);
    if (ret) {
        WARN("Remove directory failed: %s", fifos->stdin_path);
    }
    ret = util_recursive_rmdir(fifos->stdout_path, 0);
    if (ret) {
        WARN("Remove directory failed: %s", fifos->stdout_path);
    }
    ret = util_recursive_rmdir(fifos->stderr_path, 0);
    if (ret) {
        WARN("Remove directory failed: %s", fifos->stderr_path);
    }

    free_command_fifo_config(fifos);
}

static int do_create_console_fifo(const char *subpath, const char *stdflag, char **out_fifo_dir, char **out_fifo_name)
{
    int ret = 0;
    char fifo_dir[PATH_MAX] = { 0 };
    char fifo_name[PATH_MAX] = { 0 };

    ret = console_fifo_name(CLIENT_RUNDIR, subpath, stdflag, fifo_name, sizeof(fifo_name), fifo_dir, sizeof(fifo_dir),
                            true);
    if (ret != 0) {
        ERROR("Failed to get console fifo name.");
        ret = -1;
        goto out;
    }

    if (console_fifo_create(fifo_name)) {
        ERROR("Failed to create console fifo.");
        ret = -1;
        goto out;
    }

    *out_fifo_dir = util_strdup_s(fifo_dir);
    *out_fifo_name = util_strdup_s(fifo_name);

out:
    return ret;
}

int create_console_fifos(bool attach_stdin, bool attach_stdout, bool attach_stderr, const char *name, const char *type,
                         struct command_fifo_config **pconsole_fifos)
{
    int ret = 0;
    char subpath[PATH_MAX] = { 0 };
    struct command_fifo_config *fifos = NULL;

    fifos = util_common_calloc_s(sizeof(struct command_fifo_config));
    if (fifos == NULL) {
        ERROR("Failed to malloc memory for FIFO names.");
        return -1;
    }

    ret = snprintf(subpath, sizeof(subpath), "%s/%s-%u-%u", name, type, (unsigned int)getpid(),
                   (unsigned int)pthread_self());
    if (ret < 0 || (size_t)ret >= sizeof(subpath)) {
        ERROR("Path is too long");
        goto cleanup;
    }

    if (attach_stdin) {
        ret = do_create_console_fifo(subpath, "in", &fifos->stdin_path, &fifos->stdin_name);
        if (ret != 0) {
            goto cleanup;
        }
        INFO("FIFO:%s create for start success.", fifos->stdin_name);
    }

    if (attach_stdout) {
        ret = do_create_console_fifo(subpath, "out", &fifos->stdout_path, &fifos->stdout_name);
        if (ret != 0) {
            goto cleanup;
        }
        INFO("FIFO:%s create for start success.", fifos->stdout_name);
    }

    if (attach_stderr) {
        ret = do_create_console_fifo(subpath, "err", &fifos->stderr_path, &fifos->stderr_name);
        if (ret != 0) {
            goto cleanup;
        }
        INFO("FIFO:%s create for start success.", fifos->stderr_name);
    }

    *pconsole_fifos = fifos;
    return 0;

cleanup:
    console_fifo_delete(fifos->stdin_name);
    console_fifo_delete(fifos->stdout_name);
    console_fifo_delete(fifos->stderr_name);
    free_command_fifo_config(fifos);
    return -1;
}

struct console_loop_thread_args {
    struct command_fifo_config *fifo_config;
    bool tty;
};

static void *client_console_loop_thread(void *arg)
{
    int ret = 0;
    int fifoinfd = -1;
    int fifooutfd = -1;
    int fifoerrfd = -1;
    const struct console_loop_thread_args *args = arg;
    bool tty = args->tty;
    struct command_fifo_config *fifo_config = args->fifo_config;
    sem_t *wait_open = fifo_config->wait_open;
    sem_t *wait_exit = fifo_config->wait_exit;

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Start: set thread detach fail");
        goto err1;
    }

    if (fifo_config->stdin_name) {
        if (console_fifo_open_withlock(fifo_config->stdin_name, &fifoinfd, O_RDWR | O_NONBLOCK)) {
            ERROR("Start: failed to open console fifo.");
            goto err2;
        }
        INFO("FIFO:%s open success for start.", fifo_config->stdin_name);
    }

    if (fifo_config->stdout_name) {
        if (console_fifo_open(fifo_config->stdout_name, &fifooutfd, O_RDONLY | O_NONBLOCK)) {
            ERROR("Failed to open console fifo.");
            goto err2;
        }
        INFO("FIFO:%s open success for start.", fifo_config->stdout_name);
    }

    if (fifo_config->stderr_name) {
        if (console_fifo_open(fifo_config->stderr_name, &fifoerrfd, O_RDONLY | O_NONBLOCK)) {
            ERROR("Start: failed to open console fifo.");
            goto err2;
        }
        INFO("FIFO:%s open success for start.", fifo_config->stderr_name);
    }

    sem_post(wait_open);
    console_loop_with_std_fd(0, 1, 2, fifoinfd, fifooutfd, fifoerrfd, 1, tty);

err2:
    if (fifoinfd >= 0) {
        console_fifo_close(fifoinfd);
    }
    if (fifooutfd >= 0) {
        console_fifo_close(fifooutfd);
    }
    if (fifoerrfd >= 0) {
        console_fifo_close(fifoerrfd);
    }
err1:
    sem_post(wait_open);
    sem_post(wait_exit);
    return NULL;
}

int start_client_console_thread(struct command_fifo_config *console_fifos, bool tty)
{
    int res = 0;
    pthread_t a_thread;
    struct console_loop_thread_args args;

    args.fifo_config = console_fifos;
    args.tty = tty;
    res = pthread_create(&a_thread, NULL, client_console_loop_thread, (void *)(&args));
    if (res != 0) {
        CRIT("Thread creation failed");
        return -1;
    }

    sem_wait(console_fifos->wait_open);

    return 0;
}

static void *client_console_resize_thread(void *arg)
{
    int ret = 0;
    struct client_arguments *args = arg;
    struct winsize wsz = { 0 };

    if (!isatty(STDIN_FILENO)) {
        goto out;
    }

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Start: set thread detach fail");
        goto out;
    }

    while (true) {
        sleep(1); // check the windows size per 1s
        ret = ioctl(STDIN_FILENO, TIOCGWINSZ, &wsz);
        if (ret < 0) {
            WARN("Failed to get window size");
            continue;
        }
        if (wsz.ws_row == args->s_pre_wsz.ws_row && wsz.ws_col == args->s_pre_wsz.ws_col) {
            continue;
        }
        if (args->resize_cb != NULL) {
            ret = args->resize_cb(args, wsz.ws_row, wsz.ws_col);
            if (ret != 0) {
                continue;
            }
            args->s_pre_wsz.ws_row = wsz.ws_row;
            args->s_pre_wsz.ws_col = wsz.ws_col;
        }
    }

out:
    return NULL;
}

int start_client_console_resize_thread(struct client_arguments *args)
{
    int res = 0;
    pthread_t a_thread;

    res = pthread_create(&a_thread, NULL, client_console_resize_thread, (void *)(args));
    if (res != 0) {
        CRIT("Thread creation failed");
        return -1;
    }

    return 0;
}
