/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: run isula image server
*******************************************************************************/
#define _GNU_SOURCE
#include "run_image_server.h"

#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "isula_image.h"
#include "isula_health_check.h"
#include "global_config.h"
#include "isulad_config.h"
#include "log.h"
#include "utils_file.h"
#include "utils.h"

/* global options */
const char *g_imtool_gb_options[] = {
    "--graph-root",
    "--run-root",
    "--driver-name",
    "--driver-options",
    "--storage-opt",
    "--registry",
    "--insecure-registry",
    "--command-timeout",
    "--log-level",
    "--host",
    NULL,
};

#define ISULA_IMAGE_SERVER_CMD "isulad-img"
#define ISULA_IMAGE_DAEMON "daemon"
#define ISULA_IMAGE_DAEMON_HOST "--host"
#define ISULA_IMAGE_DAEMON_OPTION_TLS_VERIFY "--tls-verify=false"
#define ISULA_IMAGE_DAEMON_OPTION_USE_DECRYPTED "--use-decrypted-key=false"

#define RETRY_COUNT_MAX 15
#define HALF_A_SECOND 500000
#define ONE_TENTH_SECOND 100000

static pthread_mutex_t g_mutex;
static pid_t g_isulad_img_pid = -1;
static unsigned long long g_isulad_img_start_time = 0;
static bool g_isula_img_exit = false;

static int pack_isula_image_global_options(char *params[], size_t *count, bool ignore_storage_opt_size)
{
    int ret = -1;
    size_t i = 0;
    char *buffer = NULL;
    char *sock_addr = NULL;

    i = *count;

    add_array_elem(params, PARAM_NUM, &i, ISULA_IMAGE_SERVER_CMD);

    if (pack_global_options(g_imtool_gb_options, params, &i, ignore_storage_opt_size) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, ISULA_IMAGE_DAEMON);

    if (!conf_get_use_decrypted_key_flag()) {
        add_array_elem(params, PARAM_NUM, &i, ISULA_IMAGE_DAEMON_OPTION_USE_DECRYPTED);
    }

    if (conf_get_skip_insecure_verify_flag()) {
        add_array_elem(params, PARAM_NUM, &i, ISULA_IMAGE_DAEMON_OPTION_TLS_VERIFY);
    }

    sock_addr = conf_get_im_server_sock_addr();
    if (sock_addr == NULL) {
        COMMAND_ERROR("Get image server socket address failed");
        goto out;
    }
    ret = asprintf(&buffer, "%s=%s", ISULA_IMAGE_DAEMON_HOST, sock_addr);
    if (ret < 0) {
        COMMAND_ERROR("Out of memory");
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, buffer);

    ret = 0;
    *count = i;

out:
    free(sock_addr);
    free(buffer);
    return ret;
}

static void execute_run_isula_image_server(void *args)
{
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;
    int ret = 0;

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    ret = pack_isula_image_global_options(params, &i, false);
    if (ret != 0) {
        COMMAND_ERROR("Pack global options failed");
        goto out;
    }

    execvp(ISULA_IMAGE_SERVER_CMD, params);

    COMMAND_ERROR("Cannot run isula-image server with '%s':%s", ISULA_IMAGE_SERVER_CMD, strerror(errno));
out:
    exit(EXIT_FAILURE);
}

static void do_check_mainloop()
{
#define HEALTH_CHECK_INTERVAL 1000000
    int retry_count = 0;

    while (true) {
        if (isula_do_health_check() == 0) {
            retry_count = 0;
        }
        if ((retry_count++) > RETRY_COUNT_MAX) {
            ERROR("Cannot connect image server, Retry too many times. Will to restart image server");
            break;
        }

        usleep_nointerupt(HEALTH_CHECK_INTERVAL);
    }
}

static unsigned long long get_image_server_start_time(pid_t server_pid)
{
    int sret = 0;
    proc_t *pid_info = NULL;
    char filename[PATH_MAX] = { 0 };
    char sbuf[1024] = { 0 }; /* bufs for stat */
    unsigned long long result = 0;

    if (server_pid == 0) {
        return 0;
    }

    sret = kill(server_pid, 0);
    if (sret < 0 && errno == ESRCH) {
        return 0;
    }

    sret = snprintf(filename, sizeof(filename), "/proc/%d/stat", server_pid);
    if (sret < 0 || (size_t)sret >= sizeof(filename)) {
        ERROR("Failed to sprintf filename");
        goto out;
    }

    if ((util_file2str(filename, sbuf, sizeof(sbuf))) == -1) {
        ERROR("Failed to read pidfile %s", filename);
        goto out;
    }

    pid_info = util_stat2proc(sbuf, sizeof(sbuf));
    if (pid_info == NULL) {
        ERROR("Failed to get proc stat info");
        goto out;
    }

    result = pid_info->start_time;
out:
    free(pid_info);
    return result;
}

static void kill_old_image_server(pid_t server_pid, unsigned long long start_time, unsigned long wait_usec)
{
    if (!util_process_alive(server_pid, start_time)) {
        return;
    }
    if (kill(server_pid, SIGTERM) != 0) {
        SYSERROR("Send term signal to server process failed");
    }
    usleep_nointerupt(wait_usec);
    if (kill(server_pid, SIGKILL) != 0) {
        SYSERROR("Send kill signal to server process failed");
    }
}

static void *heartbeat_for_isulad_img(void *arg)
{
    pid_t tmp_isulad_img_pid = -1;
    unsigned long long tmp_isulad_img_start_time = 0;

    if (pthread_detach(pthread_self()) != 0) {
        ERROR("Detach heartbeat thread failed");
        return NULL;
    }

    prctl(PR_SET_NAME, "HeartBeatForImageServer");

    for (;;) {
        if (pthread_mutex_lock(&g_mutex) != 0) {
            usleep_nointerupt(ONE_TENTH_SECOND);
            continue;
        }

        tmp_isulad_img_pid = g_isulad_img_pid;
        tmp_isulad_img_start_time = g_isulad_img_start_time;

        if (pthread_mutex_unlock(&g_mutex) != 0) {
            ERROR("Lock isulad img pid failed");
            break;
        }

        if (tmp_isulad_img_pid == -1) {
            usleep_nointerupt(ONE_TENTH_SECOND);
            continue;
        }

        do_check_mainloop();

        kill_old_image_server(tmp_isulad_img_pid, tmp_isulad_img_start_time, HALF_A_SECOND);
    }

    return NULL;
}

static unsigned long get_timeout_secs(bool retry)
{
    unsigned long result = RETRY_COUNT_MAX;

    if (retry) {
        return result;
    }

    result = conf_get_im_opt_timeout();
    if (result < RETRY_COUNT_MAX) {
        result = RETRY_COUNT_MAX;
    }

    return result;
}

static bool is_timeout(unsigned long max_second, unsigned long retry_cnt)
{
    unsigned long total = retry_cnt;

    if (total >= ULONG_MAX / (total + 1)) {
        return true;
    }
    total = total * (total + 1) / 2;
    // time unit is second, retry time is 0.1s
    if (total >= max_second * 10) {
        return true;
    }
    return false;
}

static int isula_image_server_load_first_check(const struct server_monitor_conf *conf, bool retry)
{
    int ret = 0;
    unsigned long retry_cnt = 0;
    unsigned long opt_timeout = get_timeout_secs(retry);

    /* parent: check server is running */
    while (true) {
        usleep_nointerupt(ONE_TENTH_SECOND * retry_cnt);
        ret = isula_do_health_check();
        if (ret == 0) {
            break;
        }
        if (is_timeout(opt_timeout, retry_cnt)) {
            // don't post sem to main thread
            ERROR("First load image server failed");
            ret = -1;
            goto out;
        }
        retry_cnt++;
    }

    /* 1. If health check success, send a mutex to main thread and make it run again;
     * 2. Sync data between iSulad and iSulad-img.
     */
    if (retry) {
        ret = isula_sync_images();
        if (ret != 0) {
            DEBUG("Sync images list with remote failed");
        }
        ret = isula_sync_containers();
        if (ret != 0) {
            DEBUG("Sync containers list with remote failed");
        }
    } else {
        /* first run, need post sem */
        sem_post(conf->wait_ok);
    }

out:
    if (retry) {
        // ignore errors, throught restart image server to retry.
        return 0;
    }
    return ret;
}

void isula_img_exit()
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        ERROR("Lock isulad img pid failed");
        return;
    }

    g_isula_img_exit = true;
    kill_old_image_server(g_isulad_img_pid, g_isulad_img_start_time, ONE_TENTH_SECOND);

    if (pthread_mutex_unlock(&g_mutex) != 0) {
        ERROR("Unlock isulad img pid failed");
    }
}

static void update_isulad_img_pid_info(pid_t pid, unsigned long long start_time)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        ERROR("Lock isulad img pid failed");
        return;
    }

    g_isulad_img_start_time = start_time;
    g_isulad_img_pid = pid;

    if (pthread_mutex_unlock(&g_mutex) != 0) {
        ERROR("Unlock isulad img pid failed");
    }
}

static int load_isula_image_server(const struct server_monitor_conf *conf, bool retry, pid_t *img_pid)
{
    pid_t pid = 0;
    int ret = 0;
    int nret = 0;
    unsigned long long start_time = 0;

    pid = fork();
    if (pid == (pid_t) - 1) {
        ERROR("Failed to fork");
        ret = -1;
        goto out;
    }

    if (pid == (pid_t)0) {
        // child to load isulad-img binary
        nret = prctl(PR_SET_PDEATHSIG, SIGKILL, (unsigned long)0, (unsigned long)0, (unsigned long)0);
        if (nret < 0) {
            COMMAND_ERROR("Failed to set parent death signal");
            exit(127);
        }

        nret = setsid();
        if (nret < 0) {
            COMMAND_ERROR("Failed to set process %d as group leader", getpid());
        }
        execute_run_isula_image_server(NULL);
    }
    *img_pid = pid;

    /* parent */
    start_time = get_image_server_start_time(pid);

    /* check first load isulad img is success. */
    if (isula_image_server_load_first_check(conf, retry) != 0) {
        ret = -1;
    }

    /* update isulad-img information */
    update_isulad_img_pid_info(pid, start_time);

out:
    return ret;
}

static void remove_old_socket_file()
{
    char *sock_addr;

    sock_addr = conf_get_im_server_sock_addr();
    if (sock_addr != NULL) {
        if (unlink(sock_addr) != 0 && errno != ENOENT) {
            ERROR("Remove old socket file failed: %s", strerror(errno));
        }
        free(sock_addr);
    }
}

void *isula_image_server_monitor(void *arg)
{
    int nret = 0;
    struct server_monitor_conf *conf = (struct server_monitor_conf *)arg;
    bool retry_flag = false;
    pthread_t wp_thread;
    pid_t isulad_img_pid;

    if (conf == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    nret = pthread_mutex_init(&g_mutex, NULL);
    if (nret != 0) {
        ERROR("Init mutex failed: %s", strerror(nret));
        goto pexit;
    }

    nret = pthread_create(&wp_thread, NULL, heartbeat_for_isulad_img, NULL);
    if (nret != 0) {
        ERROR("Create heartbeat thread failed: %s", strerror(nret));
        goto pexit;
    }

    nret = pthread_detach(pthread_self());
    if (nret != 0) {
        ERROR("Set isula image server monitor thread failed: %s", strerror(nret));
        goto pexit;
    }
    prctl(PR_SET_NAME, "iSulaImageMonitor");
    INFO("Begin isula image server monitor");

retry:
    remove_old_socket_file();
    isulad_img_pid = (pid_t) - 1;
    // First, fork new process to run image server binary.
    nret = load_isula_image_server(conf, retry_flag, &isulad_img_pid);
    if (nret != 0) {
        if (!retry_flag) {
            ERROR("First start isulad img failed");
            goto pexit;
        }
        WARN("Load isula image server failed");
    }

    retry_flag = true;
    if (isulad_img_pid == (pid_t) - 1) {
        usleep_nointerupt(HALF_A_SECOND);
        goto retry;
    }
    /* waitpid for isulad-img process */
    nret = wait_for_pid(isulad_img_pid);
    if (nret != 0) {
        SYSERROR("Wait isulad img failed");
    }

    /* clean old isulad-img information */
    if (pthread_mutex_lock(&g_mutex) != 0) {
        ERROR("Lock isulad img pid failed");
    }

    g_isulad_img_start_time = 0;
    g_isulad_img_pid = -1;
    if (g_isula_img_exit) {
        (void)pthread_mutex_unlock(&g_mutex);
        goto pexit;
    }

    if (pthread_mutex_unlock(&g_mutex) != 0) {
        ERROR("Unlock isulad img pid failed");
    }

    usleep_nointerupt(HALF_A_SECOND);
    // Second, wait new process; if it is failed, restart it.
    goto retry;

pexit:
    return NULL;
}

