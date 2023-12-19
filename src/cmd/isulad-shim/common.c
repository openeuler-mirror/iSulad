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
 * Create: 2020-1-21
 * Description: common functions of isulad-shim
 ******************************************************************************/

#define _GNU_SOURCE
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <time.h>

#include <isula_libutils/utils_memory.h>
#include <isula_libutils/utils_file.h>
#include <isula_libutils/utils_string.h>
#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "shim_constants.h"

static __thread char *g_shim_errmsg = NULL;

// currently, log_to_stderr is only modified in the main process
// and there is no need to set a thread-local variable. 
// if it can be modified by multiple threads in the future,
// this variable needs to be set as a thread-local variable.
static bool log_to_stderr = false;

static void shim_clear_errmsg(void)
{
    if (g_shim_errmsg != NULL) {
        free(g_shim_errmsg);
        g_shim_errmsg = NULL;
    }
}

void set_log_to_stderr(bool flag)
{
    log_to_stderr = flag;
}

static int verify_log_path(const char *path)
{
    struct stat st = { 0 };
    char real_path[PATH_MAX] = { 0 };
    int ret = 0;

    if (isula_clean_path(path, real_path, sizeof(real_path)) == NULL) {
        ERROR("Failed to clean path: '%s'", path);
        return false;
    }

    if (lstat(real_path, &st) != 0) {
        SYSERROR("lstat %s failed.", real_path);
        return -1;
    }

    if (!S_ISFIFO(st.st_mode)) {
        return -1;
    }

    if ((st.st_mode & 0777) != LOG_FIFO_MODE) {
        return -1;
    }

    // chown to root
    ret = lchown(path, 0, 0);
    if (ret == 0 || (ret == EPERM && st.st_uid == 0 && st.st_gid == 0)) {
        return 0;
    }

    SYSERROR("lchown %s failed", path);
    return -1;
}

int isulad_shim_log_init(const char *file, const char *priority)
{
    __isula_auto_free char *full_path = NULL;
    const char *pre_name = "fifo:";
    size_t pre_len = strlen(pre_name);
    struct isula_libutils_log_config lconf = { 0 };

    if (file == NULL || priority == NULL || strncmp(file, pre_name, pre_len) != 0) {
        dprintf(STDERR_FILENO, "invalid shim log params");
        return -1;
    }

    lconf.name = "shim";
    /* File has prefix "fifo:", */
    full_path = isula_strdup_s(file + pre_len);

    if (verify_log_path(full_path) != 0) {
        dprintf(STDERR_FILENO, "unsafe shim log path");
        return -1;
    }

    lconf.file = full_path;
    lconf.driver = "fifo";
    lconf.priority = priority;
    if (isula_libutils_log_enable(&lconf) != 0) {
        // because shim log init error, print error msg to stderr.
        // isulad can obtain the reason why shim exits.
        dprintf(STDERR_FILENO, "failed to init shim log");
        return -1;
    }

    return 0;
}

void shim_set_error_message(const char *format, ...)
{
    int ret = 0;
    char errbuf[BUFSIZ + 1] = { 0 };
    va_list argp;

    if (format == NULL) {
        return;
    }
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0) {
        return;
    }

    shim_clear_errmsg();
    g_shim_errmsg = isula_strdup_s(errbuf);
}

void shim_append_error_message(const char *format, ...)
{
    int ret = 0;
    char errbuf[BUFSIZ + 1] = { 0 };
    char *result = NULL;

    va_list argp;
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0) {
        return;
    }
    result = isula_string_append(g_shim_errmsg, errbuf);
    if (result == NULL) {
        return;
    }
    if (g_shim_errmsg != NULL) {
        free(g_shim_errmsg);
    }
    g_shim_errmsg = result;
}

void error_exit(int exit_code)
{
    if (log_to_stderr && g_shim_errmsg != NULL) {
        dprintf(STDERR_FILENO, "shim-error: %s\n", g_shim_errmsg);
    }
    exit(exit_code);
}

void signal_routine(int sig)
{
    switch (sig) {
        case SIGALRM:
            ERROR("runtime timeout");
            shim_set_error_message("runtime timeout");
            error_exit(EXIT_FAILURE);
        default:
            break;
    }
}

int set_fd_no_inherited(int fd)
{
    int ret = SHIM_ERR;
    int flag = -1;

    flag = fcntl(fd, F_GETFD, 0);
    if (flag < 0) {
        return SHIM_ERR;
    }

    ret = fcntl(fd, F_SETFD, flag | FD_CLOEXEC);
    if (ret != 0) {
        return SHIM_ERR;
    }

    return SHIM_OK;
}

int cmd_combined_output(const char *binary, const char *params[], void *output, int *output_len)
{
    int ret = SHIM_ERR;
    int status = 0;
    int exec_fd[2] = { -1, -1 };
    int stdio[2] = { -1, -1 };
    pid_t pid = 0;
    char exec_buff[BUFSIZ] = { 0 };
    ssize_t nread;

    if (pipe2(exec_fd, O_CLOEXEC) != 0) {
        return SHIM_ERR;
    }

    if (pipe2(stdio, O_CLOEXEC) != 0) {
        return SHIM_ERR;
    }

    pid = fork();
    if (pid == (pid_t) -1) {
        return SHIM_ERR;
    }

    // child
    if (pid == (pid_t)0) {
        close(exec_fd[0]);
        close(stdio[0]);
        dup2(stdio[1], 1);
        dup2(stdio[1], 2);
        execvp(binary, (char * const *)params);
        (void)dprintf(exec_fd[1], "fork/exec error: %s", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    // parent
    close(exec_fd[1]);
    close(stdio[1]);
    nread = isula_file_read_nointr(exec_fd[0], exec_buff, BUFSIZ - 1);
    if (nread > 0) {
        ret = SHIM_ERR;
        goto out;
    }
    *output_len = isula_file_read_nointr(stdio[0], output, BUFSIZ - 1);

    ret = SHIM_OK;

out:
    close(stdio[0]);
    close(exec_fd[0]);
    wait(&status);
    if (ret != SHIM_OK) {
        kill(pid, 9);
    }

    return ret;
}

int generate_random_str(char *id, size_t len)
{
    int fd = -1;
    int num = 0;
    size_t i;
    const int m = 256;

    len = len / 2;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        return SHIM_ERR;
    }
    for (i = 0; i < len; i++) {
        int nret;
        size_t tmp_len;
        if (isula_file_read_nointr(fd, &num, sizeof(int)) < 0) {
            close(fd);
            return SHIM_ERR;
        }
        unsigned char rs = (unsigned char)(num % m);
        tmp_len = ((len - i) * 2 + 1);
        nret = snprintf((id + i * 2), tmp_len, "%02x", (unsigned int)rs);
        if (nret < 0 || (size_t)nret >= tmp_len) {
            close(fd);
            return SHIM_ERR;
        }
    }
    close(fd);
    id[i * 2] = '\0';

    return SHIM_OK;
}

/* note: This function can only read small text file. */
char *read_text_file(const char *path)
{
    char *buf = NULL;
    long len = 0;
    size_t readlen = 0;
    FILE *filp = NULL;
    const long max_size = 10 * 1024 * 1024; /* 10M */

    if (path == NULL) {
        return NULL;
    }

    filp = fopen(path, "r");
    if (filp == NULL) {
        goto err_out;
    }
    if (fseek(filp, 0, SEEK_END)) {
        goto err_out;
    }

    len = ftell(filp);
    if (len > max_size) {
        goto err_out;
    }
    if (fseek(filp, 0, SEEK_SET)) {
        goto err_out;
    }

    buf = (char *)calloc(1, (size_t)(len + 1));
    if (buf == NULL) {
        goto err_out;
    }

    readlen = fread(buf, 1, (size_t)len, filp);
    if (((readlen < (size_t)len) && (!feof(filp))) || (readlen > (size_t)len)) {
        free(buf);
        buf = NULL;
        goto err_out;
    }

    buf[(size_t)len] = 0;

err_out:

    if (filp != NULL) {
        fclose(filp);
    }

    return buf;
}

void close_fd(int *pfd)
{
    if (pfd != NULL && *pfd != -1) {
        close(*pfd);
        *pfd = -1;
    }
}

int open_no_inherit(const char *path, int flag, mode_t mode)
{
    int fd = -1;
    int ret = SHIM_ERR;

    fd = open(path, flag, mode);
    if (fd < 0) {
        return -1;
    }

    ret = set_fd_no_inherited(fd);
    if (ret != SHIM_OK) {
        close(fd);
        return -1;
    }

    return fd;
}

/* judge the fd whether is attach fifo */
struct isula_linked_list *get_attach_fifo_item(int fd, struct isula_linked_list *list)
{
    struct isula_linked_list *it = NULL;
    struct isula_linked_list *next = NULL;

    if (fd <= 0 || list == NULL || isula_linked_list_empty(list)) {
        return it;
    }

    isula_linked_list_for_each_safe(it, list, next) {
        struct shim_fifos_fd *elem = (struct shim_fifos_fd *)it->elem;
        if (elem == NULL) {
            continue;
        }
        if (elem->in_fd == fd) {
            return it;
        }
        if (elem->out_fd == fd) {
            return it;
        }
        if (elem->err_fd == fd) {
            return it;
        }
    }

    return it;
}

void free_shim_fifos_fd(struct shim_fifos_fd *item)
{
    if (item == NULL) {
        return;
    }
    if (item->in_fifo != NULL) {
        free(item->in_fifo);
        item->in_fifo = NULL;
    }
    if (item->out_fifo != NULL) {
        free(item->out_fifo);
        item->out_fifo = NULL;
    }
    if (item->err_fifo != NULL) {
        free(item->err_fifo);
        item->err_fifo = NULL;
    }
    if (item->in_fd >= 0) {
        close(item->in_fd);
        item->in_fd = -1;
    }
    if (item->out_fd >= 0) {
        close(item->out_fd);
        item->out_fd = -1;
    }
    if (item->err_fd >= 0) {
        close(item->err_fd);
        item->err_fd = -1;
    }
    free(item);
}