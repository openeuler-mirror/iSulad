/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide container utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils.h"
#include <errno.h>
#include <execinfo.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <regex.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <termios.h> // IWYU pragma: keep
#include <strings.h>
#include <time.h>

#include "isula_libutils/log.h"
#include "isula_libutils/json_common.h"
#include "utils_array.h"
#include "utils_convert.h"
#include "utils_file.h"
#include "utils_regex.h"
#include "utils_string.h"
#include "utils_verify.h"

int util_mem_realloc(void **newptr, size_t newsize, void *oldptr, size_t oldsize)
{
    void *tmp = NULL;

    if (newptr == NULL || newsize == 0) {
        goto err_out;
    }

    tmp = util_common_calloc_s(newsize);
    if (tmp == NULL) {
        ERROR("Failed to malloc memory");
        goto err_out;
    }

    if (oldptr != NULL) {
        (void)memcpy(tmp, oldptr, (newsize < oldsize) ? newsize : oldsize);
        (void)memset(oldptr, 0, oldsize);

        free(oldptr);
    }

    *newptr = tmp;
    return 0;

err_out:
    return -1;
}

static int util_read_pipe(int pipe_fd, char **out_buf, size_t *out_buf_size, size_t *out_real_size)
{
    int ret = 0;
    char *tmp = NULL;
    char *buffer = *out_buf;
    size_t old_size = *out_buf_size;
    size_t real_size = *out_real_size;
    size_t new_size = 0;
    ssize_t read_size = 0;

    if (buffer == NULL) {
        new_size = PIPE_BUF + 1;
        buffer = util_common_calloc_s(new_size);
        if (buffer == NULL) {
            ERROR("Memory out");
            ret = -1;
            goto out;
        }
        *out_buf_size = new_size;
        *out_buf = buffer;
        *out_real_size = 0;
    } else {
        if (old_size - real_size < PIPE_BUF + 1) {
            if (old_size > (SIZE_MAX - PIPE_BUF) - 1) {
                ERROR("Memory out");
                ret = -1;
                goto out;
            }

            new_size = old_size + PIPE_BUF + 1;
            ret = util_mem_realloc((void *)(&tmp), new_size, (void *)buffer, old_size);
            if (ret != 0) {
                ERROR("Memory out");
                ret = -1;
                goto out;
            }
            buffer = tmp;
            *out_buf_size = new_size;
            *out_buf = buffer;
        }
    }

    read_size = util_read_nointr(pipe_fd, buffer + real_size, PIPE_BUF);
    if (read_size > 0) {
        *out_real_size = real_size + (size_t)read_size;
        ret = 0;
        goto out;
    } else if (read_size < 0 && errno == EAGAIN) {
        ret = 0;
        goto out;
    } else {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif

#ifndef PR_SET_MM_MAP
#define PR_SET_MM_MAP 14
#endif

static bool util_dir_skip_current(const struct dirent *pdirent)
{
    if (strcmp(pdirent->d_name, ".") == 0) {
        return true;
    }

    if (strcmp(pdirent->d_name, "..") == 0) {
        return true;
    }
    return false;
}

static bool util_is_std_fileno(int fd)
{
    return fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO;
}

int util_check_inherited(bool closeall, int fd_to_ignore)
{
    struct dirent *pdirent = NULL;
    int fd, fddir;
    DIR *directory = NULL;

restart:
    directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        WARN("Failed to open directory: /proc/self/fd.");
        return -1;
    }

    fddir = dirfd(directory);
    pdirent = readdir(directory);
    for (; pdirent != NULL; pdirent = readdir(directory)) {
        if (util_dir_skip_current(pdirent)) {
            continue;
        }

        if (util_safe_int(pdirent->d_name, &fd) < 0) {
            continue;
        }

        if (util_is_std_fileno(fd) || fd == fddir || fd == fd_to_ignore) {
            continue;
        }

        if (closeall) {
            if (fd >= 0) {
                close(fd);
                fd = -1;
            }
            if (directory != NULL) {
                closedir(directory);
                directory = NULL;
            }
            goto restart;
        }
    }

    closedir(directory);
    return 0;
}

static int sig_num(const char *sig)
{
    int n;

    if (util_safe_int(sig, &n) < 0) {
        return -1;
    }

    return n;
}

int util_sig_parse(const char *sig_name)
{
    size_t n;
    const struct signame signames[] = SIGNAL_MAP_DEFAULT;

    if (sig_name == NULL) {
        return -1;
    }

    if (isdigit(*sig_name)) {
        return sig_num(sig_name);
    } else if (strncasecmp(sig_name, "sig", 3) == 0) {
        sig_name += 3;
        for (n = 0; n < sizeof(signames) / sizeof(signames[0]); n++) {
            if (strcasecmp(signames[n].name, sig_name) == 0) {
                return signames[n].num;
            }
        }
    } else {
        for (n = 0; n < sizeof(signames) / sizeof(signames[0]); n++) {
            if (strcasecmp(signames[n].name, sig_name) == 0) {
                return signames[n].num;
            }
        }
    }

    return -1;
}

void *util_smart_calloc_s(size_t unit_size, size_t count)
{
    if (unit_size == 0) {
        return NULL;
    }

    if (count > (MAX_MEMORY_SIZE / unit_size)) {
        return NULL;
    }

    return calloc(count, unit_size);
}

void *util_common_calloc_s(size_t size)
{
    if (size == 0 || size > MAX_MEMORY_SIZE) {
        return NULL;
    }

    return calloc((size_t)1, size);
}

char *util_strdup_s(const char *src)
{
    char *dst = NULL;

    if (src == NULL) {
        return NULL;
    }

    dst = strdup(src);
    if (dst == NULL) {
        abort();
    }

    return dst;
}

int util_wait_for_pid(pid_t pid)
{
    int st;
    int nret = 0;

rep:
    nret = waitpid(pid, &st, 0);
    if (nret == -1) {
        if (errno == EINTR) {
            goto rep;
        }
        return -1;
    }
    if (nret != pid) {
        goto rep;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        return -1;
    }
    return 0;
}

int util_wait_for_pid_status(pid_t pid)
{
    int st;
    int nret = 0;
rep:
    nret = waitpid(pid, &st, 0);
    if (nret == -1) {
        if (errno == EINTR) {
            goto rep;
        }
        return -1;
    }

    if (nret != pid) {
        goto rep;
    }
    return st;
}

/*
 * if errmsg contain with 'not found'/'no such' error, set exit_code 127
 * if errmsg contain with 'permission denied' error, set exit_code 126
 */
void util_contain_errmsg(const char *errmsg, int *exit_code)
{
    if (errmsg == NULL || exit_code == NULL) {
        return;
    }

    if (strcasestr(errmsg, "executable file not found") || strcasestr(errmsg, "no such file or directory") ||
        strcasestr(errmsg, "system cannot find the file specified")) {
        *exit_code = 127;
    } else if (strcasestr(errmsg, "permission denied")) {
        *exit_code = 126;
    } else if (strcasestr(errmsg, "not a directory")) {
        *exit_code = 127;
    }

    return;
}

char *util_short_digest(const char *digest)
{
#define SHORT_DIGEST_LEN 12
    char short_digest[SHORT_DIGEST_LEN + 1] = { 0 };
    size_t start_pos = 0;

    if (digest == NULL) {
        return NULL;
    }
    if (!util_valid_digest(digest)) {
        ERROR("invalid digest %s", digest);
        return NULL;
    }

    if (strstr(digest, SHA256_PREFIX) == digest) {
        start_pos = strlen(SHA256_PREFIX);
    }

    (void)memcpy(short_digest, digest + start_pos, SHORT_DIGEST_LEN);

    short_digest[SHORT_DIGEST_LEN] = 0;

    return util_strdup_s(short_digest);
}

char *util_full_digest(const char *digest)
{
    int nret = 0;
    char full_digest[PATH_MAX] = { 0 };

    if (digest == NULL) {
        ERROR("invalid NULL digest");
        return NULL;
    }

    nret = snprintf(full_digest, sizeof(full_digest), "%s%s", SHA256_PREFIX, digest);
    if (nret < 0 || (size_t)nret >= sizeof(full_digest)) {
        ERROR("digest too long failed");
        return NULL;
    }

    return util_strdup_s(full_digest);
}

/* util_stat2proc() makes sure it can handle arbitrary executable file basenames
 * for `cmd', i.e. those with embedded whitespace or embedded ')'s.
 * Such names confuse %s (see scanf(3)), so the string is split and %39c
 * is used instead. (except for embedded ')' "(%[^)]c)" would work.
 */
proc_t *util_stat2proc(const char *s, size_t len)
{
    int num;
    proc_t *p = NULL;
    char *tmp = NULL;

    if (s == NULL) {
        return NULL;
    }
    if (len == 0) {
        return NULL;
    }

    tmp = strrchr(s, ')'); /* split into "PID (cmd" and "<rest>" */
    if (tmp == NULL) {
        return NULL;
    }
    *tmp = '\0'; /* replace trailing ')' with NUL */

    p = util_common_calloc_s(sizeof(proc_t));
    if (p == NULL) {
        return NULL;
    }

    /* parse these two strings separately, skipping the leading "(". */
    /* comm[16] in kernel */
    num = sscanf(s, "%d (%15c", &p->pid, p->cmd);
    if (num != 2) {
        ERROR("Call sscanf error: %s", errno ? strerror(errno) : "");
        free(p);
        return NULL;
    }
    num = sscanf(tmp + 2, /* skip space after ')' too */
                 "%c "
                 "%d %d %d %d %d "
                 "%lu %lu %lu %lu %lu "
                 "%Lu %Lu %Lu %Lu " /* utime stime cutime cstime */
                 "%ld %ld %ld %ld "
                 "%Lu ", /* start_time */
                 &p->state, &p->ppid, &p->pgrp, &p->session, &p->tty, &p->tpgid, &p->flags, &p->min_flt, &p->cmin_flt,
                 &p->maj_flt, &p->cmaj_flt, &p->utime, &p->stime, &p->cutime, &p->cstime, &p->priority, &p->nice,
                 &p->timeout, &p->it_real_value, &p->start_time);
    if (num != 20) { // max arg to read
        ERROR("Call sscanf error: %s", errno ? strerror(errno) : "");
        free(p);
        return NULL;
    }

    if (p->tty == 0) {
        p->tty = -1; /* the old notty val, update elsewhere bef. moving to 0 */
    }
    return p;
}

bool util_process_alive(pid_t pid, unsigned long long start_time)
{
    int sret = 0;
    bool alive = true;
    proc_t *pid_info = NULL;
    char filename[PATH_MAX] = { 0 };
    char sbuf[1024] = { 0 }; /* bufs for stat */

    if (pid == 0) {
        return false;
    }

    sret = kill(pid, 0);
    if (sret < 0 && errno == ESRCH) {
        return false;
    }

    sret = snprintf(filename, sizeof(filename), "/proc/%d/stat", pid);
    if (sret < 0 || (size_t)sret >= sizeof(filename)) {
        ERROR("Failed to sprintf filename");
        goto out;
    }

    if ((util_file2str(filename, sbuf, sizeof(sbuf))) == -1) {
        ERROR("Failed to read pidfile %s", filename);
        alive = false;
        goto out;
    }

    pid_info = util_stat2proc(sbuf, sizeof(sbuf));
    if (pid_info == NULL) {
        ERROR("Failed to get proc stat info");
        alive = false;
        goto out;
    }

    if (start_time != pid_info->start_time) {
        alive = false;
    }
out:
    free(pid_info);
    return alive;
}

static void set_stderr_buf(char **stderr_buf, const char *format, ...)
{
    char errbuf[BUFSIZ + 1] = { 0 };

    UTIL_FREE_AND_SET_NULL(*stderr_buf);

    va_list argp;
    va_start(argp, format);

    int nret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);

    if (nret < 0 || nret >= BUFSIZ) {
        return;
    }

    *stderr_buf = util_marshal_string(errbuf);
    if (*stderr_buf == NULL) {
        *stderr_buf = util_strdup_s(errbuf);
    }
}

static int open_devnull(void)
{
    int fd = util_open("/dev/null", O_RDWR, 0);
    if (fd < 0) {
        ERROR("Can't open /dev/null");
    }

    return fd;
}

static int null_stdin(void)
{
    int ret = -1;
    int fd = -1;

    fd = open_devnull();
    if (fd >= 0) {
        ret = dup2(fd, STDIN_FILENO);
        close(fd);
        if (ret < 0) {
            return -1;
        }
    }

    return ret;
}

static inline bool deal_with_result_of_waitpid_nomsg(char **stderr_msg, size_t errmsg_len)
{
    if (*stderr_msg == NULL || strlen(*stderr_msg) == 0 || errmsg_len == 0) {
        return true;
    }
    return false;
}

static bool deal_with_result_of_waitpid(int status, char **stderr_msg, size_t errmsg_len)
{
    int signal;
    bool nomsg = false;

    if (stderr_msg == NULL) {
        ERROR("Invalid arguments");
        return false;
    }

    nomsg = deal_with_result_of_waitpid_nomsg(stderr_msg, errmsg_len);

    if (status < 0) {
        if (nomsg) {
            set_stderr_buf(stderr_msg, "Failed to wait exec cmd process");
        }
        return false;
    }

    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0) {
            return true;
        }
        if (nomsg) {
            set_stderr_buf(stderr_msg, "Command exit with status: %d", WEXITSTATUS(status));
        }
    } else if (WIFSIGNALED((unsigned int)status)) {
        signal = WTERMSIG(status);
        if (nomsg) {
            set_stderr_buf(stderr_msg, "Command exit with signal: %d", signal);
        }
    } else if (WIFSTOPPED(status)) {
        signal = WSTOPSIG(status);
        if (nomsg) {
            set_stderr_buf(stderr_msg, "Command stop with signal: %d", signal);
        }
    } else {
        if (nomsg) {
            set_stderr_buf(stderr_msg, "Command exit with unknown status: %d", status);
        }
    }

    return false;
}

static void marshal_stderr_msg(char **buffer, size_t *real_size)
{
    char *tmp_err = NULL;
    char *stderr_buffer = *buffer;
    size_t stderr_real_size = *real_size;

    if (stderr_buffer != NULL && strlen(stderr_buffer) > 0 && stderr_real_size > 0) {
        tmp_err = util_marshal_string(stderr_buffer);
        if (tmp_err != NULL) {
            free(stderr_buffer);
            *buffer = tmp_err;
            *real_size = strlen(tmp_err);
        }
    }
}

bool util_exec_top_cmd(exec_top_func_t cb_func, char **args, const char *pid_args, size_t args_len, char **stdout_msg,
                       char **stderr_msg)
{
    bool ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    size_t stdout_buf_size = 0;
    size_t stderr_buf_size = 0;
    size_t stdout_real_size = 0;
    size_t stderr_real_size = 0;
    int stdout_close_flag = 0;
    int stderr_close_flag = 0;
    int err_fd[2] = { -1, -1 };
    int out_fd[2] = { -1, -1 };
    pid_t pid = 0;
    int status = 0;

    if (pipe2(err_fd, O_CLOEXEC | O_NONBLOCK) != 0) {
        ERROR("Failed to create pipe");
        set_stderr_buf(&stderr_buffer, "Failed to create pipe");
        goto out;
    }
    if (pipe2(out_fd, O_CLOEXEC | O_NONBLOCK) != 0) {
        ERROR("Failed to create pipe");
        set_stderr_buf(&stderr_buffer, "Failed to create pipe");
        close(err_fd[0]);
        close(err_fd[1]);
        goto out;
    }

    pid = fork();
    if (pid == (pid_t) -1) {
        ERROR("Failed to fork()");
        set_stderr_buf(&stderr_buffer, "Failed to fork()");
        close(err_fd[0]);
        close(err_fd[1]);
        close(out_fd[0]);
        close(out_fd[1]);
        goto out;
    }

    if (pid == (pid_t)0) {
        int nret = 0;
        nret = null_stdin();
        if (nret < 0) {
            WARN("Failed to set stdin to /dev/null");
        }

        // child process, dup2 out_fd[1] to stdout
        close(out_fd[0]);
        dup2(out_fd[1], STDOUT_FILENO);

        // child process, dup2 err_fd[1] to stderr
        close(err_fd[0]);
        dup2(err_fd[1], STDERR_FILENO);

        if (util_check_inherited(true, -1) != 0) {
            COMMAND_ERROR("Close inherited fds failed");
        }

        /* become session leader */
        nret = setsid();
        if (nret < 0) {
            COMMAND_ERROR("Failed to set process %d as group leader", getpid());
        }

        cb_func(args, pid_args, args_len);
    }

    close(err_fd[1]);
    close(out_fd[1]);

    for (;;) {
        if (stdout_close_flag == 0) {
            stdout_close_flag = util_read_pipe(out_fd[0], &stdout_buffer, &stdout_buf_size, &stdout_real_size);
        }
        if (stderr_close_flag == 0) {
            stderr_close_flag = util_read_pipe(err_fd[0], &stderr_buffer, &stderr_buf_size, &stderr_real_size);
        }
        if (stdout_close_flag != 0 && stderr_close_flag != 0) {
            break;
        }
        util_usleep_nointerupt(1000);
    }

    marshal_stderr_msg(&stderr_buffer, &stderr_real_size);

    status = util_wait_for_pid_status(pid);

    ret = deal_with_result_of_waitpid(status, &stderr_buffer, stderr_real_size);

    close(err_fd[0]);
    close(out_fd[0]);
out:
    *stdout_msg = stdout_buffer;
    *stderr_msg = stderr_buffer;
    return ret;
}

static void close_pipes_fd(int *pipes, size_t pipe_size)
{
    size_t i = 0;

    for (i = 0; i < pipe_size; i++) {
        if (pipes[i] >= 0) {
            close(pipes[i]);
            pipes[i] = -1;
        }
    }
}

bool util_raw_exec_cmd(exec_func_t cb_func, void *cb_args, exitcode_deal_func_t exitcode_cb, exec_cmd_args *cmd_args)
{
    bool ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    size_t stdout_buf_size = 0;
    size_t stderr_buf_size = 0;
    size_t stdout_real_size = 0;
    size_t stderr_real_size = 0;
    int stdout_close_flag = 0;
    int stderr_close_flag = 0;
    int err_fd[2] = { -1, -1 };
    int out_fd[2] = { -1, -1 };
    int in_fd[2] = { -1, -1 };
    pid_t pid = 0;
    int status = 0;

    if (cmd_args == NULL) {
        ERROR("empty cmd args");
        return false;
    }

    if (pipe2(in_fd, O_CLOEXEC | O_NONBLOCK) != 0) {
        ERROR("Failed to create stdin pipe");
        set_stderr_buf(&stderr_buffer, "Failed to create stdin pipe");
        goto out;
    }

    if (pipe2(err_fd, O_CLOEXEC | O_NONBLOCK) != 0) {
        ERROR("Failed to create pipe");
        set_stderr_buf(&stderr_buffer, "Failed to create pipe");
        close_pipes_fd(in_fd, 2);
        goto out;
    }
    if (pipe2(out_fd, O_CLOEXEC | O_NONBLOCK) != 0) {
        ERROR("Failed to create pipe");
        set_stderr_buf(&stderr_buffer, "Failed to create pipe");
        close_pipes_fd(in_fd, 2);
        close_pipes_fd(err_fd, 2);
        goto out;
    }

    pid = fork();
    if (pid == (pid_t) -1) {
        ERROR("Failed to fork()");
        set_stderr_buf(&stderr_buffer, "Failed to fork()");
        close_pipes_fd(in_fd, 2);
        close_pipes_fd(err_fd, 2);
        close_pipes_fd(out_fd, 2);
        goto out;
    }

    if (pid == (pid_t)0) {
        int nret = 0;

        close(in_fd[1]);
        if (in_fd[0] != STDIN_FILENO) {
            dup2(in_fd[0], STDIN_FILENO);
        } else {
            if (fcntl(in_fd[0], F_SETFD, 0) != 0) {
                fprintf(stderr, "Failed to remove FD_CLOEXEC from fd.");
                exit(127);
            }
        }
        close(in_fd[0]);

        // child process, dup2 out_fd[1] to stdout
        close(out_fd[0]);
        dup2(out_fd[1], STDOUT_FILENO);

        // child process, dup2 err_fd[1] to stderr
        close(err_fd[0]);
        dup2(err_fd[1], STDERR_FILENO);

        if (util_check_inherited(true, -1) != 0) {
            COMMAND_ERROR("Close inherited fds failed");
        }

        /* become session leader */
        nret = setsid();
        if (nret < 0) {
            COMMAND_ERROR("Failed to set process %d as group leader", getpid());
        }

        cb_func(cb_args);
    }

    /* parent */
    close(err_fd[1]);
    err_fd[1] = -1;
    close(out_fd[1]);
    out_fd[1] = -1;

    close(in_fd[0]);
    in_fd[0] = -1;
    if (cmd_args->stdin_msg != NULL) {
        size_t len = strlen(cmd_args->stdin_msg);
        if (util_write_nointr(in_fd[1], cmd_args->stdin_msg, len) != len) {
            WARN("Write instr: %s failed", cmd_args->stdin_msg);
        }
    }
    close(in_fd[1]);
    in_fd[1] = -1;

    for (;;) {
        if (stdout_close_flag == 0) {
            stdout_close_flag = util_read_pipe(out_fd[0], &stdout_buffer, &stdout_buf_size, &stdout_real_size);
        }
        if (stderr_close_flag == 0) {
            stderr_close_flag = util_read_pipe(err_fd[0], &stderr_buffer, &stderr_buf_size, &stderr_real_size);
        }
        if (stdout_close_flag != 0 && stderr_close_flag != 0) {
            break;
        }
        util_usleep_nointerupt(1000);
    }

    marshal_stderr_msg(&stderr_buffer, &stderr_real_size);

    status = util_wait_for_pid_status(pid);

    ret = exitcode_cb(status, &stderr_buffer, stderr_real_size);

    close(err_fd[0]);
    close(out_fd[0]);
out:
    *(cmd_args->stdout_msg) = stdout_buffer;
    *(cmd_args->stderr_msg) = stderr_buffer;
    return ret;
}

bool util_exec_cmd(exec_func_t cb_func, void *args, const char *stdin_msg, char **stdout_msg, char **stderr_msg)
{
    exec_cmd_args c_args = { 0 };

    c_args.stdin_msg = stdin_msg;
    c_args.stdout_msg = stdout_msg;
    c_args.stderr_msg = stderr_msg;

    return util_raw_exec_cmd(cb_func, args, deal_with_result_of_waitpid, &c_args);
}

char **util_get_backtrace(void)
{
#define BACKTRACE_SIZE 16
    int addr_cnts;
    void *buffer[BACKTRACE_SIZE];
    char **syms = NULL;

    addr_cnts = backtrace(buffer, BACKTRACE_SIZE);
    if (addr_cnts <= 0) {
        return NULL;
    }

    syms = backtrace_symbols(buffer, addr_cnts);
    if (syms == NULL) {
        return NULL;
    }

    return syms;
}

/* isulad: get starttime of process pid */
proc_t *util_get_process_proc_info(pid_t pid)
{
    int sret = 0;
    proc_t *pid_info = NULL;
    char filename[PATH_MAX] = { 0 };
    char sbuf[1024] = { 0 }; /* bufs for stat */

    sret = snprintf(filename, sizeof(filename), "/proc/%d/stat", pid);
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

out:
    return pid_info;
}

int util_env_set_val(char ***penv, const size_t *penv_len, const char *key, size_t key_len, const char *newkv)
{
    size_t i = 0;
    char **env = NULL;
    size_t env_len = 0;

    if (penv == NULL || penv_len == NULL || key == NULL || newkv == NULL) {
        return -1;
    }

    env = *penv;
    env_len = *penv_len;

    for (i = 0; i < env_len; i++) {
        size_t elen = strlen(env[i]);
        if (key_len < elen && (strncmp(key, env[i], key_len) == 0) && (env[i][key_len] == '=')) {
            free(env[i]);
            env[i] = util_strdup_s(newkv);
            if (env[i] == NULL) {
                ERROR("out of memory");
                return -1;
            }
            return 0;
        }
    }

    /* can not find key env, return error. */
    return -1;
}

int util_env_insert(char ***penv, size_t *penv_len, const char *key, size_t key_len, const char *newkv)
{
    char **env = NULL;
    size_t env_len = 0;
    char **temp = NULL;
    int ret = 0;

    if (penv == NULL || penv_len == NULL || key == NULL || newkv == NULL) {
        return -1;
    }

    if (util_env_set_val(penv, penv_len, key, key_len, newkv) == 0) {
        return 0;
    }

    env = *penv;
    env_len = *penv_len;

    if (env_len > (SIZE_MAX / sizeof(char *)) - 1) {
        ERROR("Failed to realloc memory for envionment variables");
        return -1;
    }

    ret = util_mem_realloc((void **)(&temp), (env_len + 1) * sizeof(char *), env, env_len * sizeof(char *));
    if (ret != 0) {
        ERROR("Failed to realloc memory for envionment variables");
        return -1;
    }

    env = temp;
    env[env_len] = util_strdup_s(newkv);
    env_len++;

    *penv = env;
    *penv_len = env_len;
    return 0;
}

char *util_env_get_val(char **env, size_t env_len, const char *key, size_t key_len)
{
    size_t i = 0;

    if (key == NULL || env == NULL) {
        return NULL;
    }

    for (i = 0; i < env_len; i++) {
        size_t elen = strlen(env[i]);
        if (key_len < elen && !strncmp(key, env[i], key_len) && env[i][key_len] == '=') {
            return util_strdup_s(env[i] + key_len + 1);
        }
    }

    return NULL;
}

int util_parse_user_remap(const char *user_remap, unsigned int *host_uid, unsigned int *host_gid, unsigned int *size)
{
    int ret = 0;
    size_t args_len = 0;
    char **items = NULL;

    if (user_remap == NULL || host_uid == NULL || host_gid == NULL || size == NULL) {
        COMMAND_ERROR("Out of memory");
        return -1;
    }
    items = util_string_split(user_remap, ':');
    if (items == NULL) {
        COMMAND_ERROR("split user remap '%s' failed", user_remap);
        ret = -1;
        goto out;
    }
    args_len = util_array_len((const char **)items);

    switch (args_len) {
        case 3:
            ret = util_safe_uint(items[0], host_uid);
            if (ret) {
                COMMAND_ERROR("Invalid host uid for '%s', uid must be unsigned int", user_remap);
                break;
            }
            ret = util_safe_uint(items[1], host_gid);
            if (ret) {
                COMMAND_ERROR("Invalid host gid for '%s', gid must be unsigned int", user_remap);
                break;
            }
            ret = util_safe_uint(items[2], size);
            if (ret) {
                COMMAND_ERROR("Invalid id offset for '%s', offset must be unsigned int", user_remap);
                break;
            }
            if (*size > MAX_ID_OFFSET || *size == 0) {
                COMMAND_ERROR("Invalid id offset for '%s', offset must be greater than 0 and less than %d", user_remap,
                              MAX_ID_OFFSET);
                ret = -1;
                break;
            }
            break;
        default:
            COMMAND_ERROR("Invalid user remap specification '%s'. unsupported format", user_remap);
            ret = -1;
            break;
    }

out:
    util_free_array(items);
    return ret;
}

bool util_check_pid_max_kernel_namespaced()
{
    bool ret = false;
    FILE *fp = NULL;
    char *pline = NULL;
    size_t length = 0;

    fp = util_fopen("/proc/kallsyms", "r");
    if (fp == NULL) {
        SYSERROR("Failed to open /proc/kallsyms");
        return ret;
    }
    while (getline(&pline, &length, fp) != -1) {
        if (strstr(pline, "proc_dointvec_pidmax") != NULL) {
            ret = true;
            goto out;
        }
    }
out:
    fclose(fp);
    free(pline);
    return ret;
}

void util_free_sensitive_string(char *str)
{
    if (!util_valid_str(str)) {
        goto out;
    }

    (void)memset(str, 0, strlen(str));

out:
    free(str);
}

void util_memset_sensitive_string(char *str)
{
    if (!util_valid_str(str)) {
        return;
    }

    (void)memset(str, 0, strlen(str));
}

static int set_echo_back(bool echo_back)
{
    struct termios old, new;

    if (tcgetattr(STDIN_FILENO, &old)) {
        ERROR("get tc attribute failed: %s\n", strerror(errno));
        return -1;
    }

    new = old;

    if (echo_back) {
        new.c_lflag |= ECHO | ICANON;
    } else {
        new.c_lflag &= ~(ECHO | ICANON);
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &new)) {
        ERROR("set tc attribute failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int util_input_notty(char *buf, size_t maxlen)
{
    size_t i = 0;
    int ret = 0;

    for (i = 0; i < maxlen; i++) {
        int c = getchar();
        if (c == EOF || c == '\n') {
            break;
        }
        if (c < 0) {
            ret = -1;
            break;
        }
        buf[i] = (char)c;
    }

    return ret ? ret : (int)i;
}

int util_input_readall(char *buf, size_t maxlen)
{
    size_t i = 0;
    int ret = 0;

    for (;;) {
        int c = getchar();
        if (c == EOF) {
            break;
        }
        if (c < 0) {
            ret = -1;
            break;
        }
        // Skip chars larger than maxlen
        if (i + 1 >= maxlen) {
            continue;
        }
        buf[i] = (char)c;
        i++;
    }
    buf[i] = 0;

    // Strip last '\n'
    if (i > 0 && buf[i - 1] == '\n') {
        buf[i - 1] = 0;
        i--;
    }
    // Strip last '\r'
    if (i > 0 && buf[i - 1] == '\r') {
        buf[i - 1] = 0;
        i--;
    }

    return ret ? ret : (int)i;
}

static int util_input(char *buf, size_t maxlen, bool echo_back)
{
    int ret = 0;

    if (set_echo_back(echo_back)) {
        return -1;
    }

    ret = util_input_notty(buf, maxlen);

    if (set_echo_back(true)) {
        return -1;
    }

    return ret;
}

// Get input from stdin, echo back if get any character.
int util_input_echo(char *buf, size_t maxlen)
{
    return util_input(buf, maxlen, true);
}

// Get input from stdin, no echo back.
int util_input_noecho(char *buf, size_t maxlen)
{
    return util_input(buf, maxlen, false);
}

void util_usleep_nointerupt(unsigned long usec)
{
#define SECOND_TO_USECOND_MUTIPLE 1000000
    int ret = 0;
    struct timespec request = { 0 };
    struct timespec remain = { 0 };
    if (usec == 0) {
        return;
    }

    request.tv_sec = (time_t)(usec / SECOND_TO_USECOND_MUTIPLE);
    request.tv_nsec = (long)((usec % SECOND_TO_USECOND_MUTIPLE) * 1000);

    do {
        ret = nanosleep(&request, &remain);
        request = remain;
    } while (ret == -1 && errno == EINTR);
}
int util_generate_random_str(char *id, size_t len)
{
    int fd = -1;
    int num = 0;
    size_t i;
    const int m = 256;

    len = len / 2;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        ERROR("Failed to open /dev/urandom");
        return -1;
    }
    for (i = 0; i < len; i++) {
        int nret;
        if (read(fd, &num, sizeof(int)) < 0) {
            ERROR("Failed to read urandom value");
            close(fd);
            return -1;
        }
        unsigned char rs = (unsigned char)(num % m);
        nret = snprintf((id + i * 2), ((len - i) * 2 + 1), "%02x", (unsigned int)rs);
        if (nret < 0 || (size_t)nret >= ((len - i) * 2 + 1)) {
            ERROR("Failed to snprintf random string");
            close(fd);
            return -1;
        }
    }
    close(fd);
    id[i * 2] = '\0';
    return 0;
}

int util_check_inherited_exclude_fds(bool closeall, int *fds_to_ignore, size_t len_fds)
{
    struct dirent *pdirent = NULL;
    int fd, fddir;
    DIR *directory = NULL;
    size_t i = 0;

restart:
    directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        WARN("Failed to open directory: /proc/self/fd.");
        return -1;
    }

    fddir = dirfd(directory);
    pdirent = readdir(directory);
    for (; pdirent != NULL; pdirent = readdir(directory)) {
        if (util_dir_skip_current(pdirent)) {
            continue;
        }

        if (util_safe_int(pdirent->d_name, &fd) < 0) {
            continue;
        }

        for (i = 0; i < len_fds; i++) {
            if (fds_to_ignore[i] == fd) {
                break;
            }
        }

        if (i < len_fds && fd == fds_to_ignore[i]) {
            continue;
        }

        if (util_is_std_fileno(fd) || fd == fddir) {
            continue;
        }

        if (closeall) {
            if (fd >= 0) {
                close(fd);
                fd = -1;
            }
            if (directory != NULL) {
                closedir(directory);
                directory = NULL;
            }
            goto restart;
        }
    }

    closedir(directory);
    return 0;
}

static char *get_cpu_variant()
{
    char *variant = NULL;
    char *cpuinfo = NULL;
    char *start_pos = NULL;
    char *end_pos = NULL;

    cpuinfo = util_read_text_file("/proc/cpuinfo");
    if (cpuinfo == NULL) {
        ERROR("read /proc/cpuinfo failed");
        return NULL;
    }

    start_pos = strstr(cpuinfo, "CPU architecture");
    if (start_pos == NULL) {
        ERROR("can not found the key \"CPU architecture\" when try to get cpu variant");
        goto out;
    }
    end_pos = strchr(start_pos, '\n');
    if (end_pos != NULL) {
        *end_pos = 0;
    }
    start_pos = strchr(start_pos, ':');
    if (start_pos == NULL) {
        ERROR("can not found delimiter \":\" when try to get cpu variant");
        goto out;
    }
    util_trim_newline(start_pos);
    start_pos = util_trim_space(start_pos);

    variant = util_strings_to_lower(start_pos);

out:
    free(cpuinfo);
    cpuinfo = NULL;

    return variant;
}

int util_normalized_host_os_arch(char **host_os, char **host_arch, char **host_variant)
{
    int ret = 0;
    struct utsname uts;
    char *tmp_variant = NULL;

    if (host_os == NULL || host_arch == NULL || host_variant == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    if (uname(&uts) < 0) {
        ERROR("Failed to read host arch and os: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    *host_os = util_strings_to_lower(uts.sysname);

    if (strcasecmp("i386", uts.machine) == 0) {
        *host_arch = util_strdup_s("386");
    } else if ((strcasecmp("x86_64", uts.machine) == 0) || (strcasecmp("x86-64", uts.machine) == 0)) {
        *host_arch = util_strdup_s("amd64");
    } else if (strcasecmp("aarch64", uts.machine) == 0) {
        *host_arch = util_strdup_s("arm64");
    } else if ((strcasecmp("armhf", uts.machine) == 0) || (strcasecmp("armel", uts.machine) == 0)) {
        *host_arch = util_strdup_s("arm");
    } else {
        *host_arch = util_strdup_s(uts.machine);
    }

    if (!strcmp(*host_arch, "arm") || !strcmp(*host_arch, "arm64")) {
        *host_variant = get_cpu_variant();
        if (!strcmp(*host_arch, "arm64") && *host_variant != NULL &&
            (!strcmp(*host_variant, "8") || !strcmp(*host_variant, "v8"))) {
            free(*host_variant);
            *host_variant = NULL;
        }
        if (!strcmp(*host_arch, "arm") && *host_variant == NULL) {
            *host_variant = util_strdup_s("v7");
        } else if (!strcmp(*host_arch, "arm") && *host_variant != NULL) {
            tmp_variant = *host_variant;
            *host_variant = NULL;
            if (!strcmp(tmp_variant, "5")) {
                *host_variant = util_strdup_s("v5");
            } else if (!strcmp(tmp_variant, "6")) {
                *host_variant = util_strdup_s("v6");
            } else if (!strcmp(tmp_variant, "7")) {
                *host_variant = util_strdup_s("v7");
            } else if (!strcmp(tmp_variant, "8")) {
                *host_variant = util_strdup_s("v8");
            } else {
                *host_variant = util_strdup_s(tmp_variant);
            }
            free(tmp_variant);
            tmp_variant = NULL;
        }
    }

out:
    if (ret != 0) {
        free(*host_os);
        *host_os = NULL;
        free(*host_arch);
        *host_arch = NULL;
        free(*host_variant);
        *host_variant = NULL;
    }

    return ret;
}

int util_read_pid_ppid_info(uint32_t pid, pid_ppid_info_t *pid_info)
{
    int ret = 0;
    proc_t *proc = NULL;
    proc_t *p_proc = NULL;

    if (pid == 0) {
        ret = -1;
        goto out;
    }

    proc = util_get_process_proc_info((pid_t)pid);
    if (proc == NULL) {
        ret = -1;
        goto out;
    }

    p_proc = util_get_process_proc_info((pid_t)proc->ppid);
    if (p_proc == NULL) {
        ret = -1;
        goto out;
    }

    pid_info->pid = proc->pid;
    pid_info->start_time = proc->start_time;
    pid_info->ppid = proc->ppid;
    pid_info->pstart_time = p_proc->start_time;

out:
    free(proc);
    free(p_proc);
    return ret;
}

void util_parse_user_group(const char *username, char **user, char **group, char **tmp_dup)
{
    char *tmp = NULL;
    char *pdot = NULL;

    if (user == NULL || group == NULL || tmp_dup == NULL) {
        return;
    }

    if (username != NULL) {
        tmp = util_strdup_s(username);

        // for free tmp in caller
        *tmp_dup = tmp;

        pdot = strstr(tmp, ":");
        if (pdot != NULL) {
            *pdot = '\0';
            if (pdot != tmp) {
                // User found
                *user = tmp;
            }
            if (*(pdot + 1) != '\0') {
                // group found
                *group = pdot + 1;
            }
        } else {
            // No : found
            if (*tmp != '\0') {
                *user = tmp;
            }
        }
    }

    return;
}

defs_map_string_object *dup_map_string_empty_object(defs_map_string_object *src)
{
    int ret = 0;
    size_t i = 0;
    defs_map_string_object *dst = NULL;

    if (src == NULL) {
        ERROR("invalid null param");
        return NULL;
    }

    dst = util_common_calloc_s(sizeof(defs_map_string_object));
    if (dst == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    dst->keys = util_common_calloc_s(src->len * sizeof(char *));
    dst->values = util_common_calloc_s(src->len * sizeof(defs_map_string_object_element *));
    if (dst->keys == NULL || dst->values == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < src->len; i++) {
        dst->keys[i] = util_strdup_s(src->keys[i]);
        dst->values[i] = NULL;
    }
    dst->len = src->len;

out:
    if (ret != 0) {
        free_defs_map_string_object(dst);
        dst = NULL;
    }

    return dst;
}
