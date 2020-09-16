/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide exec functions
 *********************************************************************************/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "libcni_exec.h"

#include "utils.h"
#include "libcni_tools.h"
#include "libcni_errno.h"
#include "isula_libutils/log.h"

static int raw_exec(const char *plugin_path, const char *stdin_data, char * const environs[], char **stdout_str,
                    cni_exec_error **err);

static char *str_cni_exec_error(const cni_exec_error *e_err)
{
    char *result = NULL;
    int ret = 0;

    if (e_err == NULL) {
        ERROR("Argument is NULL");
        return result;
    }
    ret = asprintf(&result, "%s%s", e_err->msg ? e_err->msg : "", e_err->details ? e_err->details : "");
    if (ret < 0) {
        ERROR("Sprintf failed");
        return NULL;
    }
    return result;
}

static int do_parse_exec_stdout_str(int exec_ret, const char *cni_net_conf_json, const cni_exec_error *e_err,
                                    const char *stdout_str, struct result **result, char **err)
{
    int ret = exec_ret;
    char *version = NULL;

    if (exec_ret != 0) {
        if (e_err != NULL) {
            *err = str_cni_exec_error(e_err);
        } else {
            *err = util_strdup_s("raw exec fail");
        }
    } else {
        version = cniversion_decode(cni_net_conf_json, err);
        if (version == NULL) {
            ret = -1;
            ERROR("Decode cni version failed: %s", *err != NULL ? *err : "");
            goto out;
        }
        if (stdout_str == NULL || strlen(stdout_str) == 0) {
            ERROR("Get empty stdout message");
            goto out;
        }
        *result = new_result(version, stdout_str, err);
        if (*result == NULL) {
            ERROR("Parse result failed: %s", *err != NULL ? *err : "");
            ret = -1;
        }
    }

out:
    free(version);
    return ret;
}

static inline bool check_exec_plugin_with_result_args(const char *cni_net_conf_json, struct result * const *result,
                                                      char * const *err)
{
    return (cni_net_conf_json == NULL || result == NULL || err == NULL);
}

int exec_plugin_with_result(const char *plugin_path, const char *cni_net_conf_json, const struct cni_args *cniargs,
                            struct result **result, char **err)
{
    char **envs = NULL;
    char *stdout_str = NULL;
    cni_exec_error *e_err = NULL;
    int ret = 0;

    if (check_exec_plugin_with_result_args(cni_net_conf_json, result, err)) {
        ERROR("Invalid arguments");
        return -1;
    }
    if (cniargs != NULL) {
        envs = as_env(cniargs);
        if (envs == NULL) {
            *err = util_strdup_s("As env failed");
            ret = -1;
            goto out;
        }
    }

    ret = raw_exec(plugin_path, cni_net_conf_json, envs, &stdout_str, &e_err);
    DEBUG("Raw exec \"%s\" result: %d", plugin_path, ret);
    ret = do_parse_exec_stdout_str(ret, cni_net_conf_json, e_err, stdout_str, result, err);
out:
    free(stdout_str);
    util_free_array(envs);
    free_cni_exec_error(e_err);
    return ret;
}

int exec_plugin_without_result(const char *plugin_path, const char *cni_net_conf_json, const struct cni_args *cniargs,
                               char **err)
{
    char **envs = NULL;
    cni_exec_error *e_err = NULL;
    int ret = 0;
    bool invalid_arg = (cni_net_conf_json == NULL || err == NULL);

    if (invalid_arg) {
        ERROR("Invalid arguments");
        return -1;
    }
    if (cniargs != NULL) {
        envs = as_env(cniargs);
        if (envs == NULL) {
            *err = util_strdup_s("As env failed");
            goto out;
        }
    }

    ret = raw_exec(plugin_path, cni_net_conf_json, envs, NULL, &e_err);
    if (ret != 0) {
        if (e_err != NULL) {
            *err = str_cni_exec_error(e_err);
        } else {
            *err = util_strdup_s("raw exec fail");
        }
    }
    DEBUG("Raw exec \"%s\" result: %d", plugin_path, ret);
out:
    util_free_array(envs);
    free_cni_exec_error(e_err);
    return ret;
}

static int do_parse_get_version_errmsg(int exec_ret, const cni_exec_error *e_err, struct plugin_info **result,
                                       char **err)
{
    char *str_err = NULL;

    if (exec_ret == 0) {
        return 0;
    }

    str_err = str_cni_exec_error(e_err);
    if (str_err != NULL && strcmp(str_err, "unknown CNI_COMMAND: VERSION") == 0) {
        const char *default_supports[] = { "0.1.0", NULL };
        *result = plugin_supports(default_supports, 1, err);
        if (*result == NULL) {
            ERROR("Parse result failed: %s", *err != NULL ? *err : "");
            goto free_out;
        }
    }
    *err = str_err;
    str_err = NULL;
free_out:
    free(str_err);
    return -1;
}

int raw_get_version_info(const char *plugin_path, struct plugin_info **result, char **err)
{
    int ret = 0;
    struct cni_args args = {
        .command = "VERSION",
        .netns = "dummy",
        .ifname = "dummy",
        .path = "dummy",
        .container_id = NULL,
        .plugin_args = NULL,
        .plugin_args_len = 0,
        .plugin_args_str = NULL
    };
    char *stdin_data = NULL;
    char *stdout_str = NULL;
    const char *version = current();
    size_t len = 0;
    char **envs = NULL;
    cni_exec_error *e_err = NULL;
    bool invalid_arg = (result == NULL || err == NULL);

    if (invalid_arg) {
        ERROR("Invalid arguments");
        return -1;
    }

    envs = as_env(&args);
    if (envs == NULL) {
        ret = -1;
        *err = util_strdup_s("As env failed");
        goto free_out;
    }
    len = strlen("{\"cniVersion\":}") + strlen(version) + 1;
    stdin_data = util_common_calloc_s(len);
    if (stdin_data == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }
    ret = snprintf(stdin_data, len, "{\"cniVersion\":%s}", version);
    if (ret < 0 || (size_t)ret >= len) {
        ERROR("Sprintf failed");
        *err = util_strdup_s("Sprintf failed");
        goto free_out;
    }
    ret = raw_exec(plugin_path, stdin_data, envs, &stdout_str, &e_err);
    DEBUG("Raw exec \"%s\" result: %d", plugin_path, ret);
    ret = do_parse_get_version_errmsg(ret, e_err, result, err);
    if (ret != 0) {
        goto free_out;
    }
    *result = plugin_info_decode(stdout_str, err);
    if (*result == NULL) {
        ret = -1;
    }

free_out:
    free_cni_exec_error(e_err);
    util_free_array(envs);
    free(stdin_data);
    free(stdout_str);
    return ret;
}

static int prepare_child(int pipe_stdin, int pipe_stdout)
{
    sigset_t mask;
    int ecode = 0;
    int ret = 0;

    if (pipe_stdin != STDIN_FILENO) {
        ret = dup2(pipe_stdin, STDIN_FILENO);
    } else {
        ret = fcntl(pipe_stdin, F_SETFD, 0);
    }
    if (ret != 0) {
        ecode = EXIT_FAILURE;
        goto child_err_out;
    }
    (void)close(pipe_stdin);
    pipe_stdin = -1;

    if (pipe_stdout != STDOUT_FILENO) {
        ret = dup2(pipe_stdout, STDOUT_FILENO);
    } else {
        ret = fcntl(pipe_stdout, F_SETFD, 0);
    }
    if (ret < 0) {
        ecode = EXIT_FAILURE;
        goto child_err_out;
    }
    (void)close(pipe_stdout);
    pipe_stdout = -1;

    {
        /*
         * unblock all signal
         * */
        ret = sigfillset(&mask);
        if (ret < 0) {
            ecode = EXIT_FAILURE;
            goto child_err_out;
        }
        ret = sigprocmask(SIG_UNBLOCK, &mask, NULL);
        if (ret < 0) {
            ecode = EXIT_FAILURE;
            goto child_err_out;
        }
    }

child_err_out:
    return ecode;
}

static void child_fun(const char *plugin_path, int pipe_stdin, int pipe_stdout, char * const environs[],
                      size_t envs_len)
{
    char *argv[2] = { NULL };
    int ecode = 0;

    argv[0] = util_strdup_s(plugin_path);

    ecode = prepare_child(pipe_stdin, pipe_stdout);
    if (ecode != 0) {
        goto child_err_out;
    }

    if (envs_len > 0) {
        ecode = execvpe(plugin_path, argv, environs);
    } else {
        ecode = execvp(plugin_path, argv);
    }

    (void)fprintf(stdout, "Execv: %s failed %s", plugin_path, strerror(errno));

child_err_out:
    free(argv[0]);
    if (ecode == 0) {
        ecode = 127;
    }
    if (pipe_stdin != -1) {
        (void)close(pipe_stdin);
    }
    if (pipe_stdout != -1) {
        (void)close(pipe_stdout);
    }
    exit(ecode);
}

static inline bool check_prepare_raw_exec_args(const char *plugin_path)
{
    return (plugin_path == NULL || util_validate_absolute_path(plugin_path));
}

static int prepare_raw_exec(const char *plugin_path, int pipe_stdin[2], int pipe_stdout[2], char *errmsg, size_t len)
{
    int ret = 0;

    if (check_prepare_raw_exec_args(plugin_path)) {
        ret = snprintf(errmsg, len, "Empty or not absolute path: %s", plugin_path);
        if (ret < 0 || (size_t)ret >= len) {
            ERROR("Sprintf failed");
        }
        return -1;
    }

    ret = pipe2(pipe_stdin, O_CLOEXEC | O_NONBLOCK);
    if (ret < 0) {
        ret = snprintf(errmsg, len, "Pipe stdin failed: %s", strerror(errno));
        if (ret < 0 || (size_t)ret >= len) {
            ERROR("Sprintf failed");
        }
        return -1;
    }

    ret = pipe2(pipe_stdout, O_CLOEXEC | O_NONBLOCK);
    if (ret < 0) {
        ret = snprintf(errmsg, len, "Pipe stdout failed: %s", strerror(errno));
        if (ret < 0 || (size_t)ret >= len) {
            ERROR("Sprintf failed");
        }
        return -1;
    }
    return 0;
}

static int write_stdin_data_to_child(int pipe_stdin[2], const char *stdin_data, char *errmsg, size_t errmsg_len)
{
    int ret = 0;
    size_t len = 0;

    if (stdin_data == NULL) {
        goto close_pipe;
    }

    len = strlen(stdin_data);
    if (util_write_nointr(pipe_stdin[1], stdin_data, len) != (ssize_t)len) {
        ret = snprintf(errmsg, errmsg_len, "Write stdin data failed: %s", strerror(errno));
        if (ret < 0 || (size_t)ret >= errmsg_len) {
            ERROR("Sprintf failed");
        }
        ret = -1;
    }
close_pipe:
    (void)close(pipe_stdin[1]);
    pipe_stdin[1] = -1;
    return ret;
}

static int read_child_stdout_msg(const int pipe_stdout[2], char *errmsg, size_t errmsg_len, char **stdout_str)
{
    int ret = 0;

    if (errmsg == NULL) {
        return 0;
    }
    if (stdout_str != NULL) {
        char buffer[MAX_BUFFER_SIZE] = { 0 };
        ssize_t tmp_len = util_read_nointr(pipe_stdout[0], buffer, MAX_BUFFER_SIZE - 1);
        if (tmp_len < 0) {
            ret = snprintf(errmsg, errmsg_len, "%s; read stdout failed: %s", strlen(errmsg) > 0 ? errmsg : "",
                           strerror(errno));
            if (ret < 0 || (size_t)ret >= errmsg_len) {
                ERROR("Sprintf failed");
            }
            ret = -1;
        } else if (tmp_len > 0) {
            *stdout_str = util_strdup_s(buffer);
        }
    }

    return ret;
}

static int wait_pid_for_raw_exec_child(pid_t child_pid, const int pipe_stdout[2], char **stdout_str, char *errmsg,
                                       size_t errmsg_len, bool *parse_exec_err)
{
    pid_t wait_pid = 0;
    int wait_status = 0;
    int ret = 0;

    if (errmsg == NULL) {
        return -1;
    }
    do {
        wait_pid = waitpid(child_pid, &wait_status, 0);
    } while (wait_pid < 0 && errno == EINTR);

    ret = read_child_stdout_msg(pipe_stdout, errmsg, errmsg_len, stdout_str);

    if (wait_pid < 0) {
        ret = snprintf(errmsg, errmsg_len, "%s; waitpid failed: %s", strlen(errmsg) > 0 ? errmsg : "",
                       strerror(errno));
        if (ret < 0 || (size_t)ret >= errmsg_len) {
            ERROR("Sprintf failed");
        }
        ret = -1;
        goto err_free_out;
    } else if (WIFEXITED(wait_status) && WEXITSTATUS(wait_status)) {
        ret = snprintf(errmsg, errmsg_len, "%s; get child status: %d", strlen(errmsg) > 0 ? errmsg : "",
                       WEXITSTATUS(wait_status));
        if (ret < 0 || (size_t)ret >= errmsg_len) {
            ERROR("Sprintf failed");
        }
        ret = WEXITSTATUS(wait_status);
        *parse_exec_err = true;
        goto err_free_out;
    } else if (WIFSIGNALED(wait_status)) {
        ret = snprintf(errmsg, errmsg_len, "%s; child get signal: %d", strlen(errmsg) > 0 ? errmsg : "",
                       WTERMSIG(wait_status));
        if (ret < 0 || (size_t)ret >= errmsg_len) {
            ERROR("Sprintf failed");
        }
        ret = INK_ERR_TERM_BY_SIG;
        *parse_exec_err = true;
        goto err_free_out;
    }

err_free_out:
    return ret;
}

static void close_raw_exec_pipes(int pipe_stdin[2], int pipe_stdout[2])
{
    if (pipe_stdout[0] >= 0) {
        (void)close(pipe_stdout[0]);
        pipe_stdout[0] = -1;
    }
    if (pipe_stdout[1] >= 0) {
        (void)close(pipe_stdout[1]);
        pipe_stdout[1] = -1;
    }
    if (pipe_stdin[0] >= 0) {
        (void)close(pipe_stdin[0]);
        pipe_stdin[0] = -1;
    }
    if (pipe_stdin[1] >= 0) {
        (void)close(pipe_stdin[1]);
        pipe_stdin[1] = -1;
    }
}

static inline bool check_make_err_message_args(bool parse_exec_err, char * const *stdout_str)
{
    return (parse_exec_err && stdout_str != NULL && *stdout_str != NULL);
}

static void make_err_message(const char *plugin_path, char **stdout_str, int ret, bool parse_exec_err, char *errmsg,
                             size_t errmsg_len, cni_exec_error **err)
{
    int nret = ret;
    bool get_err_msg = false;

    if (errmsg == NULL) {
        return;
    }
    if (check_make_err_message_args(parse_exec_err, stdout_str)) {
        parser_error json_err = NULL;
        *err = cni_exec_error_parse_data(*stdout_str, NULL, &json_err);
        if (*err == NULL) {
            nret = snprintf(errmsg, errmsg_len, "exec \'%s\': %s; parse failed: %s", plugin_path,
                            strlen(errmsg) > 0 ? errmsg : "", json_err);
            if (nret < 0 || (size_t)nret >= errmsg_len) {
                ERROR("Sprintf failed");
            }
            nret = INK_ERR_PARSE_JSON_TO_OBJECT_FAILED;
        }
        free(json_err);
    }

    get_err_msg = (nret != 0 && *err == NULL && strlen(errmsg) > 0);
    if (get_err_msg) {
        *err = util_common_calloc_s(sizeof(cni_exec_error));
        if (*err != NULL) {
            char *tmp_err = NULL;
            nret = asprintf(&tmp_err, "exec \'%s\' failed: %s", plugin_path, errmsg);
            if (nret < 0) {
                tmp_err = util_strdup_s(errmsg);
            }
            (*err)->msg = tmp_err;
            (*err)->code = 1;
        }
    }
}

static int do_parent_waitpid(int pipe_stdin[2], const int pipe_stdout[2], pid_t child_pid, char *errmsg,
                             size_t errmsg_len, const char *stdin_data, char **stdout_str, bool *parse_exec_err)
{
    int ret = 0;

    if (errmsg == NULL) {
        return -1;
    }
    /* write stdin_data into stdin of child process */
    if (write_stdin_data_to_child(pipe_stdin, stdin_data, errmsg, errmsg_len) != 0) {
        ERROR("Write stdin data failed: %s", errmsg);
        ret = -1;
    }

    /* wait child exit, and deal with exitcode */
    if (wait_pid_for_raw_exec_child(child_pid, pipe_stdout, stdout_str, errmsg, errmsg_len, parse_exec_err) != 0) {
        ERROR("Wait pid for child failed: %s", errmsg);
        ret = -1;
    }

    return ret;
}

static int raw_exec(const char *plugin_path, const char *stdin_data, char * const environs[], char **stdout_str,
                    cni_exec_error **err)
{
    int ret = 0;
    int pipe_stdout[2] = { -1, -1 };
    int pipe_stdin[2] = { -1, -1 };
    pid_t child_pid = 0;
    char errmsg[MAX_BUFFER_SIZE] = { 0 };
    bool parse_exec_err = false;

    if (prepare_raw_exec(plugin_path, pipe_stdin, pipe_stdout, errmsg, sizeof(errmsg)) != 0) {
        ret = -1;
        goto err_free_out;
    }

    child_pid = fork();
    if (child_pid < 0) {
        ret = snprintf(errmsg, sizeof(errmsg), "Fork failed: %s", strerror(errno));
        if (ret < 0 || (size_t)ret >= sizeof(errmsg)) {
            ERROR("Sprintf failed");
        }
        ret = -1;
        goto err_free_out;
    }

    if (child_pid == 0) {
        (void)close(pipe_stdin[1]);
        pipe_stdin[1] = -1;
        (void)close(pipe_stdout[0]);
        pipe_stdout[0] = -1;

        size_t envs_len = 0;
        envs_len = util_array_len((const char **)environs);
        child_fun(plugin_path, pipe_stdin[0], pipe_stdout[1], environs, envs_len);
        /* exit in child_fun */
    }

    (void)close(pipe_stdout[1]);
    pipe_stdout[1] = -1;
    (void)close(pipe_stdin[0]);
    pipe_stdin[0] = -1;

    ret = do_parent_waitpid(pipe_stdin, pipe_stdout, child_pid, errmsg, sizeof(errmsg), stdin_data, stdout_str,
                            &parse_exec_err);
err_free_out:
    /* parse error json message */
    make_err_message(plugin_path, stdout_str, ret, parse_exec_err, errmsg, sizeof(errmsg), err);

    if (ret != 0 && stdout_str != NULL) {
        free(*stdout_str);
        *stdout_str = NULL;
    }

    close_raw_exec_pipes(pipe_stdin, pipe_stdout);

    return ret;
}

