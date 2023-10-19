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
 * Author: jingrui
 * Create: 2020-1-20
 * Description: runtime ops
 ******************************************************************************/

#define _GNU_SOURCE

#include "isula_rt_ops.h"
#include <unistd.h>
#include <sys/wait.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/isulad_daemon_configs.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_runtime_spec.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>

#include "isula_libutils/log.h"
#include "runtime_api.h"
#include "constants.h"
#include "isula_libutils/shim_client_process_state.h"
#include "isula_libutils/shim_client_runtime_stats.h"
#include "isula_libutils/shim_client_cgroup_resources.h"
#include "isula_libutils/oci_runtime_state.h"
#include "isulad_config.h"
#include "utils_string.h"
#include "err_msg.h"
#include "daemon_arguments.h"
#include "utils_convert.h"
#include "utils_file.h"
#include "console.h"

#define SHIM_BINARY "isulad-shim"
#define RESIZE_FIFO_NAME "resize_fifo"
#define SHIM_LOG_SIZE ((BUFSIZ - 100) / 2)
#define RESIZE_DATA_SIZE 100
#define PID_WAIT_TIME 120
#define SHIM_EXIT_TIMEOUT 2

// file name formats of cgroup resources json
#define RESOURCE_FNAME_FORMATS "%s/resources.json"

// handle string from stderr output.
typedef int(*handle_output_callback_t)(const char *output);

static void copy_process(shim_client_process_state *p, defs_process *dp)
{
    p->args = dp->args;
    p->args_len = dp->args_len;
    p->console_size = (shim_client_process_state_console_size *)dp->console_size;
    p->cwd = dp->cwd;
    p->env = dp->env;
    p->env_len = dp->env_len;
    p->terminal = dp->terminal;
    p->user = (shim_client_process_state_user *)dp->user;
    p->capabilities = (shim_client_process_state_capabilities *)dp->capabilities;
    p->apparmor_profile = dp->apparmor_profile;
    p->oom_score_adj = dp->oom_score_adj;
    p->selinux_label = dp->selinux_label;
    p->no_new_privileges = dp->no_new_privileges;
    p->rlimits = (shim_client_process_state_rlimits_element **)dp->rlimits;
    p->rlimits_len = dp->rlimits_len;
}

static void copy_annotations(shim_client_process_state *p, json_map_string_string *anno)
{
    size_t i;
    if (anno == NULL) {
        return;
    }
    for (i = 0; i < anno->len; i++) {
        if (strcmp(anno->keys[i], CONTAINER_LOG_CONFIG_KEY_FILE) == 0) {
            p->log_path = anno->values[i];
        } else if (strcmp(anno->keys[i], CONTAINER_LOG_CONFIG_KEY_ROTATE) == 0) {
            int tmaxfile = 0;
            if (util_safe_int(anno->values[i], &tmaxfile) == 0 && tmaxfile > 0) {
                p->log_maxfile = tmaxfile;
            }
            continue;
        }
        if (strcmp(anno->keys[i], CONTAINER_LOG_CONFIG_KEY_SIZE) == 0) {
            int64_t tmaxsize = 0;
            if (util_parse_byte_size_string(anno->values[i], &tmaxsize) == 0 && tmaxsize > 0) {
                p->log_maxsize = tmaxsize;
            }
        }
    }
}

static int file_write_int(const char *fname, int val)
{
    int nret;
    char sint[UINT_LEN] = { 0 };

    nret = snprintf(sint, sizeof(sint), "%d", val);
    if (nret < 0 || (size_t)nret >= sizeof(sint)) {
        return -1;
    }

    if (util_write_file(fname, sint, strlen(sint), DEFAULT_SECURE_FILE_MODE) < 0) {
        return -1;
    }

    return 0;
}

/* val will updated only when success. */
static void file_read_int(const char *fname, int *val)
{
    char *sint = NULL;
    int ival = 0;

    if (!util_file_exists(fname)) {
        free(sint);
        return;
    }

    sint = util_read_text_file(fname);
    if (sint == NULL) {
        return;
    }

    if (!util_safe_int(sint, &ival)) {
        *val = ival;
    }

    free(sint);
}

static void get_err_message(char *buf, int buf_size, const char *workdir, const char *file)
{
    int nret;
    char fname[PATH_MAX] = { 0 };
    FILE *fp = NULL;
    char *pline = NULL;
    char *lines[3] = { 0 };
    size_t length = 0;

    nret = snprintf(fname, PATH_MAX, "%s/%s", workdir, file);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("failed make full path %s/%s", workdir, file);
        return;
    }

    fp = util_fopen(fname, "r");
    if (fp == NULL) {
        return;
    }

    while (getline(&pline, &length, fp) != -1) {
        if (pline == NULL) {
            break;
        }
        if (util_strings_contains_word(pline, "error")) {
            if (lines[0] == NULL) {
                lines[0] = pline;
                pline = NULL;
                continue;
            }
            if (lines[1] == NULL) {
                lines[1] = pline;
                pline = NULL;
                continue;
            }
            if (lines[2] == NULL) {
                lines[2] = pline;
                pline = NULL;
                break;
            }
        }
    }
    fclose(fp);

    if (lines[2] != NULL) {
        (void)snprintf(buf, buf_size, "%s%s%s", lines[0], lines[1], lines[2]);
    } else if (lines[1] != NULL) {
        (void)snprintf(buf, buf_size, "%s%s", lines[0], lines[1]);
    } else if (lines[0] != NULL) {
        (void)snprintf(buf, buf_size, "%s", lines[0]);
    }

    UTIL_FREE_AND_SET_NULL(pline);
    UTIL_FREE_AND_SET_NULL(lines[0]);
    UTIL_FREE_AND_SET_NULL(lines[1]);
    UTIL_FREE_AND_SET_NULL(lines[2]);
}

static void show_shim_runtime_errlog(const char *workdir)
{
    char buf[BUFSIZ] = { 0 };
    char buf1[SHIM_LOG_SIZE] = { 0 };
    char buf2[SHIM_LOG_SIZE] = { 0 };

    if (g_isulad_errmsg != NULL) {
        return;
    }

    get_err_message(buf1, sizeof(buf1), workdir, "shim-log.json");
    get_err_message(buf2, sizeof(buf2), workdir, "log.json");
    ERROR("shim-log: %s", buf1);
    ERROR("runtime-log: %s", buf2);
    (void)snprintf(buf, sizeof(buf), "shim-log error: %s\nruntime-log error: %s\n", buf1, buf2);
    isulad_set_error_message(buf);
}

bool rt_isula_detect(const char *runtime)
{
    if (runtime != NULL && (strcasecmp(runtime, "lcr") != 0)) {
        return true;
    }

    return false;
}

static int create_process_json_file(const char *workdir, const shim_client_process_state *p)
{
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error perr = NULL;
    char *data = NULL;
    char fname[PATH_MAX] = { 0 };
    int retcode = 0;

    int nret = snprintf(fname, sizeof(fname), "%s/process.json", workdir);
    if (nret < 0 || (size_t)nret >= sizeof(fname)) {
        ERROR("Failed make process.json full path");
        return -1;
    }

    data = shim_client_process_state_generate_json(p, &ctx, &perr);
    if (data == NULL) {
        retcode = -1;
        ERROR("failed generate json for process.json error=%s", perr);
        goto out;
    }

    if (util_write_file(fname, data, strlen(data), DEFAULT_SECURE_FILE_MODE) != 0) {
        retcode = -1;
        ERROR("failed write process.json");
        goto out;
    }

out:
    UTIL_FREE_AND_SET_NULL(perr);
    UTIL_FREE_AND_SET_NULL(data);

    return retcode;
}

static void get_runtime_cmd(const char *runtime, const char **cmd)
{
    struct service_arguments *args = NULL;
    defs_map_string_object_runtimes *runtimes = NULL;
    size_t i = 0;

    if (isulad_server_conf_rdlock()) {
        ERROR("failed to lock server config");
        goto out;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("failed to get server config");
        goto unlock_out;
    }

    if (args->json_confs != NULL) {
        runtimes = args->json_confs->runtimes;
    }
    if (runtimes == NULL) {
        goto unlock_out;
    }

    for (i = 0; i < runtimes->len; i++) {
        if (strcmp(runtime, runtimes->keys[i]) == 0) {
            *cmd = runtimes->values[i]->path;
            goto unlock_out;
        }
    }

unlock_out:
    if (isulad_server_conf_unlock()) {
        ERROR("failed to unlock server config");
    }
out:
    if (strcmp(runtime, "runc") == 0) {
        *cmd = "runc";
        return;
    }

    if (strcmp(runtime, "kata-runtime") == 0) {
        *cmd = "kata-runtime";
        return;
    }
    if (*cmd == NULL) {
        ERROR("missing match runtime config for %s", runtime);
    }
}

static int get_runtime_args(const char *runtime, const char ***args, size_t *args_len)
{
    int ret = 0;
    struct service_arguments *gargs = NULL;
    defs_map_string_object_runtimes *runtimes = NULL;
    size_t i = 0;

    if (runtime == NULL) {
        return 0;
    }

    if (isulad_server_conf_rdlock()) {
        ERROR("failed to lock server config");
        goto out;
    }

    gargs = conf_get_server_conf();
    if (gargs == NULL) {
        ERROR("failed to get server config");
        goto unlock_out;
    }

    if (gargs->json_confs != NULL) {
        runtimes = gargs->json_confs->runtimes;
    }
    if (runtimes == NULL) {
        goto unlock_out;
    }

    for (i = 0; i < runtimes->len; i++) {
        if (strcmp(runtime, runtimes->keys[i]) != 0) {
            continue;
        }
        if (runtimes->values[i]->runtime_args_len > MAX_OCI_RUNTIME_ARGS) {
            isulad_set_error_message("Too many runtimeArgs, runtimeArgs must be less than %d", MAX_OCI_RUNTIME_ARGS);
            ERROR("Too many runtimeArgs, runtimeArgs must be less than %d", MAX_OCI_RUNTIME_ARGS);
            ret = -1;
        } else {
            *args = (const char **)runtimes->values[i]->runtime_args;
            *args_len = runtimes->values[i]->runtime_args_len;
        }
        goto unlock_out;
    }
unlock_out:
    if (isulad_server_conf_unlock()) {
        ERROR("failed to unlock server config");
    }
out:
    return ret;
}

static bool shim_alive(const char *workdir)
{
    int pid = 0;
    char fpid[PATH_MAX] = { 0 };
    int ret = 0;
    int nret = 0;

    nret = snprintf(fpid, sizeof(fpid), "%s/shim-pid", workdir);
    if (nret < 0 || (size_t)nret >= sizeof(fpid)) {
        ERROR("failed make shim-pid full path");
        return false;
    }

    file_read_int(fpid, &pid);

    if (pid <= 0) {
        ERROR("failed read shim-pid file %s", fpid);
        return false;
    }

    ret = kill(pid, 0);
    if (ret != 0) {
        SYSINFO("kill 0 shim-pid with error.");
    }
    return ret == 0;
}

typedef struct {
    const char *workdir;
    const char *runtime;
    const char *cmd;
    const char **args;
    size_t args_len;
    const char *subcmd;
    const char **opts;
    size_t opts_len;
    const char *id;
    char **params;
    size_t params_num;
} runtime_exec_info;

static void runtime_exec_param_dump(const char **params)
{
    char *full = NULL;
    int i = 0;

    for (i = 0; i < PARAM_NUM; i++) {
        if (*(params + i) == NULL) {
            full = util_string_join(" ", params, i);
            INFO("runtime call params[%d] %s", i, full);
            UTIL_FREE_AND_SET_NULL(full);
            return;
        }
    }
}

static void runtime_exec_param_init(runtime_exec_info *rei)
{
    const char **params = (const char **)rei->params;
    size_t j = 0;

    *params++ = rei->cmd;

    for (j = 0; j < rei->args_len; j++) {
        *params++ = *(rei->args + j);
    }

    *params++ = rei->subcmd;
    for (j = 0; j < rei->opts_len; j++) {
        *params++ = *(rei->opts + j);
    }

    if (rei->id) {
        *params++ = rei->id;
    }
    if (strcmp(rei->subcmd, "kill") == 0) {
        *params++ = "9";
    }
}

static int runtime_exec_info_init(runtime_exec_info *rei, const char *workdir, const char *runtime, const char *subcmd,
                                   const char **opts, size_t opts_len, const char *id, char **params, size_t params_num)
{
    int ret = 0;
    rei->workdir = workdir;
    rei->runtime = runtime;
    ret = get_runtime_args(runtime, &rei->args, &rei->args_len);
    if (ret != 0) {
        return -1;
    }
    get_runtime_cmd(runtime, &rei->cmd);
    rei->subcmd = subcmd;
    rei->opts = opts;
    rei->opts_len = opts_len;
    rei->id = id;
    rei->params = params;
    rei->params_num = params_num;

    runtime_exec_param_init(rei);
    runtime_exec_param_dump((const char **)rei->params);
    return 0;
}

static void runtime_exec_func(void *arg)
{
    runtime_exec_info *rei = (runtime_exec_info *)arg;

    if (rei == NULL) {
        dprintf(STDERR_FILENO, "missing runtime exec info");
        _exit(EXIT_FAILURE);
    }

    if (chdir(rei->workdir) < 0) {
        dprintf(STDERR_FILENO, "chdir %s failed", rei->workdir);
        _exit(EXIT_FAILURE);
    }

    // clear NOTIFY_SOCKET from the env to adapt runc start
    if (strcmp(rei->subcmd, "start") == 0 && unsetenv("NOTIFY_SOCKET") != 0) {
        dprintf(STDERR_FILENO, "unset env NOTIFY_SOCKET failed %s", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    execvp(rei->cmd, rei->params);
    dprintf(STDERR_FILENO, "exec %s %s %s failed", rei->cmd, rei->subcmd, rei->id);
    _exit(EXIT_FAILURE);
}

static int status_string_to_int(const char *status)
{
    if (strcmp(status, "running") == 0) {
        return RUNTIME_CONTAINER_STATUS_RUNNING;
    }
    if (strcmp(status, "stopped") == 0) {
        return RUNTIME_CONTAINER_STATUS_STOPPED;
    }
    if (strcmp(status, "paused") == 0) {
        return RUNTIME_CONTAINER_STATUS_PAUSED;
    }
    return RUNTIME_CONTAINER_STATUS_UNKNOWN;
}

static int runtime_call_status(const char *workdir, const char *runtime, const char *id,
                               struct runtime_container_status_info *ecsi)
{
    char *stdout_msg = NULL;
    char *stderr_msg = NULL;
    oci_runtime_state *state = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error perr = NULL;
    runtime_exec_info rei = { 0 };
    int ret = 0;
    char *params[PARAM_NUM] = { 0 };

    ret = runtime_exec_info_init(&rei, workdir, runtime, "state", NULL, 0, id, params, PARAM_NUM);
    if (ret != 0) {
        ERROR("Failed to init runtime exec info");
        ret = -1;
        goto out;
    }

    if (!util_exec_cmd(runtime_exec_func, &rei, NULL, &stdout_msg, &stderr_msg)) {
        ERROR("call runtime status failed: %s", stderr_msg);
        ret = -1;
        goto out;
    }

    if (stdout_msg == NULL) {
        ERROR("call runtime status no stdout_msg");
        ret = -1;
        goto out;
    }

    state = oci_runtime_state_parse_data(stdout_msg, &ctx, &perr);
    if (state == NULL) {
        ERROR("call runtime status parse json failed");
        ret = -1;
        goto out;
    }

    ecsi->status = status_string_to_int(state->status);
    ecsi->pid = state->pid;
    if (state->pid != 0) {
        ecsi->has_pid = true;
    }

    INFO("container %s status %s pid %d", id, state->status, state->pid);

out:
    free_oci_runtime_state(state);
    UTIL_FREE_AND_SET_NULL(stdout_msg);
    UTIL_FREE_AND_SET_NULL(stderr_msg);
    UTIL_FREE_AND_SET_NULL(perr);
    return ret;
}

static int runtime_call_stats(const char *workdir, const char *runtime, const char *id,
                              struct runtime_container_resources_stats_info *info)
{
    char *stdout_msg = NULL;
    char *stderr_msg = NULL;
    shim_client_runtime_stats *stats = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error perr = NULL;
    runtime_exec_info rei = { 0 };
    int ret = 0;
    char *params[PARAM_NUM] = { 0 };
    const char *opts[1] = { "--stats" };

    ret = runtime_exec_info_init(&rei, workdir, runtime, "events", opts, 1, id, params, PARAM_NUM);
    if (ret != 0) {
        ERROR("Failed to init runtime exec info");
        ret = -1;
        goto out;
    }

    if (!util_exec_cmd(runtime_exec_func, &rei, NULL, &stdout_msg, &stderr_msg)) {
        ERROR("call runtime events --stats failed: %s", stderr_msg);
        ret = -1;
        goto out;
    }

    if (stdout_msg == NULL) {
        ERROR("call runtime events --stats no stdout_msg");
        ret = -1;
        goto out;
    }

    stats = shim_client_runtime_stats_parse_data(stdout_msg, &ctx, &perr);
    if (stats == NULL) {
        ERROR("call runtime events --stats parse json failed");
        ret = -1;
        goto out;
    }

    if (stats != NULL && stats->data != NULL && stats->data->pids != NULL) {
        info->pids_current = stats->data->pids->current;
    }
    if (stats != NULL && stats->data != NULL && stats->data->cpu != NULL && stats->data->cpu->usage) {
        info->cpu_use_nanos = stats->data->cpu->usage->total;
        info->cpu_system_use = stats->data->cpu->usage->kernel;
    }
    if (stats != NULL && stats->data != NULL && stats->data->memory != NULL && stats->data->memory->usage) {
        info->mem_used = stats->data->memory->usage->usage;
        info->mem_limit = stats->data->memory->usage->limit;
    }
    if (stats != NULL && stats->data != NULL && stats->data->memory != NULL && stats->data->memory->raw) {
        info->inactive_file_total = stats->data->memory->raw->total_inactive_file;
    }

out:
    free_shim_client_runtime_stats(stats);
    UTIL_FREE_AND_SET_NULL(stdout_msg);
    UTIL_FREE_AND_SET_NULL(stderr_msg);
    UTIL_FREE_AND_SET_NULL(perr);
    return ret;
}

static int runtime_call_simple(const char *workdir, const char *runtime, const char *subcmd, const char **opts,
                               size_t opts_len, const char *id, handle_output_callback_t cb)
{
    runtime_exec_info rei = { 0 };
    char *stdout_msg = NULL;
    char *stderr_msg = NULL;
    int ret = 0;
    char *params[PARAM_NUM] = { 0 };

    ret = runtime_exec_info_init(&rei, workdir, runtime, subcmd, opts, opts_len, id, params, PARAM_NUM);
    if (ret != 0) {
        ERROR("Failed to init runtime exec info");
        return -1;
    }

    if (!util_exec_cmd(runtime_exec_func, &rei, NULL, &stdout_msg, &stderr_msg)) {
        ERROR("call runtime %s failed stderr %s", subcmd, stderr_msg);
        ret = -1;
        // additional handler for the stderr,
        // this intend to change the ret val of this function
        // for example, if output string contains some specific content,
        // we consider the runtime call simple succeeded,
        // even if the process exit with failure.
        if (stderr_msg != NULL && cb != NULL) {
            ret = cb(stderr_msg);
        }
    }

    UTIL_FREE_AND_SET_NULL(stdout_msg);
    UTIL_FREE_AND_SET_NULL(stderr_msg);
    return ret;
}

// oci runtime return -1 if the container 'does not exist'
// if output contains 'does not exist', means nothing to kill or delete, return 0
// this will change the exit status of kill or delete command
static int non_existent_output_check(const char *output)
{
    char *pattern = "does not exist";

    if (output == NULL) {
        return -1;
    }

    // container not exist, kill or delete success, return 0
    if (util_strings_contains_word(output, pattern)) {
        return 0;
    }

    // kill or delete failed, return -1
    return -1;
}

// kill success or non_existent_output_check succeed return 0, DO_RETRY_CALL will break;
// if kill failed, recheck on shim alive, if not alive, kill succeed,  still return 0;
// else, return -1, DO_RETRY_CALL will call this again;
static int runtime_call_kill_and_check(const char *workdir, const char *runtime, const char *id)
{
    int ret = -1;

    // kill succeed, return 0; non_existent_output_check succeed, return 0;
    ret = runtime_call_simple(workdir, runtime, "kill", NULL, 0, id, non_existent_output_check);
    if (ret == 0) {
        return 0;
    }

    if (!shim_alive(workdir)) {
        ret = 0;
    }

    return ret;
}

static int runtime_call_delete_force(const char *workdir, const char *runtime, const char *id)
{
    const char *opts[1] = { "--force" };
    // delete succeed, return 0;
    // When the runc version is less than or equal to v1.0.0-rc3,
    // if the container does not exist when force deleting it,
    // runc will report an error and isulad does not need to retry the deletion again.
    // related PR ID:d1a743674a98e23d348b29f52c43436356f56b79
    // non_existent_output_check succeed, return 0;
    return runtime_call_simple(workdir, runtime, "delete", opts, 1, id, non_existent_output_check);
}

#define ExitSignalOffset 128
static int status_to_exit_code(int status)
{
    int exit_code = 0;

    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else {
        exit_code = -1;
    }
    if (WIFSIGNALED(status)) {
        int signal;
        signal = WTERMSIG(status);
        exit_code = ExitSignalOffset + signal;
    }
    return exit_code;
}

/*
    exit_code records the exit code of the container, obtained by reading the stdout of isulad-shim;
    shim_exit_code records the exit code of isulad-shim, obtained through waitpid;
*/
static int shim_create(bool fg, const char *id, const char *workdir, const char *bundle, const char *runtime_cmd,
                       int *exit_code, const char *timeout, int *shim_exit_code)
{
    pid_t pid = 0;
    int shim_stderr_pipe[2] = { -1, -1 };
    int shim_stdout_pipe[2] = { -1, -1 };
    int num = 0;
    int ret = 0;
    char exec_buff[BUFSIZ + 1] = { 0 };
    char fpid[PATH_MAX] = { 0 };
    const char *params[PARAM_NUM] = { 0 };
    int i = 0;
    int status = 0;
    int nret = 0;

    params[i++] = SHIM_BINARY;
    params[i++] = id;
    params[i++] = bundle;
    params[i++] = runtime_cmd;
    params[i++] = "info";
    // execSync timeout
    if (timeout != NULL) {
        params[i++] = timeout;
    }
    runtime_exec_param_dump(params);

    nret = snprintf(fpid, sizeof(fpid), "%s/shim-pid", workdir);
    if (nret < 0 || (size_t)nret >= sizeof(fpid)) {
        ERROR("failed make shim-pid full path");
        return -1;
    }

    if (pipe2(shim_stderr_pipe, O_CLOEXEC) != 0) {
        ERROR("Failed to create pipe for shim stderr");
        return -1;
    }

    if (pipe2(shim_stdout_pipe, O_CLOEXEC) != 0) {
        ERROR("Failed to create pipe for shim stdout");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        SYSERROR("Failed fork for shim parent");
        close(shim_stderr_pipe[0]);
        close(shim_stderr_pipe[1]);
        close(shim_stdout_pipe[0]);
        close(shim_stdout_pipe[1]);
        return -1;
    }

    if (pid == (pid_t)0) {
        if (chdir(workdir) < 0) {
            (void)dprintf(shim_stderr_pipe[1], "%s: failed chdir to %s", id, workdir);
            exit(EXIT_FAILURE);
        }

        if (fg) {
            // child process, dup2 shim_stdout_pipe[1] to STDOUT
            if (dup2(shim_stdout_pipe[1], STDOUT_FILENO) < 0) {
                (void)dprintf(shim_stderr_pipe[1], "Dup stdout fd error: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }
            // child process, dup2 shim_stderr_pipe[1] to STDERR
            if (dup2(shim_stderr_pipe[1], STDERR_FILENO) < 0) {
                (void)dprintf(shim_stderr_pipe[1], "Dup stderr fd error: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }
            goto realexec;
        }

        // clear NOTIFY_SOCKET from the env to adapt runc create
        if (unsetenv("NOTIFY_SOCKET") != 0) {
            (void)dprintf(shim_stderr_pipe[1], "%s: unset env NOTIFY_SOCKET failed %s", id, strerror(errno));
            exit(EXIT_FAILURE);
        }

        pid = fork();
        if (pid < 0) {
            (void)dprintf(shim_stderr_pipe[1], "%s: fork shim-process failed %s", id, strerror(errno));
            _exit(EXIT_FAILURE);
        }
        if (pid != 0) {
            if (file_write_int(fpid, pid) != 0) {
                (void)dprintf(shim_stderr_pipe[1], "%s: write %s with %d failed", id, fpid, pid);
            }
            _exit(EXIT_SUCCESS);
        }

realexec:
        /* real shim process. */
        close(shim_stderr_pipe[0]);
        close(shim_stdout_pipe[0]);

        if (setsid() < 0) {
            (void)dprintf(shim_stderr_pipe[1], "%s: failed setsid for process %d", id, getpid());
            exit(EXIT_FAILURE);
        }

        if (util_check_inherited(true, shim_stderr_pipe[1]) != 0) {
            (void)dprintf(shim_stderr_pipe[1], "close inherited fds failed");
            exit(EXIT_FAILURE);
        }

        execvp(SHIM_BINARY, (char * const *)params);
        (void)dprintf(shim_stderr_pipe[1], "exec failed: %s", strerror(errno));
    }

    close(shim_stderr_pipe[1]);
    close(shim_stdout_pipe[1]);
    num = util_read_nointr(shim_stderr_pipe[0], exec_buff, sizeof(exec_buff) - 1);
    if (num > 0) {
        ERROR("Exec failed: %s", exec_buff);
        ret = -1;
        goto out;
    }

    status = util_wait_for_pid_status(pid);
    if (status < 0) {
        SYSERROR("Failed wait shim-parent %d exit", pid);
        ret = -1;
        goto out;
    }

    *shim_exit_code = status_to_exit_code(status);
    if (*shim_exit_code != 0) {
        ERROR("Isulad-shim exit error");
        ret = -1;
        goto out;
    }

    // exit_code is NULL when command is create.
    if (exit_code == NULL) {
        goto out;
    }

    // when exec in background, exit code is shim exit code
    if (!fg) {
        *exit_code = *shim_exit_code;
        goto out;
    }
    ret = util_read_nointr(shim_stdout_pipe[0], exit_code, sizeof(int));
    if (ret <= 0) {
        *exit_code = 137;
    }
    ret = 0;

out:
    close(shim_stderr_pipe[0]);
    close(shim_stdout_pipe[0]);
    if (ret != 0) {
        show_shim_runtime_errlog(workdir);
        if (timeout != NULL) {
            kill(pid, SIGKILL); /* can kill other process? */
        }
    }

    return ret;
}

static int get_container_process_pid(const char *workdir)
{
    char fname[PATH_MAX] = { 0 };
    int pid = 0;
    struct timespec beg = { 0 };
    struct timespec end = { 0 };

    int nret = snprintf(fname, sizeof(fname), "%s/pid", workdir);
    if (nret < 0 || (size_t)nret >= sizeof(fname)) {
        ERROR("failed make pid full path");
        return -1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &beg) != 0) {
        ERROR("failed get time");
        return -1;
    }

    while (1) {
        if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
            ERROR("failed get time");
            return -1;
        }
        if (end.tv_sec - beg.tv_sec > PID_WAIT_TIME) {
            ERROR("wait container process pid timeout %s", workdir);
            return -1;
        }
        file_read_int(fname, &pid);
        if (!pid) {
            if (shim_alive(workdir)) {
                util_usleep_nointerupt(100000);
                continue;
            }
            ERROR("failed read pid from dead shim %s", workdir);
            return -1;
        }
        return pid; /* success */
    }
    return -1;
}

static void shim_kill_force(const char *workdir)
{
    int pid = 0;
    char fpid[PATH_MAX] = { 0 };

    int nret = snprintf(fpid, sizeof(fpid), "%s/shim-pid", workdir);
    if (nret < 0 || (size_t)nret >= sizeof(fpid)) {
        INFO("shim-pid not exist");
        return;
    }

    file_read_int(fpid, &pid);

    if (pid <= 0) {
        goto out;
    }

    kill(pid, SIGKILL);

out:
    INFO("kill shim force %s", workdir);
}

int rt_isula_create(const char *id, const char *runtime, const rt_create_params_t *params)
{
    oci_runtime_spec *config = NULL;
    const char *cmd = NULL;
    const char **runtime_args = NULL;
    size_t runtime_args_len = 0;
    int ret = 0;
    char workdir[PATH_MAX] = { 0 };
    shim_client_process_state p = { 0 };
    int shim_exit_code = 0;
    int nret = 0;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("nullptr arguments not allowed");
        return -1;
    }
    config = params->oci_config_data;
    ret = get_runtime_args(runtime, &runtime_args, &runtime_args_len);
    if (ret != 0) {
        ERROR("Failed to get runtime args");
        return -1;
    }

    nret = snprintf(workdir, sizeof(workdir), "%s/%s", params->state, id);
    if (nret < 0 || (size_t)nret >= sizeof(workdir)) {
        INFO("make full workdir failed");
        ret = -1;
        goto out;
    }

    p.exit_fifo = (char *)params->exit_fifo;
    p.open_tty = params->tty;
    p.open_stdin = params->open_stdin;
    p.isulad_stdin = (char *)params->stdin;
    p.isulad_stdout = (char *)params->stdout;
    p.isulad_stderr = (char *)params->stderr;
    p.runtime_args = (char **)runtime_args;
    p.runtime_args_len = runtime_args_len;
    copy_process(&p, config->process);
    copy_annotations(&p, config->annotations);

    ret = create_process_json_file(workdir, &p);
    if (ret != 0) {
        ERROR("%s: failed create json file", id);
        goto out;
    }

    get_runtime_cmd(runtime, &cmd);
    ret = shim_create(false, id, workdir, params->bundle, cmd, NULL, NULL, &shim_exit_code);
    if (ret != 0) {
        runtime_call_delete_force(workdir, runtime, id);
        ERROR("%s: failed create shim process", id);
        goto out;
    }

out:
    return ret;
}

int rt_isula_start(const char *id, const char *runtime, const rt_start_params_t *params, pid_ppid_info_t *pid_info)
{
    char workdir[PATH_MAX] = { 0 };
    char shim_pid_file_name[PATH_MAX] = { 0 };
    pid_t pid = 0;
    pid_t shim_pid = -1;
    int ret = -1;
    int splice_ret = 0;
    proc_t *proc = NULL;
    proc_t *p_proc = NULL;
    int nret = 0;

    if (id == NULL || runtime == NULL || params == NULL || pid_info == NULL) {
        ERROR("nullptr arguments not allowed");
        return -1;
    }

    nret = snprintf(workdir, sizeof(workdir), "%s/%s", params->state, id);
    if (nret < 0 || (size_t)nret >= sizeof(workdir)) {
        ERROR("%s: missing shim workdir", id);
        return -1;
    }

    splice_ret = snprintf(shim_pid_file_name, sizeof(shim_pid_file_name), "%s/shim-pid", workdir);
    if (splice_ret < 0 || (size_t)splice_ret >= sizeof(shim_pid_file_name)) {
        ERROR("%s: wrong shim workdir", id);
        return -1;
    }

    pid = get_container_process_pid(workdir);
    if (pid < 0) {
        ERROR("%s: failed wait init pid", id);
        goto out;
    }

    file_read_int(shim_pid_file_name, &shim_pid);
    if (shim_pid < 0) {
        ERROR("%s: failed to read isulad shim pid", id);
        goto out;
    }

    proc = util_get_process_proc_info(pid);
    if (proc == NULL) {
        ERROR("%s: failed to read pidinfo", id);
        goto out;
    }

    p_proc = util_get_process_proc_info(shim_pid);
    if (p_proc == NULL) {
        ERROR("%s: failed to read isulad shim pidinfo", id);
        goto out;
    }

    pid_info->pid = proc->pid;
    pid_info->start_time = proc->start_time;
    pid_info->ppid = shim_pid;
    pid_info->pstart_time = p_proc->start_time;

    if (runtime_call_simple(workdir, runtime, "start", NULL, 0, id, NULL) != 0) {
        ERROR("call runtime start id failed");
        goto out;
    }

    ret = 0;
out:
    if (ret != 0) {
        show_shim_runtime_errlog(workdir);
        shim_kill_force(workdir);
    }

    free(proc);
    free(p_proc);

    return ret;
}

int rt_isula_restart(const char *name, const char *runtime, const rt_restart_params_t *params)
{
    ERROR(">>> restart not implemented");
    return RUNTIME_NOT_IMPLEMENT_RESET;
}

int rt_isula_clean_resource(const char *id, const char *runtime, const rt_clean_params_t *params)
{
    char workdir[PATH_MAX] = { 0 };
    int nret = 0;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("nullptr arguments not allowed");
        return -1;
    }

    if (params->statepath == NULL) {
        ERROR("missing state path");
        return -1;
    }

    nret = snprintf(workdir, sizeof(workdir), "%s/%s", params->statepath, id);
    if (nret < 0 || (size_t)nret >= sizeof(workdir)) {
        ERROR("failed get shim workdir");
        return -1;
    }

    if (shim_alive(workdir)) {
        shim_kill_force(workdir);
    }

    // retry 10 count call runtime kill, every call sleep 0.5s
    DO_RETRY_CALL(10, 500000, nret, runtime_call_kill_and_check, workdir, runtime, id);
    if (nret != 0) {
        WARN("call runtime force kill failed");
    }

    // retry 10 count call runtime delete, every call sleep 0.1s
    DO_RETRY_CALL(10, 100000, nret, runtime_call_delete_force, workdir, runtime, id);
    if (nret != 0) {
        WARN("call runtime force delete failed");
    }

    if (util_recursive_rmdir(workdir, 0) != 0) {
        ERROR("failed rmdir -r shim workdir");
        return -1;
    }

    INFO("rmdir -r %s done", workdir);
    return 0;
}

int rt_isula_rm(const char *id, const char *runtime, const rt_rm_params_t *params)
{
    char libdir[PATH_MAX] = { 0 };
    int nret = 0;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("nullptr arguments not allowed");
        return -1;
    }
    if (params->rootpath == NULL) {
        ERROR("missing root path");
        return -1;
    }

    nret = snprintf(libdir, sizeof(libdir), "%s/%s", params->rootpath, id);
    if (nret < 0 || (size_t)nret >= sizeof(libdir)) {
        ERROR("failed get shim workdir");
        return -1;
    }

    if (util_recursive_rmdir(libdir, 0) != 0) {
        ERROR("failed rmdir -r shim workdir");
        return -1;
    }

    INFO("rmdir -r %s done", libdir);
    return 0;
}

static bool fg_exec(const rt_exec_params_t *params)
{
    if (params->console_fifos[0] != NULL || params->console_fifos[1] != NULL || params->console_fifos[2] != NULL) {
        return true;
    }
    return false;
}

static char *try_generate_exec_id()
{
    char *id = NULL;

    id = util_common_calloc_s(sizeof(char) * (CONTAINER_EXEC_ID_MAX_LEN + 1));
    if (id == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (util_generate_random_str(id, (size_t)CONTAINER_EXEC_ID_MAX_LEN) != 0) {
        ERROR("Generate id failed");
        goto err_out;
    }

    return id;

err_out:
    free(id);
    return NULL;
}

static int preparation_exec(const char *id, const char *runtime, const char *workdir, const char *exec_id,
                            const rt_exec_params_t *params)
{
    int ret = 0;
    size_t runtime_args_len = 0;
    char resize_fifo_dir[PATH_MAX] = { 0 };
    const char **runtime_args = NULL;
    shim_client_process_state p = { 0 };
    defs_process *process = NULL;

    ret = util_mkdir_p(workdir, DEFAULT_SECURE_DIRECTORY_MODE);
    if (ret < 0) {
        ERROR("failed mkdir exec workdir %s", workdir);
        return -1;
    }

    ret = snprintf(resize_fifo_dir, sizeof(resize_fifo_dir), "%s/%s", workdir, RESIZE_FIFO_NAME);
    if (ret < 0 || (size_t)ret >= sizeof(resize_fifo_dir)) {
        ERROR("failed join resize fifo full path");
        return -1;
    }

    ret = console_fifo_create(resize_fifo_dir);
    if (ret < 0) {
        ERROR("failed create resize fifo file");
        return -1;
    }

    process = params->spec;
    ret = get_runtime_args(runtime, &runtime_args, &runtime_args_len);
    if (ret < 0) {
        ERROR("Failed to get runtime args");
        return -1;
    }

    p.exec = true;
    p.isulad_stdin = (char *)params->console_fifos[0];
    p.isulad_stdout = (char *)params->console_fifos[1];
    p.isulad_stderr = (char *)params->console_fifos[2];
    p.resize_fifo = resize_fifo_dir;
    p.runtime_args = (char **)runtime_args;
    p.runtime_args_len = runtime_args_len;
    copy_process(&p, process);

    ret = create_process_json_file(workdir, &p);
    if (ret != 0) {
        ERROR("%s: failed create exec json file", id);
        return -1;
    }

    return 0;
}

int rt_isula_exec(const char *id, const char *runtime, const rt_exec_params_t *params, int *exit_code)
{
    const char *cmd = NULL;
    char *exec_id = NULL;
    int ret = 0;
    int pid = 0;
    char bundle[PATH_MAX] = { 0 };
    char workdir[PATH_MAX] = { 0 };
    char *timeout = NULL;
    int shim_exit_code = 0;

    if (id == NULL || runtime == NULL || params == NULL || exit_code == NULL) {
        ERROR("nullptr arguments not allowed");
        return -1;
    }

    ret = snprintf(bundle, sizeof(bundle), "%s/%s", params->rootpath, id);
    if (ret < 0 || (size_t)ret >= sizeof(bundle)) {
        ERROR("failed join bundle path for exec");
        return -1;
    }

    if (params->suffix != NULL) {
        exec_id = util_strdup_s(params->suffix);
    } else {
        // in the health check scenario, suffix is empty
        exec_id = try_generate_exec_id();
    }
    if (exec_id == NULL) {
        ERROR("Out of memory or generate exec id failed");
        return -1;
    }

    ret = snprintf(workdir, sizeof(workdir), "%s/%s/exec/%s", params->state, id, exec_id);
    if (ret < 0 || (size_t)ret >= sizeof(workdir)) {
        ERROR("failed join exec full path");
        goto out;
    }

    ret = preparation_exec(id, runtime, workdir, exec_id, params);
    if (ret != 0) {
        ERROR("%s: failed to preparation for exec %s", id, exec_id);
        goto del_out;
    }

    get_runtime_cmd(runtime, &cmd);

    // execSync timeout
    if (params->timeout > 0) {
        timeout = util_int_to_string(params->timeout);
        if (timeout == NULL) {
            ERROR("Failed to convert execSync timeout %ld to string", params->timeout);
            ret = -1;
            goto del_out;
        }
    }

    ret = shim_create(fg_exec(params), id, workdir, bundle, cmd, exit_code, timeout, &shim_exit_code);
    if (ret != 0) {
        ERROR("%s: failed create shim process for exec %s", id, exec_id);
        goto errlog_out;
    }

    if (shim_exit_code == SHIM_EXIT_TIMEOUT) {
        ret = -1;
        isulad_set_error_message("Exec container error;exec timeout");
        ERROR("isulad-shim %d exit for execing timeout", pid);
        goto errlog_out;
    }

    pid = get_container_process_pid(workdir);
    if (pid < 0) {
        ERROR("%s: failed get exec process id", workdir);
        ret = -1;
        goto errlog_out;
    }

errlog_out:
    if (ret != 0) {
        show_shim_runtime_errlog(workdir);
    }

    if (timeout != NULL) {
        free(timeout);
    }

del_out:
    if (util_recursive_rmdir(workdir, 0)) {
        ERROR("rmdir %s failed", workdir);
    }

out:
    UTIL_FREE_AND_SET_NULL(exec_id);
    return ret;
}

int rt_isula_status(const char *id, const char *runtime, const rt_status_params_t *params,
                    struct runtime_container_status_info *status)
{
    char workdir[PATH_MAX] = { 0 };
    int ret = 0;

    if (id == NULL || runtime == NULL || params == NULL || status == NULL) {
        ERROR("nullptr arguments not allowed");
        return -1;
    }

    ret = snprintf(workdir, sizeof(workdir), "%s/%s", params->state, id);
    if (ret < 0 || (size_t)ret >= sizeof(workdir)) {
        ERROR("Failed join full workdir %s/%s", params->state, id);
        goto out;
    }

    if (!shim_alive(workdir)) {
        ERROR("shim dead %s", workdir);
        ret = -1;
        goto out;
    }

    ret = runtime_call_status(workdir, runtime, id, status);

out:
    return ret;
}

int rt_isula_attach(const char *id, const char *runtime, const rt_attach_params_t *params)
{
    ERROR("isula attach not support on isulad-shim");
    isulad_set_error_message("isula attach not support on isulad-shim");
    return -1;
}

static int to_engine_resources(const host_config *hostconfig, shim_client_cgroup_resources *cr)
{
    if (hostconfig == NULL || cr == NULL) {
        return -1;
    }

    cr->block_io = util_common_calloc_s(sizeof(shim_client_cgroup_resources_block_io));
    if (cr->block_io == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    cr->cpu = util_common_calloc_s(sizeof(shim_client_cgroup_resources_cpu));
    if (cr->cpu == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    cr->memory = util_common_calloc_s(sizeof(shim_client_cgroup_resources_memory));
    if (cr->memory == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    cr->block_io->weight = hostconfig->blkio_weight;
    cr->cpu->shares = (uint64_t)hostconfig->cpu_shares;
    cr->cpu->period = (uint64_t)hostconfig->cpu_period;
    cr->cpu->quota = hostconfig->cpu_quota;
    cr->cpu->cpus = util_strdup_s(hostconfig->cpuset_cpus);
    cr->cpu->mems = util_strdup_s(hostconfig->cpuset_mems);
    cr->memory->limit = (uint64_t)hostconfig->memory;
    cr->memory->swap = (uint64_t)hostconfig->memory_swap;
    cr->memory->reservation = (uint64_t)hostconfig->memory_reservation;
    cr->memory->kernel = (uint64_t)hostconfig->kernel_memory;
    cr->cpu->realtime_period = hostconfig->cpu_realtime_period;
    cr->cpu->realtime_runtime = hostconfig->cpu_realtime_runtime;

    // when --cpus=n is set, nano_cpus = n * 1e9.
    if (hostconfig->nano_cpus > 0) {
        // in the case, period will be set to the default value of 100000(0.1s).
        uint64_t period = (uint64_t)(100 * Time_Milli / Time_Micro);
        // set quota = period * n, in order to let container process fully occupy n cpus.
        if ((hostconfig->nano_cpus / 1e9)  > (INT64_MAX / (int64_t)period)) {
            ERROR("Overflow of quota");
            return -1;
        }
        int64_t quota = hostconfig->nano_cpus / 1e9 * (int64_t)period;
        cr->cpu->period = period;
        cr->cpu->quota = quota;
    }

    return 0;
}

static int create_resources_json_file(const char *workdir, const shim_client_cgroup_resources *cr, char *fname,
                                      size_t fname_size)
{
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error perr = NULL;
    char *data = NULL;
    int retcode = 0;
    int nret = 0;

    nret = snprintf(fname, fname_size, RESOURCE_FNAME_FORMATS, workdir);
    if (nret < 0 || (size_t)nret >= fname_size) {
        ERROR("Failed make resources.json full path");
        return -1;
    }

    data = shim_client_cgroup_resources_generate_json(cr, &ctx, &perr);
    if (data == NULL) {
        retcode = -1;
        ERROR("Failed generate json for resources.json error=%s", perr);
        goto out;
    }

    if (util_write_file(fname, data, strlen(data), DEFAULT_SECURE_FILE_MODE) != 0) {
        retcode = -1;
        ERROR("Failed write resources.json");
        goto out;
    }

out:
    UTIL_FREE_AND_SET_NULL(perr);
    UTIL_FREE_AND_SET_NULL(data);

    return retcode;
}

// show std error msg, always return -1.
static int show_stderr(const char *err)
{
    isulad_set_error_message(err);
    return -1;
}

int rt_isula_update(const char *id, const char *runtime, const rt_update_params_t *params)
{
    int ret = 0;
    char workdir[PATH_MAX] = { 0 };
    char resources_fname[PATH_MAX] = { 0 };
    const char *opts[2] = { 0 };
    shim_client_cgroup_resources *cr = NULL;

    if (id == NULL || runtime == NULL || params == NULL || params->state == NULL || strlen(params->state) == 0) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    ret = snprintf(workdir, sizeof(workdir), "%s/%s/update", params->state, id);
    if (ret < 0 || (size_t)ret >= sizeof(workdir)) {
        ERROR("Failed join update full path");
        return -1;
    }

    ret = util_mkdir_p(workdir, DEFAULT_SECURE_DIRECTORY_MODE);
    if (ret < 0) {
        ERROR("Failed mkdir update workdir %s", workdir);
        return ret;
    }

    cr = util_common_calloc_s(sizeof(shim_client_cgroup_resources));
    if (cr == NULL) {
        ERROR("Out of memory");
        goto del_out;
    }

    ret = to_engine_resources(params->hostconfig, cr);
    if (ret < 0) {
        ERROR("Failed to get resources for update");
        goto del_out;
    }

    ret = create_resources_json_file(workdir, cr, resources_fname, sizeof(resources_fname));
    if (ret != 0) {
        ERROR("%s: failed create update json file", id);
        goto del_out;
    }

    opts[0] = "--resources";
    opts[1] = resources_fname;

    if (runtime_call_simple(workdir, runtime, "update", opts, 2, id, show_stderr) != 0) {
        ERROR("Call runtime update id failed");
        ret = -1;
    }

del_out:
    if (util_recursive_rmdir(workdir, 0)) {
        ERROR("Rmdir %s failed", workdir);
    }
    free_shim_client_cgroup_resources(cr);
    return ret;
}

int rt_isula_pause(const char *id, const char *runtime, const rt_pause_params_t *params)
{
    char workdir[PATH_MAX] = { 0 };
    int ret = 0;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("nullptr arguments not allowed");
        return -1;
    }

    ret = snprintf(workdir, sizeof(workdir), "%s/%s", params->state, id);
    if (ret < 0 || (size_t)ret >= sizeof(workdir)) {
        ERROR("failed join workdir %s/%s", params->state, id);
        return -1;
    }

    return runtime_call_simple(workdir, runtime, "pause", NULL, 0, id, NULL);
}

int rt_isula_resume(const char *id, const char *runtime, const rt_resume_params_t *params)
{
    char workdir[PATH_MAX] = { 0 };
    int ret = 0;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("nullptr arguments not allowed");
        return -1;
    }

    ret = snprintf(workdir, sizeof(workdir), "%s/%s", params->state, id);
    if (ret < 0 || (size_t)ret >= sizeof(workdir)) {
        ERROR("failed join workdir %s/%s", params->state, id);
        return -1;
    }

    return runtime_call_simple(workdir, runtime, "resume", NULL, 0, id, NULL);
}

int rt_isula_listpids(const char *name, const char *runtime, const rt_listpids_params_t *params, rt_listpids_out_t *out)
{
    ERROR("isula top/listpids not support on isulad-shim");
    isulad_set_error_message("isula top/listpids not support on isulad-shim");
    return -1;
}

int rt_isula_resources_stats(const char *id, const char *runtime, const rt_stats_params_t *params,
                             struct runtime_container_resources_stats_info *rs_stats)
{
    char workdir[PATH_MAX] = { 0 };
    int ret = 0;

    if (id == NULL || runtime == NULL || params == NULL || rs_stats == NULL) {
        ERROR("nullptr arguments not allowed");
        return -1;
    }

    ret = snprintf(workdir, sizeof(workdir), "%s/%s", params->state, id);
    if (ret < 0 || (size_t)ret >= sizeof(workdir)) {
        ERROR("Failed join full workdir %s/%s", params->state, id);
        goto out;
    }

    if (!shim_alive(workdir)) {
        ERROR("shim dead %s", workdir);
        ret = -1;
        goto out;
    }

    ret = runtime_call_stats(workdir, runtime, id, rs_stats);

out:
    return ret;
}

int rt_isula_resize(const char *id, const char *runtime, const rt_resize_params_t *params)
{
    ERROR("rt_isula_resize not impl");
    return 0;
}

int rt_isula_exec_resize(const char *id, const char *runtime, const rt_exec_resize_params_t *params)
{
    char workdir[PATH_MAX] = { 0 };
    char resize_fifo_path[PATH_MAX] = { 0 };
    char data[RESIZE_DATA_SIZE] = { 0 };
    ssize_t count;
    int fd = -1;
    pid_t pid = -1;
    int ret = 0;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    /* crictl not suport exec auto resize */
    if (params->suffix == NULL) {
        WARN("Exec resize not support when isula not being used");
        return 0;
    }

    ret = snprintf(workdir, sizeof(workdir), "%s/%s/exec/%s", params->state, id, params->suffix);
    if (ret < 0 || (size_t)ret >= sizeof(workdir)) {
        ERROR("Failed to join exec resize workdir path");
        return -1;
    }

    ret = snprintf(resize_fifo_path, sizeof(resize_fifo_path), "%s/%s", workdir, RESIZE_FIFO_NAME);
    if (ret < 0 || (size_t)ret >= sizeof(resize_fifo_path)) {
        ERROR("Failed to join resize fifo path");
        return -1;
    }

    ret = snprintf(data, sizeof(data), "%u %u", params->width, params->height);
    if (ret < 0 || (size_t)ret >= sizeof(data)) {
        ERROR("Failed to write resize data");
        return -1;
    }

    fd = util_open(resize_fifo_path, O_WRONLY | O_NONBLOCK, 0);
    if (fd == -1) {
        ERROR("Open exec resize fifo error");
        ret = -1;
        goto out;
    }

    count = util_write_nointr(fd, data, strlen(data));
    if (count < 0 || (size_t)count != strlen(data)) {
        ERROR("Write exec resize data error");
        ret = -1;
        goto out;
    }

    pid = get_container_process_pid(workdir);
    if (pid < 0) {
        ERROR("%s: failed wait init pid", id);
        ret = -1;
        goto out;
    }

    if (kill(pid, SIGWINCH) < 0) {
        SYSERROR("Can't kill process (pid=%d) with signal %u", pid, SIGWINCH);
        ret = -1;
        goto out;
    }

    ret = 0;

out:
    close(fd);
    return ret;
}

int rt_isula_kill(const char *id, const char *runtime, const rt_kill_params_t *params)
{
    if (id == NULL || runtime == NULL || params == NULL || params->pid < 0) {
        ERROR("Invalid arguments not allowed");
        return -1;
    }

    if (util_process_alive(params->pid, params->start_time) == false) {
        if (params->signal == params->stop_signal || params->signal == SIGKILL) {
            WARN("Process %d is not alive", params->pid);
            return 0;
        } else {
            ERROR("Process (pid=%d) is not alive, can not kill with signal %u", params->pid, params->signal);
            return -1;
        }
    } else {
        int ret = kill(params->pid, (int)params->signal);
        if (ret < 0) {
            SYSERROR("Can not kill process (pid=%d) with signal %u", params->pid, params->signal);
            return -1;
        }
    }

    return 0;
}