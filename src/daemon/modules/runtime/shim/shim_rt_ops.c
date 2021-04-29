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
 * Author: gaohuatao
 * Create: 2020-1-20
 * Description: runtime ops
 ******************************************************************************/

#define _GNU_SOURCE


#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>

#include "shim_rt_ops.h"
#include "isula_libutils/log.h"
#include "error.h"
#include "err_msg.h"
#include "engine.h"
#include "constants.h"
#include "isula_libutils/shim_client_process_state.h"
#include "utils_string.h"
#include "shim_v2.h"

#define SHIM_LOG_SIZE ((BUFSIZ-100)/2)
#define PID_WAIT_TIME 120

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

#define ExitSignalOffsetX 128

static int status_to_exit_code(int status)
{
    int exit_code = 0;

    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else {
        exit_code = -1;
    }

    if (WIFSIGNALED(status)) {
        int signal = WTERMSIG(status);
        exit_code = ExitSignalOffsetX + signal;
    }

    return exit_code;
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

static int shim_bin_v2_create(const char *runtime, const char *id, const char *workdir, int *exit_code, char *addr,
                              const char *exit_fifo_dir)
{
    pid_t pid = 0;
    int ret = 0;
    int i = 0;
    int status = 0;
    char binary[PATH_MAX + 1] = {0};
    const char *params[PARAM_NUM] = {0};
    char fpid[PATH_MAX] = {0};
    int exec_fd[2] = {-1, -1};
    int err_fd[2] = {-1, -1};
    int out_fd[2] = {-1, -1};
    char exec_buff[BUFSIZ + 1] = {0};
    char stdout_buff[BUFSIZ + 1] = {0};
    char stderr_buff[BUFSIZ + 1] = {0};


    if (convert_v2_runtime(runtime, binary) != 0) {
        ERROR("%s: get binary name %s failed", id, runtime);
        return -1;
    }

    params[i++] = binary;
    params[i++] = "--id";
    params[i++] = id;
    params[i++] = "--namespace";
    params[i++] = "isula";
    params[i++] = "start";

    INFO("exec shim-v2 binary in %s %s %s %s %s %s", params[0], params[1], params[2], params[3], params[4], params[5]);

    if (snprintf(fpid, sizeof(fpid), "%s/shim-pid", workdir) < 0) {
        ERROR("Failed to make shim-pid full path");
        ret = -1;
        goto out;
    }

    if (pipe2(exec_fd, O_CLOEXEC) != 0 || (pipe2(out_fd, O_CLOEXEC | O_NONBLOCK) != 0) ||
        (pipe2(err_fd, O_CLOEXEC | O_NONBLOCK) != 0)) {
        ERROR("Failed to create pipe for shim create");
        ret = -1;
        goto out;
    }

    pid = fork();
    if (pid < 0) {
        ERROR("Failed to fork for shim parent %s", strerror(errno));
        ret = -1;
        goto out;
    }

    if (pid == (pid_t)0) {
        close(exec_fd[0]);
        if (chdir(workdir) < 0) {
            (void)dprintf(exec_fd[1], "%s: failed to chdir to %s", id, workdir);
            exit(EXIT_FAILURE);
        }

        if (setsid() < 0) {
            (void)dprintf(exec_fd[1], "%s: failed to setsid for process %d", id, getpid());
            exit(EXIT_FAILURE);
        }

        ret = null_stdin();
        if (ret == -1) {
            (void)dprintf(exec_fd[1], "%s: failed to set stdin for process %d", id, getpid());
            exit(EXIT_FAILURE);
        }

        close(out_fd[0]);
        dup2(out_fd[1], STDOUT_FILENO);
        close(err_fd[0]);
        dup2(err_fd[1], STDERR_FILENO);

        if (util_check_inherited(true, exec_fd[1]) != 0) {
            (void)dprintf(exec_fd[1], "close inherited fds failed");
        }

        setenv("EXIT_FIFO_DIR", exit_fifo_dir, 1);

        execvp(binary, (char * const *)params);
        (void)dprintf(exec_fd[1], "exec failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    close(exec_fd[1]);
    if (util_read_nointr(exec_fd[0], exec_buff, sizeof(exec_buff)) > 0) {
        ERROR("exec failed: %s", exec_buff);
        ret = -1;
        goto out;
    }
    close(exec_fd[0]);

    status = util_wait_for_pid_status(pid);
    if (status < 0) {
        ERROR("failed to wait shim-parent %d exit %s", pid, strerror(errno));
        ret = -1;
        goto out;
    }

    status = status_to_exit_code(status);

    close(out_fd[1]);
    util_read_nointr(out_fd[0], stdout_buff, sizeof(stdout_buff));
    close(out_fd[0]);
    close(err_fd[1]);
    util_read_nointr(err_fd[0], stderr_buff, sizeof(stderr_buff));
    close(err_fd[0]);

    if (status != 0) {
        ERROR("shim-v2 binary %d exit in %d with %s, %s", pid, status, stdout_buff, stderr_buff);
        ret = -1;
        goto out;
    }

    (void)strcpy(addr, stdout_buff);

    if (exit_code != NULL) {
        *exit_code = status;
    }

out:
    close(exec_fd[0]);
    close(out_fd[0]);
    close(err_fd[0]);
    close(exec_fd[1]);
    close(out_fd[1]);
    close(err_fd[1]);

    if (ret != 0 && pid > 0) {
        kill(pid, SIGKILL);
    }

    return ret;
}

bool rt_shim_detect(const char *runtime)
{
    if (runtime != NULL && (convert_v2_runtime(runtime, NULL) == 0)) {
        return true;
    }
    return false;
}

int rt_shim_create(const char *id, const char *runtime, const rt_create_params_t *params)
{
    int ret = 0;
    int pid = 0;
    char addr[PATH_MAX] = {0};
    char *exit_fifo_path = NULL;
    char *state_path = NULL;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    exit_fifo_path = util_path_dir(params->exit_fifo);
    if (exit_fifo_path == NULL) {
        ERROR("%s: failed to get exit fifo dir from %s", id, params->exit_fifo);
        ret = -1;
        goto out;
    }

    state_path = util_path_dir(exit_fifo_path);
    if (exit_fifo_path == NULL) {
        ERROR("%s:failed to get state dir from %s", id, exit_fifo_path);
        ret = -1;
        goto out;
    }

    if (shim_bin_v2_create(runtime, id, params->bundle, NULL, addr, state_path) != 0) {
        ERROR("%s: failed to create v2 shim", id);
        ret = -1;
        goto out;
    }

    INFO("%s: get shim-v2 address %s", id, addr);

    if (shim_v2_new(id, addr) != 0) {
        ERROR("%s: failed to init shim v2 connection on address %s", id, addr);
        ret = -1;
        goto out;
    }

    if (shim_v2_create(id, params->bundle, params->terminal, params->stdin, params->stdout, params->stderr, &pid) != 0) {
        ERROR("%s: failed to create container", id);
        ret = -1;
        goto out;
    }

out:
    free(exit_fifo_path);
    free(state_path);
    return ret;
}

int rt_shim_start(const char *id, const char *runtime, const rt_start_params_t *params, pid_ppid_info_t *pid_info)
{
    int pid = 0;

    if (shim_v2_start(id, NULL, &pid) != 0) {
        ERROR("%s: failed to start container", id);
        return -1;
    }

    pid_info->pid = pid;

    return 0;
}

int rt_shim_restart(const char *id, const char *runtime, const rt_restart_params_t *params)
{
    ERROR("rt_shim_restart not impl");
    return -1;
}

int rt_shim_clean_resource(const char *id, const char *runtime, const rt_clean_params_t *params)
{
    int ret = 0;
    char workdir[PATH_MAX] = {0};
    struct DeleteResponse res = {};

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    if (params->statepath == NULL) {
        ERROR("missing state path");
        ret = -1;
        goto out;
    }

    if (snprintf(workdir, sizeof(workdir), "%s/%s", params->statepath, id) < 0) {
        ERROR("failed to get shim workdir");
        ret = -1;
        goto out;
    }

    if (shim_v2_delete(id, NULL, &res) != 0) {
        WARN("%s: failed to delete container", id);
    }

    if (shim_v2_shutdown(id) != 0) {
        WARN("%s: failed to shutdown shim v2", id);
    }

    if (util_recursive_rmdir(workdir, 0) != 0) {
        ERROR("failed to rmdir -r shim workdir");
        ret = -1;
        goto out;
    }

    INFO("shim v2 rmdir -r %s done", workdir);

out:
    return ret;
}

int rt_shim_rm(const char *id, const char *runtime, const rt_rm_params_t *params)
{
    int ret = 0;
    char libdir[PATH_MAX] = {0};

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    if (params->rootpath == NULL) {
        ERROR("missing root path");
        ret = -1;
        goto out;
    }

    if (snprintf(libdir, sizeof(libdir), "%s/%s", params->rootpath, id) < 0) {
        ERROR("failed to get shim workdir");
        ret = -1;
        goto out;
    }

    if (util_recursive_rmdir(libdir, 0) != 0) {
        ERROR("failed to get shim workdir");
        ret = -1;
        goto out;
    }

    INFO("rmdir -r %s done", libdir);

out:
    return ret;
}

int rt_shim_exec(const char *id, const char *runtime, const rt_exec_params_t *params, int *exit_code)
{
    int ret = 0;
    int pid = 0;
    struct parser_context ctx = {OPT_GEN_SIMPLIFY, 0};
    parser_error perr = NULL;
    char *data = NULL;
    shim_client_process_state p = {0};

    if (id == NULL || params == NULL || exit_code == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    if (params->suffix == NULL) {
        ERROR("exec id is NULL");
        return -1;
    }

    copy_process(&p, params->spec);

    data = shim_client_process_state_generate_json(&p, &ctx, &perr);
    if (data == NULL) {
        ERROR("failed generate json for process.json error=%s", perr);
        ret = -1;
        goto out;
    }

    if (shim_v2_exec(id, params->suffix, params->spec->terminal, (char *)params->console_fifos[0],
                     (char *)params->console_fifos[1], (char *)params->console_fifos[2], data) != 0) {
        ERROR("%s: failed to exec container", id);
        ret = -1;
        goto out;
    }

    if (shim_v2_start(id, params->suffix, &pid) != 0) {
        ERROR("%s: failed to start exec process", id);
        ret = -1;
        goto out;
    }

    *exit_code = pid;

out:
    free(data);
    free(perr);
    return ret;
}


int rt_shim_status(const char *id, const char *runtime, const rt_status_params_t *params,
                   struct runtime_container_status_info *status)
{
    return 0;
}


int rt_shim_attach(const char *id, const char *runtime, const rt_attach_params_t *params)
{
    return 0;
}

int rt_shim_update(const char *id, const char *runtime, const rt_update_params_t *params)
{
    return 0;
}

int rt_shim_pause(const char *id, const char *runtime, const rt_pause_params_t *params)
{
    return 0;
}

int rt_shim_resume(const char *id, const char *runtime, const rt_resume_params_t *params)
{
    return 0;
}

int rt_shim_listpids(const char *id, const char *runtime, const rt_listpids_params_t *params,
                     rt_listpids_out_t *out)
{
    return 0;
}

int rt_shim_resources_stats(const char *id, const char *runtime, const rt_stats_params_t *params,
                            struct runtime_container_resources_stats_info *rs_stats)
{
    return 0;
}

int rt_shim_resize(const char *id, const char *runtime, const rt_resize_params_t *params)
{
    return 0;
}

int rt_shim_exec_resize(const char *id, const char *runtime, const rt_exec_resize_params_t *params)
{
    return 0;
}

int rt_shim_kill(const char *id, const char *runtime, const rt_kill_params_t *params)
{
    return 0;
}