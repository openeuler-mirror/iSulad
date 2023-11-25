/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: gaohuatao
 * Create: 2021-05-20
 * Description: shim v2 runtime interface implementation
 ******************************************************************************/

#define _GNU_SOURCE

#include "shim_rt_ops.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>

#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/log.h>
#include <isula_libutils/shim_client_process_state.h>

#include "utils.h"
#include "utils_string.h"
#include "constants.h"
#include "error.h"
#include "err_msg.h"
#include "engine.h"
#include "shim_rt_monitor.h"
#include "supervisor.h"

#define EXIT_SIGNAL_OFFSET_X 128

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
        exit_code = EXIT_SIGNAL_OFFSET_X + signal;
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

bool is_valid_v2_runtime(const char* name)
{
    char **parts = NULL;
    size_t parts_len = 0;

    parts = util_string_split_multi(name, '.');
    if (parts == NULL) {
        ERROR("split failed: %s", name);
        return false;
    }

    parts_len = util_array_len((const char **)parts);
    if (!(parts_len == 4 && strcmp(parts[0], "io") == 0 && strcmp(parts[1], "containerd") == 0)) {
        util_free_array(parts);
        return false;
    }
    util_free_array(parts);

    return true;
}

// convert_v2_runtime validate is the param_runtime in runtime-v2 format (io.containerd.<runtime>.<version>).
// If param_runtime is legal and param_binary is not NULL, convert runtime binary name into it.
// io.containerd.<runtime>.<version> --> containerd-shim-<runtime>-<version>
static int convert_v2_runtime(const char *runtime, char *binary)
{
    char **parts = NULL;
    size_t parts_len = 0;
    char buf[PATH_MAX]  = {0};
    int ret = 0;
    int nret;

    if (binary == NULL) {
        return -1;
    }

    parts = util_string_split_multi(runtime, '.');
    if (parts == NULL) {
        ERROR("split failed: %s", runtime);
        return -1;
    }

    parts_len = util_array_len((const char **)parts);
    if (!(parts_len == 4 && strcmp(parts[0], "io") == 0 && strcmp(parts[1], "containerd") == 0)) {
        ERROR("ShimV2 runtime format is wrong");
        ret = -1;
        goto out;
    }

    nret = snprintf(buf, sizeof(buf), "%s-%s-%s-%s", "containerd", "shim", parts[2], parts[3]);
    if (nret < 0 || (size_t)nret >= sizeof(buf)) {
        ERROR("Failed to snprintf string");
        ret = -1;
        goto out;
    }
    (void)strcpy(binary, buf);

out:
    util_free_array(parts);
    return ret;
}

static int shim_bin_v2_create(const char *runtime, const char *id, const char *workdir, int *exit_code, char *addr,
                              const char *exit_fifo_dir)
{
    pid_t pid = 0;
    int ret = 0;
    int nret = 0;
    int i = 0;
    int status = 0;
    char binary[PATH_MAX + 1] = {0};
    const char *params[PARAM_NUM] = {0};
    char fpid[PATH_MAX] = {0};
    int exec_fd[2] = {-1, -1};
    int err_fd[2] = {-1, -1};
    int out_fd[2] = {-1, -1};
    char exec_buff[BUFSIZ + 1] = {0};
    char stdout_buff[PATH_MAX + 1] = {0};
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

    nret = snprintf(fpid, sizeof(fpid), "%s/shim-pid", workdir);
    if (nret < 0 || (size_t)nret >= sizeof(fpid)) {
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
        SYSERROR("Failed to fork for shim parent");
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

        if (setenv("EXIT_FIFO_DIR", exit_fifo_dir, 1) != 0) {
            (void)dprintf(exec_fd[1], "%s: failed to set env for process %d", id, getpid());
            exit(EXIT_FAILURE);
        }

        execvp(binary, (char * const *)params);
        (void)dprintf(exec_fd[1], "exec failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    close(exec_fd[1]);
    exec_fd[1] = -1;
    if (util_read_nointr(exec_fd[0], exec_buff, sizeof(exec_buff) - 1) > 0) {
        ERROR("exec failed: %s", exec_buff);
        ret = -1;
        goto out;
    }
    close(exec_fd[0]);
    exec_fd[0] = -1;

    status = util_wait_for_pid_status(pid);
    if (status < 0) {
        SYSERROR("failed to wait shim-parent %d exit", pid);
        ret = -1;
        goto out;
    }

    status = status_to_exit_code(status);

    close(out_fd[1]);
    util_read_nointr(out_fd[0], stdout_buff, sizeof(stdout_buff) - 1);
    close(out_fd[0]);
    out_fd[0] = -1;
    out_fd[1] = -1;
    close(err_fd[1]);
    util_read_nointr(err_fd[0], stderr_buff, sizeof(stderr_buff) - 1);
    close(err_fd[0]);
    err_fd[0] = -1;
    err_fd[1] = -1;

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
    if (runtime != NULL && is_valid_v2_runtime(runtime)) {
        return true;
    }

    return false;
}

static int save_shim_v2_address(const char *bundle, const char *addr)
{
    int nret;
    char filename[PATH_MAX] = { 0 };

    if (bundle == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    if (addr == NULL || strlen(addr) == 0) {
        ERROR("Invalid shim v2 addr");
        return -1;
    }

    nret = snprintf(filename, sizeof(filename), "%s/%s", bundle, "address");
    if (nret < 0 || (size_t)nret >= sizeof(filename)) {
        ERROR("Failed to print string");
        return -1;
    }

    nret = util_atomic_write_file(filename, addr, strlen(addr), CONFIG_FILE_MODE, false);
    if (nret != 0) {
        ERROR("Failed to write file %s", filename);
        return -1;
    }

    return 0;
}

int rt_shim_create(const char *id, const char *runtime, const rt_create_params_t *params)
{
    int ret = 0;
    int pid = 0;
    int fd = -1;
    const char *task_address = NULL;
    char response[PATH_MAX] = {0};
    __isula_auto_free char *exit_fifo_path = NULL;
    __isula_auto_free char *state_path = NULL;
    __isula_auto_free char *log_path = NULL;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    exit_fifo_path = util_path_dir(params->exit_fifo);
    if (exit_fifo_path == NULL) {
        ERROR("%s: failed to get exit fifo dir from %s", id, params->exit_fifo);
        return -1;
    }

    state_path = util_path_dir(exit_fifo_path);
    if (state_path == NULL) {
        ERROR("%s:failed to get state dir from %s", id, exit_fifo_path);
        return -1;
    }

    log_path = util_string_append(SHIM_V2_LOG, params->bundle);
    if (log_path == NULL) {
        ERROR("Fail to append log path");
        return -1;
    }

    fd = util_open(log_path, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_SECURE_FILE_MODE);
    if (fd < 0) {
        ERROR("Failed to create log file for shim v2: %s", log_path);
        return -1;
    }
    close(fd);

    /**
     * If task address is not set, create a new shim-v2 and get the address.
     * If task address is set, use it directly.
     */
    if (params->task_addr == NULL || strlen(params->task_addr) == 0) {
        if (shim_bin_v2_create(runtime, id, params->bundle, NULL, response, state_path) != 0) {
            ERROR("%s: failed to create v2 shim", id);
            return -1;
        }

        task_address = response;
    } else {
        task_address = params->task_addr;
    }

    INFO("%s: get shim-v2 address %s", id, task_address);

    if (shim_v2_new(id, task_address) != 0) {
        ERROR("%s: failed to init shim v2 connection on address %s", id, task_address);
        ret = -1;
        goto out;
    }

    if (shim_v2_create(id, params->bundle, params->terminal, params->stdin, params->stdout, params->stderr, &pid) != 0) {
        ERROR("%s: failed to create container", id);
        ret = -1;
        goto out;
    }

    if (save_shim_v2_address(params->bundle, task_address) != 0) {
        ERROR("%s: failed to save shim v2 address", id);
        ret = -1;
        goto out;
    }

    return 0;

out:
    if (ret != 0) {
        if (shim_v2_kill(id, NULL, SIGKILL, false) != 0) {
            ERROR("%s: kill shim v2 failed", id);
        }
    }
    return ret;
}

int rt_shim_start(const char *id, const char *runtime, const rt_start_params_t *params, pid_ppid_info_t *pid_info)
{
    int pid = -1;

    if (shim_v2_start(id, NULL, &pid) != 0) {
        ERROR("%s: failed to start container", id);
        return -1;
    }

    pid_info->pid = pid;

    return shim_rt_monitor(id, params->exit_fifo);
}

int rt_shim_restart(const char *id, const char *runtime, const rt_restart_params_t *params)
{
    ERROR("rt_shim_restart not impl");
    return -1;
}

int rt_shim_clean_resource(const char *id, const char *runtime, const rt_clean_params_t *params)
{
    int ret = 0;
    int nret = 0;
    char workdir[PATH_MAX] = {0};
    struct DeleteResponse res = {0};

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    if (params->statepath == NULL) {
        ERROR("missing state path");
        ret = -1;
        goto out;
    }

    nret = snprintf(workdir, sizeof(workdir), "%s/%s", params->statepath, id);
    if (nret < 0 || (size_t)nret >= sizeof(workdir)) {
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
    int nret = 0;
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

    nret = snprintf(libdir, sizeof(libdir), "%s/%s", params->rootpath, id);
    if (nret < 0 || (size_t)nret >= sizeof(libdir)) {
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

    if (shim_v2_wait(id, params->suffix, exit_code) != 0) {
        ERROR("%s: failed to wait exec process", id);
        ret = -1;
        goto out;
    }

out:
    free(data);
    free(perr);
    return ret;
}

static int file_read_address(const char *fname, char *addr)
{
    int ret = 0;
    char *buf = NULL;

    if (!util_file_exists(fname)) {
        ERROR("file:%s is not exist", fname);
        ret = -1;
        goto out;
    }

    buf = util_read_text_file(fname);
    if (buf == NULL) {
        ERROR("Read text from file:%s failed", fname);
        ret = -1;
        goto out;
    }

    if (strlen(buf) >= PATH_MAX) {
        ERROR("address in file %s is too long", fname);
        ret = -1;
        goto out;
    }

    (void)stpcpy(addr, buf);

out:
    free(buf);
    return ret;
}

static int status_to_engine_container_status(enum Status s)
{
    if (s == RunningStatus) {
        return RUNTIME_CONTAINER_STATUS_RUNNING;
    } else if (s == CreatedStatus) {
        return RUNTIME_CONTAINER_STATUS_CREATED;
    } else if (s == StoppedStatus) {
        return RUNTIME_CONTAINER_STATUS_STOPPED;
    } else if (s == PauseStatus) {
        return RUNTIME_CONTAINER_STATUS_PAUSED;
    }

    return RUNTIME_CONTAINER_STATUS_UNKNOWN;
}

int rt_shim_status(const char *id, const char *runtime, const rt_status_params_t *params,
                   struct runtime_container_status_info *status)
{
    char address_file[PATH_MAX] = {0};
    char address[PATH_MAX] = {0};
    char container_state[PATH_MAX] = { 0 };
    int ret = 0;
    int nret = 0;
    struct State ss = {0};

    if (id == NULL || params == NULL || status == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    if (params->task_address != NULL && strlen(params->task_address) != 0) {
        if (strlen(params->task_address) >= PATH_MAX) {
            ERROR("Invalid task address");
            return -1;
        }
        (void)strcpy(address, params->task_address);
    } else {
        nret = snprintf(address_file, sizeof(address_file), "%s/%s/address", params->rootpath, id);
        if (nret < 0 || (size_t)nret >= sizeof(address_file)) {
            ERROR("Failed to join full workdir %s/%s", params->rootpath, id);
            ret = -1;
            goto out;
        }

        if (file_read_address(address_file, address) != 0) {
            ERROR("%s: could not read address on %s", id, address_file);
            ret = -1;
            goto out;
        }
    }

    if (shim_v2_new(id, address) != 0) {
        ERROR("%s: failed to init shim-v2 connection with address %s", id, address);
        ret = -1;
        goto out;
    }

    if (shim_v2_state(id, &ss) != 0) {
        ERROR("%s: failed to get container state", id);
        ret = -1;
        goto out;
    }

    status->status = status_to_engine_container_status(ss.status);
    status->pid = ss.pid;
    if (ss.pid != 0) {
        status->has_pid = true;
    }

    nret = snprintf(container_state, sizeof(container_state), "%s/%s", params->state, id);
    if (nret < 0 || (size_t)nret >= sizeof(container_state)) {
        ERROR("Failed to sprintf container state %s/%s", params->state, id);
        ret = -1;
        goto out;
    }
    // shim_rt_monitor will check if the container is monitored, if not, it will monitor it.
    if (shim_rt_monitor(id, exit_fifo_name(container_state)) != 0) {
        ERROR("Failed to monitor container %s", id);
        ret = -1;
    }

out:
    return ret;
}

int rt_shim_attach(const char *id, const char *runtime, const rt_attach_params_t *params)
{
    ERROR("rt_shim_attach not impl");
    isulad_set_error_message("isula attach not support on shim-v2");
    return 0;
}

int rt_shim_update(const char *id, const char *runtime, const rt_update_params_t *params)
{
    ERROR("rt_shim_update not impl");
    isulad_set_error_message("isula update not support on shim-v2");
    return -1;
}

int rt_shim_pause(const char *id, const char *runtime, const rt_pause_params_t *params)
{
    if (shim_v2_pause(id) != 0) {
        ERROR("%s: pause container failed", id);
        return -1;
    }

    return 0;
}

int rt_shim_resume(const char *id, const char *runtime, const rt_resume_params_t *params)
{
    if (shim_v2_resume(id) != 0) {
        ERROR("%s: resume container failed", id);
        return -1;
    }

    return 0;
}

int rt_shim_listpids(const char *id, const char *runtime, const rt_listpids_params_t *params,
                     rt_listpids_out_t *out)
{
    int pid = 0;

    if (id == NULL || out == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    if (shim_v2_pids(id, &pid) != 0) {
        ERROR("%s: shim listpids failed", id);
        return -1;
    }

    out->pids_len = 1;
    out->pids = util_smart_calloc_s(sizeof(pid_t), out->pids_len);
    if (out->pids == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    *(out->pids) = (pid_t)pid;
    return 0;
}

int rt_shim_resources_stats(const char *id, const char *runtime, const rt_stats_params_t *params,
                            struct runtime_container_resources_stats_info *rs_stats)
{
    ERROR("rt_shim_resources_stats not impl");
    return -1;
}

int rt_shim_resize(const char *id, const char *runtime, const rt_resize_params_t *params)
{
    if (shim_v2_resize_pty(id, NULL, params->height, params->width) != 0) {
        ERROR("rt_shim_resize failed");
        return -1;
    }

    return 0;
}

int rt_shim_exec_resize(const char *id, const char *runtime, const rt_exec_resize_params_t *params)
{
    if (shim_v2_resize_pty(id, params->suffix, params->height, params->width) != 0) {
        ERROR("rt_shim_exec_resize failed");
        return -1;
    }

    return 0;
}

int rt_shim_kill(const char *id, const char *runtime, const rt_kill_params_t *params)
{
    if (shim_v2_kill(id, NULL, params->signal, false) != 0) {
        ERROR("%s: kill process failed", id);
        return -1;
    }

    return 0;
}

// the config file of oci runtime is config.json. If it is damaged, it cannot be rebuilt.
int rt_shim_rebuild_config(const char *name, const char *runtime, const rt_rebuild_config_params_t *params)
{
    return 0;
}