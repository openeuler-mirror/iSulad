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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container information callback function definition
 *********************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <lcr/lcrcontainer.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/stat.h>
#include <malloc.h>
#include <sys/sysinfo.h>

#include "isula_libutils/log.h"
#include "console.h"
#include "isulad_config.h"
#include "config.h"
#include "image.h"
#include "execution.h"
#include "isula_libutils/container_inspect.h"
#include "containers_store.h"
#include "execution_information.h"
#include "sysinfo.h"

#include "container_state.h"
#include "runtime.h"
#include "list.h"
#include "utils.h"
#include "error.h"
#include "event_sender.h"

static int container_version_cb(const container_version_request *request, container_version_response **response)
{
    char *rootpath = NULL;
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();

    if (response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_version_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    (*response)->version = util_strdup_s(VERSION);
    (*response)->git_commit = util_strdup_s(ISULAD_GIT_COMMIT);
    (*response)->build_time = util_strdup_s(ISULAD_BUILD_TIME);

    rootpath = conf_get_isulad_rootdir();
    if (rootpath == NULL) {
        ERROR("Failed to get root directory");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }
    (*response)->root_path = util_strdup_s(rootpath);

pack_response:
    if (*response != NULL) {
        (*response)->cc = cc;
    }

    free(rootpath);

    isula_libutils_free_log_prefix();
    DAEMON_CLEAR_ERRMSG();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

#define STOP_JSON "{\"filters\":{\"status\":{\"exited\":true}}}"
#define CREATED_JSON "{\"filters\":{\"status\":{\"created\":true}}}"
static int get_container_nums(int *cRunning, int *cPaused, int *cStopped)
{
    container_list_request *list_running_request = NULL;
    container_list_request *list_stopped_request = NULL;
    container_list_request *list_created_request = NULL;
    container_list_response *list_running_response = NULL;
    container_list_response *list_stopped_response = NULL;
    container_list_response *list_created_response = NULL;
    int ret = 0;
    parser_error err = NULL;

    list_running_request = util_common_calloc_s(sizeof(*list_running_request));
    if (list_running_request == NULL) {
        ERROR("Out of memory!");
        ret = -1;
        goto out;
    }

    ret = container_list_cb(list_running_request, &list_running_response);
    if (ret != 0) {
        ERROR("Failed to get container list info!");
        ret = -1;
        goto out;
    }
    *cRunning = (int)list_running_response->containers_len;

    list_created_request = container_list_request_parse_data(CREATED_JSON, NULL, &err);
    if (list_created_request == NULL) {
        ERROR("Failed to parse json: %s", err);
        ret = -1;
        goto out;
    }

    ret = container_list_cb(list_created_request, &list_created_response);
    if (ret != 0) {
        ERROR("Failed to get container list info!");
        ret = -1;
        goto out;
    }

    list_stopped_request = container_list_request_parse_data(STOP_JSON, NULL, &err);
    if (list_stopped_request == NULL) {
        ERROR("Failed to parse json: %s", err);
        ret = -1;
        goto out;
    }

    ret = container_list_cb(list_stopped_request, &list_stopped_response);
    if (ret != 0) {
        ERROR("Failed to get container list info!");
        ret = -1;
        goto out;
    }
    *cStopped = (int)(list_stopped_response->containers_len + list_created_response->containers_len);

out:
    free_container_list_request(list_running_request);
    free_container_list_request(list_stopped_request);
    free_container_list_request(list_created_request);
    free_container_list_response(list_running_response);
    free_container_list_response(list_stopped_response);
    free_container_list_response(list_created_response);
    free(err);
    return ret;
}

static int get_proxy_env(char **proxy, const char *type)
{
    int ret = 0;
    char *tmp = NULL;

    *proxy = getenv(type);
    if (*proxy == NULL) {
        tmp = strings_to_upper(type);
        if (tmp == NULL) {
            ERROR("Failed to upper string!");
            ret = -1;
            goto out;
        }
        *proxy = getenv(tmp);
        if (*proxy == NULL) {
            *proxy = "";
        }
    }

out:
    free(tmp);
    return ret;
}

static int isulad_info_cb(const host_info_request *request, host_info_response **response)
{
    int ret = 0;
    int cRunning = 0;
    int cPaused = 0;
    int cStopped = 0;
    size_t images_num = 0;
    uint32_t cc = ISULAD_SUCCESS;
    uint64_t total_mem = 0;
    uint64_t sysmem_limit = 0;
    char *http_proxy = NULL;
    char *https_proxy = NULL;
    char *no_proxy = NULL;
    char *operating_system = NULL;
    char *huge_page_size = NULL;
    struct utsname u;
    char *rootpath = NULL;
#ifdef ENABLE_OCI_IMAGE
    im_image_count_request *im_request = NULL;
    struct graphdriver_status *driver_status = NULL;
#endif

    DAEMON_CLEAR_ERRMSG();

    if (response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(host_info_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    ret = get_container_nums(&cRunning, &cPaused, &cStopped);
    if (ret != 0) {
        ERROR("Failed to get container status info!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

#ifdef ENABLE_OCI_IMAGE
    driver_status = im_graphdriver_get_status();
    if (driver_status == NULL) {
        ERROR("Failed to get graph driver status info!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }
    im_request = util_common_calloc_s(sizeof(im_image_count_request));
    if (im_request == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }
    im_request->type = util_strdup_s(IMAGE_TYPE_OCI);
    images_num = im_get_image_count(im_request);
#endif

    operating_system = get_operating_system();
    if (operating_system == NULL) {
        ERROR("Failed to get operating system info!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    huge_page_size = get_default_huge_page_size();
    if (huge_page_size == NULL) {
        ERROR("Failed to get system hugepage size!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    sysmem_limit = get_default_total_mem_size();
    if (sysmem_limit == 0) {
        ERROR("Failed to get total mem!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    total_mem = sysmem_limit / SIZE_GB;

    if (uname(&u) != 0) {
        ERROR("Failed to get kernel info!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    ret = get_proxy_env(&http_proxy, HTTP_PROXY);
    if (ret != 0) {
        ERROR("Failed to get http proxy env!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    ret = get_proxy_env(&https_proxy, HTTPS_PROXY);
    if (ret != 0) {
        ERROR("Failed to get https proxy env!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    ret = get_proxy_env(&no_proxy, NO_PROXY);
    if (ret != 0) {
        ERROR("Failed to get no proxy env!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }
    rootpath = conf_get_isulad_rootdir();
    if (rootpath == NULL) {
        ERROR("Get isulad rootpath failed");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    (*response)->containers_num = (cRunning + cPaused + cStopped);
    (*response)->c_running = cRunning;
    (*response)->c_paused = cPaused;
    (*response)->c_stopped = cStopped;
    (*response)->images_num = (int)images_num;
    (*response)->version = util_strdup_s(VERSION);
    (*response)->kversion = util_strdup_s(u.release);
    (*response)->os_type = util_strdup_s(u.sysname);
    (*response)->architecture = util_strdup_s(u.machine);
    (*response)->nodename = util_strdup_s(u.nodename);
    (*response)->cpus = get_nprocs();
    (*response)->operating_system = util_strdup_s(operating_system);
    (*response)->cgroup_driver = util_strdup_s("cgroupfs");
    (*response)->logging_driver = util_strdup_s("json-file");
    (*response)->huge_page_size = util_strdup_s(huge_page_size);
    (*response)->isulad_root_dir = rootpath;
    rootpath = NULL;
    (*response)->total_mem = (uint32_t)total_mem;
    (*response)->http_proxy = util_strdup_s(http_proxy);
    (*response)->https_proxy = util_strdup_s(https_proxy);
    (*response)->no_proxy = util_strdup_s(no_proxy);
#ifdef ENABLE_OCI_IMAGE
    (*response)->driver_name = util_strdup_s(driver_status->driver_name);
    (*response)->driver_status = util_strdup_s(driver_status->status);
#endif

pack_response:
    if (*response != NULL) {
        (*response)->cc = cc;
    }
    free(rootpath);
#ifdef ENABLE_OCI_IMAGE
    im_free_graphdriver_status(driver_status);
    free_im_image_count_request(im_request);
#endif
    free(huge_page_size);
    free(operating_system);
    isula_libutils_free_log_prefix();
    DAEMON_CLEAR_ERRMSG();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

int get_stime(const char *title_line)
{
    size_t i = 0;
    int stime = 0;
    char **title_element = NULL;

    title_element = util_string_split(title_line, ' ');
    for (i = 0; i < util_array_len((const char **)title_element); i++) {
        if (strcmp(title_element[i], "STIME") == 0) {
            stime = (int)i;
            break;
        }
    }

    util_free_array(title_element);

    return stime;
}

int get_pid_num(const char *title_line)
{
    size_t i = 0;
    int num = 0;
    char **title_element = NULL;

    title_element = util_string_split(title_line, ' ');
    for (i = 0; i < util_array_len((const char **)title_element); i++) {
        if (strcmp(title_element[i], "PID") == 0) {
            num = (int)i;
            break;
        }
    }

    util_free_array(title_element);

    return num;
}

static int parse_output_check(char **pid_s, int pid_num, int *out_num)
{
    int ret = 0;

    // be able to display thread line also when "m" option used
    // in "isula top" client command
    if (strcmp(pid_s[pid_num], "-") == 0) {
    } else {
        if (util_safe_int(pid_s[pid_num], out_num) || *out_num < 0) {
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int parse_output_by_lines(char **process, char **tmp, int pid_num, int stime, const pid_t *pids, size_t pids_len)
{
    int ret = 0;
    size_t i = 0;
    size_t j = 0;
    int k = 0;
    char **pid_s = NULL;
    char **pid_s_pre = NULL;

    for (i = 1; i < util_array_len((const char **)tmp); i++) {
        bool flag = false;
        int tmp_num = 0;
        if (i > 1) {
            pid_s_pre = util_string_split(tmp[i - 1], ' ');
            if (pid_s_pre == NULL) {
                goto out;
            }
        }
        pid_s = util_string_split(tmp[i], ' ');
        if (pid_s == NULL) {
            util_free_array(pid_s_pre);
            goto out;
        }

        if (parse_output_check(pid_s, pid_num, &tmp_num)) {
            ret = -1;
            util_free_array(pid_s);
            util_free_array(pid_s_pre);
            goto out;
        }

        for (j = 0; j < pids_len; j++) {
            if (i > 1 && strcmp(pid_s[pid_num], "-") == 0 && !flag) {
                flag = true;
                if ((tmp_num == pids[j] || !strcmp(pid_s[stime], pid_s_pre[stime]))) {
                    process[k++] = util_strdup_s(tmp[i]);
                }
            } else if (tmp_num == pids[j]) {
                process[k++] = util_strdup_s(tmp[i]);
            }
        }
        util_free_array(pid_s);
        pid_s = NULL;
        util_free_array(pid_s_pre);
        pid_s_pre = NULL;
    }
out:
    return ret;
}

int parse_output(char **title, char ***process, size_t *process_len, const char *output, const pid_t *pids,
                 size_t pids_len)
{
    int ret = 0;
    int pid_num = 0;
    int stime = 0;
    char **tmp = NULL;

    tmp = util_string_split(output, '\n');
    if (tmp == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    *title = util_strdup_s(tmp[0]);

    pid_num = get_pid_num(*title);
    stime = get_stime(*title);
    if (util_array_len((const char **)tmp) > SIZE_MAX / sizeof(char *)) {
        ERROR("Invalid array length");
        ret = -1;
        goto out;
    }
    *process = util_common_calloc_s(util_array_len((const char **)tmp) * sizeof(char *));
    if (*process == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = parse_output_by_lines(*process, tmp, pid_num, stime, pids, pids_len);
    *process_len = util_array_len((const char **)(*process));

out:
    util_free_array(tmp);
    return ret;
}

static inline void add_ps_array_elem(char **array, size_t *pos, const char *elem)
{
    if (*pos + 1 >= (PARAM_NUM - 1)) {
        return;
    }
    array[*pos] = util_strdup_s(elem);
    *pos += 1;
}

void execute_ps_command(char **args, const char *pid_args, size_t args_len)
{
    size_t i = 0;
    char *params[PARAM_NUM] = { NULL };

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    add_ps_array_elem(params, &i, "ps");
    for (; args && *args && i < args_len + 1; args++) {
        add_ps_array_elem(params, &i, *args);
    }

    add_ps_array_elem(params, &i, pid_args);

    execvp("ps", params);

    COMMAND_ERROR("Cannot get ps info with '%s':%s", pid_args, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

static char *ps_pids_arg(const pid_t *pids, size_t pids_len)
{
    size_t i = 0;
    int nret;
    int ret = -1;
    size_t tmp_len = 0;
    char *pid_arg = NULL;
    char pid_str[UINT_LEN + 2] = { 0 };

    if (pids_len == 0 || pids_len > (SIZE_MAX - 1) / (UINT_LEN + 2)) {
        ERROR("Invalid pid size");
        return NULL;
    }
    tmp_len = pids_len * (UINT_LEN + 2) + 1;
    pid_arg = util_common_calloc_s(tmp_len);
    if (pid_arg == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (i = 0; i < pids_len; i++) {
        if (i != (pids_len - 1)) {
            nret = snprintf(pid_str, sizeof(pid_str), "%d,", pids[i]);
        } else {
            nret = snprintf(pid_str, sizeof(pid_str), "%d", pids[i]);
        }
        if ((size_t)nret >= sizeof(pid_str) || nret < 0) {
            ERROR("Failed to sprintf pids!");
            ret = -1;
            goto out;
        }

        (void)strcat(pid_arg, pid_str);
    }

    ret = 0;
out:
    if (ret != 0) {
        free(pid_arg);
        pid_arg = NULL;
    }
    return pid_arg;
}

static int get_pids(const char *name, const char *runtime, const char *rootpath, pid_t **pids, size_t *pids_len,
                    char **pid_args)
{
    int ret = 0;
    size_t i = 0;
    rt_listpids_params_t params = { 0 };
    rt_listpids_out_t *out = NULL;

    out = util_common_calloc_s(sizeof(rt_listpids_out_t));
    if (out == NULL) {
        ERROR("Memeory out");
        ret = -1;
        goto out;
    }

    params.rootpath = rootpath;

    if (runtime_listpids(name, runtime, &params, out) != 0) {
        ERROR("runtime failed to list pids");
        ret = -1;
        goto out;
    }

    if (out->pids_len > SIZE_MAX / sizeof(pid_t)) {
        ERROR("list too many pids");
        ret = -1;
        goto out;
    }

    if (out->pids_len != 0) {
        pid_t *tmp = NULL;
        tmp = util_common_calloc_s(sizeof(pid_t) * out->pids_len);
        if (tmp == NULL) {
            ERROR("Memory out");
            ret = -1;
            goto out;
        }
        for (i = 0; i < out->pids_len; i++) {
            tmp[i] = out->pids[i];
        }
        *pids = tmp;
    }

    *pids_len = out->pids_len;

    *pid_args = ps_pids_arg(*pids, *pids_len);
    if (*pid_args == NULL) {
        ERROR("failed to get pid_args");
        ret = -1;
        goto out;
    }
out:
    free_rt_listpids_out_t(out);
    return ret;
}

static int container_top_cb_check(const container_top_request *request, container_top_response **response, uint32_t *cc,
                                  container_t **cont)
{
    char *name = NULL;

    *response = util_common_calloc_s(sizeof(container_top_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        *cc = ISULAD_ERR_MEMOUT;
        return -1;
    }

    name = request->id;

    if (name == NULL) {
        DEBUG("receive NULL Request id");
        *cc = ISULAD_ERR_INPUT;
        return -1;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        *cc = ISULAD_ERR_EXEC;
        return -1;
    }

    *cont = containers_store_get(name);
    if (*cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        *cc = ISULAD_ERR_EXEC;
        return -1;
    }

    if (!is_running((*cont)->state)) {
        ERROR("Container is not running");
        isulad_set_error_message("Container is is not running.");
        *cc = ISULAD_ERR_EXEC;
        return -1;
    }

    if (is_restarting((*cont)->state)) {
        ERROR("Container %s is restarting, wait until the container is running.", name);
        isulad_set_error_message("Container %s is restarting, wait until the container is running.", name);
        *cc = ISULAD_ERR_EXEC;
        return -1;
    }

    return 0;
}

static int top_append_args(container_top_request *request)
{
    int ret = 0;

    if (request->args == NULL) {
        request->args = (char **)util_common_calloc_s(sizeof(char *));
        if (request->args == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        request->args[0] = util_strdup_s("-ef");
        request->args_len = 1;
    }

out:
    return ret;
}

static int do_top(const container_top_request *request, container_t *cont, size_t pids_len, const char *pid_args,
                  char **stdout_buffer, char **stderr_buffer)
{
    int ret = 0;
    bool command_ret = false;
    char *ps_args_with_q = NULL;
    size_t ps_args_with_q_len = 0;

    if (pids_len == 0 || pids_len > ((SIZE_MAX - 3) / (UINT_LEN + 2)) - 1) {
        ERROR("Invalid pid size");
        return -1;
    }
    ps_args_with_q_len = (pids_len + 1) * (UINT_LEN + 2) + 3;
    ps_args_with_q = util_common_calloc_s(ps_args_with_q_len);
    if (ps_args_with_q == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    (void)strcat(ps_args_with_q, "-q");

    (void)strcat(ps_args_with_q, pid_args);

    command_ret = util_exec_top_cmd(execute_ps_command, request->args, ps_args_with_q, request->args_len, stdout_buffer,
                                    stderr_buffer);
    if (!command_ret) {
        ERROR("Failed to get container ps info with error: %s",
              *stderr_buffer ? *stderr_buffer : "Failed to exec ps command");
        isulad_set_error_message("Failed to get container ps info with error: %s",
                                 *stderr_buffer ? *stderr_buffer : "Failed to exec ps command");
        free(*stdout_buffer);
        *stdout_buffer = NULL;
        free(*stderr_buffer);
        *stderr_buffer = NULL;
        // some ps options (such as f) can't be used together with q,
        // so retry without it
        command_ret = util_exec_top_cmd(execute_ps_command, request->args, pid_args, request->args_len, stdout_buffer,
                                        stderr_buffer);
        if (!command_ret) {
            ERROR("Failed to get container ps info with error: %s",
                  *stderr_buffer ? *stderr_buffer : "Failed to exec ps command");
            isulad_set_error_message("Failed to container ps info with error: %s", *stderr_buffer);
            ret = -1;
            goto out;
        }
    }
out:
    free(ps_args_with_q);
    return ret;
}

static int container_top_cb(container_top_request *request, container_top_response **response)
{
    size_t i = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;
    char *rootpath = NULL;
    char *runtime = NULL;
    char *pid_args = NULL;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    char *titles = NULL;
    char **processes = NULL;
    size_t process_len = 0;
    pid_t *pids = NULL;
    size_t pids_len = 0;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    if (top_append_args(request)) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (container_top_cb_check(request, response, &cc, &cont) < 0) {
        goto pack_response;
    }

    id = cont->common_config->id;
    rootpath = cont->root_path;
    runtime = cont->runtime;
    isula_libutils_set_log_prefix(id);

    if (get_pids(id, runtime, rootpath, &pids, &pids_len, &pid_args) != 0) {
        ERROR("failed to get all pids");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (do_top(request, cont, pids_len, pid_args, &stdout_buffer, &stderr_buffer) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (parse_output(&titles, &processes, &process_len, stdout_buffer, pids, pids_len)) {
        ERROR("Failed to parse output!");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }
    if (process_len > SIZE_MAX / sizeof(char *)) {
        ERROR("invalid processe size");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }
    (*response)->processes = util_common_calloc_s(process_len * sizeof(char *));
    if ((*response)->processes == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    (*response)->titles = titles;
    titles = NULL;
    for (i = 0; i < process_len; i++) {
        (*response)->processes[i] = util_strdup_s(processes[i]);
    }
    (*response)->processes_len = process_len;
    (void)isulad_monitor_send_container_event(id, TOP, -1, 0, NULL, NULL);

pack_response:
    if (*response != NULL) {
        (*response)->cc = cc;
    }

    free(pids);
    container_unref(cont);
    free(stdout_buffer);
    stdout_buffer = NULL;
    free(stderr_buffer);
    stderr_buffer = NULL;
    free(pid_args);
    free(titles);
    util_free_array_by_len(processes, process_len);
    isula_libutils_free_log_prefix();
    DAEMON_CLEAR_ERRMSG();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int dup_path_and_args(const container_t *cont, char **path, char ***args, size_t *args_len)
{
    int ret = 0;
    size_t i = 0;

    if (cont->common_config->path != NULL) {
        *path = util_strdup_s(cont->common_config->path);
    }
    if (cont->common_config->args_len > 0) {
        if ((cont->common_config->args_len) > SIZE_MAX / sizeof(char *)) {
            ERROR("Containers config args len is too many!");
            ret = -1;
            goto out;
        }
        *args = util_common_calloc_s(cont->common_config->args_len * sizeof(char *));
        if ((*args) == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < cont->common_config->args_len; i++) {
            if (cont->common_config->args[i] == NULL) {
                ERROR("Input value of args is null");
                ret = -1;
                goto out;
            }
            (*args)[*args_len] = util_strdup_s(cont->common_config->args[i]);
            (*args_len)++;
        }
    }
out:
    return ret;
}

// Always modify this function if host_config.json is modified.
static int dup_host_config(const host_config *src, host_config **dest)
{
    int ret = -1;
    char *json = NULL;
    parser_error err = NULL;

    if (src == NULL) {
        *dest = NULL;
        return 0;
    }

    json = host_config_generate_json(src, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    *dest = host_config_parse_data(json, NULL, &err);
    if (*dest == NULL) {
        ERROR("Failed to parse json: %s", err);
        goto out;
    }
    ret = 0;

out:
    free(err);
    free(json);
    return ret;
}

static int dup_health_check_config(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;
    size_t i = 0;

    if (src == NULL || src->healthcheck == NULL || dest == NULL) {
        return 0;
    }
    dest->health_check = util_common_calloc_s(sizeof(defs_health_check));
    if (dest->health_check == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (src->healthcheck->test != NULL && src->healthcheck->test_len != 0) {
        if (src->healthcheck->test_len > SIZE_MAX / sizeof(char *)) {
            ERROR("health check test is too much!");
            ret = -1;
            goto out;
        }
        dest->health_check->test = util_common_calloc_s(src->healthcheck->test_len * sizeof(char *));
        if (dest->health_check->test == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < src->healthcheck->test_len; i++) {
            if (src->healthcheck->test[i] == NULL) {
                ERROR("Input value of src health check test is null");
                ret = -1;
                goto out;
            }
            dest->health_check->test[i] = util_strdup_s(src->healthcheck->test[i]);
            dest->health_check->test_len++;
        }
        dest->health_check->interval = timeout_with_default(src->healthcheck->interval, DEFAULT_PROBE_INTERVAL);
        dest->health_check->start_period = timeout_with_default(src->healthcheck->start_period, DEFAULT_START_PERIOD);
        dest->health_check->timeout = timeout_with_default(src->healthcheck->timeout, DEFAULT_PROBE_TIMEOUT);
        dest->health_check->retries = src->healthcheck->retries != 0 ? src->healthcheck->retries :
                                      DEFAULT_PROBE_RETRIES;

        dest->health_check->exit_on_unhealthy = src->healthcheck->exit_on_unhealthy;
    }
out:
    return ret;
}

static int dup_container_config_env(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;
    size_t i = 0;
    char *tmpstr = NULL;

    if (src->env != NULL && src->env_len > 0) {
        if (src->env_len > SIZE_MAX / sizeof(char *)) {
            ERROR("Container inspect config env elements is too much!");
            ret = -1;
            goto out;
        }
        dest->env = util_common_calloc_s(src->env_len * sizeof(char *));
        if (dest->env == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < src->env_len; i++) {
            if (src->env[i] == NULL) {
                ERROR("Input value of src env is null");
                ret = -1;
                goto out;
            }
            tmpstr = src->env[i];
            dest->env[i] = tmpstr ? util_strdup_s(tmpstr) : NULL;
            dest->env_len++;
        }
    }

out:
    return ret;
}

static int dup_container_config_cmd_and_entrypoint(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;

    if (src == NULL || dest == NULL) {
        return 0;
    }

    ret = dup_array_of_strings((const char **)(src->cmd), src->cmd_len, &(dest->cmd), &(dest->cmd_len));
    if (ret != 0) {
        goto out;
    }

    ret = dup_array_of_strings((const char **)(src->entrypoint), src->entrypoint_len, &(dest->entrypoint),
                               &(dest->entrypoint_len));
out:
    return ret;
}

static int dup_container_config_labels(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;

    if (src->labels != NULL) {
        dest->labels = util_common_calloc_s(sizeof(json_map_string_string));
        if (dest->labels == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        ret = dup_json_map_string_string(src->labels, dest->labels);
        if (ret != 0) {
            goto out;
        }
    }
out:
    return ret;
}

static int dup_container_config_annotations(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;

    if (src->annotations != NULL) {
        dest->annotations = util_common_calloc_s(sizeof(json_map_string_string));
        if (dest->annotations == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        ret = dup_json_map_string_string(src->annotations, dest->annotations);
        if (ret != 0) {
            goto out;
        }
    }
out:
    return ret;
}

static int dup_container_config(const char *image, const container_config *src, container_inspect_config *dest)
{
    int ret = 0;

    if (src == NULL || dest == NULL) {
        return 0;
    }

    dest->hostname = src->hostname ? util_strdup_s(src->hostname) : util_strdup_s("");
    dest->user = src->user ? util_strdup_s(src->user) : util_strdup_s("");
    dest->tty = src->tty;
    dest->image = image ? util_strdup_s(image) : util_strdup_s("none");

    if (dup_container_config_env(src, dest) != 0) {
        ret = -1;
        goto out;
    }

    if (dup_container_config_cmd_and_entrypoint(src, dest) != 0) {
        ret = -1;
        goto out;
    }

    if (dup_container_config_labels(src, dest) != 0) {
        ret = -1;
        goto out;
    }

    if (dup_container_config_annotations(src, dest) != 0) {
        ret = -1;
        goto out;
    }

    if (dup_health_check_config(src, dest) != 0) {
        ERROR("Failed to duplicate health check config");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int mount_point_to_inspect(const container_t *cont, container_inspect *inspect)
{
    size_t i, len;

    if (cont->common_config->mount_points == NULL || cont->common_config->mount_points->len == 0) {
        return 0;
    }

    len = cont->common_config->mount_points->len;
    if (len > SIZE_MAX / sizeof(docker_types_mount_point *)) {
        ERROR("Invalid mount point size");
        return -1;
    }
    inspect->mounts = util_common_calloc_s(sizeof(docker_types_mount_point *) * len);
    if (inspect->mounts == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < len; i++) {
        container_config_v2_common_config_mount_points_element *mp = cont->common_config->mount_points->values[i];
        inspect->mounts[i] = util_common_calloc_s(sizeof(docker_types_mount_point));
        if (inspect->mounts[i] == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        inspect->mounts[i]->source = util_strdup_s(mp->source);
        inspect->mounts[i]->destination = util_strdup_s(mp->destination);
        inspect->mounts[i]->name = util_strdup_s(mp->name);
        inspect->mounts[i]->driver = util_strdup_s(mp->driver);
        inspect->mounts[i]->mode = util_strdup_s(mp->relabel);
        inspect->mounts[i]->propagation = util_strdup_s(mp->propagation);
        inspect->mounts[i]->rw = mp->rw;

        inspect->mounts_len++;
    }
    return 0;
}

static int pack_inspect_container_state(const container_t *cont, container_inspect *inspect)
{
    int ret = 0;
    container_config_v2_state *cont_state = NULL;

    cont_state = state_get_info(cont->state);
    if (cont_state == NULL) {
        ERROR("Failed to read %s state", cont->common_config->id);
        ret = -1;
        goto out;
    }

    inspect->state = util_common_calloc_s(sizeof(container_inspect_state));
    if (inspect->state == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    inspect->state->status = util_strdup_s(state_to_string(state_judge_status(cont_state)));
    inspect->state->running = cont_state->running;
    inspect->state->paused = cont_state->paused;
    inspect->state->restarting = cont_state->restarting;
    inspect->state->pid = cont_state->pid;

    inspect->state->exit_code = cont_state->exit_code;
    inspect->state->started_at = cont_state->started_at ? util_strdup_s(cont_state->started_at) :
                                 util_strdup_s(defaultContainerTime);
    inspect->state->finished_at = cont_state->finished_at ? util_strdup_s(cont_state->finished_at) :
                                  util_strdup_s(defaultContainerTime);
    inspect->state->error = cont->state->state->error ? util_strdup_s(cont->state->state->error) : NULL;
    inspect->restart_count = cont->common_config->restart_count;

    if (dup_health_check_status(&inspect->state->health, cont_state->health) != 0) {
        ERROR("Failed to dup health check info");
        ret = -1;
        goto out;
    }
out:
    free_container_config_v2_state(cont_state);
    return ret;
}

static int pack_inspect_host_config(const container_t *cont, container_inspect *inspect)
{
    int ret = 0;
    host_config *hostconfig = NULL;

    hostconfig = cont->hostconfig;
    if (hostconfig == NULL) {
        ERROR("Failed to read host config");
        ret = -1;
        goto out;
    }

    if (dup_host_config(hostconfig, &inspect->host_config) != 0) {
        ERROR("Failed to dup host config");
        ret = -1;
        goto out;
    }

    if (cont->runtime != NULL) {
        free(inspect->host_config->runtime);
        inspect->host_config->runtime = util_strdup_s(cont->runtime);
    }
out:
    return ret;
}

static int pack_inspect_general_data(const container_t *cont, container_inspect *inspect)
{
    int ret = 0;

    inspect->id = util_strdup_s(cont->common_config->id);
    inspect->name = util_strdup_s(cont->common_config->name);
    if (cont->common_config->created != NULL) {
        inspect->created = util_strdup_s(cont->common_config->created);
    }

    if (dup_path_and_args(cont, &(inspect->path), &(inspect->args), &(inspect->args_len)) != 0) {
        ERROR("Failed to dup path and args");
        ret = -1;
        goto out;
    }

    inspect->image = cont->image_id != NULL ? util_strdup_s(cont->image_id) : util_strdup_s("");

    if (cont->common_config->log_path != NULL) {
        inspect->log_path = util_strdup_s(cont->common_config->log_path);
    }

    if (cont->common_config->hosts_path != NULL) {
        inspect->hosts_path = util_strdup_s(cont->common_config->hosts_path);
    }
    if (cont->common_config->resolv_conf_path != NULL) {
        inspect->resolv_conf_path = util_strdup_s(cont->common_config->resolv_conf_path);
    }
    if (cont->common_config->mount_label != NULL) {
        inspect->mount_label = util_strdup_s(cont->common_config->mount_label);
    }
    if (cont->common_config->process_label != NULL) {
        inspect->process_label = util_strdup_s(cont->common_config->process_label);
    }

    if (cont->common_config->seccomp_profile != NULL) {
        inspect->seccomp_profile = util_strdup_s(cont->common_config->seccomp_profile);
    }

    inspect->no_new_privileges = cont->common_config->no_new_privileges;

    if (mount_point_to_inspect(cont, inspect) != 0) {
        ERROR("Failed to transform to mount point");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int pack_inspect_config(const container_t *cont, container_inspect *inspect)
{
    int ret = 0;

    inspect->config = util_common_calloc_s(sizeof(container_inspect_config));
    if (inspect->config == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (dup_container_config(cont->common_config->image, cont->common_config->config, inspect->config) != 0) {
        ERROR("Failed to dup container config");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int merge_default_ulimit_with_ulimit(container_inspect *out_inspect)
{
    int ret = 0;
    host_config_ulimits_element **rlimits = NULL;
    size_t i, j, ulimits_len;

    if (conf_get_isulad_default_ulimit(&rlimits) != 0) {
        ERROR("Failed to get isulad default ulimit");
        ret = -1;
        goto out;
    }

    ulimits_len = ulimit_array_len(rlimits);
    for (i = 0; i < ulimits_len; i++) {
        for (j = 0; j < out_inspect->host_config->ulimits_len; j++) {
            if (strcmp(rlimits[i]->name, out_inspect->host_config->ulimits[j]->name) == 0) {
                break;
            }
        }
        if (j < out_inspect->host_config->ulimits_len) {
            continue;
        }

        if (ulimit_array_append(&out_inspect->host_config->ulimits, rlimits[i],
                                out_inspect->host_config->ulimits_len) != 0) {
            ERROR("ulimit append failed");
            ret = -1;
            goto out;
        }
        out_inspect->host_config->ulimits_len++;
    }

out:
    free_default_ulimit(rlimits);
    return ret;
}

static int pack_inspect_data(const container_t *cont, container_inspect **out_inspect)
{
    int ret = 0;
    container_inspect *inspect = NULL;

    inspect = util_common_calloc_s(sizeof(container_inspect));
    if (inspect == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (pack_inspect_general_data(cont, inspect) != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (pack_inspect_container_state(cont, inspect) != 0) {
        ret = -1;
        goto out;
    }

    if (pack_inspect_host_config(cont, inspect) != 0) {
        ret = -1;
        goto out;
    }

    if (merge_default_ulimit_with_ulimit(inspect) != 0) {
        ret = -1;
        goto out;
    }

    if (pack_inspect_config(cont, inspect) != 0) {
        ret = -1;
        goto out;
    }

    if (!strcmp(cont->common_config->image_type, IMAGE_TYPE_OCI)) {
        inspect->graph_driver = im_graphdriver_get_metadata(cont->common_config->id);
        if (inspect->graph_driver == NULL) {
            ret = -1;
            goto out;
        }
    }

out:
    *out_inspect = inspect;
    return ret;
}

/*
 * RETURN VALUE:
 * 0: inspect success
 * -1: no such container with "id"
 * -2: have the container with "id", but failed to inspect due to other reasons
*/
static int inspect_container_helper(const char *id, int timeout, char **container_json)
{
    int ret = 0;
    container_inspect *inspect = NULL;
    parser_error err = NULL;
    container_t *cont = NULL;
    struct parser_context ctx = { OPT_GEN_KAY_VALUE | OPT_GEN_SIMPLIFY, 0 };

    if (!util_valid_container_id_or_name(id)) {
        ERROR("Inspect invalid name %s", id);
        isulad_set_error_message("Inspect invalid name %s", id);
        ret = -1;
        goto out;
    }

    cont = containers_store_get(id);
    if (cont == NULL) {
        ret = -1;
        isulad_try_set_error_message("No such image or container or accelerator:%s", id);
        goto out;
    }

    ret = container_timedlock(cont, timeout);
    if (ret != 0) {
        ERROR("Container %s inspect failed due to trylock timeout for %ds.", id, timeout);
        isulad_try_set_error_message("Container %s inspect failed due to trylock timeout for %ds.", id, timeout);
        ret = -2;
        goto out;
    }

    if (pack_inspect_data(cont, &inspect) != 0) {
        ret = -2;
        goto unlock;
    }

    *container_json = container_inspect_generate_json(inspect, &ctx, &err);
    if (*container_json == NULL) {
        ERROR("Failed to generate inspect json:%s", err);
        ret = -2;
        goto unlock;
    }

unlock:
    container_unlock(cont);
out:
    container_unref(cont);
    free_container_inspect(inspect);
    free(err);

    return ret;
}

static int container_inspect_cb(const container_inspect_request *request, container_inspect_response **response)
{
    int timeout = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *name = NULL;
    char *container_json = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_inspect_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    timeout = request->timeout;

    if (name == NULL) {
        ERROR("receive NULL Request id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    isula_libutils_set_log_prefix(name);

    INFO("Inspect :%s", name);

    if (inspect_container_helper(name, timeout, &container_json) != 0) {
        cc = ISULAD_ERR_EXEC;
    }

pack_response:
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
        (*response)->container_json = container_json;
    }

    isula_libutils_free_log_prefix();
    malloc_trim(0);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_wait_response(container_wait_response *response, uint32_t cc, uint32_t exit_code)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    response->exit_code = exit_code;
}

static int container_wait_cb(const container_wait_request *request, container_wait_response **response)
{
    char *name = NULL;
    char *id = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    uint32_t exit_code = 0;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_wait_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;

    if (name == NULL) {
        DEBUG("receive NULL Request id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("No such container '%s'", name);
        cc = ISULAD_ERR_EXEC;
        isulad_try_set_error_message("No such container:%s", name);
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    if (request->condition == WAIT_CONDITION_STOPPED) {
        (void)container_wait_stop_locking(cont, -1);
    } else {
        (void)container_wait_rm_locking(cont, -1);
    }

    exit_code = state_get_exitcode(cont->state);

    INFO("Wait Container:%s", id);

pack_response:
    pack_wait_response(*response, cc, exit_code);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int rename_request_check(const struct isulad_container_rename_request *request)
{
    int ret = 0;

    if (!util_valid_str(request->old_name) || !util_valid_str(request->new_name)) {
        ERROR("Neither old nor new names may be empty");
        isulad_set_error_message("Neither old nor new names may be empty");
        ret = -1;
        goto out;
    }

    if (!util_valid_container_id_or_name(request->old_name)) {
        ERROR("Invalid container old name (%s)", request->old_name);
        isulad_set_error_message("Invalid container old name (%s)", request->old_name);
        ret = -1;
        goto out;
    }

    if (!util_valid_container_name(request->new_name)) {
        ERROR("Invalid container new name (%s), only [a-zA-Z0-9][a-zA-Z0-9_.-]+$ are allowed.", request->new_name);
        isulad_set_error_message("Invalid container new name (%s), only [a-zA-Z0-9][a-zA-Z0-9_.-]+$ are allowed.",
                                 request->new_name);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static void pack_rename_response(struct isulad_container_rename_response *response, const char *id, uint32_t cc)
{
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static void restore_names_at_fail(container_t *cont, const char *ori_name, const char *new_name)
{
    const char *id = cont->common_config->id;

    free(cont->common_config->name);
    cont->common_config->name = util_strdup_s(ori_name);

    if (!name_index_rename(ori_name, new_name, id)) {
        ERROR("Failed to restore name from \"%s\" to \"%s\" for container %s", new_name, ori_name, id);
    }
}

static int container_rename(container_t *cont, const char *new_name)
{
    int ret = 0;
    char *id = cont->common_config->id;
    char *old_name = NULL;

    container_lock(cont);

    old_name = util_strdup_s(cont->common_config->name);

    if (strcmp(old_name, new_name) == 0) {
        ERROR("Renaming a container with the same name as its current name");
        isulad_set_error_message("Renaming a container with the same name as its current name");
        ret = -1;
        goto out;
    }

    if (is_removal_in_progress(cont->state) || is_dead(cont->state)) {
        ERROR("Can't rename container which is dead or marked for removal");
        isulad_set_error_message("Can't rename container which is dead or marked for removal");
        ret = -1;
        goto out;
    }

    if (!name_index_rename(new_name, old_name, id)) {
        ERROR("Name %s is in use", new_name);
        isulad_set_error_message("Conflict. The name \"%s\" is already in use by container %s. "
                                 "You have to remove (or rename) that container to be able to reuse that name.",
                                 new_name, new_name);
        ret = -1;
        goto out;
    }

    free(cont->common_config->name);
    cont->common_config->name = util_strdup_s(new_name);

    if (container_to_disk(cont) != 0) {
        ERROR("Failed to save container config of %s in renaming %s progress", id, new_name);
        isulad_set_error_message("Failed to save container config of %s in renaming %s progress", id, new_name);
        ret = -1;
        goto restore;
    }

    goto out;

restore:
    restore_names_at_fail(cont, old_name, new_name);
out:
    container_unlock(cont);
    free(old_name);
    return ret;
}

static int container_rename_cb(const struct isulad_container_rename_request *request,
                               struct isulad_container_rename_response **response)
{
    int nret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;
    char *old_name = NULL;
    char *new_name = NULL;
    container_t *cont = NULL;
    char annotations[EVENT_EXTRA_ANNOTATION_MAX] = { 0 };

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_create_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (rename_request_check(request) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }
    old_name = request->old_name;
    new_name = request->new_name;

    cont = containers_store_get(old_name);
    if (cont == NULL) {
        ERROR("No such container:%s", old_name);
        isulad_set_error_message("No such container:%s", old_name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Renaming}", id);

    if (container_rename(cont, new_name) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    nret = snprintf(annotations, sizeof(annotations), "oldName=%s", request->old_name);
    if (nret < 0 || (size_t)nret >= sizeof(annotations)) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Renamed to %s}", id, new_name);
    (void)isulad_monitor_send_container_event(id, RENAME, -1, 0, NULL, annotations);
    goto pack_response;

pack_response:
    pack_rename_response(*response, id, cc);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

void container_information_callback_init(service_container_callback_t *cb)
{
    cb->version = container_version_cb;
    cb->info = isulad_info_cb;
    cb->inspect = container_inspect_cb;
    cb->list = container_list_cb;
    cb->wait = container_wait_cb;
    cb->top = container_top_cb;
    cb->rename = container_rename_cb;
}
