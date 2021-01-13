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
#include "libcni_exec.h"

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

#include <isula_libutils/cni_inner_plugin_info.h>
#include <isula_libutils/cni_version.h>
#include <isula_libutils/log.h>
#include <isula_libutils/cni_exec_error.h>

#include "utils.h"
#include "libcni_errno.h"
#include "libcni_result_parse.h"
#include "err_msg.h"

typedef struct _plugin_exec_args_t {
    const char *path;
    char **environs;
} plugin_exec_args_t;

static bool deal_with_plugin_errcode(int status, char **stderr_msg, size_t errmsg_len)
{
    int signal;

    if (stderr_msg == NULL) {
        ERROR("Invalid arguments");
        return false;
    }

    if (status < 0) {
        ERROR("Failed to wait exec cmd process");
        return false;
    }

    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0) {
            return true;
        }
        ERROR("Plugin return error: %s", get_cni_err_msg(WEXITSTATUS(status)));
    } else if (WIFSIGNALED((unsigned int)status)) {
        signal = WTERMSIG(status);
        ERROR("Command exit with signal: %d", signal);
    } else if (WIFSTOPPED(status)) {
        signal = WSTOPSIG(status);
        ERROR("Command stop with signal: %d", signal);
    } else {
        ERROR("Command exit with unknown status: %d", status);
    }

    return false;
}

static void child_fun(void *args)
{
    plugin_exec_args_t *pargs = (plugin_exec_args_t *)args;
    char *argv[2] = { NULL };
    int ecode = 0;
    size_t envs_len;

    envs_len = util_array_len((const char **)pargs->environs);
    argv[0] = util_strdup_s(pargs->path);

    if (envs_len > 0) {
        ecode = execvpe(pargs->path, argv, pargs->environs);
    } else {
        ecode = execvp(pargs->path, argv);
    }

    (void)fprintf(stderr, "Execv: %s failed %s", pargs->path, strerror(errno));

    free(argv[0]);
    if (ecode == 0) {
        ecode = 127;
    }
    exit(ecode);
}

static void make_err_message(const char *plugin_path, char **stdout_str, const char *stderr_msg, cni_exec_error **err)
{
    if (stdout_str != NULL && *stdout_str != NULL && strlen(*stdout_str) > 0) {
        parser_error json_err = NULL;
        *err = cni_exec_error_parse_data(*stdout_str, NULL, &json_err);
        if (*err == NULL) {
            ERROR("parse plugin output: %s failed: %s", *stdout_str, json_err);
        }
        free(json_err);
    }

    if (stderr_msg != NULL) {
        // if get error from stdout, just log stderr
        if (*err != NULL) {
            ERROR("Run plugin get error: %s", stderr_msg);
            return;
        }

        *err = util_common_calloc_s(sizeof(cni_exec_error));
        if (*err == NULL) {
            ERROR("Out of memory");
            return;
        }
        int nret = 0;
        char *tmp_err = NULL;
        nret = asprintf(&tmp_err, "exec \'%s\' failed: %s", plugin_path, stderr_msg);
        if (nret < 0) {
            tmp_err = util_strdup_s(stderr_msg);
        }
        (*err)->msg = tmp_err;
        (*err)->code = 1;
    }
}

static int raw_exec(const char *plugin_path, const char *stdin_data, char **environs, char **stdout_str,
                    cni_exec_error **err)
{
    int ret = -1;
    char *stderr_msg = NULL;
    bool nret = false;
    plugin_exec_args_t p_args = {
        .path = plugin_path,
        .environs = environs,
    };
    exec_cmd_args cmd_args = {
        .stdin_msg = stdin_data,
        .stdout_msg = stdout_str,
        .stderr_msg = &stderr_msg,
    };

    nret = util_raw_exec_cmd(child_fun, (void *)&p_args, deal_with_plugin_errcode, &cmd_args);
    if (nret) {
        ret = 0;
        goto out;
    }

    make_err_message(plugin_path, stdout_str, stderr_msg, err);
    if (stdout_str != NULL) {
        free(*stdout_str);
        *stdout_str = NULL;
    }

out:
    free(stderr_msg);
    return ret;
}

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

static char *cniversion_decode(const char *jsonstr)
{
    parser_error err = NULL;
    cni_version *conf = NULL;
    char *result = NULL;

    conf = cni_version_parse_data(jsonstr, NULL, &err);
    if (conf == NULL) {
        ERROR("decoding config \"%s\", failed: %s", jsonstr, err);
        goto out;
    }
    if (conf->cni_version == NULL || strlen(conf->cni_version) == 0) {
        result = util_strdup_s("0.3.0");
        goto out;
    }

    result = util_strdup_s(conf->cni_version);
out:
    free(err);
    free_cni_version(conf);
    return result;
}

static int do_parse_exec_stdout_str(int exec_ret, const char *cni_net_conf_json, const cni_exec_error *e_err,
                                    const char *stdout_str, struct cni_opt_result **result)
{
    int ret = 0;
    char *version = NULL;
    char *err_msg = NULL;

    if (exec_ret != 0) {
        err_msg = str_cni_exec_error(e_err);
        ERROR("raw exec failed: %s", err_msg);
        isulad_append_error_message("raw exec failed: %s. ", err_msg);
        ret = -1;
        goto out;
    }

    version = cniversion_decode(cni_net_conf_json);
    if (version == NULL) {
        ret = -1;
        goto out;
    }
    if (stdout_str == NULL || strlen(stdout_str) == 0) {
        ERROR("Get empty stdout message");
        ret = -1;
        goto out;
    }
    free_cni_opt_result(*result);
    *result = new_result(version, stdout_str);
    if (*result == NULL) {
        ret = -1;
    }

out:
    free(version);
    free(err_msg);
    return ret;
}

static inline bool check_exec_plugin_with_result_args(const char *cni_net_conf_json,
                                                      struct cni_opt_result * const *result)
{
    return (cni_net_conf_json == NULL || result == NULL);
}

static char *env_stringify(char *(*pargs)[2], size_t len)
{
    char **entries = NULL;
    const char **work = NULL;
    char *result = NULL;
    size_t i = 0;
    bool invalid_arg = (pargs == NULL || len == 0);

    if (invalid_arg) {
        ERROR("Invalid arguments");
        return NULL;
    }

    if (len > SIZE_MAX - 1) {
        ERROR("Too large arguments");
        return NULL;
    }

    entries = util_smart_calloc_s(sizeof(char *), (len + 1));
    if (entries == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    for (i = 0; i < len; i++) {
        work = (const char **)pargs[i];
        entries[i] = util_string_join("=", work, 2);
        if (entries[i] == NULL) {
            ERROR("Join args failed");
            goto free_out;
        }
    }

    result = util_string_join(";", (const char **)entries, len);
free_out:
    util_free_array(entries);
    return result;
}

#define CNI_ENVS_LEN 6
#define ENV_CNI_COMMAND "CNI_COMMAND"
#define ENV_CNI_CONTAINERID "CNI_CONTAINERID"
#define ENV_CNI_NETNS "CNI_NETNS"
#define ENV_CNI_ARGS "CNI_ARGS"
#define ENV_CNI_IFNAME "CNI_IFNAME"
#define ENV_CNI_PATH "CNI_PATH"

static int add_cni_envs(const struct cni_args *cniargs, size_t *pos, char **result)
{
    char *plugin_args_str = NULL;
    char *buffer = NULL;
    size_t i = *pos;
    int nret = 0;
    int ret = -1;

    plugin_args_str = cniargs->plugin_args_str ? util_strdup_s(cniargs->plugin_args_str) : NULL;
    if (plugin_args_str == NULL || strlen(plugin_args_str) == 0) {
        free(plugin_args_str);
        plugin_args_str = env_stringify(cniargs->plugin_args, cniargs->plugin_args_len);
    }

    nret = asprintf(&buffer, "%s=%s", ENV_CNI_COMMAND, cniargs->command);
    if (nret < 0) {
        ERROR("Sprintf failed");
        goto free_out;
    }
    result[i++] = buffer;
    buffer = NULL;
    nret = asprintf(&buffer, "%s=%s", ENV_CNI_CONTAINERID, cniargs->container_id);
    if (nret < 0) {
        ERROR("Sprintf failed");
        goto free_out;
    }
    result[i++] = buffer;
    buffer = NULL;
    nret = asprintf(&buffer, "%s=%s", ENV_CNI_NETNS, cniargs->netns);
    if (nret < 0) {
        ERROR("Sprintf failed");
        goto free_out;
    }
    result[i++] = buffer;
    buffer = NULL;
    nret = asprintf(&buffer, "%s=%s", ENV_CNI_ARGS, plugin_args_str);
    if (nret < 0) {
        ERROR("Sprintf failed");
        goto free_out;
    }
    result[i++] = buffer;
    buffer = NULL;
    nret = asprintf(&buffer, "%s=%s", ENV_CNI_IFNAME, cniargs->ifname);
    if (nret < 0) {
        ERROR("Sprintf failed");
        goto free_out;
    }
    result[i++] = buffer;
    buffer = NULL;
    nret = asprintf(&buffer, "%s=%s", ENV_CNI_PATH, cniargs->path);
    if (nret < 0) {
        ERROR("Sprintf failed");
        goto free_out;
    }
    result[i++] = buffer;

    ret = 0;
free_out:
    free(plugin_args_str);
    *pos = i;
    return ret;
}

static char **as_env(const struct cni_args *cniargs)
{
#define NO_PROXY_KEY "no_proxy"
#define HTTP_PROXY_KEY "http_proxy"
#define HTTPS_PROXY_KEY "https_proxy"
    char **result = NULL;
    char **pos = NULL;
    size_t len = 0;
    size_t i = 0;
    size_t j = 0;
    char **envir = environ;

    if (cniargs == NULL) {
        ERROR("Invlaid cni args");
        return NULL;
    }

    len = util_array_len((const char **)envir);

    if (len > (SIZE_MAX - (CNI_ENVS_LEN + 1))) {
        ERROR("Too large arguments");
        return NULL;
    }

    len += (CNI_ENVS_LEN + 1);
    result = util_smart_calloc_s(sizeof(char *), len);
    if (result == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (add_cni_envs(cniargs, &i, result) != 0) {
        goto free_out;
    }

    /* inherit environs of parent */
    for (pos = envir; pos != NULL && *pos != NULL && i < len; pos++) {
        // ignore proxy environs
        if (strncasecmp(*pos, NO_PROXY_KEY, strlen(NO_PROXY_KEY)) == 0 ||
            strncasecmp(*pos, HTTP_PROXY_KEY, strlen(HTTP_PROXY_KEY)) == 0 ||
            strncasecmp(*pos, HTTPS_PROXY_KEY, strlen(HTTPS_PROXY_KEY)) == 0) {
            continue;
        }
        result[i] = util_strdup_s(*pos);
        i++;
    }

    return result;
free_out:
    for (j = 0; j < i; j++) {
        free(result[j]);
    }
    free(result);
    return NULL;
}

int exec_plugin_with_result(const char *plugin_path, const char *cni_net_conf_json, const struct cni_args *cniargs,
                            struct cni_opt_result **result)
{
    char **envs = NULL;
    char *stdout_str = NULL;
    cni_exec_error *e_err = NULL;
    int ret = 0;

    if (check_exec_plugin_with_result_args(cni_net_conf_json, result)) {
        ERROR("Invalid arguments");
        return -1;
    }
    if (cniargs != NULL) {
        envs = as_env(cniargs);
        if (envs == NULL) {
            ERROR("create env failed");
            ret = -1;
            goto out;
        }
    }

    ret = raw_exec(plugin_path, cni_net_conf_json, envs, &stdout_str, &e_err);
    DEBUG("Raw exec \"%s\" result: %d", plugin_path, ret);
    ret = do_parse_exec_stdout_str(ret, cni_net_conf_json, e_err, stdout_str, result);
out:
    free(stdout_str);
    util_free_array(envs);
    free_cni_exec_error(e_err);
    return ret;
}

int exec_plugin_without_result(const char *plugin_path, const char *cni_net_conf_json, const struct cni_args *cniargs)
{
    char *err_msg = NULL;
    char **envs = NULL;
    cni_exec_error *e_err = NULL;
    int ret = 0;

    if (cni_net_conf_json == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }
    if (cniargs != NULL) {
        envs = as_env(cniargs);
        if (envs == NULL) {
            goto out;
        }
    }

    ret = raw_exec(plugin_path, cni_net_conf_json, envs, NULL, &e_err);
    if (ret != 0) {
        err_msg = str_cni_exec_error(e_err);
        ERROR("raw exec failed: %s", err_msg);
        isulad_append_error_message("raw exec failed: %s. ", err_msg);
    }
    DEBUG("Raw exec \"%s\" result: %d", plugin_path, ret);
out:
    util_free_array(envs);
    free_cni_exec_error(e_err);
    free(err_msg);
    return ret;
}

void free_cni_args(struct cni_args *cargs)
{
    size_t i = 0;

    if (cargs == NULL) {
        return;
    }

    free(cargs->command);
    cargs->command = NULL;
    free(cargs->container_id);
    cargs->container_id = NULL;
    free(cargs->netns);
    cargs->netns = NULL;
    free(cargs->plugin_args_str);
    cargs->plugin_args_str = NULL;
    free(cargs->ifname);
    cargs->ifname = NULL;
    free(cargs->path);
    cargs->path = NULL;
    for (i = 0; i < cargs->plugin_args_len; i++) {
        free(cargs->plugin_args[i][0]);
        cargs->plugin_args[i][0] = NULL;
        free(cargs->plugin_args[i][1]);
        cargs->plugin_args[i][1] = NULL;
    }
    free(cargs->plugin_args);
    cargs->plugin_args = NULL;
    free(cargs);
}