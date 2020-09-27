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

#include "utils.h"
#include "libcni_tools.h"
#include "libcni_errno.h"
#include "isula_libutils/log.h"

static int raw_exec(const char *plugin_path, const char *stdin_data, char** environs, char **stdout_str,
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
    int ret = 0;
    char *version = NULL;

    if (exec_ret != 0) {
        if (e_err != NULL) {
            *err = str_cni_exec_error(e_err);
        } else {
            *err = util_strdup_s("raw exec fail");
        }
        goto out;
    }

    version = cniversion_decode(cni_net_conf_json, err);
    if (version == NULL) {
        ret = -1;
        ERROR("Decode cni version failed: %s", *err != NULL ? *err : "");
        goto out;
    }
    if (stdout_str == NULL || strlen(stdout_str) == 0) {
        ERROR("Get empty stdout message");
        ret = -1;
        goto out;
    }
    *result = new_result(version, stdout_str, err);
    if (*result == NULL) {
        ERROR("Parse result failed: %s", *err != NULL ? *err : "");
        ret = -1;
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

typedef struct _plugin_exec_args_t {
    const char *path;
    char **environs;
} plugin_exec_args_t;

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
    if (stdout_str != NULL && *stdout_str != NULL) {
        parser_error json_err = NULL;
        *err = cni_exec_error_parse_data(*stdout_str, NULL, &json_err);
        if (*err == NULL) {
            ERROR("parse plugin output failed: %s", json_err);
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

static int raw_exec(const char *plugin_path, const char *stdin_data, char **environs, char **stdout_str,
                    cni_exec_error **err)
{
    int ret = 0;
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
    if (!nret) {
        ret = -1;
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

