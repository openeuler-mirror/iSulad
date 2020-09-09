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
 * Description: provide args functions
 *********************************************************************************/
#define _GNU_SOURCE
#define __USE_GNU
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "utils.h"
#include "args.h"
#include "isula_libutils/log.h"

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

    if (len > (INT_MAX / sizeof(char *)) - 1) {
        ERROR("Too large arguments");
        return NULL;
    }
    entries = clibcni_util_common_calloc_s(sizeof(char *) * (len + 1));
    if (entries == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    for (i = 0; i < len; i++) {
        work = (const char **)pargs[i];
        entries[i] = clibcni_util_string_join("=", work, 2);
        if (entries[i] == NULL) {
            ERROR("Join args failed");
            goto free_out;
        }
    }

    result = clibcni_util_string_join(";", (const char **)entries, len);
free_out:
    clibcni_util_free_array(entries);
    return result;
}

static int add_cni_envs(const struct cni_args *cniargs, size_t *pos, char **result)
{
    char *plugin_args_str = NULL;
    char *buffer = NULL;
    size_t i = *pos;
    int nret = 0;
    int ret = -1;

    plugin_args_str = cniargs->plugin_args_str ? clibcni_util_strdup_s(cniargs->plugin_args_str) : NULL;
    if (clibcni_is_null_or_empty(plugin_args_str)) {
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

char **as_env(const struct cni_args *cniargs)
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

    len = clibcni_util_array_len((const char * const *)envir);

    if (len > ((SIZE_MAX / sizeof(char *)) - (CNI_ENVS_LEN + 1))) {
        ERROR("Too large arguments");
        return NULL;
    }

    len += (CNI_ENVS_LEN + 1);
    result = clibcni_util_common_calloc_s(len * sizeof(char *));
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
        if (strcasecmp(*pos, NO_PROXY_KEY) == 0 || strcasecmp(*pos, HTTP_PROXY_KEY) == 0 ||
            strcasecmp(*pos, HTTPS_PROXY_KEY) == 0) {
            continue;
        }
        result[i] = clibcni_util_strdup_s(*pos);
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
