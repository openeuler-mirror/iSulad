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
 * Description: provide version functions
 *********************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>

#include "version.h"
#include "utils.h"
#include "isula_libutils/cni_version.h"
#include "isula_libutils/cni_inner_plugin_info.h"
#include "types.h"
#include "current.h"
#include "isula_libutils/log.h"

const char *g_curr_support_versions[3] = { "0.3.0", curr_implemented_spec_version, NULL };

void free_plugin_info(struct plugin_info *pinfo)
{
    if (pinfo != NULL) {
        size_t i = 0;
        free(pinfo->cniversion);
        pinfo->cniversion = NULL;
        for (i = 0; i < pinfo->supported_versions_len; i++) {
            free(pinfo->supported_versions[i]);
            pinfo->supported_versions[i] = NULL;
        }
        free(pinfo->supported_versions);
        pinfo->supported_versions = NULL;
        free(pinfo);
    }
}

static void convert_from_cni_inner_plugin_info(cni_inner_plugin_info *inner, struct plugin_info **result, char **errmsg)
{
    bool invalid_arg = (inner == NULL || result == NULL);

    if (invalid_arg) {
        *errmsg = clibcni_util_strdup_s("Invalid argument");
        ERROR("Invalid argument");
        return;
    }

    *result = clibcni_util_common_calloc_s(sizeof(struct plugin_info));
    if (*result == NULL) {
        *errmsg = clibcni_util_strdup_s("Out of memory");
        ERROR("Out of memory");
        return;
    }
    (*result)->cniversion = inner->cni_version;
    inner->cni_version = NULL;
    (*result)->supported_versions_len = inner->supported_versions_len;
    inner->supported_versions_len = 0;
    (*result)->supported_versions = inner->supported_versions;
    inner->supported_versions = NULL;
}

struct plugin_info *plugin_supports(const char * const *supported_versions, size_t len, char **errmsg)
{
    struct plugin_info *result = NULL;
    size_t i = 0;
    size_t size = 0;
    bool invalid_arg = (supported_versions == NULL || len < 1);

    if (invalid_arg) {
        *errmsg = clibcni_util_strdup_s("Invalid version argument");
        return NULL;
    }

    result = clibcni_util_common_calloc_s(sizeof(struct plugin_info));
    if (result == NULL) {
        ERROR("Out of memory");
        *errmsg = clibcni_util_strdup_s("Out of memory");
        return NULL;
    }
    result->cniversion = clibcni_util_strdup_s(current());

    if (len > (SIZE_MAX / sizeof(char *) - 1)) {
        *errmsg = clibcni_util_strdup_s("Too many plugins");
        ERROR("Too many plugins");
        goto err_out;
    }

    size = sizeof(char *) * (len + 1);
    result->supported_versions = clibcni_util_common_calloc_s(size);
    if (result->supported_versions == NULL) {
        ERROR("Out of memory");
        *errmsg = clibcni_util_strdup_s("Out of memory");
        goto err_out;
    }

    for (i = 0; i < len; i++) {
        result->supported_versions[i] = clibcni_util_strdup_s(supported_versions[i]);
        result->supported_versions_len = i + 1;
    }

    return result;
err_out:
    free_plugin_info(result);
    return NULL;
}

struct plugin_info *plugin_info_decode(const char *jsonstr, char **errmsg)
{
    cni_inner_plugin_info *pinfo = NULL;
    struct plugin_info *result = NULL;
    parser_error err = NULL;
    const char *type020[] = { "0.1.0", "0.2.0" };
    int nret = 0;

    if (errmsg == NULL) {
        return NULL;
    }
    if (jsonstr == NULL) {
        *errmsg = clibcni_util_strdup_s("empty argument");
        ERROR("Invalid arguments");
        goto out;
    }
    pinfo = cni_inner_plugin_info_parse_data(jsonstr, NULL, &err);
    if (pinfo == NULL) {
        nret = asprintf(errmsg, "decoding version info: %s", err);
        if (nret < 0) {
            *errmsg = clibcni_util_strdup_s("Out of memory");
        }
        ERROR("decoding version info: %s", err);
        goto out;
    }
    if (clibcni_is_null_or_empty(pinfo->cni_version)) {
        *errmsg = clibcni_util_strdup_s("decoding version info: missing field cniVersion");
        goto out;
    }
    if (pinfo->supported_versions_len == 0) {
        if (strcmp(pinfo->cni_version, "0.2.0") == 0) {
            result = plugin_supports(type020, sizeof(type020) / sizeof(char *), errmsg);
            goto out;
        }
        *errmsg = clibcni_util_strdup_s("decoding version info: missing field supportedVersions");
        goto out;
    }

    convert_from_cni_inner_plugin_info(pinfo, &result, errmsg);
out:
    free(err);
    free_cni_inner_plugin_info(pinfo);
    return result;
}

char *cniversion_decode(const char *jsonstr, char **errmsg)
{
    parser_error err = NULL;
    cni_version *conf = NULL;
    char *result = NULL;
    int nret = 0;

    if (errmsg == NULL) {
        return NULL;
    }
    conf = cni_version_parse_data(jsonstr, NULL, &err);
    if (conf == NULL) {
        nret = asprintf(errmsg, "decoding config \"%s\", failed: %s", jsonstr, err);
        if (nret < 0) {
            *errmsg = clibcni_util_strdup_s("Out of memory");
        }
        ERROR("decoding config \"%s\", failed: %s", jsonstr, err);
        goto out;
    }
    if (conf->cni_version == NULL || strlen(conf->cni_version) == 0) {
        result = clibcni_util_strdup_s("0.1.0");
        goto out;
    }

    result = clibcni_util_strdup_s(conf->cni_version);
out:
    free(err);
    free_cni_version(conf);
    return result;
}

static bool check_raw(const char *version, const char **supports)
{
    const char **work = NULL;
    bool invalid_arg = (version == NULL || supports == NULL);

    if (invalid_arg) {
        return false;
    }

    for (work = supports; *work != NULL; work++) {
        if (strcmp(version, *work) == 0) {
            return true;
        }
    }
    return false;
}

struct result_factories g_factories[1] = {
    {
        .supported_versions = g_curr_support_versions,
        .new_result_op = &new_curr_result
    }
};

struct result *new_result(const char *version, const char *jsonstr, char **err)
{
    size_t i = 0;
    int ret = 0;

    if (err == NULL) {
        return NULL;
    }
    for (i = 0; i < sizeof(g_factories) / sizeof(struct result_factories); i++) {
        if (check_raw(version, g_factories[i].supported_versions)) {
            return g_factories[i].new_result_op(jsonstr, err);
        }
    }
    ret = asprintf(err, "unsupported CNI result version \"%s\"", version);
    if (ret < 0) {
        *err = clibcni_util_strdup_s("Out of memory");
    }
    ERROR("unsupported CNI result version \"%s\"", version);
    return NULL;
}
