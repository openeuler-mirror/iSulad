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

#include "libcni_version.h"
#include "libcni_types.h"
#include "libcni_current.h"

#include "isula_libutils/cni_version.h"
#include "isula_libutils/cni_inner_plugin_info.h"
#include "isula_libutils/log.h"
#include "utils.h"

/*
 * isula will never support old versions: 0.1.0 and 0.2.0;
 * but we would like to support future versions.
 * */
#define CURR_SUPPORT_VERSION_LEN 4
const char *g_curr_support_versions[CURR_SUPPORT_VERSION_LEN] = { "0.3.0", "0.3.1", curr_implemented_spec_version, NULL };

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

static void convert_from_cni_inner_plugin_info(cni_inner_plugin_info *inner, struct plugin_info **result)
{
    *result = util_common_calloc_s(sizeof(struct plugin_info));
    if (*result == NULL) {
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

struct plugin_info *plugin_supports(const char * const *supported_versions, size_t len)
{
    struct plugin_info *result = NULL;
    size_t i = 0;
    bool invalid_arg = (supported_versions == NULL || len < 1);

    if (invalid_arg) {
        ERROR("Invalid arguments");
        return NULL;
    }

    result = util_common_calloc_s(sizeof(struct plugin_info));
    if (result == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    result->cniversion = util_strdup_s(current());

    if (len > CURR_SUPPORT_VERSION_LEN) {
        ERROR("Too many versions");
        goto err_out;
    }

    result->supported_versions = util_smart_calloc_s(len + 1, sizeof(char *));
    if (result->supported_versions == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    for (i = 0; i < len; i++) {
        result->supported_versions[i] = util_strdup_s(supported_versions[i]);
        result->supported_versions_len += 1;
    }

    return result;
err_out:
    free_plugin_info(result);
    return NULL;
}

struct plugin_info *plugin_info_decode(const char *jsonstr)
{
    cni_inner_plugin_info *pinfo = NULL;
    struct plugin_info *result = NULL;
    parser_error err = NULL;

    if (jsonstr == NULL) {
        ERROR("Invalid arguments");
        goto out;
    }
    pinfo = cni_inner_plugin_info_parse_data(jsonstr, NULL, &err);
    if (pinfo == NULL) {
        ERROR("decoding version info: %s", err);
        goto out;
    }
    if (pinfo->cni_version == NULL || strlen(pinfo->cni_version) == 0) {
        goto out;
    }
    if (pinfo->supported_versions_len == 0) {
        goto out;
    }

    convert_from_cni_inner_plugin_info(pinfo, &result);
out:
    free(err);
    free_cni_inner_plugin_info(pinfo);
    return result;
}

char *cniversion_decode(const char *jsonstr)
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

struct result *new_result(const char *version, const char *jsonstr)
{
    size_t i = 0;

    for (i = 0; i < sizeof(g_factories) / sizeof(struct result_factories); i++) {
        if (check_raw(version, g_factories[i].supported_versions)) {
            return g_factories[i].new_result_op(jsonstr);
        }
    }

    ERROR("unsupported CNI result version \"%s\"", version);
    return NULL;
}

struct parse_version {
    int major;
    int minor;
    int micro;
};

static bool do_parse_version(const char **splits, size_t splits_len, struct parse_version *ret)
{
    if (util_safe_int(splits[0], &ret->major) != 0) {
        ERROR("failed to convert major version part: %s", splits[0]);
        return false;
    }

    if (splits_len >= 2 && util_safe_int(splits[1], &ret->minor) != 0) {
        ERROR("failed to convert minor version part: %s", splits[1]);
        return false;
    }

    if (splits_len >= 3 && util_safe_int(splits[2], &ret->micro) != 0) {
        ERROR("failed to convert micro version part: %s", splits[2]);
        return false;
    }

    return true;
}

static bool parse_version_from_str(const char *src_version, struct parse_version *result)
{
    char **splits = NULL;
    const size_t max_len = 4;
    size_t tlen = 0;
    bool ret = false;

    splits = util_string_split(src_version, '.');
    if (splits == NULL) {
        ERROR("Split version: \"%s\" failed", src_version);
        return false;
    }
    tlen = util_array_len((const char **)splits);
    if (tlen < 1 || tlen >= max_len) {
        ERROR("Invalid version: \"%s\"", src_version);
        goto out;
    }

    ret = do_parse_version((const char **)splits, tlen, result);

out:
    util_free_array(splits);
    return ret;
}

static bool do_compare_version(const struct parse_version *p_first, const struct parse_version *p_second)
{
    bool ret = false;

    if (p_first->major > p_second->major) {
        ret = true;
    } else if (p_first->major == p_second->major) {
        if (p_first->minor > p_second->minor) {
            ret = true;
        } else if (p_first->minor == p_second->minor && p_first->micro >= p_second->micro) {
            ret = true;
        }
    }

    return ret;
}

int version_greater_than_or_equal_to(const char *first, const char *second, bool *result)
{
    struct parse_version first_parsed = {0};
    struct parse_version second_parsed = {0};

    if (result == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (!parse_version_from_str(first, &first_parsed)) {
        return -1;
    }

    if (!parse_version_from_str(second, &second_parsed)) {
        return -1;
    }

    *result = do_compare_version(&first_parsed, &second_parsed);

    return 0;
}

