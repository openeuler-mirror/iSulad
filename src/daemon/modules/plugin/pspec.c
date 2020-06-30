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
 * Create: 2018-12-01
 * Description: provide plugin definition
 ******************************************************************************/

#include "utils.h"
#include "isula_libutils/log.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/oci_runtime_pspec.h"
#include "plugin_api.h"
#include "pspec.h"

/*
 * update field in old & clear in new.
 * field must be *ptr.
 */
#define PTR_UPDATE(old, new, field, ffree) \
    do {                                   \
        if ((new)->field == NULL) {        \
            break;                         \
        }                                  \
        ffree((old)->field);               \
        (old)->field = (new)->field;       \
        (new)->field = NULL;               \
    } while (0)

/*
 * update field in old & clear in new.
 * field must be **ptr.
 */
#define PPR_UPDATE(old, new, field, len_field, ffree)      \
    do {                                                   \
        if ((new) == NULL || (new)->field == NULL) {       \
            break;                                         \
        }                                                  \
        if ((old)->field != NULL) {                        \
            size_t ix_ = 0;                                \
            for (ix_ = 0; ix_ < (old)->len_field; ix_++) { \
                ffree((old)->field[ix_]);                  \
                (old)->field[ix_] = NULL;                  \
            }                                              \
            free((old)->field);                            \
            (old)->field = NULL;                           \
        }                                                  \
        (old)->field = (new)->field;                       \
        (new)->field = NULL;                               \
        (old)->len_field = (new)->len_field;               \
        (new)->len_field = 0;                              \
    } while (0)

static oci_runtime_pspec *raw_get_pspec(oci_runtime_spec *oci)
{
    oci_runtime_pspec *pspec = NULL;

    if (oci == NULL) {
        return NULL;
    }

    pspec = util_common_calloc_s(sizeof(oci_runtime_pspec));
    if (pspec == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    if (oci->linux->resources != NULL && pspec->resources == NULL) {
        pspec->resources = util_common_calloc_s(sizeof(defs_resources));
        if (pspec->resources == NULL) {
            ERROR("Out of memory");
            free_oci_runtime_pspec(pspec);
            return NULL;
        }
    }

    PTR_UPDATE(pspec, oci, annotations, free_json_map_string_string);
    PTR_UPDATE(pspec, oci, root, free_oci_runtime_spec_root);

    PPR_UPDATE(pspec, oci, mounts, mounts_len, free_defs_mount);
    PPR_UPDATE(pspec, oci->process, env, env_len, free);
    PPR_UPDATE(pspec, oci->linux, devices, devices_len, free_defs_device);

    PPR_UPDATE(pspec->resources, oci->linux->resources, devices, devices_len, free_defs_device_cgroup);

    return pspec;
}

static void raw_set_pspec(oci_runtime_spec *oci, oci_runtime_pspec *pspec)
{
    if (oci == NULL || pspec == NULL) {
        return;
    }
    if (pspec->resources != NULL && oci->linux->resources == NULL) {
        oci->linux->resources = util_common_calloc_s(sizeof(defs_resources));
        if (oci->linux->resources == NULL) {
            ERROR("out of memory");
            return;
        }
    }

    PTR_UPDATE(oci, pspec, annotations, free_json_map_string_string);
    PTR_UPDATE(oci, pspec, root, free_oci_runtime_spec_root);

    PPR_UPDATE(oci, pspec, mounts, mounts_len, free_defs_mount);
    PPR_UPDATE(oci->process, pspec, env, env_len, free);
    PPR_UPDATE(oci->linux, pspec, devices, devices_len, free_defs_device);

    PPR_UPDATE(oci->linux->resources, pspec->resources, devices, devices_len, free_defs_device_cgroup);
}

char *get_pspec(oci_runtime_spec *oci)
{
    oci_runtime_pspec *pspec = NULL;
    char *data = NULL;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;

    if (oci == NULL) {
        return NULL;
    }

    pspec = raw_get_pspec(oci);
    if (pspec == NULL) {
        ERROR("failed load pspec");
        return NULL;
    }

    data = oci_runtime_pspec_generate_json(pspec, &ctx, &err);
    if (data == NULL) {
        ERROR("failed gernerate json for pspec error=%s", err);
    }
    UTIL_FREE_AND_SET_NULL(err);

    if (pspec != NULL) {
        raw_set_pspec(oci, pspec); /* make sure oci not modified before
                                           return. */
        free_oci_runtime_pspec(pspec);
    }

    return data;
}

int set_pspec(oci_runtime_spec *oci, const char *data)
{
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;
    oci_runtime_pspec *pspec = NULL;

    if (data == NULL) {
        return 0;
    }

    pspec = oci_runtime_pspec_parse_data(data, &ctx, &err);
    UTIL_FREE_AND_SET_NULL(err);
    if (pspec == NULL) {
        ERROR("failed parse json for pspec");
        goto failed;
    }

    raw_set_pspec(oci, pspec);
    free_oci_runtime_pspec(pspec);
    return 0;

failed:
    return -1;
}

static void raw_update_pspec(oci_runtime_pspec *base, oci_runtime_pspec *new)
{
    if (base == NULL || new == NULL) {
        return;
    }
    if (new->resources != NULL && base->resources == NULL) {
        base->resources = util_common_calloc_s(sizeof(defs_resources));
        if (base->resources == NULL) {
            ERROR("Out of memory");
            return;
        }
    }

    PTR_UPDATE(base, new, annotations, free_json_map_string_string);
    PTR_UPDATE(base, new, root, free_oci_runtime_spec_root);

    PPR_UPDATE(base, new, mounts, mounts_len, free_defs_mount);
    PPR_UPDATE(base, new, env, env_len, free);
    PPR_UPDATE(base, new, devices, devices_len, free_defs_device);

    PPR_UPDATE(base->resources, new->resources, devices, devices_len, free_defs_device_cgroup);
}

char *merge_pspec(const char *base, const char *data)
{
    char *dst = NULL;
    oci_runtime_pspec *old = NULL;
    oci_runtime_pspec *new = NULL;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;

    if (base == NULL && data == NULL) {
        return NULL;
    }

    if (base != NULL) {
        old = oci_runtime_pspec_parse_data(base, &ctx, &err);
        UTIL_FREE_AND_SET_NULL(err);
        if (old == NULL) {
            ERROR("failed parse old json for pspec");
            return NULL;
        }
    }

    if (data != NULL) {
        new = oci_runtime_pspec_parse_data(data, &ctx, &err);
        UTIL_FREE_AND_SET_NULL(err);
        if (new == NULL) {
            ERROR("failed parse new json for pspec");
            goto revert_free_old;
        }
    }

    raw_update_pspec(old, new);
    if (old == NULL) {
        old = new;
        new = NULL;
    }

    dst = oci_runtime_pspec_generate_json(old, &ctx, &err);
    UTIL_FREE_AND_SET_NULL(err);
    if (dst == NULL) {
        ERROR("failed gernerate json for runtime_info");
    }

    free_oci_runtime_pspec(new);
revert_free_old:
    free_oci_runtime_pspec(old);

    return dst;
}
