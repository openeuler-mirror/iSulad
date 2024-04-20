/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuxu
 * Create: 2024-03-06
 * Description: provide cdi version function
 ******************************************************************************/
#include "cdi_version.h"

#include <ctype.h>
#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "error.h"
#include "utils_version.h"
#include "utils_string.h"
#include "cdi_container_edits.h"
#include "cdi_parser.h"

#define CDI_V010        "0.1.0"
#define CDI_V020        "0.2.0"
#define CDI_V030        "0.3.0"
#define CDI_V040        "0.4.0"
#define CDI_V050        "0.5.0"
#define CDI_V060        "0.6.0"
#define CDI_V_EARLIEST  CDI_V030

typedef bool (*required_version_cb)(cdi_spec *spec);

struct required_version_map {
    char *version;
    required_version_cb cb;
};

static bool requires_v060(cdi_spec *spec)
{
    size_t i;
    int ret = 0;
    __isula_auto_free char *vendor = NULL;
    __isula_auto_free char *class = NULL;

    // The 0.6.0 spec allows annotations to be specified at a spec level
    if (spec->annotations != NULL) {
        return true;
    }

    // The 0.6.0 spec allows annotations to be specified at a device level
    if (spec->devices != NULL) {
        for (i = 0; i < spec->devices_len; i++) {
            if (spec->devices[i]->annotations != NULL) {
                return true;
            }
        }
    }

    // The 0.6.0 spec allows dots "." in Kind name label (class)
    ret = cdi_parser_parse_qualifier(spec->kind, &vendor, &class);
    if (ret == 0 && vendor != NULL) {
        if (util_strings_count(class, '.') > 0) {
            return true;
        }
    }
    return false;
}

static bool check_host_path(cdi_container_edits *e)
{
    size_t i;

    if (e == NULL) {
        return false;
    }
    for (i = 0; i < e->device_nodes_len; i++) {
        // The HostPath field was added in 0.5.0
        if (e->device_nodes[i]->host_path != NULL) {
            return true;
        }
    }
    return false;
}

static bool requires_v050(cdi_spec *spec)
{
    size_t i;

    for (i = 0; i < spec->devices_len; i++) {
        // The 0.5.0 spec allowed device names to start with a digit instead of requiring a letter
        if (spec->devices[i]->name != NULL && strlen(spec->devices[i]->name) > 0 &&
            !isalpha(spec->devices[i]->name[0])) {
            return true;
        }
        if (check_host_path(spec->devices[i]->container_edits)) {
            return true;
        }
    }

    return check_host_path(spec->container_edits);
}

static bool check_mount_type(cdi_container_edits *e)
{
    size_t i;

    if (e == NULL) {
        return false;
    }
    for (i = 0; i < e->mounts_len; i++) {
        // The Type field was added in 0.4.0
        if (e->mounts[i]->type != NULL) {
            return true;
        }
    }
    return false;
}

static bool requires_v040(cdi_spec *spec)
{
    size_t i;

    for (i = 0; i < spec->devices_len; i++) {
        if (check_mount_type(spec->devices[i]->container_edits)) {
            return true;
        }
    }

    return check_mount_type(spec->container_edits);
}

#define VALID_SPEC_VERSIONS_LEN 6
static struct required_version_map g_valid_spec_versions[VALID_SPEC_VERSIONS_LEN] = {
    {CDI_V010, NULL},
    {CDI_V020, NULL},
    {CDI_V030, NULL},
    {CDI_V040, requires_v040},
    {CDI_V050, requires_v050},
    {CDI_V060, requires_v060}
};

const char *cdi_minimum_required_version(cdi_spec *spec)
{
    const char *min_version = CDI_V_EARLIEST;
    int i;
    bool result = true;

    if (spec == NULL) {
        return NULL;
    }

    for (i = 0; i < VALID_SPEC_VERSIONS_LEN; i++) {
        if (g_valid_spec_versions[i].cb == NULL) {
            continue;
        }
        if (g_valid_spec_versions[i].cb(spec)) {
            if (util_version_greater_than(g_valid_spec_versions[i].version, min_version, &result) != 0) {
                ERROR("Failed to compare version %s and %s", g_valid_spec_versions[i].version, min_version);
                return NULL;
            }
            if (result) {
                min_version = g_valid_spec_versions[i].version;
            }
        }
        if (strcmp(min_version, CDI_CURRENT_VERSION) == 0) {
            break;
        }
    }

    return min_version;
}

bool cdi_is_valid_version(const char *spec_version)
{
    int i;
    
    for (i = 0; i < VALID_SPEC_VERSIONS_LEN; i++) {
        if (strcmp(g_valid_spec_versions[i].version, spec_version) == 0) {
            return true;
        }
    }
    return false;
}
