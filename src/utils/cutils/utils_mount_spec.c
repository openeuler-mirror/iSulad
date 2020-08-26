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
 * Author: wangfengtu
 * Create: 2020-10-19
 * Description: provide mount spec utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_mount_spec.h"

#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <strings.h>

#include "utils.h"
#include "utils_array.h"
#include "utils_string.h"
#include "path.h"

#define CACHE_ERRMSG_LEN 512
#define CACHE_ERRMSG(errmsg, fmt, args...)              \
    do {                                         \
        (void)snprintf(errmsg, CACHE_ERRMSG_LEN, fmt "\n", ##args); \
    } while (0)

static int parse_mount_item_type(const char *value, char *mount_str, mount_spec *m, char *errmsg)
{
    if (m->type != NULL) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.More than one type found", mount_str);
        return EINVALIDARGS;
    }

    if (value == NULL || value[0] == 0) {
        m->type = util_strdup_s(DEFAULT_MOUNT_TYPE);
        return EINVALIDARGS;
    }

#ifdef ENABLE_OCI_IMAGE
    if (strcmp(value, "squashfs") && strcmp(value, "bind") && strcmp(value, "volume")) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Type must be one of squashfs/bind/volume", mount_str);
#else
    if (strcmp(value, "squashfs") && strcmp(value, "bind")) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Type must be squashfs or bind", mount_str);
#endif
        return EINVALIDARGS;
    }

    m->type = util_strdup_s(value);

    return 0;
}

static int parse_mount_item_src(const char *value, char *mount_str, mount_spec *m, char *errmsg)
{
    char srcpath[PATH_MAX] = {0};

    /* If value of source is NULL, ignore it */
    if (value == NULL) {
        return 0;
    }

    if (m->source) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.More than one source found", mount_str);
        return EINVALIDARGS;
    }

#ifndef ENABLE_OCI_IMAGE
    if (value[0] != '/') {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Source must be absolute path", mount_str);
        return EINVALIDARGS;
    }
#endif

    if (value[0] == '/') {
        if (!util_clean_path(value, srcpath, sizeof(srcpath))) {
            CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Can't translate source path to clean path", mount_str);
            return EINVALIDARGS;
        }
        m->source = util_strdup_s(srcpath);
    } else {
        m->source = util_strdup_s(value);
    }

    return 0;
}

static int parse_mount_item_dst(const char *value, char *mount_str, mount_spec *m, char *errmsg)
{
    char dstpath[PATH_MAX] = { 0 };

    /* If value of destination is NULL, ignore it */
    if (value == NULL) {
        return 0;
    }

    if (m->target) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.More than one destination found", mount_str);
        return EINVALIDARGS;
    }

    if (value[0] != '/') {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Destination must be absolute path", mount_str);
        return EINVALIDARGS;
    }

    if (!util_clean_path(value, dstpath, sizeof(dstpath))) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Can't translate destination path to clean path", mount_str);
        return EINVALIDARGS;
    }

    if (strcmp(dstpath, "/") == 0) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Destination can't be '/'", mount_str);
        return EINVALIDARGS;
    }

    m->target = util_strdup_s(dstpath);

    return 0;
}

static int parse_mount_item_ro(const char *value, char *mount_str, mount_spec *m, char *errmsg)
{
    if (value == NULL || util_valid_value_true(value)) {
        m->readonly = true;
    } else if (util_valid_value_false(value)) {
        m->readonly = false;
    } else {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Invalid readonly mode:%s", mount_str, value);
        return EINVALIDARGS;
    }
    return 0;
}

static int parse_mount_item_propagation(const char *value, char *mount_str, mount_spec *m, char *errmsg)
{
    /* If value of destination is NULL, ignore it */
    if (value == NULL) {
        return 0;
    }

    if (m->bind_options != NULL && m->bind_options->propagation != NULL) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.More than one bind-propagation found", mount_str);
        return EINVALIDARGS;
    }

    if (!util_valid_propagation_mode(value)) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Invalid propagation mode:%s", mount_str, value);
        return EINVALIDARGS;
    }

    if (m->bind_options == NULL) {
        m->bind_options = util_common_calloc_s(sizeof(bind_options));
        if (m->bind_options == NULL) {
            CACHE_ERRMSG(errmsg, "Out of memory");
            return EINVALIDARGS;
        }
    }
    m->bind_options->propagation = util_strdup_s(value);

    return 0;
}

static int parse_mount_item_selinux(const char *value, char *mount_str, mount_spec *m, char *errmsg)
{
    /* If value of destination is NULL, ignore it */
    if (value == NULL) {
        return 0;
    }

    if (m->bind_options != NULL && m->bind_options->selinux_opts != NULL) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.More than one bind-selinux-opts found", mount_str);
        return EINVALIDARGS;
    }

    if (!util_valid_label_mode(value)) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Invalid bind selinux opts:%s", mount_str, value);
        return EINVALIDARGS;
    }

    if (m->bind_options == NULL) {
        m->bind_options = util_common_calloc_s(sizeof(bind_options));
        if (m->bind_options == NULL) {
            CACHE_ERRMSG(errmsg, "Out of memory");
            return EINVALIDARGS;
        }
    }
    m->bind_options->selinux_opts = util_strdup_s(value);

    return 0;
}

#ifdef ENABLE_OCI_IMAGE
static int parse_mount_item_nocopy(const char *value, char *mount_str, mount_spec *m, char *errmsg)
{
    /* If value of destination is NULL, ignore it */
    if (value == NULL) {
        return 0;
    }

    if (m->volume_options != NULL) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.More than one volume-nocopy found", mount_str);
        return EINVALIDARGS;
    }

    if (!util_valid_value_true(value) && !util_valid_value_false(value)) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Invalid volume nocopy:%s", mount_str, value);
        return EINVALIDARGS;
    }

    if (m->volume_options == NULL) {
        m->volume_options = util_common_calloc_s(sizeof(volume_options));
        if (m->volume_options == NULL) {
            CACHE_ERRMSG(errmsg, "Out of memory");
            return EINVALIDARGS;
        }
    }

    if (util_valid_value_true(value)) {
        m->volume_options->no_copy = true;
    } else {
        m->volume_options->no_copy = false;
    }

    return 0;
}
#endif

// check mount spec valid
static int check_mount_spec(char *mount_str, mount_spec *m, char *errmsg)
{
    // check source
    if (strcmp(m->type, "volume") != 0 && m->source == NULL) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Missing source", mount_str);
        return EINVALIDARGS;
    }

    if (strcmp(m->type, "volume") != 0) {
        if (m->source == NULL || m->source[0] != '/') {
            CACHE_ERRMSG(errmsg, "source is requested for type %s", m->type);
            return -1;
        }

        if (m->source == NULL || m->source[0] != '/') {
            CACHE_ERRMSG(errmsg, "source %s should be absolute path for type %s", m->source, m->type);
            return -1;
        }
    }

    if (strcmp(m->type, "volume") == 0 && m->source != NULL && !util_valid_volume_name(m->source)) {
        CACHE_ERRMSG(errmsg, "Invalid volume name %s, only \"%s\" are allowed", m->source, VALID_VOLUME_NAME);
        return -1;
    }

    // check destination
    if (m->target == NULL) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Missing destination", mount_str);
        return EINVALIDARGS;
    }

    if (m->target[0] != '/') {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.destination should be absolute path", mount_str);
        return -1;
    }

    if (strcmp(m->type, "squashfs") == 0) {
        char real_path[PATH_MAX] = { 0 };
        if (strlen(m->source) > PATH_MAX || realpath(m->source, real_path) == NULL) {
            CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Source %s not exist", mount_str, m->source);
            return EINVALIDARGS;
        }

        /* Make sure it's a regular file */
        if (!util_valid_file(real_path, S_IFREG)) {
            CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Source %s is not a squashfs file", mount_str,
                         m->source);
            return EINVALIDARGS;
        }
    }

    return 0;
}


static int parse_mounts_item(const char *mntkey, const char *value, char *mount_str, mount_spec *m, char *errmsg)
{
    if (util_valid_key_type(mntkey)) {
        return parse_mount_item_type(value, mount_str, m, errmsg);
    } else if (util_valid_key_src(mntkey)) {
        return parse_mount_item_src(value, mount_str, m, errmsg);
    } else if (util_valid_key_dst(mntkey)) {
        return parse_mount_item_dst(value, mount_str, m, errmsg);
    } else if (util_valid_key_ro(mntkey)) {
        return parse_mount_item_ro(value, mount_str, m, errmsg);
    } else if (util_valid_key_propagation(mntkey)) {
        return parse_mount_item_propagation(value, mount_str, m, errmsg);
    } else if (util_valid_key_selinux(mntkey)) {
        return parse_mount_item_selinux(value, mount_str, m, errmsg);
#ifdef ENABLE_OCI_IMAGE
    } else if (util_valid_key_nocopy(mntkey)) {
        return parse_mount_item_nocopy(value, mount_str, m, errmsg);
#endif
    } else {
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Unsupported item:%s", mount_str, mntkey);
        return EINVALIDARGS;
    }
}

int util_parse_mount_spec(char *mount_str, mount_spec **spec, char **errmsg_out)
{
    mount_spec *m = NULL;
    int ret = 0;
    size_t i = 0;
    size_t items_len = 0;
    char **items = NULL;
    char **key_val = NULL;
    char errmsg[CACHE_ERRMSG_LEN] = {0};

    if (mount_str == NULL) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification: can't be empty");
        ret = -1;
        goto out;
    }
    if (!mount_str[0]) {
        CACHE_ERRMSG(errmsg, "Invalid mount specification: can't be empty");
        ret = -1;
        goto out;
    }

    m = util_common_calloc_s(sizeof(mount_spec));
    if (m == NULL) {
        CACHE_ERRMSG(errmsg, "out of memory");
        ret = -1;
        goto out;
    }

    items = util_string_split(mount_str, ',');
    if (items == NULL) {
        ret = EINVALIDARGS;
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'. unsupported format", mount_str);
        goto out;
    }

    items_len = util_array_len((const char **)items);

    for (i = 0; i < items_len; i++) {
        key_val = util_string_split(items[i], '=');
        if (key_val == NULL) {
            continue;
        }
        ret = parse_mounts_item(key_val[0], key_val[1], mount_str, m, errmsg);
        if (ret != 0) {
            goto out;
        }
        util_free_array(key_val);
        key_val = NULL;
    }

    if (m->type == NULL) {
#ifdef ENABLE_OCI_IMAGE
        m->type = util_strdup_s(DEFAULT_MOUNT_TYPE);
#else
        CACHE_ERRMSG(errmsg, "Invalid mount specification '%s'.Missing type", mount_str);
        ret = EINVALIDARGS;
        goto out;
#endif
    }

    if (check_mount_spec(mount_str, m, errmsg) != 0) {
        ret = EINVALIDARGS;
        goto out;
    }

    *spec = m;
    m = NULL;

out:
    if (ret != 0 && strlen(errmsg) != 0 && errmsg_out != NULL) {
        *errmsg_out = util_strdup_s(errmsg);
    }
    free_mount_spec(m);
    util_free_array(key_val);
    util_free_array(items);
    return ret;
}

bool util_valid_mount_spec(const char *mount_str, char **errmsg)
{
    int ret = 0;
    mount_spec *m = NULL;

    // if parse success, it's valid
    ret = util_parse_mount_spec((char*)mount_str, &m, errmsg);
    if (ret != 0) {
        goto out;
    }

out:
    free_mount_spec(m);

    return ret ? false : true;
}

