/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2020-11-04
 * Description: provide parse volume functions
 ******************************************************************************/
#include "parse_volume.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "path.h"
#include "err_msg.h"

#define DefaultPropagationMode "rprivate"
#define DefaultROMode "rw"
#define DefaultRBind "rbind"
#define DefaultSelinuxOpt "z"

static int check_mode(char **valid_modes, size_t valid_modes_len, char *mode)
{
    size_t i = 0;

    for (i = 0; i < valid_modes_len; i++) {
        if (strcmp(valid_modes[i], mode) == 0) {
            return 0;
        }
    }

    return -1;
}

static int check_modes(const defs_mount *m, const char *volume_str, char **valid_modes, size_t valid_modes_len)
{
    size_t i = 0;

    for (i = 0; i < m->options_len; i++) {
        if (check_mode(valid_modes, valid_modes_len, m->options[i]) != 0) {
            isulad_set_error_message("Invalid volume specification '%s',Invalid mode %s for type %s", volume_str,
                                     m->options[i], m->type);
            return -1;
        }
    }

    return 0;
}

static int check_volume_opts(const char *volume_str, const defs_mount *m)
{
    char *valid_bind_modes[] = { "ro", "rw", "z", "Z", "private", "rprivate", "slave", "rslave", "shared", "rshared" };
    char *valid_volume_modes[] = { "ro", "rw", "z", "Z", "nocopy" };
    int ret = 0;

    if (strcmp(m->type, MOUNT_TYPE_BIND) == 0) {
        ret = check_modes(m, volume_str, valid_bind_modes, sizeof(valid_bind_modes) / sizeof(char *));
    }
    if (strcmp(m->type, MOUNT_TYPE_VOLUME) == 0) {
        ret = check_modes(m, volume_str, valid_volume_modes, sizeof(valid_volume_modes) / sizeof(char *));
    }

    return ret;
}

static int check_mount_dst(const defs_mount *m)
{
    if (m->destination == NULL) {
        ERROR("destination is requested");
        isulad_set_error_message("destination is requested");
        return -1;
    }

    if (m->destination[0] != '/') {
        ERROR("destination should be absolute path");
        isulad_set_error_message("destination should be absolute path");
        return -1;
    }

    return 0;
}

static int check_mount_source(const defs_mount *m)
{
    if (strcmp(m->type, MOUNT_TYPE_VOLUME) != 0 && (m->source == NULL || m->source[0] != '/')) {
        ERROR("Invalid source %s, type %s", m->source, m->type);
        isulad_set_error_message("Invalid source %s, type %s", m->source, m->type);
        return EINVALIDARGS;
    }

    if (m->source != NULL && m->source[0] != '/' && !util_valid_volume_name(m->source)) {
        ERROR("Invalid volume name %s, only \"%s\" are allowed", m->source, VALID_VOLUME_NAME);
        isulad_set_error_message("Invalid volume name %s, only \"%s\" are allowed. If you intended to pass "
                                 "a host directory, use absolute path.",
                                 m->source, VALID_VOLUME_NAME);
        return EINVALIDARGS;
    }

    return 0;
}

int append_default_tmpfs_options(defs_mount *m)
{
    if (util_array_append(&m->options, "noexec") != 0) {
        ERROR("append default tmpfs options noexec failed");
        return -1;
    }
    m->options_len++;

    if (util_array_append(&m->options, "nosuid") != 0) {
        ERROR("append default tmpfs options nosuid failed");
        return -1;
    }
    m->options_len++;

    if (util_array_append(&m->options, "nodev") != 0) {
        ERROR("append default tmpfs options nodev failed");
        return -1;
    }
    m->options_len++;

    if (util_array_append(&m->options, DefaultPropagationMode) != 0) {
        ERROR("append default tmpfs options %s failed", DefaultPropagationMode);
        return -1;
    }
    m->options_len++;

    return 0;
}

int append_default_mount_options(defs_mount *m, bool has_ro, bool has_pro, bool has_sel)
{
    int ret = 0;

    if (m == NULL) {
        ret = -1;
        goto out;
    }

    if (strcmp(m->type, MOUNT_TYPE_BIND) == 0) {
        if (!has_ro) {
            ret = util_array_append(&m->options, DefaultROMode);
            if (ret != 0) {
                ERROR("append default ro mode to array failed");
                ret = -1;
                goto out;
            }
            m->options_len++;
        }

        if (!has_pro) {
            ret = util_array_append(&m->options, DefaultPropagationMode);
            if (ret != 0) {
                ERROR("append default propagation mode to array failed");
                ret = -1;
                goto out;
            }
            m->options_len++;
        }
    }

    if (!has_sel && strcmp(m->type, MOUNT_TYPE_VOLUME) == 0) {
        ret = util_array_append(&m->options, DefaultSelinuxOpt);
        if (ret != 0) {
            ERROR("append default rbind to array failed");
            ret = -1;
            goto out;
        }
        m->options_len++;
    }

    if (strcmp(m->type, MOUNT_TYPE_BIND) == 0 || strcmp(m->type, MOUNT_TYPE_VOLUME) == 0) {
        ret = util_array_append(&m->options, DefaultRBind);
        if (ret != 0) {
            ERROR("append default rbind to array failed");
            ret = -1;
            goto out;
        }
        m->options_len++;
    }

    if (strcmp(m->type, MOUNT_TYPE_TMPFS) == 0) {
        if (append_default_tmpfs_options(m) != 0) {
            ERROR("append default tmpfs options failed");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int check_mount_element(const char *volume_str, const defs_mount *m)
{
    int ret = 0;

    if (m == NULL) {
        ret = EINVALIDARGS;
        goto out;
    }

    if (m->type == NULL) {
        ERROR("type is requested");
        ret = EINVALIDARGS;
        goto out;
    }

    if (strcmp(m->type, MOUNT_TYPE_BIND) != 0 && strcmp(m->type, MOUNT_TYPE_VOLUME) != 0) {
        ERROR("invalid type %s, only support bind/volume", m->type);
        isulad_set_error_message("invalid type %s, only support bind/volume", m->type);
        ret = EINVALIDARGS;
        goto out;
    }

    if (check_mount_source(m) != 0) {
        ret = EINVALIDARGS;
        goto out;
    }

    if (check_mount_dst(m) != 0) {
        ret = EINVALIDARGS;
        goto out;
    }

    if (check_volume_opts(volume_str, m) != 0) {
        ret = EINVALIDARGS;
        goto out;
    }

out:
    return ret;
}

static int get_src_dst_mode_by_volume(const char *volume, defs_mount *mount_element, char ***modes)
{
    int ret = 0;
    size_t alen = 0;
    char **array = NULL;

    // split volume to src:dest:mode
    array = util_string_split(volume, ':');
    if (array == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }

    alen = util_array_len((const char **)array);
    switch (alen) {
        case 1:
            // anonymous volume
            mount_element->destination = util_strdup_s(array[0]);
            goto free_out;
        case 2:
            if (util_valid_mount_mode(array[1])) {
                // Destination + Mode is not a valid volume - volumes
                // cannot include a mode. eg /foo:rw
                ERROR("Invalid volume specification '%s'", volume);
                isulad_set_error_message("Invalid volume specification '%s',Invalid mode:%s", volume, array[1]);
                ret = -1;
                break;
            }
            mount_element->source = util_strdup_s(array[0]);
            mount_element->destination = util_strdup_s(array[1]);
            break;
        case 3:
            mount_element->source = util_strdup_s(array[0]);
            mount_element->destination = util_strdup_s(array[1]);
            if (!util_valid_mount_mode(array[2])) {
                ERROR("Invalid volume specification '%s'", volume);
                isulad_set_error_message("Invalid volume specification '%s'.Invalid mode:%s", volume, array[2]);
                ret = -1;
                break;
            }
            *modes = util_string_split(array[2], ',');
            if (*modes == NULL) {
                ERROR("Out of memory");
                ret = -1;
                break;
            }

            break;
        default:
            ERROR("Invalid volume specification '%s'", volume);
            isulad_set_error_message("Invalid volume specification '%s'", volume);
            ret = -1;
            break;
    }
    if (ret != 0) {
        goto free_out;
    }

    if (mount_element->source[0] != '/' && !util_valid_volume_name(mount_element->source)) {
        ERROR("Invalid volume name %s, only \"%s\" are allowed", mount_element->source, VALID_VOLUME_NAME);
        isulad_set_error_message("Invalid volume name %s, only \"%s\" are allowed. If you intended to pass "
                                 "a host directory, use absolute path.",
                                 mount_element->source, VALID_VOLUME_NAME);
        ret = -1;
        goto free_out;
    }

    if (mount_element->destination[0] != '/' || strcmp(mount_element->destination, "/") == 0) {
        ERROR("Invalid volume: path must be absolute, and destination can't be '/'");
        isulad_set_error_message("Invalid volume: path must be absolute, and destination can't be '/'");
        ret = -1;
        goto free_out;
    }

free_out:
    util_free_array(array);
    return ret;
}

static int check_volume_element(const char *volume)
{
    int ret = 0;

    if (volume == NULL || !strcmp(volume, "")) {
        ERROR("Volume can't be empty");
        ret = -1;
        return ret;
    }

    if (volume[0] == ':' || volume[strlen(volume) - 1] == ':') {
        ERROR("Delimiter ':' can't be the first or the last character");
        ret = -1;
        return ret;
    }

    return ret;
}

defs_mount *parse_volume(const char *volume)
{
    int ret = 0;
    size_t i = 0;
    size_t mlen = 0;
    defs_mount *mount_element = NULL;
    char **modes = NULL;
    char path[PATH_MAX] = { 0x00 };
    char *rw = NULL;
    char *pro = NULL;
    char *label = NULL;
    size_t max_options_len = 4;
    char *nocopy = NULL;

    ret = check_volume_element(volume);
    if (ret != 0) {
        goto free_out;
    }

    mount_element = util_common_calloc_s(sizeof(defs_mount));
    if (mount_element == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    ret = get_src_dst_mode_by_volume(volume, mount_element, &modes);
    if (ret != 0) {
        goto free_out;
    }

    mlen = util_array_len((const char **)modes);
    for (i = 0; i < mlen; i++) {
        if (util_valid_rw_mode(modes[i])) {
            rw = modes[i];
        } else if (util_valid_propagation_mode(modes[i])) {
            pro = modes[i];
        } else if (util_valid_label_mode(modes[i])) {
            label = modes[i];
        } else if (util_valid_copy_mode(modes[i])) {
            nocopy = modes[i];
        }
    }

    if (!util_clean_path(mount_element->destination, path, sizeof(path))) {
        ERROR("Failed to get clean path");
        ret = -1;
        goto free_out;
    }
    free(mount_element->destination);
    mount_element->destination = util_strdup_s(path);

    if (mount_element->source != NULL && mount_element->source[0] == '/') {
        if (!util_clean_path(mount_element->source, path, sizeof(path))) {
            ERROR("Failed to get clean path");
            ret = -1;
            goto free_out;
        }
        free(mount_element->source);
        mount_element->source = util_strdup_s(path);
    }

    mount_element->options = util_common_calloc_s(max_options_len * sizeof(char *));
    if (mount_element->options == NULL) {
        ERROR("Out of memory");
        mount_element->options_len = 0;
        ret = -1;
        goto free_out;
    }
    if (rw != NULL) {
        mount_element->options[mount_element->options_len++] = util_strdup_s(rw);
    }
    if (pro != NULL) {
        mount_element->options[mount_element->options_len++] = util_strdup_s(pro);
    }
    if (label != NULL) {
        mount_element->options[mount_element->options_len++] = util_strdup_s(label);
    }
    if (nocopy != NULL) {
        mount_element->options[mount_element->options_len++] = util_strdup_s(nocopy);
    }
    if (mount_element->source != NULL && mount_element->source[0] == '/') {
        mount_element->type = util_strdup_s(MOUNT_TYPE_BIND);
    } else {
        mount_element->type = util_strdup_s(MOUNT_TYPE_VOLUME);
        if (mount_element->source != NULL) {
            mount_element->named = true;
        }
    }

    ret = check_mount_element(volume, mount_element);
    if (ret != 0) {
        goto free_out;
    }

    ret = append_default_mount_options(mount_element, rw != NULL, pro != NULL, label != NULL);
    if (ret != 0) {
        goto free_out;
    }

free_out:
    util_free_array(modes);
    if (ret != 0) {
        free_defs_mount(mount_element);
        mount_element = NULL;
    }
    return mount_element;
}
