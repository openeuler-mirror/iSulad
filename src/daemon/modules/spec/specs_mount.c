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
 * Description: provide container specs functions
 ******************************************************************************/
#include "specs_mount.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <isula_libutils/container_config_v2.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_runtime_config_linux.h>
#include <limits.h>
#include <stdint.h>

#include "isula_libutils/log.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_inspect.h"
#include "utils.h"
#include "path.h"
#include "isulad_config.h"
#include "namespace.h"
#include "specs_extend.h"
#include "container_api.h"
#ifdef ENABLE_SELINUX
#include "selinux_label.h"
#endif
#include "err_msg.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_verify.h"
#include "image_api.h"
#include "volume_api.h"
#include "parse_volume.h"

enum update_rw {
    update_rw_untouch,
    update_rw_readonly,
    update_rw_readwrite,
};

static int get_devices(const char *dir, char ***devices, size_t *device_len, int recursive_depth);

static int append_additional_mounts(oci_runtime_spec *oci_spec, const char *type)
{
    int ret = 0;
    size_t i = 0;
    size_t j = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    defs_mount **spec_mounts = NULL;
    defs_mount *tmp_mount = NULL;
    char **files = NULL;
    size_t files_len = 0;
    char *mount_options[] = { "nosuid", "noexec", "nodev" };
    size_t mount_options_len = 0;
    char *net_files[] = { "/proc/sys/net" };
    char *ipc_files[] = { "/proc/sys/kernel/shmmax",          "/proc/sys/kernel/shmmni", "/proc/sys/kernel/shmall",
                          "/proc/sys/kernel/shm_rmid_forced", "/proc/sys/kernel/msgmax", "/proc/sys/kernel/msgmni",
                          "/proc/sys/kernel/msgmnb",          "/proc/sys/kernel/sem",    "/proc/sys/fs/mqueue"
                        };

    if (strcmp(type, "net") == 0) {
        files = &net_files[0];
        files_len = sizeof(net_files) / sizeof(net_files[0]);
    } else if (strcmp(type, "ipc") == 0) {
        files = &ipc_files[0];
        files_len = sizeof(ipc_files) / sizeof(ipc_files[0]);
    } else {
        return -1;
    }

    if (files_len > (SIZE_MAX / sizeof(defs_mount *)) - oci_spec->mounts_len) {
        ERROR("Too many mounts to append!");
        ret = -1;
        goto out;
    }

    mount_options_len = sizeof(mount_options) / sizeof(mount_options[0]);
    new_size = (oci_spec->mounts_len + files_len) * sizeof(defs_mount *);
    old_size = oci_spec->mounts_len * sizeof(defs_mount *);

    ret = util_mem_realloc((void **)&spec_mounts, new_size, oci_spec->mounts, old_size);
    if (ret != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    oci_spec->mounts = spec_mounts;
    for (i = 0; i < files_len; i++) {
        tmp_mount = util_common_calloc_s(sizeof(defs_mount));
        if (tmp_mount == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        tmp_mount->source = util_strdup_s(files[i]);
        tmp_mount->destination = util_strdup_s(files[i]);
        tmp_mount->type = util_strdup_s("proc");
        for (j = 0; j < mount_options_len; j++) {
            ret = util_array_append(&(tmp_mount->options), mount_options[j]);
            if (ret != 0) {
                ERROR("append mount options to array failed");
                ret = -1;
                goto out;
            }
            tmp_mount->options_len++;
        }

        spec_mounts[oci_spec->mounts_len++] = tmp_mount;
        tmp_mount = NULL;
    }

out:
    free_defs_mount(tmp_mount);
    return ret;
}

int adapt_settings_for_mounts(oci_runtime_spec *oci_spec, container_config *container_spec)
{
    size_t i, array_str_len;
    int ret = 0;
    char **array_str = NULL;

    if (container_spec == NULL) {
        return -1;
    }

    array_str = util_string_split(container_spec->ns_change_opt, ',');
    if (array_str == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    array_str_len = util_array_len((const char **)array_str);

    for (i = 0; i < array_str_len; i++) {
        if (strcmp(array_str[i], "net") == 0) {
            ret = append_additional_mounts(oci_spec, "net");
        } else {
            ret = append_additional_mounts(oci_spec, "ipc");
        }
        if (ret != 0) {
            goto out;
        }
    }

out:
    util_free_array(array_str);
    return ret;
}

static bool valid_dirent_info(const char *dir, const struct dirent *info_archivo)
{
    size_t i = 0;
    int nret = 0;
    char *pdot = NULL;
    char fullpath[PATH_MAX] = { 0 };
    char *skip_files[] = { "/dev/pts", "/dev/shm", "/dev/fd", "/dev/mqueue", "/dev/console" };

    if (dir == NULL || info_archivo == NULL) {
        return false;
    }

    // skip . ..
    if (strncmp(info_archivo->d_name, ".", PATH_MAX) == 0 || strncmp(info_archivo->d_name, "..", PATH_MAX) == 0) {
        return false;
    }

    // do not map device which name contains ":"
    pdot = strstr(info_archivo->d_name, ":");
    if (pdot != NULL) {
        INFO("Skipping device %s include \":\"", info_archivo->d_name);
        return false;
    }

    nret = snprintf(fullpath, PATH_MAX, "%s/%s", dir, info_archivo->d_name);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("get_devices: Failed to combine device path");
        return false;
    }

    for (i = 0; i < sizeof(skip_files) / sizeof(skip_files[0]); i++) {
        if (strncmp(fullpath, skip_files[i], PATH_MAX) == 0) {
            INFO("Skipping device: %s", fullpath);
            return false;
        }
    }

    return true;
}

static int pack_devices(const char *fullpath, char ***devices, size_t *device_len)
{
    int ret = 0;
    size_t tmp_length;
    size_t new_size = 0;
    size_t old_size = 0;
    char **tmp_device = NULL;

    tmp_length = *device_len;
    if (tmp_length > (SIZE_MAX / sizeof(char *)) - 1) {
        ERROR("Too many devices");
        ret = -1;
        goto out;
    }

    old_size = sizeof(char *) * tmp_length;
    tmp_length += 1;
    new_size = sizeof(char *) * tmp_length;

    ret = util_mem_realloc((void **)&tmp_device, new_size, *devices, old_size);
    if (ret != 0) {
        ERROR("get_devices: Failed to realloc memory");
        ret = -1;
        goto out;
    }

    tmp_device[tmp_length - 1] = util_strdup_s(fullpath);
    *devices = tmp_device;
    *device_len = tmp_length;

out:
    return ret;
}

static int get_devices_in_path(const char *fullpath, int recursive_depth, char ***devices, size_t *device_len)
{
    int ret = 0;
    struct stat fileStat;

    if (lstat(fullpath, &fileStat) != 0) {
        ERROR("Failed to get(%s) file stat.", fullpath);
        ret = 0;
        goto out;
    }

    // scan device recursively
    if (S_ISDIR(fileStat.st_mode)) {
        ret = get_devices(fullpath, devices, device_len, (recursive_depth + 1));
        if (ret != 0) {
            INFO("get_devices: Failed in path: %s", fullpath);
            ret = -1;
            goto out;
        }
    } else if (S_ISCHR(fileStat.st_mode) || S_ISBLK(fileStat.st_mode)) {
        if (pack_devices(fullpath, devices, device_len) != 0) {
            ret = -1;
            goto out;
        }
    } else {
        INFO("Skip device %s, mode(%o) not support to merge.", fullpath, fileStat.st_mode & S_IFMT);
    }

out:
    return ret;
}

/* get_devices: retrieve all devices under dir
 * when errors occurs, caller should free memory pointing to *devices
 */
static int get_devices(const char *dir, char ***devices, size_t *device_len, int recursive_depth)
{
    int nret = 0;
    char *fullpath = NULL;
    DIR *midir = NULL;
    struct dirent *info_archivo = NULL;

    if ((recursive_depth + 1) > MAX_PATH_DEPTH) {
        ERROR("Reach the max dev path depth:%s", dir);
        return -1;
    }
    midir = opendir(dir);
    if (midir == NULL) {
        ERROR("get_devices: Error in opendir");
        return -1;
    }
    info_archivo = readdir(midir);
    for (; info_archivo != NULL; info_archivo = readdir(midir)) {
        if (!valid_dirent_info(dir, info_archivo)) {
            continue;
        }

        fullpath = util_common_calloc_s(PATH_MAX);
        if (fullpath == NULL) {
            ERROR("Memory out");
            closedir(midir);
            return -1;
        }
        nret = snprintf(fullpath, PATH_MAX, "%s/%s", dir, info_archivo->d_name);
        if (nret < 0 || nret >= PATH_MAX) {
            ERROR("get_devices: Failed to combine device path");
            closedir(midir);
            free(fullpath);
            return -1;
        }

        if (get_devices_in_path(fullpath, recursive_depth, devices, device_len) != 0) {
            closedir(midir);
            free(fullpath);
            return -1;
        }

        free(fullpath);
        fullpath = NULL;
    }

    closedir(midir);
    return 0;
}

int split_volume_from(char *volume_from, char **id, char **mode)
{
    char **parts = NULL;
    size_t size = 0;
    int ret = 0;

    parts = util_string_split(volume_from, ':');
    size = util_array_len((const char **)parts);
    if (size == 0 || size > 2) {
        ret = -1;
        goto out;
    }

    *id = util_strdup_s(parts[0]);
    if (size == 2) {
        *mode = util_strdup_s(parts[1]);
    }

out:
    util_free_array(parts);

    return ret;
}

static defs_mount *mount_point_to_defs_mnt(container_config_v2_common_config_mount_points_element *mp,
                                           enum update_rw update_rw_mode)
{
    defs_mount *mnt = NULL;
    char **parts = NULL;
    size_t options_len = 0;
    int ret = 0;
    size_t i = 0;
    bool has_ro = false;
    bool has_pro = false;
    bool has_sel = false;

    parts = util_string_split(mp->relabel, ',');
    options_len = util_array_len((const char **)parts);

    mnt = util_common_calloc_s(sizeof(defs_mount));
    if (mnt == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    mnt->options =
        util_common_calloc_s(sizeof(char *) * (options_len + 3)); // +2 for readonly/propagation/selinux_relabel
    if (mnt->options == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    mnt->type = util_strdup_s(mp->type);
    if (strcmp(mnt->type, MOUNT_TYPE_VOLUME) == 0) {
        mnt->source = util_strdup_s(mp->name);
        mnt->named = mp->named;
    } else {
        mnt->source = util_strdup_s(mp->source);
    }
    mnt->destination = util_strdup_s(mp->destination);
    if (update_rw_mode == update_rw_readonly || (update_rw_mode == update_rw_untouch && !mp->rw)) {
        has_ro = true;
    }
    if (mp->propagation != NULL) {
        mnt->options[mnt->options_len++] = util_strdup_s(mp->propagation);
        has_pro = true;
    }

    for (i = 0; i < options_len; i++) {
        if (strcmp(parts[i], "ro") == 0 || strcmp(parts[i], "rw") == 0) {
            continue;
        }
        mnt->options[mnt->options_len++] = util_strdup_s(parts[i]);
        if (util_valid_label_mode(parts[i])) {
            has_sel = true;
        }
    }

    if (has_ro) {
        mnt->options[mnt->options_len++] = util_strdup_s("ro");
    }

    ret = append_default_mount_options(mnt, has_ro, has_pro, has_sel);
    if (ret != 0) {
        goto out;
    }

out:
    util_free_array(parts);
    if (ret != 0) {
        free_defs_mount(mnt);
        mnt = NULL;
    }

    return mnt;
}

void free_defs_mounts(defs_mount **mnts, size_t mnts_len)
{
    size_t i = 0;

    for (i = 0; i < mnts_len; i++) {
        free_defs_mount(mnts[i]);
        mnts[i] = NULL;
    }
    free(mnts);

    return;
}

static int mount_points_to_defs_mnts(container_config_v2_common_config_mount_points *mount_points,
                                     enum update_rw update_rw_mode, defs_mount ***mnts_out, size_t *mnts_len_out)
{
    defs_mount **mnts = NULL;
    size_t mnts_len = 0;
    int ret = 0;
    size_t i = 0;

    mnts = util_common_calloc_s(sizeof(defs_mount *) * mount_points->len);
    if (mnts == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < mount_points->len; i++) {
        if (strcmp(mount_points->values[i]->type, MOUNT_TYPE_VOLUME) != 0 &&
            strcmp(mount_points->values[i]->type, MOUNT_TYPE_BIND) != 0) {
            continue;
        }

        mnts[mnts_len] = mount_point_to_defs_mnt(mount_points->values[i], update_rw_mode);
        if (mnts[i] == NULL) {
            ret = -1;
            goto out;
        }
        mnts_len++;
    }

    *mnts_out = mnts;
    *mnts_len_out = mnts_len;
out:
    if (ret != 0) {
        free_defs_mounts(mnts, mnts_len);
    }

    return ret;
}

static int parser_volume_from_mode(char *mode, enum update_rw *rw)
{
    char **parts = NULL;
    int ret = 0;
    size_t i = 0;
    *rw = update_rw_untouch; // default to use the same readonly mode

    if (mode == NULL) {
        return 0;
    }

    if (!util_valid_mount_mode(mode)) {
        ERROR("invalid mode %s found", mode);
        return -1;
    }

    parts = util_string_split(mode, ',');
    if (parts == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < util_array_len((const char **)parts); i++) {
        if (util_valid_propagation_mode(parts[i]) || util_valid_copy_mode(parts[i])) {
            ret = -1;
            goto out;
        }

        if (util_valid_rw_mode(parts[i])) {
            if (strcmp(mode, "rw") == 0) {
                *rw = update_rw_readwrite;
            } else if (strcmp(mode, "ro") == 0) {
                *rw = update_rw_readonly;
            }
        }
    }

out:
    util_free_array(parts);

    return ret;
}

static int parse_volumes_from(char *volume_from, defs_mount ***mnts_out, size_t *mnts_len_out)
{
    char *id = NULL;
    char *mode = NULL;
    container_t *cont = NULL;
    defs_mount **mnts = NULL;
    size_t mnts_len = 0;
    int ret = 0;
    enum update_rw update_rw_mode = update_rw_untouch;

    ret = split_volume_from(volume_from, &id, &mode);
    if (ret != 0) {
        ERROR("failed to split volume-from: %s", volume_from);
        isulad_set_error_message("failed to split volume-from: %s", volume_from);
        return -1;
    }

    ret = parser_volume_from_mode(mode, &update_rw_mode);
    if (ret != 0) {
        ERROR("failed to parser mode %s, volume-from %s", mode, volume_from);
        isulad_set_error_message("failed to parser mode %s, volume-from %s", mode, volume_from);
        goto out;
    }

    cont = containers_store_get(id);
    if (cont == NULL) {
        ERROR("container %s not found when parse volumes-from:%s", id, volume_from);
        isulad_set_error_message("container %s not found when parse volumes-from:%s", id, volume_from);
        ret = -1;
        goto out;
    }

    // no mount point
    if (cont->common_config == NULL || cont->common_config->mount_points == NULL) {
        goto out;
    }

    ret = mount_points_to_defs_mnts(cont->common_config->mount_points, update_rw_mode, &mnts, &mnts_len);
    if (ret != 0) {
        goto out;
    }

    *mnts_out = mnts;
    *mnts_len_out = mnts_len;

out:
    container_unref(cont);
    free(id);
    free(mode);
    if (ret != 0) {
        free_defs_mounts(mnts, mnts_len);
    }

    return ret;
}

static int append_tmpfs_option_size(defs_mount *m, size_t size)
{
    int nret = 0;
    char kvbuf[MOUNT_PROPERTIES_SIZE] = {0};

    if (size == 0) {
        return 0;
    }

    nret = snprintf(kvbuf, sizeof(kvbuf), "size=%zu", size);
    if (nret < 0 || (size_t)nret >= sizeof(kvbuf)) {
        ERROR("Failed to snprintf tmpfs size");
        return -1;
    }

    if (util_array_append(&m->options, kvbuf) != 0) {
        ERROR("append tmpfs option size failed");
        return -1;
    }
    m->options_len++;

    return 0;
}

static int append_tmpfs_option_mode(defs_mount *m, uint32_t mode)
{
    int nret = 0;
    char kvbuf[MOUNT_PROPERTIES_SIZE] = {0};

    if (mode == 0) {
        return 0;
    }

    nret = snprintf(kvbuf, sizeof(kvbuf), "mode=%o", mode);
    if (nret < 0 || (size_t)nret >= sizeof(kvbuf)) {
        ERROR("Failed to snprintf tmpfs mode");
        return -1;
    }

    if (util_array_append(&m->options, kvbuf) != 0) {
        ERROR("append tmpfs option mode failed");
        return -1;
    }
    m->options_len++;

    return 0;
}

static defs_mount *parse_mount(mount_spec *spec)
{
    int ret = 0;
    defs_mount *m = NULL;
    bool has_pro = false;
    bool has_sel = false;

    m = util_common_calloc_s(sizeof(defs_mount));
    if (m == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    m->type = util_strdup_s(spec->type);
    if (strcmp(m->type, MOUNT_TYPE_TMPFS) == 0) {
        m->source = util_strdup_s("tmpfs");
    } else {
        m->source = util_strdup_s(spec->source);
    }
    m->destination = util_strdup_s(spec->target);
    if (strcmp(m->type, MOUNT_TYPE_VOLUME) == 0 && m->source != NULL) {
        m->named = true;
    }

    if (spec->readonly) {
        if (util_array_append(&m->options, "ro")) {
            ERROR("append ro mode to array failed");
            ret = -1;
            goto out;
        }
        m->options_len++;
    }

    if (spec->bind_options != NULL) {
        if (spec->bind_options->propagation != NULL) {
            if (util_array_append(&m->options, spec->bind_options->propagation)) {
                ERROR("append propagation to array failed");
                ret = -1;
                goto out;
            }
            m->options_len++;
            has_pro = true;
        }
        if (spec->bind_options->selinux_opts != NULL) {
            if (util_array_append(&m->options, spec->bind_options->selinux_opts)) {
                ERROR("append selinux opts to array failed");
                ret = -1;
                goto out;
            }
            m->options_len++;
            has_sel = true;
        }
    }

    if (spec->volume_options != NULL && spec->volume_options->no_copy) {
        if (util_array_append(&m->options, "nocopy")) {
            ERROR("append nocopy to array failed");
            ret = -1;
            goto out;
        }
        m->options_len++;
    }

    if (strcmp(m->type, MOUNT_TYPE_TMPFS) == 0 && spec->tmpfs_options != NULL) {
        if (append_tmpfs_option_size(m, (size_t) spec->tmpfs_options->size_bytes) != 0) {
            ERROR("append tmpfs option size failed");
            ret = -1;
            goto out;
        }

        if (append_tmpfs_option_mode(m, spec->tmpfs_options->mode) != 0) {
            ERROR("append tmpfs option mode failed");
            ret = -1;
            goto out;
        }
    }

    ret = append_default_mount_options(m, true, has_pro, has_sel);
    if (ret != 0) {
        goto out;
    }

out:
    if (ret != 0) {
        free_defs_mount(m);
        m = NULL;
    }

    return m;
}

static defs_mount *parse_anonymous_volume(char *volume)
{
    int ret = 0;
    char path[PATH_MAX] = { 0 };
    defs_mount *mount_element = NULL;

    if (!util_clean_path(volume, path, sizeof(path))) {
        ERROR("Failed to get clean path %s", volume);
        return NULL;
    }

    if (volume == NULL || path[0] != '/' || strcmp(path, "/") == 0) {
        ERROR("invalid anonymous volume %s", volume);
        isulad_set_error_message("invalid anonymous volume %s", volume);
        return NULL;
    }

    mount_element = util_common_calloc_s(sizeof(defs_mount));
    if (mount_element == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    mount_element->type = util_strdup_s(MOUNT_TYPE_VOLUME);
    mount_element->source = NULL;
    mount_element->destination = util_strdup_s(path);
    mount_element->named = false;
    ret = append_default_mount_options(mount_element, false, false, false);
    if (ret != 0) {
        goto out;
    }

out:
    if (ret != 0) {
        free_defs_mount(mount_element);
        mount_element = NULL;
    }
    return mount_element;
}

static host_config_devices_element *parse_one_device(const char *device_path, const char *dir_host,
                                                     const char *dir_container, const char *permissions)
{
    int nret = 0;
    const char *cgroup_permissions = NULL;
    host_config_devices_element *device_map = NULL;
    char tmp_container_path[PATH_MAX] = { 0 };

    if (device_path == NULL || !strcmp(device_path, "")) {
        ERROR("devices can't be empty");
        return NULL;
    }

    cgroup_permissions = permissions ? permissions : "rwm";

    device_map = util_common_calloc_s(sizeof(host_config_devices_element));
    if (device_map == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    device_map->path_on_host = util_strdup_s(device_path);
    if (dir_container != NULL) {
        nret = snprintf(tmp_container_path, sizeof(tmp_container_path), "%s/%s", dir_container,
                        device_path + strlen(dir_host));
        if (nret < 0 || (size_t)nret >= sizeof(tmp_container_path)) {
            ERROR("Failed to sprintf device path in container %s/%s", dir_container, device_path + strlen(dir_host));
            goto erro_out;
        }
        device_map->path_in_container = util_strdup_s(tmp_container_path);
    } else {
        device_map->path_in_container = util_strdup_s(device_path);
    }

    device_map->cgroup_permissions = util_strdup_s(cgroup_permissions);

    if (device_map->path_on_host == NULL || device_map->path_in_container == NULL ||
        device_map->cgroup_permissions == NULL) {
        goto erro_out;
    } else {
        return device_map;
    }

erro_out:
    free_host_config_devices_element(device_map);
    return NULL;
}

static int get_devices_from_path(const host_config_devices_element *dev_map, defs_device *spec_dev,
                                 defs_device_cgroup *spec_dev_cgroup)
{
    int ret = 0;
    struct stat st;
    char *dev_type = NULL;
    unsigned int file_mode = 0;

    if (dev_map == NULL || spec_dev == NULL || spec_dev_cgroup == NULL) {
        return -1;
    }

    ret = stat(dev_map->path_on_host, &st);
    if (ret < 0) {
        ERROR("device %s no exists", dev_map->path_on_host);
        isulad_set_error_message("Error gathering device information while adding device \"%s\",stat %s: "
                                 "no such file or directory",
                                 dev_map->path_on_host, dev_map->path_on_host);
        return -1;
    }

    file_mode = st.st_mode & 0777;

    /* check device type first */
    if (S_ISBLK(st.st_mode)) {
        file_mode |= S_IFBLK;
        dev_type = "b";
    } else if (S_ISCHR(st.st_mode)) {
        file_mode |= S_IFCHR;
        dev_type = "c";
    } else {
        ERROR("Cannot determine the device number for device %s", dev_map->path_on_host);
        return -1;
    }

    /* fill spec dev */
    spec_dev->major = (int64_t)major(st.st_rdev);
    spec_dev->minor = (int64_t)minor(st.st_rdev);
    spec_dev->uid = st.st_uid;
    spec_dev->gid = st.st_gid;
    spec_dev->file_mode = (int)file_mode;
    spec_dev->type = util_strdup_s(dev_type);
    spec_dev->path = util_strdup_s(dev_map->path_in_container);

    /* fill spec cgroup dev */
    spec_dev_cgroup->allow = true;
    spec_dev_cgroup->access = util_strdup_s(dev_map->cgroup_permissions);
    spec_dev_cgroup->type = util_strdup_s(dev_type);
    spec_dev_cgroup->major = (int64_t)major(st.st_rdev);
    spec_dev_cgroup->minor = (int64_t)minor(st.st_rdev);

    return 0;
}

static int merge_custom_device(defs_device **out_spec_dev, defs_device_cgroup **out_spec_dev_cgroup,
                               const host_config_devices_element *dev_map)
{
    int ret = 0;
    defs_device *spec_dev = NULL;
    defs_device_cgroup *spec_dev_cgroup = NULL;

    spec_dev = util_common_calloc_s(sizeof(defs_device));
    if (spec_dev == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto erro_out;
    }

    spec_dev_cgroup = util_common_calloc_s(sizeof(defs_device_cgroup));
    if (spec_dev_cgroup == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto erro_out;
    }

    ret = get_devices_from_path(dev_map, spec_dev, spec_dev_cgroup);
    if (ret != 0) {
        ERROR("Failed to get devices info");
        ret = -1;
        goto erro_out;
    }

    *out_spec_dev = spec_dev;
    *out_spec_dev_cgroup = spec_dev_cgroup;
    goto out;

erro_out:
    free_defs_device(spec_dev);
    free_defs_device_cgroup(spec_dev_cgroup);
out:
    return ret;
}

static int get_weight_devices_from_path(const defs_blkio_weight_device *weight_dev,
                                        defs_block_io_device_weight *spec_weight_dev)
{
    int ret = 0;
    struct stat st;

    if (weight_dev == NULL || spec_weight_dev == NULL) {
        return -1;
    }

    ret = stat(weight_dev->path, &st);
    if (ret < 0) {
        ERROR("Failed to get state of device:%s", weight_dev->path);
        return -1;
    }

    /* fill spec weight dev */
    spec_weight_dev->major = (int64_t)major(st.st_rdev);
    spec_weight_dev->minor = (int64_t)minor(st.st_rdev);
    spec_weight_dev->weight = weight_dev->weight;
    /* Notes You MUST specify at least one of weight or leafWeight
     * in a given entry, and MAY specify both
     * docker did not specify the leaf weight
     */
    spec_weight_dev->leaf_weight = 0;

    return 0;
}

static int merge_host_config_blk_weight_device(defs_block_io_device_weight **out_spec_weight_dev,
                                               const defs_blkio_weight_device *weight_dev)
{
    int ret = 0;
    defs_block_io_device_weight *spec_weight_dev = NULL;

    spec_weight_dev = util_common_calloc_s(sizeof(defs_block_io_device_weight));
    if (spec_weight_dev == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto erro_out;
    }

    ret = get_weight_devices_from_path(weight_dev, spec_weight_dev);
    if (ret != 0) {
        ERROR("Failed to get weight devices info");
        ret = -1;
        goto erro_out;
    }

    *out_spec_weight_dev = spec_weight_dev;
    goto out;

erro_out:
    free_defs_block_io_device_weight(spec_weight_dev);

out:
    return ret;
}

static int get_blkio_device_throttle_info(const defs_blkio_device *blkio_dev_info,
                                          defs_block_io_device_throttle *blkio_dev_throttle)
{
    int ret = 0;
    struct stat st;

    if (blkio_dev_info == NULL || blkio_dev_throttle == NULL) {
        return -1;
    }

    ret = stat(blkio_dev_info->path, &st);
    if (ret < 0) {
        ERROR("no such file or directory :%s", blkio_dev_info->path);
        isulad_set_error_message("no such file or directory: %s", blkio_dev_info->path);
        return -1;
    }

    /* fill spec throttle write bps dev */
    blkio_dev_throttle->rate = blkio_dev_info->rate;
    blkio_dev_throttle->major = (int64_t)major(st.st_rdev);
    blkio_dev_throttle->minor = (int64_t)minor(st.st_rdev);

    return 0;
}

static int merge_host_config_blk_device(defs_block_io_device_throttle **blkio_dev_throttle,
                                        const defs_blkio_device *blkio_dev)
{
    int ret = 0;
    defs_block_io_device_throttle *tmp_throttle = NULL;

    tmp_throttle = util_common_calloc_s(sizeof(defs_block_io_device_throttle));
    if (tmp_throttle == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto erro_out;
    }

    ret = get_blkio_device_throttle_info(blkio_dev, tmp_throttle);
    if (ret != 0) {
        ERROR("Failed to get throttle read bps devices info");
        ret = -1;
        goto erro_out;
    }

    *blkio_dev_throttle = tmp_throttle;
    goto out;

erro_out:
    free_defs_block_io_device_throttle(tmp_throttle);

out:
    return ret;
}

static int merge_all_devices(oci_runtime_spec *oci_spec, host_config_devices_element **dev_maps, size_t devices_len,
                             const char *permissions)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    defs_device **spec_dev = NULL;

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        goto out;
    }

    /* malloc for linux->device */
    if (devices_len > LIST_DEVICE_SIZE_MAX - oci_spec->linux->devices_len) {
        ERROR("Too many linux devices to merge, the limit is %lld", LIST_DEVICE_SIZE_MAX);
        isulad_set_error_message("Too many linux devices to merge, the limit is %d", LIST_DEVICE_SIZE_MAX);
        ret = -1;
        goto out;
    }
    new_size = (oci_spec->linux->devices_len + devices_len) * sizeof(defs_device *);
    old_size = oci_spec->linux->devices_len * sizeof(defs_device *);
    ret = util_mem_realloc((void **)&spec_dev, new_size, oci_spec->linux->devices, old_size);
    if (ret != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    oci_spec->linux->devices = spec_dev;

    /* malloc for cgroup->device */
    defs_device_cgroup **spec_cgroup_dev = NULL;
    if (devices_len > SIZE_MAX / sizeof(defs_device_cgroup *) - oci_spec->linux->resources->devices_len) {
        ERROR("Too many cgroup devices to merge!");
        ret = -1;
        goto out;
    }
    new_size = (oci_spec->linux->resources->devices_len + devices_len) * sizeof(defs_device_cgroup *);
    old_size = oci_spec->linux->resources->devices_len * sizeof(defs_device_cgroup *);
    ret = util_mem_realloc((void **)&spec_cgroup_dev, new_size, oci_spec->linux->resources->devices, old_size);
    if (ret != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    oci_spec->linux->resources->devices = spec_cgroup_dev;

    for (i = 0; i < devices_len; i++) {
        ret = merge_custom_device(&oci_spec->linux->devices[oci_spec->linux->devices_len],
                                  &oci_spec->linux->resources->devices[oci_spec->linux->resources->devices_len],
                                  dev_maps[i]);
        if (ret != 0) {
            ERROR("Failed to merge custom device");
            ret = -1;
            goto out;
        }
        oci_spec->linux->devices_len++;
        oci_spec->linux->resources->devices_len++;
    }
out:
    return ret;
}

static void free_multi_dev_maps(host_config_devices_element **dev_maps, size_t devices_len)
{
    size_t i = 0;

    if (dev_maps == NULL) {
        return;
    }

    for (i = 0; i < devices_len; i++) {
        free_host_config_devices_element(dev_maps[i]);
        dev_maps[i] = NULL;
    }
    free(dev_maps);
}

static host_config_devices_element **parse_multi_devices(const char *dir_host, const char *dir_container,
                                                         const char *permissions, char **devices, size_t devices_len)
{
    size_t i = 0;
    host_config_devices_element **dev_maps = NULL;

    if (devices_len == 0) {
        return NULL;
    }

    if (devices_len > SIZE_MAX / sizeof(host_config_devices_element *)) {
        ERROR("Too many devices");
        return NULL;
    }

    dev_maps = util_common_calloc_s(devices_len * sizeof(host_config_devices_element *));
    if (dev_maps == NULL) {
        ERROR("Memory out");
        return NULL;
    }

    for (i = 0; i < devices_len; i++) {
        dev_maps[i] = parse_one_device(devices[i], dir_host, dir_container, permissions);
        if (dev_maps[i] == NULL) {
            ERROR("Failed to parse device %s", devices[i]);
            goto on_error;
        }
    }

    return dev_maps;

on_error:
    free_multi_dev_maps(dev_maps, devices_len);
    return NULL;
}

static int merge_all_devices_in_dir(const char *dir, const char *dir_container, const char *permissions,
                                    oci_runtime_spec *oci_spec)
{
    int ret = 0;
    size_t i = 0;
    char **devices = NULL;
    size_t devices_len = 0;
    host_config_devices_element **dev_maps = NULL;

    ret = get_devices(dir, &devices, &devices_len, 0);
    if (ret != 0) {
        ERROR("Failed to get host's device in directory:%s", dir);
        isulad_set_error_message("Failed to get host's device in directory:%s", dir);
        ret = -1;
        goto out;
    }
    if (devices_len == 0) {
        ERROR("Error gathering device information while adding devices in directory \"%s\":no available device nodes",
              dir);
        isulad_set_error_message("Error gathering device information while adding devices in directory"
                                 " \"%s\":,no available device nodes",
                                 dir);
        ret = -1;
        goto out;
    }
    /* devices which will be populated into container */
    if (devices != NULL) {
        dev_maps = parse_multi_devices(dir, dir_container, permissions, devices, devices_len);
        if (dev_maps == NULL) {
            ERROR("Failed to parse multi devices");
            ret = -1;
            goto out;
        }

        ret = merge_all_devices(oci_spec, dev_maps, devices_len, permissions);
        if (ret != 0) {
            ERROR("Failed to merge devices");
            ret = -1;
            goto out;
        }
    }
out:
    if (devices != NULL) {
        for (i = 0; i < devices_len; i++) {
            free(devices[i]);
        }
        free(devices);
    }

    free_multi_dev_maps(dev_maps, devices_len);
    return ret;
}

int merge_all_devices_and_all_permission(oci_runtime_spec *oci_spec)
{
    int ret = 0;
    size_t i = 0;
    defs_resources *ptr = NULL;
    defs_device_cgroup *spec_dev_cgroup = NULL;

    ret = merge_all_devices_in_dir("/dev", NULL, NULL, oci_spec);
    if (ret != 0) {
        ERROR("Failed to merge all devices in /dev");
        ret = -1;
        goto out;
    }

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        goto out;
    }

    ptr = oci_spec->linux->resources;
    if (ptr->devices != NULL) {
        for (i = 0; i < ptr->devices_len; i++) {
            free_defs_device_cgroup(ptr->devices[i]);
            ptr->devices[i] = NULL;
        }
        free(ptr->devices);
        ptr->devices = NULL;
        ptr->devices_len = 0;
    }

    ptr->devices = util_common_calloc_s(sizeof(defs_device_cgroup *));
    if (ptr->devices == NULL) {
        ret = -1;
        goto out;
    }

    ptr->devices_len = 1;

    spec_dev_cgroup = util_common_calloc_s(sizeof(defs_device_cgroup));
    if (spec_dev_cgroup == NULL) {
        ret = -1;
        goto out;
    }

    spec_dev_cgroup->allow = true;
    spec_dev_cgroup->access = util_strdup_s("rwm");
    spec_dev_cgroup->type = util_strdup_s("a");
    spec_dev_cgroup->major = -1;
    spec_dev_cgroup->minor = -1;

    ptr->devices[0] = spec_dev_cgroup;

out:
    return ret;
}

static inline bool is_sys_proc_mount_destination(const char *destination)
{
    return strcmp("/sys", destination) == 0 || strcmp("/proc", destination) == 0 ||
           strcmp("/sys/fs/cgroup", destination) == 0;
}

static inline bool is_ro_mount_option(const char *option)
{
    return strncmp(option, "ro", strlen("ro")) == 0;
}

int set_mounts_readwrite_option(const oci_runtime_spec *oci_spec)
{
    size_t i = 0;
    size_t j = 0;

    if (oci_spec == NULL) {
        return -1;
    }

    if (oci_spec->mounts == NULL || oci_spec->mounts_len == 0) {
        return 0;
    }

    /* make sure /sys and proc and sys/fs/cgroup writeable */

    for (i = 0; i < oci_spec->mounts_len; i++) {
        if (!oci_spec->mounts[i]->destination) {
            continue;
        }
        if (!is_sys_proc_mount_destination(oci_spec->mounts[i]->destination)) {
            continue;
        }
        if (!oci_spec->mounts[i]->options || !oci_spec->mounts[i]->options_len) {
            continue;
        }
        // default mount permission is rw, so do nothing if "ro" not found
        for (j = 0; j < oci_spec->mounts[i]->options_len; j++) {
            // change mount permission to rw
            if (is_ro_mount_option(oci_spec->mounts[i]->options[j])) {
                oci_spec->mounts[i]->options[j][1] = 'w';
                break;
            }
        }
    }

    return 0;
}

static container_config_v2_common_config_mount_points_element *defs_mnt_to_mount_point(const defs_mount *mnt)
{
    container_config_v2_common_config_mount_points_element *mp = NULL;
    size_t i;
    char *mode = NULL;

    mp = util_common_calloc_s(sizeof(container_config_v2_common_config_mount_points_element));
    if (mp == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    mp->type = util_strdup_s(mnt->type);
    mp->source = util_strdup_s(mnt->source);
    mp->destination = util_strdup_s(mnt->destination);
    mp->rw = true;
    for (i = 0; i < mnt->options_len; i++) {
        if (strcmp(mnt->options[i], "ro") == 0) {
            mp->rw = false;
        }
        if (util_valid_propagation_mode(mnt->options[i])) {
            free(mp->propagation);
            mp->propagation = util_strdup_s(mnt->options[i]);
            continue;
        }
        if (strstr(mnt->options[i], MOUNT_TYPE_BIND) != NULL) {
            continue;
        }
        if (mode == NULL) {
            mode = util_strdup_s(mnt->options[i]);
        } else {
            int pret;
            size_t len = strlen(mode) + strlen(mnt->options[i]) + 2;
            char *new_mode = util_common_calloc_s(len);
            if (new_mode == NULL) {
                ERROR("Out of memory");
                goto cleanup;
            }
            pret = snprintf(new_mode, len, "%s,%s", mode, mnt->options[i]);
            if (pret < 0 || (size_t)pret >= len) {
                ERROR("Sprintf failed");
                free(new_mode);
                goto cleanup;
            }
            free(mode);
            mode = new_mode;
        }
    }
    mp->relabel = mode;
    return mp;
cleanup:
    free(mode);
    free_container_config_v2_common_config_mount_points_element(mp);
    return NULL;
}

static char *container_path_in_host(char *base_fs, char *container_path)
{
    return util_path_join(base_fs, container_path + 1); // +1 means strip prefix "/"
}

static bool have_nocopy(defs_mount *mnt)
{
    size_t i = 0;
    for (i = 0; i < mnt->options_len; i++) {
        if (strcmp(mnt->options[i], "nocopy") == 0) {
            return true;
        }
    }
    return false;
}

static int copy_data_to_volume(char *base_fs, defs_mount *mnt)
{
    int ret = 0;
    char *copy_src = NULL;
    char *copy_dst = NULL;
    struct stat st;
    char **entries = NULL;
    size_t entry_num = 0;

    if (base_fs == NULL || mnt == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    // copy data from container volume mount point to host volume directory
    copy_src = container_path_in_host(base_fs, mnt->destination);
    copy_dst = mnt->source;

    if (stat(copy_src, &st) != 0) {
        if (errno == ENOENT) {
            goto out;
        }
        ERROR("stat for copy data to volume failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }
    if (!S_ISDIR(st.st_mode)) {
        ERROR("mount point %s in container is not direcotry", mnt->destination);
        ret = -1;
        goto out;
    }

    ret = util_list_all_entries(copy_dst, &entries);
    if (ret != 0) {
        ERROR("list entries of %s failed", copy_src);
        goto out;
    }
    entry_num = util_array_len((const char **)entries);
    if (entry_num != 0) {
        // ignore copy nonempty directory
        goto out;
    }

    ret = util_copy_dir_recursive(copy_dst, copy_src);

out:
    util_free_array(entries);
    free(copy_src);

    return ret;
}

#ifdef ENABLE_SELINUX
static int relabel_volume(struct volume *vol, defs_mount *mnt, char *mount_label)
{
    int ret = 0;
    bool need_relabel = false;
    bool is_shared = false;
    size_t i = 0;

    if (vol == NULL || mnt == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    for (i = 0; i < mnt->options_len; i++) {
        if (strcmp(mnt->options[i], "Z") == 0) {
            need_relabel = true;
            is_shared = false;
        } else if (strcmp(mnt->options[i], "z") == 0) {
            need_relabel = true;
            is_shared = true;
        }
    }

    ret = volume_mount(vol->name);
    if (ret != 0) {
        goto out;
    }

    if (need_relabel && relabel(vol->mount_point, mount_label, is_shared) != 0) {
        ERROR("Error setting label on mount source '%s'", mnt->source);
        ret = -1;
        goto out;
    }

out:
    (void)volume_umount(vol->name);

    return ret;
}
#endif

static int merge_fs_mounts_to_oci_spec(oci_runtime_spec *oci_spec, defs_mount **mounts, size_t mounts_len)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    defs_mount **mounts_temp = NULL;

    if (mounts_len == 0) {
        return 0;
    }

    if (oci_spec == NULL) {
        ret = -1;
        goto out;
    }
    if (mounts_len > LIST_SIZE_MAX - oci_spec->mounts_len) {
        ERROR("Too many mounts to merge, the limit is %lld", LIST_SIZE_MAX);
        isulad_set_error_message("Too many mounts to merge, the limit is %d", LIST_SIZE_MAX);
        ret = -1;
        goto out;
    }
    new_size = (oci_spec->mounts_len + mounts_len) * sizeof(defs_mount *);
    old_size = oci_spec->mounts_len * sizeof(defs_mount *);
    ret = util_mem_realloc((void **)&mounts_temp, new_size, oci_spec->mounts, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory mounts");
        ret = -1;
        goto out;
    }
    oci_spec->mounts = mounts_temp;

    for (i = 0; i < mounts_len; i++) {
        defs_mount *mnt = mounts[i];
        oci_spec->mounts[oci_spec->mounts_len] = mnt;
        oci_spec->mounts_len++;
        mounts[i] = NULL;
    }

out:
    return ret;
}

static int merge_fs_mounts_to_v2_spec(defs_mount **mounts, size_t mounts_len,
                                      container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    size_t new_mp_key_size, new_mp_val_size, old_mp_key_size, old_mp_val_size;
    size_t i = 0;
    char **mp_key = NULL;
    container_config_v2_common_config_mount_points_element **mp_val = NULL;
    struct volume *vol = NULL;

    if (mounts_len == 0) {
        return 0;
    }

    if (v2_spec != NULL) {
        if (v2_spec->mount_points == NULL) {
            v2_spec->mount_points = util_common_calloc_s(sizeof(container_config_v2_common_config_mount_points));
            if (v2_spec->mount_points == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
        }
        new_mp_key_size = (v2_spec->mount_points->len + mounts_len) * sizeof(char *);
        old_mp_key_size = v2_spec->mount_points->len * sizeof(char *);
        new_mp_val_size = (v2_spec->mount_points->len + mounts_len) *
                          sizeof(container_config_v2_common_config_mount_points_element *);
        old_mp_val_size = v2_spec->mount_points->len * sizeof(container_config_v2_common_config_mount_points_element *);

        ret = util_mem_realloc((void **)&mp_key, new_mp_key_size, v2_spec->mount_points->keys, old_mp_key_size);
        if (ret != 0) {
            ERROR("Failed to realloc memory mount point");
            ret = -1;
            goto out;
        }
        v2_spec->mount_points->keys = mp_key;
        ret = util_mem_realloc((void **)&mp_val, new_mp_val_size, v2_spec->mount_points->values, old_mp_val_size);
        if (ret != 0) {
            ERROR("Failed to realloc memory mount point");
            ret = -1;
            goto out;
        }
        v2_spec->mount_points->values = mp_val;
    }

    for (i = 0; i < mounts_len; i++) {
        defs_mount *mnt = mounts[i];
        if (strcmp(mnt->type, MOUNT_TYPE_VOLUME) == 0) {
            struct volume_options opts = { .ref = v2_spec->id };
            // support local volume only currently.
            vol = volume_create(VOLUME_DEFAULT_DRIVER_NAME, mnt->source, &opts);
            if (vol == NULL) {
                ERROR("Failed to create volume");
                ret = -1;
                goto out;
            }
            free(mnt->source);
            mnt->source = util_strdup_s(vol->path);

#ifdef ENABLE_SELINUX
            if (v2_spec->mount_label != NULL) {
                ret = relabel_volume(vol, mnt, v2_spec->mount_label);
                if (ret != 0) {
                    ERROR("Failed to relabel volume");
                    ret = -1;
                    goto out;
                }
            }
#endif
        }

        if (v2_spec != NULL) {
            v2_spec->mount_points->values[v2_spec->mount_points->len] = defs_mnt_to_mount_point(mnt);
            if (v2_spec->mount_points->values[v2_spec->mount_points->len] == NULL) {
                ERROR("Failed to transform to mount point");
                ret = -1;
                goto out;
            }
            if (vol != NULL) {
                v2_spec->mount_points->values[v2_spec->mount_points->len]->name = util_strdup_s(vol->name);
                v2_spec->mount_points->values[v2_spec->mount_points->len]->driver = util_strdup_s(vol->driver);
            }
            v2_spec->mount_points->values[v2_spec->mount_points->len]->named = mnt->named;
            v2_spec->mount_points->keys[v2_spec->mount_points->len] = util_strdup_s(mnt->destination);
            v2_spec->mount_points->len++;
        }

        if (vol != NULL && !have_nocopy(mnt)) {
            /* if mount point have data and it's mounted from volume,
             * we need to copy data from destination mount point to volume */
            ret = copy_data_to_volume(v2_spec->base_fs, mnt);
            if (ret != 0) {
                ERROR("Failed to copy data to volume");
                goto out;
            }
        }

        // mount -t have no type volume, trans volume to bind
        if (strcmp(mnt->type, MOUNT_TYPE_VOLUME) == 0) {
            free(mnt->type);
            mnt->type = util_strdup_s(MOUNT_TYPE_BIND);
        }
        free_volume(vol);
        vol = NULL;
    }

out:
    free_volume(vol);

    return ret;
}

static int merge_custom_one_device(oci_runtime_spec *oci_spec, const host_config_devices_element *device)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        goto out;
    }

    /* malloc for linux->device */
    defs_device **spec_dev = NULL;
    if (oci_spec->linux->devices_len > SIZE_MAX / sizeof(defs_device *) - 1) {
        ERROR("Too many linux devices to merge!");
        ret = -1;
        goto out;
    }
    new_size = (oci_spec->linux->devices_len + 1) * sizeof(defs_device *);
    old_size = new_size - sizeof(defs_device *);
    ret = util_mem_realloc((void **)&spec_dev, new_size, oci_spec->linux->devices, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for devices");
        ret = -1;
        goto out;
    }

    oci_spec->linux->devices = spec_dev;

    /* malloc for cgroup->device */
    defs_device_cgroup **spec_cgroup_dev = NULL;
    if (oci_spec->linux->resources->devices_len > SIZE_MAX / sizeof(defs_device_cgroup *) - 1) {
        ERROR("Too many cgroup devices to merge!");
        ret = -1;
        goto out;
    }
    new_size = (oci_spec->linux->resources->devices_len + 1) * sizeof(defs_device_cgroup *);
    old_size = new_size - sizeof(defs_device_cgroup *);
    ret = util_mem_realloc((void **)&spec_cgroup_dev, new_size, oci_spec->linux->resources->devices, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for cgroup devices");
        ret = -1;
        goto out;
    }
    oci_spec->linux->resources->devices = spec_cgroup_dev;

    ret = merge_custom_device(&oci_spec->linux->devices[oci_spec->linux->devices_len],
                              &oci_spec->linux->resources->devices[oci_spec->linux->resources->devices_len], device);
    if (ret != 0) {
        ERROR("Failed to merge custom device");
        ret = -1;
        goto out;
    }
    oci_spec->linux->devices_len++;
    oci_spec->linux->resources->devices_len++;

out:
    return ret;
}

static int merge_custom_devices(oci_runtime_spec *oci_spec, host_config_devices_element **devices, size_t devices_len)
{
    int ret = 0;
    size_t i = 0;
    char *path_on_host = NULL;
    char *cgroup_permissions = NULL;
    char *dir_in_container = NULL;
    host_config_devices_element *device = NULL;

    if (oci_spec == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < devices_len; i++) {
        device = devices[i];
        path_on_host = device->path_on_host;
        cgroup_permissions = device->cgroup_permissions;
        dir_in_container = device->path_in_container;

        if (util_dir_exists(path_on_host)) {
            ret = merge_all_devices_in_dir(path_on_host, dir_in_container, cgroup_permissions, oci_spec);
            if (ret != 0) {
                ERROR("Failed to merge all devices in directory:%s", path_on_host);
                ret = -1;
                goto out;
            }
        } else {
            ret = merge_custom_one_device(oci_spec, device);
            if (ret != 0) {
                ERROR("Failed to merge device %s", path_on_host);
                ret = -1;
                goto out;
            }
        }
    }

out:
    return ret;
}

static int merge_blkio_weight_device(oci_runtime_spec *oci_spec, defs_blkio_weight_device **blkio_weight_device,
                                     size_t blkio_weight_device_len)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    defs_block_io_device_weight **weight_device = NULL;

    ret = make_sure_oci_spec_linux_resources_blkio(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (oci_spec->linux->resources->block_io->weight_device_len > LIST_DEVICE_SIZE_MAX - blkio_weight_device_len) {
        ERROR("Too many weight devices to merge, the limit is %lld", LIST_DEVICE_SIZE_MAX);
        isulad_set_error_message("Too many weight devices to merge, the limit is %d", LIST_DEVICE_SIZE_MAX);
        ret = -1;
        goto out;
    }

    new_size = (oci_spec->linux->resources->block_io->weight_device_len + blkio_weight_device_len) *
               sizeof(defs_block_io_device_weight *);
    old_size = oci_spec->linux->resources->block_io->weight_device_len * sizeof(defs_block_io_device_weight *);
    ret = util_mem_realloc((void **)&weight_device, new_size, oci_spec->linux->resources->block_io->weight_device,
                           old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for weight devices");
        ret = -1;
        goto out;
    }
    oci_spec->linux->resources->block_io->weight_device = weight_device;

    for (i = 0; i < blkio_weight_device_len; i++) {
        ret = merge_host_config_blk_weight_device(
                  &oci_spec->linux->resources->block_io
                  ->weight_device[oci_spec->linux->resources->block_io->weight_device_len],
                  blkio_weight_device[i]);
        if (ret != 0) {
            ERROR("Failed to merge blkio weight device");
            ret = -1;
            goto out;
        }
        oci_spec->linux->resources->block_io->weight_device_len++;
    }

out:
    return ret;
}

static int merge_blkio_read_bps_device(oci_runtime_spec *oci_spec, defs_blkio_device **blkio_read_bps_device,
                                       size_t throttle_read_bps_device_len)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    defs_block_io_device_throttle **throttle_read_bps_device = NULL;

    ret = make_sure_oci_spec_linux_resources_blkio(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (oci_spec->linux->resources->block_io->throttle_read_bps_device_len >
        LIST_DEVICE_SIZE_MAX - throttle_read_bps_device_len) {
        ERROR("Too many throttle read bps devices to merge, the limit is %lld", LIST_DEVICE_SIZE_MAX);
        isulad_set_error_message("Too many throttle read bps devices devices to merge, the limit is %d",
                                 LIST_DEVICE_SIZE_MAX);
        ret = -1;
        goto out;
    }

    new_size = (oci_spec->linux->resources->block_io->throttle_read_bps_device_len + throttle_read_bps_device_len) *
               sizeof(defs_block_io_device_throttle *);
    old_size = oci_spec->linux->resources->block_io->throttle_read_bps_device_len *
               sizeof(defs_block_io_device_throttle *);
    ret = util_mem_realloc((void **)&throttle_read_bps_device, new_size,
                           oci_spec->linux->resources->block_io->throttle_read_bps_device, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for blkio throttle read bps devices");
        ret = -1;
        goto out;
    }
    oci_spec->linux->resources->block_io->throttle_read_bps_device = throttle_read_bps_device;

    for (i = 0; i < throttle_read_bps_device_len; i++) {
        ret = merge_host_config_blk_device(
                  &oci_spec->linux->resources->block_io
                  ->throttle_read_bps_device[oci_spec->linux->resources->block_io->throttle_read_bps_device_len],
                  blkio_read_bps_device[i]);
        if (ret != 0) {
            ERROR("Failed to merge blkio throttle read bps device");
            ret = -1;
            goto out;
        }
        oci_spec->linux->resources->block_io->throttle_read_bps_device_len++;
    }

out:
    return ret;
}

static int merge_blkio_write_bps_device(oci_runtime_spec *oci_spec, defs_blkio_device **blkio_write_bps_device,
                                        size_t throttle_write_bps_device_len)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    defs_block_io_device_throttle **throttle_write_bps_device = NULL;

    ret = make_sure_oci_spec_linux_resources_blkio(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (oci_spec->linux->resources->block_io->throttle_write_bps_device_len >
        LIST_DEVICE_SIZE_MAX - throttle_write_bps_device_len) {
        ERROR("Too many throttle write bps devices to merge, the limit is %lld", LIST_DEVICE_SIZE_MAX);
        isulad_set_error_message("Too many throttle write bps devices devices to merge, the limit is %d",
                                 LIST_DEVICE_SIZE_MAX);
        ret = -1;
        goto out;
    }

    new_size = (oci_spec->linux->resources->block_io->throttle_write_bps_device_len + throttle_write_bps_device_len) *
               sizeof(defs_block_io_device_throttle *);
    old_size = oci_spec->linux->resources->block_io->throttle_write_bps_device_len *
               sizeof(defs_block_io_device_throttle *);
    ret = util_mem_realloc((void **)&throttle_write_bps_device, new_size,
                           oci_spec->linux->resources->block_io->throttle_write_bps_device, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for throttle write bps devices");
        ret = -1;
        goto out;
    }
    oci_spec->linux->resources->block_io->throttle_write_bps_device = throttle_write_bps_device;

    for (i = 0; i < throttle_write_bps_device_len; i++) {
        ret = merge_host_config_blk_device(
                  &oci_spec->linux->resources->block_io
                  ->throttle_write_bps_device[oci_spec->linux->resources->block_io->throttle_write_bps_device_len],
                  blkio_write_bps_device[i]);
        if (ret != 0) {
            ERROR("Failed to merge blkio throttle write bps device");
            ret = -1;
            goto out;
        }
        oci_spec->linux->resources->block_io->throttle_write_bps_device_len++;
    }

out:
    return ret;
}

static int merge_blkio_read_iops_device(oci_runtime_spec *oci_spec, defs_blkio_device **blkio_read_iops_device,
                                        size_t throttle_read_iops_device_len)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    defs_block_io_device_throttle **throttle_read_iops_device = NULL;

    ret = make_sure_oci_spec_linux_resources_blkio(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (oci_spec->linux->resources->block_io->throttle_read_iops_device_len >
        LIST_DEVICE_SIZE_MAX - throttle_read_iops_device_len) {
        ERROR("Too many throttle read iops devices to merge, the limit is %lld", LIST_DEVICE_SIZE_MAX);
        isulad_set_error_message("Too many throttle read iops devices devices to merge, the limit is %d",
                                 LIST_DEVICE_SIZE_MAX);
        ret = -1;
        goto out;
    }

    new_size = (oci_spec->linux->resources->block_io->throttle_read_iops_device_len + throttle_read_iops_device_len) *
               sizeof(defs_block_io_device_throttle *);
    old_size = oci_spec->linux->resources->block_io->throttle_read_iops_device_len *
               sizeof(defs_block_io_device_throttle *);
    ret = util_mem_realloc((void **)&throttle_read_iops_device, new_size,
                           oci_spec->linux->resources->block_io->throttle_read_iops_device, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for blkio throttle read iops devices");
        ret = -1;
        goto out;
    }
    oci_spec->linux->resources->block_io->throttle_read_iops_device = throttle_read_iops_device;

    for (i = 0; i < throttle_read_iops_device_len; i++) {
        ret = merge_host_config_blk_device(
                  &oci_spec->linux->resources->block_io
                  ->throttle_read_iops_device[oci_spec->linux->resources->block_io->throttle_read_iops_device_len],
                  blkio_read_iops_device[i]);
        if (ret != 0) {
            ERROR("Failed to merge blkio throttle read iops device");
            ret = -1;
            goto out;
        }
        oci_spec->linux->resources->block_io->throttle_read_iops_device_len++;
    }

out:
    return ret;
}

static int merge_blkio_write_iops_device(oci_runtime_spec *oci_spec, defs_blkio_device **blkio_write_iops_device,
                                         size_t throttle_write_iops_device_len)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    defs_block_io_device_throttle **throttle_write_iops_device = NULL;

    ret = make_sure_oci_spec_linux_resources_blkio(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (oci_spec->linux->resources->block_io->throttle_write_iops_device_len >
        LIST_DEVICE_SIZE_MAX - throttle_write_iops_device_len) {
        ERROR("Too many throttle write iops devices to merge, the limit is %lld", LIST_DEVICE_SIZE_MAX);
        isulad_set_error_message("Too many throttle write iops devices devices to merge, the limit is %d",
                                 LIST_DEVICE_SIZE_MAX);
        ret = -1;
        goto out;
    }

    new_size = (oci_spec->linux->resources->block_io->throttle_write_iops_device_len + throttle_write_iops_device_len) *
               sizeof(defs_block_io_device_throttle *);
    old_size = oci_spec->linux->resources->block_io->throttle_write_iops_device_len *
               sizeof(defs_block_io_device_throttle *);
    ret = util_mem_realloc((void **)&throttle_write_iops_device, new_size,
                           oci_spec->linux->resources->block_io->throttle_write_iops_device, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for throttle write iops devices");
        ret = -1;
        goto out;
    }
    oci_spec->linux->resources->block_io->throttle_write_iops_device = throttle_write_iops_device;

    for (i = 0; i < throttle_write_iops_device_len; i++) {
        ret = merge_host_config_blk_device(
                  &oci_spec->linux->resources->block_io->throttle_write_iops_device
                  [oci_spec->linux->resources->block_io->throttle_write_iops_device_len],
                  blkio_write_iops_device[i]);
        if (ret != 0) {
            ERROR("Failed to merge blkio throttle write iops device");
            ret = -1;
            goto out;
        }
        oci_spec->linux->resources->block_io->throttle_write_iops_device_len++;
    }

out:
    return ret;
}

static int merge_conf_populate_device(oci_runtime_spec *oci_spec, host_config *host_spec)
{
    int ret = 0;

    if (host_spec->privileged) {
        INFO("Skipped \"--device\" due to conflict with \"--privileged\"");
        return 0;
    }

    if (host_spec->devices != NULL && host_spec->devices_len != 0) {
        /* privileged containers will populate all devices in host */
        ret = merge_custom_devices(oci_spec, host_spec->devices, host_spec->devices_len);
        if (ret != 0) {
            ERROR("Failed to merge custom devices");
            goto out;
        }
    }
out:
    return ret;
}

/* format example: b 7:* rmw */
static int parse_device_cgroup_rule(defs_device_cgroup *spec_dev_cgroup, const char *rule)
{
    int ret = 0;
    char **parts = NULL;
    size_t parts_len = 0;
    char **file_mode = NULL;
    size_t file_mode_len = 0;

    if (rule == NULL || spec_dev_cgroup == NULL) {
        return -1;
    }

    parts = util_string_split(rule, ' ');
    if (parts == NULL) {
        ERROR("Failed to split rule %s", rule);
        ret = -1;
        goto free_out;
    }

    parts_len = util_array_len((const char **)parts);
    if (parts_len != 3) {
        ERROR("Invalid rule %s", rule);
        ret = -1;
        goto free_out;
    }

    /* fill spec cgroup dev */
    spec_dev_cgroup->allow = true;
    spec_dev_cgroup->access = util_strdup_s(parts[2]);
    spec_dev_cgroup->type = util_strdup_s(parts[0]);

    file_mode = util_string_split(parts[1], ':');
    if (file_mode == NULL) {
        ERROR("Invalid rule mode %s", parts[1]);
        ret = -1;
        goto free_out;
    }

    file_mode_len = util_array_len((const char **)file_mode);
    if (file_mode_len != 2) {
        ERROR("Invalid rule mode %s", parts[1]);
        ret = -1;
        goto free_out;
    }

    if (strcmp(file_mode[0], "*") == 0) {
        spec_dev_cgroup->major = -1;
    } else {
        if (util_safe_llong(file_mode[0], (long long *)&spec_dev_cgroup->major) != 0) {
            ERROR("Invalid rule mode %s", file_mode[0]);
            ret = -1;
            goto free_out;
        }
    }

    if (strcmp(file_mode[1], "*") == 0) {
        spec_dev_cgroup->minor = -1;
    } else {
        if (util_safe_llong(file_mode[1], (long long *)&spec_dev_cgroup->minor) != 0) {
            ERROR("Invalid rule mode %s", file_mode[1]);
            ret = -1;
            goto free_out;
        }
    }

free_out:
    util_free_array(parts);
    util_free_array(file_mode);

    return ret;
}

static int make_device_cgroup_rule(defs_device_cgroup **out_spec_dev_cgroup, const char *dev_cgroup_rule)
{
    int ret = 0;
    defs_device_cgroup *spec_dev_cgroup = NULL;

    spec_dev_cgroup = util_common_calloc_s(sizeof(defs_device_cgroup));
    if (spec_dev_cgroup == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto erro_out;
    }

    ret = parse_device_cgroup_rule(spec_dev_cgroup, dev_cgroup_rule);
    if (ret != 0) {
        ERROR("Failed to parse device cgroup rule %s", dev_cgroup_rule);
        ret = -1;
        goto erro_out;
    }

    *out_spec_dev_cgroup = spec_dev_cgroup;
    goto out;

erro_out:
    free_defs_device_cgroup(spec_dev_cgroup);
out:
    return ret;
}

static int do_merge_device_cgroup_rules(oci_runtime_spec *oci_spec, const char **dev_cgroup_rules,
                                        size_t dev_cgroup_rules_len)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        goto out;
    }

    /* malloc for cgroup->device */
    defs_device_cgroup **spec_cgroup_dev = NULL;
    if (dev_cgroup_rules_len > SIZE_MAX / sizeof(defs_device_cgroup *) - oci_spec->linux->resources->devices_len) {
        ERROR("Too many cgroup devices to merge!");
        ret = -1;
        goto out;
    }
    new_size = (oci_spec->linux->resources->devices_len + dev_cgroup_rules_len) * sizeof(defs_device_cgroup *);
    old_size = oci_spec->linux->resources->devices_len * sizeof(defs_device_cgroup *);
    ret = util_mem_realloc((void **)&spec_cgroup_dev, new_size, oci_spec->linux->resources->devices, old_size);
    if (ret != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    oci_spec->linux->resources->devices = spec_cgroup_dev;

    for (i = 0; i < dev_cgroup_rules_len; i++) {
        ret = make_device_cgroup_rule(&oci_spec->linux->resources->devices[oci_spec->linux->resources->devices_len],
                                      dev_cgroup_rules[i]);
        if (ret != 0) {
            ERROR("Failed to merge custom device");
            ret = -1;
            goto out;
        }
        oci_spec->linux->resources->devices_len++;
    }
out:
    return ret;
}

static int merge_conf_device_cgroup_rule(oci_runtime_spec *oci_spec, host_config *host_spec)
{
    int ret = 0;

    if (host_spec->privileged) {
        INFO("Skipped \"--device-cgroup-rule\" due to conflict with \"--privileged\"");
        return 0;
    }

    if (host_spec->device_cgroup_rules == NULL || host_spec->device_cgroup_rules_len == 0) {
        return 0;
    }

    ret = do_merge_device_cgroup_rules(oci_spec, (const char **)host_spec->device_cgroup_rules,
                                       host_spec->device_cgroup_rules_len);
    if (ret != 0) {
        ERROR("Failed to merge custom devices cgroup rules");
        goto out;
    }
out:
    return ret;
}

int merge_conf_device(oci_runtime_spec *oci_spec, host_config *host_spec)
{
    int ret = 0;

    /* blkio weight devices */
    if (host_spec->blkio_weight_device != NULL && host_spec->blkio_weight_device_len != 0) {
        ret = merge_blkio_weight_device(oci_spec, host_spec->blkio_weight_device, host_spec->blkio_weight_device_len);
        if (ret != 0) {
            ERROR("Failed to merge blkio weight devices");
            goto out;
        }
    }

    /* blkio throttle read bps devices */
    if (host_spec->blkio_device_read_bps != NULL && host_spec->blkio_device_read_bps_len != 0) {
        ret = merge_blkio_read_bps_device(oci_spec, host_spec->blkio_device_read_bps,
                                          host_spec->blkio_device_read_bps_len);
        if (ret != 0) {
            ERROR("Failed to merge blkio read bps devices");
            goto out;
        }
    }

    /* blkio throttle write bps devices */
    if (host_spec->blkio_device_write_bps != NULL && host_spec->blkio_device_write_bps_len != 0) {
        ret = merge_blkio_write_bps_device(oci_spec, host_spec->blkio_device_write_bps,
                                           host_spec->blkio_device_write_bps_len);
        if (ret != 0) {
            ERROR("Failed to merge blkio write bps devices");
            goto out;
        }
    }

    /* blkio throttle read iops devices */
    if (host_spec->blkio_device_read_iops != NULL && host_spec->blkio_device_read_iops_len != 0) {
        ret = merge_blkio_read_iops_device(oci_spec, host_spec->blkio_device_read_iops,
                                           host_spec->blkio_device_read_iops_len);
        if (ret != 0) {
            ERROR("Failed to merge blkio read iops devices");
            goto out;
        }
    }

    /* blkio throttle write iops devices */
    if (host_spec->blkio_device_write_iops != NULL && host_spec->blkio_device_write_iops_len != 0) {
        ret = merge_blkio_write_iops_device(oci_spec, host_spec->blkio_device_write_iops,
                                            host_spec->blkio_device_write_iops_len);
        if (ret != 0) {
            ERROR("Failed to merge blkio write iops devices");
            goto out;
        }
    }

    /* devices which will be populated into container */
    if (merge_conf_populate_device(oci_spec, host_spec)) {
        ret = -1;
        goto out;
    }

    /* device cgroup rules which will be added into container */
    if (merge_conf_device_cgroup_rule(oci_spec, host_spec)) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static bool mounts_expand(defs_mount ***all_mounts, size_t *all_mounts_len, size_t add_len)
{
    defs_mount **tmp_mount = NULL;
    int ret = 0;
    defs_mount **old_mount = *all_mounts;
    size_t old_len = *all_mounts_len;

    if (add_len > SIZE_MAX / sizeof(defs_mount *) - old_len) {
        ERROR("Too many mount elements!");
        return false;
    }
    ret = util_mem_realloc((void **)&tmp_mount, (old_len + add_len) * sizeof(defs_mount *), old_mount,
                           old_len * sizeof(defs_mount *));
    if (ret < 0) {
        ERROR("memory realloc failed for mount array expand");
        return false;
    }
    *all_mounts = tmp_mount;
    *all_mounts_len = old_len + add_len;

    return true;
}

static bool mount_file(defs_mount ***all_mounts, size_t *all_mounts_len, const char *src_path, const char *dst_path)
{
    char **options = NULL;
    size_t options_len = 2;
    bool ret = false;
    defs_mount *tmp_mounts = NULL;

    options = util_common_calloc_s(options_len * sizeof(char *));
    if (options == NULL) {
        ERROR("Out of memory");
        goto out_free;
    }
    options[0] = util_strdup_s("rbind");
    options[1] = util_strdup_s("rprivate");
    /* generate mount node */
    tmp_mounts = util_common_calloc_s(sizeof(defs_mount));
    if (tmp_mounts == NULL) {
        ERROR("Malloc tmp_mounts memory failed");
        goto out_free;
    }

    tmp_mounts->destination = util_strdup_s(dst_path);
    tmp_mounts->source = util_strdup_s(src_path);
    tmp_mounts->type = util_strdup_s(MOUNT_TYPE_BIND);
    tmp_mounts->options = options;
    tmp_mounts->options_len = options_len;
    options = NULL;

    /* expand mount array */
    if (!mounts_expand(all_mounts, all_mounts_len, 1)) {
        goto out_free;
    }

    /* add a new mount node */
    (*all_mounts)[(*all_mounts_len) - 1] = tmp_mounts;

    ret = true;
out_free:

    if (!ret) {
        util_free_array_by_len(options, options_len);
        free_defs_mount(tmp_mounts);
    }
    return ret;
}

static bool add_host_channel_mount(defs_mount ***all_mounts, size_t *all_mounts_len,
                                   const host_config_host_channel *host_channel)
{
    char **options = NULL;
    size_t options_len = 3;
    bool ret = false;
    defs_mount *tmp_mounts = NULL;

    options = util_common_calloc_s(options_len * sizeof(char *));
    if (options == NULL) {
        ERROR("Out of memory");
        goto out_free;
    }
    options[0] = util_strdup_s("rbind");
    options[1] = util_strdup_s("rprivate");
    options[2] = util_strdup_s(host_channel->permissions);
    /* generate mount node */
    tmp_mounts = util_common_calloc_s(sizeof(defs_mount));
    if (tmp_mounts == NULL) {
        ERROR("Malloc tmp_mounts memory failed");
        goto out_free;
    }

    tmp_mounts->destination = util_strdup_s(host_channel->path_in_container);
    tmp_mounts->source = util_strdup_s(host_channel->path_on_host);
    tmp_mounts->type = util_strdup_s(MOUNT_TYPE_BIND);
    tmp_mounts->options = options;
    tmp_mounts->options_len = options_len;
    options = NULL;

    /* expand mount array */
    if (!mounts_expand(all_mounts, all_mounts_len, 1)) {
        goto out_free;
    }

    (*all_mounts)[(*all_mounts_len) - 1] = tmp_mounts;

    ret = true;
out_free:
    if (!ret) {
        util_free_array_by_len(options, options_len);
        free_defs_mount(tmp_mounts);
    }
    return ret;
}

#ifndef ENABLE_GVISOR
static int change_dev_shm_size(oci_runtime_spec *oci_spec, host_config *host_spec)
{
    size_t i = 0;
    size_t j = 0;
    char size_opt[MOUNT_PROPERTIES_SIZE] = { 0 };
    char *tmp = NULL;

    if (namespace_is_none(host_spec->ipc_mode)) {
        return 0;
    }

    int nret = snprintf(size_opt, sizeof(size_opt), "size=%lld", (long long int)host_spec->shm_size);
    if (nret < 0 || (size_t)nret >= sizeof(size_opt)) {
        ERROR("Out of memory");
        return -1;
    }

    if (oci_spec->mounts == NULL) {
        return -1;
    }

    for (i = 0; i < oci_spec->mounts_len; i++) {
        if (strcmp("/dev/shm", oci_spec->mounts[i]->destination) != 0) {
            continue;
        }

        for (j = 0; j < oci_spec->mounts[i]->options_len; j++) {
            // change dev shm mount size
            if (strncmp("size=", oci_spec->mounts[i]->options[j], strlen("size=")) == 0) {
                tmp = oci_spec->mounts[i]->options[j];
                oci_spec->mounts[i]->options[j] = util_strdup_s(size_opt);
                free(tmp);
                tmp = NULL;
                return 0;
            }
        }
    }

    ERROR("/dev/shm mount point not exist");
    return -1;
}
#endif

static inline bool is_mount_destination_hosts(const char *destination)
{
    return strcmp(destination, "/etc/hosts") == 0;
}

static inline bool is_mount_destination_resolv(const char *destination)
{
    return strcmp(destination, "/etc/resolv.conf") == 0;
}

static inline bool is_mount_destination_hostname(const char *destination)
{
    return strcmp(destination, "/etc/hostname") == 0;
}

/* find whether mount entry with destination "/etc/hostname" "/etc/hosts" "/etc/resolv.conf" exits in mount
 * if not exists: append mounts to ocispec by v2_spec
 * if exists: replace the source in v2_spec
 */
static int append_network_files_mounts(defs_mount ***all_mounts, size_t *all_mounts_len, host_config *host_spec,
                                       container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    size_t i = 0;
    bool has_hosts_mount = false;
    bool has_resolv_mount = false;
    bool has_hostname_mount = false;
    defs_mount **old_mounts = *all_mounts;
    size_t old_mounts_len = *all_mounts_len;
#ifdef ENABLE_SELINUX
    bool share = namespace_is_container(host_spec->network_mode);
#endif

    for (i = 0; i < old_mounts_len; i++) {
        if (is_mount_destination_hosts(old_mounts[i]->destination)) {
            has_hosts_mount = true;
            free(v2_spec->hosts_path);
            v2_spec->hosts_path = util_strdup_s(old_mounts[i]->source);
        }
        if (is_mount_destination_resolv(old_mounts[i]->destination)) {
            has_resolv_mount = true;
            free(v2_spec->resolv_conf_path);
            v2_spec->resolv_conf_path = util_strdup_s(old_mounts[i]->source);
        }
        if (is_mount_destination_hostname(old_mounts[i]->destination)) {
            has_hostname_mount = true;
            free(v2_spec->hostname_path);
            v2_spec->hostname_path = util_strdup_s(old_mounts[i]->source);
        }
    }

    if (!util_file_exists(v2_spec->hosts_path)) {
        WARN("HostsPath set to %s, but can't stat this filename; skipping", v2_spec->resolv_conf_path);
    } else {
        /* add network config files */
        if (!has_hosts_mount) {
#ifdef ENABLE_SELINUX
            if (relabel(v2_spec->hosts_path, v2_spec->mount_label, share) != 0) {
                ERROR("Error to relabel hosts path: %s", v2_spec->hosts_path);
                ret = -1;
                goto out;
            }
#endif
            if (!mount_file(all_mounts, all_mounts_len, v2_spec->hosts_path, ETC_HOSTS)) {
                ERROR("Merge hosts mount failed");
                ret = -1;
                goto out;
            }
        }
    }
    if (!util_file_exists(v2_spec->resolv_conf_path)) {
        WARN("ResolvConfPath set to %s, but can't stat this filename skipping", v2_spec->resolv_conf_path);
    } else {
        if (!has_resolv_mount) {
#ifdef ENABLE_SELINUX
            if (relabel(v2_spec->resolv_conf_path, v2_spec->mount_label, share) != 0) {
                ERROR("Error to relabel resolv.conf path: %s", v2_spec->resolv_conf_path);
                ret = -1;
                goto out;
            }
#endif
            if (!mount_file(all_mounts, all_mounts_len, v2_spec->resolv_conf_path, RESOLV_CONF_PATH)) {
                ERROR("Merge resolv.conf mount failed");
                ret = -1;
                goto out;
            }
        }
    }

    if (!util_file_exists(v2_spec->hostname_path)) {
        WARN("HostnamePath set to %s, but can't stat this filename; skipping", v2_spec->resolv_conf_path);
    } else {
        if (!has_hostname_mount) {
#ifdef ENABLE_SELINUX
            if (relabel(v2_spec->hostname_path, v2_spec->mount_label, share) != 0) {
                ERROR("Error to relabel hostname path: %s", v2_spec->hostname_path);
                return -1;
            }
#endif
            if (!mount_file(all_mounts, all_mounts_len, v2_spec->hostname_path, ETC_HOSTNAME)) {
                ERROR("Merge hostname mount failed");
                ret = -1;
                goto out;
            }
        }
    }

out:
    return ret;
}

static int chown_for_shm(const char *shm_path, const char *user_remap)
{
    unsigned int host_uid = 0;
    unsigned int host_gid = 0;
    unsigned int size = 0;

    if (shm_path == NULL) {
        return 0;
    }

    if (user_remap != NULL) {
        if (util_parse_user_remap(user_remap, &host_uid, &host_gid, &size)) {
            ERROR("Failed to split string '%s'.", user_remap);
            return -1;
        }
        if (chown(shm_path, host_uid, host_gid) != 0) {
            ERROR("Failed to chown host path '%s'.", shm_path);
            return -1;
        }
    }
    return 0;
}

static char *get_prepare_share_shm_path(const char *truntime, const char *cid)
{
#define SHM_MOUNT_FILE_NAME "/mounts/shm/"
    char *c_root_path = NULL;
    size_t slen = 0;
    char *spath = NULL;
    int nret = 0;

    if (truntime == NULL) {
        truntime = "lcr";
    }
    c_root_path = conf_get_routine_rootdir(truntime);
    if (c_root_path == NULL) {
        goto err_out;
    }

    // c_root_path + "/" + cid + "/mounts/shm"
    if (strlen(c_root_path) > (((PATH_MAX - strlen(cid)) - 1) - strlen(SHM_MOUNT_FILE_NAME)) - 1) {
        ERROR("Too large path");
        goto err_out;
    }
    slen = strlen(c_root_path) + 1 + strlen(cid) + strlen(SHM_MOUNT_FILE_NAME) + 1;
    spath = util_smart_calloc_s(sizeof(char), slen);
    if (spath == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    nret = snprintf(spath, slen, "%s/%s/mounts/shm/", c_root_path, cid);
    if (nret < 0 || nret >= slen) {
        ERROR("Sprintf failed");
        goto err_out;
    }

    free(c_root_path);
    return spath;

err_out:
    free(spath);
    free(c_root_path);
    return NULL;
}

static bool has_mount_shm(host_config *host_spec, container_config_v2_common_config *v2_spec)
{
    container_t *cont = NULL;
    bool ret = false;

    cont = util_common_calloc_s(sizeof(container_t));
    if (cont == NULL) {
        ERROR("Out of memory");
        goto out;
    }
    cont->common_config = v2_spec;
    cont->hostconfig = host_spec;

    ret = container_has_mount_for(cont, "/dev/shm");

    cont->common_config = NULL;
    cont->hostconfig = NULL;
out:
    free(cont);
    return ret;
}

static int prepare_share_shm(host_config *host_spec, container_config_v2_common_config *v2_spec)
{
#define MAX_PROPERTY_LEN 64
    char shmproperty[MAX_PROPERTY_LEN] = { 0 };
    int ret = -1;
    int nret = 0;
    bool has_mount = false;
    char *spath = NULL;
#ifdef ENABLE_USERNS_REMAP
    char *tmp_path = NULL;
    char *p = NULL;
    char *userns_remap = NULL;
#endif
    // has mount for /dev/shm
    if (has_mount_shm(host_spec, v2_spec)) {
        return 0;
    }

    spath = get_prepare_share_shm_path(host_spec->runtime, v2_spec->id);
    if (spath == NULL) {
        goto out;
    }

    nret = util_mkdir_p(spath, 0700);
    if (nret != 0) {
        ERROR("Build shm dir failed");
        goto out;
    }
    nret = snprintf(shmproperty, MAX_PROPERTY_LEN, "mode=1777,size=%" PRId64, host_spec->shm_size);
    if (nret < 0 || nret >= MAX_PROPERTY_LEN) {
        ERROR("Sprintf failed");
        goto out;
    }

    nret = mount("shm", spath, "tmpfs", MS_NOEXEC | MS_NODEV | MS_NOSUID, shmproperty);
    if (nret < 0) {
        ERROR("Mount %s failed: %s", spath, strerror(errno));
        goto out;
    }
    has_mount = true;

    nret = chown_for_shm(spath, host_spec->user_remap);
    if (nret != 0) {
        goto out;
    }

    v2_spec->shm_path = spath;
#ifdef ENABLE_USERNS_REMAP
    userns_remap = conf_get_isulad_userns_remap();

    if (host_spec->user_remap == NULL && userns_remap != NULL) {
        // find parent directory
        tmp_path = util_strdup_s(spath);
        p = strrchr(tmp_path, '/');
        if (p == NULL) {
            ERROR("Failed to find parent directory for %s", tmp_path);
            goto out;
        }
        *p = '\0';

        if (set_file_owner_for_userns_remap(tmp_path, userns_remap) != 0) {
            ERROR("Unable to change directory %s owner for user remap.", tmp_path);
            goto out;
        }

        p = strrchr(tmp_path, '/');
        if (p == NULL) {
            ERROR("Failed to find parent directory for %s", tmp_path);
            goto out;
        }
        *p = '\0';

        if (set_file_owner_for_userns_remap(tmp_path, userns_remap) != 0) {
            ERROR("Unable to change directory %s owner for user remap.", tmp_path);
            goto out;
        }
    }
#endif

    spath = NULL;
    ret = 0;
out:
    if (ret != 0 && has_mount) {
        (void)umount(spath);
    }
    free(spath);
#ifdef ENABLE_USERNS_REMAP
    free(tmp_path);
    free(userns_remap);
#endif
    return ret;
}

static bool add_shm_mount(defs_mount ***all_mounts, size_t *all_mounts_len, const char *shm_path)
{
    char **options = NULL;
    size_t options_len = 2;
    bool ret = false;
    defs_mount *tmp_mounts = NULL;

#ifndef ENABLE_GVISOR
    options_len += 1;
#endif
    options = util_common_calloc_s(options_len * sizeof(char *));
    if (options == NULL) {
        ERROR("Out of memory");
        goto out_free;
    }
    options[0] = util_strdup_s("rbind");
    options[1] = util_strdup_s("rprivate");
#ifndef ENABLE_GVISOR
    /* runsc won't distinguish this mount option, the mount operation is performed by high-lever runtime,
     * and ignored this option for low-level runtime.
     */
    options[2] = util_strdup_s("size=65536k"); // default shm size is 64MB
#endif
    /* generate mount node */
    tmp_mounts = util_common_calloc_s(sizeof(defs_mount));
    if (tmp_mounts == NULL) {
        ERROR("Malloc tmp_mounts memory failed");
        goto out_free;
    }

    tmp_mounts->destination = util_strdup_s("/dev/shm");
    tmp_mounts->source = util_strdup_s(shm_path);
    tmp_mounts->type = util_strdup_s(MOUNT_TYPE_BIND);
    tmp_mounts->options = options;
    tmp_mounts->options_len = options_len;
    options = NULL;

    /* expand mount array */
    if (!mounts_expand(all_mounts, all_mounts_len, 1)) {
        goto out_free;
    }

    (*all_mounts)[(*all_mounts_len) - 1] = tmp_mounts;

    ret = true;
out_free:

    if (!ret) {
        util_free_array_by_len(options, options_len);
        free_defs_mount(tmp_mounts);
    }
    return ret;
}

#define SHM_MOUNT_POINT "/dev/shm"
static int setup_ipc_dirs(host_config *host_spec, container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    container_t *cont = NULL;
    char *tmp_cid = NULL;
    char *right_path = NULL;

    // ignore shm of system container
    if (host_spec->system_container) {
        return 0;
    }
    // setup shareable dirs
    if (host_spec->ipc_mode == NULL || namespace_is_shareable(host_spec->ipc_mode)) {
        return prepare_share_shm(host_spec, v2_spec);
    }

    if (namespace_is_container(host_spec->ipc_mode)) {
        tmp_cid = namespace_get_connected_container(host_spec->ipc_mode);
        cont = containers_store_get(tmp_cid);
        if (cont == NULL) {
            ERROR("Invalid share path: %s", host_spec->ipc_mode);
            ret = -1;
            goto out;
        }
        right_path = util_strdup_s(cont->common_config->shm_path);
        container_unref(cont);
    } else if (namespace_is_host(host_spec->ipc_mode)) {
        if (!util_file_exists(SHM_MOUNT_POINT)) {
            ERROR("/dev/shm is not mounted, but must be for --ipc=host");
            ret = -1;
            goto out;
        }
        right_path = util_strdup_s(SHM_MOUNT_POINT);
    }

    free(v2_spec->shm_path);
    v2_spec->shm_path = right_path;
out:
    free(tmp_cid);
    return ret;
}

int destination_compare(const void *p1, const void *p2)
{
    defs_mount *mount_1 = *(defs_mount **)p1;
    defs_mount *mount_2 = *(defs_mount **)p2;

    return strcmp(mount_1->destination, mount_2->destination);
}

static defs_mount *get_conflict_mount_point(defs_mount **mounts, size_t mounts_len, defs_mount *mnt)
{
    size_t i = 0;

    for (i = 0; i < mounts_len; i++) {
        if (mounts[i] == NULL) {
            continue;
        }
        if (strcmp(mounts[i]->destination, mnt->destination) == 0) {
            return mounts[i];
        }
    }

    return NULL;
}

static int calc_volumes_from_len(host_config *host_spec, size_t *len)
{
    char *id = NULL;
    char *mode = NULL;
    container_t *cont = NULL;
    int ret = 0;
    int i = 0;

    *len = 0;
    for (i = 0; i < host_spec->volumes_from_len; i++) {
        ret = split_volume_from(host_spec->volumes_from[i], &id, &mode);
        if (ret != 0) {
            ERROR("failed to split volume-from: %s", host_spec->volumes_from[i]);
            goto out;
        }

        cont = containers_store_get(id);
        if (cont == NULL) {
            ERROR("container %s not found when calc volumes from len, volumes-from:%s", id, host_spec->volumes_from[i]);
            ret = -1;
            goto out;
        }

        if (cont->common_config != NULL && cont->common_config->mount_points != NULL) {
            *len += cont->common_config->mount_points->len;
        }

        free(id);
        id = NULL;
        container_unref(cont);
        cont = NULL;
    }

out:
    free(id);
    free(mode);
    container_unref(cont);

    return ret;
}

static int calc_mounts_len(host_config *host_spec, container_config *container_spec, size_t *len)
{
    size_t volumes_from_len = 0;

    if (calc_volumes_from_len(host_spec, &volumes_from_len) != 0) {
        return -1;
    }

    *len = host_spec->mounts_len + host_spec->binds_len + volumes_from_len;
    if (host_spec->tmpfs != NULL) {
        (*len) += host_spec->tmpfs->len;
    }

    if (container_spec->volumes != NULL && container_spec->volumes->len != 0) {
        (*len) += container_spec->volumes->len;
    }
    if (container_spec->mounts != NULL && container_spec->mounts_len != 0) {
        (*len) += container_spec->mounts_len;
    }

    return 0;
}

static void add_mount(defs_mount **merged_mounts, size_t *merged_mounts_len, defs_mount *mnt)
{
    merged_mounts[*merged_mounts_len] = mnt;
    *merged_mounts_len += 1;
}

static int add_embedded_layers(container_config *container_spec, defs_mount **merged_mounts,
                               size_t *merged_mounts_len)
{
    int ret = 0;
    size_t i = 0;
    defs_mount *mnt = NULL;
    defs_mount *conflict = NULL;
    mount_spec *spec = NULL;
    char *errmsg = NULL;

    for (i = 0; container_spec->mounts != 0 && i < container_spec->mounts_len; i++) {
        ret = util_parse_mount_spec(container_spec->mounts[i], &spec, &errmsg);
        if (ret != 0) {
            ERROR("parse mount spec failed: %s", errmsg);
            ret = -1;
            goto out;
        }

        mnt = parse_mount(spec);
        if (mnt == NULL) {
            ERROR("parse mount failed");
            ret = -1;
            goto out;
        }

        // do not use duplicate mount point
        conflict = get_conflict_mount_point(merged_mounts, *merged_mounts_len, mnt);
        if (conflict != NULL) {
            ERROR("Duplicate mount point: %s", conflict->destination);
            isulad_set_error_message("Duplicate mount point: %s", conflict->destination);
            ret = -1;
            goto out;
        }

        add_mount(merged_mounts, merged_mounts_len, mnt);
        mnt = NULL;
        free_mount_spec(spec);
        spec = NULL;
    }

out:
    free_defs_mount(mnt);
    free_mount_spec(spec);
    free(errmsg);

    return ret;
}

static int add_mounts(host_config *host_spec, defs_mount **merged_mounts, size_t *merged_mounts_len)
{
    int ret = 0;
    size_t i = 0;
    defs_mount *mnt = NULL;
    defs_mount *conflict = NULL;

    for (i = 0; i < host_spec->mounts_len; i++) {
        mnt = parse_mount(host_spec->mounts[i]);
        if (mnt == NULL) {
            ERROR("parse mount failed");
            ret = -1;
            goto out;
        }

        conflict = get_conflict_mount_point(merged_mounts, *merged_mounts_len, mnt);
        if (conflict != NULL) {
            ERROR("Duplicate mount point: %s", conflict->destination);
            isulad_set_error_message("Duplicate mount point: %s", conflict->destination);
            ret = -1;
            goto out;
        }

        add_mount(merged_mounts, merged_mounts_len, mnt);
    }

out:
    if (ret != 0) {
        free_defs_mount(mnt);
    }

    return ret;
}

static int add_volumes(host_config *host_spec, defs_mount **merged_mounts, size_t *merged_mounts_len)
{
    int ret = 0;
    size_t i = 0;
    defs_mount *mnt = NULL;
    defs_mount *conflict = NULL;

    for (i = 0; i < host_spec->binds_len; i++) {
        mnt = parse_volume(host_spec->binds[i]);
        if (mnt == NULL) {
            ERROR("parse binds %s failed", host_spec->binds[i]);
            ret = -1;
            goto out;
        }

        conflict = get_conflict_mount_point(merged_mounts, *merged_mounts_len, mnt);
        if (conflict != NULL) {
            ERROR("Duplicate mount point: %s", conflict->destination);
            isulad_set_error_message("Duplicate mount point: %s", conflict->destination);
            ret = -1;
            goto out;
        }

        add_mount(merged_mounts, merged_mounts_len, mnt);
        mnt = NULL;
    }

out:
    if (ret != 0) {
        free_defs_mount(mnt);
    }

    return ret;
}

static char *get_valid_tmpfs_dst_path(char *tmpfs)
{
    char dstpath[PATH_MAX] = {0};

    if (tmpfs == NULL) {
        return NULL;
    }

    if (tmpfs[0] != '/') {
        ERROR("Invalid mount specification '%s'.Destination must be absolute path", tmpfs);
        isulad_set_error_message("Invalid mount specification '%s'.Destination must be absolute path", tmpfs);
        return NULL;
    }

    if (!util_clean_path(tmpfs, dstpath, sizeof(dstpath))) {
        ERROR("Invalid mount specification '%s'.Can't translate destination path to clean path", tmpfs);
        isulad_set_error_message("Invalid mount specification '%s'.Can't translate destination path to clean path",
                                 tmpfs);
        return NULL;
    }

    if (strcmp(dstpath, "/") == 0) {
        ERROR("Invalid mount specification '%s'.Destination can't be '/'", tmpfs);
        isulad_set_error_message("Invalid mount specification '%s'.Destination can't be '/'", tmpfs);
        return NULL;
    }

    return util_strdup_s(dstpath);
}

static defs_mount *parse_tmpfs(char *tmpfs)
{
    int ret = 0;
    defs_mount *m = NULL;
    char *dstpath = NULL;

    dstpath = get_valid_tmpfs_dst_path(tmpfs);
    if (dstpath == NULL) {
        return NULL;
    }

    m = util_common_calloc_s(sizeof(defs_mount));
    if (m == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    m->type = util_strdup_s(MOUNT_TYPE_TMPFS);
    m->source = util_strdup_s("tmpfs");
    m->destination = util_strdup_s(dstpath);

    if (append_default_tmpfs_options(m) != 0) {
        ERROR("append default tmpfs options failed");
        ret = -1;
        goto out;
    }

out:
    free(dstpath);
    if (ret != 0) {
        free_defs_mount(m);
        m = NULL;
    }

    return m;
}

static int add_tmpfs(host_config *host_spec, defs_mount **merged_mounts, size_t *merged_mounts_len)
{
    int ret = 0;
    size_t i = 0;
    defs_mount *mnt = NULL;
    defs_mount *conflict = NULL;
    json_map_string_string *tmpfs = host_spec->tmpfs;

    if (tmpfs == NULL) {
        return 0;
    }
    for (i = 0; i < tmpfs->len; i++) {
        mnt = parse_tmpfs(tmpfs->keys[i]);
        if (mnt == NULL) {
            ERROR("parse binds %s failed", tmpfs->keys[i]);
            ret = -1;
            goto out;
        }

        conflict = get_conflict_mount_point(merged_mounts, *merged_mounts_len, mnt);
        if (conflict != NULL) {
            ERROR("Duplicate mount point: %s", conflict->destination);
            isulad_set_error_message("Duplicate mount point: %s", conflict->destination);
            ret = -1;
            goto out;
        }

        add_mount(merged_mounts, merged_mounts_len, mnt);
        mnt = NULL;
    }

out:
    if (ret != 0) {
        free_defs_mount(mnt);
    }

    return ret;
}

static int add_volumes_from(host_config *host_spec, defs_mount **merged_mounts, size_t *merged_mounts_len)
{
    int ret = 0;
    size_t i = 0;
    size_t j = 0;
    defs_mount **mnts = NULL;
    size_t mnts_len = 0;
    defs_mount *conflict = NULL;

    for (i = 0; i < host_spec->volumes_from_len; i++) {
        ret = parse_volumes_from(host_spec->volumes_from[i], &mnts, &mnts_len);
        if (ret != 0) {
            ERROR("parse mount failed");
            goto out;
        }

        for (j = 0; j < mnts_len; j++) {
            // use user specified config and drop the mount config from other containers if conflict
            conflict = get_conflict_mount_point(merged_mounts, *merged_mounts_len, mnts[j]);
            if (conflict != NULL) {
                free_defs_mount(mnts[j]);
                mnts[j] = NULL;
                continue;
            }

            add_mount(merged_mounts, merged_mounts_len, mnts[j]);
            mnts[j] = NULL;
        }
        free_defs_mounts(mnts, mnts_len);
        mnts = NULL;
        mnts_len = 0;
    }
out:

    free_defs_mounts(mnts, mnts_len);

    return ret;
}

static int add_image_config_volumes(container_config *container_spec, defs_mount **merged_mounts,
                                    size_t *merged_mounts_len)
{
    int ret = 0;
    size_t i = 0;
    defs_mount *mnt = NULL;
    defs_mount *conflict = NULL;

    for (i = 0; container_spec->volumes != 0 && i < container_spec->volumes->len; i++) {
        mnt = parse_anonymous_volume(container_spec->volumes->keys[i]);
        if (mnt == NULL) {
            ERROR("parse binds %s failed", container_spec->volumes->keys[i]);
            ret = -1;
            goto out;
        }

        // use user specified config and drop the volume config in image config if conflict
        conflict = get_conflict_mount_point(merged_mounts, *merged_mounts_len, mnt);
        if (conflict != NULL) {
            free_defs_mount(mnt);
            mnt = NULL;
            continue;
        }

        add_mount(merged_mounts, merged_mounts_len, mnt);
        mnt = NULL;
    }

out:
    free_defs_mount(mnt);

    return ret;
}

// merge rules:
// 1. if -v conflict with --mount, fail
// 2. if --volumes-from conflict with -v/--mount, drop the mount of --volumes-from
// 3. if anonymous volumes in image config conflict with -v/--mount/--volumes-from,
//    drop the anonymous volumes in image config
static int merge_all_fs_mounts(host_config *host_spec, container_config *container_spec, defs_mount ***all_mounts,
                               size_t *all_mounts_len)
{
    int ret = 0;
    defs_mount **merged_mounts = NULL;
    size_t merged_mounts_len = 0;
    size_t len = 0;

    ret = calc_mounts_len(host_spec, container_spec, &len);
    if (ret != 0) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    merged_mounts = util_common_calloc_s(sizeof(defs_mount *) * len);
    if (merged_mounts == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    // add embedded layers
    ret = add_embedded_layers(container_spec, merged_mounts, &merged_mounts_len);
    if (ret != 0) {
        goto out;
    }

    // add --mounts
    ret = add_mounts(host_spec, merged_mounts, &merged_mounts_len);
    if (ret != 0) {
        goto out;
    }

    // add --volume
    ret = add_volumes(host_spec, merged_mounts, &merged_mounts_len);
    if (ret != 0) {
        goto out;
    }

    // add --tmpfs
    ret = add_tmpfs(host_spec, merged_mounts, &merged_mounts_len);
    if (ret != 0) {
        goto out;
    }

    // add --volumes-from
    ret = add_volumes_from(host_spec, merged_mounts, &merged_mounts_len);
    if (ret != 0) {
        goto out;
    }

    // add anonymous volumes in image config
    ret = add_image_config_volumes(container_spec, merged_mounts, &merged_mounts_len);
    if (ret != 0) {
        goto out;
    }

    *all_mounts = merged_mounts;
    *all_mounts_len = merged_mounts_len;

out:
    if (ret != 0) {
        free_defs_mounts(merged_mounts, merged_mounts_len);
    }

    return ret;
}

int merge_conf_mounts(oci_runtime_spec *oci_spec, host_config *host_spec, container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    container_config *container_spec = v2_spec->config;
    defs_mount **all_fs_mounts = NULL;
    size_t all_fs_mounts_len = 0;
    bool mounted = false;

    ret = im_mount_container_rootfs(v2_spec->image_type, v2_spec->image, v2_spec->id);
    if (ret != 0) {
        ERROR("Mount container %s failed when merge mounts", v2_spec->id);
        goto out;
    }
    mounted = true;

    ret = merge_all_fs_mounts(host_spec, container_spec, &all_fs_mounts, &all_fs_mounts_len);
    if (ret != 0) {
        ERROR("Failed to merge all mounts");
        goto out;
    }

    /* mounts to mount filesystem */
    ret = merge_fs_mounts_to_v2_spec(all_fs_mounts, all_fs_mounts_len, v2_spec);
    if (ret) {
        ERROR("Failed to merge mounts in to v2 spec");
        goto out;
    }

    (void)im_umount_container_rootfs(v2_spec->image_type, v2_spec->image, v2_spec->id);
    mounted = false;

    /* host channel to mount */
    if (host_spec->host_channel != NULL) {
        if (!add_host_channel_mount(&all_fs_mounts, &all_fs_mounts_len, host_spec->host_channel)) {
            ERROR("Failed to merge host channel mount");
            goto out;
        }
    }

    if (host_spec->shm_size == 0) {
        host_spec->shm_size = DEFAULT_SHM_SIZE;
    }

    /* setup ipc dir */
    if (setup_ipc_dirs(host_spec, v2_spec) != 0) {
        ret = -1;
        goto out;
    }

    /* add ipc mount */
    if (v2_spec->shm_path != NULL) {
        // check whether duplication
        add_shm_mount(&all_fs_mounts, &all_fs_mounts_len, v2_spec->shm_path);
    }

    if (!host_spec->system_container) {
        ret = append_network_files_mounts(&all_fs_mounts, &all_fs_mounts_len, host_spec, v2_spec);
        if (ret) {
            ERROR("Failed to append network mounts");
            goto out;
        }
    }

    qsort(all_fs_mounts, all_fs_mounts_len, sizeof(all_fs_mounts[0]), destination_compare);

    ret = merge_fs_mounts_to_oci_spec(oci_spec, all_fs_mounts, all_fs_mounts_len);
    if (ret) {
        ERROR("Failed to merge all mounts in to oci spec");
        goto out;
    }

#ifndef ENABLE_GVISOR
    if (!has_mount_shm(host_spec, v2_spec) && host_spec->shm_size > 0) {
        ret = change_dev_shm_size(oci_spec, host_spec);
        if (ret) {
            ERROR("Failed to set dev shm size");
            goto out;
        }
    }
#endif

out:
    if (mounted) {
        (void)im_umount_container_rootfs(v2_spec->image_type, v2_spec->image, v2_spec->id);
    }

    free_defs_mounts(all_fs_mounts, all_fs_mounts_len);

    return ret;
}

int add_rootfs_mount(const container_config *container_spec)
{
    int ret = 0;
    char *mntparent = NULL;

    mntparent = conf_get_isulad_mount_rootfs();
    if (mntparent == NULL) {
        ERROR("Failed to get mount parent directory");
        ret = -1;
        goto out;
    }
    if (append_json_map_string_string(container_spec->annotations, "rootfs.mount", mntparent)) {
        ERROR("Realloc annotatinons failed");
        ret = -1;
        goto out;
    }

out:
    free(mntparent);
    return ret;
}
