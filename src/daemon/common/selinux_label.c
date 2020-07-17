/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2019-12-15
 * Description: provide selinux label handle function definition
 ******************************************************************************/

#include "selinux_label.h"

#include <selinux/selinux.h>
#include <selinux/context.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <stdint.h>
#include <sys/statfs.h>
#include <syscall.h>

#include "map.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "err_msg.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"

#define SELINUXFS_MOUNT "/sys/fs/selinux"
#define SELINUXFS_MAGIC 0xf97cff8c

typedef struct selinux_state_t {
    bool enabled_set;
    bool enabled;
    bool selinuxf_set;
    char *selinuxfs;
    map_t *mcs_list; // map string boolean
    pthread_rwlock_t rwlock;
} selinux_state;

static selinux_state *g_selinux_state = NULL;

static bool set_state_enable(bool enabled)
{
    bool result = false;

    if (pthread_rwlock_rdlock(&g_selinux_state->rwlock) != 0) {
        ERROR("lock mcs list failed");
        return false;
    }

    g_selinux_state->enabled_set = true;
    g_selinux_state->enabled = enabled;
    result = g_selinux_state->enabled;

    if (pthread_rwlock_unlock(&g_selinux_state->rwlock) != 0) {
        ERROR("unlock mcs list failed");
    }

    return result;
}

static int set_state_selinux_fs(char *selinuxfs)
{
    if (pthread_rwlock_rdlock(&g_selinux_state->rwlock) != 0) {
        ERROR("lock selinux state failed");
        return -1;
    }

    g_selinux_state->selinuxf_set = true;
    free(g_selinux_state->selinuxfs);
    g_selinux_state->selinuxfs = util_strdup_s(selinuxfs);

    if (pthread_rwlock_unlock(&g_selinux_state->rwlock) != 0) {
        ERROR("unlock selinux state failed");
        return -1;
    }

    return 0;
}

/* Verify the mount point for selinux file system has a selinuxfs. */
static bool verify_selinuxfs_mount(const char *mnt)
{
    struct statfs sfbuf;

    while (true) {
        int rc = statfs(mnt, &sfbuf);
        if (rc == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        return false;
    }

    if ((uint32_t)sfbuf.f_type != (uint32_t)SELINUXFS_MAGIC) {
        return false;
    }

    if ((sfbuf.f_flags & ST_RDONLY) != 0) {
        return false;
    }

    return true;
}
// returns a next selinuxfs mount point found,
// if there is one, or an empty string in case of EOF or error.
static void find_selinux_fs_among_mounts(char **fs)
{
#define MOUNT_POOINT_FIFTH_FIELD 5
    FILE *fp = NULL;
    char *buf = NULL;
    char **fields = NULL;
    size_t len;

    fp = fopen("/proc/self/mountinfo", "re");
    if (fp == NULL) {
        INFO("/proc/self/mountinfo not exists");
        return;
    }
    __fsetlocking(fp, FSETLOCKING_BYCALLER);

    while (getline(&buf, &len, fp) != -1) {
        if (!strstr(buf, " - selinuxfs ")) {
            continue;
        }
        fields = util_string_split((const char *)buf, ' ');
        if (fields == NULL || util_array_len((const char **)fields) < MOUNT_POOINT_FIFTH_FIELD + 1) {
            util_free_array(fields);
            continue;
        }
        if (verify_selinuxfs_mount(fields[MOUNT_POOINT_FIFTH_FIELD - 1])) {
            *fs = util_strdup_s(fields[MOUNT_POOINT_FIFTH_FIELD - 1]);
        }
        goto out;
    }

out:
    util_free_array(fields);
    free(buf);
    fclose(fp);
}

static void find_selinux_fs(char **fs)
{
    // fast path: check the default mount first
    if (verify_selinuxfs_mount(SELINUXFS_MOUNT)) {
        *fs = util_strdup_s(SELINUXFS_MOUNT);
        return;
    }
    // check if selinuxfs is available before going the slow path
    if (selinuxfs_exists() == 0) {
        return;
    }
    // slow path: try to find among the mounts
    find_selinux_fs_among_mounts(fs);

    return;
}

static int get_state_selinuxfs(char **fs)
{
    bool selinuxfs_set = false;
    char *selinuxfs = NULL;

    if (pthread_rwlock_rdlock(&g_selinux_state->rwlock) != 0) {
        ERROR("lock mcs list failed");
        return -1;
    }

    selinuxfs_set = g_selinux_state->selinuxf_set;
    selinuxfs = g_selinux_state->selinuxfs;

    if (pthread_rwlock_unlock(&g_selinux_state->rwlock) != 0) {
        ERROR("unlock mcs list failed");
        return -1;
    }

    if (selinuxfs_set) {
        *fs = util_strdup_s(selinuxfs);
        return 0;
    }

    find_selinux_fs(fs);

    return set_state_selinux_fs(*fs);
}

static int get_selinux_mount_point(char **fs)
{
    return get_state_selinuxfs(fs);
}

static int read_con(const char *fpath, char **content)
{
    int ret = 0;
    char *tmp = NULL;
    char *trim_str = NULL;

    if (fpath == NULL) {
        ERROR("Empty path");
        return -1;
    }

    tmp = isula_utils_read_file(fpath);
    if (tmp == NULL) {
        ERROR("Failed to read file: %s", fpath);
        ret = -1;
        goto out;
    }

    trim_str = util_trim_space(tmp);
    *content = util_strdup_s(trim_str);

out:
    free(tmp);
    return ret;
}

// get_current_label returns the SELinux label of the current process thread.
static int get_current_label(char **content)
{
    int nret = 0;
    char path[PATH_MAX] = { 0 };

    nret = snprintf(path, sizeof(path), "/proc/self/task/%ld/attr/current", (long int)syscall(__NR_gettid));
    if (nret < 0 || nret >= sizeof(path)) {
        ERROR("Humanize sprintf failed!");
        return -1;
    }

    return read_con(path, content);
}

bool selinux_get_enable()
{
    bool enabled_set = false;
    bool enabled = false;
    char *fs = NULL;

    if (pthread_rwlock_rdlock(&g_selinux_state->rwlock) != 0) {
        ERROR("lock selinux state failed");
        return false;
    }

    enabled_set = g_selinux_state->enabled_set;
    enabled = g_selinux_state->enabled;

    if (pthread_rwlock_unlock(&g_selinux_state->rwlock) != 0) {
        ERROR("unlock selinux state failed");
        return false;
    }

    if (enabled_set) {
        return enabled;
    }

    enabled = false;

    if (get_selinux_mount_point(&fs) != 0) {
        ERROR("Failed to get selinux mount point");
        return false;
    }

    if (fs != NULL) {
        char *content = NULL;

        if (get_current_label(&content) != 0 || content == NULL) {
            ERROR("Failed to get current label");
            return false;
        }
        if (strcmp(content, "kernel") != 0) {
            enabled = true;
        }
        free(content);
    }

    free(fs);
    return set_state_enable(enabled);
}

// just disable selinux support for iSulad
void selinux_set_disabled()
{
    (void)set_state_enable(false);
}

static int get_random_value(unsigned int range, unsigned int *val)
{
    int ret = 0;
    int num = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        ERROR("Failed to open urandom device\n");
        return -1;
    }

    if (read(fd, &num, sizeof(int)) < 0) {
        ERROR("Failed to read urandom value\n");
        ret = -1;
        goto out;
    }

    *val = (unsigned)num % range;

out:
    close(fd);
    return ret;
}

/* selinux state free */
static void do_selinux_state_free(selinux_state *state)
{
    if (state == NULL) {
        return;
    }

    map_free(state->mcs_list);
    state->mcs_list = NULL;
    free(state->selinuxfs);
    pthread_rwlock_destroy(&(state->rwlock));
    free(state);
}

/* memory store new */
static selinux_state *selinux_state_new(void)
{
    selinux_state *state = util_common_calloc_s(sizeof(selinux_state));
    if (state == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (pthread_rwlock_init(&(state->rwlock), NULL) != 0) {
        ERROR("Failed to init memory store rwlock");
        free(state);
        return NULL;
    }

    state->mcs_list = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (state->mcs_list == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }

    return state;

error_out:
    do_selinux_state_free(state);
    return NULL;
}

/* selinux state init */
int selinux_state_init(void)
{
    g_selinux_state = selinux_state_new();
    if (g_selinux_state == NULL) {
        return -1;
    }

    return 0;
}

void selinux_state_free()
{
    do_selinux_state_free(g_selinux_state);
}

/* MCS already exists */
static bool is_mcs_already_exists(const char *mcs)
{
    char *val = NULL;

    if (mcs == NULL) {
        return false;
    }
    if (pthread_rwlock_rdlock(&g_selinux_state->rwlock) != 0) {
        ERROR("lock selinux state failed");
        return false;
    }

    val = map_search(g_selinux_state->mcs_list, (void *)mcs);

    if (pthread_rwlock_unlock(&g_selinux_state->rwlock) != 0) {
        ERROR("unlock selinux state failed");
    }

    return val != NULL;
}

/* MCS list add */
static bool mcs_add(const char *mcs)
{
    bool ret = false;
    bool val = true;

    if (pthread_rwlock_wrlock(&g_selinux_state->rwlock)) {
        ERROR("lock memory store failed");
        return false;
    }

    ret = map_replace(g_selinux_state->mcs_list, (void *)mcs, (void *)&val);

    if (pthread_rwlock_unlock(&g_selinux_state->rwlock)) {
        ERROR("unlock memory store failed");
        return false;
    }

    return ret;
}

static bool mcs_delete(const char *mcs)
{
    bool ret = false;
    bool val = true;

    if (mcs == NULL) {
        return 0;
    }

    if (pthread_rwlock_wrlock(&g_selinux_state->rwlock) != 0) {
        ERROR("lock name index failed");
        return false;
    }

    ret = map_replace(g_selinux_state->mcs_list, (void *)mcs, (void *)&val);

    if (pthread_rwlock_unlock(&g_selinux_state->rwlock) != 0) {
        ERROR("unlock name index failed");
        return false;
    }

    return ret;
}

static int add_mcs_to_global_list(const char *mcs)
{
    if (is_mcs_already_exists(mcs)) {
        DEBUG("MCS label already exists");
        return -1;
    }

    if (!mcs_add(mcs)) {
        ERROR("Failed to add mcs to global list");
        return -1;
    }

    return 0;
}

static int uniq_mcs(unsigned int range, char *mcs, size_t len)
{
    unsigned int c1, c2;

    while (true) {
        int nret;

        if (get_random_value(range, &c1) != 0 || get_random_value(range, &c2) != 0) {
            return -1;
        }
        if (c1 == c2) {
            continue;
        } else if (c1 > c2) {
            unsigned int tmp = c1;
            c1 = c2;
            c2 = tmp;
        }

        nret = snprintf(mcs, len, "s0:c%d,c%d", c1, c2);
        if (nret < 0 || nret >= len) {
            ERROR("Failed to compose mcs");
            return -1;
        }

        if (add_mcs_to_global_list(mcs)) {
            continue;
        }

        break;
    }

    return 0;
}

static bool should_skip_in_lxc_contexts(const char *line)
{
    // skip blank lines
    if (strlen(line) == 0) {
        return true;
    }

    // skip comments
    if (line[0] == ';' || line[0] == '#') {
        return true;
    }

    return false;
}

static int parse_lxc_context_info(const char *line, char **process_label, char **file_label)
{
    int ret = 0;
    size_t groups_len = 0;
    char **groups = NULL;
    char *key = NULL;
    char *val = NULL;

    groups = util_string_split(line, '=');
    if (groups == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    groups_len = util_array_len((const char **)groups);
    if (groups_len != 2) {
        ERROR("Invalid context");
        ret = -1;
        goto out;
    }

    key = util_trim_space(groups[0]);
    val = util_trim_space(groups[1]);

    if (strcmp(key, "process") == 0) {
        free(*process_label);
        *process_label = util_string_delchar(val, '"');
    } else if (strcmp(key, "file") == 0) {
        free(*file_label);
        *file_label = util_string_delchar(val, '"');
    }

out:
    util_free_array(groups);
    return ret;
}

static void update_process_and_mount_label_range(char **process_label, char **file_label)
{
#define MCS_MAX_LEN 20
    context_t scon = context_new(*process_label);

    if (context_range_get(scon) != NULL) {
        char mcs[MCS_MAX_LEN] = { 0x00 };

        uniq_mcs(1024, mcs, MCS_MAX_LEN);
        context_range_set(scon, mcs);
        free(*process_label);
        *process_label = util_strdup_s(context_str(scon));

        context_t mcon = context_new(*file_label);
        context_range_set(mcon, mcs);
        free(*file_label);
        *file_label = util_strdup_s(context_str(mcon));
        context_free(mcon);
    }

    context_free(scon);
}

static int container_label(char **process_label, char **file_label)
{
    int ret = 0;
    size_t len;
    ssize_t num;
    FILE *file = NULL;
    char *buf = NULL;
    const char *lxc_path = NULL;

    if (!selinux_get_enable()) {
        return 0;
    }

    lxc_path = selinux_lxc_contexts_path();
    if (lxc_path == NULL) {
        ERROR("Failed to get selinux lxc contexts path");
        return -1;
    }

    file = fopen(lxc_path, "re");
    if (file == NULL) {
        ERROR("Failed to open '%s'", lxc_path);
        return -1;
    }
    __fsetlocking(file, FSETLOCKING_BYCALLER);

    for (num = getline(&buf, &len, file); num != -1; num = getline(&buf, &len, file)) {
        char *line = util_strdup_s(buf);
        char *tmp_line = util_trim_space(line);

        if (should_skip_in_lxc_contexts(tmp_line)) {
            free(line);
            continue;
        }

        if (parse_lxc_context_info(tmp_line, process_label, file_label) != 0) {
            ERROR("Failed to parse lxc context info");
            free(line);
            ret = -1;
            goto out;
        }

        free(line);
    }

    if (*process_label == NULL || *file_label == NULL) {
        ret = 0;
        goto out;
    }

    update_process_and_mount_label_range(process_label, file_label);

out:
    free(buf);
    fclose(file);
    return ret;
}

static bool valid_options(const char *opt)
{
    size_t i;
    const char *opts[] = { "disable", "type", "user", "role", "level" };

    for (i = 0; i < sizeof(opts) / sizeof(char *); i++) {
        if (strcmp(opt, opts[i]) == 0) {
            return true;
        }
    }

    return false;
}

static int release_label(const char *label)
{
    int ret = 0;
    const char *range = NULL;

    if (label == NULL) {
        ERROR("Invalid label");
        return -1;
    }

    context_t tmp = context_new(label);
    range = context_range_get(tmp);
    if (range != NULL) {
        if (!mcs_delete(range)) {
            ERROR("delete mcs '%s' failed", range);
            ret = -1;
            goto out;
        }
    }

out:
    context_free(tmp);
    return ret;
}

static int reserve_label(const char *label)
{
    int ret = 0;
    const char *range = NULL;

    if (label == NULL) {
        ERROR("Invalid label");
        return -1;
    }

    context_t tmp = context_new(label);
    range = context_range_get(tmp);
    if (range != NULL) {
        if (!mcs_add(range)) {
            ERROR("add mcs '%s' failed", range);
            ret = -1;
            goto out;
        }
    }

out:
    context_free(tmp);
    return ret;
}

static int parse_label_security_opt(const char *label_opt, context_t pcon, context_t mcon)
{
    int ret = 0;
    bool failure = false;
    char **items = NULL;
    size_t items_len = 0;

    items = util_string_split_n(label_opt, ':', 2);
    if (items == NULL) {
        ERROR("split label '%s' failed", label_opt);
        ret = -1;
        goto out;
    }

    items_len = util_array_len((const char **)items);
    if (items_len != 2 || strlen(items[1]) == 0) {
        isulad_set_error_message("Bad security label option \"%s\"", label_opt);
        ERROR("Bad security label option \"%s\"", label_opt);
        ret = -1;
        goto out;
    }

    if (!valid_options(items[0])) {
        isulad_set_error_message("Bad label option \"%s\", valid options 'disable, user, role, level, type'", items[0]);
        ERROR("Bad label option \"%s\", valid options 'disable, user, role, level, type'", items[0]);
        ret = -1;
        goto out;
    }

    if (strcmp(items[0], "type") == 0) {
        failure = (context_type_set(pcon, items[1]) != 0);
    } else if (strcmp(items[0], "user") == 0) {
        failure = (context_user_set(pcon, items[1]) != 0 || context_user_set(mcon, items[1]) != 0);
    } else if (strcmp(items[0], "role") == 0) {
        failure = (context_role_set(pcon, items[1]) != 0);
    } else if (strcmp(items[0], "level") == 0) {
        failure = (context_range_set(pcon, items[1]) != 0 || context_range_set(mcon, items[1]) != 0);
    } else {
        failure = true;
    }

    if (failure) {
        isulad_set_error_message("Failed to set selinux context: %s", label_opt);
        ERROR("Failed to set selinux context: %s", label_opt);
        ret = -1;
        goto out;
    }

out:
    util_free_array(items);
    return ret;
}

// InitLabels returns the process label and file labels to be used within
// the container.  A list of options can be passed into this function to alter
// the labels.  The labels returned will include a random MCS String, that is
// guaranteed to be unique.
int init_label(const char **label_opts, size_t label_opts_len, char **dst_process_label, char **dst_mount_label)
{
    int ret = 0;
    char *process_label = NULL;
    char *mount_label = NULL;
    context_t pcon = NULL;
    context_t mcon = NULL;

    if (!selinux_get_enable()) {
        return 0;
    }

    if (container_label(&process_label, &mount_label) != 0) {
        ret = -1;
        goto out;
    }

    if (process_label != NULL) {
        size_t i;
        pcon = context_new(process_label);
        mcon = context_new(mount_label);
        for (i = 0; i < label_opts_len; i++) {
            if (strcmp(label_opts[i], "disable") == 0) {
                goto out;
            }
            if (strstr(label_opts[i], ":") == NULL) {
                isulad_set_error_message("Bad label option %s, valid options 'disable"
                                         " or user, role, level, type' followed by ':' and a value",
                                         label_opts[i]);
                ERROR("Bad label option %s, valid options 'disable' or \n"
                      "'user, role, level, type' followed by ':' and a value",
                      label_opts[i]);
                ret = -1;
                goto out;
            }

            if (parse_label_security_opt(label_opts[i], pcon, mcon) != 0) {
                ERROR("Failed to parse security label option");
                ret = -1;
                goto out;
            }
        }
        if (release_label(process_label) != 0) {
            ERROR("Failed to release process label: %s", process_label);
            ret = -1;
            goto out;
        }
        free(process_label);
        process_label = util_strdup_s(context_str(pcon));
        free(mount_label);
        mount_label = util_strdup_s(context_str(mcon));
        if (reserve_label(process_label) != 0) {
            ERROR("Failed to release process label: %s", process_label);
            ret = -1;
            goto out;
        }
    }

    *dst_process_label = process_label;
    *dst_mount_label = mount_label;
    process_label = NULL;
    mount_label = NULL;

out:
    context_free(pcon);
    context_free(mcon);
    free(process_label);
    free(mount_label);
    return ret;
}

static bool is_exclude_relabel_path(const char *path)
{
    const char *exclude_path[] = { "/", "/usr", "/etc", "/tmp", "/home", "/run", "/var", "/root" };
    size_t i;

    for (i = 0; i < sizeof(exclude_path) / sizeof(char *); i++) {
        if (strcmp(path, exclude_path[i]) == 0) {
            return true;
        }
    }

    return false;
}

// Prevent users from relabing system files
static int bad_prefix(const char *fpath)
{
    const char *bad_prefixes = "/usr";

    if (fpath == NULL) {
        ERROR("Empty file path");
        return -1;
    }

    if (strncmp(fpath, bad_prefixes, strlen(bad_prefixes)) == 0) {
        ERROR("relabeling content in %s is not allowed", bad_prefixes);
        return -1;
    }

    return 0;
}

static int recurse_set_file_label(const char *basePath, const char *label)
{
    int ret = 0;
    DIR *dir = NULL;
    struct dirent *ptr = NULL;
    char base[PATH_MAX] = { 0 };

    if ((dir = opendir(basePath)) == NULL) {
        ERROR("Failed to Open dir: %s", basePath);
        return -1;
    }

    ret = lsetfilecon(basePath, label);
    if (ret != 0) {
        ERROR("Failed to set file label");
        goto out;
    }

    while ((ptr = readdir(dir)) != NULL) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        } else {
            int nret = snprintf(base, sizeof(base), "%s/%s", basePath, ptr->d_name);
            if (nret < 0 || nret >= sizeof(base)) {
                ERROR("Failed to get path");
                ret = -1;
                goto out;
            }
            if (ptr->d_type == DT_DIR) {
                ret = recurse_set_file_label(base, label);
                if (ret != 0) {
                    ERROR("Failed to set dir label");
                    goto out;
                }
            } else {
                ret = lsetfilecon(base, label);
                if (ret != 0) {
                    ERROR("Failed to set file label");
                    goto out;
                }
            }
        }
    }

out:
    closedir(dir);
    return ret;
}

// Chcon changes the `fpath` file object to the SELinux label `label`.
// If `fpath` is a directory and `recurse`` is true, Chcon will walk the
// directory tree setting the label.
static int selinux_chcon(const char *fpath, const char *label, bool recurse)
{
    struct stat s_buf;

    if (fpath == NULL) {
        ERROR("Empty file path");
        return -1;
    }

    if (label == NULL) {
        return 0;
    }

    if (bad_prefix(fpath) != 0) {
        return -1;
    }
    if (stat(fpath, &s_buf) != 0) {
        return -1;
    }
    if (recurse && S_ISDIR(s_buf.st_mode)) {
        return recurse_set_file_label(fpath, label);
    }

    if (lsetfilecon(fpath, label) != 0) {
        ERROR("Failed to set file label");
        return -1;
    }

    return 0;
}

// Relabel changes the label of path to the filelabel string.
// It changes the MCS label to s0 if shared is true.
// This will allow all containers to share the content.
int relabel(const char *path, const char *file_label, bool shared)
{
    int ret = 0;
    char *tmp_file_label = NULL;

    if (!selinux_get_enable()) {
        return 0;
    }

    if (file_label == NULL) {
        return 0;
    }

    tmp_file_label = util_strdup_s(file_label);
    if (is_exclude_relabel_path(path)) {
        ERROR("SELinux relabeling of %s is not allowed", path);
        ret = -1;
        goto out;
    }

    if (shared) {
        context_t c = context_new(file_label);
        context_range_set(c, "s0");
        free(tmp_file_label);
        tmp_file_label = util_strdup_s(context_str(c));
        context_free(c);
    }

    if (selinux_chcon(path, tmp_file_label, true) != 0) {
        ERROR("Failed to modify %s's selinux context: %s", path, tmp_file_label);
        ret = -1;
        goto out;
    }

out:
    free(tmp_file_label);
    return ret;
}

static int append_security_opt_string(const char *field, const char *value, char ***security_opts)
{
    int ret = 0;
    int nret = 0;
    char *sec_opt = NULL;
    size_t temp_len = strlen(field) + strlen(value) + 1;

    sec_opt = util_common_calloc_s(temp_len);
    if (sec_opt == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    nret = snprintf(sec_opt, temp_len, "%s%s", field, value);
    if (nret < 0 || nret >= temp_len) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (util_array_append(security_opts, sec_opt) < 0) {
        ERROR("Failed to append element to array");
        ret = -1;
        goto out;
    }

out:
    free(sec_opt);
    return ret;
}

// DupSecOpt takes an SELinux process label and returns security options that
// can be used to set the SELinux Type and Level for future container processes.
int dup_security_opt(const char *src, char ***dst, size_t *len)
{
    int ret = 0;
    size_t new_len = 3;
    char **security_opts = NULL;

    if (src == NULL) {
        return 0;
    }

    context_t con = context_new(src);
    if (context_user_get(con) == NULL || context_role_get(con) == NULL || context_type_get(con) == NULL) {
        return 0;
    }
    if (context_range_get(con) != NULL) {
        new_len++;
    }

    if (append_security_opt_string("user:", context_user_get(con), &security_opts) != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (append_security_opt_string("role:", context_role_get(con), &security_opts) != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (append_security_opt_string("type:", context_type_get(con), &security_opts) != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (context_range_get(con) != NULL) {
        if (append_security_opt_string("level:", context_range_get(con), &security_opts) != 0) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
    }
    *dst = security_opts;
    *len = new_len;

    security_opts = NULL;

out:
    util_free_array(security_opts);
    context_free(con);
    return ret;
}

int get_disable_security_opt(char ***labels, size_t *labels_len)
{
    if (util_array_append(labels, "disable") != 0) {
        ERROR("Failed to append label");
        return -1;
    }

    *labels_len = util_array_len((const char **)(*labels));

    return 0;
}

#define MOUNT_CONTEXT "context="

static char *fill_selinux_label_with_src(const char *src, const char *mount_label)
{
    int nret = 0;
    char *result = NULL;
    size_t data_size = 0;

    if (strlen(mount_label) >= (INT_MAX - strlen(src) - strlen(MOUNT_CONTEXT) - 4)) {
        ERROR("mount_label string too large");
        goto err_out;
    }

    data_size = strlen(src) + 1 + strlen(MOUNT_CONTEXT) + 2 + strlen(mount_label) + 1;

    result = util_common_calloc_s(data_size);
    if (result == NULL) {
        ERROR("Memory out");
        goto err_out;
    }

    nret = snprintf(result, data_size, "%s,%s\"%s\"", src, MOUNT_CONTEXT, mount_label);
    if (nret < 0 || (size_t)nret >= data_size) {
        ERROR("failed to snprintf selinux label");
        goto err_out;
    }

    goto out;

err_out:
    free(result);
    result = NULL;

out:
    return result;
}

static char *fill_selinux_label_without_src(const char *mount_label)
{
    int nret = 0;
    char *result = NULL;
    size_t data_size = 0;

    if (strlen(mount_label) >= (INT_MAX - strlen(MOUNT_CONTEXT) - 3)) {
        ERROR("mount_label string too large");
        goto err_out;
    }

    data_size = strlen(MOUNT_CONTEXT) + strlen(mount_label) + 3;

    result = util_common_calloc_s(data_size);
    if (result == NULL) {
        ERROR("Memory out");
        goto err_out;
    }

    nret = snprintf(result, data_size, "%s\"%s\"", MOUNT_CONTEXT, mount_label);
    if (nret < 0 || (size_t)nret >= data_size) {
        ERROR("failed to snprintf selinux label");
        goto err_out;
    }

    goto out;

err_out:
    free(result);
    result = NULL;

out:
    return result;
}

char *selinux_format_mountlabel(const char *src, const char *mount_label)
{
    char *result = NULL;

    if (src == NULL && mount_label == NULL) {
        return NULL;
    }

    if (src != NULL && mount_label != NULL) {
        result = fill_selinux_label_with_src(src, mount_label);
    } else if (src == NULL) {
        result = fill_selinux_label_without_src(mount_label);
    } else {
        result = util_strdup_s(src);
    }

    return result;
}