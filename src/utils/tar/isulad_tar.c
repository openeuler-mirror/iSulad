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
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide tar functions
 ********************************************************************************/
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "isulad_tar.h"
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>

#include "stdbool.h"
#include "utils.h"
#include "path.h"
#include "isula_libutils/log.h"
#include "error.h"
#include "isula_libutils/json_common.h"
#include "util_archive.h"

static void set_char_to_separator(char *p)
{
    *p = '/';
}

void free_archive_copy_info(struct archive_copy_info *info)
{
    if (info == NULL) {
        return;
    }
    free(info->path);
    info->path = NULL;
    free(info->rebase_name);
    info->rebase_name = NULL;
    free(info);
}

static int get_rebase_name(const char *path, const char *real_path, char **resolved_path, char **rebase_name)
{
    int nret;
    int ret = -1;
    char resolved[PATH_MAX + 3] = { 0 };
    char *path_base = NULL;
    char *resolved_base = NULL;

    nret = snprintf(resolved, PATH_MAX, "%s", real_path);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Failed to print string");
        return -1;
    }

    if (util_specify_current_dir(path) && !util_specify_current_dir(real_path)) {
        set_char_to_separator(&resolved[strlen(resolved)]);
        resolved[strlen(resolved)] = '.';
    }

    if (util_has_trailing_path_separator(path) && !util_has_trailing_path_separator(resolved)) {
        resolved[strlen(resolved)] = '/';
    }

    nret = util_split_dir_and_base_name(path, NULL, &path_base);
    if (nret != 0) {
        ERROR("split %s failed", path);
        goto cleanup;
    }
    nret = util_split_dir_and_base_name(resolved, NULL, &resolved_base);
    if (nret != 0) {
        ERROR("split %s failed", resolved);
        goto cleanup;
    }

    if (strcmp(path_base, resolved_base) != 0) {
        // path is a symlink
        *rebase_name = path_base;
        path_base = NULL;
    }

    *resolved_path = util_strdup_s(resolved);
    ret = 0;

cleanup:
    free(path_base);
    free(resolved_base);
    return ret;
}

int resolve_host_source_path(const char *path, bool follow_link, char **resolved_path, char **rebase_name, char **err)
{
    int ret = -1;
    int nret = 0;
    char real_path[PATH_MAX] = { 0 };
    char resolved[PATH_MAX] = { 0 };
    char *dirpath = NULL;
    char *basepath = NULL;
    char *tmp_path_base = NULL;
    char *tmp_resolved_base = NULL;

    *resolved_path = NULL;
    *rebase_name = NULL;

    if (follow_link) {
        if (realpath(path, real_path) == NULL) {
            ERROR("Can not get real path of %s: %s", real_path, strerror(errno));
            format_errorf(err, "Can not get real path of %s: %s", real_path, strerror(errno));
            return -1;
        }
        nret = get_rebase_name(path, real_path, resolved_path, rebase_name);
        if (nret < 0) {
            ERROR("Failed to get rebase name");
            return -1;
        }
    } else {
        nret = util_filepath_split(path, &dirpath, &basepath);
        if (nret < 0) {
            ERROR("Can not split path %s", path);
            format_errorf(err, "Can not split path %s", path);
            goto cleanup;
        }
        if (realpath(dirpath, real_path) == NULL) {
            ERROR("Can not get real path of %s: %s", dirpath, strerror(errno));
            format_errorf(err, "Can not get real path of %s: %s", dirpath, strerror(errno));
            goto cleanup;
        }
        nret = snprintf(resolved, sizeof(resolved), "%s/%s", real_path, basepath);
        if (nret < 0 || (size_t)nret >= sizeof(resolved)) {
            ERROR("Path is too long");
            goto cleanup;
        }
        *resolved_path = util_strdup_s(resolved);
        nret = util_split_dir_and_base_name(path, NULL, &tmp_path_base);
        if (nret != 0) {
            ERROR("split %s failed", path);
            goto cleanup;
        }

        nret = util_split_dir_and_base_name(resolved, NULL, &tmp_resolved_base);
        if (nret != 0) {
            ERROR("split %s failed", resolved);
            goto cleanup;
        }

        if (util_has_trailing_path_separator(path) && strcmp(tmp_path_base, tmp_resolved_base) != 0) {
            *rebase_name = tmp_path_base;
            tmp_path_base = NULL;
        }
    }
    ret = 0;
cleanup:
    free(dirpath);
    free(basepath);
    free(tmp_path_base);
    free(tmp_resolved_base);
    return ret;
}

struct archive_copy_info *copy_info_source_path(const char *path, bool follow_link, char **err)
{
    int nret;
    struct archive_copy_info *info = NULL;
    struct stat st;
    char *resolved_path = NULL;
    char *rebase_name = NULL;

    info = util_common_calloc_s(sizeof(struct archive_copy_info));
    if (info == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    nret = resolve_host_source_path(path, follow_link, &resolved_path, &rebase_name, err);
    if (nret < 0) {
        goto cleanup;
    }

    nret = lstat(resolved_path, &st);
    if (nret < 0) {
        ERROR("lstat %s: %s", resolved_path, strerror(errno));
        format_errorf(err, "lstat %s: %s", resolved_path, strerror(errno));
        goto cleanup;
    }

    info->path = resolved_path;
    resolved_path = NULL;
    info->exists = true;
    info->isdir = S_ISDIR(st.st_mode);
    info->rebase_name = rebase_name;
    rebase_name = NULL;

    return info;
cleanup:
    free(resolved_path);
    free(rebase_name);
    free(info);
    return NULL;
}

static int copy_info_destination_path_ret(struct archive_copy_info *info, struct stat st, char **err, int ret,
                                          const char *path)
{
    int i;
    int max_symlink_iter = 10;
    char *iter_path = NULL;

    iter_path = util_strdup_s(path);
    for (i = 0; i <= max_symlink_iter && ret == 0 && S_ISLNK(st.st_mode); i++) {
        char target[PATH_MAX + 1] = { 0 };
        char *parent = NULL;

        ret = (int)readlink(iter_path, target, PATH_MAX);
        if (ret < 0) {
            ERROR("Failed to read link of %s: %s", iter_path, strerror(errno));
            format_errorf(err, "Failed to read link of %s: %s", iter_path, strerror(errno));
            goto cleanup;
        }
        // is not absolutely path
        if (target[0] != '\0') {
            if (util_split_path_dir_entry(iter_path, &parent, NULL) < 0) {
                goto cleanup;
            }
            free(iter_path);
            iter_path = util_path_join(parent, target);
            if (iter_path == NULL) {
                ERROR("Failed to join path");
                free(parent);
                goto cleanup;
            }
        } else {
            free(iter_path);
            iter_path = util_strdup_s(target);
        }
        ret = lstat(iter_path, &st);
        free(parent);
    }

    if (i > max_symlink_iter) {
        ERROR("Too many symlinks in: %s", path);
        format_errorf(err, "Too many symlinks in: %s", path);
        goto cleanup;
    }

    if (ret != 0) {
        char *dst_parent = NULL;
        if (errno != ENOENT) {
            ERROR("Can not stat %s: %s", iter_path, strerror(errno));
            format_errorf(err, "Can not stat %s: %s", iter_path, strerror(errno));
            goto cleanup;
        }

        if (util_split_path_dir_entry(iter_path, &dst_parent, NULL) < 0) {
            goto cleanup;
        }

        if (!util_dir_exists(dst_parent)) {
            ERROR("Path %s is not exists or not a directory", dst_parent);
            format_errorf(err, "Path %s is not exists or not a directory", dst_parent);
            free(dst_parent);
            goto cleanup;
        }
        free(dst_parent);
        info->path = iter_path;
        return 0;
    }

    info->path = iter_path;
    info->exists = true;
    info->isdir = S_ISDIR(st.st_mode);
    return 0;
cleanup:
    free(iter_path);
    return -1;
}

struct archive_copy_info *copy_info_destination_path(const char *path, char **err)
{
    struct archive_copy_info *info = NULL;
    struct stat st;
    int ret = 0;
    int nret = -1;

    info = util_common_calloc_s(sizeof(struct archive_copy_info));
    if (info == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    ret = lstat(path, &st);
    if (ret == 0 && !S_ISLNK(st.st_mode)) {
        info->path = util_strdup_s(path);
        info->exists = true;
        info->isdir = S_ISDIR(st.st_mode);
        return info;
    }

    nret = copy_info_destination_path_ret(info, st, err, ret, path);
    if (nret == 0) {
        return info;
    } else {
        goto cleanup;
    }
cleanup:
    free(info);
    return NULL;
}

static bool asserts_directory(const char *path)
{
    return util_has_trailing_path_separator(path) || util_specify_current_dir(path);
}

char *prepare_archive_copy(const struct archive_copy_info *srcinfo, const struct archive_copy_info *dstinfo,
                           char **src_base, char **dst_base, char **err)
{
    char *dstdir = NULL;
    char *srcbase = NULL;
    char *dstbase = NULL;

    if (util_split_path_dir_entry(dstinfo->path, &dstdir, &dstbase) < 0) {
        goto cleanup;
    }
    if (util_split_path_dir_entry(srcinfo->path, NULL, &srcbase) < 0) {
        goto cleanup;
    }

    if (dstinfo->exists && dstinfo->isdir) {
        // dst exists and is a directory, untar src content directly
        free(dstdir);
        dstdir = util_strdup_s(dstinfo->path);
    } else if (dstinfo->exists && srcinfo->isdir) {
        // dst exists and is a file, src content is a directory, report error
        format_errorf(err, "cannot copy directory to file");
        free(dstdir);
        dstdir = NULL;
    } else if (dstinfo->exists) {
        // dst exists and is a file, src is a file, rename basename of src name to dest's basename.
        if (srcinfo->rebase_name != NULL) {
            free(srcbase);
            srcbase = util_strdup_s(srcinfo->rebase_name);
        }
        *src_base = util_strdup_s(srcbase);
        *dst_base = util_strdup_s(dstbase);
    } else if (srcinfo->isdir) {
        // dst does not exist and src is a directory, untar the content to parent of dest,
        // and rename basename of src name to dest's basename.
        if (srcinfo->rebase_name != NULL) {
            free(srcbase);
            srcbase = util_strdup_s(srcinfo->rebase_name);
        }
        *src_base = util_strdup_s(srcbase);
        *dst_base = util_strdup_s(dstbase);
    } else if (asserts_directory(dstinfo->path)) {
        // dst does not exist and is want to be created as a directory, but src is not a directory, report error.
        format_errorf(err, "no such directory, can not copy file");
        free(dstdir);
        dstdir = NULL;
    } else {
        // dst does not exist and is not want to be created as a directory, and the src is not a directory,
        // create the dst file and renamed src content to basename of dst.
        if (srcinfo->rebase_name != NULL) {
            free(srcbase);
            srcbase = util_strdup_s(srcinfo->rebase_name);
        }
        *src_base = util_strdup_s(srcbase);
        *dst_base = util_strdup_s(dstbase);
    }

cleanup:
    free(srcbase);
    free(dstbase);
    return dstdir;
}

int archive_copy_to(const struct io_read_wrapper *content, const struct archive_copy_info *srcinfo,
                    const char *dstpath, char **err)
{
    int ret = -1;
    struct archive_copy_info *dstinfo = NULL;
    char *dstdir = NULL;
    char *src_base = NULL;
    char *dst_base = NULL;

    dstinfo = copy_info_destination_path(dstpath, err);
    if (dstinfo == NULL) {
        ERROR("Can not get destination info: %s", dstpath);
        return -1;
    }

    dstdir = prepare_archive_copy(srcinfo, dstinfo, &src_base, &dst_base, err);
    if (dstdir == NULL) {
        ERROR("Can not prepare archive copy");
        goto cleanup;
    }

    ret = archive_chroot_untar_stream(content, dstdir, ".", src_base, dst_base, err);

cleanup:
    free_archive_copy_info(dstinfo);
    free(dstdir);
    free(src_base);
    free(dst_base);
    return ret;
}

static int tar_resource_rebase(const char *path, const char *rebase, struct io_read_wrapper *archive_reader, char **err)
{
    int ret = -1;
    int nret;
    struct stat st;
    char *srcdir = NULL;
    char *srcbase = NULL;

    if (lstat(path, &st) < 0) {
        ERROR("lstat %s: %s", path, strerror(errno));
        format_errorf(err, "lstat %s: %s", path, strerror(errno));
        return -1;
    }
    if (util_split_path_dir_entry(path, &srcdir, &srcbase) < 0) {
        ERROR("Can not split path: %s", path);
        goto cleanup;
    }

    DEBUG("chroot tar stream srcdir(%s) srcbase(%s) rebase(%s)", srcdir, srcbase, rebase);
    nret = archive_chroot_tar_stream(srcdir, srcbase, srcbase, rebase, archive_reader);
    if (nret < 0) {
        ERROR("Can not archive path: %s", path);
        goto cleanup;
    }
    ret = 0;
cleanup:
    free(srcdir);
    free(srcbase);
    return ret;
}

int tar_resource(const struct archive_copy_info *info, struct io_read_wrapper *archive_reader, char **err)
{
    return tar_resource_rebase(info->path, info->rebase_name, archive_reader, err);
}
