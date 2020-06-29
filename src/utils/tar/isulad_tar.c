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
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stdbool.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <libtar.h>

#include "isulad_tar.h"
#include "utils.h"
#include "path.h"
#include "isula_libutils/log.h"
#include "error.h"
#include "isula_libutils/json_common.h"

#define TAR_MAX_OPTS 50
#define TAR_CMD "tar"
#define TAR_TRANSFORM_OPT "--transform"
#define TAR_CREATE_OPT "-c"
#define TAR_EXACT_OPT "-x"
#define TAR_CHDIR_OPT "-C"
#define TAR_GZIP_OPT "-z"
#define TAR_DEFAULT_MODE 0600
#define TAR_DEFAULT_FLAG (O_WRONLY | O_CREAT)

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

/*
 * compress file.
 * param filename:      archive file to compres.
 * return:              zero if compress success, non-zero if not.
 */
int gzip(const char *filename, size_t len)
{
    int pipefd[2] = { -1, -1 };
    int status = 0;
    pid_t pid = 0;

    if (filename == NULL) {
        return -1;
    }
    if (len == 0) {
        return -1;
    }

    if (pipe2(pipefd, O_CLOEXEC) != 0) {
        ERROR("Failed to create pipe\n");
        return -1;
    }

    pid = fork();
    if (pid == -1) {
        ERROR("Failed to fork()\n");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        // child process, dup2 pipefd[1] to stderr
        close(pipefd[0]);
        dup2(pipefd[1], 2);

        if (!util_valid_cmd_arg(filename)) {
            fprintf(stderr, "Invalid filename: %s\n", filename);
            exit(EXIT_FAILURE);
        }

        execlp("gzip", "gzip", "-f", filename, NULL);

        fprintf(stderr, "Failed to exec gzip");
        exit(EXIT_FAILURE);
    }

    ssize_t size_read = 0;
    char buffer[BUFSIZ] = { 0 };

    close(pipefd[1]);

    if (waitpid(pid, &status, 0) != pid) {
        close(pipefd[0]);
        return -1;
    }

    size_read = read(pipefd[0], buffer, BUFSIZ);
    close(pipefd[0]);

    if (size_read) {
        ERROR("Received error:\n%s", buffer);
    }
    return status;
}

struct archive_context {
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    pid_t pid;
};

static ssize_t archive_context_read(void *context, void *buf, size_t len)
{
    struct archive_context *ctx = (struct archive_context *)context;
    if (ctx == NULL) {
        return -1;
    }
    if (ctx->stdout_fd >= 0) {
        return util_read_nointr(ctx->stdout_fd, buf, len);
    }
    return 0;
}

static ssize_t archive_context_write(const void *context, const void *buf, size_t len)
{
    struct archive_context *ctx = (struct archive_context *)context;
    if (ctx == NULL) {
        return -1;
    }
    if (ctx->stdin_fd >= 0) {
        return util_write_nointr(ctx->stdin_fd, buf, len);
    }
    return 0;
}

static int close_wait_pid(struct archive_context *ctx, int *status)
{
    int ret = 0;

    // close stdin and stdout first, this will make sure the process of tar exit.
    if (ctx->stdin_fd >= 0) {
        close(ctx->stdin_fd);
    }

    if (ctx->stdout_fd >= 0) {
        close(ctx->stdout_fd);
    }

    if (ctx->pid > 0) {
        if (waitpid(ctx->pid, status, 0) != ctx->pid) {
            ERROR("Failed to wait pid %u", ctx->pid);
            ret = -1;
        }
    }

    return ret;
}

static int archive_context_close(void *context, char **err)
{
    int ret = 0;
    int status = 0;
    char *reason = NULL;
    ssize_t size_read = 0;
    char buffer[BUFSIZ + 1] = { 0 };
    struct archive_context *ctx = (struct archive_context *)context;
    char *marshaled = NULL;

    if (ctx == NULL) {
        return 0;
    }

    ret = close_wait_pid(ctx, &status);

    if (WIFSIGNALED((unsigned int)status)) {
        status = WTERMSIG(status);
        reason = "signaled";
    } else if (WIFEXITED(status)) {
        status = WEXITSTATUS(status);
        reason = "exited";
    } else {
        reason = "unknown";
    }

    if (ctx->stderr_fd >= 0) {
        size_read = util_read_nointr(ctx->stderr_fd, buffer, BUFSIZ);
        if (size_read > 0) {
            reason = buffer;
            char *err_info = NULL;
            marshaled = json_marshal_string(buffer, (size_t)size_read, NULL, &err_info);
            if (marshaled == NULL) {
                ERROR("Can not marshal json buffer: %s", err_info);
            } else {
                reason = marshaled;
            }
            free(err_info);
        }
        close(ctx->stderr_fd);
    }

    if (size_read > 0 || status != 0) {
        format_errorf(err, "tar exited with status %d: %s", status, reason);
        ret = -1;
    }

    free(marshaled);
    free(ctx);
    return ret;
}

static int get_rebase_name(const char *path, const char *real_path,
                           char **resolved_path, char **rebase_name)
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

    if (specify_current_dir(path) && !specify_current_dir(real_path)) {
        set_char_to_separator(&resolved[strlen(resolved)]);
        resolved[strlen(resolved)] = '.';
    }

    if (has_trailing_path_separator(path) && !has_trailing_path_separator(resolved)) {
        resolved[strlen(resolved)] = '/';
    }

    nret = split_dir_and_base_name(path, NULL, &path_base);
    if (nret != 0) {
        ERROR("split %s failed", path);
        goto cleanup;
    }
    nret = split_dir_and_base_name(resolved, NULL, &resolved_base);
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

int resolve_host_source_path(const char *path, bool follow_link,
                             char **resolved_path, char **rebase_name, char **err)
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
        nret = filepath_split(path, &dirpath, &basepath);
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
        nret = split_dir_and_base_name(path, NULL, &tmp_path_base);
        if (nret != 0) {
            ERROR("split %s failed", path);
            goto cleanup;
        }

        nret = split_dir_and_base_name(resolved, NULL, &tmp_resolved_base);
        if (nret != 0) {
            ERROR("split %s failed", resolved);
            goto cleanup;
        }

        if (has_trailing_path_separator(path) && strcmp(tmp_path_base, tmp_resolved_base) != 0) {
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

static int copy_info_destination_path_ret(struct archive_copy_info *info,
                                          struct stat st, char **err, int ret, const char *path)
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
            if (split_path_dir_entry(iter_path, &parent, NULL) < 0) {
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

        if (split_path_dir_entry(iter_path, &dst_parent, NULL) < 0) {
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
    return has_trailing_path_separator(path) || specify_current_dir(path);
}

static char *format_transform_of_tar(const char *srcbase, const char *dstbase)
{
    char *transform = NULL;
    const char *src_escaped = srcbase;
    const char *dst_escaped = dstbase;
    int nret;
    size_t len;

    if (srcbase == NULL || dstbase == NULL) {
        return NULL;
    }

    // escape "/" by "." to avoid generating leading / in tar archive which is dangerous to host when untar.
    // this means tar or untar with leading / is forbidden and may got error, take care of this when coding.
    if (strcmp(srcbase, "/") == 0) {
        src_escaped = ".";
    }

    if (strcmp(dstbase, "/") == 0) {
        dst_escaped = ".";
    }

    len = strlen(src_escaped) + strlen(dst_escaped) + 5;
    if (len > PATH_MAX) {
        ERROR("Invalid path length");
        return NULL;
    }

    transform = util_common_calloc_s(len);
    if (transform == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    nret = snprintf(transform, len, "s/%s/%s/", src_escaped, dst_escaped);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Failed to print string");
        free(transform);
        return NULL;
    }
    return transform;
}

char *prepare_archive_copy(const struct archive_copy_info *srcinfo, const struct archive_copy_info *dstinfo,
                           char **transform, char **err)
{
    char *dstdir = NULL;
    char *srcbase = NULL;
    char *dstbase = NULL;

    if (split_path_dir_entry(dstinfo->path, &dstdir, &dstbase) < 0) {
        goto cleanup;
    }
    if (split_path_dir_entry(srcinfo->path, NULL, &srcbase) < 0) {
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
        *transform = format_transform_of_tar(srcbase, dstbase);
    } else if (srcinfo->isdir) {
        // dst does not exist and src is a directory, untar the content to parent of dest,
        // and rename basename of src name to dest's basename.
        if (srcinfo->rebase_name != NULL) {
            free(srcbase);
            srcbase = util_strdup_s(srcinfo->rebase_name);
        }
        *transform = format_transform_of_tar(srcbase, dstbase);
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
        *transform = format_transform_of_tar(srcbase, dstbase);
    }

cleanup:
    free(srcbase);
    free(dstbase);
    return dstdir;
}

static void close_pipe_fd(int pipe_fd[])
{
    if (pipe_fd[0] != -1) {
        close(pipe_fd[0]);
        pipe_fd[0] = -1;
    }
    if (pipe_fd[1] != -1) {
        close(pipe_fd[1]);
        pipe_fd[1] = -1;
    }
}

int archive_untar(const struct io_read_wrapper *content, bool compression, const char *dstdir,
                  const char *transform, char **err)
{
    int stdin_pipe[2] = { -1, -1 };
    int stderr_pipe[2] = { -1, -1 };
    int ret = -1;
    int cret = 0;
    pid_t pid;
    struct archive_context *ctx = NULL;
    char *buf = NULL;
    size_t buf_len = ARCHIVE_BLOCK_SIZE;
    ssize_t read_len;
    const char *params[TAR_MAX_OPTS] = { NULL };

    buf = util_common_calloc_s(buf_len);
    if (buf == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (pipe(stderr_pipe) != 0) {
        ERROR("Failed to create pipe: %s", strerror(errno));
        goto cleanup;
    }
    if (pipe(stdin_pipe) != 0) {
        ERROR("Failed to create pipe: %s", strerror(errno));
        goto cleanup;
    }

    pid = fork();
    if (pid == (pid_t) - 1) {
        ERROR("Failed to fork: %s", strerror(errno));
        goto cleanup;
    }

    if (pid == (pid_t)0) {
        int i = 0;
        // child process, dup2 stderr[1] to stderr, stdout[0] to stdin.
        close(stderr_pipe[0]);
        dup2(stderr_pipe[1], 2);
        close(stdin_pipe[1]);
        dup2(stdin_pipe[0], 0);

        params[i++] = TAR_CMD;
        params[i++] = TAR_EXACT_OPT;
        if (compression) {
            params[i++] = TAR_GZIP_OPT;
        }
        params[i++] = TAR_CHDIR_OPT;
        params[i++] = dstdir;
        if (transform != NULL) {
            params[i++] = TAR_TRANSFORM_OPT;
            params[i++] = transform;
        }

        execvp(TAR_CMD, (char * const *)params);

        fprintf(stderr, "Failed to exec tar: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    close(stderr_pipe[1]);
    stderr_pipe[1] = -1;
    close(stdin_pipe[0]);
    stdin_pipe[0] = -1;

    ctx = util_common_calloc_s(sizeof(struct archive_context));
    if (ctx == NULL) {
        goto cleanup;
    }

    ctx->pid = pid;
    ctx->stdin_fd = stdin_pipe[1];
    stdin_pipe[1] = -1;
    ctx->stdout_fd = -1;
    ctx->stderr_fd = stderr_pipe[0];
    stderr_pipe[0] = -1;

    read_len = content->read(content->context, buf, buf_len);
    while (read_len > 0) {
        ssize_t writed_len = archive_context_write(ctx, buf, (size_t)read_len);
        if (writed_len < 0) {
            DEBUG("Tar may exited: %s", strerror(errno));
            break;
        }
        read_len = content->read(content->context, buf, buf_len);
    }

    ret = 0;

cleanup:
    free(buf);
    cret = archive_context_close(ctx, err);
    ret = (cret != 0) ? cret : ret;
    close_pipe_fd(stderr_pipe);
    close_pipe_fd(stdin_pipe);

    return ret;
}

int archive_copy_to(const struct io_read_wrapper *content, bool compression, const struct archive_copy_info *srcinfo,
                    const char *dstpath, char **err)
{
    int ret = -1;
    struct archive_copy_info *dstinfo = NULL;
    char *dstdir = NULL;
    char *transform = NULL;

    dstinfo = copy_info_destination_path(dstpath, err);
    if (dstinfo == NULL) {
        ERROR("Can not get destination info: %s", dstpath);
        return -1;
    }

    dstdir = prepare_archive_copy(srcinfo, dstinfo, &transform, err);
    if (dstdir == NULL) {
        ERROR("Can not prepare archive copy");
        goto cleanup;
    }

    ret = archive_untar(content, compression, dstdir, transform, err);

cleanup:
    free_archive_copy_info(dstinfo);
    free(dstdir);
    free(transform);
    return ret;
}

static void close_archive_pipes_fd(int *pipes, size_t pipe_size)
{
    size_t i = 0;

    for (i = 0; i < pipe_size; i++) {
        if (pipes[i] >= 0) {
            close(pipes[i]);
            pipes[i] = -1;
        }
    }
}

/*
 * Archive file or directory.
 * param src		:	file or directory to compression.
 * param compression	:	using gzip compression or not
 * param exclude_base	:	exclude source basename in the archived file or not
 * return		:	zero if archive success, non-zero if not.
 */
int archive_path(const char *srcdir, const char *srcbase, const char *rebase_name,
                 bool compression, struct io_read_wrapper *archive_reader)
{
    int stderr_pipe[2] = { -1, -1 };
    int stdout_pipe[2] = { -1, -1 };
    int ret = -1;
    pid_t pid;
    struct archive_context *ctx = NULL;
    char *transform = NULL;
    const char *params[TAR_MAX_OPTS] = { NULL };

    transform = format_transform_of_tar(srcbase, rebase_name);

    if (pipe(stderr_pipe) != 0) {
        ERROR("Failed to create pipe: %s", strerror(errno));
        goto free_out;
    }
    if (pipe(stdout_pipe) != 0) {
        ERROR("Failed to create pipe: %s", strerror(errno));
        goto free_out;
    }

    pid = fork();
    if (pid == (pid_t) - 1) {
        ERROR("Failed to fork: %s", strerror(errno));
        goto free_out;
    }

    if (pid == (pid_t)0) {
        int i = 0;
        // child process, dup2 stderr[1] to stderr, stdout[1] to stdout.
        close(stderr_pipe[0]);
        close(stdout_pipe[0]);
        dup2(stderr_pipe[1], 2);
        dup2(stdout_pipe[1], 1);

        params[i++] = TAR_CMD;
        params[i++] = TAR_CREATE_OPT;
        if (compression) {
            params[i++] = TAR_GZIP_OPT;
        }
        params[i++] = TAR_CHDIR_OPT;
        params[i++] = srcdir;
        if (transform != NULL) {
            params[i++] = TAR_TRANSFORM_OPT;
            params[i++] = transform;
        }
        params[i++] = srcbase;

        execvp(TAR_CMD, (char * const *)params);

        fprintf(stderr, "Failed to exec tar: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    close(stderr_pipe[1]);
    stderr_pipe[1] = -1;
    close(stdout_pipe[1]);
    stdout_pipe[1] = -1;

    ctx = util_common_calloc_s(sizeof(struct archive_context));
    if (ctx == NULL) {
        goto free_out;
    }

    ctx->stdin_fd = -1;
    ctx->stdout_fd = stdout_pipe[0];
    stdout_pipe[0] = -1;
    ctx->stderr_fd = stderr_pipe[0];
    stderr_pipe[0] = -1;
    ctx->pid = pid;

    archive_reader->close = archive_context_close;
    archive_reader->context = ctx;
    ctx = NULL;
    archive_reader->read = archive_context_read;

    ret = 0;
free_out:
    free(transform);
    close_archive_pipes_fd(stderr_pipe, 2);
    close_archive_pipes_fd(stdout_pipe, 2);
    free(ctx);

    return ret;
}

int tar_resource_rebase(const char *path, const char *rebase, struct io_read_wrapper *archive_reader, char **err)
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
    if (split_path_dir_entry(path, &srcdir, &srcbase) < 0) {
        ERROR("Can not split path: %s", path);
        goto cleanup;
    }

    DEBUG("Copying %s from %s", srcbase, srcdir);
    nret = archive_path(srcdir, srcbase, rebase, false, archive_reader);
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

static int tar_all(char *path, int fd)
{
    TAR *tar = NULL;
    int ret = 0;

    ret = tar_fdopen(&tar, fd, NULL, NULL, TAR_DEFAULT_FLAG, TAR_DEFAULT_MODE, TAR_GNU);
    if (ret != 0) {
        ERROR("open file for exporting container rootfs failed: %s", strerror(errno));
        fprintf(stderr, "open file for exporting container rootfs failed: %s", strerror(errno));
        return -1;
    }

    ret = tar_append_tree(tar, path, ".");
    if (ret != 0) {
        ERROR("append files tree for exporting container rootfs failed: %s", strerror(errno));
        fprintf(stderr, "append files tree for exporting container rootfs failed: %s", strerror(errno));
        goto out;
    }

out:

    tar_close(tar);
    tar = NULL;

    return ret;
}

int chroot_tar(char *path, char *file, char **errmsg)
{
    int ret = 0;
    pid_t pid;
    int pipe_for_read[2] = { -1, -1 };
    int keepfds[] = { -1, -1 };
    char errbuf[BUFSIZ] = {0};
    int fd = 0;

    if (pipe2(pipe_for_read, O_CLOEXEC) != 0) {
        ERROR("Failed to create pipe");
        ret = -1;
        goto cleanup;
    }

    pid = fork();
    if (pid == (pid_t) -1) {
        ERROR("Failed to fork()");
        ret = -1;
        close(pipe_for_read[0]);
        close(pipe_for_read[1]);
        goto cleanup;
    }

    if (pid == (pid_t)0) {
        keepfds[0] = isula_libutils_get_log_fd();
        keepfds[1] = pipe_for_read[1];
        ret = util_check_inherited_exclude_fds(true, keepfds, 2);
        if (ret != 0) {
            ERROR("Failed to close fds.");
            ret = -1;
            goto child_out;
        }

        // child process, dup2 pipe_for_read[1] to stderr,
        if (dup2(pipe_for_read[1], 2) < 0) {
            ERROR("Dup fd error: %s", strerror(errno));
            ret = -1;
            goto child_out;
        }

        fd = open(file, TAR_DEFAULT_FLAG, TAR_DEFAULT_MODE);
        if (fd < 0) {
            ERROR("Failed to open file %s for export: %s", file, strerror(errno));
            fprintf(stderr, "Failed to open file %s for export: %s", file, strerror(errno));
            ret = -1;
            goto child_out;
        }

        if (chroot(path) != 0) {
            ERROR("Failed to chroot to %s", path);
            fprintf(stderr, "Failed to chroot to %s", path);
            ret = -1;
            goto child_out;
        }

        if (chdir("/") != 0) {
            ERROR("Failed to chroot to /");
            fprintf(stderr, "Failed to chroot to /");
            ret = -1;
            goto child_out;
        }

        ret = tar_all("/", fd);

child_out:

        if (ret != 0) {
            exit(EXIT_FAILURE);
        } else {
            exit(EXIT_SUCCESS);
        }
    }

    ret = wait_for_pid(pid);
    if (ret != 0) {
        ERROR("tar failed");
        if (read(pipe_for_read[0], errbuf, BUFSIZ) < 0) {
            ERROR("read error message from child failed");
        }
        close(pipe_for_read[0]);
        pipe_for_read[0] = -1;
    }

    close(pipe_for_read[1]);
    pipe_for_read[1] = -1;

cleanup:
    if (errmsg != NULL && strlen(errbuf) != 0) {
        *errmsg = util_strdup_s(errbuf);
    }

    return ret;
}
