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
 * Description: provide container stream callback function definition
 ********************************************************************************/
#define _GNU_SOURCE
#include "execution_stream.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <isula_libutils/container_attach_request.h>
#include <isula_libutils/container_attach_response.h>
#include <isula_libutils/container_config_v2.h>
#include <isula_libutils/container_copy_to_request.h>
#include <isula_libutils/container_exec_request.h>
#include <isula_libutils/container_exec_response.h>
#include <isula_libutils/container_path_stat.h>
#include <isula_libutils/host_config.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/timestamp.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>

#include "isula_libutils/log.h"
#include "io_wrapper.h"
#include "image_api.h"
#include "path.h"
#include "isulad_tar.h"
#include "container_api.h"
#include "error.h"
#include "isula_libutils/logger_json_file.h"
#include "constants.h"
#include "runtime_api.h"
#include "events_sender_api.h"
#include "service_container_api.h"
#include "io_handler.h"
#include "err_msg.h"
#include "event_type.h"
#include "stream_wrapper.h"
#include "utils.h"
#include "utils_file.h"
#include "utils_verify.h"

struct container_log_config {
    char *driver;
    char *path;
    int rotate;
    int64_t size;
};

static int container_exec_cb(const container_exec_request *request, container_exec_response **response, int stdinfd,
                             struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_exec_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->container_id == NULL) {
        ERROR("receive NULL Request id");
        cc = ISULAD_ERR_INPUT;
        ret = -1;
        goto pack_err_response;
    }

    if (!util_valid_container_id_or_name(request->container_id)) {
        ERROR("Invalid container name %s", request->container_id);
        isulad_set_error_message("Invalid container name %s", request->container_id);
        cc = ISULAD_ERR_EXEC;
        ret = -1;
        goto pack_err_response;
    }

    if (request->suffix != NULL && !util_valid_exec_suffix(request->suffix)) {
        ERROR("Invalid exec suffix %s", request->suffix);
        isulad_set_error_message("Invalid exec suffix %s", request->suffix);
        cc = ISULAD_ERR_EXEC;
        ret = -1;
        goto pack_err_response;
    }

    cont = containers_store_get(request->container_id);
    if (cont == NULL) {
        ERROR("No such container:%s", request->container_id);
        isulad_set_error_message("No such container:%s", request->container_id);
        cc = ISULAD_ERR_EXEC;
        ret = -1;
        goto pack_err_response;
    }

    id = cont->common_config->id;

    isula_libutils_set_log_prefix(id);

    if (exec_container(cont, request, *response, stdinfd, stdout_handler, stderr_handler) != 0) {
        ret = -1;
        goto out;
    }

    goto out;

pack_err_response:
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

out:
    container_unref(cont);
    return ret;
}

static int container_attach_cb_check(const container_attach_request *request, container_attach_response **response,
                                     uint32_t *cc, container_t **cont)
{
    char *name = NULL;

    *response = util_common_calloc_s(sizeof(container_attach_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        *cc = ISULAD_ERR_MEMOUT;
        return -1;
    }

    name = request->container_id;

    if (name == NULL) {
        DEBUG("Receive NULL Request id");
        *cc = ISULAD_ERR_INPUT;
        return -1;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        *cc = ISULAD_ERR_EXEC;
        return -1;
    }

    *cont = containers_store_get(name);
    if (*cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        *cc = ISULAD_ERR_EXEC;
        return -1;
    }
    return 0;
}

static int attach_check_container_state(const container_t *cont)
{
    int ret = 0;
    const char *id = cont->common_config->id;

    if (!container_is_running(cont->state)) {
        ERROR("Container is not running");
        isulad_set_error_message("Container is is not running.");
        ret = -1;
        goto out;
    }

    if (container_is_paused(cont->state)) {
        ERROR("Container %s is paused, unpause the container before attach.", id);
        isulad_set_error_message("Container %s is paused, unpause the container before attach.", id);
        ret = -1;
        goto out;
    }

    if (container_is_restarting(cont->state)) {
        ERROR("Container %s is restarting, wait until the container is running.", id);
        isulad_set_error_message("Container %s is restarting, wait until the container is running.", id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int attach_prepare_console(const container_t *cont, const container_attach_request *request, int stdinfd,
                                  struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                                  char **fifos, char **fifopath, pthread_t *tid)
{
    int ret = 0;
    const char *id = cont->common_config->id;

    if (request->attach_stdin || request->attach_stdout || request->attach_stderr) {
        if (create_daemon_fifos(id, cont->runtime, request->attach_stdin, request->attach_stdout,
                                request->attach_stderr, "attach", fifos, fifopath)) {
            ret = -1;
            goto out;
        }

        if (ready_copy_io_data(-1, true, request->stdin, request->stdout, request->stderr, stdinfd, stdout_handler,
                               stderr_handler, (const char **)fifos, tid)) {
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static void close_io_writer(const struct io_write_wrapper *stdout_handler,
                            const struct io_write_wrapper *stderr_handler)
{
    if (stdout_handler != NULL && stdout_handler->close_func != NULL) {
        (void)stdout_handler->close_func(stdout_handler->context, NULL);
    }
    if (stderr_handler != NULL && stderr_handler->close_func != NULL) {
        (void)stderr_handler->close_func(stderr_handler->context, NULL);
    }
}

static int container_attach_cb(const container_attach_request *request, container_attach_response **response,
                               int stdinfd, struct io_write_wrapper *stdout_handler,
                               struct io_write_wrapper *stderr_handler)
{
    char *id = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    char *fifos[3] = { NULL, NULL, NULL };
    char *fifopath = NULL;
    pthread_t tid = 0;
    container_t *cont = NULL;
    rt_attach_params_t params = { 0 };

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    if (container_attach_cb_check(request, response, &cc, &cont) < 0) {
        close_io_writer(stdout_handler, stderr_handler);
        goto pack_response;
    }
    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    if (attach_check_container_state(cont)) {
        close_io_writer(stdout_handler, stderr_handler);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (attach_prepare_console(cont, request, stdinfd, stdout_handler, stderr_handler, fifos, &fifopath, &tid) != 0) {
        cc = ISULAD_ERR_EXEC;
        close_io_writer(stdout_handler, stderr_handler);
        goto pack_response;
    }

    params.rootpath = cont->root_path;
    params.stdin = fifos[0];
    params.stdout = fifos[1];
    params.stderr = fifos[2];

    (void)isulad_monitor_send_container_event(id, ATTACH, -1, 0, NULL, NULL);

    if (runtime_attach(cont->common_config->id, cont->runtime, &params)) {
        ERROR("Runtime attach container failed");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

pack_response:
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    delete_daemon_fifos(fifopath, (const char **)fifos);
    free(fifos[0]);
    free(fifos[1]);
    free(fifos[2]);
    free(fifopath);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int copy_from_container_cb_check(const struct isulad_copy_from_container_request *request,
                                        struct isulad_copy_from_container_response **response, container_t **cont)
{
    int ret = -1;
    char *name = NULL;

    *response = util_common_calloc_s(sizeof(struct isulad_copy_from_container_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    name = request->id;
    if (name == NULL) {
        ERROR("receive NULL Request id");
        goto out;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        goto out;
    }

    if (request->srcpath == NULL || request->srcpath[0] == '\0') {
        ERROR("bad parameter: path cannot be empty");
        isulad_set_error_message("bad parameter: path cannot be empty");
        goto out;
    }

    *cont = containers_store_get(name);
    if (*cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int archive_and_send_copy_data(const stream_func_wrapper *stream,
                                      struct isulad_copy_from_container_response *response, const char *resolvedpath,
                                      const char *abspath)
{
    int ret = -1;
    int nret;
    size_t buf_len = ARCHIVE_BLOCK_SIZE;
    ssize_t read_len;
    char *srcdir = NULL;
    char *srcbase = NULL;
    char *absbase = NULL;
    char *err = NULL;
    char *buf = NULL;
    char cleaned[PATH_MAX + 2] = { 0 };
    struct io_read_wrapper reader = { 0 };

    buf = util_common_calloc_s(buf_len);
    if (buf == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (cleanpath(resolvedpath, cleaned, sizeof(cleaned)) == NULL) {
        ERROR("Can not clean path: %s", resolvedpath);
        goto cleanup;
    }

    nret = split_dir_and_base_name(cleaned, &srcdir, &srcbase);
    if (nret != 0) {
        ERROR("split %s failed", cleaned);
        goto cleanup;
    }

    nret = split_dir_and_base_name(abspath, NULL, &absbase);
    if (nret != 0) {
        ERROR("split %s failed", abspath);
        goto cleanup;
    }
    nret = archive_path(srcdir, srcbase, absbase, false, &reader);
    if (nret != 0) {
        ERROR("Archive %s failed", resolvedpath);
        goto cleanup;
    }

    read_len = reader.read(reader.context, buf, buf_len);
    while (read_len > 0) {
        bool writed = true;
        response->data = buf;
        response->data_len = (size_t)read_len;
        writed = stream->write_func(stream->writer, response);
        response->data = NULL;
        response->data_len = 0;
        if (!writed) {
            DEBUG("Write to client failed, client may be exited");
            break;
        }
        read_len = reader.read(reader.context, buf, buf_len);
    }

    ret = 0;
cleanup:
    free(buf);
    free(srcdir);
    free(srcbase);
    free(absbase);
    if (reader.close != NULL) {
        int cret = reader.close(reader.context, &err);
        if (err != NULL) {
            isulad_set_error_message("%s", err);
        }
        ret = (cret != 0) ? cret : ret;
    }
    free(err);
    return ret;
}

static container_path_stat *do_container_stat_path(const char *rootpath, const char *resolvedpath, const char *abspath)
{
    int nret;
    char *hostpath = NULL;
    char *target = NULL;
    timestamp *mtime = NULL;
    struct stat st;
    container_path_stat *stat = NULL;

    nret = lstat(resolvedpath, &st);
    if (nret < 0) {
        ERROR("lstat %s: %s", resolvedpath, strerror(errno));
        isulad_set_error_message("lstat %s: %s", resolvedpath, strerror(errno));
        goto cleanup;
    }

    if (S_ISLNK(st.st_mode)) {
        char *p = NULL;
        hostpath = get_resource_path(rootpath, abspath);
        if (hostpath == NULL) {
            ERROR("Failed to get resource path");
            goto cleanup;
        }
        p = strstr(hostpath, rootpath);
        if (p == NULL) {
            ERROR("rootpath %s should be in scope of hostpath %s", rootpath, hostpath);
            goto cleanup;
        }
        target = util_path_join("/", p + strlen(rootpath));
        if (target == NULL) {
            ERROR("Can not join path");
            goto cleanup;
        }
    }

    mtime = util_common_calloc_s(sizeof(timestamp));
    if (mtime == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }

    stat = util_common_calloc_s(sizeof(container_path_stat));
    if (stat == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }
    nret = split_dir_and_base_name(abspath, NULL, &stat->name);
    if (nret != 0) {
        ERROR("split %s failed", abspath);
        goto cleanup;
    }
    stat->size = (int64_t)st.st_size;
    stat->mode = (uint32_t)st.st_mode;
    stat->mtime = mtime;
    mtime = NULL;
    stat->mtime->seconds = (int64_t)st.st_mtim.tv_sec;
    stat->mtime->nanos = (int32_t)st.st_mtim.tv_nsec;
    stat->link_target = target;
    target = NULL;

cleanup:
    free_timestamp(mtime);
    free(target);
    free(hostpath);
    return stat;
}

static int copy_from_container_send_path_stat(const stream_func_wrapper *stream, const container_path_stat *stat)
{
    int ret = -1;
    char *json = NULL;
    char *err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };

    json = container_path_stat_generate_json(stat, &ctx, &err);
    if (json == NULL) {
        ERROR("Can not generate json: %s", err);
        goto cleanup;
    }

    if (!stream->add_initial_metadata(stream->context, "isulad-container-path-stat", json)) {
        goto cleanup;
    }
    // send metadata, client should always ignore the first read
    if (!stream->write_func(stream->writer, NULL)) {
        goto cleanup;
    }

    ret = 0;
cleanup:
    free(json);
    free(err);
    return ret;
}

static container_path_stat *resolve_and_stat_path(const char *rootpath, const char *srcpath, char **resolvedpath,
                                                  char **abspath)
{
    int nret;
    char *resolved = NULL;
    char *abs = NULL;
    container_path_stat *stat = NULL;

    nret = resolve_path(rootpath, srcpath, &resolved, &abs);
    if (nret < 0) {
        ERROR("Can not resolve path: %s", srcpath);
        return NULL;
    }

    stat = do_container_stat_path(rootpath, resolved, abs);
    if (resolvedpath != NULL) {
        *resolvedpath = resolved;
        resolved = NULL;
    }
    if (abspath != NULL) {
        *abspath = abs;
        abs = NULL;
    }
    free(resolved);
    free(abs);
    return stat;
}

static int pause_container(const container_t *cont)
{
    int ret = 0;
    rt_pause_params_t params = { 0 };
    const char *id = cont->common_config->id;

    params.rootpath = cont->root_path;
    params.state = cont->state_path;
    if (runtime_pause(id, cont->runtime, &params)) {
        ERROR("Failed to pause container:%s", id);
        ret = -1;
        goto out;
    }

    container_state_set_paused(cont->state);

    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int resume_container(const container_t *cont)
{
    int ret = 0;
    rt_resume_params_t params = { 0 };
    const char *id = cont->common_config->id;

    params.rootpath = cont->root_path;
    params.state = cont->state_path;
    if (runtime_resume(id, cont->runtime, &params)) {
        ERROR("Failed to resume container:%s", id);
        ret = -1;
        goto out;
    }

    container_state_reset_paused(cont->state);

    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int copy_from_container_cb(const struct isulad_copy_from_container_request *request,
                                  const stream_func_wrapper *stream, char **err)
{
    int ret = -1;
    int nret;
    char *resolvedpath = NULL;
    char *abspath = NULL;
    container_path_stat *stat = NULL;
    container_t *cont = NULL;
    struct isulad_copy_from_container_response *response = NULL;
    bool need_pause = false;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || stream == NULL || err == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    if (copy_from_container_cb_check(request, &response, &cont) < 0) {
        goto pack_response;
    }

    container_lock(cont);

    if (container_is_removal_in_progress(cont->state) || container_is_dead(cont->state)) {
        ERROR("can't copy file from a container which is dead or marked for removal");
        isulad_set_error_message("can't copy file from a container which is dead or marked for removal");
        goto unlock_container;
    }

    need_pause = container_is_running(cont->state) && !container_is_paused(cont->state);
    if (need_pause) {
        if (pause_container(cont) != 0) {
            ERROR("can't copy to a container which is cannot be paused");
            isulad_set_error_message("can't copy to a container which is cannot be paused");
            goto unlock_container;
        }
    }

    nret = im_mount_container_rootfs(cont->common_config->image_type, cont->common_config->image,
                                     cont->common_config->id);
    if (nret != 0) {
        goto unpause_container;
    }

    stat = resolve_and_stat_path(cont->common_config->base_fs, request->srcpath, &resolvedpath, &abspath);
    if (stat == NULL) {
        goto cleanup_rootfs;
    }
    DEBUG("Got resolved path: %s, abspath: %s", resolvedpath, abspath);

    nret = copy_from_container_send_path_stat(stream, stat);
    if (nret < 0) {
        ERROR("Can not send metadata to client");
        goto cleanup_rootfs;
    }

    nret = archive_and_send_copy_data(stream, response, resolvedpath, abspath);
    if (nret < 0) {
        ERROR("Failed to send archive data");
        goto cleanup_rootfs;
    }

    (void)isulad_monitor_send_container_event(cont->common_config->id, ARCHIVE_PATH, -1, 0, NULL, NULL);
    ret = 0;
cleanup_rootfs:
    if (im_umount_container_rootfs(cont->common_config->image_type, cont->common_config->image,
                                   cont->common_config->id) != 0) {
        WARN("Can not umount rootfs of container: %s", cont->common_config->id);
    }
unpause_container:
    if (need_pause && resume_container(cont) != 0) {
        ERROR("can't resume container which has been paused before copy");
    }
unlock_container:
    container_unlock(cont);
    container_unref(cont);
pack_response:
    if (g_isulad_errmsg != NULL) {
        *err = util_strdup_s(g_isulad_errmsg);
    }
    isulad_copy_from_container_response_free(response);
    free_container_path_stat(stat);
    free(resolvedpath);
    free(abspath);
    DAEMON_CLEAR_ERRMSG();
    return ret;
}

static int copy_to_container_cb_check(const container_copy_to_request *request, container_t **cont)
{
    int ret = -1;
    char *name = NULL;

    name = request->id;
    if (name == NULL) {
        ERROR("receive NULL Request id");
        goto out;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        goto out;
    }

    if (request->src_path == NULL || request->src_path[0] == '\0') {
        ERROR("bad parameter: path cannot be empty");
        isulad_set_error_message("bad parameter: path cannot be empty");
        goto out;
    }

    *cont = containers_store_get(name);
    if (*cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static ssize_t extract_stream_to_io_read(void *content, void *buf, size_t buf_len)
{
    stream_func_wrapper *stream = (stream_func_wrapper *)content;
    struct isulad_copy_to_container_data copy = { 0 };

    if (!stream->read_func(stream->reader, &copy)) {
        DEBUG("Client may exited");
        return -1;
    }
    if (copy.data_len > buf_len) {
        free(copy.data);
        return -1;
    }
    (void)memcpy(buf, copy.data, copy.data_len);
    free(copy.data);
    return (ssize_t)(copy.data_len);
}

int read_and_extract_archive(stream_func_wrapper *stream, const char *resolved_path, const char *transform)
{
    int ret = -1;
    char *err = NULL;
    struct io_read_wrapper content = { 0 };

    content.context = stream;
    content.read = extract_stream_to_io_read;
    ret = archive_untar(&content, false, resolved_path, transform, &err);
    if (ret != 0) {
        ERROR("Can not untar to container: %s", (err != NULL) ? err : "unknown");
        isulad_set_error_message("Can not untar to container: %s", (err != NULL) ? err : "unknown");
    }
    free(err);
    return ret;
}

static char *copy_to_container_get_dstdir(const container_t *cont, const container_copy_to_request *request,
                                          char **transform)
{
    char *dstdir = NULL;
    char *error = NULL;
    container_path_stat *dststat = NULL;
    struct archive_copy_info srcinfo = { 0 };
    struct archive_copy_info *dstinfo = NULL;

    if (cont == NULL) {
        return NULL;
    }

    dstinfo = util_common_calloc_s(sizeof(struct archive_copy_info));
    if (dstinfo == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }
    dstinfo->path = util_strdup_s(request->dst_path);
    // stat once
    dststat = resolve_and_stat_path(cont->common_config->base_fs, request->dst_path, NULL, NULL);
    if (dststat != NULL) {
        if (S_ISLNK(dststat->mode)) {
            free(dstinfo->path);
            dstinfo->path = util_strdup_s(dststat->link_target);
            free_container_path_stat(dststat);
            // stat twice
            dststat = resolve_and_stat_path(cont->common_config->base_fs, dstinfo->path, NULL, NULL);
        }
        if (dststat != NULL) {
            dstinfo->exists = true;
            dstinfo->isdir = S_ISDIR(dststat->mode);
        }
    }
    // ignore any error
    DAEMON_CLEAR_ERRMSG();

    srcinfo.exists = true;
    srcinfo.isdir = request->src_isdir;
    srcinfo.path = request->src_path;
    srcinfo.rebase_name = request->src_rebase_name;

    dstdir = prepare_archive_copy(&srcinfo, dstinfo, transform, &error);
    if (dstdir == NULL) {
        if (error == NULL) {
            ERROR("Can not prepare archive copy");
        } else {
            ERROR("%s", error);
            isulad_set_error_message("%s", error);
        }
        goto cleanup;
    }
cleanup:
    free(error);
    free_archive_copy_info(dstinfo);
    free_container_path_stat(dststat);
    return dstdir;
}

static int copy_to_container_resolve_path(const container_t *cont, const char *dstdir, char **resolvedpath,
                                          char **abspath)
{
    int ret = -1;
    char *joined = NULL;
    char cleaned[PATH_MAX] = { 0 };

    if (cont == NULL) {
        return -1;
    }

    joined = util_path_join("/", dstdir);
    if (joined == NULL) {
        ERROR("Can not join path");
        return -1;
    }
    if (cleanpath(joined, cleaned, sizeof(cleaned)) == NULL) {
        ERROR("Can not clean path: %s", dstdir);
        goto cleanup;
    }
    *abspath = preserve_trailing_dot_or_separator(cleaned, dstdir);
    if (*abspath == NULL) {
        ERROR("Can not preserve path");
        goto cleanup;
    }

    *resolvedpath = get_resource_path(cont->common_config->base_fs, *abspath);
    if (*resolvedpath == NULL) {
        ERROR("Can not get resource path");
        goto cleanup;
    }
    ret = 0;
cleanup:
    free(joined);
    return ret;
}

static int copy_to_container_check_path_valid(const container_t *cont, const char *resolvedpath, const char *abspath)
{
    int ret = -1;
    int nret;
    struct stat st;

    if (cont == NULL) {
        return -1;
    }

    if (cont->hostconfig->readonly_rootfs) {
        ERROR("container rootfs is marked read-only");
        isulad_set_error_message("container rootfs is marked read-only");
        goto cleanup;
    }

    nret = lstat(resolvedpath, &st);
    if (nret < 0) {
        ERROR("lstat %s: %s", resolvedpath, strerror(errno));
        isulad_set_error_message("lstat %s: %s", resolvedpath, strerror(errno));
        goto cleanup;
    }

    if (!S_ISDIR(st.st_mode)) {
        ERROR("extraction point is not a directory");
        isulad_set_error_message("extraction point is not a directory");
        goto cleanup;
    }
    ret = 0;
cleanup:
    return ret;
}

static int copy_to_container_cb(const container_copy_to_request *request, stream_func_wrapper *stream, char **err)
{
    int ret = -1;
    int nret;
    char *resolvedpath = NULL;
    char *abspath = NULL;
    char *dstdir = NULL;
    char *transform = NULL;
    container_t *cont = NULL;
    bool need_pause = false;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || stream == NULL || err == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    if (copy_to_container_cb_check(request, &cont) < 0) {
        goto pack_response;
    }

    container_lock(cont);

    if (container_is_removal_in_progress(cont->state) || container_is_dead(cont->state)) {
        ERROR("can't copy to a container which is dead or marked for removal");
        isulad_set_error_message("can't copy to a container which is dead or marked for removal");
        goto unlock_container;
    }

    need_pause = container_is_running(cont->state) && !container_is_paused(cont->state);
    if (need_pause) {
        if (pause_container(cont) != 0) {
            ERROR("can't copy to a container which is cannot be paused");
            isulad_set_error_message("can't copy to a container which is cannot be paused");
            goto unlock_container;
        }
    }

    nret = im_mount_container_rootfs(cont->common_config->image_type, cont->common_config->image,
                                     cont->common_config->id);
    if (nret != 0) {
        goto unpause_container;
    }

    dstdir = copy_to_container_get_dstdir(cont, request, &transform);
    if (dstdir == NULL) {
        goto cleanup_rootfs;
    }

    nret = copy_to_container_resolve_path(cont, dstdir, &resolvedpath, &abspath);
    if (nret < 0) {
        goto cleanup_rootfs;
    }

    nret = copy_to_container_check_path_valid(cont, resolvedpath, abspath);
    if (nret < 0) {
        goto cleanup_rootfs;
    }

    nret = read_and_extract_archive(stream, resolvedpath, transform);
    if (nret < 0) {
        ERROR("Failed to send archive data");
        goto cleanup_rootfs;
    }

    (void)isulad_monitor_send_container_event(cont->common_config->id, EXTRACT_TO_DIR, -1, 0, NULL, NULL);
    ret = 0;

cleanup_rootfs:
    if (im_umount_container_rootfs(cont->common_config->image_type, cont->common_config->image,
                                   cont->common_config->id) != 0) {
        WARN("Can not umount rootfs of container: %s", cont->common_config->id);
    }

unpause_container:
    if (need_pause && resume_container(cont) != 0) {
        ERROR("can't resume container which has been paused before copy");
    }

unlock_container:
    container_unlock(cont);
    container_unref(cont);
pack_response:
    if (g_isulad_errmsg != NULL) {
        *err = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    free(resolvedpath);
    free(abspath);
    free(dstdir);
    free(transform);
    return ret;
}

static int container_logs_cb_check(const struct isulad_logs_request *request, struct isulad_logs_response *response)
{
    if (request == NULL || request->id == NULL) {
        response->cc = ISULAD_ERR_INPUT;
        ERROR("Receive NULL request or id");
        return -1;
    }

    if (!util_valid_container_id_or_name(request->id)) {
        ERROR("Invalid container name %s", request->id);
        response->cc = ISULAD_ERR_INPUT;
        if (asprintf(&(response->errmsg), "Invalid container name %s", request->id) < 0) {
            response->errmsg = util_strdup_s("Out of memory");
        }
        return -1;
    }

    return 0;
}

static int do_decode_write_log_entry(const char *json_str, const stream_func_wrapper *stream)
{
    bool write_ok = false;
    int ret = -1;
    parser_error jerr = NULL;
    logger_json_file *logentry = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY | OPT_GEN_NO_VALIDATE_UTF8, stderr };

    logentry = logger_json_file_parse_data(json_str, &ctx, &jerr);
    if (logentry == NULL) {
        ERROR("parse logentry: %s, failed: %s", json_str, jerr);
        goto out;
    }

    /* send to client */
    write_ok = stream->write_func(stream->writer, logentry);
    if (!write_ok) {
        ERROR("Send log to client failed");
        goto out;
    }

    ret = 0;
out:
    free_logger_json_file(logentry);
    free(jerr);
    return ret;
}

/*
 * return:
 *      <  0, mean read failed
 *      == 0, mean read zero line
 *      >  0, mean read many lines
 * */
static int64_t do_read_log_file(const char *path, int64_t require_line, long pos, const stream_func_wrapper *stream,
                                long *last_pos)
{
#define MAX_JSON_DECODE_RETRY 20
    int retries = 0;
    int decode_retries = 0;
    int64_t read_lines = 0;
    FILE *fp = NULL;
    char buffer[MAXLINE + 1] = { 0 };

    for (retries = 0; retries <= LOG_MAX_RETRIES; retries++) {
        fp = util_fopen(path, "r");
        if (fp != NULL || errno != ENOENT) {
            break;
        }
        /* fopen is too fast, need wait rename operator finish */
        usleep_nointerupt(1000);
    }
    if (fp == NULL) {
        ERROR("open file: %s failed: %s", path, strerror(errno));
        return -1;
    }
    if (pos > 0 && fseek(fp, pos, SEEK_SET) != 0) {
        ERROR("fseek to %ld failed: %s", pos, strerror(errno));
        read_lines = -1;
        goto out;
    }
    *last_pos = pos;

    while (fgets(buffer, MAXLINE, fp) != NULL) {
        (*last_pos) += (long)strlen(buffer);

        if (do_decode_write_log_entry(buffer, stream) != 0) {
            /* read a incomplete json object, try agin */
            decode_retries++;
            if (decode_retries < MAX_JSON_DECODE_RETRY) {
                continue;
            }
            read_lines = -1;
            goto out;
        }
        decode_retries = 0;

        read_lines++;
        if (read_lines == require_line) {
            break;
        }
    }

out:
    fclose(fp);
    return read_lines;
}

struct last_log_file_position {
    /* read file position */
    long pos;
    /* which log file */
    int file_index;
};

static int do_read_all_container_logs(int64_t require_line, const char *path, const stream_func_wrapper *stream,
                                      struct last_log_file_position *position)
{
    int ret = -1;
    int i = position->file_index;
    int64_t read_lines = 0;
    int64_t left_lines = require_line;
    long pos = position->pos;
    char log_path[PATH_MAX] = { 0 };

    for (; i > 0; i--) {
        int nret = snprintf(log_path, PATH_MAX, "%s.%d", path, i);
        if (nret >= PATH_MAX || nret < 0) {
            ERROR("Sprintf failed");
            goto out;
        }
        read_lines = do_read_log_file(log_path, left_lines, pos, stream, &(position->pos));
        if (read_lines < 0) {
            if (errno == ENOENT) {
                continue;
            }
            goto out;
        }
        /* only last file need pos */
        pos = 0;
        if (require_line < 0) {
            continue;
        }
        left_lines -= read_lines;
        if (left_lines <= 0) {
            /* get enough lines */
            ret = 0;
            goto out;
        }
    }
    read_lines = do_read_log_file(path, left_lines, pos, stream, &(position->pos));
    ret = read_lines < 0 ? -1 : 0;
out:
    position->file_index = i;
    return ret;
}

static int do_show_all_logs(const struct container_log_config *conf, const stream_func_wrapper *stream,
                            struct last_log_file_position *last_pos)
{
    int ret = 0;
    int index = conf->rotate - 1;
    char log_path[PATH_MAX] = { 0 };

    while (index > 0) {
        int nret = snprintf(log_path, PATH_MAX, "%s.%d", conf->path, index);
        if (nret >= PATH_MAX || nret < 0) {
            ERROR("Sprintf failed");
            ret = -1;
            goto out;
        }
        if (util_file_exists(log_path)) {
            break;
        }
        index--;
    }
    last_pos->file_index = index;
    last_pos->pos = 0;
    ret = do_read_all_container_logs(-1, conf->path, stream, last_pos);
out:
    return ret;
}

static int do_tail_find(FILE *fp, int64_t require_line, int64_t *get_line, long *get_pos)
{
#define SECTION_SIZE 4096
    char buffer[SECTION_SIZE] = { 0 };
    size_t read_size, i;
    long len, pos, step_size;
    int ret = -1;

    if (fseek(fp, 0L, SEEK_END) != 0) {
        ERROR("Fseek failed: %s", strerror(errno));
        goto out;
    }
    len = ftell(fp);
    if (len < 0) {
        ERROR("Ftell failed: %s", strerror(errno));
        goto out;
    }
    if (len < SECTION_SIZE) {
        pos = len;
        step_size = len;
    } else {
        step_size = SECTION_SIZE;
        pos = len - step_size;
    }
    while (true) {
        if (fseek(fp, pos, SEEK_SET) != 0) {
            ERROR("Fseek failed: %s", strerror(errno));
            goto out;
        }
        read_size = fread(buffer, sizeof(char), (size_t)step_size, fp);
        for (i = read_size; i > 0; i--) {
            if (buffer[i - 1] != '\n') {
                continue;
            }
            (*get_line) += 1;
            if ((*get_line) > require_line) {
                (*get_pos) = pos + (long)i;
                (*get_line) = require_line;
                ret = 0;
                goto out;
            }
        }
        if (pos == 0) {
            break;
        }
        if (pos < step_size) {
            step_size = pos;
            pos = 0;
        } else {
            pos -= step_size;
        }
    }

    ret = 0;
out:
    return ret;
}

static int util_find_tail_position(const char *file_name, int64_t require_line, int64_t *get_line, long *pos)
{
    FILE *fp = NULL;
    int ret = -1;

    if (file_name == NULL) {
        return 0;
    }
    if (get_line == NULL || pos == NULL) {
        ERROR("Invalid Arguments");
        return -1;
    }

    fp = util_fopen(file_name, "rb");
    if (fp == NULL) {
        ERROR("open file: %s failed: %s", file_name, strerror(errno));
        return -1;
    }

    ret = do_tail_find(fp, require_line, get_line, pos);

    fclose(fp);
    return ret;
}

static int do_tail_container_logs(int64_t require_line, const struct container_log_config *conf,
                                  const stream_func_wrapper *stream, struct last_log_file_position *last_pos)
{
    int i, ret;
    int64_t left = require_line;
    int64_t get_line = 0;
    long pos = 0;
    char log_path[PATH_MAX] = { 0 };

    if (require_line < 0) {
        /* read all logs */
        return do_show_all_logs(conf, stream, last_pos);
    }
    if (require_line == 0) {
        /* require empty logs */
        return 0;
    }
    ret = util_find_tail_position(conf->path, left, &get_line, &pos);
    if (ret != 0) {
        return -1;
    }
    if (pos != 0) {
        /* first line in first log file */
        get_line = do_read_log_file(conf->path, require_line, pos, stream, &(last_pos->pos));
        last_pos->file_index = 0;
        return get_line < 0 ? -1 : 0;
    }
    for (i = 1; i < conf->rotate; i++) {
        if (left <= get_line) {
            i--;
            break;
        }
        left -= get_line;
        get_line = 0;
        int nret = snprintf(log_path, PATH_MAX, "%s.%d", conf->path, i);
        if (nret >= PATH_MAX || nret < 0) {
            ERROR("Sprintf failed");
            goto out;
        }
        ret = util_find_tail_position(log_path, left, &get_line, &pos);
        if (ret != 0) {
            if (errno == ENOENT) {
                i--;
                break;
            }
            goto out;
        }
        if (pos != 0) {
            break;
        }
    }
    i = (i == conf->rotate ? i - 1 : i);

    last_pos->pos = pos;
    last_pos->file_index = i;
    ret = do_read_all_container_logs(require_line, conf->path, stream, last_pos);
out:
    return ret;
}

struct follow_args {
    const char *path;
    stream_func_wrapper *stream;
    bool *finish;
    long last_file_pos;
    int last_file_index;
};

static int handle_rotate(int fd, int wd, const char *path)
{
    int watch_fd = -1;
    int retries = 0;

    INFO("Do rotate...");
    if (inotify_rm_watch(fd, wd) < 0) {
        WARN("Rm watch failed");
    }

    for (; retries < LOG_MAX_RETRIES; retries++) {
        watch_fd = inotify_add_watch(fd, path, IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVE_SELF);
        if (watch_fd >= 0) {
            break;
        }
        usleep_nointerupt(1000);
    }
    if (watch_fd < 0) {
        SYSERROR("Add watch %s failed", path);
    }
    return watch_fd;
}

static void cleanup_handler(void *arg)
{
    int *fds = (int *)arg;

    if (fds[0] < 0) {
        return;
    }

    if (fds[1] >= 0 && inotify_rm_watch(fds[0], fds[1]) < 0) {
        SYSERROR("Rm watch failed");
    }
    close(fds[0]);
}

static int hanlde_events(int fd, const struct follow_args *farg)
{
    int write_cnt, rename_cnt;
    int watch_fd = 0;
    int ret = -1;
    size_t i = 0;
    ssize_t len = 0;
    struct inotify_event *c_event = NULL;
    char buf[MAXLINE] __attribute__((aligned(__alignof__(struct inotify_event)))) = { 0 };
    int clean_fds[2] = { fd, -1 };

    struct last_log_file_position last_pos = {
        .file_index = farg->last_file_index,
        .pos = farg->last_file_pos,
    };

    pthread_cleanup_push(cleanup_handler, clean_fds);

    watch_fd = inotify_add_watch(fd, farg->path, IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVE_SELF);
    if (watch_fd < 0) {
        SYSERROR("Add watch %s failed", farg->path);
        goto out;
    }
    clean_fds[1] = watch_fd;

    for (;;) {
        if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) {
            ERROR("set cancel state failed");
        }
        len = util_read_nointr(fd, buf, sizeof(buf));
        if (len < 0) {
            SYSERROR("Read inotify event failed");
            goto out;
        }
        if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0) {
            ERROR("set cancel state failed");
        }

        write_cnt = 0;
        rename_cnt = 0;
        for (i = 0; i < (size_t)len; i += (sizeof(struct inotify_event) + c_event->len)) {
            c_event = (struct inotify_event *)(&buf[i]);
            if (c_event->mask & IN_MODIFY) {
                write_cnt++;
            } else if (c_event->mask & (IN_DELETE | IN_MOVED_FROM | IN_MOVE_SELF)) {
                rename_cnt++;
            }
        }
        if (rename_cnt == 0 && write_cnt == 0) {
            continue;
        }

        last_pos.file_index = rename_cnt;
        if (do_read_all_container_logs(write_cnt, farg->path, farg->stream, &last_pos) != 0) {
            ERROR("Read all new logs failed");
            goto out;
        }
        if (rename_cnt > 0) {
            watch_fd = handle_rotate(fd, watch_fd, farg->path);
            if (watch_fd < 0) {
                goto out;
            }
            /* if terminal log file rotated and index of last_pos is not 0,
             * this mean we reach end of console.log.1. We need change last_pos
             * to begin of console.log.
             * */
            if (last_pos.file_index > 0) {
                last_pos.pos = 0;
                last_pos.file_index = 0;
            }
        }
    }

out:
    pthread_cleanup_pop(1);
    return ret;
}

static void *follow_thread_func(void *arg)
{
    int inotify_fd = 0;
    struct follow_args *farg = (struct follow_args *)arg;

    prctl(PR_SET_NAME, "logs-worker");

    INFO("Get args, path: %s, last pos: %ld, last file: %d", farg->path, farg->last_file_pos, farg->last_file_index);

    inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd < 0) {
        SYSERROR("Init inotify failed");
        goto set_flag;
    }

    if (hanlde_events(inotify_fd, farg) != 0) {
        ERROR("Handle inotify event failed");
    }

set_flag:
    *(farg->finish) = true;
    return NULL;
}

static int do_follow_log_file(const char *cid, stream_func_wrapper *stream, struct last_log_file_position *last_pos,
                              const char *path)
{
    int ret = 0;
    bool finish = false;
    bool *finish_pointer = &finish;
    pthread_t thread = 0;

    struct follow_args arg = {
        .path = path,
        .last_file_pos = last_pos->pos,
        .last_file_index = last_pos->file_index,
        .stream = stream,
        .finish = finish_pointer,
    };
    container_t *cont = NULL;

    ret = pthread_create(&thread, NULL, follow_thread_func, &arg);
    if (ret != 0) {
        ERROR("Thread create failed");
        return -1;
    }

    cont = containers_store_get(cid);
    if (cont == NULL) {
        ERROR("No such container:%s", cid);
        ret = -1;
        goto out;
    }

    /* check whether need finish */
    while (true) {
        if (finish) {
            ret = -1;
            break;
        }
        if (!container_is_running(cont->state)) {
            break;
        }
        if (stream->is_cancelled(stream->context)) {
            ret = -1;
            break;
        }
        usleep_nointerupt(10000);
    }

out:
    if (pthread_cancel(thread) != 0) {
        ERROR("cancel log work thread failed");
        ret = -1;
    }
    if (pthread_join(thread, NULL) != 0) {
        ERROR("Joint log work failed");
        ret = -1;
    }
    container_unref(cont);
    return ret;
}

static int check_log_config(const struct container_log_config *log_config)
{
    if (log_config == NULL) {
        ERROR("Log config is NULL");
        return -1;
    }
    if (log_config->path == NULL) {
        isulad_set_error_message("Do not set log path");
        ERROR("Do not set log path");
        return -1;
    }
    if (strcmp(log_config->path, "none") == 0) {
        ERROR("Disable console log");
        isulad_set_error_message("disable console log");
        return -1;
    }
    return 0;
}

static int container_get_container_log_config(const container_t *cont, struct container_log_config **log_config)
{
    *log_config = (struct container_log_config *)util_common_calloc_s(sizeof(struct container_log_config));
    if (*log_config == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    (*log_config)->path = util_strdup_s(cont->log_path);
    (*log_config)->driver = util_strdup_s(cont->log_driver);
    (*log_config)->rotate = cont->log_rotate;
    (*log_config)->size = cont->log_maxsize;

    return 0;
}

static void pack_logs_response(struct isulad_logs_response *response, uint32_t cc)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
}

static bool support_logs(struct container_log_config *log_config)
{
    if (log_config->driver == NULL) {
        return true;
    }

    // syslog do not support logs
    if (strcmp(CONTAINER_LOG_CONFIG_SYSLOG_DRIVER, log_config->driver) == 0) {
        return false;
    }

    return true;
}

static void container_log_config_free(struct container_log_config *conf)
{
    if (conf == NULL) {
        return;
    }
    free(conf->path);
    conf->path = NULL;
    free(conf->driver);
    conf->driver = NULL;
    conf->rotate = 0;
    conf->size = 0;
    free(conf);
}

static int container_logs_cb(const struct isulad_logs_request *request, stream_func_wrapper *stream,
                             struct isulad_logs_response **response)
{
    int nret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;
    container_t *cont = NULL;
    struct container_log_config *log_config = NULL;
    struct last_log_file_position last_pos = { 0 };
    Container_Status status = CONTAINER_STATUS_UNKNOWN;

    *response = (struct isulad_logs_response *)util_common_calloc_s(sizeof(struct isulad_logs_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    (*response)->cc = ISULAD_SUCCESS;

    /* check request */
    if (container_logs_cb_check(request, *response) != 0) {
        goto out;
    }

    cont = containers_store_get(request->id);
    if (cont == NULL) {
        ERROR("No such container: %s", request->id);
        cc = ISULAD_ERR_EXEC;
        isulad_set_error_message("No such container: %s", request->id);
        goto out;
    }
    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    status = container_state_get_status(cont->state);
    if (status == CONTAINER_STATUS_CREATED) {
        goto out;
    }

    /* check state of container */
    if (container_is_in_gc_progress(id)) {
        isulad_set_error_message("can not get logs from container which is dead or marked for removal");
        cc = ISULAD_ERR_EXEC;
        ERROR("can not get logs from container which is dead or marked for removal");
        goto out;
    }
    if (container_get_container_log_config(cont, &log_config) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }
    if (!support_logs(log_config)) {
        isulad_set_error_message("Do not support logs for log driver: %s", log_config->driver);
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    EVENT("Event: {Object: %s, Content: path: %s, rotate: %d, size: %ld }", id, log_config->path, log_config->rotate,
          log_config->size);

    nret = check_log_config(log_config);
    if (nret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    /* tail of container log file */
    if (do_tail_container_logs(request->tail, log_config, stream, &last_pos) != 0) {
        isulad_set_error_message("do tail log file failed");
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    if (!request->follow) {
        goto out;
    }

    if (!container_is_running(cont->state)) {
        goto out;
    }

    /* follow of container log file */
    if (do_follow_log_file(id, stream, &last_pos, log_config->path) != 0) {
        isulad_set_error_message("do follow log file failed");
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

out:
    pack_logs_response(*response, cc);

    container_unref(cont);
    container_log_config_free(log_config);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

void container_stream_callback_init(service_container_callback_t *cb)
{
    cb->attach = container_attach_cb;
    cb->exec = container_exec_cb;
    cb->copy_from_container = copy_from_container_cb;
    cb->copy_to_container = copy_to_container_cb;
    cb->logs = container_logs_cb;
}
