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
 * Description: provide container list callback function definition
 ********************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <lcr/lcrcontainer.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <malloc.h>

#include "constants.h"
#include "isula_libutils/log.h"
#include "engine.h"
#include "console.h"
#include "isulad_config.h"
#include "config.h"
#include "image.h"
#include "execution.h"
#include "verify.h"
#include "isula_libutils/container_inspect.h"
#include "containers_store.h"
#include "supervisor.h"
#include "containers_gc.h"
#include "execution_extend.h"
#include "execution_information.h"
#include "execution_stream.h"
#include "execution_create.h"
#include "plugin.h"
#include "health_check.h"
#include "execution_network.h"
#include "runtime.h"
#include "specs_extend.h"
#include "utils.h"
#include "error.h"
#include "collector.h"
#include "specs.h"


static int filter_by_label(const container_t *cont, const container_get_id_request *request)
{
    int ret = 0;
    size_t i, len_key, len_val;
    char *p_equal = NULL;
    json_map_string_string *labels = NULL;

    if (request->label == NULL) {
        ret = 0;
        goto out;
    }

    if (cont->common_config->config == NULL || cont->common_config->config->labels == NULL || \
        cont->common_config->config->labels->len == 0) {
        ERROR("No such container: %s", request->id_or_name);
        isulad_set_error_message("No such container: %s", request->id_or_name);
        ret = -1;
        goto out;
    }
    p_equal = strchr(request->label, '=');
    if (p_equal == NULL) {
        ERROR("Invalid label: %s", request->label);
        isulad_set_error_message("Invalid label: %s", request->label);
        ret = -1;
        goto out;
    }
    len_key = (size_t)(p_equal - request->label);
    len_val = (strlen(request->label) - len_key) - 1;
    labels = cont->common_config->config->labels;
    for (i = 0; i < labels->len; i++) {
        if (strlen(labels->keys[i]) == len_key && strncmp(labels->keys[i], request->label, len_key) == 0 && \
            strlen(labels->values[i]) == len_val && strncmp(labels->values[i], p_equal + 1, len_val) == 0) {
            ret = 0;
            goto out;
        }
    }
    ret = -1;
    ERROR("No such container: %s", request->id_or_name);
    isulad_set_error_message("No such container: %s", request->id_or_name);

out:
    return ret;
}

static void pack_get_id_response(container_get_id_response *response, const char *id, uint32_t cc)
{
    if (response == NULL) {
        return;
    }

    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static void pack_get_runtime_response(container_get_runtime_response *response, const char *runtime, uint32_t cc)
{
    if (response == NULL) {
        return;
    }

    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (runtime != NULL) {
        response->runtime = util_strdup_s(runtime);
    }
}

/*
 * This function gets long id of container by name or short id
 */
static int container_get_id_cb(const container_get_id_request *request, container_get_id_response **response)
{
    char *id = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_get_id_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(request->id_or_name)) {
        ERROR("Invalid container name: %s", request->id_or_name ? request->id_or_name : "");
        isulad_set_error_message("Invalid container name: %s", request->id_or_name ? request->id_or_name : "");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(request->id_or_name);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container: %s", request->id_or_name);
        isulad_set_error_message("No such container: %s", request->id_or_name);
        goto pack_response;
    }

    if (filter_by_label(cont, request) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;

pack_response:
    pack_get_id_response(*response, id, cc);

    container_unref(cont);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int container_get_runtime_cb(const char *real_id, container_get_runtime_response **response)
{
    char *runtime = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (real_id == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_get_runtime_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(real_id)) {
        ERROR("Invalid container name: %s", real_id);
        isulad_set_error_message("Invalid container name: %s", real_id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(real_id);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container: %s", real_id);
        isulad_set_error_message("No such container: %s", real_id);
        goto pack_response;
    }

    runtime = cont->runtime;

pack_response:
    pack_get_runtime_response(*response, runtime, cc);

    container_unref(cont);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int send_signal_to_process(pid_t pid, unsigned long long start_time, uint32_t signal)
{
    if (util_process_alive(pid, start_time) == false) {
        if (signal == SIGTERM || signal == SIGKILL) {
            WARN("Process %d is not alive", pid);
            return 0;
        } else {
            ERROR("Process (pid=%d) is not alive, can not kill with signal %u", pid, signal);
            return -1;
        }
    } else {
        int ret = kill(pid, (int)signal);
        if (ret < 0) {
            ERROR("Can not kill process (pid=%d) with signal %u: %s", pid, signal, strerror(errno));
            return -1;
        }
    }

    return 0;
}

static int umount_dev_tmpfs_for_system_container(const container_t *cont)
{
    if (cont->hostconfig != NULL && cont->hostconfig->system_container && cont->hostconfig->external_rootfs != NULL) {
        char rootfs_dev_path[PATH_MAX] = { 0 };
        int nret = snprintf(rootfs_dev_path, sizeof(rootfs_dev_path), "%s/dev", cont->common_config->base_fs);
        if ((size_t)nret >= sizeof(rootfs_dev_path) || nret < 0) {
            ERROR("Out of memory");
            return -1;
        }
        if (umount(rootfs_dev_path) < 0 && errno != ENOENT) {
            WARN("Failed to umount dev tmpfs: %s, error: %s", rootfs_dev_path, strerror(errno));
        }
    }
    return 0;
}

static int do_clean_container(const container_t *cont, pid_t pid)
{
    int ret = 0;
    char *engine_log_path = NULL;
    char *loglevel = NULL;
    char *logdriver = NULL;
    const char *id = cont->common_config->id;
    const char *runtime = cont->runtime;
    rt_clean_params_t params = { 0 };

    if (conf_get_daemon_log_config(&loglevel, &logdriver, &engine_log_path) != 0) {
        ERROR("Failed to get log config");
        ret = -1;
        goto out;
    }

    params.rootpath = cont->root_path;
    params.statepath = cont->state_path;
    params.logpath = engine_log_path;
    params.loglevel = loglevel;
    params.pid = pid;

    ret = runtime_clean_resource(id, runtime, &params);
    if (ret != 0) {
        ERROR("Failed to clean failed started container %s", id);
        ret = -1;
        goto out;
    }

    if (im_umount_container_rootfs(cont->common_config->image_type, cont->common_config->image, id)) {
        ERROR("Failed to umount rootfs for container %s", id);
        ret = -1;
        goto out;
    }

    if (umount_dev_tmpfs_for_system_container(cont) < 0) {
        ret = -1;
        goto out;
    }

out:
    free(loglevel);
    free(engine_log_path);
    free(logdriver);
    return ret;
}

int clean_container_resource(const char *id, const char *runtime, pid_t pid)
{
    int ret = 0;
    container_t *cont = NULL;

    if (id == NULL || runtime == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    cont = containers_store_get(id);
    if (cont == NULL) {
        WARN("No such container:%s", id);
        goto out;
    }

    ret = do_clean_container(cont, pid);
    if (ret != 0) {
        ERROR("Runtime clean container resource failed");
        ret = -1;
        goto out;
    }
out:
    container_unref(cont);
    return ret;
}

static int start_request_check(const container_start_request *h)
{
    int ret = 0;

    if (h == NULL || h->id == NULL) {
        ERROR("recive NULL Request id");
        ret = -1;
        goto out;
    }

    if (!util_valid_container_id_or_name(h->id)) {
        ERROR("Invalid container name %s", h->id);
        isulad_set_error_message("Invalid container name %s", h->id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int prepare_start_state_files(const container_t *cont, char **exit_fifo, int *exit_fifo_fd, char **pid_file)
{
    int ret = 0;
    int nret = 0;
    char container_state[PATH_MAX] = { 0 };
    char pidfile[PATH_MAX] = { 0 };
    const char *id = cont->common_config->id;

    nret = snprintf(container_state, sizeof(container_state), "%s/%s", cont->state_path, id);
    if (nret < 0 || (size_t)nret >= sizeof(container_state)) {
        ERROR("Failed to sprintf container_state");
        ret = -1;
        goto out;
    }

    nret = util_mkdir_p(container_state, TEMP_DIRECTORY_MODE);
    if (nret < 0) {
        ERROR("Unable to create container state directory %s.", container_state);
        ret = -1;
        goto out;
    }

    nret = snprintf(pidfile, sizeof(pidfile), "%s/pid.file", container_state);
    if (nret < 0 || (size_t)nret >= sizeof(pidfile)) {
        ERROR("Failed to sprintf pidfile");
        ret = -1;
        goto out;
    }
    *pid_file = util_strdup_s(pidfile);
    if (*pid_file == NULL) {
        ERROR("Failed to dup pid file in state directory %s", container_state);
        ret = -1;
        goto out;
    }

    *exit_fifo = exit_fifo_create(container_state);
    if (*exit_fifo == NULL) {
        ERROR("Failed to create exit FIFO in state directory %s", container_state);
        ret = -1;
        goto out;
    }

    *exit_fifo_fd = exit_fifo_open(*exit_fifo);
    if (*exit_fifo_fd < 0) {
        ERROR("Failed to open exit FIFO %s", *exit_fifo);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static void umount_rootfs_on_failure(const container_t *cont)
{
    const char *id = cont->common_config->id;
    int nret = im_umount_container_rootfs(cont->common_config->image_type, cont->common_config->image, id);
    if (nret != 0) {
        ERROR("Failed to umount rootfs for container %s", id);
    }
}

static int chmod_runtime_bundle_permission(const char *runtime)
{
    int ret = 0;
    char *bundle_dir = NULL;
    char *engine_dir = NULL;
    char *root_dir = NULL;

    bundle_dir = conf_get_routine_rootdir(runtime);
    if (bundle_dir == NULL) {
        ret = -1;
        goto error_out;
    }

    engine_dir = conf_get_engine_rootpath();
    if (engine_dir == NULL) {
        ret = -1;
        goto error_out;
    }

    root_dir = conf_get_isulad_rootdir();
    if (root_dir == NULL) {
        ret = -1;
        goto error_out;
    }

    ret = chmod(bundle_dir, USER_REMAP_DIRECTORY_MODE);
    if (ret != 0) {
        ERROR("Failed to chmod bundle dir '%s' for user remap", bundle_dir);
        goto error_out;
    }
    ret = chmod(engine_dir, USER_REMAP_DIRECTORY_MODE);
    if (ret != 0) {
        ERROR("Failed to chmod engine dir '%s' for user remap", engine_dir);
        goto error_out;
    }
    ret = chmod(root_dir, USER_REMAP_DIRECTORY_MODE);
    if (ret != 0) {
        ERROR("Failed to chmod root dir '%s' for user remap", root_dir);
        goto error_out;
    }

error_out:
    free(bundle_dir);
    free(engine_dir);
    free(root_dir);
    return ret;
}

static int mount_host_channel(const host_config_host_channel *host_channel, const char *user_remap)
{
    char properties[MOUNT_PROPERTIES_SIZE] = { 0 };

    if (host_channel == NULL) {
        return 0;
    }
    if (util_detect_mounted(host_channel->path_on_host)) {
        return 0;
    }
    int nret = snprintf(properties, sizeof(properties), "mode=1777,size=%llu",
                        (long long unsigned int)host_channel->size);
    if (nret < 0 || (size_t)nret >= sizeof(properties)) {
        ERROR("Failed to generate mount properties");
        return -1;
    }
    if (mount("tmpfs", host_channel->path_on_host, "tmpfs",
              MS_NOEXEC | MS_NOSUID | MS_NODEV,
              (void *)properties)) {
        ERROR("Failed to mount host path '%s'", host_channel->path_on_host);
        return -1;
    }
    if (user_remap != NULL) {
        unsigned int host_uid = 0;
        unsigned int host_gid = 0;
        unsigned int size = 0;
        if (util_parse_user_remap(user_remap, &host_uid, &host_gid, &size)) {
            ERROR("Failed to split string '%s'.", user_remap);
            return -1;
        }
        if (chown(host_channel->path_on_host, host_uid, host_gid) != 0) {
            ERROR("Failed to chown host path '%s'.", host_channel->path_on_host);
            return -1;
        }
    }
    return 0;
}

static int mount_dev_tmpfs_for_system_container(const container_t *cont)
{
    char rootfs_dev_path[PATH_MAX] = { 0 };

    if (cont == NULL || cont->hostconfig == NULL || cont->common_config == NULL) {
        return 0;
    }
    if (!cont->hostconfig->system_container || cont->hostconfig->external_rootfs == NULL) {
        return 0;
    }
    int nret = snprintf(rootfs_dev_path, sizeof(rootfs_dev_path), "%s/dev", cont->common_config->base_fs);
    if (nret < 0 || (size_t)nret >= sizeof(rootfs_dev_path)) {
        ERROR("Out of memory");
        return -1;
    }
    if (!util_dir_exists(rootfs_dev_path)) {
        if (util_mkdir_p(rootfs_dev_path, CONFIG_DIRECTORY_MODE)) {
            ERROR("Failed to mkdir '%s'", rootfs_dev_path);
            return -1;
        }
    }
    /* set /dev mount size to half of container memory limit */
    if (cont->hostconfig->memory > 0) {
        char mnt_opt[MOUNT_PROPERTIES_SIZE] = { 0 };
        nret = snprintf(mnt_opt, sizeof(mnt_opt), "size=%lld,mode=755", (long long int)(cont->hostconfig->memory / 2));
        if (nret < 0 || (size_t)nret >= sizeof(mnt_opt)) {
            ERROR("Out of memory");
            return -1;
        }
        if (mount("tmpfs", rootfs_dev_path, "tmpfs", 0, mnt_opt) != 0) {
            ERROR("Failed to mount dev tmpfs on '%s'", rootfs_dev_path);
            return -1;
        }
    } else {
        if (mount("tmpfs", rootfs_dev_path, "tmpfs", 0, "mode=755") != 0) {
            ERROR("Failed to mount dev tmpfs on '%s'", rootfs_dev_path);
            return -1;
        }
    }
    if (cont->hostconfig->user_remap != NULL) {
        unsigned int host_uid = 0;
        unsigned int host_gid = 0;
        unsigned int size = 0;
        if (util_parse_user_remap(cont->hostconfig->user_remap, &host_uid, &host_gid, &size)) {
            ERROR("Failed to split string '%s'.", cont->hostconfig->user_remap);
            return -1;
        }
        if (chown(rootfs_dev_path, host_uid, host_gid) != 0) {
            ERROR("Failed to chown host path '%s'.", rootfs_dev_path);
            return -1;
        }
    }
    return 0;
}

static int prepare_user_remap_config(const container_t *cont)
{
    if (cont == NULL) {
        return 0;
    }

    if (cont->hostconfig == NULL) {
        return 0;
    }

    if (cont->hostconfig->user_remap != NULL) {
        if (chmod_runtime_bundle_permission(cont->runtime)) {
            ERROR("Failed to chmod bundle permission for user remap");
            return -1;
        }
    }

    if (cont->hostconfig->host_channel != NULL) {
        if (mount_host_channel(cont->hostconfig->host_channel, cont->hostconfig->user_remap)) {
            ERROR("Failed to mount host channel");
            return -1;
        }
    }
    return 0;
}

static int generate_user_and_groups_conf(const container_t *cont, defs_process_user **puser)
{
    int ret = -1;
    char *username = NULL;

    if (cont == NULL || cont->common_config == NULL) {
        ERROR("Can not found container config");
        return -1;
    }

    *puser = util_common_calloc_s(sizeof(defs_process_user));
    if (*puser == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (cont->common_config->config != NULL) {
        username = cont->common_config->config->user;
    }

    /* username may be NULL, we will handle it as UID 0 in get_user */
    ret = im_get_user_conf(cont->common_config->image_type, cont->common_config->base_fs, cont->hostconfig, username,
                           *puser);
    if (ret != 0) {
        ERROR("Get user failed with '%s'", username ? username : "");
        free_defs_process_user(*puser);
        *puser = NULL;
    }

    return ret;
}

static int create_env_path_dir(const char *env_path)
{
    int ret = 0;
    size_t len = 0;
    size_t i = 0;
    char *dir = NULL;

    len = strlen(env_path);
    if (len == 0) {
        return 0;
    }
    dir = util_strdup_s(env_path);
    for (i = len - 1; i > 0; i--) {
        if (dir[i] == '/') {
            dir[i] = '\0';
            break;
        }
    }
    if (strlen(dir) == 0) {
        free(dir);
        return 0;
    }
    ret = util_mkdir_p(dir, DEFAULT_SECURE_DIRECTORY_MODE);
    free(dir);
    return ret;
}

static int write_env_content(const char *env_path, const char **env, size_t env_len)
{
    int ret = 0;
    int fd = -1;
    size_t i = 0;
    ssize_t nret = 0;

    ret = create_env_path_dir(env_path);
    if (ret < 0) {
        ERROR("Failed to create env path dir");
        return ret;
    }
    fd = util_open(env_path, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_SECURE_FILE_MODE);
    if (fd < 0) {
        SYSERROR("Failed to create env file: %s", env_path);
        ret = -1;
        goto out;
    }
    if (env != NULL) {
        for (i = 0; i < env_len; i++) {
            size_t len = strlen(env[i]) + strlen("\n") + 1;
            char *env_content = NULL;
            env_content = util_common_calloc_s(len);
            if (env_content == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
            nret = snprintf(env_content, len, "%s\n", env[i]);
            if (nret < 0 || (size_t)nret >= len) {
                ERROR("Out of memory");
                free(env_content);
                ret = -1;
                goto out;
            }
            nret = util_write_nointr(fd, env_content, strlen(env_content));
            if (nret < 0 || nret != len - 1) {
                SYSERROR("Write env file failed");
                free(env_content);
                ret = -1;
                goto out;
            }
            free(env_content);
        }
    }
out:
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}

static int write_env_to_target_file(const container_t *cont, const oci_runtime_spec *oci_spec)
{
    int ret = 0;
    char *env_path = NULL;

    if (cont->hostconfig->env_target_file == NULL || oci_spec->process == NULL) {
        return 0;
    }
    env_path = util_path_join(cont->common_config->base_fs, cont->hostconfig->env_target_file);
    if (env_path == NULL) {
        ERROR("Failed to get env target file path: %s", cont->hostconfig->env_target_file);
        return -1;
    }
    ret = write_env_content(env_path,
                            (const char **)oci_spec->process->env,
                            oci_spec->process->env_len);
    free(env_path);
    return ret;
}

static int do_post_start_on_success(const char *id, const char *runtime,
                                    const char *pidfile, int exit_fifo_fd, const container_pid_t *pid_info)
{
    int ret = 0;

    // exit_fifo_fd was closed in supervisor_add_exit_monitor
    if (supervisor_add_exit_monitor(exit_fifo_fd, pid_info, id, runtime)) {
        ERROR("Failed to add exit monitor to supervisor");
        ret = -1;
    }
    return ret;
}

static void clean_resources_on_failure(const container_t *cont, const char *engine_log_path, const char *loglevel)
{
    int ret = 0;
    const char *id = cont->common_config->id;
    const char *runtime = cont->runtime;
    rt_clean_params_t params = { 0 };

    params.rootpath = cont->root_path;
    params.statepath = cont->state_path;
    params.logpath = engine_log_path;
    params.loglevel = loglevel;
    params.pid = 0;

    ret = runtime_clean_resource(id, runtime, &params);
    if (ret != 0) {
        ERROR("Failed to clean failed started container %s", id);
    }

    return;
}

static int update_process_user(const container_t *cont, const oci_runtime_spec *oci_spec)
{
    int ret = 0;
    defs_process_user *puser = NULL;

    if (generate_user_and_groups_conf(cont, &puser) != 0) {
        ret = -1;
        goto out;
    }

    free_defs_process_user(oci_spec->process->user);
    oci_spec->process->user = puser;
    puser = NULL;

out:
    free_defs_process_user(puser);
    return ret;
}

static int renew_oci_config(const container_t *cont, oci_runtime_spec *oci_spec)
{
    int ret = 0;

    ret = update_process_user(cont, oci_spec);
    if (ret != 0) {
        ERROR("Failed to update process user");
        goto out;
    }

    ret = merge_share_namespace(oci_spec, cont->hostconfig);
    if (ret != 0) {
        ERROR("Failed to merge share ns");
        goto out;
    }

out:
    return ret;
}

static int create_mtab_link(const oci_runtime_spec *oci_spec)
{
    char *pathname = "/proc/mounts";
    char *slink = NULL;
    char *dir = NULL;
    int ret = 0;

    if (oci_spec->root == NULL || oci_spec->root->path == NULL) {
        ERROR("Root path is NULL, can not create link /etc/mtab for target /proc/mounts");
        return -1;
    }

    slink = util_path_join(oci_spec->root->path, "/etc/mtab");
    if (slink == NULL) {
        ERROR("Failed to join path:%s with /etc/mtab", oci_spec->root->path);
        ret = -1;
        goto out;
    }

    dir = util_path_dir(slink);
    if (dir == NULL) {
        ERROR("Failed to get dir %s", slink);
        ret = -1;
        goto out;
    }

    if (unlink(dir) != 0) {
        WARN("Failed to delete \"%s\": %s", dir, strerror(errno));
    }

    if (util_fileself_exists(slink)) {
        goto out;
    }

    if (!util_dir_exists(dir)) {
        if (util_mkdir_p(dir, ETC_FILE_MODE) != 0) {
            ret = -1;
            ERROR("Unable to create mtab directory %s.", dir);
            goto out;
        }
    }

    if (symlink(pathname, slink) != 0) {
        ret = -1;
        SYSERROR("Failed to create \"%s\"", slink);
        goto out;
    }

out:
    free(slink);
    free(dir);
    return ret;
}

static int do_start_container(container_t *cont, const char *console_fifos[], bool reset_rm,
                              container_pid_t *pid_info)
{
    int ret = 0;
    int nret = 0;
    int exit_fifo_fd = -1;
    bool tty = false;
    bool open_stdin = false;
    unsigned int start_timeout = 0;
    char *engine_log_path = NULL;
    char *loglevel = NULL;
    char *logdriver = NULL;
    char *exit_fifo = NULL;
    char *pidfile = NULL;
    char bundle[PATH_MAX] = { 0 };
    const char *runtime = cont->runtime;
    const char *id = cont->common_config->id;
    oci_runtime_spec *oci_spec = NULL;
    rt_create_params_t create_params = { 0 };
    rt_start_params_t start_params = { 0 };

    nret = snprintf(bundle, sizeof(bundle), "%s/%s", cont->root_path, id);
    if (nret < 0 || (size_t)nret >= sizeof(bundle)) {
        ERROR("Failed to print bundle string");
        ret = -1;
        goto out;
    }
    DEBUG("bd:%s, state:%s", bundle, cont->state_path);
    if (mount_dev_tmpfs_for_system_container(cont) < 0) {
        ret = -1;
        goto out;
    }

    if (prepare_user_remap_config(cont) != 0) {
        ret = -1;
        goto out;
    }

    if (reset_rm && !reset_restart_manager(cont, true)) {
        ERROR("Failed to reset restart manager");
        isulad_set_error_message("Failed to reset restart manager");
        ret = -1;
        goto out;
    }

    if (conf_get_daemon_log_config(&loglevel, &logdriver, &engine_log_path) != 0) {
        ret = -1;
        goto out;
    }

    nret = prepare_start_state_files(cont, &exit_fifo, &exit_fifo_fd, &pidfile);
    if (nret != 0) {
        ret = -1;
        goto out;
    }

    oci_spec = load_oci_config(cont->root_path, id);
    if (oci_spec == NULL) {
        ERROR("Failed to load oci config");
        ret = -1;
        goto close_exit_fd;
    }

    if (write_env_to_target_file(cont, oci_spec) < 0) {
        ret = -1;
        goto close_exit_fd;
    }

    nret = im_mount_container_rootfs(cont->common_config->image_type, cont->common_config->image, id);
    if (nret != 0) {
        ERROR("Failed to mount rootfs for container %s", id);
        ret = -1;
        goto close_exit_fd;
    }

    nret = create_mtab_link(oci_spec);
    if (nret != 0) {
        ERROR("Failed to create link /etc/mtab for target /proc/mounts");
        ret = -1;
        goto close_exit_fd;
    }

    if (renew_oci_config(cont, oci_spec) != 0) {
        ret = -1;
        goto close_exit_fd;
    }

    if (verify_container_settings_start(oci_spec) != 0) {
        ret = -1;
        goto close_exit_fd;
    }

    if (save_oci_config(id, cont->root_path, oci_spec) != 0) {
        ERROR("Failed to save container settings");
        ret = -1;
        goto close_exit_fd;
    }

    start_timeout = conf_get_start_timeout();
    if (cont->common_config->config != NULL) {
        tty = cont->common_config->config->tty;
        open_stdin = cont->common_config->config->open_stdin;
    }

    if (plugin_event_container_pre_start(cont)) {
        ERROR("Plugin event pre start failed ");
        plugin_event_container_post_stop(cont); /* ignore error */
        ret = -1;
        goto close_exit_fd;
    }

    create_params.bundle = bundle;
    create_params.state = cont->state_path;
    create_params.oci_config_data = oci_spec;
    create_params.terminal = tty;
    create_params.stdin = console_fifos[0];
    create_params.stdout = console_fifos[1];
    create_params.stderr = console_fifos[2];
    create_params.exit_fifo = exit_fifo;
    create_params.tty = tty;
    create_params.open_stdin = open_stdin;

    if (runtime_create(id, runtime, &create_params) != 0) {
        ret = -1;
        goto close_exit_fd;
    }

    start_params.rootpath = cont->root_path;
    start_params.state = cont->state_path;
    start_params.tty = tty;
    start_params.open_stdin = open_stdin;
    start_params.logpath = engine_log_path;
    start_params.loglevel = loglevel;
    start_params.console_fifos = console_fifos;
    start_params.start_timeout = start_timeout;
    start_params.container_pidfile = pidfile;
    start_params.exit_fifo = exit_fifo;

    ret = runtime_start(id, runtime, &start_params, pid_info);
    if (ret == 0) {
        if (do_post_start_on_success(id, runtime, pidfile, exit_fifo_fd, pid_info) != 0) {
            ERROR("Failed to do post start on runtime start success");
            ret = -1;
            goto clean_resources;
        }
    } else {
        goto close_exit_fd;
    }
    goto out;

close_exit_fd:
    close(exit_fifo_fd);

clean_resources:
    clean_resources_on_failure(cont, engine_log_path, loglevel);

out:
    free(loglevel);
    free(engine_log_path);
    free(logdriver);
    free(exit_fifo);
    free(pidfile);
    free_oci_runtime_spec(oci_spec);
    if (ret != 0) {
        umount_rootfs_on_failure(cont);
        (void)umount_dev_tmpfs_for_system_container(cont);
    }
    return ret;
}

static bool save_after_auto_remove(container_t *cont)
{
    if (cont->hostconfig != NULL && cont->hostconfig->auto_remove) {
        int nret = set_container_to_removal(cont);
        if (nret != 0) {
            ERROR("Failed to set container %s state to removal", cont->common_config->id);
            return true;
        }
        container_unlock(cont);
        nret = cleanup_container(cont, true);
        container_lock(cont);
        if (nret != 0) {
            ERROR("Failed to cleanup container %s", cont->common_config->id);
            return true;
        }
        return false; /* do not save container if already auto removed */
    }

    return true;
}

int start_container(container_t *cont, const char *console_fifos[], bool reset_rm)
{
    int ret = 0;
    container_pid_t pid_info = { 0 };
    int exit_code = 125;

    if (cont == NULL || console_fifos == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    container_lock(cont);

    if (reset_rm && is_running(cont->state)) {
        ret = 0;
        goto out;
    }

    if (is_paused(cont->state)) {
        ERROR("Cannot start a paused container, try unpause instead");
        isulad_set_error_message("Cannot start a paused container, try unpause instead.");
        ret = -1;
        goto out;
    }

    if (is_removal_in_progress(cont->state) || is_dead(cont->state)) {
        ERROR("Container is marked for removal and cannot be started.");
        isulad_set_error_message("Container is marked for removal and cannot be started.");
        ret = -1;
        goto out;
    }

    if (gc_is_gc_progress(cont->common_config->id)) {
        isulad_set_error_message("You cannot start container %s in garbage collector progress.", cont->common_config->id);
        ERROR("You cannot start container %s in garbage collector progress.", cont->common_config->id);
        ret = -1;
        goto out;
    }

    ret = do_start_container(cont, console_fifos, reset_rm, &pid_info);
    if (ret != 0) {
        ERROR("Runtime start container failed");
        ret = -1;
        goto set_stopped;
    } else {
        state_set_running(cont->state, &pid_info, true);
        cont->common_config->has_been_manually_stopped = false;
        init_health_monitor(cont->common_config->id);
        goto save_container;
    }

set_stopped:
    container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
    util_contain_errmsg(g_isulad_errmsg, &exit_code);
    state_set_stopped(cont->state, exit_code);
    container_wait_stop_cond_broadcast(cont);
    if (!save_after_auto_remove(cont)) {
        goto out;
    }

save_container:
    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", cont->common_config->id);
        ret = -1;
        goto out;
    }
out:
    container_unlock(cont);
    return ret;
}

static int prepare_start_io(container_t *cont, const container_start_request *request,
                            char **fifopath, char *fifos[], int stdinfd, struct io_write_wrapper *stdout_handler,
                            struct io_write_wrapper *stderr_handler)
{
    int ret = 0;
    char *id = NULL;
    pthread_t tid = 0;

    id = cont->common_config->id;

    if (request->attach_stdin || request->attach_stdout || request->attach_stderr) {
        if (create_daemon_fifos(id, cont->runtime, request->attach_stdin, request->attach_stdout,
                                request->attach_stderr, "start", fifos, fifopath)) {
            ret = -1;
            goto out;
        }

        if (ready_copy_io_data(-1, true, request->stdin, request->stdout, request->stderr,
                               stdinfd, stdout_handler, stderr_handler, (const char **)fifos, &tid)) {
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static void pack_start_response(container_start_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }

    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static int container_start_prepare(container_t *cont, const container_start_request *request,
                                   int stdinfd, struct io_write_wrapper *stdout_handler,
                                   struct io_write_wrapper *stderr_handler,
                                   char **fifopath, char *fifos[])
{
    const char *id = cont->common_config->id;

    if (container_to_disk_locking(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        isulad_set_error_message("Failed to save container \"%s\" to disk", id);
        return -1;
    }

    if (prepare_start_io(cont, request, fifopath, fifos, stdinfd, stdout_handler, stderr_handler) != 0) {
        return -1;
    }

    return 0;
}

static int container_start_cb(const container_start_request *request, container_start_response **response,
                              int stdinfd, struct io_write_wrapper *stdout_handler,
                              struct io_write_wrapper *stderr_handler)
{
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;
    char *fifos[3] = { NULL, NULL, NULL };
    char *fifopath = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_start_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    if (start_request_check(request)) {
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    cont = containers_store_get(request->id);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container:%s", request->id);
        isulad_set_error_message("No such container:%s", request->id);
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Starting}", id);

    state_set_starting(cont->state);

    if (is_running(cont->state)) {
        INFO("Container is already running");
        goto pack_response;
    }

    if (container_start_prepare(cont, request, stdinfd, stdout_handler, stderr_handler, &fifopath, fifos) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (start_container(cont, (const char **)fifos, true) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Running}", id);
    (void)isulad_monitor_send_container_event(id, START, -1, 0, NULL, NULL);

pack_response:
    delete_daemon_fifos(fifopath, (const char **)fifos);
    free(fifos[0]);
    free(fifos[1]);
    free(fifos[2]);
    free(fifopath);
    pack_start_response(*response, cc, id);
    if (cont != NULL) {
        state_reset_starting(cont->state);
        container_unref(cont);
    }
    isula_libutils_free_log_prefix();
    malloc_trim(0);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int kill_with_signal(container_t *cont, uint32_t signal)
{
    int ret = 0;
    int nret = 0;
    const char *id = cont->common_config->id;
    bool need_unpause = is_paused(cont->state);
    rt_resume_params_t params = { 0 };
    char annotations[EXTRA_ANNOTATION_MAX] = {0};

    if (container_exit_on_next(cont)) {
        ERROR("Failed to cancel restart manager");
        ret = -1;
        goto out;
    }
    cont->common_config->has_been_manually_stopped = true;
    (void)container_to_disk(cont);

    if (!is_running(cont->state)) {
        INFO("Container %s is already stopped", id);
        ret = 0;
        goto out;
    }
    if (is_restarting(cont->state)) {
        INFO("Container %s is currently restarting we do not need to send the signal to the process", id);
        ret = 0;
        goto out;
    }

    stop_health_checks(id);

    ret = send_signal_to_process(cont->state->state->pid, cont->state->state->start_time, signal);
    if (ret != 0) {
        ERROR("Failed to send signal to container %s with signal %u", id, signal);
    }
    if (signal == SIGKILL && need_unpause) {
        params.rootpath = cont->root_path;
        params.state = cont->state_path;
        if (runtime_resume(id, cont->runtime, &params) != 0) {
            ERROR("Cannot unpause container: %s", id);
            ret = -1;
            goto out;
        }
    }

    nret = snprintf(annotations, sizeof(annotations), "signal=%u", signal);
    if (nret < 0 || (size_t)nret >= sizeof(annotations)) {
        ERROR("Failed to get signal string");
        ret = -1;
        goto out;
    }

    (void)isulad_monitor_send_container_event(id, KILL, -1, 0, NULL, annotations);

out:
    return ret;
}

static int force_kill(container_t *cont)
{
    int ret = 0;
    const char *id = cont->common_config->id;

    ret = kill_with_signal(cont, SIGKILL);
    if (ret != 0) {
        WARN("Failed to stop Container(%s), try to wait 'STOPPED' for 90 seconds", id);
    }
    ret = container_wait_stop(cont, 90);
    if (ret != 0) {
        WARN("Container(%s) stuck for 90 seconds, try to kill the monitor of container", id);
        ret = send_signal_to_process(cont->state->state->p_pid, cont->state->state->p_start_time, SIGKILL);
        if (ret != 0) {
            ERROR("Container stuck for 90 seconds and failed to kill the monitor of container, "
                  "please check the config");
            isulad_set_error_message("Container stuck for 90 seconds "
                                     "and failed to kill the monitor of container, please check configuration files");
            goto out;
        }
        ret = container_wait_stop(cont, -1);
    }
out:
    return ret;
}

int stop_container(container_t *cont, int timeout, bool force, bool restart)
{
    int ret = 0;
    char *id = NULL;

    if (cont == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    id = cont->common_config->id;

    container_lock(cont);

    if (is_paused(cont->state)) {
        ERROR("Container %s is paused. Unpause the container before stopping or killing", id);
        isulad_set_error_message("Container %s is paused. Unpause the container before stopping or killing", id);
        ret = -1;
        goto out;
    }
    // set AutoRemove flag to false before stop so the container won't be
    // removed during restart process
    if (restart) {
        cont->hostconfig->auto_remove = false;
    }

    if (!force) {
        ret = kill_with_signal(cont, SIGTERM);
        if (ret) {
            ERROR("Failed to grace shutdown container %s", id);
        }
        ret = container_wait_stop(cont, timeout);
        if (ret != 0) {
            ERROR("Failed to wait Container(%s) 'STOPPED' for %d seconds, force killing",
                  id, timeout);
            ret = force_kill(cont);
            if (ret != 0) {
                ERROR("Failed to force kill container %s", id);
                goto out;
            }
        }
    } else {
        ret = force_kill(cont);
        if (ret != 0) {
            ERROR("Failed to force kill container %s", id);
            goto out;
        }
    }
out:
    if (restart) {
        cont->hostconfig->auto_remove = cont->hostconfig->auto_remove_bak;
    }
    container_unlock(cont);
    return ret;
}

static int restart_container(container_t *cont)
{
    int ret = 0;
    char timebuffer[512] = { 0 };
    const char *id = cont->common_config->id;
    const char *runtime = cont->runtime;
    const char *rootpath = cont->root_path;
    rt_restart_params_t params = { 0 };

    container_lock(cont);

    if (is_removal_in_progress(cont->state) || is_dead(cont->state)) {
        ERROR("Container is marked for removal and cannot be started.");
        isulad_set_error_message("Container is marked for removal and cannot be started.");
        goto out;
    }

    (void)get_now_time_buffer(timebuffer, sizeof(timebuffer));

    params.rootpath = rootpath;

    ret = runtime_restart(id, runtime, &params);
    if (ret == -2) {
        goto out;
    }

    if (ret == 0) {
        update_start_and_finish_time(cont->state, timebuffer);
    }

    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", cont->common_config->id);
        ret = -1;
        goto out;
    }
out:
    container_unlock(cont);
    return ret;
}

static uint32_t stop_and_start(container_t *cont, int timeout)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    const char *console_fifos[3] = { NULL, NULL, NULL };
    const char *id = cont->common_config->id;

    ret = stop_container(cont, timeout, false, true);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto out;
    }

    /* begin start container */
    state_set_starting(cont->state);
    if (container_to_disk_locking(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        cc = ISULAD_ERR_EXEC;
        isulad_set_error_message("Failed to save container \"%s\" to disk", id);
        goto out;
    }

    if (is_running(cont->state)) {
        INFO("Container is already running");
        goto out;
    }

    if (start_container(cont, console_fifos, true) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }
out:
    state_reset_starting(cont->state);
    return cc;
}

static void pack_restart_response(container_restart_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static uint32_t do_restart_container(container_t *cont, int timeout)
{
    int ret = 0;

    ret = restart_container(cont);
    if (ret == -1) {
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        return ISULAD_ERR_EXEC;
    } else if (ret == RUNTIME_NOT_IMPLEMENT_RESET) {
        /* runtime don't implement restart, use stop and start */
        return stop_and_start(cont, timeout);
    }

    return ISULAD_SUCCESS;
}

static int container_restart_cb(const container_restart_request *request,
                                container_restart_response **response)
{
    int timeout = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *name = NULL;
    char *id = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_restart_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    timeout = request->timeout;

    if (!util_valid_container_id_or_name(name)) {
        cc = ISULAD_ERR_EXEC;
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container: %s", name);
        isulad_set_error_message("No such container:%s", name);
        goto pack_response;
    }

    id = cont->common_config->id;

    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: restarting}", id);

    if (gc_is_gc_progress(id)) {
        isulad_set_error_message("You cannot restart container %s in garbage collector progress.", id);
        ERROR("You cannot restart container %s in garbage collector progress.", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cc = do_restart_container(cont, timeout);
    if (cc != ISULAD_SUCCESS) {
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Restarted}", id);
    (void)isulad_monitor_send_container_event(id, RESTART, -1, 0, NULL, NULL);

pack_response:
    pack_restart_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_stop_response(container_stop_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static int container_stop_cb(const container_stop_request *request,
                             container_stop_response **response)
{
    int timeout = 0;
    bool force = false;
    char *name = NULL;
    char *id = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_stop_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    force = request->force;
    timeout = request->timeout;

    if (name == NULL) {
        ERROR("Stop: receive NULL id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Stopping}", id);

    if (gc_is_gc_progress(id)) {
        isulad_set_error_message("You cannot stop container %s in garbage collector progress.", id);
        ERROR("You cannot stop container %s in garbage collector progress.", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (stop_container(cont, timeout, force, false)) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto pack_response;
    }

    INFO("Stoped Container:%s", id);
    (void)isulad_monitor_send_container_event(id, STOP, -1, 0, NULL, NULL);

pack_response:
    pack_stop_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int kill_container(container_t *cont, uint32_t signal)
{
    int ret = 0;
    char *id = NULL;

    id = cont->common_config->id;

    container_lock(cont);

    if (!is_running(cont->state)) {
        ERROR("Cannot kill container: Container %s is not running", id);
        isulad_set_error_message("Cannot kill container: Container %s is not running", id);
        ret = -1;
        goto out;
    }

    if (signal == 0 || signal == SIGKILL) {
        ret = force_kill(cont);
    } else {
        ret = kill_with_signal(cont, signal);
    }

    if (ret != 0) {
        ret = -1;
        goto out;
    }

out:
    container_unlock(cont);
    return ret;
}

static void pack_kill_response(container_kill_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static int container_kill_cb(const container_kill_request *request,
                             container_kill_response **response)
{
    int ret = 0;
    char *name = NULL;
    char *id = NULL;
    uint32_t signal = 0;
    uint32_t cc = ISULAD_SUCCESS;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_kill_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    signal = request->signal;

    if (name == NULL) {
        ERROR("Kill: receive NULL id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(name)) {
        isulad_set_error_message("Invalid container name %s", name);
        ERROR("Invalid container name %s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (!util_check_signal_valid((int)signal)) {
        isulad_set_error_message("Not supported signal %d", signal);
        ERROR("Not supported signal %d", signal);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Killing, Signal:%u}", id, signal);


    if (gc_is_gc_progress(id)) {
        isulad_set_error_message("You cannot kill container %s in garbage collector progress.", id);
        ERROR("You cannot kill container %s in garbage collector progress.", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    ret = kill_container(cont, signal);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Killed, Signal:%u}", id, signal);

pack_response:
    pack_kill_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int do_runtime_rm_helper(const char *id, const char *runtime, const char *rootpath)
{
    int ret = 0;
    rt_rm_params_t params = { 0 };

    params.rootpath = rootpath;

    if (runtime_rm(id, runtime, &params)) {
        ERROR("Runtime remove container failed");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int umount_residual_shm(const char *mount_info, const char *target)
{
    if (strncmp(mount_info, target, strlen(target)) != 0) {
        return 0;
    }

    DEBUG("Try to umount: %s", mount_info);
    if (umount2(mount_info, MNT_DETACH)) {
        SYSERROR("Failed to umount residual mount: %s", mount_info);
    }

    return 0;
}

int cleanup_mounts_by_id(const char *id, const char *engine_root_path)
{
    char target[PATH_MAX] = {0};
    int nret = 0;

    nret = snprintf(target, PATH_MAX, "%s/%s", engine_root_path, id);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Sprintf failed");
        return -1;
    }

    if (!util_deal_with_mount_info(umount_residual_shm, target)) {
        ERROR("Cleanup mounts failed");
        return -1;
    }

    return 0;
}

static int do_cleanup_container_resources(container_t *cont)
{
    int ret = 0;
    char *id = NULL;
    char *name = NULL;
    char *statepath = NULL;
    char container_state[PATH_MAX] = { 0 };
    const char *runtime = NULL;
    const char *rootpath = NULL;
    container_t *cont_tmp = NULL;

    container_lock(cont);

    id = cont->common_config->id;
    name = cont->common_config->name;
    statepath = cont->state_path;
    runtime = cont->runtime;
    rootpath = cont->root_path;

    /* check if container was deregistered by previous rm already */
    cont_tmp = containers_store_get(id);
    if (cont_tmp == NULL) {
        ret = 0;
        goto out;
    }
    container_unref(cont_tmp);

    (void)container_to_disk(cont);

    if (gc_is_gc_progress(id)) {
        isulad_set_error_message("You cannot remove container %s in garbage collector progress.", id);
        ERROR("You cannot remove container %s in garbage collector progress.", id);
        ret = -1;
        goto out;
    }

    ret = snprintf(container_state, sizeof(container_state), "%s/%s", statepath, id);
    if (ret < 0 || (size_t)ret >= sizeof(container_state)) {
        ERROR("Failed to sprintf container_state");
        ret = -1;
        goto out;
    }
    ret = util_recursive_rmdir(container_state, 0);
    if (ret != 0) {
        ERROR("Failed to delete container's state directory %s: %s", container_state, strerror(errno));
        ret = -1;
        goto out;
    }

    if (im_remove_container_rootfs(cont->common_config->image_type, id)) {
        ERROR("Failed to remove rootfs for container %s", id);
        ret = -1;
        goto out;
    }

    umount_share_shm(cont);

    umount_host_channel(cont->hostconfig->host_channel);

    // clean residual mount points
    cleanup_mounts_by_id(id, rootpath);

    if (do_runtime_rm_helper(id, runtime, rootpath) != 0) {
        ret = -1;
        goto out;
    }

    /* broadcast remove condition */
    container_wait_rm_cond_broadcast(cont);

    if (!containers_store_remove(id)) {
        ERROR("Failed to remove container '%s' from containers store", id);
        ret = -1;
        goto out;
    }

    if (!name_index_remove(name)) {
        ERROR("Failed to remove '%s' from name index", name);
        ret = -1;
    }

out:
    container_unlock(cont);
    return ret;
}

int set_container_to_removal(const container_t *cont)
{
    int ret = 0;
    char *id = NULL;

    if (cont == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    id = cont->common_config->id;

    bool removal_progress = state_set_removal_in_progress(cont->state);
    if (removal_progress) {
        isulad_set_error_message("Container:%s was already in removal progress", id);
        ERROR("Container:%s was already in removal progress", id);
        ret = -1;
        goto out;
    }
out:
    return ret;
}

int cleanup_container(container_t *cont, bool force)
{
    int ret = 0;
    char *id = NULL;

    if (cont == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    id = cont->common_config->id;

    if (is_running(cont->state)) {
        if (!force) {
            if (is_paused(cont->state)) {
                isulad_set_error_message("You cannot remove a paused container %s. "
                                         "Unpause and then stop the container before "
                                         "attempting removal or force remove", id);
                ERROR("You cannot remove a paused container %s. Unpause and then stop the container before "
                      "attempting removal or force remove", id);
            } else {
                isulad_set_error_message("You cannot remove a running container %s. "
                                         "Stop the container before attempting removal or use -f", id);
                ERROR("You cannot remove a running container %s."
                      " Stop the container before attempting removal or use -f", id);
            }
            ret = -1;
            goto reset_removal_progress;
        }
        ret = stop_container(cont, 3, force, false);
        if (ret != 0) {
            isulad_append_error_message("Could not stop running container %s, cannot remove. ", id);
            ERROR("Could not stop running container %s, cannot remove", id);
            ret = -1;
            goto reset_removal_progress;
        }
    }

    plugin_event_container_post_remove(cont);

    ret = do_cleanup_container_resources(cont);
    if (ret != 0) {
        goto reset_removal_progress;
    }

    goto out;

reset_removal_progress:
    state_reset_removal_in_progress(cont->state);
out:
    return ret;
}

static void pack_delete_response(container_delete_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static int container_delete_cb(const container_delete_request *request,
                               container_delete_response **response)
{
    bool force = false;
    uint32_t cc = ISULAD_SUCCESS;
    char *name = NULL;
    char *id = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_delete_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    force = request->force;

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Deleting}", id);

    container_lock(cont);
    int nret = set_container_to_removal(cont);
    container_unlock(cont);
    if (nret != 0) {
        ERROR("Failed to set container %s state to removal", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (cleanup_container(cont, force)) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Deleted}", id);

pack_response:
    pack_delete_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

void container_callback_init(service_container_callback_t *cb)
{
    cb->get_id = container_get_id_cb;
    cb->get_runtime = container_get_runtime_cb;
    cb->create = container_create_cb;
    cb->start = container_start_cb;
    cb->stop = container_stop_cb;
    cb->restart = container_restart_cb;
    cb->kill = container_kill_cb;
    cb->remove = container_delete_cb;

    container_information_callback_init(cb);
    container_stream_callback_init(cb);
    container_extend_callback_init(cb);
}

