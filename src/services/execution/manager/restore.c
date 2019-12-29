/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container list callback function definition
 ********************************************************************************/

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>

#include "lcrd_config.h"
#include "log.h"
#include "restore.h"
#include "containers_store.h"
#include "supervisor.h"
#include "containers_gc.h"
#include "container_unix.h"
#include "error.h"
#include "image.h"

#ifdef ENABLE_OCI_IMAGE
#include "oci_images_store.h"
#endif

#include "execution.h"

/* restore supervisor */
static int restore_supervisor(const char *id, const char *runtime, const char *statepath)
{
    int ret = 0;
    int nret = 0;
    int exit_fifo_fd = -1;
    char container_state[PATH_MAX] = { 0 };
    char pidfile[PATH_MAX] = { 0 };
    char *exit_fifo = NULL;
    container_pid_t *pid_info = NULL;

    nret = snprintf(container_state, sizeof(container_state), "%s/%s", statepath, id);
    if (nret < 0 || (size_t)nret >= sizeof(container_state)) {
        ERROR("Failed to sprintf container state %s/%s", statepath, id);
        ret = -1;
        goto out;
    }

    exit_fifo = exit_fifo_name(container_state);
    if (exit_fifo == NULL) {
        ERROR("Failed to get exit fifo name %s/%s", statepath, id);
        ret = -1;
        goto out;
    }

    exit_fifo_fd = exit_fifo_open(exit_fifo);
    if (exit_fifo_fd < 0) {
        ERROR("Failed to open exit FIFO %s", exit_fifo);
        ret = -1;
        goto out;
    }

    nret = snprintf(pidfile, sizeof(pidfile), "%s/pid.file", container_state);
    if (nret < 0 || (size_t)nret >= sizeof(pidfile)) {
        close(exit_fifo_fd);
        ERROR("Failed to sprintf pidfile");
        ret = -1;
        goto out;
    }

    pid_info = container_read_pidfile(pidfile);
    if (pid_info == NULL) {
        close(exit_fifo_fd);
        ERROR("Failed to get started container's pid info");
        ret = -1;
        goto out;
    }

    if (supervisor_add_exit_monitor(exit_fifo_fd, pid_info, id, runtime)) {
        ERROR("Failed to add exit monitor to supervisor");
        ret = -1;
        goto out;
    }

out:
    free(exit_fifo);
    free(pid_info);

    return ret;
}

static container_pid_t *container_read_proc(uint32_t pid)
{
    container_pid_t *pid_info = NULL;
    proc_t *proc_info = NULL;

    if (pid == 0) {
        goto out;
    }

    proc_info = util_get_process_proc_info((pid_t)pid);
    if (proc_info == NULL) {
        goto out;
    }

    pid_info = util_common_calloc_s(sizeof(container_pid_t));
    if (pid_info == NULL) {
        goto out;
    }

    pid_info->pid = proc_info->pid;
    pid_info->start_time = proc_info->start_time;

out:
    free(proc_info);
    return pid_info;
}

/* post stopped container to gc */
static int post_stopped_container_to_gc(const char *id, const char *runtime, const char *statepath, uint32_t pid)
{
    int ret = 0;
    int nret = 0;
    char container_state[PATH_MAX] = { 0 };
    char pidfile[PATH_MAX] = { 0 };
    container_pid_t *pid_info = NULL;

    nret = snprintf(container_state, sizeof(container_state), "%s/%s", statepath, id);
    if (nret < 0 || (size_t)nret >= sizeof(container_state)) {
        ERROR("Failed to sprintf container state %s/%s", statepath, id);
        ret = -1;
        goto out;
    }

    nret = snprintf(pidfile, sizeof(pidfile), "%s/pid.file", container_state);
    if (nret < 0 || (size_t)nret >= sizeof(pidfile)) {
        ERROR("Failed to sprintf pidfile");
        ret = -1;
        goto out;
    }

    pid_info = container_read_pidfile(pidfile);
    if (pid_info == NULL) {
        WARN("Failed to get started container's pid info, try to read proc filesystem");
        pid_info = container_read_proc(pid);
        if (pid_info == NULL) {
            ERROR("Failed to get started container's pid info");
            ret = -1;
            goto out;
        }
    }

    if (gc_add_container(id, runtime, pid_info)) {
        ERROR("Failed to post container %s to garbage collector", id);
        ret = -1;
        goto out;
    }

out:
    free(pid_info);
    return ret;
}

static container_pid_t *load_running_container_pid_info(const container_t *cont)
{
    int nret = 0;
    const char *id = cont->common_config->id;
    char pidfile[PATH_MAX] = { 0 };
    char container_state[PATH_MAX] = { 0 };
    container_pid_t *pid_info = NULL;

    nret = snprintf(container_state, sizeof(container_state), "%s/%s", cont->state_path, id);
    if (nret < 0 || (size_t)nret >= sizeof(container_state)) {
        ERROR("Failed to sprintf container_state for container %s", id);
        goto out;
    }

    nret = snprintf(pidfile, sizeof(pidfile), "%s/pid.file", container_state);
    if (nret < 0 || (size_t)nret >= sizeof(pidfile)) {
        ERROR("Failed to sprintf pidfile");
        goto out;
    }

    pid_info = container_read_pidfile(pidfile);
    if (pid_info == NULL) {
        goto out;
    }

out:
    return pid_info;
}

#ifdef ENABLE_OCI_IMAGE
static void post_nonexist_image_containers(const container_t *cont, Container_Status status,
                                           const struct engine_container_summary_info *info)
{
    int nret;
    const char *id = cont->common_config->id;

    if (info->status == ENGINE_CONTAINER_STATUS_STOPPED) {
        if (status != CONTAINER_STATUS_STOPPED && \
            status != CONTAINER_STATUS_CREATED) {
            nret = post_stopped_container_to_gc(id, cont->runtime, cont->state_path, 0);
            if (nret != 0) {
                ERROR("Failed to post container %s to garbage"
                      "collector, that may lost some resources"
                      "used with container!", id);
            }
            state_set_stopped(cont->state, 255);
        }
    } else if (info->status == ENGINE_CONTAINER_STATUS_RUNNING) {
        nret = post_stopped_container_to_gc(id, cont->runtime, cont->state_path, info->pid);
        if (nret != 0) {
            ERROR("Failed to post container %s to garbage"
                  "collector, that may lost some resources"
                  "used with container!", id);
        }
        state_set_stopped(cont->state, 255);
    } else {
        ERROR("Container %s get invalid status %d", id, info->status);
    }

    return;
}

static int check_container_image_exist(const container_t *cont)
{
    int ret = 0;
    char *tmp = NULL;
    const char *id = cont->common_config->id;
    const char *image_name = cont->common_config->image;
    const char *image_type = cont->common_config->image_type;
    oci_image_t *image = NULL;

    if (image_type == NULL || image_name == NULL) {
        ERROR("Failed to get image type for container %s", id);
        ret = -1;
        goto out;
    }

    /* only check exist for oci image */
    if (strcmp(image_type, IMAGE_TYPE_OCI) == 0) {
        ret = im_resolv_image_name(image_type, image_name, &tmp);
        if (ret != 0) {
            ERROR("Failed to resolve image %s", image_name);
            goto out;
        }
        image = oci_images_store_get(tmp);
        if (image == NULL) {
            WARN("Image %s not exist", tmp);
            ret = -1;
            goto out;
        }
        oci_image_unref(image);
    }

out:
    free(tmp);
    return ret;
}
#endif

static void try_to_set_container_running(Container_Status status, const container_t *cont,
                                         const container_pid_t *pid_info)
{
    int pid = 0;

    pid = state_get_pid(cont->state);
    if (status != CONTAINER_STATUS_RUNNING || pid != pid_info->pid) {
        state_set_running(cont->state, pid_info, true);
    }
}

static void try_to_set_paused_container_pid(Container_Status status, const container_t *cont,
                                            const container_pid_t *pid_info)
{
    int pid = 0;

    pid = state_get_pid(cont->state);
    if (status != CONTAINER_STATUS_RUNNING || pid != pid_info->pid) {
        state_set_running(cont->state, pid_info, false);
    }
}

static int restore_check_id_valid(const char *id, const struct engine_container_summary_info *info,
                                  size_t container_num)
{
    size_t i = 0;

    if (id == NULL) {
        ERROR("Cannot get container id from config v2");
        return -1;
    }

    for (i = 0; i < container_num; i++) {
        if (strcmp(id, info[i].id) == 0) {
            break;
        }
    }

    if (i >= container_num) {
        ERROR("Container %s is not in runtime container array", id);
        return -1;
    }

    return (int)i;
}

static int restore_stopped_container(Container_Status status, const container_t *cont, bool *need_save)
{
    const char *id = cont->common_config->id;

    if (status != CONTAINER_STATUS_STOPPED && \
        status != CONTAINER_STATUS_CREATED) {
        int nret = post_stopped_container_to_gc(id, cont->runtime, cont->state_path, 0);
        if (nret != 0) {
            ERROR("Failed to post container %s to garbage"
                  "collector, that may lost some resources"
                  "used with container!", id);
        }
        state_set_stopped(cont->state, 255);
        *need_save = true;
    }

    return 0;
}

static int restore_running_container(Container_Status status, container_t *cont,
                                     const struct engine_container_summary_info *info)
{
    int ret = 0;
    const char *id = cont->common_config->id;
    container_pid_t *pid_info = NULL;

    pid_info = load_running_container_pid_info(cont);
    if (pid_info == NULL) {
        ERROR("Failed to restore container:%s due to unable to read container pid info", id);
        int nret = post_stopped_container_to_gc(id, cont->runtime, cont->state_path, info->pid);
        if (nret != 0) {
            ERROR("Failed to post container %s to garbage"
                  "collector, that may lost some resources"
                  "used with container!", id);
        }
        ret = -1;
        goto out;
    } else {
        try_to_set_container_running(status, cont, pid_info);
    }
    container_reset_manually_stopped(cont);

out:
    free(pid_info);
    return ret;
}

static int restore_paused_container(Container_Status status, container_t *cont,
                                    const struct engine_container_summary_info *info)
{
    int ret = 0;
    const char *id = cont->common_config->id;
    container_pid_t *pid_info = NULL;

    state_set_paused(cont->state);

    pid_info = load_running_container_pid_info(cont);
    if (pid_info == NULL) {
        ERROR("Failed to restore container:%s due to unable to read container pid info", id);
        int nret = post_stopped_container_to_gc(id, cont->runtime, cont->state_path, info->pid);
        if (nret != 0) {
            ERROR("Failed to post container %s to garbage"
                  "collector, that may lost some resources"
                  "used with container!", id);
        }
        ret = -1;
        goto out;
    } else {
        try_to_set_paused_container_pid(status, cont, pid_info);
    }
    container_reset_manually_stopped(cont);

out:
    free(pid_info);
    return ret;
}

/* restore state */
static int restore_state(container_t *cont, const struct engine_container_summary_info *info, size_t container_num)
{
    int ret = 0;
    int c_index = 0;
    bool need_save = false;
    const char *id = cont->common_config->id;
    Container_Status status = CONTAINER_STATUS_UNKNOWN;

    c_index = restore_check_id_valid(id, info, container_num);
    if (c_index < 0) {
        ret = -1;
        goto out;
    }

    status = state_get_status(cont->state);
    (void)container_exit_on_next(cont); /* cancel restart policy */

#ifdef ENABLE_OCI_IMAGE
    if (check_container_image_exist(cont) != 0) {
        ERROR("Failed to restore container:%s due to image not exist", id);
        post_nonexist_image_containers(cont, status, &info[c_index]);
        ret = -1;
        goto out;
    }
#endif

    if (info[c_index].status == ENGINE_CONTAINER_STATUS_STOPPED) {
        ret = restore_stopped_container(status, cont, &need_save);
        if (ret != 0) {
            goto out;
        }
    } else if (info[c_index].status == ENGINE_CONTAINER_STATUS_RUNNING) {
        ret = restore_running_container(status, cont, &info[c_index]);
        if (ret != 0) {
            goto out;
        }
    } else if (info[c_index].status == ENGINE_CONTAINER_STATUS_PAUSED) {
        ret = restore_paused_container(status, cont, &info[c_index]);
        if (ret != 0) {
            goto out;
        }
    } else {
        ERROR("Container %s get invalid status %d", id, info[c_index].status);
    }

    if (is_removal_in_progress(cont->state)) {
        state_reset_removal_in_progress(cont->state);
        need_save = true;
    }

out:
    if (need_save && container_to_disk(cont) != 0) {
        ERROR("Failed to re-save container \"%s\" to disk", id);
        ret = -1;
    }
    return ret;
}

/* remove invalid container */
static int remove_invalid_container(const container_t *cont, const char *runtime, const char *root, const char *state,
                                    const char *id)
{
    int ret = 0;
    char container_root[PATH_MAX] = { 0x00 };
    char container_state[PATH_MAX] = { 0x00 };

    ret = snprintf(container_state, sizeof(container_state), "%s/%s", state, id);
    if (ret < 0 || (size_t)ret >= sizeof(container_state)) {
        ERROR("Failed to sprintf container state %s/%s", state, id);
        ret = -1;
        goto out;
    }
    ret = util_recursive_rmdir(container_state, 0);
    if (ret != 0) {
        ERROR("Failed to delete container's state directory %s", container_state);
        ret = -1;
        goto out;
    }

    ret = snprintf(container_root, sizeof(container_root), "%s/%s", root, id);
    if (ret < 0 || (size_t)ret >= sizeof(container_root)) {
        ERROR("Failed to sprintf invalid root directory %s/%s", root, id);
        ret = -1;
        goto out;
    }

    if (cont != NULL && im_remove_container_rootfs(cont->common_config->image_type, id)) {
        ERROR("Failed to remove rootfs for container %s", id);
        ret = -1;
        goto out;
    }

    ret = util_recursive_rmdir(container_root, 0);
    if (ret != 0) {
        ERROR("Failed to delete container's state directory %s", container_state);
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static void restored_restart_container(container_t *cont)
{
    char *id = NULL;
    char *started_at = NULL;
    uint64_t timeout = 0;

    id = cont->common_config->id;

    started_at = state_get_started_at(cont->state);
    if (restart_manager_should_restart(id, state_get_exitcode(cont->state),
                                       cont->common_config->has_been_manually_stopped,
                                       time_seconds_since(started_at),
                                       &timeout)) {
        cont->common_config->restart_count++;
        INFO("Restart container %s after 5 second", id);
        (void)container_restart_in_thread(id, 5ULL * Time_Second, (int)state_get_exitcode(cont->state));
    }
    free(started_at);
}

/* handle restored container */
static void handle_restored_container()
{
    int ret = 0;
    size_t i = 0;
    size_t container_num = 0;
    char *id = NULL;
    container_t **conts = NULL;
    container_t *cont = NULL;

    ret = containers_store_list(&conts, &container_num);
    if (ret != 0) {
        ERROR("query all containers info failed");
        return;
    }

    for (i = 0; i < container_num; i++) {
        cont = conts[i];
        container_lock(cont);

        (void)reset_restart_manager(cont, false);

        id = cont->common_config->id;

        if (is_running(cont->state)) {
            if (restore_supervisor(id, cont->runtime, cont->state_path)) {
                ERROR("Failed to restore %s supervisor", id);
            }
            init_health_monitor(id);
        } else {
            if (cont->hostconfig != NULL && cont->hostconfig->auto_remove_bak) {
                (void)set_container_to_removal(cont);
                container_unlock(cont);
                (void)cleanup_container(cont, true);
                container_lock(cont);
            } else {
                restored_restart_container(cont);
            }
        }

        container_unlock(cont);
        container_unref(cont);
    }

    free(conts);
    return;
}

/* scan dir to add store */
static void scan_dir_to_add_store(const char *runtime, const char *rootpath, const char *statepath,
                                  const size_t subdir_num, const char **subdir, const size_t container_num,
                                  const struct engine_container_summary_info *info)
{
    size_t i = 0;
    container_t *cont = NULL;

    for (i = 0; i < subdir_num; i++) {
        cont = NULL;
        bool aret = false;
        bool index_flag = false;
        cont = container_load(runtime, rootpath, statepath, subdir[i]);
        if (cont == NULL) {
            ERROR("Failed to load subdir:%s", subdir[i]);
            goto error_load;
        }

        if (restore_state(cont, info, container_num)) {
            WARN("Failed to restore container %s state", subdir[i]);
            goto error_load;
        }

        index_flag = name_index_add(cont->common_config->name, cont->common_config->id);
        if (!index_flag) {
            ERROR("Failed add %s into name indexs", subdir[i]);
            goto error_load;
        }
        aret = containers_store_add(cont->common_config->id, cont);
        if (!aret) {
            ERROR("Failed add container %s to store", subdir[i]);
            goto error_load;
        }

        continue;
error_load:
        if (remove_invalid_container(cont, runtime, rootpath, statepath, subdir[i])) {
            ERROR("Failed to delete subdir:%s", subdir[i]);
        }
        container_unref(cont);

        if (index_flag) {
            name_index_remove(subdir[i]);
        }
        continue;
    }
}

/* query all containers info */
static int query_all_containers_info(const char *runtime, struct engine_container_summary_info **container_summary,
                                     size_t *container_num)
{
    int ret = 0;
    int container_nums = 0;
    char *engine_path = NULL;
    struct engine_operation *engine_ops = NULL;

    if (runtime == NULL || container_summary == NULL || container_num == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_get_all_containers_info_op == NULL) {
        ERROR("Failed to get list op of engine %s", runtime);
        ret = -1;
        goto out;
    }

    engine_path = conf_get_routine_rootdir(runtime);
    if (engine_path == NULL) {
        ret = -1;
        goto out;
    }
    container_nums = engine_ops->engine_get_all_containers_info_op(engine_path, container_summary);
    if (container_nums < 0) {
        ERROR("Engine %s get all containers info failed", runtime);
        ret = -1;
        goto out;
    }
    *container_num = (size_t)container_nums;

out:
    free(engine_path);
    if (engine_ops != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }

    return ret;
}

/* all containers info free */
static void all_containers_info_free(const char *runtime, struct engine_container_summary_info *container_summary,
                                     size_t container_num)
{
    struct engine_operation *engine_ops = NULL;

    if (container_summary == NULL || runtime == NULL) {
        return;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_free_all_containers_info_op == NULL) {
        ERROR("Failed to get free op of engine %s", runtime);
        return;
    }

    engine_ops->engine_free_all_containers_info_op(container_summary, (int)container_num);

    if (engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return;
}

/* restore container by runtime */
static int restore_container_by_runtime(const char *runtime)
{
    int ret = 0;
    char *rootpath = NULL;
    char *statepath = NULL;
    size_t container_num = 0;
    size_t subdir_num = 0;
    char **subdir = NULL;
    struct engine_container_summary_info *info = NULL;

    rootpath = conf_get_routine_rootdir(runtime);
    if (rootpath == NULL) {
        ERROR("Root path is NULL");
        ret = -1;
        goto out;
    }

    statepath = conf_get_routine_statedir(runtime);
    if (statepath == NULL) {
        ERROR("State path is NULL");
        ret = -1;
        goto out;
    }

    ret = util_list_all_subdir(rootpath, &subdir);
    if (ret != 0) {
        ERROR("Failed to read %s'subdirectory", rootpath);
        ret = -1;
        goto out;
    }
    subdir_num = util_array_len((const char **)subdir);
    if (subdir_num == 0) {
        goto out;
    }

    ret = query_all_containers_info(runtime, &info, &container_num);
    if (ret < 0) {
        ERROR("query all containers info failed");
        ret = -1;
        goto out;
    }

    scan_dir_to_add_store(runtime, rootpath, statepath, subdir_num, (const char **)subdir, container_num, info);

out:
    all_containers_info_free(runtime, info, container_num);
    free(rootpath);
    free(statepath);
    util_free_array(subdir);
    return ret;
}

/* containers restore */
void containers_restore(void)
{
    int ret = 0;
    size_t subdir_num = 0;
    size_t i = 0;
    char *engines_path = NULL;
    char **subdir = NULL;

    engines_path = conf_get_engine_rootpath();
    if (engines_path == NULL) {
        ERROR("Failed to get engines path");
        goto out;
    }

    ret = util_list_all_subdir(engines_path, &subdir);
    if (ret != 0) {
        ERROR("Failed to list engines");
        goto out;
    }
    subdir_num = util_array_len((const char **)subdir);

    for (i = 0; i < subdir_num; i++) {
        DEBUG("Restore the containers by runtime:%s", subdir[i]);
        ret = restore_container_by_runtime(subdir[i]);
        if (ret != 0) {
            ERROR("Failed to restore containers by runtime:%s", subdir[i]);
        }
    }

    handle_restored_container();

out:
    free(engines_path);
    util_free_array(subdir);
    return;
}

