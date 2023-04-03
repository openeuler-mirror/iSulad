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
 * Author: xuxuepeng
 * Create: 2023-01-29
 * Description: provide sandbox supervisor functions
 ******************************************************************************/

#include <sys/mount.h>
#include "service_sandboxer_api.h"
#include "controller_api.h"
#include "isula_libutils/log.h"
#include "specs_api.h"

static int prepare_sandbox_state_dir(sandbox_t *sandbox, char **sandbox_state_dir)
{
    int ret = 0;
    int nret = 0;
    char state_dir[PATH_MAX] = { 0 };
    const char *id = sandbox->sandboxconfig->id;

    nret = snprintf(state_dir, sizeof(state_dir), "%s/%s", sandbox->statepath, id);
    if (nret < 0 || (size_t)nret >= sizeof(state_dir)) {
        ERROR("Failed to sprintf sandbox state directory");
        ret = -1;
        goto out;
    }

    nret = util_mkdir_p(state_dir, TEMP_DIRECTORY_MODE);
    if (nret < 0) {
        ERROR("Unable to create sandbox state directory %s.", state_dir);
        ret = -1;
        goto out;
    }

    *sandbox_state_dir = util_strdup_s(state_dir);
    if (*sandbox_state_dir == NULL) {
        ERROR("Failed to dup the path of state directory %s", state_dir);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int remove_sandbox_state_dir(sandbox_t *sandbox){
    int ret = 0;
    int nret = 0;
    char state_dir[PATH_MAX] = { 0 };
    const char *id = sandbox->sandboxconfig->id;
    nret = snprintf(state_dir, sizeof(state_dir), "%s/%s", sandbox->statepath, id);
    if (nret < 0 || (size_t)nret >= sizeof(state_dir)) {
        ERROR("Failed to sprintf sandbox state directory");
        ret = -1;
    }
    
    if (util_recursive_remove_path(state_dir) != 0){
        ERROR("Unable to remove sandbox state dir");
        ret = -1;
    }
    return ret;
}

static void set_ctrl_create_params(ctrl_create_params_t *params, sandbox_t *sandbox)
{
    // TODO: Anything need to be mounted for sandbox if we don't have pause container anymore?
    params->mounts_len = 0;
    params->mounts = NULL;
    params->config = sandbox->config_option;
    params->netns_path = sandbox->sandboxconfig->netns_path;
}

static int do_create_sandbox(sandbox_t *sandbox)
{
    ctrl_create_params_t create_params = { 0 };
    const char *sandbox_id = sandbox->sandboxconfig->id;

    set_ctrl_create_params(&create_params, sandbox);

    // TODO: Create controller params
    if (sandbox_ctrl_create(sandbox->sandboxer, sandbox_id, &create_params) != 0) {
        ERROR("Failed to create sandbox by controller, %s", sandbox_id);
        return -1;
    }

    return 0;
}

int create_sandbox(sandbox_t *sandbox)
{
    // TODO: remap shared memory?
    // TODO: set up log level
    // TODO: Setup env target file ? necessary for sandbox?
    // TODO: prepare state files
    // TODO: setup ipc
    int ret = 0;
    char *state_dir = NULL;

    if (sandbox == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    sandbox_lock(sandbox);

    // TODO: Check if pause/remove in progress?
    // TODO: Setup state files?
    // Currently we can pass over the state directory to sandboxer,
    // and let sandboxer to manager the status?

    if (prepare_sandbox_state_dir(sandbox, &state_dir) != 0) {
        ret = -1;
        // I guess we could try to show _why_ we cant make a directory if that is possible
        ERROR("Failed to prepare sandbox state directory for sandbox %s", sandbox->sandboxconfig->id);
        goto out;
    }

    if (do_create_sandbox(sandbox) != 0) {
        ret = -1;
    }
out:
    sandbox_unlock(sandbox);
    return ret;
}

static int do_start_sandbox(sandbox_t *sandbox)
{
    const char *sandbox_id = sandbox->sandboxconfig->id;

    if (sandbox_ctrl_start(sandbox->sandboxer, sandbox_id) != 0) {
        ERROR("Failed to start sandbox by controller, %s", sandbox_id);
        return -1;
    }
    // TODO: Ignore start response and let status rpc to check if vm is started?

    return 0;
}

// TODO: ugly, memory allocation in response from controller need to be handled in an elegent way.
static void release_sandbox_status_response(ctrl_status_response_t *status_resp)
{
    if (status_resp == NULL) {
        return;
    }
    free(status_resp->state);
    status_resp->state = NULL;
    free(status_resp->task_address);
    status_resp->task_address = NULL;
}

static int do_update_sandbox_status(sandbox_t *sandbox)
{
    ctrl_status_response_t status_resp = { 0 };
    const char *sandbox_id = sandbox->sandboxconfig->id;

    if (sandbox_ctrl_status(sandbox->sandboxer, sandbox_id, false, &status_resp)) {
        ERROR("Failed to get sandbox status by controller, %s", sandbox_id);
        return -1;
    }

    sandbox_update_status(sandbox, status_resp.pid, status_resp.state, status_resp.task_address,
                          status_resp.created_at, status_resp.exited_at);
    release_sandbox_status_response(&status_resp);
    return 0;
}


int start_sandbox(sandbox_t *sandbox)
{
    int ret = 0;
    sandbox_lock(sandbox);
    if (do_start_sandbox(sandbox) != 0) {
        ret = -1;
        goto out;
    }

    if (do_update_sandbox_status(sandbox) != 0) {
        ERROR("Failed to update sandbox status after start, %s", sandbox->sandboxconfig->id);
        ret = -1;
        goto out;
    }

    if (!sandbox_is_ready(sandbox)) {
        ret = -1;
        ERROR("Sandbox is not ready after start, %s", sandbox->sandboxconfig->id);
    }
out:
    sandbox_unlock(sandbox);
    return ret;
}

int stop_sandbox(sandbox_t *sandbox)
{
    int ret = 0;
    const char *sandbox_id = NULL;

    if (sandbox == NULL) {
        ERROR("Invalid arguments for stop sandbox");
        return -1;
    }

    sandbox_lock(sandbox);
    sandbox_id = sandbox->sandboxconfig->id;

    if (!sandbox_is_ready(sandbox)) {
        WARN("Sandbox is not ready, sandbox_id %s", sandbox_id);
        goto out;
    }

    // TODO: set proper timeout?
    if (sandbox_ctrl_stop(sandbox->sandboxer, sandbox_id, 0) != 0) {
        ret = -1;
        ERROR("Failed to stop sandbox, %s", sandbox_id);
        goto out;
    }

    if (do_update_sandbox_status(sandbox) != 0) {
        ERROR("Failed to update sandbox status after stop, %s", sandbox_id);
        ret = -1;
        goto out;
    }

    if (sandbox_is_ready(sandbox)) {
        ret = -1;
        ERROR("Sandbox is still running after stop, %s", sandbox_id);
    }

out:
    sandbox_unlock(sandbox);
    return ret;
}

// TODO: Redundant function as the one in service_container.c
int sandbox_umount_residual_shm(const char *mount_info, const char *target)
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

// TODO: Redundant function as the one in service_container.c
int sandbox_cleanup_mounts_by_id(const char *id, const char *engine_root_path)
{
    char target[PATH_MAX] = { 0 };
    int nret = 0;

    nret = snprintf(target, PATH_MAX, "%s/%s", engine_root_path, id);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Sprintf failed");
        return -1;
    }

    if (!util_deal_with_mount_info(sandbox_umount_residual_shm, target)) {
        ERROR("Cleanup mounts failed");
        return -1;
    }

    return 0;
}

int delete_sandbox(sandbox_t *sandbox, bool force)
{
    int ret = 0;
    const char *sandbox_id = NULL;

    if (sandbox == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    sandbox_lock(sandbox);

    sandbox_id = sandbox->sandboxconfig->id;
    if (sandbox_is_ready(sandbox)) {
        if (force) {
            if (stop_sandbox(sandbox) != 0) {
                ERROR("Failed to stop sandbox before removing sandbox, %s", sandbox_id);
                ret = -1;
                goto out;
            }
        } else {
            ERROR("Sandbox is still running, unable to remove, %s", sandbox_id);
            ret = -1;
            goto out;
        }
    }

    if (sandbox_ctrl_shutdown(sandbox->sandboxer, sandbox_id) != 0) {
        ret = -1;
        ERROR("Failed to shutdown sandbox by controller, %s", sandbox_id);
        goto out;
    }

    // clean residual mount points
    sandbox_cleanup_mounts_by_id(sandbox_id, sandbox->rootpath);

    // TODO: What if failed to delete, is gc necessary?
    // TODO: state dir removed in stop stage or in remove stage?
    remove_sandbox_state_dir(sandbox);
    // TODO: Handle fifo if necessary
out:
    sandbox_unlock(sandbox);

    return ret;
}

int update_sandbox_status(sandbox_t *sandbox)
{
    int ret = 0;
    if (sandbox == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    sandbox_lock(sandbox);

    if (do_update_sandbox_status(sandbox) != 0) {
        ERROR("Failed to update sandbox status, %s", sandbox->sandboxconfig->id);
        ret = -1;
    }

    sandbox_unlock(sandbox);

    return ret;
}
