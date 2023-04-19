/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-01-30
 * Description: provide sandbox functions
 ******************************************************************************/

#include "sandbox_api.h"
#include "util_atomic.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "err_msg.h"

#define SANDBOX_READY_STATE_STR "SANDBOX_READY"
#define SANDBOX_NOTREADY_STATE_STR "SANDBOX_NOTREADY"

static sandbox_status_t convert_ready_state(const char *state)
{
    if (state == NULL) {
        return SANDBOX_UNKNOWN;
    }
    if (strcmp(state, SANDBOX_READY_STATE_STR) == 0) {
        return SANDBOX_READY;
    }
    if (strcmp(state, SANDBOX_NOTREADY_STATE_STR) == 0) {
        return SANDBOX_NOT_READY;
    }
    return SANDBOX_UNKNOWN;
}

static int init_sandbox_mutex(sandbox_t *sandbox)
{
    int ret = 0;

    ret = pthread_mutex_init(&(sandbox->mutex), NULL);
    if (ret != 0) {
        ERROR("Failed to init mutex of sandbox");
        return -1;
    }
    sandbox->init_mutex = true;

    return 0;
}

// TODO: More sandbox info needed for initialization
sandbox_t *sandbox_new(const char *name, const char *sandboxer,
                       const char *sandbox_rootdir,
                       const char *sandbox_statedir)
{
    int ret;
    sandbox_t *sandbox = NULL;

    if (name == NULL ||
        sandboxer == NULL ||
        sandbox_rootdir == NULL ||
        sandbox_statedir == NULL) {
        return NULL;
    }

    sandbox = util_common_calloc_s(sizeof(sandbox_t));
    if (sandbox == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    atomic_int_set(&sandbox->refcnt, 1);

    ret = init_sandbox_mutex(sandbox);
    if (ret != 0) {
        goto error_out;
    }

    sandbox->name = util_strdup_s(name);
    sandbox->sandboxer = util_strdup_s(sandboxer);
    sandbox->rootpath = util_strdup_s(sandbox_rootdir);
    sandbox->statepath = util_strdup_s(sandbox_statedir);
    sandbox->status = SANDBOX_UNKNOWN;

    return sandbox;

error_out:
    sandbox_unref(sandbox);
    return NULL;
}

bool sandbox_is_ready(sandbox_t *sandbox)
{
    if (sandbox == NULL) {
        return false;
    }
    return sandbox->status == SANDBOX_READY;
}

void sandbox_set_ready(sandbox_t *sandbox)
{
    if (sandbox == NULL) {
        return;
    }
    sandbox->status = SANDBOX_READY;
}

void sandbox_set_not_ready(sandbox_t *sandbox)
{
    if (sandbox == NULL) {
        return;
    }
    sandbox->status = SANDBOX_NOT_READY;
}

int sandbox_fill_host_config(sandbox_t *sandbox, host_config *hostconfig)
{
    if (sandbox == NULL || hostconfig == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    sandbox->hostconfig = hostconfig;
    return 0;
}

int sandbox_fill_sandbox_config(sandbox_t *sandbox, sandbox_config *sandboxconfig)
{
    if (sandbox == NULL || sandboxconfig == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    sandbox->sandboxconfig = sandboxconfig;
    return 0;
}

int sandbox_fill_sandbox_pod_config_option(sandbox_t *sandbox, const char *pod_config_option)
{
    if (sandbox == NULL || pod_config_option == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }
    sandbox->config_option = util_strdup_s(pod_config_option);
    return 0;
}

int sandbox_update_status(sandbox_t *sandbox, uint32_t pid, const char *state,
                          const char *task_address, uint64_t created_at, uint64_t exited_at)
{
    if (sandbox == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }
    sandbox->pid = pid;
    sandbox->status = convert_ready_state(state);
    sandbox->task_address = util_strdup_s(task_address);
    sandbox->created_at = created_at;
    sandbox->exited_at = exited_at;
    return 0;
}

/* save json config file */
static int save_sandbox_json_config_file(const char *id, const char *rootpath, const char *json_data, const char *fname)
{
    int ret = 0;
    int nret;
    char filename[PATH_MAX] = { 0 };

    if (json_data == NULL || strlen(json_data) == 0) {
        return 0;
    }
    nret = snprintf(filename, sizeof(filename), "%s/%s/%s", rootpath, id, fname);
    if (nret < 0 || (size_t)nret >= sizeof(filename)) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    nret = util_atomic_write_file(filename, json_data, strlen(json_data), CONFIG_FILE_MODE, false);
    if (nret != 0) {
        ERROR("Write file %s failed: %s", filename, strerror(errno));
        isulad_set_error_message("Write file '%s' failed: %s", filename, strerror(errno));
        ret = -1;
    }

out:
    return ret;
}

#define SANDBOX_CONFIG_JSON "sandbox-config.json"
/* save sandbox config json */
int save_sandbox_config_json(const char *id, const char *rootpath, const char *configstr)
{
    if (rootpath == NULL || id == NULL || configstr == NULL) {
        return -1;
    }

    return save_sandbox_json_config_file(id, rootpath, configstr, SANDBOX_CONFIG_JSON);
}

#define SANDBOX_HOST_CONFIG_JSON "host-config.json"
/* save host config */
int save_sandbox_host_config(const char *id, const char *rootpath, const char *hostconfigstr)
{
    if (rootpath == NULL || id == NULL || hostconfigstr == NULL) {
        return -1;
    }
    return save_sandbox_json_config_file(id, rootpath, hostconfigstr, SANDBOX_HOST_CONFIG_JSON);
}

void sandbox_refinc(sandbox_t *sandbox)
{
    if (sandbox == NULL) {
        return;
    }
    atomic_int_inc(&sandbox->refcnt);
}

void sandbox_unref(sandbox_t *sandbox)
{
    bool is_zero = false;

    if (sandbox == NULL) {
        return;
    }

    is_zero = atomic_int_dec_test(&sandbox->refcnt);
    if (!is_zero) {
        return;
    }
    DEBUG("Sandbox released, %s", sandbox->sandboxconfig->id);
    sandbox_free(sandbox);
}

/* container lock */
void sandbox_lock(sandbox_t *sandbox)
{
    if (sandbox == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    if (pthread_mutex_lock(&sandbox->mutex) != 0) {
        ERROR("Failed to lock sandbox '%s'", sandbox->sandboxconfig->id);
    }
}

/* container unlock */
void sandbox_unlock(sandbox_t *sandbox)
{
    if (sandbox == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    if (pthread_mutex_unlock(&sandbox->mutex) != 0) {
        ERROR("Failed to unlock container '%s'", sandbox->sandboxconfig->id);
    }
}

void sandbox_free(sandbox_t *sandbox)
{
    if (sandbox == NULL) {
        return;
    }
    free(sandbox->name);
    sandbox->name = NULL;
    free(sandbox->sandboxer);
    sandbox->sandboxer = NULL;
    free(sandbox->updated_at);
    sandbox->updated_at = NULL;
    free(sandbox->rootpath);
    sandbox->rootpath = NULL;
    free(sandbox->statepath);
    sandbox->statepath = NULL;
    free(sandbox->task_address);
    sandbox->task_address = NULL;
    free_host_config(sandbox->hostconfig);
    sandbox->hostconfig = NULL;
    free_sandbox_config(sandbox->sandboxconfig);
    sandbox->sandboxconfig = NULL;

    if (sandbox->init_mutex) {
        pthread_mutex_destroy(&sandbox->mutex);
    }

    free(sandbox);
}
