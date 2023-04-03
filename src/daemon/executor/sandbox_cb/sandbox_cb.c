/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-01-28
 * Description: provide sandbox functions
 *********************************************************************************/
#include <stdio.h>
#include <sys/stat.h>

#include "sandbox_cb.h"
#include "service_sandboxer_api.h"
#include "isula_libutils/log.h"
#include "isula_libutils/sandbox_status.h"
#include "isula_libutils/sandbox_sandbox.h"
#include "error.h"
#include "err_msg.h"
#include "isulad_config.h"
#include "sandbox_network.h"
// #include "specs_api.h"

// TODO: Can be even improved by using function internally
//       since ERROR and isulad_set_error_message always using the same message,
//       in the code below, the const string are duplicated in the generated binary 
//       so if passed with the same string pointer, the binary size can be reduced.
//       using function instead of macro can reduce the duplication.
#define SB_CB_ERROR_FORMAT(err_var, error_code, ...) \
do { \
    err_var = error_code; \
    ERROR(__VA_ARGS__); \
    isulad_set_error_message(__VA_ARGS__); \
} while(0)

static char *try_generate_sandbox_id()
{
    int i = 0;
    int max_time = 10;
    char *id = NULL;
    sandbox_t *value = NULL;

    id = util_smart_calloc_s(sizeof(char), (SANDBOX_ID_MAX_LEN + 1));
    if (id == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (i = 0; i < max_time; i++) {
        if (util_generate_random_str(id, (size_t)SANDBOX_ID_MAX_LEN)) {
            ERROR("Generate id failed");
            goto err_out;
        }

        value = sandboxes_store_get_by_id(id);
        if (value != NULL) {
            sandbox_unref(value);
            value = NULL;
            continue;
        } else {
            goto out;
        }
    }

err_out:
    free(id);
    id = NULL;
out:
    return id;
}

static void pack_sandbox_allocate_id_response(sandbox_allocate_id_response *response, const char *id, uint32_t cc)
{
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}


static int sandbox_allocate_id_cb(const sandbox_allocate_id_request *request, sandbox_allocate_id_response **response)
{
    char *sandbox_id = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    sandbox_t *sandbox = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Null request or response for sandbox get-id");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(sandbox_allocate_id_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (!util_valid_container_id_or_name(request->name)) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_INPUT, "Invalid sandbox name: %s", request->name ? request->name : "");
        goto pack_allocate_id_response;
    }

    sandbox = sandboxes_store_get(request->name);
    if (sandbox != NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Conflict. The name \"%s\" is already in use by sandbox %s. "
                           "You have to remove (or rename) that sandbox to be able to reuse that name.",
                           request->name, sandbox->sandboxconfig->id);
        goto pack_allocate_id_response;
    }

    sandbox_id = try_generate_sandbox_id();
    if (sandbox_id == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to generate id for sandbox: %s", request->name);
        goto pack_allocate_id_response;
    }

    if (!sandbox_name_index_add(request->name, sandbox_id)) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to insert to sandbox name-index store, %s: %s", request->name, sandbox_id);
        goto pack_allocate_id_response;
    }

pack_allocate_id_response:
    pack_sandbox_allocate_id_response(*response, sandbox_id, cc);
    sandbox_unref(sandbox);
    free(sandbox_id);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}


static int get_name_id_from_creatre_request(const sandbox_create_request *request,
                                            char **out_id, char **out_name, uint32_t *cc)
{
    int ret = 0;
    char *id = request->id;
    char *name = request->name;
    char *registered_id = NULL;

    if (id == NULL || name == NULL) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_INPUT, "Invalid name or id in create request");
        return -1;
    }

    // TODO: util_valid_container_name needs to be refactored to be used for both container and sandbox
    if (!util_valid_container_name(name)) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_INPUT, "Invalid sandbox name (%s), only [a-zA-Z0-9][a-zA-Z0-9_.-]+$ are allowed.", name);
        ret = -1;
        goto out;
    }

    registered_id = sandbox_name_index_get(name);
    if (registered_id == NULL) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_INPUT, "Sandbox name %s is not registered in name-index store", name);
        ret = -1;
        goto out;
    }

    if (strcmp(id, registered_id) != 0) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_EXEC, "Sandbox id %s doesn't match with name %s in name-index store", id, name);
        ret = -1;
        goto out;
    }

    *out_id = util_strdup_s(id);
    *out_name = util_strdup_s(name);

out:
    free(registered_id);
    return ret;
}

static void pack_sandbox_create_response(sandbox_create_response *response, const char *id, uint32_t cc)
{
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
}

static inline bool is_default_sandboxer(const char *name)
{
    if (strcmp(name, DEFAULT_SANDBOXER_NAME) == 0) {
        return true;
    }
    return false;
}

static bool is_customized_sandboxer(const char* name)
{
    bool ret = true;
    struct service_arguments *args = NULL;
    defs_map_string_object_sandboxers *sandboxers = NULL;

    if (isulad_server_conf_rdlock()) {
        return false;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get isulad server config");
        ret = false;
        goto unlock_out;
    }

    if (args->json_confs != NULL) {
        sandboxers = args->json_confs->sandboxers;
    }
    if (sandboxers == NULL) {
        ret = false;
        goto unlock_out;
    }

    size_t sandboxer_nums = sandboxers->len;
    size_t i;
    for (i = 0; i < sandboxer_nums; i++) {
        if (strcmp(name, sandboxers->keys[i]) == 0) {
            ret = true;
            goto unlock_out;
        }
    }
unlock_out:
    if (isulad_server_conf_unlock()) {
        ERROR("Failed to unlock isulad server config");
        ret = false;
    }

    return ret;
}

static bool sandboxer_check(const char *sandboxer)
{
    if (is_customized_sandboxer(sandboxer) || is_default_sandboxer(sandboxer)) {
        return true;
    }
    return false;
}

static int create_sandbox_root_dir(const char *id, const char *rootdir)
{
    int ret = 0;
    int nret;
    char sandbox_root[PATH_MAX] = { 0x00 };
    // TODO: Check if permission is correct
    mode_t mask = umask(S_IWOTH);
    // TODO: to confirm if userns remap is necessary for sandbox
#ifdef ENABLE_USERNS_REMAP
    char *userns_remap = conf_get_isulad_userns_remap();
#endif

    nret = snprintf(sandbox_root, sizeof(sandbox_root), "%s/%s", rootdir, id);
    if ((size_t)nret >= sizeof(sandbox_root) || nret < 0) {
        ret = -1;
        goto out;
    }
    // create container dir
    nret = util_mkdir_p(sandbox_root, CONFIG_DIRECTORY_MODE);
    if (nret != 0 && errno != EEXIST) {
        SYSERROR("Failed to create sandbox path %s", sandbox_root);
        ret = -1;
        goto out;
    }

#ifdef ENABLE_USERNS_REMAP
    if (set_file_owner_for_userns_remap(sandbox_root, userns_remap) != 0) {
        ERROR("Unable to change directory %s owner for user remap.", sandbox_root);
        ret = -1;
        goto out;
    }
#endif

out:
    umask(mask);
#ifdef ENABLE_USERNS_REMAP
    free(userns_remap);
#endif
    return ret;
}

static int preparate_sandbox_environment(const sandbox_create_request *request, const char *id, char **sandboxer,
                                         char **sandbox_root, uint32_t *cc)
{
    int ret = 0;

    if (util_valid_str(request->runtime)) {
        *sandboxer = util_strings_to_lower(request->runtime);
    } else {
        *sandboxer = conf_get_default_sandboxer();
    }

    if (*sandboxer == NULL) {
        *sandboxer = util_strdup_s(DEFAULT_SANDBOXER_NAME);
    }

    if (!sandboxer_check(*sandboxer)) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_EXEC, "Invalid sandboxer name:%s", *sandboxer);
        ret = -1;
        goto clean;
    }

    *sandbox_root = conf_get_sandbox_rootdir(*sandboxer);
    if (*sandbox_root == NULL) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_EXEC, "Failed to get sandbox root directory");
        ret = -1;
        goto clean;
    }

    if (create_sandbox_root_dir(id, *sandbox_root) != 0) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_EXEC, "Failed to create sandbox root directory");
        ret = -1;
        goto clean;
    }

clean:
    if (ret != 0) {
        free(*sandboxer);
        *sandboxer = NULL;
        free(*sandbox_root);
        *sandbox_root = NULL;
    }
    return ret;
}

static sandbox_t *register_new_sandbox(const char *id, const char *name, const char *sandboxer,
                                       const char *sandbox_rootdir)
{
    int ret = -1;
    bool registered = false;
    char *sandbox_statedir = NULL;
    sandbox_t *sandbox = NULL;

    sandbox_statedir = conf_get_sandbox_statedir(sandboxer);
    if (sandbox_statedir == NULL) {
        goto out;
    }

    sandbox = sandbox_new(name, sandboxer, sandbox_rootdir, sandbox_statedir);
    if (sandbox == NULL) {
        ERROR("Failed to create sandbox '%s'", id);
        goto out;
    }

    registered = sandboxes_store_add(id, sandbox);
    if (!registered) {
        ERROR("Failed to register sandbox '%s'", id);
        goto out;
    }

    ret = 0;

out:
    free(sandbox_statedir);
    if (ret != 0) {
        if (sandbox != NULL) {
            sandbox_unref(sandbox);
            sandbox = NULL;
        }
    } else {
        // return sandbox
        sandbox_refinc(sandbox);
    }
    return sandbox;
}

static int write_sandbox_config(const sandbox_t *sandbox)
{
    int ret = 0;
    parser_error err = NULL;
    char *json_sandbox_config = NULL;

    // TODO: reference chain is too long for sandbox ID, consider add id field in sandbox_t
    if (sandbox->sandboxconfig == NULL) {
        ERROR("Empty sandbox config for sandbox, '%s'", sandbox->sandboxconfig->id);
        return -1;
    }

    json_sandbox_config = sandbox_config_generate_json(sandbox->sandboxconfig, NULL, &err);
    if (json_sandbox_config == NULL) {
        ERROR("Failed to generate sandbox config json string:%s", err ? err : " ");
        ret = -1;
        goto out;
    }

    ret = save_sandbox_config_json(sandbox->sandboxconfig->id, sandbox->rootpath, json_sandbox_config);
    if (ret != 0) {
        ERROR("Failed to save sandbox config json to file");
        ret = -1;
        goto out;
    }

out:
    free(json_sandbox_config);
    free(err);
    return ret;
}

static int write_host_config(const sandbox_t *sandbox)
{
    int ret = 0;
    parser_error err = NULL;
    char *json_host_config = NULL;

    if (sandbox->hostconfig == NULL) {
        ERROR("Empty host config for sandbox, '%s'", sandbox->sandboxconfig->id);
        return -1;
    }

    json_host_config = host_config_generate_json(sandbox->hostconfig, NULL, &err);
    if (json_host_config == NULL) {
        ERROR("Failed to generate sandbox host config json string:%s", err ? err : " ");
        ret = -1;
        goto out;
    }

    ret = save_sandbox_host_config(sandbox->sandboxconfig->id, sandbox->rootpath, json_host_config);
    if (ret != 0) {
        ERROR("Failed to save sandbox host config json to file");
        ret = -1;
        goto out;
    }

out:
    free(json_host_config);
    free(err);

    return ret;
}

static int sandbox_write_config(const sandbox_t *sandbox) {
    int ret = 0;
    if (write_host_config(sandbox) != 0) {
        ret = -1;
    }
    if (write_sandbox_config(sandbox) != 0) {
        ret = -1;
    }
    return ret;
}

static int deserialize_isulad_config_from_request(const sandbox_create_request *request, host_config **out_hostconfig,
                                                  sandbox_config **out_sandboxconfig, uint32_t *cc)
{
    int ret = 0;
    host_config *hostconfig = NULL;
    sandbox_config *sandboxconfig = NULL;
    parser_error err = NULL;

    if(request->isulad_host_config == NULL || request->isulad_sandbox_config == NULL) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_EXEC, "Invalid isulad config for sandbox create request");
        return -1;
    }

    hostconfig = host_config_parse_data(request->isulad_host_config, NULL, &err);
    if (hostconfig == NULL) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_EXEC, "Failed to parse host config data: %s", err);
        ret = -1;
        goto err_out;
    }

    sandboxconfig = sandbox_config_parse_data(request->isulad_sandbox_config, NULL, &err);
    if (sandboxconfig == NULL) {
        SB_CB_ERROR_FORMAT(*cc, ISULAD_ERR_EXEC, "Failed to parse sandbox config data: %s", err);
        ret = -1;
        goto err_out;
    }

    *out_hostconfig = hostconfig;
    *out_sandboxconfig = sandboxconfig;
    hostconfig = NULL;
    sandboxconfig = NULL;

err_out:
    free_host_config(hostconfig);
    free_sandbox_config(sandboxconfig);
    return ret;
}

static int remove_sandbox_from_store(sandbox_t* sandbox)
{
    int ret = 0;
    char *id = sandbox->sandboxconfig->id;
    char *name = sandbox->name;
    if(!sandboxes_store_remove(id)) {
        ERROR("Failed to remove sandbox %s from sandboxes store", id);
        ret = -1;
    }

    if(!sandbox_name_index_remove(name)) {
        ERROR("Failed to remove sandbox %s from name-index store", name);
        ret = -1;
    }

    return ret;
}

static int sandbox_create_cb(const sandbox_create_request *request, sandbox_create_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;
    char *name = NULL;
    host_config *hostconfig = NULL;
    sandbox_config *sandboxconfig = NULL;
    char *sandboxer = NULL;
    char *sandbox_root = NULL;
    sandbox_t *sandbox = NULL;
    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid Null input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(sandbox_create_response));
    if (*response == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_MEMOUT, "Out of memory");
        goto rollback;
    }

    if (deserialize_isulad_config_from_request(request, &hostconfig, &sandboxconfig, &cc) != 0) {
        goto rollback;
    }

    if (get_name_id_from_creatre_request(request, &id, &name, &cc) != 0) {
        goto rollback;
    }

    if (preparate_sandbox_environment(request, id, &sandboxer, &sandbox_root, &cc) != 0) {
        goto rollback;
    }

    // TODO: Sort out network process, does it make sense to have CNI network setup in CRI entry?
    // init_network_confs
    if (init_sandbox_network_confs(id, sandbox_root, hostconfig, sandboxconfig) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to set init network configs, %s", id);
        goto rollback;
    }

    // TODO: log config
    sandbox = register_new_sandbox(id, name, sandboxer, sandbox_root);
    if (sandbox == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to register sandbox, %s", id);
        goto rollback;
    }

    sandbox_fill_sandbox_pod_config_option(sandbox, request->pod_config_option);
    sandbox_fill_host_config(sandbox, hostconfig);
    hostconfig = NULL;
    sandbox_fill_sandbox_config(sandbox, sandboxconfig);
    sandboxconfig = NULL;


    if (sandbox_write_config(sandbox) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to save sandbox config, %s", id);
        goto rollback;
    }

    // TODO: cgroup path init
    // TODO: host channel and share memory?

    if (create_sandbox(sandbox) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to create sandbox");
        goto rollback;
    }

    goto pack_create_response;

rollback:
    // TODO: Rollback in a better way, especially when sandbox_name_index_add invoked in get_id callback
    remove_sandbox_from_store(sandbox);
pack_create_response:
    pack_sandbox_create_response(*response, id, cc);
    free(name);
    free(id);
    free(sandboxer);
    free(sandbox_root);
    free_host_config(hostconfig);
    free_sandbox_config(sandboxconfig);
    sandbox_unref(sandbox);

    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_sandbox_start_response(sandbox_start_response *response, uint32_t cc)
{
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
}

static int sandbox_start_cb(const sandbox_start_request *request, sandbox_start_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;
    char *sandbox_id = NULL;
    sandbox_t *sandbox = NULL;
    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL || request->id == NULL) {
        ERROR("Null request or response for sandbox run");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(sandbox_start_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    sandbox_id = request->id;

    // TODO: Validate sandbox id

    sandbox = sandboxes_store_get(sandbox_id);
    if (sandbox == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to get sandbox by id %s", sandbox_id);
        goto pack_start_response;
    }

    // Check state of sandbox
    if (sandbox_is_ready(sandbox)) {
        INFO("Sandbox has already been started, id='%s'", sandbox_id);
        goto pack_start_response;
    }

    if (start_sandbox(sandbox) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to start sandbox");
    }
pack_start_response:
    pack_sandbox_start_response(*response, cc);
    sandbox_unref(sandbox);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

// TODO: This function is duplicated, use the same one as container
static int sandbox_dup_host_config(const host_config *src, host_config **dest)
{
    int ret = -1;
    char *json = NULL;
    parser_error err = NULL;

    if (src == NULL) {
        *dest = NULL;
        return 0;
    }

    json = host_config_generate_json(src, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    *dest = host_config_parse_data(json, NULL, &err);
    if (*dest == NULL) {
        ERROR("Failed to parse json: %s", err);
        goto out;
    }
    ret = 0;

out:
    free(err);
    free(json);
    return ret;
}

static int sandbox_dup_sandbox_config(const sandbox_config *src, sandbox_config **dest)
{
    int ret = -1;
    char *json = NULL;
    parser_error err = NULL;

    if (src == NULL) {
        *dest = NULL;
        return 0;
    }

    json = sandbox_config_generate_json(src, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    *dest = sandbox_config_parse_data(json, NULL, &err);
    if (*dest == NULL) {
        ERROR("Failed to parse json: %s", err);
        goto out;
    }
    ret = 0;

out:
    free(err);
    free(json);
    return ret;
}

static int sandbox_inspect_cb(const sandbox_inspect_request *request, sandbox_inspect_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;
    sandbox_t *sandbox_store_obj = NULL;
    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid inspect arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(sandbox_inspect_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    sandbox_store_obj = sandboxes_store_get(request->id_or_name);
    if (sandbox_store_obj == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "No such sandbox: %s", request->id_or_name);
        goto clean;
    }

    (*response)->id = util_strdup_s(sandbox_store_obj->sandboxconfig->id);

    if (sandbox_dup_host_config(sandbox_store_obj->hostconfig, &(*response)->isulad_host_config) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to dup host config");
        goto clean;
    }

    // TODO: Reconsider names of inspect field
    if (sandbox_dup_sandbox_config(sandbox_store_obj->sandboxconfig, &(*response)->isulad_sandbox_config) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to dup sandbox config");
        goto clean;
    }

clean:
    sandbox_unref(sandbox_store_obj);
    if (cc != ISULAD_SUCCESS) {
        if (*response != NULL) {
            (*response)->cc = cc;
            if (g_isulad_errmsg != NULL) {
                (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
                DAEMON_CLEAR_ERRMSG();
            }
        }
        return -1;
    }
    return 0;
}

static void pack_sandbox_stop_response(sandbox_stop_response *response, uint32_t cc)
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

static int sandbox_stop_cb(const sandbox_stop_request *request, sandbox_stop_response **response)
{
    sandbox_t *sandbox_store_obj = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid stop arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(sandbox_stop_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    sandbox_store_obj = sandboxes_store_get(request->id);
    if (sandbox_store_obj == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "No such sandbox: %s", request->id);
        goto clean;
    }
    if (stop_sandbox(sandbox_store_obj) !=0){
        // TODO to think what todo if we cant stop sandbox
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Unable to stop sandbox %s", request->id);
        goto clean;
    }
clean:
    pack_sandbox_stop_response(*response, cc);
    sandbox_unref(sandbox_store_obj);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_remove_response(sandbox_remove_response *response, uint32_t cc)
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


static int remove_sandbox_root_dir(const char *id, const char *rootdir)
{
    int ret = 0;
    int nret;
    char sandbox_root[PATH_MAX] = { 0x00 };

    nret = snprintf(sandbox_root, sizeof(sandbox_root), "%s/%s", rootdir, id);
    if ((size_t)nret >= sizeof(sandbox_root) || nret < 0) {
        ret = -1;
        goto out;
    }
    // create container dir
    nret = util_recursive_remove_path(sandbox_root);
    if (nret != 0 && errno != EEXIST) {
        SYSERROR("Failed to remove sandbox path %s", sandbox_root);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int sandbox_remove_cb(const sandbox_remove_request *request, sandbox_remove_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;
    sandbox_t *sandbox = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(sandbox_remove_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (!util_valid_container_id_or_name(request->id)) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Invalid sandbox name: %s", request->id);
        goto pack_response;
    }

    sandbox = sandboxes_store_get(request->id);
    if (sandbox == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to get sandbox ID for sandbox run callback");
        goto pack_response;
    }

    id = sandbox->sandboxconfig->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Removing}", id);

    // TODO: Check if the removal is already in progress?
    //       Set sandbox to removal in progress
    if (delete_sandbox(sandbox, request->force) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to delete sandbox, %s", id);
        goto pack_response;
    }

    if (remove_sandbox_root_dir(id, sandbox->rootpath) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to remove sandbox rootdir, %s", id);
        goto pack_response;
    }

    if (remove_sandbox_from_store(sandbox) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to remove sandbox from store, %s", id);
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Removed}", id);

pack_response:
    pack_remove_response(*response, cc);
    sandbox_unref(sandbox);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int sandbox_status_cb(const sandbox_status_request *request, sandbox_status_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;
    sandbox_t *sandbox_store_obj = NULL;
    if (request == NULL || response == NULL) {
        ERROR("Invalid callback arguments.");
        return -1;
    }

    *response = (sandbox_status_response *)util_common_calloc_s(sizeof(*response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    sandbox_store_obj = sandboxes_store_get(request->id);
    if (sandbox_store_obj == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "No such sandbox: %s", request->id);
        goto clean;
    }

    (*response)->status = util_common_calloc_s(sizeof(sandbox_status));
    if ((*response)->status == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_MEMOUT,"Out of memory");
        goto clean;
    }

    // TODO: Maybe use boolean state is better, since we have to copy string here
    if (sandbox_store_obj->status==SANDBOX_READY){
        (*response)->status->state = util_strdup_s("READY");
    } else {
        (*response)->status->state = util_strdup_s("NOT_READY");
    }
    (*response)->status->created_at = sandbox_store_obj->created_at;
    (*response)->status->id = util_strdup_s(request->id);
clean:
    sandbox_unref(sandbox_store_obj);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static size_t get_all_sandbox_ids(map_t *map_id_name, char **id_array, size_t id_size)
{
    size_t count = 0;

    map_itor *itor = map_itor_new(map_id_name);
    if (itor == NULL) {
        ERROR("Out of memory");
        return count;
    }

    while(count < id_size && map_itor_valid(itor)) {
        id_array[count] = util_strdup_s((const char*)map_itor_key(itor));
        count++;
        map_itor_next(itor);
    };

    map_itor_free(itor);

    return count;
}

static json_map_string_string *make_json_map_from(json_map_string_string *src)
{
    if (src == NULL) {
        return NULL;
    }
    json_map_string_string *dest = util_common_calloc_s(sizeof(json_map_string_string));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    if (dup_json_map_string_string(src, dest)) {
        ERROR("Failed to dup json map");
        free_json_map_string_string(dest);
        return NULL;
    };
    return dest;
}

static void fill_sandbox_info(sandbox_sandbox *sandbox_info, sandbox_t *sandbox)
{
    sandbox_info->id = util_strdup_s(sandbox->sandboxconfig->id);
    sandbox_info->metadata_name = util_strdup_s(sandbox->sandboxconfig->metadata_name);
    sandbox_info->metadata_uid = util_strdup_s(sandbox->sandboxconfig->metadata_uid);
    sandbox_info->metadata_namespace = util_strdup_s(sandbox->sandboxconfig->metadata_namespace);
    sandbox_info->metadata_attempt = sandbox->sandboxconfig->metadata_attempt;
    sandbox_info->ready = (sandbox->status == SANDBOX_READY);
    sandbox_info->created_at = sandbox->created_at;
    sandbox_info->runtime = util_strdup_s(sandbox->sandboxer);
    sandbox_info->labels = util_common_calloc_s(sizeof(json_map_string_string));
    sandbox_info->labels = make_json_map_from(sandbox->sandboxconfig->labels);
    sandbox_info->annotations = make_json_map_from(sandbox->sandboxconfig->annotations);
}

static sandbox_sandbox *get_sandbox_info(char *sandbox_id)
{
    int ret = 0;
    sandbox_t *sandbox = NULL;
    sandbox_sandbox *sandbox_info = NULL;
    
    sandbox = sandboxes_store_get(sandbox_id);
    if (sandbox == NULL) {
        ERROR("Sandbox '%s' doesn't exist", sandbox_id);
        return NULL;
    }

    sandbox_info = util_common_calloc_s(sizeof(sandbox_sandbox));
    if (sandbox_info == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    fill_sandbox_info(sandbox_info, sandbox);

out:
    sandbox_unref(sandbox);
    if (ret != 0) {
        free_sandbox_sandbox(sandbox_info);
        sandbox_info = NULL;
    }
    return sandbox_info;
}

static int pack_sandbox_list_response(char **id_array, size_t id_size, sandbox_list_response *response)
{
    size_t count = 0;
    response->sandboxes = util_smart_calloc_s(sizeof(sandbox_sandbox*), id_size);
    if (response->sandboxes == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for(count = 0; count < id_size; count++) {
        response->sandboxes[count] = get_sandbox_info(id_array[count]);
    }
    response->sandboxes_len = id_size;
    return 0;
}

static void free_sandbox_id_array(char **id_array, size_t id_size)
{
    size_t count = 0;
    if (id_array == NULL) {
        return;
    }
    for(count = 0; count < id_size; count++) {
        free(id_array[count]);
    }
}

// TODO: Simple implementation for now with all sandboxes info dumped
//       Add filter later
static int sandbox_list_cb(const sandbox_list_request *request, sandbox_list_response **response)
{
    map_t *map_id_name = NULL;
    char **id_array = NULL;
    size_t id_size = 0;
    size_t count = 0;
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(sandbox_list_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    // Get id name for name filtering
    map_id_name = sandbox_name_index_get_all();
    if (map_id_name == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to get all entries from name-index store");
        goto pack_response;
    }

    id_size = map_size(map_id_name);
    if (id_size == 0) {
        goto pack_response;
    }

    id_array = util_smart_calloc_s(sizeof(char*), id_size);
    if (id_array == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }
    count = get_all_sandbox_ids(map_id_name, id_array, id_size);

    if (pack_sandbox_list_response(id_array, count, *response) != 0) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Failed to pack sandbox list");
        goto pack_response;
    }

pack_response:
    map_free(map_id_name);
    free_sandbox_id_array(id_array, id_size);
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_sandbox_get_id_response(sandbox_get_id_response *response, const char *id, uint32_t cc)
{
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

// TODO: allow generate new ID
static int sandbox_get_id_cb(const sandbox_get_id_request *request, sandbox_get_id_response **response)
{
    char *sandbox_id = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    sandbox_t *sandbox = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Null request or response for sandbox get-id");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(sandbox_get_id_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (!util_valid_container_id_or_name(request->id_or_name)) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Invalid sandbox name: %s", request->id_or_name ? request->id_or_name : "");
        goto pack_get_id_response;
    }

    sandbox = sandboxes_store_get(request->id_or_name);
    if (sandbox == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "No such sandbox: %s", request->id_or_name);
        goto pack_get_id_response;
    }

    sandbox_id = sandbox->sandboxconfig->id;

pack_get_id_response:
    pack_sandbox_get_id_response(*response, sandbox_id, cc);
    sandbox_unref(sandbox);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_sandbox_get_runtime_response(sandbox_get_runtime_response *response, const char *runtime, uint32_t cc)
{
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (runtime != NULL) {
        response->runtime = util_strdup_s(runtime);
    }
}

static int sandbox_get_runtime_cb(const char *sandbox_id, sandbox_get_runtime_response **response)
{
    char *runtime = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    sandbox_t *sandbox = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (sandbox_id == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(sandbox_get_runtime_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (!util_valid_container_id_or_name(sandbox_id)) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "Invalid sandbox name: %s", sandbox_id);
        goto pack_response;
    }

    sandbox = sandboxes_store_get(sandbox_id);
    if (sandbox == NULL) {
        SB_CB_ERROR_FORMAT(cc, ISULAD_ERR_EXEC, "No such sandbox: %s", sandbox_id);
        goto pack_response;
    }

    runtime = sandbox->sandboxer;

pack_response:
    pack_sandbox_get_runtime_response(*response, runtime, cc);
    sandbox_unref(sandbox);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

/* sandbox callback init */
void sandbox_callback_init(service_sandbox_callback_t *cb)
{
    if (cb == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    cb->allocate_id = sandbox_allocate_id_cb;
    cb->create = sandbox_create_cb;
    cb->start = sandbox_start_cb;
    cb->inspect = sandbox_inspect_cb;
    cb->stop = sandbox_stop_cb;
    cb->remove = sandbox_remove_cb;
    cb->status = sandbox_status_cb;
    cb->list = sandbox_list_cb;
    cb->get_id = sandbox_get_id_cb;
    cb->get_runtime = sandbox_get_runtime_cb;
}