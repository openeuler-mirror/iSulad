/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container lcrc library functions
 ******************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include "liblcrc.h"
#include "log.h"
#include "pack_config.h"
#include "utils.h"

/* lcrc filters free */
void lcrc_filters_free(struct lcrc_filters *filters)
{
    size_t i;
    if (filters == NULL) {
        return;
    }
    for (i = 0; i < filters->len; i++) {
        free(filters->keys[i]);
        filters->keys[i] = NULL;
        free(filters->values[i]);
        filters->values[i] = NULL;
    }
    free(filters->keys);
    filters->keys = NULL;
    free(filters->values);
    filters->values = NULL;
    free(filters);
}

struct lcrc_filters *lcrc_filters_parse_args(const char **array, size_t len)
{
    struct lcrc_filters *filters = NULL;
    size_t i;

    if (len == 0 || array == NULL) {
        return NULL;
    }

    if (len > (SIZE_MAX / sizeof(char *))) {
        ERROR("Too many filters");
        return NULL;
    }

    filters = util_common_calloc_s(sizeof(*filters));
    if (filters == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    filters->keys = util_common_calloc_s(sizeof(char *) * len);
    if (filters->keys == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }
    filters->values = util_common_calloc_s(sizeof(char *) * len);
    if (filters->values == NULL) {
        free(filters->keys);
        filters->keys = NULL;
        ERROR("Out of memory");
        goto cleanup;
    }

    for (i = 0; i < len; i++) {
        char *valuepos = NULL;
        char *copy = NULL;
        char *lowerkey = NULL;
        if (strlen(array[i]) == 0) {
            continue;
        }
        copy = util_strdup_s(array[i]);
        valuepos = strchr(copy, '=');
        if (valuepos == NULL) {
            COMMAND_ERROR("Bad format of filter '%s', (expected name=value)", copy);
            free(copy);
            goto cleanup;
        }
        *valuepos++ = '\0';
        filters->values[filters->len] = util_strdup_s(util_trim_space(valuepos));
        lowerkey = strings_to_lower(util_trim_space(copy));
        free(copy);
        if (lowerkey == NULL) {
            free(filters->values[filters->len]);
            filters->values[filters->len] = NULL;
            ERROR("Out of memory");
            goto cleanup;
        }
        filters->keys[filters->len] = lowerkey;
        filters->len++;
    }
    return filters;
cleanup:
    lcrc_filters_free(filters);
    return NULL;
}

/* lcrc container info free */
void lcrc_container_info_free(struct lcrc_container_info *info)
{
    if (info == NULL) {
        return;
    }

    free(info->id);
    info->id = NULL;
    free(info);
}

/* lcrc version request free */
void lcrc_version_request_free(struct lcrc_version_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request);
}

/* lcrc version response free */
void lcrc_version_response_free(struct lcrc_version_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response->version);
    response->version = NULL;

    free(response->git_commit);
    response->git_commit = NULL;

    free(response->build_time);
    response->build_time = NULL;

    free(response->root_path);
    response->root_path = NULL;

    free(response);
}

/* lcrc info request free */
void lcrc_info_request_free(struct lcrc_info_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request);
}

/* lcrc info response free */
void lcrc_info_response_free(struct lcrc_info_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response->version);
    response->version = NULL;

    free(response->kversion);
    response->kversion = NULL;

    free(response->os_type);
    response->os_type = NULL;

    free(response->architecture);
    response->architecture = NULL;

    free(response->nodename);
    response->nodename = NULL;

    free(response->operating_system);
    response->operating_system = NULL;

    free(response->cgroup_driver);
    response->cgroup_driver = NULL;

    free(response->logging_driver);
    response->logging_driver = NULL;

    free(response->huge_page_size);
    response->huge_page_size = NULL;

    free(response->isulad_root_dir);
    response->isulad_root_dir = NULL;

    free(response->http_proxy);
    response->http_proxy = NULL;

    free(response->https_proxy);
    response->https_proxy = NULL;

    free(response->no_proxy);
    response->no_proxy = NULL;
    free(response);
}

void lcrc_ns_change_files_free(lcrc_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    util_free_array(hostconfig->ns_change_files);
    hostconfig->ns_change_files = NULL;
    hostconfig->ns_change_files_len = 0;
}

void lcrc_host_config_storage_opts_free(lcrc_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    free_json_map_string_string(hostconfig->storage_opts);
    hostconfig->storage_opts = NULL;
}

void lcrc_host_config_sysctl_free(lcrc_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    free_json_map_string_string(hostconfig->sysctls);
    hostconfig->sysctls = NULL;
}

/* lcrc host config free */
void lcrc_host_config_free(lcrc_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    util_free_array(hostconfig->cap_add);
    hostconfig->cap_add = NULL;
    hostconfig->cap_add_len = 0;

    util_free_array(hostconfig->cap_drop);
    hostconfig->cap_drop = NULL;
    hostconfig->cap_drop_len = 0;

    free_json_map_string_string(hostconfig->storage_opts);
    hostconfig->storage_opts = NULL;

    free_json_map_string_string(hostconfig->sysctls);
    hostconfig->sysctls = NULL;

    util_free_array(hostconfig->devices);
    hostconfig->devices = NULL;
    hostconfig->devices_len = 0;

    util_free_array(hostconfig->hugetlbs);
    hostconfig->hugetlbs = NULL;
    hostconfig->hugetlbs_len = 0;

    free(hostconfig->network_mode);
    hostconfig->network_mode = NULL;

    free(hostconfig->ipc_mode);
    hostconfig->ipc_mode = NULL;

    free(hostconfig->pid_mode);
    hostconfig->pid_mode = NULL;

    free(hostconfig->uts_mode);
    hostconfig->uts_mode = NULL;

    free(hostconfig->userns_mode);
    hostconfig->userns_mode = NULL;

    free(hostconfig->user_remap);
    hostconfig->user_remap = NULL;

    util_free_array(hostconfig->ulimits);
    hostconfig->ulimits = NULL;
    hostconfig->ulimits_len = 0;

    free(hostconfig->restart_policy);
    hostconfig->restart_policy = NULL;

    free(hostconfig->host_channel);
    hostconfig->host_channel = NULL;

    free(hostconfig->hook_spec);
    hostconfig->hook_spec = NULL;

    free(hostconfig->env_target_file);
    hostconfig->env_target_file = NULL;

    free(hostconfig->cgroup_parent);
    hostconfig->cgroup_parent = NULL;

    util_free_array(hostconfig->binds);
    hostconfig->binds = NULL;
    hostconfig->binds_len = 0;

    util_free_array(hostconfig->blkio_weight_device);
    hostconfig->blkio_weight_device = NULL;
    hostconfig->blkio_weight_device_len = 0;

    container_cgroup_resources_free(hostconfig->cr);
    hostconfig->cr = NULL;

    free(hostconfig);
}

/* lcrc container config free */
void lcrc_container_config_free(lcrc_container_config_t *config)
{
    if (config == NULL) {
        return;
    }

    util_free_array(config->env);
    config->env = NULL;
    config->env_len = 0;

    free(config->hostname);
    config->hostname = NULL;

    free(config->user);
    config->user = NULL;

    util_free_array(config->mounts);
    config->mounts = NULL;
    config->mounts_len = 0;

    util_free_array(config->cmd);
    config->cmd = NULL;
    config->cmd_len = 0;

    free(config->entrypoint);
    config->entrypoint = NULL;

    free(config->log_file);
    config->log_file = NULL;

    free(config->log_file_size);
    config->log_file_size = NULL;

    free_json_map_string_string(config->annotations);
    config->annotations = NULL;

    free(config->workdir);
    config->workdir = NULL;

    free(config);
}

/* lcrc create request free */
void lcrc_create_request_free(struct lcrc_create_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request->rootfs);
    request->rootfs = NULL;

    free(request->image);
    request->image = NULL;

    free(request->runtime);
    request->runtime = NULL;

    lcrc_host_config_free(request->hostconfig);
    request->hostconfig = NULL;

    lcrc_container_config_free(request->config);
    request->config = NULL;
    free(request);
}

/* lcrc create response free */
void lcrc_create_response_free(struct lcrc_create_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response->id);
    response->id = NULL;

    free(response);
}

/* lcrc start request free */
void lcrc_start_request_free(struct lcrc_start_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request->stdin);
    request->stdin = NULL;

    free(request->stdout);
    request->stdout = NULL;

    free(request->stderr);
    request->stderr = NULL;

    free(request);
}

/* lcrc start response free */
void lcrc_start_response_free(struct lcrc_start_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc_top_request_free */
void lcrc_top_request_free(struct lcrc_top_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    if (request->ps_argc && request->ps_args != NULL) {
        int i;
        for (i = 0; i < request->ps_argc; i++) {
            free(request->ps_args[i]);
            request->ps_args[i] = NULL;
        }
        free(request->ps_args);
        request->ps_args = NULL;
        request->ps_argc = 0;
    }

    free(request);
}
/* lcrc_top_response_free */
void lcrc_top_response_free(struct lcrc_top_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->titles);
    response->titles = NULL;

    if (response->processes_len && response->processes != NULL) {
        size_t i;
        for (i = 0; i < response->processes_len; i++) {
            free(response->processes[i]);
            response->processes[i] = NULL;
        }
        free(response->processes);
        response->processes = NULL;
        response->processes_len = 0;
    }

    free(response);
}

/* lcrc stop request free */
void lcrc_stop_request_free(struct lcrc_stop_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request);
}

/* lcrc stop response free */
void lcrc_stop_response_free(struct lcrc_stop_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc restart request free */
void lcrc_restart_request_free(struct lcrc_restart_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request);
}

/* lcrc restart response free */
void lcrc_restart_response_free(struct lcrc_restart_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc delete request free */
void lcrc_delete_request_free(struct lcrc_delete_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request);
}

/* lcrc delete response free */
void lcrc_delete_response_free(struct lcrc_delete_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response->name);
    response->name = NULL;

    free(response);
}

/* lcrc list request free */
void lcrc_list_request_free(struct lcrc_list_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request);
}

/* lcrc list response free */
void lcrc_list_response_free(struct lcrc_list_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    if (response->container_num > 0 && response->container_summary != NULL) {
        int i;
        for (i = 0; i < (int)response->container_num; i++) {
            if (response->container_summary[i]->id != NULL) {
                free(response->container_summary[i]->id);
                response->container_summary[i]->id = NULL;
            }
            if (response->container_summary[i]->name != NULL) {
                free(response->container_summary[i]->name);
                response->container_summary[i]->name = NULL;
            }
            if (response->container_summary[i]->runtime != NULL) {
                free(response->container_summary[i]->runtime);
                response->container_summary[i]->runtime = NULL;
            }
            if (response->container_summary[i]->image != NULL) {
                free(response->container_summary[i]->image);
                response->container_summary[i]->image = NULL;
            }
            if (response->container_summary[i]->command != NULL) {
                free(response->container_summary[i]->command);
                response->container_summary[i]->command = NULL;
            }
            if (response->container_summary[i]->startat != NULL) {
                free(response->container_summary[i]->startat);
                response->container_summary[i]->startat = NULL;
            }
            if (response->container_summary[i]->finishat != NULL) {
                free(response->container_summary[i]->finishat);
                response->container_summary[i]->finishat = NULL;
            }
            if (response->container_summary[i]->health_state != NULL) {
                free(response->container_summary[i]->health_state);
                response->container_summary[i]->health_state = NULL;
            }
            free(response->container_summary[i]);
            response->container_summary[i] = NULL;
        }
        free(response->container_summary);
        response->container_summary = NULL;
    }
    free(response);
}

/* lcrc exec request free */
void lcrc_exec_request_free(struct lcrc_exec_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request->suffix);
    request->suffix = NULL;

    free(request->stdout);
    request->stdout = NULL;

    free(request->stdin);
    request->stdin = NULL;

    free(request->stderr);
    request->stderr = NULL;

    if (request->argc && request->argv != NULL) {
        int i;
        for (i = 0; i < request->argc; i++) {
            free(request->argv[i]);
            request->argv[i] = NULL;
        }
        free(request->argv);
        request->argv = NULL;
        request->argc = 0;
    }
    if (request->env_len && request->env != NULL) {
        size_t j;
        for (j = 0; j < request->env_len; j++) {
            free(request->env[j]);
            request->env[j] = NULL;
        }
        free(request->env);
        request->env = NULL;
        request->env_len = 0;
    }
    free(request);
}

/* lcrc exec response free */
void lcrc_exec_response_free(struct lcrc_exec_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc attach request free */
void lcrc_attach_request_free(struct lcrc_attach_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request->stderr);
    request->stderr = NULL;

    free(request->stdout);
    request->stdout = NULL;

    free(request->stdin);
    request->stdin = NULL;

    free(request);
}

/* lcrc attach response free */
void lcrc_attach_response_free(struct lcrc_attach_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc pause request free */
void lcrc_pause_request_free(struct lcrc_pause_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;
    free(request);
}

/* lcrc pause response free */
void lcrc_pause_response_free(struct lcrc_pause_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc resume request free */
void lcrc_resume_request_free(struct lcrc_resume_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;
    free(request);
}

/* lcrc resume response free */
void lcrc_resume_response_free(struct lcrc_resume_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc kill request free */
void lcrc_kill_request_free(struct lcrc_kill_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;
    free(request);
}

/* lcrc kill response free */
void lcrc_kill_response_free(struct lcrc_kill_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;
    free(response);
}

/* lcrc update config free */
void lcrc_update_config_free(lcrc_update_config_t *config)
{
    if (config == NULL) {
        return;
    }

    free(config->restart_policy);
    config->restart_policy = NULL;

    container_cgroup_resources_free(config->cr);
    config->cr = NULL;

    free(config);
}

/* lcrc update request free */
void lcrc_update_request_free(struct lcrc_update_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    lcrc_update_config_free(request->updateconfig);
    request->updateconfig = NULL;

    free(request);
}

/* lcrc update response free */
void lcrc_update_response_free(struct lcrc_update_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc stats request free */
void lcrc_stats_request_free(struct lcrc_stats_request *request)
{
    size_t i = 0;

    if (request == NULL) {
        return;
    }

    for (i = 0; i < request->containers_len; i++) {
        free(request->containers[i]);
        request->containers[i] = NULL;
    }

    free(request->containers);
    request->containers = NULL;

    free(request);
}

/* lcrc stats response free */
void lcrc_stats_response_free(struct lcrc_stats_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    if (response->container_stats != NULL && response->container_num) {
        size_t i;
        for (i = 0; i < response->container_num; i++) {
            free(response->container_stats[i].id);
            response->container_stats[i].id = NULL;
        }
        free(response->container_stats);
        response->container_stats = NULL;
    }
    free(response);
}

/* lcrc events request free */
void lcrc_events_request_free(struct lcrc_events_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;

    free(request);
}

/* lcrc events response free */
void lcrc_events_response_free(struct lcrc_events_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

void lcrc_copy_from_container_request_free(struct lcrc_copy_from_container_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;
    free(request->runtime);
    request->runtime = NULL;
    free(request->srcpath);
    request->srcpath = NULL;

    free(request);
}

void lcrc_copy_from_container_response_free(struct lcrc_copy_from_container_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;
    free_container_path_stat(response->stat);
    response->stat = NULL;
    free(response);
}

void lcrc_copy_to_container_request_free(struct lcrc_copy_to_container_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;
    free(request->runtime);
    request->runtime = NULL;
    free(request->srcpath);
    request->srcpath = NULL;
    free(request->srcrebase);
    request->srcrebase = NULL;
    free(request->dstpath);
    request->dstpath = NULL;

    free(request);
}

void lcrc_copy_to_container_response_free(struct lcrc_copy_to_container_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc inspect request free */
void lcrc_inspect_request_free(struct lcrc_inspect_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request);
}

/* lcrc inspect response free */
void lcrc_inspect_response_free(struct lcrc_inspect_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response->json);
    response->json = NULL;

    free(response);
}

/* lcrc wait request free */
void lcrc_wait_request_free(struct lcrc_wait_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;
    free(request);
}

/* lcrc wait response free */
void lcrc_wait_response_free(struct lcrc_wait_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc health check request free */
void lcrc_health_check_request_free(struct lcrc_health_check_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->service);
    request->service = NULL;

    free(request);
}

/* lcrc health check response free */
void lcrc_health_check_response_free(struct lcrc_health_check_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc create image request free */
void lcrc_create_image_request_free(struct lcrc_create_image_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->image_info.imageref);
    request->image_info.imageref = NULL;

    free(request->image_info.type);
    request->image_info.type = NULL;

    free(request->image_info.digest);
    request->image_info.digest = NULL;

    free(request);
    return;
}

/* lcrc create image response free */
void lcrc_create_image_response_free(struct lcrc_create_image_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response->image_info.imageref);
    response->image_info.imageref = NULL;

    free(response->image_info.type);
    response->image_info.type = NULL;

    free(response->image_info.digest);
    response->image_info.digest = NULL;

    free(response);
    return;
}

/* lcrc images list free */
void lcrc_images_list_free(size_t images_num, struct lcrc_image_info *images_list)
{
    int i = 0;
    struct lcrc_image_info *in = NULL;

    if (images_num == 0 || images_list == NULL) {
        return;
    }

    for (i = 0, in = images_list; i < (int)images_num; i++, in++) {
        free(in->imageref);
        free(in->type);
        free(in->digest);
    }

    free(images_list);
    return;
}

/* lcrc list images request free */
void lcrc_list_images_request_free(struct lcrc_list_images_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request);
    return;
}

/* lcrc list images response free */
void lcrc_list_images_response_free(struct lcrc_list_images_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    lcrc_images_list_free(response->images_num, response->images_list);
    response->images_num = 0;
    response->images_list = NULL;
    free(response);
}

/* lcrc rmi request free */
void lcrc_rmi_request_free(struct lcrc_rmi_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->image_name);
    request->image_name = NULL;

    free(request);
    return;
}

/* lcrc rmi response free */
void lcrc_rmi_response_free(struct lcrc_rmi_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* lcrc pull response free */
void lcrc_pull_request_free(struct lcrc_pull_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->image_name);
    request->image_name = NULL;

    free(request);
    return;
}

/* lcrc pull response free */
void lcrc_pull_response_free(struct lcrc_pull_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->image_ref);
    response->image_ref = NULL;

    free(response->errmsg);
    response->errmsg = NULL;
    free(response);
    return;
}

/* lcrc load request free */
void lcrc_load_request_free(struct lcrc_load_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->file);
    request->file = NULL;

    free(request->type);
    request->type = NULL;

    free(request->tag);
    request->tag = NULL;

    free(request);
    return;
}

/* lcrc load response free */
void lcrc_load_response_free(struct lcrc_load_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* lcrc login response free */
void lcrc_login_response_free(struct lcrc_login_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* lcrc logout response free */
void lcrc_logout_response_free(struct lcrc_logout_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* lcrc export request free */
void lcrc_export_request_free(struct lcrc_export_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request->file);
    request->file = NULL;

    free(request);
}

/* lcrc export response free */
void lcrc_export_response_free(struct lcrc_export_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc rename request free */
void lcrc_rename_request_free(struct lcrc_rename_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->old_name);
    request->old_name = NULL;

    free(request->new_name);
    request->new_name = NULL;

    free(request);
}

/* lcrc rename response free */
void lcrc_rename_response_free(struct lcrc_rename_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* lcrc resize request free */
void lcrc_resize_request_free(struct lcrc_resize_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;

    free(request->suffix);
    request->suffix = NULL;

    free(request);
}

/* lcrc resize response free */
void lcrc_resize_response_free(struct lcrc_resize_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}


/* lcrc logs request free */
void lcrc_logs_request_free(struct lcrc_logs_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;
    free(request->runtime);
    request->runtime = NULL;
    free(request->since);
    request->since = NULL;
    free(request->until);
    request->until = NULL;

    free(request);
}

/* lcrc logs response free */
void lcrc_logs_response_free(struct lcrc_logs_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

