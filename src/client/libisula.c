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
 * Create: 2018-11-08
 * Description: provide container isula library functions
 ******************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include "libisula.h"
#include "isula_libutils/log.h"
#include "utils.h"

/* isula filters free */
void isula_filters_free(struct isula_filters *filters)
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

struct isula_filters *isula_filters_parse_args(const char **array, size_t len)
{
    struct isula_filters *filters = NULL;
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
    isula_filters_free(filters);
    return NULL;
}

/* isula container info free */
void isula_container_info_free(struct isula_container_info *info)
{
    if (info == NULL) {
        return;
    }

    free(info->id);
    info->id = NULL;
    free(info);
}

/* isula version request free */
void isula_version_request_free(struct isula_version_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request);
}

/* isula version response free */
void isula_version_response_free(struct isula_version_response *response)
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

/* isula info request free */
void isula_info_request_free(struct isula_info_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request);
}

/* isula info response free */
void isula_info_response_free(struct isula_info_response *response)
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

    free(response->driver_name);
    response->driver_name = NULL;

    free(response->driver_status);
    response->driver_status = NULL;

    free(response);
}

void isula_ns_change_files_free(isula_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    util_free_array_by_len(hostconfig->ns_change_files, hostconfig->ns_change_files_len);
    hostconfig->ns_change_files = NULL;
    hostconfig->ns_change_files_len = 0;
}

void isula_host_config_storage_opts_free(isula_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    free_json_map_string_string(hostconfig->storage_opts);
    hostconfig->storage_opts = NULL;
}

void isula_host_config_sysctl_free(isula_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    free_json_map_string_string(hostconfig->sysctls);
    hostconfig->sysctls = NULL;
}

/* isula host config free */
void isula_host_config_free(isula_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    util_free_array_by_len(hostconfig->cap_add, hostconfig->cap_add_len);
    hostconfig->cap_add = NULL;
    hostconfig->cap_add_len = 0;

    util_free_array_by_len(hostconfig->cap_drop, hostconfig->cap_drop_len);
    hostconfig->cap_drop = NULL;
    hostconfig->cap_drop_len = 0;

    free_json_map_string_string(hostconfig->storage_opts);
    hostconfig->storage_opts = NULL;

    free_json_map_string_string(hostconfig->sysctls);
    hostconfig->sysctls = NULL;

    util_free_array_by_len(hostconfig->devices, hostconfig->devices_len);
    hostconfig->devices = NULL;
    hostconfig->devices_len = 0;

    util_free_array_by_len(hostconfig->hugetlbs, hostconfig->hugetlbs_len);
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

    util_free_array_by_len(hostconfig->ulimits, hostconfig->ulimits_len);
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

    util_free_array_by_len(hostconfig->binds, hostconfig->binds_len);
    hostconfig->binds = NULL;
    hostconfig->binds_len = 0;

    util_free_array_by_len(hostconfig->blkio_weight_device, hostconfig->blkio_weight_device_len);
    hostconfig->blkio_weight_device = NULL;
    hostconfig->blkio_weight_device_len = 0;

    container_cgroup_resources_free(hostconfig->cr);
    hostconfig->cr = NULL;

    free(hostconfig);
}

/* isula container config free */
void isula_container_config_free(isula_container_config_t *config)
{
    if (config == NULL) {
        return;
    }

    util_free_array_by_len(config->env, config->env_len);
    config->env = NULL;
    config->env_len = 0;

    free(config->hostname);
    config->hostname = NULL;

    free(config->user);
    config->user = NULL;

    util_free_array_by_len(config->mounts, config->mounts_len);
    config->mounts = NULL;
    config->mounts_len = 0;

    util_free_array_by_len(config->cmd, config->cmd_len);
    config->cmd = NULL;
    config->cmd_len = 0;

    free(config->entrypoint);
    config->entrypoint = NULL;

    free(config->log_driver);
    config->log_driver = NULL;

    free_json_map_string_string(config->annotations);
    config->annotations = NULL;

    free(config->workdir);
    config->workdir = NULL;

    free(config);
}

/* isula create request free */
void isula_create_request_free(struct isula_create_request *request)
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

    isula_host_config_free(request->hostconfig);
    request->hostconfig = NULL;

    isula_container_config_free(request->config);
    request->config = NULL;
    free(request);
}

/* isula create response free */
void isula_create_response_free(struct isula_create_response *response)
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

/* isula start request free */
void isula_start_request_free(struct isula_start_request *request)
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

/* isula start response free */
void isula_start_response_free(struct isula_start_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula_top_request_free */
void isula_top_request_free(struct isula_top_request *request)
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
/* isula_top_response_free */
void isula_top_response_free(struct isula_top_response *response)
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

/* isula stop request free */
void isula_stop_request_free(struct isula_stop_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request);
}

/* isula stop response free */
void isula_stop_response_free(struct isula_stop_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula restart request free */
void isula_restart_request_free(struct isula_restart_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request);
}

/* isula restart response free */
void isula_restart_response_free(struct isula_restart_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula delete request free */
void isula_delete_request_free(struct isula_delete_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request);
}

/* isula delete response free */
void isula_delete_response_free(struct isula_delete_response *response)
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

/* isula list request free */
void isula_list_request_free(struct isula_list_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request);
}

/* isula list response free */
void isula_list_response_free(struct isula_list_response *response)
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

/* isula exec request free */
void isula_exec_request_free(struct isula_exec_request *request)
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

    free(request->user);
    request->user = NULL;

    util_free_array_by_len(request->argv, request->argc);
    request->argv = NULL;
    request->argc = 0;

    util_free_array_by_len(request->env, request->env_len);
    request->env = NULL;
    request->env_len = 0;

    free(request);
}

/* isula exec response free */
void isula_exec_response_free(struct isula_exec_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula attach request free */
void isula_attach_request_free(struct isula_attach_request *request)
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

/* isula attach response free */
void isula_attach_response_free(struct isula_attach_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula pause request free */
void isula_pause_request_free(struct isula_pause_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;
    free(request);
}

/* isula pause response free */
void isula_pause_response_free(struct isula_pause_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula resume request free */
void isula_resume_request_free(struct isula_resume_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;
    free(request);
}

/* isula resume response free */
void isula_resume_response_free(struct isula_resume_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula kill request free */
void isula_kill_request_free(struct isula_kill_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;
    free(request);
}

/* isula kill response free */
void isula_kill_response_free(struct isula_kill_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;
    free(response);
}

/* isula update config free */
void isula_update_config_free(isula_update_config_t *config)
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

/* isula update request free */
void isula_update_request_free(struct isula_update_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    isula_update_config_free(request->updateconfig);
    request->updateconfig = NULL;

    free(request);
}

/* isula update response free */
void isula_update_response_free(struct isula_update_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula stats request free */
void isula_stats_request_free(struct isula_stats_request *request)
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

/* isula stats response free */
void isula_stats_response_free(struct isula_stats_response *response)
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

/* isula events request free */
void isula_events_request_free(struct isula_events_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;

    free(request);
}

/* isula events response free */
void isula_events_response_free(struct isula_events_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

void isula_copy_from_container_request_free(struct isula_copy_from_container_request *request)
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

void isula_copy_from_container_response_free(struct isula_copy_from_container_response *response)
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

void isula_copy_to_container_request_free(struct isula_copy_to_container_request *request)
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

void isula_copy_to_container_response_free(struct isula_copy_to_container_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula inspect request free */
void isula_inspect_request_free(struct isula_inspect_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->name);
    request->name = NULL;

    free(request);
}

/* isula inspect response free */
void isula_inspect_response_free(struct isula_inspect_response *response)
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

/* isula wait request free */
void isula_wait_request_free(struct isula_wait_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;
    free(request);
}

/* isula wait response free */
void isula_wait_response_free(struct isula_wait_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula health check request free */
void isula_health_check_request_free(struct isula_health_check_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->service);
    request->service = NULL;

    free(request);
}

/* isula health check response free */
void isula_health_check_response_free(struct isula_health_check_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula create image request free */
void isula_create_image_request_free(struct isula_create_image_request *request)
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

/* isula create image response free */
void isula_create_image_response_free(struct isula_create_image_response *response)
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

/* isula images list free */
void isula_images_list_free(size_t images_num, struct isula_image_info *images_list)
{
    int i = 0;
    struct isula_image_info *in = NULL;

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

/* isula list images request free */
void isula_list_images_request_free(struct isula_list_images_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request);
    return;
}

/* isula list images response free */
void isula_list_images_response_free(struct isula_list_images_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    isula_images_list_free(response->images_num, response->images_list);
    response->images_num = 0;
    response->images_list = NULL;
    free(response);
}

/* isula rmi request free */
void isula_rmi_request_free(struct isula_rmi_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->image_name);
    request->image_name = NULL;

    free(request);
    return;
}

/* isula rmi response free */
void isula_rmi_response_free(struct isula_rmi_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* isula tag request free */
void isula_tag_request_free(struct isula_tag_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->src_name);
    request->src_name = NULL;
    free(request->dest_name);
    request->dest_name = NULL;

    free(request);
    return;
}

/* isula tag response free */
void isula_tag_response_free(struct isula_tag_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* isula pull response free */
void isula_pull_request_free(struct isula_pull_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->image_name);
    request->image_name = NULL;

    free(request);
    return;
}

/* isula pull response free */
void isula_pull_response_free(struct isula_pull_response *response)
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

/* isula import request free */
void isula_import_request_free(struct isula_import_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->file);
    request->file = NULL;

    free(request->tag);
    request->tag = NULL;

    free(request);
    return;
}

/* isula import response free */
void isula_import_response_free(struct isula_import_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->id);
    response->id = NULL;

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* isula load request free */
void isula_load_request_free(struct isula_load_request *request)
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

/* isula load response free */
void isula_load_response_free(struct isula_load_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* isula login response free */
void isula_login_response_free(struct isula_login_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* isula logout response free */
void isula_logout_response_free(struct isula_logout_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
    return;
}

/* isula export request free */
void isula_export_request_free(struct isula_export_request *request)
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

/* isula export response free */
void isula_export_response_free(struct isula_export_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula rename request free */
void isula_rename_request_free(struct isula_rename_request *request)
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

/* isula rename response free */
void isula_rename_response_free(struct isula_rename_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula resize request free */
void isula_resize_request_free(struct isula_resize_request *request)
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

/* isula resize response free */
void isula_resize_response_free(struct isula_resize_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isula logs request free */
void isula_logs_request_free(struct isula_logs_request *request)
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

/* isula logs response free */
void isula_logs_response_free(struct isula_logs_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* container cgroup resources free */
void container_cgroup_resources_free(container_cgroup_resources_t *cr)
{
    if (cr == NULL) {
        return;
    }
    free(cr->cpuset_cpus);
    cr->cpuset_cpus = NULL;

    free(cr->cpuset_mems);
    cr->cpuset_mems = NULL;

    free(cr);
}

void container_events_format_free(container_events_format_t *value)
{
    size_t i;

    if (value == NULL) {
        return;
    }

    free(value->opt);
    value->opt = NULL;

    free(value->id);
    value->id = NULL;

    for (i = 0; i < value->annotations_len; i++) {
        free(value->annotations[i]);
        value->annotations[i] = NULL;
    }

    free(value->annotations);
    value->annotations = NULL;

    free(value);
}