/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-06-22
 * Description: provide container supervisor definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_API_SERVICE_CONTAINER_API_H
#define DAEMON_MODULES_API_SERVICE_CONTAINER_API_H
#include "container_api.h"
#include "io_wrapper.h"
#include "isula_libutils/container_exec_request.h"
#include "isula_libutils/container_exec_response.h"

#ifdef __cplusplus
extern "C" {
#endif

int start_container(container_t *cont, const char *console_fifos[], bool reset_rm);

int stop_container(container_t *cont, int timeout, bool force, bool restart);

int clean_container_resource(const char *id, const char *runtime, pid_t pid);

int cleanup_mounts_by_id(const char *id, const char *engine_root_path);

void umount_host_channel(const host_config_host_channel *host_channel);

void umount_share_shm(container_t *cont);

int release_volumes(container_config_v2_common_config_mount_points *mount_points,
                    char *id, bool rm_anonymous_volumes);

int kill_container(container_t *cont, uint32_t signal);

int set_container_to_removal(const container_t *cont);

int delete_container(container_t *cont, bool force);

int exec_container(const container_t *cont, const container_exec_request *request, container_exec_response *response,
                   int stdinfd, struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler);

#ifdef __cplusplus
}
#endif

#endif
