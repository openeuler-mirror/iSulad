/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtaoo
 * Create: 2024-03-26
 * Description: provide nri plugin api definition
 ******************************************************************************/

#ifndef DAEMON_NRI_PLUGIN_OPS_H
#define DAEMON_NRI_PLUGIN_OPS_H

#include <isula_libutils/nri_update_containers_request.h>
#include <isula_libutils/nri_update_containers_response.h>
#include <isula_libutils/nri_register_plugin_request.h>

#ifdef __cplusplus
extern "C" {
#endif

bool nri_adaption_init(void);
bool nri_adaption_shutdown(void);

#ifdef __cplusplus
}
#endif

int nri_update_containers(const char *plugin_id, const nri_update_containers_request *request,
                          nri_update_containers_response **response);
int nri_registry_containers(const char *plugin_id, const nri_register_plugin_request *request);

int nri_external_plugin_connect(int fd);

#endif // DAEMON_NRI_PLUGIN_OPS_H
