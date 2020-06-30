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
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide container unix definition
 ******************************************************************************/
#ifndef __ISULAD_CONTAINER_UNIX_H__
#define __ISULAD_CONTAINER_UNIX_H__

#include <pthread.h>

#include "container_api.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

restart_manager_t *get_restart_manager(container_t *cont);

void container_reset_manually_stopped(container_t *cont);

int save_host_config(const char *id, const char *rootpath, const char *hostconfigstr);
int save_config_v2_json(const char *id, const char *rootpath, const char *v2configstr);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __ISULAD_CONTAINER_UNIX_H__ */
