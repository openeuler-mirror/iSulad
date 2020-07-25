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
 * Create: 2018-11-22
 * Description: provide container rest definition
 **********************************************************************************/
#ifndef API_SERVICES_CONTAINERS_REST_CONTAINER_REST_H
#define API_SERVICES_CONTAINERS_REST_CONTAINER_REST_H

#include "isula_libutils/container_create_request.h"
#include "isula_libutils/container_create_response.h"
#include "isula_libutils/container_start_request.h"
#include "isula_libutils/container_start_response.h"
#include "isula_libutils/container_stop_request.h"
#include "isula_libutils/container_stop_response.h"
#include "isula_libutils/container_restart_request.h"
#include "isula_libutils/container_restart_response.h"
#include "isula_libutils/container_pause_request.h"
#include "isula_libutils/container_pause_response.h"
#include "isula_libutils/container_kill_request.h"
#include "isula_libutils/container_kill_response.h"
#include "isula_libutils/container_update_request.h"
#include "isula_libutils/container_update_response.h"
#include "isula_libutils/container_version_request.h"
#include "isula_libutils/container_version_response.h"
#include "isula_libutils/container_exec_request.h"
#include "isula_libutils/container_exec_response.h"
#include "isula_libutils/container_delete_request.h"
#include "isula_libutils/container_delete_response.h"
#include "isula_libutils/container_inspect_request.h"
#include "isula_libutils/container_inspect_response.h"
#include "isula_libutils/container_list_request.h"
#include "isula_libutils/container_list_response.h"
#include "isula_libutils/container_attach_request.h"
#include "isula_libutils/container_attach_response.h"
#include "isula_libutils/container_resume_request.h"
#include "isula_libutils/container_resume_response.h"
#include "isula_libutils/container_wait_request.h"
#include "isula_libutils/container_wait_response.h"

#ifndef RestHttpHead
#define RestHttpHead "http://localhost"
#endif

#define ContainerServiceCreate "/ContainerService/Create"
#define ContainerServiceStart "/ContainerService/Start"
#define ContainerServiceRestart "/ContainerService/Restart"
#define ContainerServiceStop "/ContainerService/Stop"
#define ContainerServiceVersion "/ContainerService/Version"
#define ContainerServiceUpdate "/ContainerService/Update"
#define ContainerServicePause "/ContainerService/Pause"
#define ContainerServiceKill "/ContainerService/Kill"
#define ContainerServiceExec "/ContainerService/Exec"
#define ContainerServiceRemove "/ContainerService/Remove"
#define ContainerServiceInspect "/ContainerService/Inspect"
#define ContainerServiceList "/ContainerService/List"
#define ContainerServiceAttach "/ContainerService/Attach"
#define ContainerServiceResume "/ContainerService/Resume"
#define ContainerServiceWait "/ContainerService/Wait"

/* "/ContainerService/Kill",
"/ContainerService/Delete",
"/ContainerService/Pause",
"/ContainerService/Info",
"/ContainerService/Inspect",
"/ContainerService/Stats",
"/ContainerService/Events",
"/ContainerService/Exec",
"/ContainerService/Version",
"/ContainerService/Update",
"/ContainerService/Attach",
*/
#endif

