/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: run isula image server
*******************************************************************************/
#ifndef __IMAGE_RUN_IMAGE_SERVER_H
#define __IMAGE_RUN_IMAGE_SERVER_H

#include <pthread.h>
#include <semaphore.h>
#include "linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct server_monitor_conf {
    sem_t *wait_ok;
};

void *isula_image_server_monitor(void *arg);

void isula_img_exit();

#ifdef __cplusplus
}
#endif

#endif /* __IMAGE_RUN_IMAGE_SERVER_H */
