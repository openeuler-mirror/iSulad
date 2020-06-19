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
* Author: liuhao
* Create: 2019-07-12
* Description: provide isula connect command definition
*******************************************************************************/
#ifndef __ISULAD_CLIENT_CONNECT_H
#define __ISULAD_CLIENT_CONNECT_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned int deadline;
    char *socket;
    // gRPC tls config
    bool tls;
    bool tls_verify;
    char *ca_file;
    char *cert_file;
    char *key_file;
} client_connect_config_t;

#ifdef __cplusplus
}
#endif
#endif

