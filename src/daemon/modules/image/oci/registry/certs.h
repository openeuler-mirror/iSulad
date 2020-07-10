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
 * Author: wangfengtu
 * Create: 2020-03-20
 * Description: provide certs file process definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_REGISTRY_CERTS_H
#define DAEMON_MODULES_IMAGE_OCI_REGISTRY_CERTS_H

#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

void certs_set_dir(char *certs_dir);

int certs_load(char *host, bool use_decrypted_key, char **ca_file, char **cert_file, char **key_file);

#ifdef __cplusplus
}
#endif

#endif

