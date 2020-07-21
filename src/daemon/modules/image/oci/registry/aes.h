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
 * Create: 2020-04-23
 * Description: provide aes process definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_REGISTRY_AES_H
#define DAEMON_MODULES_IMAGE_OCI_REGISTRY_AES_H

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#define AUTH_AESKEY_NAME "aeskey"
#define DEFAULT_AUTH_AESKEY "/root/.isulad/" AUTH_AESKEY_NAME

void aes_set_key_dir(char *key_dir);
// output length is "input_len+AES_256_CFB_IV_LEN"
int aes_encode(unsigned char *input, size_t input_len, unsigned char **output);
// output length is "input_len-AES_256_CFB_IV_LEN"
int aes_decode(unsigned char *input, size_t input_len, unsigned char **output);

#ifdef __cplusplus
}
#endif

#endif

