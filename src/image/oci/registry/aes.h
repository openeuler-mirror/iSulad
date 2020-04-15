/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2020-04-23
 * Description: provide aes process definition
 ******************************************************************************/
#ifndef __IMAGE_AES_H
#define __IMAGE_AES_H

#ifdef __cplusplus
extern "C" {
#endif

#define AUTH_AESKEY "/root/.isulad/aeskey"

int aes_decode(unsigned char *input, size_t input_len, unsigned char *output, size_t output_buf_len);
int aes_encode(unsigned char *input, size_t input_len, unsigned char *output, size_t output_buf_len);

#ifdef __cplusplus
}
#endif

#endif

