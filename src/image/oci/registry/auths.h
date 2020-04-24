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
 * Description: provide auths file process definition
 ******************************************************************************/
#ifndef __IMAGE_AUTHS_H
#define __IMAGE_AUTHS_H

#ifdef __cplusplus
extern "C" {
#endif

#define AUTH_FILE_PATH "/root/.isulad/auths.json"
#define AUTH_FILE_MODE 0600
#define MAX_AUTHS_LEN 65536

int auths_load(char *host, char **username, char **password);

int auths_save(char *host, char *username, char *password);

int auths_delete(char *host);

#ifdef __cplusplus
}
#endif

#endif

