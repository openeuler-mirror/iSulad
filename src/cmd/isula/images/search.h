/******************************************************************************
 * Copyright (c) KylinSoft  Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.

 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xiangli
 * Create: 2022-6-10
 * Description: provide search image
 ********************************************************************************/

#ifndef CMD_ISULA_IMAGES_SEARCH_H
#define CMD_ISULA_IMAGES_SEARCH_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned int name_length;
    unsigned int tag_length;
} lengths;

extern const char g_cmd_search_desc[];
extern const char g_cmd_search_usage[];
extern struct client_arguments g_cmd_search_args;
int client_search(const struct client_arguments *args);

int cmd_search_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_IMAGES_SEARCH_H
