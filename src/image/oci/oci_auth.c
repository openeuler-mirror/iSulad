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
 * Author: wangfengtu
 * Create: 2019-06-24
 * Description: provide oci auth functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "utils.h"
#include "log.h"
#include "imagetool_auth_input.h"
#include "json_common.h"
#include "oci_auth.h"

char *pack_input_auth_string(auth_config *auth)
{
    char *auth_string = NULL;
    imagetool_auth_input *auth_data = NULL;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err = NULL;

    auth_data = util_common_calloc_s(sizeof(imagetool_auth_input));
    if (auth_data == NULL) {
        ERROR("memory out");
        goto out;
    }

    auth_data->username = auth->username != NULL ? util_strdup_s(auth->username) : NULL;
    auth_data->password = auth->password != NULL ? util_strdup_s(auth->password) : NULL;
    auth_data->auth = auth->auth != NULL ? util_strdup_s(auth->auth) : NULL;

    auth_string = imagetool_auth_input_generate_json(auth_data, &ctx, &err);
    if (auth_string == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }

out:
    free_sensitive_string(auth_data->username);
    auth_data->username = NULL;
    free_sensitive_string(auth_data->password);
    auth_data->password = NULL;
    free_imagetool_auth_input(auth_data);
    free(err);
    return auth_string;
}


