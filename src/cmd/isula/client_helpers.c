/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2022-12-17
 * Description: provide client helpers function definition
 ******************************************************************************/
#include "client_helpers.h"

#include "utils.h"
#include "protocol_type.h"
#include "isula_connect.h"
#include <isula_libutils/log.h>
#include <isula_libutils/container_inspect.h>

int inspect_container(const struct client_arguments *args, container_inspect **inspect_data)
{
    int ret = 0;
    struct isula_inspect_request inspect_request = { 0 };
    struct isula_inspect_response *inspect_response = NULL;
    client_connect_config_t config = { 0 };
    isula_connect_ops *ops = NULL;
    parser_error perr = NULL;

    if (inspect_data == NULL) {
        COMMAND_ERROR("Empty inspect data");
        return -1;
    }

    inspect_response = util_common_calloc_s(sizeof(struct isula_inspect_response));
    if (inspect_response == NULL) {
        COMMAND_ERROR("Out of memory");
        return -1;
    }

    inspect_request.name = args->name;
    inspect_request.timeout = args->time;
    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.inspect) {
        COMMAND_ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.inspect(&inspect_request, inspect_response, &config);
    if (ret) {
        client_print_error(inspect_response->cc, inspect_response->server_errono, inspect_response->errmsg);
        goto out;
    }

    /* parse oci container json */
    if (inspect_response == NULL || inspect_response->json == NULL) {
        COMMAND_ERROR("Inspect data is empty");
        ret = -1;
        goto out;
    }

    *inspect_data = container_inspect_parse_data(inspect_response->json, NULL, &perr);
    if (*inspect_data == NULL) {
        COMMAND_ERROR("Can not parse inspect json: %s", perr);
        ret = -1;
        goto out;
    }

out:
    isula_inspect_response_free(inspect_response);
    free(perr);
    return ret;
}

