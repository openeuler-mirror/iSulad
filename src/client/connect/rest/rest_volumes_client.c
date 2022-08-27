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
 * Create: 2022-08-23
 * Description: provide volumes restful client functions
 ******************************************************************************/
#include "rest_volumes_client.h"

#include <unistd.h>
#include <error.h>
#include <isula_libutils/log.h>
#include "isula_connect.h"
#include "volumes.rest.h"
#include "rest_common.h"
#include "utils.h"

/* list request to rest */
static int list_request_to_rest(const struct isula_list_volume_request *request, char **body, size_t *body_len)
{
    volume_list_volume_request *nrequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    nrequest = util_common_calloc_s(sizeof(volume_list_volume_request));
    if (nrequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    nrequest->unuseful = request->unuseful;

    *body = volume_list_volume_request_generate_json(nrequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate volume list request json:%s", err);
        ret = -1;
        goto out;
    }
    
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_volume_list_volume_request(nrequest);
    return ret;
}

static int unpack_volume_info_for_list_response(const volume_list_volume_response *nresponse,
                                                struct isula_list_volume_response *response)
{
    size_t i;
    struct isula_volume_info *volume_info = NULL;

    if (nresponse->volumes_len == 0) {
        return 0;
    }

    volume_info = (struct isula_volume_info *)util_smart_calloc_s(sizeof(struct isula_volume_info),
                                                                  nresponse->volumes_len);
    if (volume_info == NULL) {
        ERROR("out of memory");
        return -1;
    }

    for (i = 0; i < nresponse->volumes_len; i++) {
        volume_info[i].driver = util_strdup_s(nresponse->volumes[i]->driver);
        volume_info[i].name = util_strdup_s(nresponse->volumes[i]->name);
    }

    response->volumes = volume_info;
    response->volumes_len = nresponse->volumes_len;

    volume_info = NULL;

    return 0;
}

/* unpack list response */
static int unpack_list_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_list_volume_response *response = (struct isula_list_volume_response *)arg;
    volume_list_volume_response *nresponse = NULL;
    parser_error err = NULL;
    int ret;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        return ret;
    }

    nresponse = volume_list_volume_response_parse_data(message->body, NULL, &err);
    if (nresponse == NULL) {
        ERROR("Invalid volume list response:%s", err);
        ret = -1;
        goto out;
    }

    response->server_errono = nresponse->cc;
    response->errmsg = util_strdup_s(nresponse->errmsg);
    if (unpack_volume_info_for_list_response(nresponse, response) != 0) {
        ret = -1;
        goto out;
    }

    ret = (nresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_volume_list_volume_response(nresponse);
    return ret;
}

/* rest volumn list */
static int rest_volume_list(const struct isula_list_volume_request *request,
                            struct isula_list_volume_response *response, void *arg)
{
    char *body = NULL;
    int ret;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = list_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }

    ret = rest_send_request(socketname, RestHttpHead VolumesServiceList, body, len, &output);
    if (ret != 0) {
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }

    ret = get_response(output, unpack_list_response, (void *)response);

out:
    buffer_free(output);
    put_body(body);
    return ret;
}

/* rest volumes client ops init */
int rest_volumes_client_ops_init(isula_connect_ops *ops)
{
    if (ops == NULL) {
        return -1;
    }

    ops->volume.list = &rest_volume_list;

    return 0;
}
