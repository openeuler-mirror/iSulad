/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container restful service functions
 ******************************************************************************/
#include <unistd.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "error.h"
#include "callback.h"
#include "container.rest.h"
#include "rest_service_common.h"
#include "rest_containers_service.h"

struct rest_handle_st {
    const char *name;
    void *(*request_parse_data)(const char *jsondata, struct parser_context *ctx, parser_error *err);
    int (*request_check)(void *reqeust);
};

/* update request check */
static int update_request_check(void *req)
{
    int ret = 0;
    container_update_request *req_update = (container_update_request *)req;
    if (req_update->name == NULL) {
        DEBUG("container name required!");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* restart request check */
static int restart_request_check(void *req)
{
    int ret = 0;
    container_restart_request *req_restart = (container_restart_request *)req;
    if (req_restart->id == NULL) {
        ERROR("Container name required!");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* version request check */
static int version_request_check(void *req)
{
    return 0;
}

/* stop request check */
static int stop_request_check(void *req)
{
    int ret = 0;
    container_stop_request *req_stop = (container_stop_request *)req;
    if (req_stop->id == NULL) {
        DEBUG("container name required!");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* wait request check */
static int wait_request_check(void *req)
{
    int ret = 0;
    container_wait_request *req_wait = (container_wait_request *)req;
    if (req_wait->id == NULL) {
        DEBUG("container name error");
        ret = -1;
        goto out;
    }

    if (req_wait->condition != WAIT_CONDITION_REMOVED && req_wait->condition != WAIT_CONDITION_STOPPED) {
        ERROR("container wait condition error");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* kill request check */
static int kill_request_check(void *req)
{
    int ret = 0;
    container_kill_request *req_kill = (container_kill_request *)req;
    if (req_kill->id == NULL) {
        DEBUG("container name required!");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* remove request check */
static int remove_request_check(void *req)
{
    int ret = 0;
    container_delete_request *req_rm = (container_delete_request *)req;
    if (req_rm->id == NULL) {
        DEBUG("container name required!");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* exec request check */
static int exec_request_check(void *req)
{
    int ret = 0;
    container_exec_request *req_exec = (container_exec_request *)req;
    if (req_exec->container_id == NULL) {
        DEBUG("Missing container name in the request!");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* list request check */
static int list_request_check(void *req)
{
    int ret = 0;

    return ret;
}

/* create request check */
static int create_request_check(void *req)
{
    int ret = 0;
    container_create_request *req_create = (container_create_request *)req;
    if (req_create->rootfs == NULL && req_create->image == NULL) {
        DEBUG("container image or rootfs error");
        ret = -1;
        goto out;
    }

    if (req_create->runtime == NULL) {
        DEBUG("recive NULL Request runtime");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* container inspect request check */
static int container_inspect_request_check(void *req)
{
    int ret = 0;
    container_inspect_request *req_inspect = (container_inspect_request *)req;
    if (req_inspect->id == NULL) {
        DEBUG("container name required!");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* start request check */
static int start_request_check(void *req)
{
    int ret = 0;
    container_start_request *req_start = (container_start_request *)req;
    if (req_start->id == NULL) {
        DEBUG("container name error");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* evhtp send create repsponse */
static void evhtp_send_create_repsponse(evhtp_request_t *req, container_create_response *response, int rescode)
{
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate create response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = container_create_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Create: failed to generate request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

static struct rest_handle_st g_rest_handle[] = {
    {
        .name = ContainerServiceCreate,
        .request_parse_data = (void *)container_create_request_parse_data,
        .request_check = create_request_check,
    },
    {
        .name = ContainerServiceStart,
        .request_parse_data = (void *)container_start_request_parse_data,
        .request_check = start_request_check,
    },
    {
        .name = ContainerServiceRestart,
        .request_parse_data = (void *)container_restart_request_parse_data,
        .request_check = restart_request_check,
    },
    {
        .name = ContainerServiceStop,
        .request_parse_data = (void *)container_stop_request_parse_data,
        .request_check = stop_request_check,
    },
    {
        .name = ContainerServiceVersion,
        .request_parse_data = (void *)container_version_request_parse_data,
        .request_check = version_request_check,
    },
    {
        .name = ContainerServiceUpdate,
        .request_parse_data = (void *)container_update_request_parse_data,
        .request_check = update_request_check,
    },
    {
        .name = ContainerServiceKill,
        .request_parse_data = (void *)container_kill_request_parse_data,
        .request_check = kill_request_check,
    },
    {
        .name = ContainerServiceExec,
        .request_parse_data = (void *)container_exec_request_parse_data,
        .request_check = exec_request_check,
    },
    {
        .name = ContainerServiceRemove,
        .request_parse_data = (void *)container_delete_request_parse_data,
        .request_check = remove_request_check,
    },
    {
        .name = ContainerServiceList,
        .request_parse_data = (void *)container_list_request_parse_data,
        .request_check = list_request_check,
    },
    {
        .name = ContainerServiceWait,
        .request_parse_data = (void *)container_wait_request_parse_data,
        .request_check = wait_request_check,
    },
    {
        .name = ContainerServiceInspect,
        .request_parse_data = (void *)container_inspect_request_parse_data,
        .request_check = container_inspect_request_check,
    },
};

static int action_request_from_rest(evhtp_request_t *req, void **request, const char *req_type)
{
    char *body = NULL;
    size_t body_len;
    int ret = 0;
    parser_error err = NULL;
    int array_size = 0;
    int i = 0;
    struct rest_handle_st *ops = NULL;

    array_size = sizeof(g_rest_handle) / sizeof(g_rest_handle[0]);
    for (i = 0; i < array_size; i++) {
        if (strcmp(req_type, g_rest_handle[i].name) == 0) {
            ops = &g_rest_handle[i];
            break;
        }
    }
    if (i >= array_size) {
        ERROR("Unknown action type");
        return -1;
    }

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *request = (void *)ops->request_parse_data(body, NULL, &err);
    if (*request == NULL) {
        ERROR("Invalid request body:%s", err);
        ret = -1;
        goto out;
    }

    if (ops->request_check(*request) < 0) {
        ret = -1;
        goto out;
    }
out:
    put_body(body);
    if (err != NULL) {
        free(err);
    }
    return ret;
}

/* evhtp send start repsponse */
static void evhtp_send_start_repsponse(evhtp_request_t *req, container_start_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate start response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = container_start_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate start request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* evhtp send list repsponse */
static void evhtp_send_list_repsponse(evhtp_request_t *req, container_list_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate inspect response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = container_list_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate list request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* evhtp send wait repsponse */
static void evhtp_send_wait_repsponse(evhtp_request_t *req, container_wait_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    responsedata = container_wait_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate wait request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest create cb */
static void rest_create_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_create_response *cresponse = NULL;
    container_create_request *crequest = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.create == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceCreate);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.create(crequest, &cresponse);

    evhtp_send_create_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_create_response(cresponse);
    free_container_create_request(crequest);
}

/* rest start cb */
static void rest_start_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_start_response *cresponse = NULL;
    container_start_request *crequest = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.start == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceStart);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.start(crequest, &cresponse, -1, NULL, NULL);

    evhtp_send_start_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_start_request(crequest);
    free_container_start_response(cresponse);
}

/* rest wait cb */
static void rest_wait_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_wait_request *crequest = NULL;
    container_wait_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.wait == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceWait);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.wait(crequest, &cresponse);

    evhtp_send_wait_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_wait_request(crequest);
    free_container_wait_response(cresponse);
}

/* evhtp send stop repsponse */
static void evhtp_send_stop_repsponse(evhtp_request_t *req, container_stop_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate stop response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = container_stop_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate stop request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest stop cb */
static void rest_stop_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_stop_request *crequest = NULL;
    container_stop_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.stop == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceStop);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.stop(crequest, &cresponse);

    evhtp_send_stop_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_stop_response(cresponse);
    free_container_stop_request(crequest);
}

/* evhtp send restart response */
static void evhtp_send_restart_response(evhtp_request_t *req, container_restart_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate restart response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }
    responsedata = container_restart_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate restart response json: %s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest restart cb */
static void rest_restart_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_restart_request *crequest = NULL;
    container_restart_response *cresponse = NULL;

    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    cb = get_service_executor();
    if (cb == NULL || cb->container.restart == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceRestart);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.restart(crequest, &cresponse);

    evhtp_send_restart_response(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_restart_request(crequest);
    free_container_restart_response(cresponse);
}

/* evhtp send version repsponse */
static void evhtp_send_version_repsponse(evhtp_request_t *req, container_version_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    responsedata = container_version_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate version request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest version cb */
static void rest_version_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_version_request *crequest = NULL;
    container_version_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.version == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceVersion);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.version(crequest, &cresponse);

    evhtp_send_version_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_version_request(crequest);
    free_container_version_response(cresponse);
}

/* evhtp send update repsponse */
static void evhtp_send_update_repsponse(evhtp_request_t *req, container_update_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Invalid NULL response");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = container_update_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate update request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest update cb */
static void rest_update_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_update_request *container_req = NULL;
    container_update_response *container_res = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.update == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&container_req, ContainerServiceUpdate);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.update(container_req, &container_res);
    evhtp_send_update_repsponse(req, container_res, RESTFUL_RES_OK);

out:
    free_container_update_request(container_req);
    free_container_update_response(container_res);
}

/* evhtp send kill repsponse */
static void evhtp_send_kill_repsponse(evhtp_request_t *req, container_kill_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate kill response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }
    responsedata = container_kill_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate kill request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest kill cb */
static void rest_kill_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_kill_request *crequest = NULL;
    container_kill_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.kill == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceKill);
    if (tret < 0) {
        ERROR("bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.kill(crequest, &cresponse);

    evhtp_send_kill_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_kill_request(crequest);
    free_container_kill_response(cresponse);
}

/* evhtp send container inspect repsponse */
static void evhtp_send_container_inspect_repsponse(evhtp_request_t *req, container_inspect_response *response,
                                                   int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate inspect response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = container_inspect_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate inspect request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest container inspect cb */
static void rest_container_inspect_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_inspect_request *crequest = NULL;
    container_inspect_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.inspect == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceInspect);
    if (tret < 0) {
        ERROR("bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.inspect(crequest, &cresponse);

    evhtp_send_container_inspect_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_inspect_request(crequest);
    free_container_inspect_response(cresponse);
}

/* evhtp send exec repsponse */
static void evhtp_send_exec_repsponse(evhtp_request_t *req, container_exec_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate exec response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = container_exec_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate exec request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest exec cb */
static void rest_exec_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_exec_request *crequest = NULL;
    container_exec_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || !cb->container.exec) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceExec);
    if (tret < 0) {
        ERROR("bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.exec(crequest, &cresponse, -1, NULL, NULL);

    evhtp_send_exec_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_exec_request(crequest);
    free_container_exec_response(cresponse);
}

/* evhtp send remove repsponse */
static void evhtp_send_remove_repsponse(evhtp_request_t *req, container_delete_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate remove response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }
    responsedata = container_delete_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate remove request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest remove cb */
static void rest_remove_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_delete_request *crequest = NULL;
    container_delete_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.remove == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceRemove);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.remove(crequest, &cresponse);

    evhtp_send_remove_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_delete_request(crequest);
    free_container_delete_response(cresponse);
}

/* rest list cb */
static void rest_list_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    container_list_request *crequest = NULL;
    container_list_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->container.list == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&crequest, ContainerServiceList);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->container.list(crequest, &cresponse);

    evhtp_send_list_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_container_list_request(crequest);
    free_container_list_response(cresponse);
}

/* rest register containers handler */
int rest_register_containers_handler(evhtp_t *htp)
{
    if (evhtp_set_cb(htp, ContainerServiceCreate, rest_create_cb, NULL) == NULL) {
        ERROR("Failed to register create callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceStop, rest_stop_cb, NULL) == NULL) {
        ERROR("Failed to register stop callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceRestart, rest_restart_cb, NULL) == NULL) {
        ERROR("Failed to register restart callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceVersion, rest_version_cb, NULL) == NULL) {
        ERROR("Failed to register version callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceUpdate, rest_update_cb, NULL) == NULL) {
        ERROR("Failed to register update callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceKill, rest_kill_cb, NULL) == NULL) {
        ERROR("Failed to register kill callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceInspect, rest_container_inspect_cb, NULL) == NULL) {
        ERROR("Failed to register inspect callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceExec, rest_exec_cb, NULL) == NULL) {
        ERROR("Failed to register exec callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceRemove, rest_remove_cb, NULL) == NULL) {
        ERROR("Failed to register remove callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceStart, rest_start_cb, NULL) == NULL) {
        ERROR("Failed to register start callback");
        return -1;
    }
    if (evhtp_set_cb(htp, ContainerServiceList, rest_list_cb, NULL) == NULL) {
        ERROR("Failed to register list callback");
        return -1;
    }

    if (evhtp_set_cb(htp, ContainerServiceWait, rest_wait_cb, NULL) == NULL) {
        ERROR("Failed to register wait callback");
        return -1;
    }
    return 0;
}
