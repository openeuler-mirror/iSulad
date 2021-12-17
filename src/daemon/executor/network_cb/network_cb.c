/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2020-09-10
 * Description: provide network callback functions
 ********************************************************************************/

#include "network_cb.h"

#include <pthread.h>

#include "network_api.h"
#include "utils.h"
#include "error.h"
#include "err_msg.h"
#include "isula_libutils/log.h"
#include "utils_network.h"
#include "service_container_api.h"

const char *g_accept_network_filter[] = { "name", "plugin", NULL };

static pthread_rwlock_t g_network_rwlock = PTHREAD_RWLOCK_INITIALIZER;
enum lock_type { SHARED = 0, EXCLUSIVE };

static inline bool network_conflist_lock(enum lock_type type)
{
    int nret = 0;

    if (type == SHARED) {
        nret = pthread_rwlock_rdlock(&g_network_rwlock);
    } else {
        nret = pthread_rwlock_wrlock(&g_network_rwlock);
    }
    if (nret != 0) {
        ERROR("Lock network list failed: %s", strerror(nret));
        return false;
    }

    return true;
}

static inline void network_conflist_unlock()
{
    int nret = 0;

    nret = pthread_rwlock_unlock(&g_network_rwlock);
    if (nret != 0) {
        FATAL("Unlock network list failed: %s", strerror(nret));
    }
}

static int check_parameter(const network_create_request *request)
{
    int ret = 0;
    uint8_t *ip = NULL;
    size_t ip_len = 0;
    struct ipnet *net = NULL;

    if (request->name != NULL && !util_validate_network_name(request->name)) {
        isulad_set_error_message("Invalid network name %s", request->name);
        return EINVALIDARGS;
    }

    if (request->subnet == NULL) {
        if (request->gateway != NULL) {
            isulad_set_error_message("Cannot specify gateway without subnet");
            ret = EINVALIDARGS;
        }
        return ret;
    }

    ret = util_parse_cidr(request->subnet, &net);
    if (ret != 0 || net == NULL) {
        ERROR("Parse CIDR %s failed", request->subnet);
        isulad_set_error_message("Invalid subnet %s", request->subnet);
        ret = EINVALIDARGS;
        goto out;
    }

    if (request->gateway == NULL) {
        goto out;
    }

    ret = util_parse_ip_from_str(request->gateway, &ip, &ip_len);
    if (ret != 0 || ip == NULL || ip_len == 0) {
        ERROR("Parse IP %s failed", request->gateway);
        isulad_set_error_message("Invalid gateway %s", request->gateway);
        ret = EINVALIDARGS;
        goto out;
    }

    if (!util_net_contain_ip(net, ip, ip_len, false)) {
        isulad_set_error_message("subnet \"%s\" and gateway \"%s\" not match", request->subnet, request->gateway);
        ret = EINVALIDARGS;
    }

out:
    util_free_ipnet(net);
    free(ip);
    return ret;
}

static int network_create_cb(const network_create_request *request, network_create_response **response)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = util_common_calloc_s(sizeof(network_create_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    ret = check_parameter(request);
    if (ret != 0) {
        cc = ISULAD_ERR_INPUT;
        ERROR("check network parameter failed");
        goto out;
    }

    network_conflist_lock(EXCLUSIVE);

    ret = network_module_conf_create(NETWOKR_API_TYPE_NATIVE, request, &(*response)->name, &cc);

    network_conflist_unlock();

out:
    (*response)->cc = cc;
    if (g_isulad_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }

    return ret;
}

static int network_inspect_cb(const network_inspect_request *request, network_inspect_response **response)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *network_json = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = util_common_calloc_s(sizeof(network_inspect_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    if (request->name == NULL || strlen(request->name) == 0) {
        ERROR("NULL network name in inspect request");
        isulad_set_error_message("NULL network name in inspect request");
        cc = ISULAD_ERR_INPUT;
        ret = EINVALIDARGS;
        goto out;
    }

    if (!util_validate_network_name(request->name)) {
        isulad_set_error_message("Invalid network name %s", request->name);
        cc = ISULAD_ERR_INPUT;
        ret = EINVALIDARGS;
        goto out;
    }

    ret = network_module_conf_inspect(NETWOKR_API_TYPE_NATIVE, request->name, &network_json);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
    }

out:
    (*response)->cc = cc;
    if (g_isulad_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    (*response)->network_json = util_strdup_s(network_json);
    free(network_json);

    return ret;
}

static int do_add_filters(const char *filter_key, const json_map_string_bool *filter_value,
                          struct filters_args *filters)
{
    size_t i;

    for (i = 0; i < filter_value->len; i++) {
        if (strcmp(filter_key, "name") == 0) {
            if (!util_validate_network_name(filter_value->keys[i])) {
                ERROR("Unrecognised filter value for name: %s", filter_value->keys[i]);
                isulad_set_error_message("Unrecognised filter value for name: %s", filter_value->keys[i]);
                return -1;
            }
        }
        if (!filters_args_add(filters, filter_key, filter_value->keys[i])) {
            ERROR("Add filter args failed");
            return -1;
        }
    }

    return 0;
}

static int fold_filter(const network_list_request *request, struct filters_args **filters)
{
    size_t i;
    struct filters_args *tmp_filters = NULL;

    if (request->filters == NULL) {
        return 0;
    }
    tmp_filters = filters_args_new();
    if (tmp_filters == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < request->filters->len; i++) {
        if (!filters_args_valid_key(g_accept_network_filter, sizeof(g_accept_network_filter) / sizeof(char *),
                                    request->filters->keys[i])) {
            ERROR("Invalid filter '%s'", request->filters->keys[i]);
            isulad_set_error_message("Invalid filter '%s'", request->filters->keys[i]);
            goto error_out;
        }
        if (do_add_filters(request->filters->keys[i], request->filters->values[i], tmp_filters) != 0) {
            goto error_out;
        }
    }
    *filters = tmp_filters;
    return 0;

error_out:
    filters_args_free(tmp_filters);
    return -1;
}

static int network_list_cb(const network_list_request *request, network_list_response **response)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    struct filters_args *filters = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = util_common_calloc_s(sizeof(network_list_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    ret = fold_filter(request, &filters);
    if (ret != 0) {
        ERROR("Failed to fold filters");
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    ret = network_module_conf_list(NETWOKR_API_TYPE_NATIVE, filters, &(*response)->networks, &(*response)->networks_len);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        ERROR("Failed to list network");
    }

out:
    (*response)->cc = cc;
    if (g_isulad_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    filters_args_free(filters);

    return ret;
}

static int network_remove_cb(const network_remove_request *request, network_remove_response **response)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = (network_remove_response *)util_common_calloc_s(sizeof(network_remove_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    if (!util_validate_network_name(request->name)) {
        isulad_set_error_message("Invalid network name %s", request->name);
        cc = ISULAD_ERR_INPUT;
        ret = EINVALIDARGS;
        goto out;
    }

    ret = network_module_conf_rm(NETWOKR_API_TYPE_NATIVE, request->name, &(*response)->name);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        ret = ECOMMON;
        goto out;
    }

out:
    (*response)->cc = cc;
    if (g_isulad_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }

    return ret;
}

void network_callback_init(service_network_callback_t *cb)
{
    cb->create = network_create_cb;
    cb->inspect = network_inspect_cb;
    cb->list = network_list_cb;
    cb->remove = network_remove_cb;
}
