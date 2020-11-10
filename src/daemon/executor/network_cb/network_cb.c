/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
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

#include "network_config.h"
#include "utils.h"
#include "error.h"
#include "err_msg.h"
#include "isula_libutils/log.h"
#include "libcni_types.h"
#include "libcni_utils.h"

pthread_rwlock_t network_rwlock = PTHREAD_RWLOCK_INITIALIZER;
enum lock_type { SHARED = 0, EXCLUSIVE };

static inline bool network_conflist_lock(enum lock_type type)
{
    int nret = 0;

    if (type == SHARED) {
        nret = pthread_rwlock_rdlock(&network_rwlock);
    } else {
        nret = pthread_rwlock_wrlock(&network_rwlock);
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

    nret = pthread_rwlock_unlock(&network_rwlock);
    if (nret != 0) {
        FATAL("Unlock network list failed: %s", strerror(nret));
    }
}

static bool network_is_valid_name(const char *name)
{
    if (strnlen(name, MAX_NETWORK_NAME_LEN + 1) > MAX_NETWORK_NAME_LEN) {
        isulad_set_error_message("Network name \"%s\" too long, max length:%d", name,
                                 MAX_NETWORK_NAME_LEN);
        return false;
    }
    if (util_reg_match(CNI_VALID_NAME_CHARS, name) != 0) {
        isulad_set_error_message("Invalid network name:%s, only %s are allowed", name, CNI_VALID_NAME_CHARS);
        return false;
    }

    return true;
}

static int check_parameter(const network_create_request *request)
{
    int ret = 0;
    uint8_t *ip = NULL;
    size_t ip_len = 0;
    struct ipnet *net = NULL;

    if (request->name != NULL && !network_is_valid_name(request->name)) {
        return EINVALIDARGS;
    }

    if (request->driver != NULL && strcmp(request->driver, g_default_driver) != 0) {
        isulad_set_error_message("Cannot support driver:%s", request->driver);
        return EINVALIDARGS;
    }

    if (request->subnet == NULL) {
        if (request->gateway != NULL) {
            isulad_set_error_message("Cannot specify gateway without subnet");
            ret = EINVALIDARGS;
        }
        return ret;
    }

    ret = parse_cidr(request->subnet, &net);
    if (ret != 0 || net == NULL) {
        ERROR("Parse CIDR %s failed", request->subnet);
        isulad_set_error_message("Invalid subnet %s", request->subnet);
        ret = EINVALIDARGS;
        goto out;
    }

    if (request->gateway == NULL) {
        goto out;
    }

    ret = parse_ip_from_str(request->gateway, &ip, &ip_len);
    if (ret != 0 || ip == NULL || ip_len == 0) {
        ERROR("Parse IP %s failed", request->gateway);
        isulad_set_error_message("Invalid gateway %s", request->gateway);
        ret = EINVALIDARGS;
        goto out;
    }

    if (!net_contain_ip(net, ip, ip_len, false)) {
        isulad_set_error_message("subnet \"%s\" and gateway \"%s\" not match", request->subnet, request->gateway);
        ret = EINVALIDARGS;
    }

out:
    free_ipnet_type(net);
    free(ip);
    return ret;
}

static int network_create_cb(const network_create_request *request, network_create_response **response)
{
    int ret = 0;

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
        (*response)->cc = ISULAD_ERR_INPUT;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
        return ret;
    }

    network_conflist_lock(EXCLUSIVE);

    if (request->driver == NULL || strcmp(request->driver, g_default_driver) == 0) {
        ret = network_config_bridge_create(request, response);
    }
    // TODO: support macvlan and other network drivers

    network_conflist_unlock();

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

    if (!network_is_valid_name(request->name)) {
        cc = ISULAD_ERR_INPUT;
        ret = EINVALIDARGS;
        goto out;
    }

    network_conflist_lock(SHARED);

    ret = network_config_inspect(request->name, &network_json);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
    }

    network_conflist_unlock();

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

static int network_list_cb(const network_list_request *request, network_list_response **response)
{
    // TODO
    return 0;
}

static int network_remove_cb(const network_remove_request *request, network_remove_response **response)
{
    // TODO
    return 0;
}

void network_callback_init(service_network_callback_t *cb)
{
    cb->create = network_create_cb;
    cb->inspect = network_inspect_cb;
    cb->list = network_list_cb;
    cb->remove = network_remove_cb;
}
