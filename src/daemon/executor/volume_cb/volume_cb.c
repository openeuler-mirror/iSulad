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
 * Create: 2020-09-03
 * Description: provide volume functions
 *********************************************************************************/

#include <stdio.h>
#include <malloc.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/json_common.h>
#include "isula_libutils/volume_list_volume_request.h"
#include "isula_libutils/volume_list_volume_response.h"
#include "isula_libutils/volume_remove_volume_request.h"
#include "isula_libutils/volume_remove_volume_response.h"
#include "isula_libutils/volume_prune_volume_request.h"
#include "isula_libutils/volume_prune_volume_response.h"
#include "isula_libutils/volume_volume.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "volume_cb.h"
#include "utils.h"
#include "error.h"
#include "err_msg.h"
#include "isula_libutils/log.h"
#include "volume_api.h"

/* volume list cb */
static int volume_list_cb(const volume_list_volume_request *request, volume_list_volume_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;
    struct volumes *list = NULL;
    size_t i = 0;
    volume_volume *vol = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    *response = util_common_calloc_s(sizeof(volume_list_volume_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto err_out;
    }

    EVENT("Volume Event: {Object: list volumes, Type: listing}");

    list = volume_list();
    if (list == NULL) {
        cc = ISULAD_ERR_EXEC;
        goto err_out;
    }

    if (list->vols_len == 0) {
        goto out;
    }

    (*response)->volumes = util_common_calloc_s(sizeof(volume_volume *) * list->vols_len);
    if ((*response)->volumes == NULL) {
        ERROR("out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto err_out;
    }

    for (i = 0; i < list->vols_len; i++) {
        vol = util_common_calloc_s(sizeof(volume_volume));
        if (vol == NULL) {
            ERROR("out of memory");
            cc = ISULAD_ERR_MEMOUT;
            goto err_out;
        }
        vol->driver = util_strdup_s(list->vols[i]->driver);
        vol->name = util_strdup_s(list->vols[i]->name);
        (*response)->volumes[i] = vol;
        (*response)->volumes_len++;
    }

out:
    EVENT("Volume Event: {Object: list volumes, Type: listed");

err_out:
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }
    free_volumes(list);

    return (cc != ISULAD_SUCCESS) ? ECOMMON : 0;
}

/* volume remove cb */
static int volume_remove_cb(const volume_remove_volume_request *request, volume_remove_volume_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || request->name == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    *response = util_common_calloc_s(sizeof(volume_remove_volume_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    EVENT("Volume Event: {Object: %s, Type: Deleting}", request->name);

    if (volume_remove(request->name) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    EVENT("Volume Event: {Object: %s, Type: Deleted}", request->name);

out:
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    return (cc != ISULAD_SUCCESS) ? ECOMMON : 0;
}

/* volume prune cb */
static int volume_prune_cb(const volume_prune_volume_request *request, volume_prune_volume_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;
    struct volume_names *pruned = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    *response = util_common_calloc_s(sizeof(volume_prune_volume_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    EVENT("Volume Event: {Object: prune volumes, Type: Prune}");

    if (volume_prune(&pruned) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    (*response)->volumes = pruned->names;
    pruned->names = NULL;
    (*response)->volumes_len = pruned->names_len;
    pruned->names_len = 0;

    EVENT("Volume Event: {Object: prune volumes, Type: Pruned");

out:
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }
    free_volume_names(pruned);

    return (cc != ISULAD_SUCCESS) ? ECOMMON : 0;
}

/* volume callback init */
void volume_callback_init(service_volume_callback_t *cb)
{
    if (cb == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    cb->list = volume_list_cb;
    cb->remove = volume_remove_cb;
    cb->prune = volume_prune_cb;
}
