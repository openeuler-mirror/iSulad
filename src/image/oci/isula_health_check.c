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
* Author: liuhao
* Create: 2019-07-15
* Description: isula health check operator implement
*******************************************************************************/
#include "isula_health_check.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "log.h"

int isula_do_health_check()
{
#define HEALTH_CHECK_TIMEOUT 3
    int ret = -1;
    struct isula_health_check_request ireq = {0};
    struct isula_health_check_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->health_check == NULL) {
        ERROR("Umimplement health check operator");
        return -1;
    }

    iresp = (struct isula_health_check_response *)util_common_calloc_s(sizeof(struct isula_health_check_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }
    // update deadline for health check to 3s
    conf.deadline = HEALTH_CHECK_TIMEOUT;

    ret = im_ops->health_check(&ireq, iresp, &conf);
    if (ret != 0) {
        WARN("Health check failed: %s", iresp->errmsg);
    }

out:
    free_isula_health_check_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
