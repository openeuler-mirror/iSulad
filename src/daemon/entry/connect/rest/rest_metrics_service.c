/******************************************************************************
 * Copyright (c) KylinSoft  Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.

 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xiapin
 * Create: 2021-08-17
 * Description: provide metric restful service function
 ******************************************************************************/
#ifdef ENABLE_METRICS
#include "rest_metrics_service.h"
#include "metrics_service.h"
#include "isula_libutils/log.h"

#include "callback.h"

int rest_register_metrics_handler(evhtp_t *htp)
{
    if (evhtp_set_cb(htp, METRIC_GET_BY_TYPE, metrics_get_by_type_cb, NULL) == NULL) {
        ERROR("Failed to register metrics get callback");
        return -1;
    }

    return 0;
}
#endif