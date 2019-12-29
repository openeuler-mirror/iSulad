/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container lcrd functions
 ******************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#include "liblcrd.h"
#include "log.h"
#include "pack_config.h"
#include "utils.h"

// record the errno
__thread char *g_lcrd_errmsg = NULL;

/* lcrd container conf request free */
void lcrd_container_conf_request_free(struct lcrd_container_conf_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request->name);
    request->name = NULL;

    free(request);
}

/* lcrd container conf response free */
void lcrd_container_conf_response_free(struct lcrd_container_conf_response *response)
{
    if (response == NULL) {
        return;
    }
    free(response->errmsg);
    response->errmsg = NULL;

    free(response->container_logpath);
    response->container_logpath = NULL;

    free(response->container_logsize);
    response->container_logsize = NULL;

    free(response);
}

/* lcrd events request free */
void lcrd_events_request_free(struct lcrd_events_request *request)
{
    if (request == NULL) {
        return;
    }
    if (request->id != NULL) {
        free(request->id);
        request->id = NULL;
    }
    free(request);
}

void lcrd_copy_from_container_request_free(struct lcrd_copy_from_container_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request->id);
    request->id = NULL;
    free(request->runtime);
    request->runtime = NULL;
    free(request->srcpath);
    request->srcpath = NULL;

    free(request);
}

void lcrd_copy_from_container_response_free(struct lcrd_copy_from_container_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->data);
    response->data = NULL;
    response->data_len = 0;

    free(response);
}

/* lcrd set error message */
void lcrd_set_error_message(const char *format, ...)
{
    int ret = 0;
    char errbuf[BUFSIZ + 1] = { 0 };

    DAEMON_CLEAR_ERRMSG();
    va_list argp;
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0 || ret >= BUFSIZ) {
        return;
    }

    g_lcrd_errmsg = util_strdup_s(errbuf);
}

/* lcrd try set error message */
void lcrd_try_set_error_message(const char *format, ...)
{
    int ret = 0;

    if (g_lcrd_errmsg != NULL) {
        return;
    }
    char errbuf[BUFSIZ + 1] = { 0 };

    va_list argp;
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0 || ret >= BUFSIZ) {
        return;
    }

    g_lcrd_errmsg = util_strdup_s(errbuf);
}

/* lcrd append error message */
void lcrd_append_error_message(const char *format, ...)
{
    int ret = 0;
    char errbuf[BUFSIZ + 1] = { 0 };
    char *result = NULL;

    va_list argp;
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0 || ret >= BUFSIZ) {
        return;
    }
    result = util_string_append(g_lcrd_errmsg, errbuf);
    if (result == NULL) {
        return;
    }
    if (g_lcrd_errmsg != NULL) {
        free(g_lcrd_errmsg);
    }
    g_lcrd_errmsg = result;
}

/* lcrd container rename request free */
void lcrd_container_rename_request_free(struct lcrd_container_rename_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->old_name);
    request->old_name = NULL;
    free(request->new_name);
    request->new_name = NULL;

    free(request);
}

/* lcrd container rename response free */
void lcrd_container_rename_response_free(struct lcrd_container_rename_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->id);
    response->id = NULL;
    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

void lcrd_logs_request_free(struct lcrd_logs_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;
    free(request->runtime);
    request->runtime = NULL;
    free(request->since);
    request->since = NULL;
    free(request->until);
    request->until = NULL;
    free(request);
}

void lcrd_logs_response_free(struct lcrd_logs_response *response)
{
    if (response == NULL) {
        return;
    }
    free(response->errmsg);
    response->errmsg = NULL;
    free(response);
}

void container_log_config_free(struct container_log_config *conf)
{
    if (conf == NULL) {
        return;
    }
    free(conf->path);
    conf->path = NULL;
    conf->rotate = 0;
    conf->size = 0;
    free(conf);
}

