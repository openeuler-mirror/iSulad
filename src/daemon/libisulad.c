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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container isulad functions
 ******************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#include "libisulad.h"
#include "utils.h"

// record the errno
__thread char *g_isulad_errmsg = NULL;

/* isulad events request free */
void isulad_events_request_free(struct isulad_events_request *request)
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

void isulad_copy_from_container_request_free(struct isulad_copy_from_container_request *request)
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

void isulad_copy_from_container_response_free(struct isulad_copy_from_container_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->data);
    response->data = NULL;
    response->data_len = 0;

    free(response);
}

/* isulad set error message */
void isulad_set_error_message(const char *format, ...)
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

    g_isulad_errmsg = util_strdup_s(errbuf);
}

/* isulad try set error message */
void isulad_try_set_error_message(const char *format, ...)
{
    int ret = 0;

    if (g_isulad_errmsg != NULL) {
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

    g_isulad_errmsg = util_strdup_s(errbuf);
}

/* isulad append error message */
void isulad_append_error_message(const char *format, ...)
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
    result = util_string_append(g_isulad_errmsg, errbuf);
    if (result == NULL) {
        return;
    }
    if (g_isulad_errmsg != NULL) {
        free(g_isulad_errmsg);
    }
    g_isulad_errmsg = result;
}

/* isulad container rename request free */
void isulad_container_rename_request_free(struct isulad_container_rename_request *request)
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

/* isulad container rename response free */
void isulad_container_rename_response_free(struct isulad_container_rename_response *response)
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

/* isulad container rename request free */
void isulad_container_resize_request_free(struct isulad_container_resize_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;

    free(request->suffix);
    request->suffix = NULL;

    free(request);
}

/* isulad container rename response free */
void isulad_container_resize_response_free(struct isulad_container_resize_response *response)
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


void isulad_logs_request_free(struct isulad_logs_request *request)
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

void isulad_logs_response_free(struct isulad_logs_response *response)
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
    free(conf->driver);
    conf->driver = NULL;
    conf->rotate = 0;
    conf->size = 0;
    free(conf);
}

void isulad_events_format_free(struct isulad_events_format *value)
{
    size_t i;

    if (value == NULL) {
        return;
    }
    free(value->id);
    value->id = NULL;

    free(value->opt);
    value->opt = NULL;

    for (i = 0; i < value->annotations_len; i++) {
        free(value->annotations[i]);
        value->annotations[i] = NULL;
    }
    free(value->annotations);
    value->annotations = NULL;

    free(value);
}

