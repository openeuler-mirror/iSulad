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
 * Description: provide container inspect functions
 ******************************************************************************/

#include "inspect.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "utils.h"
#include "connect.h"
#include "inspect_format.h"

const char g_cmd_inspect_desc[] = "Return low-level information on a container or image";
const char g_cmd_inspect_usage[] = "inspect [options] CONTAINER|IMAGE [CONTAINER|IMAGE...]";

struct client_arguments g_cmd_inspect_args = {
    .format = NULL,
    .time = 120, // timeout time
};

#define CONTAINER_INSPECT_ERR (-1)
#define CONTAINER_NOT_FOUND (-2)

/*
 * RETURN VALUE:
 * 0: inspect container success
 * CONTAINER_INSPECT_ERR: have the container, but failed to inspect due to other reasons
 * CONTAINER_NOT_FOUND: no such container
*/
static int client_inspect_container(const struct isula_inspect_request *request,
                                    struct isula_inspect_response *response, client_connect_config_t *config,
                                    const isula_connect_ops *ops)
{
    int ret = 0;

    ret = ops->container.inspect(request, response, config);
    if (ret != 0) {
        if ((response->errmsg != NULL) &&
            (strstr(response->errmsg, "Inspect invalid name") != NULL ||
             strstr(response->errmsg, "No such image or container or accelerator") != NULL)) {
            return CONTAINER_NOT_FOUND;
        }

        /* have the container, but failed to inspect due to other reasons */
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = CONTAINER_INSPECT_ERR;
    }

    return ret;
}

static int client_inspect_image(const struct isula_inspect_request *request, struct isula_inspect_response *response,
                                client_connect_config_t *config, const isula_connect_ops *ops)
{
    int ret = 0;

    ret = ops->image.inspect(request, response, config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }

    return ret;
}

/*
 * Create a inspect request message and call RPC
 */
static char *client_inspect(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_inspect_request request = { 0 };
    struct isula_inspect_response *response = NULL;
    client_connect_config_t config = { 0 };
    char *res_json = NULL;
    int result = 0;

    response = util_common_calloc_s(sizeof(struct isula_inspect_response));
    if (response == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    request.name = args->name;
    request.bformat = args->format ? true : false;
    request.timeout = args->time;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.inspect == NULL || ops->image.inspect == NULL) {
        ERROR("Unimplemented ops");
        goto out;
    }

    config = get_connect_config(args);
    result = client_inspect_container(&request, response, &config, ops);
    if (result == CONTAINER_NOT_FOUND) {
        isula_inspect_response_free(response);
        response = NULL;

        response = util_common_calloc_s(sizeof(struct isula_inspect_response));
        if (response == NULL) {
            ERROR("Out of memory");
            goto out;
        }

        result = client_inspect_image(&request, response, &config, ops);
    }

    if (result != 0) {
        goto out;
    }

    if (response == NULL || response->json == NULL) {
        ERROR("Container or image json is empty");
        goto out;
    }

    res_json = util_strdup_s(response->json);

out:
    isula_inspect_response_free(response);
    return res_json;
}

static char **inspect_split_filter(const char *format, size_t *filter_len)
{
    int i = 0;
    size_t count = 0;
    size_t res_count = 0;
    int last_num = 0;
    char **res_array = NULL;
    const char *p = NULL;

    if (format == NULL || filter_len == NULL) {
        return NULL;
    }

    count = util_strings_count(format, '}');
    *filter_len = (count + 1) / 2;
    if (*filter_len <= 1) {
        res_array = (char **)util_common_calloc_s(sizeof(char *));
        if (res_array == NULL) {
            ERROR("out of memory");
            return NULL;
        }

        *filter_len = 1;
        res_array[0] = util_strdup_s(format);
        if (res_array[0] == NULL) {
            ERROR("out of memory");
            util_free_array_by_len(res_array, 1);
            return NULL;
        }
        return res_array;
    }

    res_array = (char **)util_common_calloc_s(sizeof(char *) * (*filter_len));
    if (res_array == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    for (i = 0, count = 0; format[i] != '\0'; i++) {
        if (format[i] == '}') {
            count++;
            if (count == 0 || count % 2 == 1) {
                continue;
            } else if (res_count != *filter_len - 1) {
                res_array[res_count] = (char *)util_common_calloc_s(i - last_num + 2);
                if (res_array[res_count] == NULL) {
                    ERROR("out of memory");
                    util_free_array_by_len(res_array, *filter_len);
                    return NULL;
                }
                p = &format[last_num];
                (void)strncpy(res_array[res_count], p, i - last_num + 1);
                res_count++;
                last_num = i + 1;
            } else {
                res_array[res_count] = (char *)util_common_calloc_s(strlen(format) - last_num + 1);
                if (res_array[res_count] == NULL) {
                    ERROR("out of memory");
                    util_free_array_by_len(res_array, *filter_len);
                    return NULL;
                }
                p = &format[last_num];
                (void)strncpy(res_array[res_count], p, strlen(format) - last_num);
            }
        }
    }
    return res_array;
}

static int inspect_parse_json(const char *json, const char *filter, container_tree_t *tree_array)
{
    yajl_val tree = NULL;
    tree = inspect_load_json(json);
    if (tree == NULL) {
        return -1;
    }

    if (!inspect_filter_done(tree, filter, tree_array)) {
        yajl_tree_free(tree);
        return -1;
    }
    tree_array->tree_root = tree;

    return 0;
}

static int generate_filter_string(char ***filter_string, bool **json_format, size_t *filter_string_len)
{
    int i = 0;
    int j = 0;
    int ret = 0;
    size_t format_size = 0;
    char **format_string = NULL;

    if (filter_string == NULL || json_format == NULL || filter_string_len == NULL) {
        return -1;
    }

    format_string = inspect_split_filter(g_cmd_inspect_args.format, &format_size);
    if (format_string == NULL) {
        return ECOMMON;
    }

    *filter_string_len = format_size;
    *filter_string = (char **)util_common_calloc_s(sizeof(char *) * format_size);
    if (*filter_string == NULL) {
        ERROR("out of memory");
        ret = ECOMMON;
        goto error_out;
    }

    *json_format = (bool *)util_common_calloc_s(sizeof(bool) * format_size * g_cmd_inspect_args.argc);
    if (*json_format == NULL) {
        ERROR("out of memory");
        ret = ECOMMON;
        goto error_out;
    }

    for (i = 0; i < format_size; i++) {
        if (inspect_check_format_f(format_string[i], &(*json_format)[i]) != 0) {
            ret = ECOMMON;
            goto error_out;
        }

        (*filter_string)[i] = inspect_parse_filter(format_string[i]);
        if ((*filter_string)[i] == NULL) {
            COMMAND_ERROR("Inspect format parameter invalid: %s", g_cmd_inspect_args.format);
            ret = EINVALIDARGS;
            goto error_out;
        }
    }

    for (i = 1; i < g_cmd_inspect_args.argc; i++) {
        for (j = 0; j < format_size; j++) {
            (*json_format)[i * format_size + j] = (*json_format)[j];
        }
    }

    util_free_array_by_len(format_string, format_size);
    return ret;

error_out:
    free(*json_format);
    util_free_array_by_len(*filter_string, format_size);
    util_free_array_by_len(format_string, format_size);
    *json_format = NULL;
    *filter_string = NULL;
    return ret;
}

static int do_inspect()
{
    int i = 0;
    int j = 0;
    int status = 0;
    int ret = 0;
    int success_counts = 0;
    char *json = NULL;
    char **filter_string = NULL;
    size_t filter_string_len = 0;
    container_tree_t *tree_array = NULL;
    size_t array_size = 0;
    bool *json_format = NULL;

    if (g_cmd_inspect_args.format != NULL) {
        ret = generate_filter_string(&filter_string, &json_format, &filter_string_len);
        if (ret != 0) {
            goto out;
        }

        array_size = sizeof(container_tree_t) * (size_t)(g_cmd_inspect_args.argc * filter_string_len + 1);
    } else {
        array_size = sizeof(container_tree_t) * (size_t)(g_cmd_inspect_args.argc + 1);
    }

    tree_array = (container_tree_t *)util_common_calloc_s(array_size);
    if (tree_array == NULL) {
        ERROR("out of memory");
        ret = ECOMMON;
        goto out;
    }

    for (i = 0; i < g_cmd_inspect_args.argc; i++) {
        g_cmd_inspect_args.name = g_cmd_inspect_args.argv[i];
        json = client_inspect(&g_cmd_inspect_args);
        if (json == NULL) {
            status = -1;
            break;
        }

        if (g_cmd_inspect_args.format != NULL) {
            for (j = 0; j < filter_string_len; j++) {
                if (inspect_parse_json(json, filter_string[j], &tree_array[i * filter_string_len + j])) {
                    status = -1;
                    free(json);
                    json = NULL;
                    break;
                }
                success_counts++;
            }
        } else {
            if (inspect_parse_json(json, NULL, &tree_array[i])) {
                status = -1;
                free(json);
                json = NULL;
                break;
            }
            success_counts++;
        }
        free(json);
        json = NULL;
    }

    if (status == 0 && tree_array != NULL) {
        inspect_show_result(success_counts, tree_array, g_cmd_inspect_args.format, json_format);
    }

    if (status) {
        COMMAND_ERROR("Inspect error: No such object:%s", g_cmd_inspect_args.name);
        ret = ECOMMON;
        goto out;
    }

out:
    inspect_free_trees(success_counts, tree_array);
    free(tree_array);
    free(json_format);
    util_free_array_by_len(filter_string, filter_string_len);
    return ret;
}

int cmd_inspect_main(int argc, const char **argv)
{
    int ret = 0;
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;

    if (client_arguments_init(&g_cmd_inspect_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_inspect_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf) INSPECT_OPTIONS(g_cmd_inspect_args),
               COMMON_OPTIONS(g_cmd_inspect_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_inspect_desc,
                 g_cmd_inspect_usage);
    if (command_parse_args(&cmd, &g_cmd_inspect_args.argc, &g_cmd_inspect_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_inspect_args.argc == 0) {
        COMMAND_ERROR("\"inspect\" requires a minimum of 1 argument.");
        exit(EINVALIDARGS);
    }

    if (g_cmd_inspect_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many arguments.");
        exit(EINVALIDARGS);
    }

    if ((size_t)g_cmd_inspect_args.argc > SIZE_MAX / sizeof(container_tree_t) - 1) {
        COMMAND_ERROR("The number of parameters of inspect is too large");
        exit(ECOMMON);
    }
    ret = do_inspect();

    exit(ret);
}
