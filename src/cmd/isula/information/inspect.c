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
#include "error.h"
#include "inspect.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "console.h"
#include "utils.h"
#include "isula_libutils/json_common.h"
#include <regex.h>

const char g_cmd_inspect_desc[] = "Return low-level information on a container or image";
const char g_cmd_inspect_usage[] = "inspect [options] CONTAINER|IMAGE [CONTAINER|IMAGE...]";

struct client_arguments g_cmd_inspect_args = {
    .format = NULL,
    .time = 120, // timeout time
};

#define PRINTF_TAB_LEN 4
#define TOP_LEVEL_OBJ 0x10
#define IS_TOP_LEVEL_OBJ(value) ((value)&TOP_LEVEL_OBJ)

#define LAST_ELEMENT_BIT 0x0F
#define NOT_LAST_ELEMENT 0x00
#define LAST_ELEMENT 0x01
#define IS_LAST_ELEMENT(value) (LAST_ELEMENT == ((value)&LAST_ELEMENT_BIT))

#define YAJL_TYPEOF(json) ((json)->type)

#define CONTAINER_INSPECT_ERR (-1)
#define CONTAINER_NOT_FOUND (-2)

typedef struct {
    yajl_val tree_root; /* Should be free by yajl_tree_free() */
    yajl_val tree_print; /* Point to the object be printf */
} container_tree_t;

static yajl_val inspect_get_json_info(yajl_val element, char *key_string);
static void print_json_aux(yajl_val element, int indent, int flags, bool json_format);

/*
 * Parse text into a JSON tree. If text is valid JSON, returns a
 * yajl_val structure, otherwise prints and error and returns null.
 * Note: return tree need free by function yajl_tree_free (tree).
 */
#define ERR_BUF 1024
static yajl_val inspect_load_json(const char *json_data)
{
    yajl_val tree = NULL;
    char errbuf[ERR_BUF];

    tree = yajl_tree_parse(json_data, errbuf, sizeof(errbuf));
    if (tree == NULL) {
        ERROR("Parse json data failed %s\n", errbuf);
        return NULL;
    }

    return tree;
}

static yajl_val json_get_val(yajl_val tree, const char *name, yajl_type type)
{
    const char *path[] = { name, NULL };
    return yajl_tree_get(tree, path, type);
}

static yajl_val json_object(yajl_val element, char *key)
{
    yajl_val node = NULL;
    char *top_key = key;
    char *next_context = NULL;

    top_key = strtok_r(top_key, ".", &next_context);
    if (top_key == NULL) {
        return NULL;
    }

    node = json_get_val(element, top_key, yajl_t_any);
    if (node) {
        node = inspect_get_json_info(node, next_context);
    }
    return node;
}

static yajl_val json_array(yajl_val element, char *key)
{
    if (element == NULL || key == NULL) {
        return NULL;
    }
    size_t i = 0;
    size_t size = 0;
    yajl_val node = NULL;
    yajl_val value = NULL;
    char *top_key = key;
    char *next_context = NULL;
    if (YAJL_GET_ARRAY(element) != NULL) {
        size = YAJL_GET_ARRAY(element)->len;
    }
    top_key = strtok_r(top_key, ".", &next_context);
    if (top_key == NULL) {
        return NULL;
    }

    for (i = 0; i < size; i++) {
        value = element->u.array.values[i];

        node = json_get_val(value, top_key, yajl_t_any);
        if (node) {
            node = inspect_get_json_info(node, next_context);
            if (node) {
                break;
            }
        }
    }
    return node;
}

static yajl_val inspect_get_json_info(yajl_val element, char *key_string)
{
    yajl_val node = NULL;

    if (element == NULL) {
        return NULL;
    }

    /* If "key_string" equal to NULL, return the input element. */
    if ((key_string == NULL) || (strlen(key_string) == 0)) {
        return element;
    }

    switch (YAJL_TYPEOF(element)) {
        case yajl_t_object:
            node = json_object(element, key_string);
            break;
        case yajl_t_array:
            node = json_array(element, key_string);
            break;
        case yajl_t_any:
        case yajl_t_null:
        case yajl_t_false:
        case yajl_t_true:
        case yajl_t_number:
        case yajl_t_string:
        default:
            ERROR("unrecognized JSON type %d\n", YAJL_TYPEOF(element));
            break;
    }

    return node;
}

static bool inspect_filter_done(yajl_val root, const char *filter, container_tree_t *tree_array)
{
    yajl_val object = root;
    char *key_string = NULL;

    if (filter != NULL) {
        key_string = util_strdup_s(filter);

        object = inspect_get_json_info(root, key_string);
        if (object == NULL) {
            COMMAND_ERROR("Executing \"\" at <.%s>: map has no entry for key \"%s\"", filter, key_string);
            free(key_string);
            return false;
        }
        free(key_string);
    }

    tree_array->tree_print = object;

    return true;
}

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
static int client_inspect(const struct client_arguments *args, const char *filter, container_tree_t *tree_array)
{
    isula_connect_ops *ops = NULL;
    struct isula_inspect_request request = { 0 };
    struct isula_inspect_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;
    yajl_val tree = NULL;

    response = util_common_calloc_s(sizeof(struct isula_inspect_response));
    if (response == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    request.name = args->name;
    request.bformat = args->format ? true : false;
    request.timeout = args->time;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.inspect == NULL || ops->image.inspect == NULL) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = client_inspect_container(&request, response, &config, ops);
    if (ret == CONTAINER_NOT_FOUND) {
        isula_inspect_response_free(response);
        response = NULL;

        response = util_common_calloc_s(sizeof(struct isula_inspect_response));
        if (response == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        ret = client_inspect_image(&request, response, &config, ops);
    }

    if (ret != 0) {
        goto out;
    }

    if (response == NULL || response->json == NULL) {
        ERROR("Container or image json is empty");
        ret = -1;
        goto out;
    }

    tree = inspect_load_json(response->json);
    if (tree == NULL) {
        ret = -1;
        goto out;
    }

    if (!inspect_filter_done(tree, filter, tree_array)) {
        ret = -1;
        yajl_tree_free(tree);
        goto out;
    }

    tree_array->tree_root = tree;

out:
    isula_inspect_response_free(response);
    return ret;
}

static void print_json_string(yajl_val element, int flags, bool json_format)
{
    const char *str = YAJL_GET_STRING(element);
    const char *hexchars = "0123456789ABCDEF";
    char hex[7] = { '\\', 'u', '0', '0', '\0', '\0', '\0' };

    if (json_format) {
        putchar('"');
    }
    if (str == NULL) {
        goto out;
    }

    for (; *str != '\0'; str++) {
        const char *escapestr = NULL;
        switch (*str) {
            case '\r':
                escapestr = "\\r";
                break;
            case '\n':
                escapestr = "\\n";
                break;
            case '\\':
                escapestr = "\\\\";
                break;
            case '"':
                escapestr = "\\\"";
                break;
            case '\f':
                escapestr = "\\f";
                break;
            case '\b':
                escapestr = "\\b";
                break;
            case '\t':
                escapestr = "\\t";
                break;
            default:
                if ((unsigned char)(*str) < 0x20) {
                    hex[4] = hexchars[(unsigned char)(*str) >> 4];
                    hex[5] = hexchars[(unsigned char)(*str) & 0x0F];
                    escapestr = hex;
                }
                break;
        }
        if (escapestr != NULL) {
            printf("%s", escapestr);
        } else {
            putchar(*str);
        }
    }

out:
    if (json_format) {
        putchar('"');
    }
    if (!IS_LAST_ELEMENT((unsigned int)flags)) {
        putchar(',');
    }
}

static void print_json_number(yajl_val element, int flags)
{
    if (IS_LAST_ELEMENT((unsigned int)flags)) {
        printf("%s", YAJL_GET_NUMBER(element));
    } else {
        printf("%s,", YAJL_GET_NUMBER(element));
    }
}

static void print_json_true(int flags)
{
    if (IS_LAST_ELEMENT((unsigned int)flags)) {
        printf("true");
    } else {
        printf("true,");
    }
}

static void print_json_false(int flags)
{
    if (IS_LAST_ELEMENT((unsigned int)flags)) {
        printf("false");
    } else {
        printf("false,");
    }
}

static void print_json_null(int flags)
{
    if (IS_LAST_ELEMENT((unsigned int)flags)) {
        printf("null");
    } else {
        printf("null,");
    }
}

static void print_json_indent(int indent, bool new_line)
{
    int i = 0;

    if (new_line) {
        printf("\n");
    }

    for (i = 0; i < indent; i++) {
        putchar(' ');
    }
}

static void print_json_object(yajl_val element, int indent, int flags, bool json_format)
{
    size_t size = 0;
    const char *objkey = NULL;
    yajl_val value = NULL;
    size_t i = 0;
    if (element == NULL) {
        return;
    }
    if (YAJL_GET_OBJECT(element) != NULL) {
        size = YAJL_GET_OBJECT(element)->len;
    }
    if (IS_TOP_LEVEL_OBJ((unsigned int)flags)) {
        print_json_indent(indent, false);
    }

    if (size == 0) {
        if (IS_LAST_ELEMENT((unsigned int)flags)) {
            printf("{}");
        } else {
            printf("{},");
        }
        return;
    }

    printf("{");

    for (i = 0; i < size; i++) {
        print_json_indent(indent + PRINTF_TAB_LEN, true);
        objkey = element->u.object.keys[i];
        value = element->u.object.values[i];

        printf("\"%s\": ", objkey);
        if ((i + 1) == size) {
            print_json_aux(value, indent + PRINTF_TAB_LEN, LAST_ELEMENT, json_format);
        } else {
            print_json_aux(value, indent + PRINTF_TAB_LEN, NOT_LAST_ELEMENT, json_format);
        }
    }

    print_json_indent(indent, true);

    if (IS_LAST_ELEMENT((unsigned int)flags)) {
        printf("}");
    } else {
        printf("},");
    }
}

static void print_json_array(yajl_val element, int indent, int flags, bool json_format)
{
    size_t i = 0;
    size_t size = 0;
    yajl_val value = NULL;

    if (element == NULL) {
        return;
    }
    if (YAJL_GET_ARRAY(element) != NULL) {
        size = YAJL_GET_ARRAY(element)->len;
    }

    if (IS_TOP_LEVEL_OBJ((unsigned int)flags)) {
        print_json_indent(indent, false);
    }

    if (size == 0) {
        if (IS_LAST_ELEMENT((unsigned int)flags)) {
            printf("[]");
        } else {
            printf("[],");
        }
        return;
    }

    printf("[");

    for (i = 0; i < size; i++) {
        print_json_indent(indent + PRINTF_TAB_LEN, true);
        value = element->u.array.values[i];

        if ((i + 1) == size) {
            print_json_aux(value, indent + PRINTF_TAB_LEN, LAST_ELEMENT, json_format);
        } else {
            print_json_aux(value, indent + PRINTF_TAB_LEN, NOT_LAST_ELEMENT, json_format);
        }
    }
    print_json_indent(indent, true);

    if (IS_LAST_ELEMENT((unsigned int)flags)) {
        printf("]");
    } else {
        printf("],");
    }
}

static void print_json_aux(yajl_val element, int indent, int flags, bool json_format)
{
    if (element == NULL) {
        return;
    }

    switch (YAJL_TYPEOF(element)) {
        case yajl_t_object:
            print_json_object(element, indent, flags, json_format);
            break;
        case yajl_t_array:
            print_json_array(element, indent, flags, json_format);
            break;
        case yajl_t_string:
            print_json_string(element, flags, json_format);
            break;
        case yajl_t_number:
            print_json_number(element, flags);
            break;
        case yajl_t_true:
            print_json_true(flags);
            break;
        case yajl_t_false:
            print_json_false(flags);
            break;
        case yajl_t_null:
            print_json_null(flags);
            break;
        case yajl_t_any:
        default:
            ERROR("unrecognized JSON type %d\n", YAJL_TYPEOF(element));
            break;
    }
}

/*
 * Print yajl tree as JSON format.
 */
static void print_json(yajl_val tree, int indent, bool json_format)
{
    if (tree == NULL) {
        return;
    }

    print_json_aux(tree, indent, LAST_ELEMENT | TOP_LEVEL_OBJ, json_format);
}

static void inspect_show_result(int show_nums, const container_tree_t *tree_array, const char *format, bool json_format)
{
    int i = 0;
    yajl_val tree = NULL;
    int indent = 0;

    if (show_nums == 0) {
        if (format == NULL) {
            printf("[]\n");
        }
        return;
    }

    if (format == NULL) {
        printf("[\n");
        indent = PRINTF_TAB_LEN;
    }

    for (i = 0; i < show_nums; i++) {
        tree = tree_array[i].tree_print;
        print_json(tree, indent, json_format);

        if ((i + 1) != show_nums) {
            if (format == NULL) {
                printf(",\n");
            } else {
                printf("\n");
            }
        }
    }

    if (format == NULL) {
        printf("\n]\n");
    } else {
        printf("\n");
    }
}

static void inspect_free_trees(int tree_nums, container_tree_t *tree_array)
{
    int i = 0;

    for (i = 0; i < tree_nums; i++) {
        if (tree_array[i].tree_root) {
            yajl_tree_free(tree_array[i].tree_root);
            tree_array[i].tree_root = NULL;
            tree_array[i].tree_print = NULL;
        }
    }
}

/* arg string format: "{{json .State.Running}}"
 * ret_string should be free outside by free().
 */
static char *inspect_pause_filter(const char *arg)
{
    char *input_str = NULL;
    char *p = NULL;
    char *ret_string = NULL;
    char *next_context = NULL;

    input_str = util_strdup_s(arg);

    p = strtok_r(input_str, ".", &next_context);
    if (p == NULL) {
        goto out;
    }

    p = next_context;
    if (p == NULL) {
        goto out;
    }

    p = strtok_r(p, " }", &next_context);
    if (p == NULL) {
        goto out;
    }

    ret_string = util_strdup_s(p);

out:
    if (input_str != NULL) {
        free(input_str);
    }

    return ret_string;
}

#define MATCH_NUM 1
#define CHECK_FAILED (-1)
#define JSON_ARGS "^\\s*\\{\\s*\\{\\s*(json)?\\s+[^\\s]+\\s*.*\\}\\s*\\}\\s*$"

static int inspect_check(const char *json_str, const char *regex)
{
    int status = 0;
    regmatch_t pmatch[MATCH_NUM] = { { 0 } };
    regex_t reg;

    if (json_str == NULL) {
        ERROR("Filter string is NULL.");
        return CHECK_FAILED;
    }

    regcomp(&reg, regex, REG_EXTENDED);

    status = regexec(&reg, json_str, MATCH_NUM, pmatch, 0);
    regfree(&reg);

    if (status != 0) {
        /* Log by caller */
        return CHECK_FAILED;
    }

    return 0;
}

static int inspect_check_format_f(const char *json_str, bool *json_format)
{
    int ret = 0;

    if (json_str == NULL) {
        ERROR("Filter string is NULL.");
        return CHECK_FAILED;
    }

    /* check "{{json .xxx.xxx}}" */
    ret = inspect_check(json_str, "^\\s*\\{\\s*\\{\\s*(json\\s+)?(\\.\\w+)+\\s*\\}\\s*\\}\\s*$");
    if (ret == 0) {
        if (inspect_check(json_str, "^\\s*\\{\\s*\\{\\s*json\\s+(\\.\\w+)+\\s*\\}\\s*\\}\\s*$") != 0) {
            *json_format = false;
        }
        return 0;
    }

    /* check "{{ ... }}" */
    ret = inspect_check(json_str, "^\\s*\\{\\s*\\{\\s*[^{}]*\\s*\\}\\s*\\}\\s*$");
    if (ret != 0) {
        COMMAND_ERROR("Unexpected \"{\" or \"}\" in operand, should be \"{{ ... }}\".");
        goto out;
    }

    /* json args. */
    ret = inspect_check(json_str, "^\\s*\\{\\s*\\{\\s*(json)?\\s*\\}\\s*\\}\\s*$");
    if (ret == 0) {
        COMMAND_ERROR("Executing \"\" at <json>: wrong number of args for json: want 1 got 0.");
        goto out;
    }

    /* check "{{json... }}" */
    ret = inspect_check(json_str, "^\\s*\\{\\s*\\{\\s*(json)?\\W.*\\s*\\}\\s*\\}\\s*$");
    if (ret != 0) {
        COMMAND_ERROR("Output mode error, E.g \"{{json ... }}\" or \"{{ ... }}\" is right.");
        goto out;
    }

    /* json args. */
    ret = inspect_check(json_str, JSON_ARGS);
    if (ret != 0) {
        COMMAND_ERROR("Executing \"\" at <json>: wrong number of args for json: want 1 got 0.");
        goto out;
    }

    /* "{{json .xxx.xxx }}" check failed log */
    COMMAND_ERROR("Unexpected <.> in operand. E.g \"{{json .xxx.xxx }}\" is right.");

out:

    return CHECK_FAILED;
}

int cmd_inspect_main(int argc, const char **argv)
{
    int i = 0;
    int status = 0;
    struct isula_libutils_log_config lconf = { 0 };
    int success_counts = 0;
    char *filter_string = NULL;
    container_tree_t *tree_array = NULL;
    size_t array_size = 0;
    command_t cmd;
    bool json_format = true;

    if (client_arguments_init(&g_cmd_inspect_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_inspect_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf), INSPECT_OPTIONS(g_cmd_inspect_args),
               COMMON_OPTIONS(g_cmd_inspect_args)
    };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_inspect_desc,
                 g_cmd_inspect_usage);
    if (command_parse_args(&cmd, &g_cmd_inspect_args.argc, &g_cmd_inspect_args.argv)) {
        exit(EINVALIDARGS);
    }
    isula_libutils_default_log_config(argv[0], &lconf);
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
    array_size = sizeof(container_tree_t) * (size_t)(g_cmd_inspect_args.argc + 1);
    tree_array = (container_tree_t *)util_common_calloc_s(array_size);
    if (tree_array == NULL) {
        ERROR("Malloc failed\n");
        exit(ECOMMON);
    }

    if (g_cmd_inspect_args.format != NULL) {
        int ret;
        ret = inspect_check_format_f(g_cmd_inspect_args.format, &json_format);
        if (ret != 0) {
            free(tree_array);
            tree_array = NULL;
            exit(ECOMMON);
        }

        filter_string = inspect_pause_filter(g_cmd_inspect_args.format);
        if (filter_string == NULL) {
            COMMAND_ERROR("Inspect format parameter invalid: %s", g_cmd_inspect_args.format);
            free(tree_array);
            tree_array = NULL;
            exit(EINVALIDARGS);
        }
    }

    for (i = 0; i < g_cmd_inspect_args.argc; i++) {
        g_cmd_inspect_args.name = g_cmd_inspect_args.argv[i];

        if (client_inspect(&g_cmd_inspect_args, filter_string, &tree_array[i])) {
            status = -1;
            break;
        }
        success_counts++;
    }

    if (tree_array != NULL) {
        inspect_show_result(success_counts, tree_array, g_cmd_inspect_args.format, json_format);
        inspect_free_trees(success_counts, tree_array);
    }
    free(tree_array);
    free(filter_string);

    if (status) {
        COMMAND_ERROR("Inspect error: No such object:%s", g_cmd_inspect_args.name);
        exit(ECOMMON);
    }
    exit(EXIT_SUCCESS);
}
