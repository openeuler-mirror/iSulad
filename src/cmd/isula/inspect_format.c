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
 * Author: zhangxiaoyu
 * Create: 2020-09-28
 * Description: provide inspect format functions
 ******************************************************************************/
#include "inspect_format.h"

#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yajl/yajl_tree.h>

#include "isula_libutils/log.h"
#include "utils.h"

#define PRINTF_TAB_LEN 4
#define TOP_LEVEL_OBJ 0x10
#define IS_TOP_LEVEL_OBJ(value) ((value)&TOP_LEVEL_OBJ)

#define LAST_ELEMENT_BIT 0x0F
#define NOT_LAST_ELEMENT 0x00
#define LAST_ELEMENT 0x01
#define IS_LAST_ELEMENT(value) (LAST_ELEMENT == ((value)&LAST_ELEMENT_BIT))

#define YAJL_TYPEOF(json) ((json)->type)

static yajl_val inspect_get_json_info(yajl_val element, char *key_string);
static void print_json_aux(yajl_val element, int indent, int flags, bool json_format);

/*
 * Parse text into a JSON tree. If text is valid JSON, returns a
 * yajl_val structure, otherwise prints and error and returns null.
 * Note: return tree need free by function yajl_tree_free (tree).
 */
#define ERR_BUF 1024
yajl_val inspect_load_json(const char *json_data)
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

bool inspect_filter_done(yajl_val root, const char *filter, container_tree_t *tree_array)
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

void inspect_show_result(int show_nums, const container_tree_t *tree_array, const char *format, bool *json_format)
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
        if (json_format == NULL) {
            print_json(tree, indent, true);
        } else {
            print_json(tree, indent, json_format[i]);
        }

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

void inspect_free_trees(int tree_nums, container_tree_t *tree_array)
{
    int i = 0;

    if (tree_array == NULL) {
        return;
    }

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
char *inspect_parse_filter(const char *arg)
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

int inspect_check_format_f(const char *json_str, bool *json_format)
{
    int ret = 0;

    if (json_str == NULL) {
        ERROR("Filter string is NULL.");
        return CHECK_FAILED;
    }

    /* check "{{json .xxx.xxx}}" */
    ret = inspect_check(json_str, "^\\s*\\{\\s*\\{\\s*(json\\s+)?(\\.\\w+)+\\s*\\}\\s*\\}\\s*$");
    if (ret == 0) {
        if (inspect_check(json_str, "^\\s*\\{\\s*\\{\\s*json\\s+(\\.\\w+)+\\s*\\}\\s*\\}\\s*$") == 0) {
            *json_format = true;
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
