/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2019-10-25
 * Description: provide regex patten functions
 ********************************************************************************/

#define _GNU_SOURCE
#include "utils_regex.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <regex.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_string.h"

/*
 * return value:
 * -1  failed
 *  0  match
 *  1  no match
 */
int util_reg_match(const char *patten, const char *str)
{
    int nret = 0;
    regex_t reg;
    regmatch_t regmatch = { 0 };

    if (patten == NULL || str == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    nret = regcomp(&reg, patten, REG_EXTENDED | REG_NOSUB);
    if (nret) {
        return -1;
    }

    nret = regexec(&reg, str, 1, &regmatch, 0);
    if (nret == 0) {
        nret = 0;
        goto free_out;
    } else if (nret == REG_NOMATCH) {
        nret = 1;
        goto free_out;
    } else {
        nret = -1;
        ERROR("reg match failed");
        goto free_out;
    }

free_out:
    regfree(&reg);

    return nret;
}

static int get_regex_size_from_wildcard(const char *wildcard, const char *escapes, size_t escapes_size, size_t *len)
{
    size_t size = 0;
    size_t i, tmp;

    for (i = 0; i < escapes_size; i++) {
        tmp = util_strings_count(wildcard, escapes[i]);
        if (tmp > SIZE_MAX - size) {
            ERROR("Invalid wildcard");
            return -1;
        }
        size += tmp;
    }

    tmp = util_strings_count(wildcard, '*');
    if (tmp > SIZE_MAX - size - strlen(wildcard) - 3) {
        ERROR("Invalid wildcard");
        return -1;
    }
    // ^ + escape char size + wildcard + * size + $ + '\0'
    *len = 1 + size + strlen(wildcard) + tmp + 1 + 1;
    return 0;
}

int util_wildcard_to_regex(const char *wildcard, char **regex)
{
    size_t i;
    size_t index = 0;
    size_t regex_size;
    char escapes[] = { '$', '^', '[', ']', '(', ')', '{', '|', '+', '\\', '.', '<', '>', '}' };

    if (wildcard == NULL || regex == NULL) {
        ERROR("Invalid output parameter");
        return -1;
    }
    if (get_regex_size_from_wildcard(wildcard, escapes, sizeof(escapes) / sizeof(char), &regex_size) != 0) {
        return -1;
    }
    *regex = (char *)util_common_calloc_s(regex_size);
    if (*regex == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    (*regex)[index++] = '^';
    for (i = 0; i < strlen(wildcard); i++) {
        char ch = wildcard[i];
        bool escaped = false;
        size_t j;
        for (j = 0; j < sizeof(escapes) / sizeof(char); j++) {
            if (ch == escapes[j]) {
                (*regex)[index++] = '\\';
                (*regex)[index++] = ch;
                escaped = true;
                break;
            }
        }
        if (!escaped) {
            if (ch == '*') {
                (*regex)[index++] = '.';
                (*regex)[index++] = '*';
            } else if (ch == '?') {
                (*regex)[index++] = '.';
            } else {
                (*regex)[index++] = ch;
            }
        }
    }
    (*regex)[index++] = '$';
    (*regex)[index] = '\0';

    return 0;
}
