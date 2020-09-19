/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide util functions
 *********************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "utils_regex.h"

#include "isula_libutils/log.h"

#define CNI_VALID_NAME_CHARS "^[a-zA-Z0-9][a-zA-Z0-9_.-]*$"
#define MAX_INTERFACE_NAME_LENGTH 15

bool clibcni_util_validate_name(const char *name)
{
    if (name == NULL) {
        ERROR("missing network name");
        return false;
    }

    if (util_reg_match(CNI_VALID_NAME_CHARS, name) != 0) {
        ERROR("invalid characters found in network name: %s", name);
        return false;
    }

    return true;
}

bool clibcni_util_validate_id(const char *id)
{
    if (id == NULL) {
        ERROR("missing container ID");
        return false;
    }

    if (util_reg_match(CNI_VALID_NAME_CHARS, id) != 0) {
        ERROR("invalid characters found in container id: %s", id);
        return false;
    }

    return true;
}

static bool is_invalid_char(char c)
{
    switch (c) {
        case '/':
            return true;
        case ':':
            return true;
        case '\t':
            return true;
        case '\n':
            return true;
        case '\v':
            return true;
        case '\f':
            return true;
        case '\r':
            return true;
        case ' ':
            return true;
    }
    return false;
}

bool clibcni_util_validate_interface(const char *if_name)
{
    size_t i = 0;

    // 1. interface name must not be empty
    if (if_name == NULL || strlen(if_name) == 0) {
        ERROR("interface is empty");
        return false;
    }

    // 2. interface name must be less than 16 characters
    if (strlen(if_name) > MAX_INTERFACE_NAME_LENGTH) {
        ERROR("interface name is too long");
        return false;
    }

    // 3. interface name must not be "." or ".."
    if (strcmp(if_name, ".") == 0 || strcmp(if_name, "..") == 0) {
        ERROR("interface name is . or ..");
        return false;
    }

    // 4. interface name must not contain / or : or any whitespace characters
    for (i = 0; i < strlen(if_name); i++) {
        if (is_invalid_char(if_name[i])) {
            ERROR("interface name contain / or : or whitespace characters: %s", if_name);
            return false;
        }
    }

    return true;
}

