/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2022-10-17
 * Description: provide template string parse function
 ********************************************************************************/

#include "template_string_parse.h"
#include "utils.h"

/* arg string format: "{{json .State.Running}} or {{.Name}}"
 * ret_string should be free outside by free().
 */
char *parse_single_template_string(const char *arg)
{
    char *input_str = NULL;
    char *p = NULL;
    char *ret_string = NULL;
    char *next_context = NULL;

    if(arg == NULL) {
        return ret_string;
    }

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
