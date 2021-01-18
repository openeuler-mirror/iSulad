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
 * Description: provide inspect format function definition
 ******************************************************************************/
#ifndef CMD_ISULA_INSPECT_FORMAT_H
#define CMD_ISULA_INSPECT_FORMAT_H

#include <stdbool.h>
#include <yajl/yajl_tree.h>

typedef struct {
    yajl_val tree_root; /* Should be free by yajl_tree_free() */
    yajl_val tree_print; /* Point to the object be printf */
} container_tree_t;

int inspect_check_format_f(const char *json_str, bool *json_format);

char *inspect_parse_filter(const char *arg);

yajl_val inspect_load_json(const char *json_data);

bool inspect_filter_done(yajl_val root, const char *filter, container_tree_t *tree_array);

void inspect_show_result(int show_nums, const container_tree_t *tree_array, const char *format, bool *json_format);

void inspect_free_trees(int tree_nums, container_tree_t *tree_array);

#endif // CMD_ISULA_INSPECT_FORMAT_H

