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
 * Author: maoweiyong
 * Create: 2018-11-07
 * Description: provide oci runtime hooks functions
 *******************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <read_file.h>
#include "oci_runtime_hooks.h"

#include "log.h"
#include "utils.h"

#define PARSE_ERR_BUFFER_SIZE 1024

oci_runtime_spec_hooks *oci_runtime_spec_hooks_parse_file(const char *filename,
                                                          const struct parser_context *ctx,
                                                          parser_error *err)
{
    yajl_val tree;
    size_t filesize;
    char *content = NULL;
    char errbuf[PARSE_ERR_BUFFER_SIZE] = { 0 };
    struct parser_context tmp_ctx = { 0 };

    if (filename == NULL || err == NULL) {
        return NULL;
    }

    *err = NULL;
    if (ctx == NULL) {
        ctx = &tmp_ctx;
    }
    content = read_file(filename, &filesize);
    if (content == NULL) {
        if (asprintf(err, "cannot read the file: %s", filename) < 0) {
            *err = util_strdup_s("error allocating memory");
        }
        return NULL;
    }
    tree = yajl_tree_parse(content, errbuf, sizeof(errbuf));
    free(content);
    if (tree == NULL) {
        if (asprintf(err, "cannot parse the file: %s", errbuf) < 0) {
            *err = util_strdup_s("error allocating memory");
        }
        return NULL;
    }
    oci_runtime_spec_hooks *ptr = make_oci_runtime_spec_hooks(tree, ctx, err);
    yajl_tree_free(tree);
    return ptr;
}

