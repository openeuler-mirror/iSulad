/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: isula image load operator implement
*******************************************************************************/
#include "isula_image_load.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "libisulad.h"
#include "utils_verify.h"
#include "log.h"

const int g_output_max_size = 10 * SIZE_MB; /* 10M */

static char **get_refs(const char *output)
{
    char **refs = NULL;
    char *ref = NULL;
    char **lines = NULL;
    size_t len = 0;
    size_t size = 0;
    char *key_word = "Loaded image: ";
    int ret = -1;
    size_t i = 0;

    lines = util_string_split(output, '\n');
    if (lines == NULL) {
        return NULL;
    }

    len = util_array_len((const char **)lines);
    for (i = 0; i < len; i++) {
        ref = strstr(lines[i], key_word);
        if (ref == NULL || ref != lines[i]) {
            continue;
        }

        ref += strlen(key_word);

        /* +1 for terminator */
        size = strnlen(ref, (size_t)MAX_IMAGE_REF_LEN);
        if (size == 0 || size > MAX_IMAGE_REF_LEN) {
            ERROR("Invalid ref %s", ref);
            ret = -1;
            goto out;
        }
        ret = util_array_append(&refs, (const char *)ref);
        if (ret != 0) {
            ERROR("Append ref %s to array failed", ref);
            goto out;
        }
    }

out:
    if (ret != 0) {
        util_free_array(refs);
        refs = NULL;
    }
    util_free_array(lines);
    lines = NULL;

    return refs;
}

static char **get_refs_from_output(const char *output)
{
    char *tmp_output = NULL;
    char **refs = NULL;

    if (output == NULL) {
        ERROR("Failed to load image because can not get output");
        isulad_set_error_message("Failed to load image because can not get output");
        return NULL;
    }

    if (strnlen(output, (size_t)(g_output_max_size + 1)) > (size_t)g_output_max_size) {
        ERROR("Failed to load image because stdoutput exceeded max size");
        isulad_set_error_message("Failed to load image because stdoutput exceeded max size");
        return NULL;
    }

    /* get_refs_from_output will modify outmsg, get a copy to do this because
       we want to print original output if get reference failed. */
    tmp_output = util_strdup_s(output);
    refs = get_refs(tmp_output);
    if (refs == NULL) {
        ERROR("Failed to load image because cann't get image reference from output."
              "stdout buffer is [%s]", output);
        isulad_set_error_message("Failed to load image because cann't get image reference from output");
        goto out;
    }

out:
    free(tmp_output);

    return refs;
}

static int generate_isula_load_request(const char *file, const char *tag, struct isula_load_request **ireq)
{
    struct isula_load_request *tmp_req = NULL;

    tmp_req = (struct isula_load_request *)util_common_calloc_s(sizeof(struct isula_load_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    tmp_req->file = util_strdup_s(file);
    tmp_req->tag = util_strdup_s(tag);

    *ireq = tmp_req;
    return 0;
}

static int is_valid_arguments(const char *file, const char *tag, char ***refs)
{
    if (file == NULL) {
        isulad_set_error_message("Load image requires input file path");
        return -1;
    }
    if (tag != NULL && !util_valid_image_name(tag)) {
        isulad_try_set_error_message("Invalid tag:%s", tag);
        return -1;
    }

    if (refs == NULL) {
        ERROR("Refs is null");
        return -1;
    }

    return 0;
}

int isula_image_load(const char *file, const char *tag, char ***refs)
{
    int ret = -1;
    struct isula_load_request *ireq = NULL;
    struct isula_load_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    if (is_valid_arguments(file, tag, refs) != 0) {
        return -1;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->load == NULL) {
        ERROR("Umimplement load operator");
        return -1;
    }

    ret = generate_isula_load_request(file, tag, &ireq);
    if (ret != 0) {
        goto out;
    }

    iresp = (struct isula_load_response *)util_common_calloc_s(sizeof(struct isula_load_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    ret = im_ops->load(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Load image %s failed: %s", file, iresp->errmsg);
        isulad_set_error_message("Load image %s failed: %s", file, iresp->errmsg);
        goto out;
    }
    *refs = get_refs_from_output(iresp->outmsg);
    if (*refs == NULL) {
        ret = -1;
        goto out;
    }

out:
    free_isula_load_request(ireq);
    free_isula_load_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
