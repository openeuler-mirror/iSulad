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
* Author: gaohuatao
* Create: 2020-05-14
* Description: isula load operator implement
*******************************************************************************/
#ifndef __IMAGE_OCI_LOAD_H
#define __IMAGE_OCI_LOAD_H

#include "image.h"
#include "isula_libutils/image_manifest_items.h"
#include "isula_libutils/oci_image_manifest.h"
#include "isula_libutils/oci_image_spec.h"
#include "isula_libutils/json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // uncompressed_digest
    char *diff_id;
    // compressed digest
    char *compressed_digest;
    char *chain_id;
    char *fpath;
} load_layer_blob_t;

typedef struct {
    load_layer_blob_t **layers;
    size_t layers_len;
    char **repo_tags;
    size_t repo_tags_len;
    char *config_fpath;
    char *im_id;
    char *im_digest;
    char *manifest_fpath;
    char *manifest_digest;
    types_timestamp_t create_time;
    oci_image_manifest *manifest;
} load_image_t;

int oci_do_load(const im_load_request *request);

#ifdef __cplusplus
}
#endif

#endif
