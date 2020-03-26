/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: liuhao
 * Create: 2020-03-26
 * Description: provide layer store functions
 ******************************************************************************/

#include "layer.h"

#include "constants.h"
#include "storage_mount_point.h"
#include "util_atomic.h"
#include "utils.h"
#include "log.h"

static layer_t *new_layer(const char *layer_path, storage_layer *slayer, const char *mount_point_path, storage_mount_point *smount_point)
{
    layer_t *result = NULL;
    int nret = 0;

    if (slayer == NULL) {
        ERROR("Empty storage layer");
        goto err_out;
    }

    result = (layer_t *)util_smart_calloc_s(sizeof(layer_t), 1);
    if (result == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    atomic_int_set(&result->refcnt, 1);

    nret = pthread_mutex_init(&(result->mutex), NULL);
    if (nret != 0) {
        ERROR("Failed to init mutex of layer");
        goto err_out;
    }
    result->init_mutex = true;

    result->layer_json_path = util_strdup_s(layer_path);
    result->mount_point_json_path = util_strdup_s(mount_point_path);
    result->slayer = slayer;
    result->smount_point = smount_point;

    return result;
err_out:
    free_layer_t(result);
    return NULL;
}

void layer_ref_inc(layer_t *layer)
{
    if (layer == NULL) {
        return;
    }
    atomic_int_inc(&layer->refcnt);
}

void layer_ref_dec(layer_t *layer)
{
    bool is_zero = false;

    if (layer == NULL) {
        return;
    }

    is_zero = atomic_int_dec_test(&layer->refcnt);
    if (!is_zero) {
        return;
    }

    free_layer_t(layer);
}

layer_t *load_layer(const char *fname, const char *mountpoint_fname)
{
    parser_error err = NULL;
    layer_t *result = NULL;
    storage_layer *slayer = NULL;
    storage_mount_point *smount_point = NULL;

    if (fname == NULL) {
        return result;
    }
    slayer = storage_layer_parse_file(fname, NULL, &err);
    if (slayer == NULL) {
        ERROR("Parse layer failed: %s", err);
        goto free_out;
    }
    if (mountpoint_fname != NULL) {
        smount_point = storage_mount_point_parse_file(mountpoint_fname, NULL, &err);
        if (smount_point == NULL) {
            ERROR("Parse mount point failed: %s", err);
            goto free_out;
        }
    }
    result = new_layer(fname, slayer, mountpoint_fname, smount_point);
    if (result == NULL) {
        goto free_out;
    }

    return result;
free_out:
    free(err);
    free_storage_mount_point(smount_point);
    free_storage_layer(slayer);
    return NULL;
}

int save_layer(layer_t *layer)
{
    char *jstr = NULL;
    parser_error jerr;
    int ret = -1;

    if (layer == NULL || layer->layer_json_path == NULL || layer->slayer == NULL) {
        return ret;
    }

    jstr = storage_layer_generate_json(layer->slayer, NULL, &jerr);
    if (jstr == NULL) {
        ERROR("Marsh layer failed: %s", jerr);
        goto out;
    }
    //TODO: use atom write file
    ret = util_write_file(layer->layer_json_path, jstr, strlen(jstr), SECURE_CONFIG_FILE_MODE);

out:
    free(jstr);
    free(jerr);
    return ret;
}

int save_mount_point(layer_t *layer)
{
    char *jstr = NULL;
    parser_error jerr;
    int ret = -1;

    if (layer == NULL || layer->mount_point_json_path == NULL || layer->smount_point == NULL) {
        return ret;
    }

    jstr = storage_mount_point_generate_json(layer->smount_point, NULL, &jerr);
    if (jstr == NULL) {
        ERROR("Marsh mount point failed: %s", jerr);
        goto out;
    }
    //TODO: use atom write file
    ret = util_write_file(layer->mount_point_json_path, jstr, strlen(jstr), SECURE_CONFIG_FILE_MODE);

out:
    free(jstr);
    free(jerr);
    return ret;
}

void free_layer_t(layer_t *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free_storage_mount_point(ptr->smount_point);
    ptr->smount_point = NULL;
    free_storage_layer(ptr->slayer);
    ptr->slayer = NULL;
    if (ptr->init_mutex) {
        pthread_mutex_destroy(&ptr->mutex);
    }
    free(ptr->layer_json_path);
    ptr->layer_json_path = NULL;
    free(ptr->mount_point_json_path);
    ptr->mount_point_json_path = NULL;
    free(ptr);
}

