/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: WuJing
 * Create: 2020-04-26
 * Description: provide oci image storage mock
 ******************************************************************************/

#include "storage_mock.h"

namespace {
MockStorage *g_storage_mock = NULL;
}

void MockStorage_SetMock(MockStorage *mock)
{
    g_storage_mock = mock;
}

struct layer_list *storage_layers_get_by_compress_digest(const char *digest)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageLayersGetByCompressDigest(digest);
    }

    return NULL;
}

void free_layer_list(struct layer_list *ptr)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->FreeLayerList(ptr);
    }
}

int storage_img_create(const char *id, const char *parent_id, const char *metadata,
                       struct storage_img_create_options *opts)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageImgCreate(id, parent_id, metadata, opts);
    }
    return -1;
}

imagetool_image * storage_img_get(const char *img_id)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageImgGet(img_id);
    }
    return NULL;
}

int storage_img_set_big_data(const char *img_id, const char *key, const char *val)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageImgSetBigData(img_id, key, val);
    }
    return -1;
}

int storage_img_add_name(const char *img_id, const char *img_name)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageImgAddName(img_id, img_name);
    }
    return -1;
}

int storage_img_delete(const char *img_id, bool commit)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageImgDelete(img_id, commit);
    }
    return -1;
}

int storage_img_set_loaded_time(const char *img_id, types_timestamp_t *loaded_time)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageImgSetLoadedTime(img_id, loaded_time);
    }
    return -1;
}

int storage_img_set_image_size(const char *image_id)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageImgSetImageSize(image_id);
    }
    return -1;
}

char * storage_get_img_top_layer(const char *id)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageGetImgTopLayer(id);
    }
    return NULL;
}

int storage_layer_create(const char *layer_id, storage_layer_create_opts_t *opts)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageLayerCreate(layer_id, opts);
    }
    return -1;
}

struct layer * storage_layer_get(const char *layer_id)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageLayerGet(layer_id);
    }
    return NULL;
}

int storage_layer_try_repair_lowers(const char *layer_id, const char *last_layer_id)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageLayerTryRepairLowers(layer_id, last_layer_id);
    }
    return -1;
}

void free_layer(struct layer *l)
{
    if (g_storage_mock != NULL) {
        g_storage_mock->FreeLayer(l);
    }
    return;
}

int storage_inc_hold_refs(const char *layer_id)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageIncHoldRefs(layer_id);
    }
    return -1;
}

int storage_dec_hold_refs(const char *layer_id)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageIncHoldRefs(layer_id);
    }
    return -1;
}

char *storage_rootfs_mount(const char *container_id)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageRootfsMount(container_id);
    }
    return NULL;
}

int storage_rootfs_umount(const char *container_id, bool force)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageRootfsUmount(container_id, force);
    }
    return -1;
}

container_inspect_graph_driver *storage_get_metadata_by_container_id(const char *id)
{
    if (g_storage_mock != NULL) {
        return g_storage_mock->StorageGetMetadataByContainerId(id);
    }
    return NULL;
}
