/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wujing
 * Create: 2020-03-30
 * Description: provide oci storage images unit test
 ******************************************************************************/
#include "layer_store.h"
#include <cstddef>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <tuple>
#include <fstream>
#include <climits>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gtest/gtest.h>
#include "path.h"
#include "storage.h"
#include "layer.h"

std::string GetDirectory()
{
    char abs_path[PATH_MAX];
    int ret = readlink("/proc/self/exe", abs_path, sizeof(abs_path));
    if (ret < 0 || (size_t)ret >= sizeof(abs_path)) {
        return "";
    }

    for (int i { ret }; i >= 0; --i) {
        if (abs_path[i] == '/') {
            abs_path[i + 1] = '\0';
            break;
        }
    }

    return static_cast<std::string>(abs_path);
}

bool dirExists(const char *path)
{
    DIR *dp = NULL;
    if ((dp = opendir(path)) == NULL) {
        return false;
    }

    closedir(dp);
    return true;
}

/********************************test data 1: container layer json**************************************
{
  "id": "ac86325a0e6384e251f2f4418d7b36321ad6811f9ba8a3dc87e13d634b0ec1d1",
  "names": [
    "689feccc14f14112b43b1fbf7dc14c3426e4fdd6e2bff462ec70b9f6ee4b3fae-layer"
  ],
  "parent": "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a",
  "created": "2020-04-29T07:34:27.076073345Z"
}

mount info
{
    "id": "ac86325a0e6384e251f2f4418d7b36321ad6811f9ba8a3dc87e13d634b0ec1d1",
    "path": "/var/lib/isulad/storage/overlay/ac86325a0e6384e251f2f4418d7b36321ad6811f9ba8a3dc87e13d634b0ec1d1/merged",
    "count": 1
}
 ******************************************************************************************/

/********************************test data 2: busybox image layer json**************************************
{
  "id": "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a",
  "created": "2020-04-16T12:08:52.304153815Z",
  "compressed-diff-digest": "sha256:8f52abd3da461b2c0c11fda7a1b53413f1a92320eb96525ddf92c0b5cde781ad",
  "compressed-size": 740169,
  "diff-digest": "sha256:6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a",
  "diff-size": 1441280,
  "compression": 2
}
 ******************************************************************************************/

class StorageImagesUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        struct storage_module_init_options opts = {0};
        std::string dir = GetDirectory() + "/data";
        std::string rundir = GetDirectory() + "/data/run";

        ASSERT_STRNE(cleanpath(dir.c_str(), real_path, sizeof(real_path)), nullptr);
        opts.storage_root = strdup(real_path);
        ASSERT_STRNE(cleanpath(rundir.c_str(), real_run_path, sizeof(real_run_path)), nullptr);
        opts.storage_run_root = strdup(real_run_path);
        opts.driver_name = strdup("overlay");
        ASSERT_EQ(layer_store_init(&opts), 0);
        free(opts.storage_root);
        free(opts.driver_name);
    }

    void TearDown() override
    {
    }

    std::vector<std::string> ids { "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a",
        "ac86325a0e6384e251f2f4418d7b36321ad6811f9ba8a3dc87e13d634b0ec1d1" };
    char real_path[PATH_MAX] = { 0x00 };
    char real_run_path[PATH_MAX] = { 0x00 };
};

TEST_F(StorageImagesUnitTest, test_layers_load)
{
    size_t layers_len = 0;
    struct layer **layers = layer_store_list(&layers_len);

    ASSERT_EQ(layers_len, 2);

    // check layer 6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a
    ASSERT_NE(layers[0], nullptr);
    ASSERT_STREQ(layers[0]->id, "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a");
    ASSERT_EQ(layers[0]->parent, nullptr);
    ASSERT_STREQ(layers[0]->compressed_digest, "sha256:8f52abd3da461b2c0c11fda7a1b53413f1a92320eb96525ddf92c0b5cde781ad");
    ASSERT_EQ(layers[0]->compress_size, 740169);
    ASSERT_STREQ(layers[0]->uncompressed_digest, "sha256:6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a");
    ASSERT_EQ(layers[0]->uncompress_size, 1441280);

    // check layer ac86325a0e6384e251f2f4418d7b36321ad6811f9ba8a3dc87e13d634b0ec1d1
    ASSERT_NE(layers[1], nullptr);
    ASSERT_STREQ(layers[1]->id, "ac86325a0e6384e251f2f4418d7b36321ad6811f9ba8a3dc87e13d634b0ec1d1");
    ASSERT_STREQ(layers[1]->parent, "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a");
    ASSERT_EQ(layers[1]->mount_count, 1);
    ASSERT_STREQ(layers[1]->mount_point,
                 "/var/lib/isulad/storage/overlay/ac86325a0e6384e251f2f4418d7b36321ad6811f9ba8a3dc87e13d634b0ec1d1/merged");
}

/********************************test data *************************************************
{
    "id": "50551ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10",
    "digest": "manifest",
    "names": [
        "euleros:3.1",
        "hello_world:latest"
    ],
    "layer": "9994458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a",
    "metadata": "{}",
    "created": "2020-04-02T05:44:23.408951489-04:00",
    "loaded": "2020-04-02T05:44:23.408987703-04:00"
}
******************************************************************************************/
TEST_F(StorageImagesUnitTest, test_layer_store_create)
{
    std::string id { "d3b9337701b412d8235da15ae7653560ccc6cf042c18298214aa5543c38588f8" };
    std::string parent { "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a" };
    struct layer_opts opts = {
        .parent = strdup(parent.c_str()),
        .writable = true,
    };
    char *new_id = nullptr;

    auto created_layer = layer_store_create(id.c_str(), &opts, nullptr, &new_id);
    ASSERT_EQ(created_layer, 0);

    ASSERT_TRUE(layer_store_exists(id.c_str()));

    ASSERT_EQ(layer_store_delete(id.c_str()), 0);
    ASSERT_FALSE(layer_store_exists(id.c_str()));
    ASSERT_FALSE(dirExists((std::string(real_path) + "/" + id).c_str()));
}

TEST_F(StorageImagesUnitTest, test_layer_store_lookup)
{
    std::string id { "ac86325a0e6384e251f2f4418d7b36321ad6811f9ba8a3dc87e13d634b0ec1d1" };
    std::string name { "689feccc14f14112b43b1fbf7dc14c3426e4fdd6e2bff462ec70b9f6ee4b3fae-layer" };
    std::string incorrectId { "4db68de4ff27" };
    struct layer *l = NULL;

    l = layer_store_lookup(name.c_str());
    ASSERT_NE(l, nullptr);
    ASSERT_STREQ(l->id, id.c_str());
    free_layer(l);
    l = layer_store_lookup(id.c_str());
    ASSERT_NE(l, nullptr);
    ASSERT_STREQ(l->id, id.c_str());
    free_layer(l);
    l = layer_store_lookup(incorrectId.c_str());
    ASSERT_EQ(l->id, nullptr);
    free_layer(l);
}

TEST_F(StorageImagesUnitTest, test_layer_store_exists)
{
    std::string id { "ac86325a0e6384e251f2f4418d7b36321ad6811f9ba8a3dc87e13d634b0ec1d1" };
    std::string name { "689feccc14f14112b43b1fbf7dc14c3426e4fdd6e2bff462ec70b9f6ee4b3fae-layer" };
    std::string incorrectId { "4db68de4ff27" };

    ASSERT_TRUE(layer_store_exists(name.c_str()));
    ASSERT_TRUE(layer_store_exists(id.c_str()));
    ASSERT_FALSE(layer_store_exists(incorrectId.c_str()));
}

TEST_F(StorageImagesUnitTest, test_layer_store_list)
{
    struct layer **layers = NULL;
    size_t len = 0;

    layers = layer_store_list(&len);
    ASSERT_EQ(len, 2);

    for (size_t i {}; i < len; i++) {
        ASSERT_NE(find(ids.begin(), ids.end(), std::string(layers[i]->id)), ids.end());
    }

    for (size_t i {}; i < len; i++) {
        free_layer(layers[i]);
        layers[i] = NULL;
    }
    free(layers);
}

TEST_F(StorageImagesUnitTest, test_layer_store_by_compress_digest)
{
    struct layer **layers = NULL;
    size_t len = 0;
    std::string compress { "sha256:8f52abd3da461b2c0c11fda7a1b53413f1a92320eb96525ddf92c0b5cde781ad" };
    std::string id { "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a" };

    layers = layer_store_by_compress_digest(compress.c_str(), &len);
    ASSERT_EQ(len, 1);

    ASSERT_STREQ(layers[0]->id, id.c_str());
    ASSERT_STREQ(layers[0]->compressed_digest, compress.c_str());
    ASSERT_EQ(layers[0]->compress_size, 740169);

    for (size_t i {}; i < len; i++) {
        free_layer(layers[i]);
        layers[i] = NULL;
    }
    free(layers);
}

TEST_F(StorageImagesUnitTest, test_layer_store_by_uncompress_digest)
{
    struct layer **layers = NULL;
    size_t len = 0;
    std::string uncompress { "sha256:6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a" };
    std::string id { "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a" };

    layers = layer_store_by_uncompress_digest(uncompress.c_str(), &len);
    ASSERT_EQ(len, 1);

    ASSERT_STREQ(layers[0]->id, id.c_str());
    ASSERT_STREQ(layers[0]->uncompressed_digest, uncompress.c_str());
    ASSERT_EQ(layers[0]->uncompress_size, 1441280);

    for (size_t i {}; i < len; i++) {
        free_layer(layers[i]);
        layers[i] = NULL;
    }
    free(layers);
}

