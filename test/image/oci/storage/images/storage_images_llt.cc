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
#include "image_store.h"
#include "imagetool_images_list.h"
#include "utils.h"
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

/********************************test data 1: image.json**************************************
  {
  "id": "39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10",
  "digest": "sha256:94192fe835d92cba5513297aad1cbcb32c9af455fb575e926ee5ec683a95e586",
  "names": [
  "rnd-dockerhub.huawei.com/official/centos:latest"
  ],
  "layer": "edd34c086208711c693a7b7a3ade23e24e6170ae24d8d2dab7c4f3efca61d509",
  "metadata": "{}",
  "big-data-names": [
  "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10",
  "manifest"
  ],
  "big-data-sizes": {
  "manifest": 741,
  "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10": 2235
  },
  "big-data-digests": {
  "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10": "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10",
  "manifest": "sha256:94192fe835d92cba5513297aad1cbcb32c9af455fb575e926ee5ec683a95e586"
  },
  "created": "2017-07-10T12:46:57.770791248Z",
  "Loaded": "2020-03-16T03:46:12.172621513Z"
  }
 ******************************************************************************************/

/********************************test data 2: image.json**************************************
  {
  "id": "e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b",
  "digest": "sha256:64da743694ece2ca88df34bf4c5378fdfc44a1a5b50478722e2ff98b82e4a5c9",
  "names": [
  "rnd-dockerhub.huawei.com/official/busybox:latest"
  ],
  "layer": "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a",
  "metadata": "{}",
  "big-data-names": [
  "sha256:e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b",
  "manifest"
  ],
  "big-data-sizes": {
  "sha256:e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b": 1497,
  "manifest": 527
  },
  "big-data-digests": {
  "sha256:e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b": "sha256:e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b",
  "manifest": "sha256:64da743694ece2ca88df34bf4c5378fdfc44a1a5b50478722e2ff98b82e4a5c9"
  },
  "created": "2019-06-15T00:19:54.402459069Z",
  "Loaded": "2020-03-16T03:46:17.439778957Z"
  }
 ******************************************************************************************/

class StorageImagesUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        struct storage_module_init_options opts;
        std::string dir = GetDirectory() + "/data";

        ASSERT_STRNE(cleanpath(dir.c_str(), real_path, sizeof(real_path)), nullptr);
        opts.storage_root = strdup(real_path);
        opts.driver_name = strdup("overlay");
        ASSERT_EQ(image_store_init(&opts), 0);
        free(opts.storage_root);
        free(opts.driver_name);
    }

    void TearDown() override
    {
    }

    std::vector<std::string> ids { "39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10",
        "e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b" };
    char real_path[PATH_MAX] = { 0x00 };
};

/*typedef struct {
    char *id;

    char **repo_tags;
    size_t repo_tags_len;

    char **repo_digests;
    size_t repo_digests_len;

    uint64_t size;

    char *created;

    char *loaded;

    imagetool_image_uid *uid;

    char *username;

    oci_image_spec *spec;

    defs_health_check *healthcheck;

}
imagetool_image;*/

TEST_F(StorageImagesUnitTest, test_images_load)
{
    auto image = image_store_get_image(ids.at(0).c_str());
    ASSERT_NE(image, nullptr);
    /*ASSERT_STREQ(image->digest, "sha256:94192fe835d92cba5513297aad1cbcb32c9af455fb575e926ee5ec683a95e586");
    ASSERT_EQ(image->names_len, 1);
    ASSERT_STREQ(image->names[0], "rnd-dockerhub.huawei.com/official/centos:latest");
    ASSERT_STREQ(image->layer, "edd34c086208711c693a7b7a3ade23e24e6170ae24d8d2dab7c4f3efca61d509");
    ASSERT_STREQ(image->metadata, "{}");
    ASSERT_EQ(image->big_data_names_len, 2);
    ASSERT_STREQ(image->big_data_names[0], "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10");
    ASSERT_STREQ(image->big_data_names[1], "manifest");
    ASSERT_EQ(image->big_data_sizes->len, 2);
    ASSERT_STREQ(image->big_data_sizes->keys[0], "manifest");
    ASSERT_EQ(image->big_data_sizes->values[0], 741);
    ASSERT_STREQ(image->big_data_sizes->keys[1],
                 "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10");
    ASSERT_EQ(image->big_data_sizes->values[1], 2235);
    ASSERT_EQ(image->big_data_digests->len, 2);
    ASSERT_STREQ(image->big_data_digests->keys[0],
                 "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10");
    ASSERT_STREQ(image->big_data_digests->values[0],
                 "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10");
    ASSERT_STREQ(image->big_data_digests->keys[1], "manifest");
    ASSERT_STREQ(image->big_data_digests->values[1],
                 "sha256:94192fe835d92cba5513297aad1cbcb32c9af455fb575e926ee5ec683a95e586");
    ASSERT_STREQ(image->created, "2017-07-10T12:46:57.770791248Z");
    ASSERT_STREQ(image->loaded, "2020-03-16T03:46:12.172621513Z");*/

    ASSERT_STREQ(image->created, "2017-07-10T12:46:57.770791248Z");
    ASSERT_STREQ(image->loaded, "2020-03-16T03:46:12.172621513Z");
    ASSERT_EQ(image->healthcheck, nullptr);
    ASSERT_EQ(image->username, nullptr);
    ASSERT_EQ(image->size, 0);
    ASSERT_NE(image->spec, nullptr);
    ASSERT_NE(image->spec->config, nullptr);
    ASSERT_EQ(image->spec->config->env_len, 1);
    ASSERT_STREQ(image->spec->config->env[0], "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    ASSERT_EQ(image->spec->config->cmd_len, 1);
    ASSERT_STREQ(image->spec->config->cmd[0], "/bin/bash");

    /*image = image_store_get_image(ids.at(1).c_str());
    ASSERT_NE(image, nullptr);
    ASSERT_STREQ(image->digest, "sha256:64da743694ece2ca88df34bf4c5378fdfc44a1a5b50478722e2ff98b82e4a5c9");
    ASSERT_EQ(image->names_len, 1);
    ASSERT_STREQ(image->names[0], "rnd-dockerhub.huawei.com/official/busybox:latest");
    ASSERT_STREQ(image->layer, "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a");
    ASSERT_STREQ(image->metadata, "{}");
    ASSERT_EQ(image->big_data_names_len, 2);
    ASSERT_STREQ(image->big_data_names[0], "sha256:e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b");
    ASSERT_STREQ(image->big_data_names[1], "manifest");
    ASSERT_EQ(image->big_data_sizes->len, 2);
    ASSERT_STREQ(image->big_data_sizes->keys[0],
                 "sha256:e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b");
    ASSERT_EQ(image->big_data_sizes->values[0], 1497);
    ASSERT_STREQ(image->big_data_sizes->keys[1], "manifest");
    ASSERT_EQ(image->big_data_sizes->values[1], 527);
    ASSERT_EQ(image->big_data_digests->len, 2);
    ASSERT_STREQ(image->big_data_digests->keys[0],
                 "sha256:e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b");
    ASSERT_STREQ(image->big_data_digests->values[0],
                 "sha256:e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b");
    ASSERT_STREQ(image->big_data_digests->keys[1], "manifest");
    ASSERT_STREQ(image->big_data_digests->values[1],
                 "sha256:64da743694ece2ca88df34bf4c5378fdfc44a1a5b50478722e2ff98b82e4a5c9");
    ASSERT_STREQ(image->created, "2019-06-15T00:19:54.402459069Z");
    ASSERT_STREQ(image->loaded, "2020-03-16T03:46:17.439778957Z");*/
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
TEST_F(StorageImagesUnitTest, test_image_store_create)
{
    std::string id { "50551ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10" };
    const char *names[2] = { "hello_world:latest", "euleros:3.1" };
    std::string layer { "9994458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a" };
    std::string metadata { "{}" };
    types_timestamp_t time { 0x00 };
    // std::string searchableDigest {"manifest"};
    auto created_image = image_store_create(id.c_str(), names, sizeof(names) / sizeof(names[0]), layer.c_str(),
                                            metadata.c_str(), &time, nullptr);
    ASSERT_NE(created_image, nullptr);

    auto image = image_store_get_image(id.c_str());
    ASSERT_NE(image, nullptr);
    // ASSERT_STREQ(image->digest, "manifest");
    /*ASSERT_EQ(image->names_len, 2);
    ASSERT_STREQ(image->names[0], "euleros:3.1");
    ASSERT_STREQ(image->names[1], "hello_world:latest");
    ASSERT_STREQ(image->layer, "9994458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a");
    ASSERT_STREQ(image->metadata, "{}");*/
    ASSERT_NE(image->created, nullptr);
    ASSERT_NE(image->loaded, nullptr);

    ASSERT_EQ(image_store_delete(id.c_str()), 0);
    ASSERT_EQ(image_store_get_image(id.c_str()), nullptr);
    ASSERT_FALSE(dirExists((std::string(real_path) + "/" + id).c_str()));
}

TEST_F(StorageImagesUnitTest, test_image_store_lookup)
{
    std::string id { "e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b" };
    std::string name { "rnd-dockerhub.huawei.com/official/busybox:latest" };
    std::string truncatedId { "e4db68de4ff27" };
    std::string incorrectId { "4db68de4ff27" };

    ASSERT_STREQ(image_store_lookup(name.c_str()), id.c_str());
    ASSERT_STREQ(image_store_lookup(truncatedId.c_str()), id.c_str());
    ASSERT_EQ(image_store_lookup(incorrectId.c_str()), nullptr);
}

TEST_F(StorageImagesUnitTest, test_image_store_exists)
{
    std::string id { "39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10" };
    std::string name { "rnd-dockerhub.huawei.com/official/centos:latest" };
    std::string truncatedId { "398" };
    std::string incorrectId { "ff67da98ab8540d713209" };

    ASSERT_TRUE(image_store_exists(name.c_str()));
    ASSERT_TRUE(image_store_exists(truncatedId.c_str()));
    ASSERT_FALSE(image_store_exists(incorrectId.c_str()));
}

TEST_F(StorageImagesUnitTest, test_image_store_metadata)
{
    std::string incorrectId { "ff67da98ab8540d713209" };

    for (auto elem : ids) {
        ASSERT_STREQ(image_store_metadata(elem.c_str()), "{}");
    }

    ASSERT_EQ(image_store_metadata(incorrectId.c_str()), nullptr);
}

/********************************test data 1: image.json**************************************
  {
  "id": "39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10",
  "digest": "sha256:94192fe835d92cba5513297aad1cbcb32c9af455fb575e926ee5ec683a95e586",
  "names": [
  "rnd-dockerhub.huawei.com/official/centos:latest"
  ],
  "layer": "edd34c086208711c693a7b7a3ade23e24e6170ae24d8d2dab7c4f3efca61d509",
  "metadata": "{}",
  "big-data-names": [
  "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10",
  "manifest"
  ],
  "big-data-sizes": {
  "manifest": 741,
  "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10": 2235
  },
  "big-data-digests": {
  "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10": "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10",
  "manifest": "sha256:94192fe835d92cba5513297aad1cbcb32c9af455fb575e926ee5ec683a95e586"
  },
  "created": "2017-07-10T12:46:57.770791248Z",
  "Loaded": "2020-03-16T03:46:12.172621513Z"
  }
 ******************************************************************************************/
TEST_F(StorageImagesUnitTest, test_image_store_get_all_images)
{
    imagetool_images_list *images_list = NULL;

    images_list = (imagetool_images_list *)util_common_calloc_s(sizeof(imagetool_images_list));
    ASSERT_NE(images_list, nullptr);
    ASSERT_EQ(image_store_get_all_images(images_list), 0);
    ASSERT_EQ(images_list->images_len, 2);
    for (size_t i {}; i < images_list->images_len; i++) {
        ASSERT_NE(find(ids.begin(), ids.end(), std::string(images_list->images[i]->id)), ids.end());

        auto img = images_list->images[i];
        if (std::string(images_list->images[i]->id) == ids.at(0)) {
            ASSERT_STREQ(img->created, "2017-07-10T12:46:57.770791248Z");
            ASSERT_STREQ(img->loaded, "2020-03-16T03:46:12.172621513Z");
            ASSERT_EQ(img->healthcheck, nullptr);
            ASSERT_EQ(img->username, nullptr);
            // TODO : verfiy image size
            ASSERT_EQ(img->size, 0);
            ASSERT_EQ(img->spec->config->env_len, 1);
            ASSERT_STREQ(img->spec->config->env[0], "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
            ASSERT_EQ(img->spec->config->cmd_len, 1);
            ASSERT_STREQ(img->spec->config->cmd[0], "/bin/bash");
        }

    }

    free_imagetool_images_list(images_list);
}

TEST_F(StorageImagesUnitTest, test_image_store_delete)
{
    std::string backup = std::string(real_path) + ".bak";
    std::string command = "cp -r " + std::string(real_path) + " " + backup;
    std::string rm_command = "rm -rf " + std::string(real_path);
    std::string undo_command = "mv " + backup + " " + std::string(real_path);
    ASSERT_EQ(system(command.c_str()), 0);

    for (auto elem : ids) {
        ASSERT_TRUE(image_store_exists(elem.c_str()));
        ASSERT_TRUE(dirExists((std::string(real_path) + "/overlay-images/" + elem).c_str()));
        ASSERT_EQ(image_store_delete(elem.c_str()), 0);
        ASSERT_FALSE(image_store_exists(elem.c_str()));
        ASSERT_FALSE(dirExists((std::string(real_path) + "/overlay-images/" + elem).c_str()));
    }

    ASSERT_EQ(system(rm_command.c_str()), 0);
    ASSERT_EQ(system(undo_command.c_str()), 0);
}

TEST_F(StorageImagesUnitTest, test_image_store_wipe)
{
    std::string backup = std::string(real_path) + ".bak";
    std::string command = "cp -r " + std::string(real_path) + " " + backup;
    std::string rm_command = "rm -rf " + std::string(real_path);
    std::string undo_command = "mv " + backup + " " + std::string(real_path);
    ASSERT_EQ(system(command.c_str()), 0);

    for (auto elem : ids) {
        ASSERT_TRUE(image_store_exists(elem.c_str()));
        ASSERT_TRUE(dirExists((std::string(real_path) + "/overlay-images/" + elem).c_str()));
    }

    ASSERT_EQ(image_store_wipe(), 0);

    for (auto elem : ids) {
        ASSERT_FALSE(image_store_exists(elem.c_str()));
        ASSERT_FALSE(dirExists((std::string(real_path) + "/overlay-images/" + elem).c_str()));
    }

    ASSERT_EQ(system(rm_command.c_str()), 0);
    ASSERT_EQ(system(undo_command.c_str()), 0);
}
