/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-03-30
 * Description: provide oci storage images unit test
 ******************************************************************************/
#include "image_store.h"
#include "isula_libutils/imagetool_image.h"
#include "utils_array.h"
#include <cstring>
#include <iostream>
#include <algorithm>
#include <tuple>
#include <fstream>
#include <string>
#include <fstream>
#include <streambuf>
#include <climits>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gtest/gtest.h>
#include "utils.h"
#include "path.h"

#include "storage.h"
#include "isula_libutils/imagetool_images_list.h"

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
  "imagehub.isulad.com/official/centos:latest"
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
  "imagehub.isulad.com/official/busybox:latest"
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
        ASSERT_STRNE(cleanpath(dir.c_str(), store_real_path, sizeof(store_real_path)), nullptr);

        opts.storage_root = strdup(store_real_path);
        opts.driver_name = strdup("overlay");
        ASSERT_EQ(image_store_init(&opts), 0);
        free(opts.storage_root);
        free(opts.driver_name);
    }

    void TearDown() override
    {
        image_store_free();
    }

    std::vector<std::string> ids { "39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10",
        "e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b" };
    char store_real_path[PATH_MAX] = { 0x00 };
};

TEST_F(StorageImagesUnitTest, test_images_load)
{
    auto image = image_store_get_image(ids.at(0).c_str());
    ASSERT_NE(image, nullptr);

    ASSERT_STREQ(image->created, "2017-07-10T12:46:57.770791248Z");
    ASSERT_STREQ(image->loaded, "2020-03-16T03:46:12.172621513Z");
    ASSERT_EQ(image->healthcheck, nullptr);
    ASSERT_EQ(image->username, nullptr);
    ASSERT_EQ(image->size, 0);
    ASSERT_EQ(image->repo_tags_len, 1);
    ASSERT_STREQ(image->repo_tags[0], "imagehub.isulad.com/official/centos:latest");
    ASSERT_EQ(image->repo_digests_len, 1);
    ASSERT_STREQ(
        image->repo_digests[0],
        "imagehub.isulad.com/official/centos@sha256:94192fe835d92cba5513297aad1cbcb32c9af455fb575e926ee5ec683a95e586");
    ASSERT_NE(image->spec, nullptr);
    ASSERT_NE(image->spec->config, nullptr);
    ASSERT_EQ(image->spec->config->env_len, 1);
    ASSERT_STREQ(image->spec->config->env[0], "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    ASSERT_EQ(image->spec->config->cmd_len, 1);
    ASSERT_STREQ(image->spec->config->cmd[0], "/bin/bash");

    free_imagetool_image(image);

    char **names { nullptr };
    size_t names_len { 0 };
    ASSERT_EQ(image_store_big_data_names(ids.at(0).c_str(), &names, &names_len), 0);
    ASSERT_EQ(names_len, 2);
    ASSERT_STREQ(names[0], "sha256:39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10");
    ASSERT_STREQ(names[1], "manifest");

    ASSERT_EQ(image_store_big_data_size(ids.at(0).c_str(), names[0]), 2235);
    ASSERT_EQ(image_store_big_data_size(ids.at(0).c_str(), names[1]), 741);
    for (size_t i {}; i < names_len; ++i) {
        free(names[i]);
        names[i] = nullptr;
    }
    free(names);
}

/********************************test data *************************************************
{
  "id": "ffc8ef7968a2acb7545006bed022001addaa262c0f760883146c4a4fae54e689",
  "digest": "sha256:fdb7b1fccaaa535cb8211a194dd6314acc643f3a36d1a7d2b79c299a9173fa7e",
  "names": [
    "docker.io/library/health_check:latest"
  ],
  "layer": "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a",
  "metadata": "{}",
  "big-data-names": [
    "sha256:ffc8ef7968a2acb7545006bed022001addaa262c0f760883146c4a4fae54e689",
    "manifest"
  ],
  "big-data-sizes": {
    "sha256:ffc8ef7968a2acb7545006bed022001addaa262c0f760883146c4a4fae54e689": 2270,
    "manifest": 428
  },
  "big-data-digests": {
    "sha256:ffc8ef7968a2acb7545006bed022001addaa262c0f760883146c4a4fae54e689": "sha256:ffc8ef7968a2acb7545006bed022001addaa262c0f760883146c4a4fae54e689",
    "manifest": "sha256:fdb7b1fccaaa535cb8211a194dd6314acc643f3a36d1a7d2b79c299a9173fa7e"
  },
  "created": "2020-03-30T08:02:50.586247435Z",
  "Loaded": "2020-04-29T09:06:29.385966253Z"
}
******************************************************************************************/
TEST_F(StorageImagesUnitTest, test_image_store_create)
{
    std::string id { "ffc8ef7968a2acb7545006bed022001addaa262c0f760883146c4a4fae54e689" };
    const char *names[] = { "docker.io/library/health_check:latest" };
    std::string layer { "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a" };
    std::string metadata { "{}" };
    types_timestamp_t time { 0x00 };
    char *created_image = image_store_create(id.c_str(), names, sizeof(names) / sizeof(names[0]), layer.c_str(),
                                             metadata.c_str(), &time, nullptr);
    std::cout << created_image << std::endl;
    ASSERT_STREQ(created_image, id.c_str());

    char real_path[PATH_MAX] = { 0x00 };
    std::string config_file =
        GetDirectory() +
        "/data/resources/ffc8ef7968a2acb7545006bed022001addaa262c0f760883146c4a4fae54e689/"
        "=c2hhMjU2OmZmYzhlZjc5NjhhMmFjYjc1NDUwMDZiZWQwMjIwMDFhZGRhYTI2MmMwZjc2MDg4MzE0NmM0YTRmYWU1NGU2ODk=";
    ASSERT_STRNE(cleanpath(config_file.c_str(), real_path, sizeof(real_path)), "manifest");

    std::ifstream t(real_path);
    std::string buffer((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());

    std::cout << "config v2 :" << std::endl;
    std::cout << buffer << std::endl;

    std::string key = "sha256:" + std::string(created_image);
    ASSERT_EQ(image_store_set_big_data(created_image, key.c_str(), buffer.c_str()), 0);

    std::string img_store_path = std::string(store_real_path) + "/overlay-images/";
    ASSERT_TRUE(dirExists((img_store_path + id).c_str()));
    std::string cp_command = "cp " + std::string(store_real_path) + "/resources/" + id + "/manifest "
                             + img_store_path + id + "/";
    std::cout << cp_command << std::endl;

    ASSERT_EQ(system(cp_command.c_str()), 0);
    ASSERT_EQ(image_store_big_data_size(id.c_str(), "manifest"), 428);

    std::string manifest_file = GetDirectory() +
                                "/data/resources/ffc8ef7968a2acb7545006bed022001addaa262c0f760883146c4a4fae54e689/" +
                                "manifest";
    ASSERT_STRNE(cleanpath(manifest_file.c_str(), real_path, sizeof(real_path)), nullptr);

    std::ifstream manifest_stream(real_path);
    std::string manifest_content((std::istreambuf_iterator<char>(manifest_stream)), std::istreambuf_iterator<char>());

    std::cout << "manifest :" << std::endl;
    std::cout << manifest_content << std::endl;

    char *data = image_store_big_data(id.c_str(), "manifest");
    ASSERT_STREQ(data, manifest_content.c_str());
    free(data);

    auto image = image_store_get_image(id.c_str());
    ASSERT_NE(image, nullptr);
    ASSERT_NE(image->created, nullptr);
    ASSERT_NE(image->loaded, nullptr);
    ASSERT_NE(image->repo_tags, nullptr);
    ASSERT_EQ(image->repo_tags_len, 1);
    ASSERT_STREQ(image->repo_tags[0], "docker.io/library/health_check:latest");
    ASSERT_NE(image->username, nullptr);
    ASSERT_EQ(image->size, 0);
    ASSERT_EQ(image->spec->config->env_len, 1);
    ASSERT_STREQ(image->spec->config->env[0], "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    ASSERT_EQ(image->spec->config->cmd_len, 1);
    ASSERT_STREQ(image->spec->config->cmd[0], "sh");
    ASSERT_NE(image->healthcheck, nullptr);
    ASSERT_EQ(image->healthcheck->test_len, 2);
    ASSERT_STREQ(image->healthcheck->test[0], "CMD-SHELL");
    ASSERT_STREQ(image->healthcheck->test[1], "date >> /tmp/health_check || exit 1");
    ASSERT_EQ(image->healthcheck->interval, 3000000000);
    ASSERT_EQ(image->healthcheck->retries, 3);
    ASSERT_EQ(image->healthcheck->start_period, 1000000000);
    ASSERT_EQ(image->healthcheck->timeout, 3000000000);
    ASSERT_TRUE(image->healthcheck->exit_on_unhealthy);

    ASSERT_EQ(image->repo_digests_len, 1);

    ASSERT_STREQ(
        image->repo_digests[0],
        "docker.io/library/health_check@sha256:fdb7b1fccaaa535cb8211a194dd6314acc643f3a36d1a7d2b79c299a9173fa7e");

    free_imagetool_image(image);

    char *toplayer = NULL;
    ASSERT_STREQ((toplayer = image_store_top_layer(id.c_str())),
                 "6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a");
    free(toplayer);

    ASSERT_EQ(image_store_set_image_size(id.c_str(), 1000), 0);

    image = image_store_get_image(id.c_str());
    ASSERT_EQ(image->size, 1000);
    free_imagetool_image(image);

    ASSERT_EQ(image_store_add_name(id.c_str(), "docker.io/library/test:latest"), 0);
    image = image_store_get_image(id.c_str());
    ASSERT_EQ(image->repo_tags_len, 2);
    ASSERT_STREQ(image->repo_tags[0], "docker.io/library/health_check:latest");
    ASSERT_STREQ(image->repo_tags[1], "docker.io/library/test:latest");
    free_imagetool_image(image);

    char **img_names = NULL;
    img_names = (char **)util_common_calloc_s(2 * sizeof(char *));
    img_names[0] = util_strdup_s("busybox:latest");
    img_names[1] = util_strdup_s("centos:3.0");
    ASSERT_EQ(image_store_set_names(id.c_str(), (const char **)img_names, 2), 0);
    image = image_store_get_image(id.c_str());
    ASSERT_EQ(image->repo_tags_len, 2);
    ASSERT_STREQ(image->repo_tags[0], "busybox:latest");
    ASSERT_STREQ(image->repo_tags[1], "centos:3.0");
    util_free_array_by_len(img_names, 2);
    free_imagetool_image(image);

    ASSERT_EQ(image_store_set_metadata(id.c_str(), "{metadata}"), 0);
    char *manifest_val = NULL;
    ASSERT_STREQ((manifest_val = image_store_metadata(id.c_str())), "{metadata}");
    free(manifest_val);

    free(created_image);

    ASSERT_EQ(image_store_delete(id.c_str()), 0);
    ASSERT_EQ(image_store_get_image(id.c_str()), nullptr);
    ASSERT_FALSE(dirExists((img_store_path + id).c_str()));

    char *random_id = image_store_create(nullptr, names, sizeof(names) / sizeof(names[0]), layer.c_str(),
                                         metadata.c_str(), &time, nullptr);
    std::cout << random_id << std::endl;
    ASSERT_STRNE(random_id, nullptr);
    ASSERT_STREQ(image_store_lookup(random_id), random_id);
    ASSERT_TRUE(dirExists((img_store_path + std::string(random_id)).c_str()));

    cp_command = "cp " + std::string(store_real_path) + "/resources/" + id + "/manifest "
                 + img_store_path + std::string(random_id) +  "/";
    std::cout << cp_command << std::endl;
    ASSERT_EQ(system(cp_command.c_str()), 0);

    char *digest = image_store_big_data_digest(random_id, "manifest");
    ASSERT_STREQ(digest, "sha256:fdb7b1fccaaa535cb8211a194dd6314acc643f3a36d1a7d2b79c299a9173fa7e");
    free(digest);

    ASSERT_EQ(image_store_delete(random_id), 0);
    ASSERT_STRNE(image_store_lookup(random_id), random_id);
    ASSERT_FALSE(dirExists((img_store_path + std::string(random_id)).c_str()));
    free(random_id);
}

TEST_F(StorageImagesUnitTest, test_image_store_lookup)
{
    std::string id { "e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b" };
    std::string name { "imagehub.isulad.com/official/busybox:latest" };
    std::string truncatedId { "e4db68de4ff27" };
    std::string incorrectId { "4db68de4ff27" };

    char *value = NULL;
    ASSERT_STREQ((value = image_store_lookup(name.c_str())), id.c_str());
    free(value);
    ASSERT_STREQ((value = image_store_lookup(truncatedId.c_str())), id.c_str());
    free(value);
    ASSERT_EQ(image_store_lookup(incorrectId.c_str()), nullptr);
}

TEST_F(StorageImagesUnitTest, test_image_store_exists)
{
    std::string id { "39891ff67da98ab8540d71320915f33d2eb80ab42908e398472cab3c1ce7ac10" };
    std::string name { "imagehub.isulad.com/official/centos:latest" };
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
        char *metadata = image_store_metadata(elem.c_str());
        ASSERT_STREQ(metadata, "{}");
        free(metadata);
    }

    ASSERT_EQ(image_store_metadata(incorrectId.c_str()), nullptr);
}

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
            ASSERT_EQ(img->size, 0);
            ASSERT_EQ(img->spec->config->env_len, 1);
            ASSERT_STREQ(img->spec->config->env[0],
                         "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
            ASSERT_EQ(img->spec->config->cmd_len, 1);
            ASSERT_STREQ(img->spec->config->cmd[0], "/bin/bash");
        }
    }

    free_imagetool_images_list(images_list);
}

TEST_F(StorageImagesUnitTest, test_image_store_delete)
{
    std::string backup = std::string(store_real_path) + ".bak";
    std::string command = "cp -r " + std::string(store_real_path) + " " + backup;
    std::string rm_command = "rm -rf " + std::string(store_real_path);
    std::string undo_command = "mv " + backup + " " + std::string(store_real_path);
    ASSERT_EQ(system(command.c_str()), 0);

    for (auto elem : ids) {
        ASSERT_TRUE(image_store_exists(elem.c_str()));
        ASSERT_TRUE(dirExists((std::string(store_real_path) + "/overlay-images/" + elem).c_str()));
        ASSERT_EQ(image_store_delete(elem.c_str()), 0);
        ASSERT_FALSE(image_store_exists(elem.c_str()));
        ASSERT_FALSE(dirExists((std::string(store_real_path) + "/overlay-images/" + elem).c_str()));
    }

    ASSERT_EQ(system(rm_command.c_str()), 0);
    ASSERT_EQ(system(undo_command.c_str()), 0);
}

TEST_F(StorageImagesUnitTest, test_image_store_wipe)
{
    std::string backup = std::string(store_real_path) + ".bak";
    std::string command = "cp -r " + std::string(store_real_path) + " " + backup;
    std::string rm_command = "rm -rf " + std::string(store_real_path);
    std::string undo_command = "mv " + backup + " " + std::string(store_real_path);
    ASSERT_EQ(system(command.c_str()), 0);

    for (auto elem : ids) {
        ASSERT_TRUE(image_store_exists(elem.c_str()));
        ASSERT_TRUE(dirExists((std::string(store_real_path) + "/overlay-images/" + elem).c_str()));
    }

    ASSERT_EQ(image_store_wipe(), 0);

    for (auto elem : ids) {
        ASSERT_FALSE(image_store_exists(elem.c_str()));
        ASSERT_FALSE(dirExists((std::string(store_real_path) + "/overlay-images/" + elem).c_str()));
    }

    ASSERT_EQ(system(rm_command.c_str()), 0);
    ASSERT_EQ(system(undo_command.c_str()), 0);
}
