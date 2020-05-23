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
 * Author: jikui
 * Create: 2020-05-18
 * Description: provide oci storage rootfs unit test
 ******************************************************************************/
#include "rootfs_store.h"
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

std::string BIG_DATA_CONTENT = "big data test";
std::string META_DATA_CONTENT = "metadata test";

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

static void free_rootfs_list(struct rootfs_list *list)
{
    size_t i;

    if (list == NULL) {
        return;
    }

    for (i = 0; i < list->rootfs_len; i++) {
        free_storage_rootfs(list->rootfs[i]);
        list->rootfs[i] = NULL;
    }

    free(list->rootfs);
    list->rootfs = NULL;
    list->rootfs_len = 0;

    free(list);
}

class StorageRootfsUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        struct storage_module_init_options opts;
        std::string dir = GetDirectory() + "/data";
        ASSERT_STRNE(cleanpath(dir.c_str(), store_real_path, sizeof(store_real_path)), nullptr);

        opts.storage_root = strdup(store_real_path);
        opts.driver_name = strdup("overlay");
        ASSERT_EQ(rootfs_store_init(&opts), 0);
        free(opts.storage_root);
        free(opts.driver_name);
    }

    void TearDown() override
    {
        rootfs_store_free();
    }

    std::vector<std::string> ids { "0e025f44cdca20966a5e5f11e1d9d8eb726aef2d38ed20f89ea986987c2010a9",
        "28a8e1311d71345b08788c16b8c4f45a57641854f0e7c16802eedd0eb334b832" };
    char store_real_path[PATH_MAX] = { 0x00 };
};

TEST_F(StorageRootfsUnitTest, test_rootfs_load)
{
    std::string source = std::string(store_real_path) + "/overlay-containers/" + ids.at(0);
    std::string backup = std::string(store_real_path) + "/overlay-containers/" + ids.at(0) + ".bak";
    std::string cp_command = "cp -r " + source + " " + backup;
    storage_rootfs *cntr = NULL;
    storage_rootfs *cntr_tmp = NULL;
    cntrootfs_t cnrf;

    cntr = rootfs_store_get_rootfs(ids.at(0).c_str());
    ASSERT_EQ(system(cp_command.c_str()), 0);
    ASSERT_NE(cntr, nullptr);
    ASSERT_STREQ(cntr->created, "2020-05-27T08:55:26.273287183Z");
    ASSERT_STREQ(cntr->image, "e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b");
    ASSERT_STREQ(cntr->layer, "253836aa199405a39b6262b1e55a0d946b80988bc2f82d8f2b802fc175e4874e");
    ASSERT_STRNE(cntr->metadata, nullptr);
    ASSERT_EQ(cntr->names_len, 1);
    ASSERT_STREQ(cntr->names[0], "0e025f44cdca20966a5e5f11e1d9d8eb726aef2d38ed20f89ea986987c2010a9");
    ASSERT_EQ(rootfs_store_set_big_data(ids.at(0).c_str(), "userdata", BIG_DATA_CONTENT.c_str()), 0);
    ASSERT_STREQ(rootfs_store_big_data(ids.at(0).c_str(), "userdata"), BIG_DATA_CONTENT.c_str());
    ASSERT_EQ(rootfs_store_set_metadata(ids.at(0).c_str(), META_DATA_CONTENT.c_str()), 0);

    cntr_tmp = rootfs_store_get_rootfs(ids.at(0).c_str());
    cnrf.srootfs = cntr_tmp;
    cnrf.refcnt = 0;
    ASSERT_EQ(rootfs_store_save(&cnrf), 0);

    free_storage_rootfs(cntr);
    free_storage_rootfs(cntr_tmp);
}

TEST_F(StorageRootfsUnitTest, test_rootfs_store_create)
{
    std::string id { "5aca18b065db4741a9e24ff898cec48307ee12cb9ecec5dcb83e8210230f766f" };
    const char *names_with_id[] = { "5aca18b065db4741a9e24ff898cec48307ee12cb9ecec5dcb83e8210230f766f" };
    const char *names_without_id[] = { "jkha18b065db4741a9e24ff898cec48307ee12cb9ecec5dcbhje8210230f766f" };
    std::string image { "e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b" };
    std::string layer_with_id { "f32ca140c6716a68d7bba0fe6529334e98de529bd8fb7a203a21f08e772629a9" };
    std::string layer_without_id { "h88ca140c6716a68d7bba0fe6529334e98de529bd8fb7agf3a21f08e772629a9" };
    std::string metadata { "{}" };
    char *created_container = rootfs_store_create(id.c_str(), names_with_id,
                                                  sizeof(names_with_id) / sizeof(names_with_id[0]), image.c_str(), layer_with_id.c_str(),
                                                  metadata.c_str(), nullptr);
    char *container_without_id = rootfs_store_create(nullptr, names_without_id,
                                                     sizeof(names_without_id) / sizeof(names_without_id[0]), image.c_str(),
                                                     layer_without_id.c_str(), metadata.c_str(), nullptr);

    ASSERT_STREQ(created_container, id.c_str());
    ASSERT_NE(container_without_id, nullptr);
    ASSERT_EQ(rootfs_store_delete(id.c_str()), 0);
    ASSERT_EQ(rootfs_store_get_rootfs(id.c_str()), nullptr);
    ASSERT_EQ(rootfs_store_delete(container_without_id), 0);
    ASSERT_FALSE(dirExists((std::string(store_real_path) + "/" + id).c_str()));
}

TEST_F(StorageRootfsUnitTest, test_rootfs_store_lookup)
{
    std::string id { "28a8e1311d71345b08788c16b8c4f45a57641854f0e7c16802eedd0eb334b832" };
    std::string name { "28a8e1311d71345b08788c16b8c4f45a57641854f0e7c16802eedd0eb334b832" };
    std::string truncatedId { "28a8e1311d71" };
    std::string incorrectId { "89jfl9hds13k" };

    char *value = NULL;
    ASSERT_STREQ((value = rootfs_store_lookup(name.c_str())), id.c_str());
    free(value);
    ASSERT_STREQ((value = rootfs_store_lookup(truncatedId.c_str())), id.c_str());
    free(value);
    ASSERT_EQ(rootfs_store_lookup(incorrectId.c_str()), nullptr);
}

TEST_F(StorageRootfsUnitTest, test_rootfs_store_exists)
{
    std::string id { "28a8e1311d71345b08788c16b8c4f45a57641854f0e7c16802eedd0eb334b832" };
    std::string name { "28a8e1311d71345b08788c16b8c4f45a57641854f0e7c16802eedd0eb334b832" };
    std::string truncatedId { "28a8e1311d71345b" };
    std::string incorrectId { "c4f45a57641854f0" };

    ASSERT_TRUE(rootfs_store_exists(name.c_str()));
    ASSERT_TRUE(rootfs_store_exists(truncatedId.c_str()));
    ASSERT_FALSE(rootfs_store_exists(incorrectId.c_str()));
}

TEST_F(StorageRootfsUnitTest, test_rootfs_store_metadata)
{
    std::string incorrectId { "ff67da98ab8540d713209" };
    char *metadata = NULL;

    metadata = rootfs_store_metadata(ids.at(0).c_str());
    ASSERT_STREQ(metadata, META_DATA_CONTENT.c_str());
    free(metadata);
    metadata = NULL;

    metadata = rootfs_store_metadata(ids.at(1).c_str());
    ASSERT_STREQ(metadata, "{}");
    free(metadata);
    metadata = NULL;

    ASSERT_EQ(rootfs_store_metadata(incorrectId.c_str()), nullptr);
}

TEST_F(StorageRootfsUnitTest, test_rootfs_store_get_all_rootfs)
{
    std::string source = std::string(store_real_path) + "/overlay-containers/" + ids.at(0);
    std::string backup = std::string(store_real_path) + "/overlay-containers/" + ids.at(0) + ".bak";
    std::string rm_command = "rm -rf " + source;
    std::string mv_command = "mv " + backup + " " + source;
    rootfs_list *rf_list = NULL;
    char *digest = NULL;
    char **names = NULL;
    size_t names_len = 0;

    rf_list = (rootfs_list *)util_common_calloc_s(sizeof(rootfs_list));
    ASSERT_NE(rf_list, nullptr);
    ASSERT_EQ(rootfs_store_get_all_rootfs(rf_list), 0);
    ASSERT_EQ(rf_list->rootfs_len, 2);
    for (size_t i {}; i < rf_list->rootfs_len; i++) {
        ASSERT_NE(find(ids.begin(), ids.end(), std::string(rf_list->rootfs[i]->id)), ids.end());

        auto cntr = rf_list->rootfs[i];
        if (std::string(rf_list->rootfs[i]->id) == ids.at(0)) {
            ASSERT_STREQ(cntr->created, "2020-05-27T08:55:26.273287183Z");
            ASSERT_STREQ(cntr->image, "e4db68de4ff27c2adfea0c54bbb73a61a42f5b667c326de4d7d5b19ab71c6a3b");
            ASSERT_STREQ(cntr->layer, "253836aa199405a39b6262b1e55a0d946b80988bc2f82d8f2b802fc175e4874e");
            ASSERT_STREQ(cntr->names[0], "0e025f44cdca20966a5e5f11e1d9d8eb726aef2d38ed20f89ea986987c2010a9");
            ASSERT_EQ(cntr->names_len, 1);
            ASSERT_STREQ(cntr->big_data_names[0], "userdata");
            ASSERT_EQ(*(cntr->big_data_sizes->values), rootfs_store_big_data_size(ids.at(0).c_str(), "userdata"));
            ASSERT_NE(digest = rootfs_store_big_data_digest(ids.at(0).c_str(), "userdata"), nullptr);
            ASSERT_EQ(rootfs_store_big_data_names(ids.at(0).c_str(), &names, &names_len), 0);
        }
    }

    util_free_array_by_len(names, names_len);
    free_rootfs_list(rf_list);
    free(digest);
    ASSERT_EQ(system(rm_command.c_str()), 0);
    ASSERT_EQ(system(mv_command.c_str()), 0);
}

TEST_F(StorageRootfsUnitTest, test_rootfs_store_delete)
{
    std::string backup = std::string(store_real_path) + ".bak";
    std::string command = "cp -r " + std::string(store_real_path) + " " + backup;
    std::string rm_command = "rm -rf " + std::string(store_real_path);
    std::string undo_command = "mv " + backup + " " + std::string(store_real_path);
    ASSERT_EQ(system(command.c_str()), 0);

    for (auto elem : ids) {
        ASSERT_TRUE(rootfs_store_exists(elem.c_str()));
        ASSERT_TRUE(dirExists((std::string(store_real_path) + "/overlay-containers/" + elem).c_str()));
        ASSERT_EQ(rootfs_store_delete(elem.c_str()), 0);
        ASSERT_FALSE(rootfs_store_exists(elem.c_str()));
        ASSERT_FALSE(dirExists((std::string(store_real_path) + "/overlay-containers/" + elem).c_str()));
    }

    ASSERT_EQ(system(rm_command.c_str()), 0);
    ASSERT_EQ(system(undo_command.c_str()), 0);
}

TEST_F(StorageRootfsUnitTest, test_rootfs_store_wipe)
{
    std::string backup = std::string(store_real_path) + ".bak";
    std::string command = "cp -r " + std::string(store_real_path) + " " + backup;
    std::string rm_command = "rm -rf " + std::string(store_real_path);
    std::string undo_command = "mv " + backup + " " + std::string(store_real_path);
    ASSERT_EQ(system(command.c_str()), 0);

    for (auto elem : ids) {
        ASSERT_TRUE(rootfs_store_exists(elem.c_str()));
        ASSERT_TRUE(dirExists((std::string(store_real_path) + "/overlay-containers/" + elem).c_str()));
    }

    ASSERT_EQ(rootfs_store_wipe(), 0);

    for (auto elem : ids) {
        ASSERT_FALSE(rootfs_store_exists(elem.c_str()));
        ASSERT_FALSE(dirExists((std::string(store_real_path) + "/overlay-containers/" + elem).c_str()));
    }

    ASSERT_EQ(system(rm_command.c_str()), 0);
    ASSERT_EQ(system(undo_command.c_str()), 0);
}
