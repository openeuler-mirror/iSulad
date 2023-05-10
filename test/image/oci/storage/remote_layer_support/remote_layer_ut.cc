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
 * Author: wangrunze
 * Create: 2023-03-16
 * Description: provide remote layer support ut
 ******************************************************************************/
#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "map.h"
#include "utils_file.h"
#include "utils.h"
#include "remote_store_mock.h"
#include "ro_symlink_maintain.h"
#include "remote_support.h"

using ::testing::Invoke;
using ::testing::NiceMock;

static bool flag;
static bool remove_layer_flag;
static bool layer_valid_flag;
static bool overlay_valid_flag;

bool invokeOverlayRemoteLayerValid(const char *id)
{
    if (overlay_valid_flag) {
        return true;
    }
    return false;
}

bool invokeLayerRemoteLayerValid(const char *id)
{
    if (layer_valid_flag) {
        return false;
    }
    return true;
}

int invokeLayerLoadOneLayer(const char *id)
{
    if (flag) {
        return -1;
    }
    return 0;
}

int invokeLayerRemoveOneLayer(const char *id)
{
    if (remove_layer_flag) {
        return -1;
    }
    return 0;
}

int invokeImageAppendOneImage(const char *id)
{
    if (flag) {
        return -1;
    }
    return 0;
}

int invokeImageRemoveOneImage(const char *id)
{
    if (flag) {
        return -1;
    }
    return 0;
}

char *invokeImageGetTopLayer(const char *id)
{
    return util_strdup_s("top_layer");
}

int invokeImageValidSchemaV1(const char *path, bool *valid)
{
    *valid = false;
    return flag ? -1 : 0;
}

void mockCommonAll(MockRemoteStore *mock)
{
    EXPECT_CALL(*mock, LayerLoadOneLayer(::testing::_)).WillRepeatedly(Invoke(invokeLayerLoadOneLayer));
    EXPECT_CALL(*mock, LayerRemoveOneLayer(::testing::_)).WillRepeatedly(Invoke(invokeLayerRemoveOneLayer));

    EXPECT_CALL(*mock, ImageAppendOneImage(::testing::_)).WillRepeatedly(Invoke(invokeImageAppendOneImage));
    EXPECT_CALL(*mock, ImageRemoveOneImage(::testing::_)).WillRepeatedly(Invoke(invokeImageRemoveOneImage));
    EXPECT_CALL(*mock, ImageGetTopLayer(::testing::_)).WillRepeatedly(Invoke(invokeImageGetTopLayer));
    EXPECT_CALL(*mock, ImageValidSchemaV1(::testing::_, ::testing::_)).WillRepeatedly(Invoke(invokeImageValidSchemaV1));
}

class RemoteLayerUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        MockRemoteStore_SetMock(&mock);
        mockCommonAll(&mock);
    }

    void TearDown() override
    {
        MockRemoteStore_SetMock(nullptr);
    }

    NiceMock<MockRemoteStore> mock;
};

TEST_F(RemoteLayerUnitTest, test_map_diff)
{
    // old: a b x
    // new: x b c
    map_t *old_one = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    map_t *new_one = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    bool exist = true;

    map_insert(old_one, (void *)"a", (void *)&exist);
    map_insert(old_one, (void *)"b", (void *)&exist);
    map_insert(new_one, (void *)"b", (void *)&exist);
    map_insert(new_one, (void *)"c", (void *)&exist);

    char **added = remote_added_layers(old_one, new_one);
    char **deleted = remote_deleted_layers(old_one, new_one);

    ASSERT_EQ(added[0][0], 'c');
    ASSERT_EQ(deleted[0][0], 'a');
}

TEST_F(RemoteLayerUnitTest, test_remote_create)
{
    struct remote_image_data *image = remote_image_create("foo", "bar");
    ASSERT_EQ(strcmp(image->image_home, "foo"), 0);
    remote_image_destroy(image);

    struct remote_layer_data *layer = remote_layer_create("foo", "bar");
    ASSERT_EQ(strcmp(layer->layer_home, "foo"), 0);
    ASSERT_EQ(strcmp(layer->layer_ro, "bar"), 0);
    remote_layer_destroy(layer);

    struct remote_overlay_data *overlay = remote_overlay_create("foo", "bar");
    ASSERT_EQ(strcmp(overlay->overlay_home, "foo"), 0);
    ASSERT_EQ(strcmp(overlay->overlay_ro, "bar"), 0);
    remote_overlay_destroy(overlay);
}

// generate a random string with length
// each charater is from 'a'-'f' or '0'-'9'
static char *random_name(int length)
{
    char *name = (char *)util_common_calloc_s(length + 1);
    if (name == NULL) {
        return NULL;
    }

    for (int i = 0; i < length; i++) {
        int r = rand() % 16;
        if (r < 10) {
            name[i] = '0' + r;
        } else {
            name[i] = 'a' + r - 10;
        }
    }

    return name;
}

// generate a random string with random length
char *random_invalid_name()
{
    int length = rand() % 64 + 1;
    return random_name(length);
}

static int clean_image_home(const char *path)
{
    //remove images dir and sub dirs
    if (util_recursive_remove_path(path) != 0) {
        return -1;
    }

    return 0;
}

static int prepare_image_home(const char *path, bool valid)
{
    int i = 0;
    const char *name_template = "b97242f89c8a29d13aea12843a08441a4bbfc33528f55b60366c1d8f6923d0d4";
    char *image_name = NULL;

    clean_image_home(path);

    // make a dir with name images
    if (mkdir(path, 0755) != 0) {
        return -1;
    }

    // make 10 sub dirs inside images
    while (i < 10) {
        char *dir = NULL;
        if (valid) {
            image_name = random_name(strlen(name_template));
        } else {
            image_name = random_invalid_name();
        }
        if (asprintf(&dir, "%s/%s", path, image_name) < 0) {
            return -1;
        }
        if (mkdir(dir, 0755) != 0) {
            free(dir);
            return -1;
        }
        free(dir);
        free(image_name);
        i++;
    }

    return 0;
}

TEST_F(RemoteLayerUnitTest, test_image_refresh_invalid_data)
{
    struct remote_image_data *image = remote_image_create("foo", "bar");
    remote_image_refresh(image);
}

TEST_F(RemoteLayerUnitTest, test_image_refresh_invalid_sub_dir)
{
    struct remote_image_data *image = remote_image_create("images", "bar");
    if (prepare_image_home(image->image_home, false) != 0) {
        return;
    }
    remote_image_refresh(image);
    clean_image_home(image->image_home);
}

TEST_F(RemoteLayerUnitTest, test_image_refresh)
{
    flag = false;
    struct remote_image_data *image = remote_image_create("images", "bar");

    if (prepare_image_home(image->image_home, true) != 0) {
        return;
    }

    remote_image_refresh(image);
    clean_image_home(image->image_home);
}

TEST_F(RemoteLayerUnitTest, test_image_refresh2)
{
    flag = true;
    struct remote_image_data *image = remote_image_create("images", "bar");

    if (prepare_image_home(image->image_home, true) != 0) {
        return;
    }

    remote_image_refresh(image);
    clean_image_home(image->image_home);
}

static int clean_layer_home(const char *path)
{
    //remove layers dir and sub dirs
    if (util_recursive_remove_path(path) != 0) {
        return -1;
    }

    return 0;
}

static int prepare_layer_home(const char *layer_home, const char *layer_ro, const char *overlay_home,
                              const char *overlay_ro, bool valid)
{
    int i = 0;
    const char *name_template = "b97242f89c8a29d13aea12843a08441a4bbfc33528f55b60366c1d8f6923d0d4";
    char *layer_name = NULL;
    char *overlay_name = NULL;
    char *link_name = NULL;
    char *link_path = NULL;
    char link_home[4096] = { 0x0 };
    int fd = 0;

    clean_layer_home(layer_home);
    clean_layer_home(overlay_home);

    // make a dir with name images
    if (mkdir(layer_home, 0755) != 0) {
        return -1;
    }

    if (mkdir(layer_ro, 0755) != 0) {
        return -1;
    }

    if (mkdir(overlay_home, 0755) != 0) {
        return -1;
    }

    if (mkdir(overlay_ro, 0755) != 0) {
        return -1;
    }

    snprintf(link_home, sizeof(link_home), "%s/%s", overlay_home, "l");

    if (mkdir(link_home, 0755) != 0) {
        return -1;
    }

    // make 10 sub dirs inside images
    while (i < 10) {
        char *layer_dir = NULL;
        char *overlay_dir = NULL;
        if (valid) {
            layer_name = random_name(strlen(name_template));
            overlay_name = layer_name;
            link_name = random_name(26);
        } else {
            layer_name = random_invalid_name();
            overlay_name = layer_name;
            link_name = random_invalid_name();
        }
        if (asprintf(&layer_dir, "%s/%s", layer_ro, layer_name) < 0) {
            continue;
        }
        if (mkdir(layer_dir, 0755) != 0) {
            free(layer_dir);
            continue;
        }

        if (asprintf(&overlay_dir, "%s/%s", overlay_ro, overlay_name) < 0) {
            continue;
        }

        if (mkdir(overlay_dir, 0755) != 0) {
            free(layer_dir);
            continue;
        }

        // create a new file named link under overlay_dir, and write "hello" into the file
        if (asprintf(&link_path, "%s/%s", overlay_dir, "link") < 0) {
            continue;
        }

        if ((fd = open(link_path, O_CREAT | O_RDWR, 0644)) < 0) {
            continue;
        }

        if (write(fd, link_name, 26) < 0) {
            continue;
        }

        free(layer_dir);
        free(overlay_dir);
        free(layer_name);
        i++;
    }

    return 0;
}

static bool remove_layer(const char *path_name, const struct dirent *sub_dir, void *context)
{
    char *path = NULL;
    path = util_path_join((char *)context, sub_dir->d_name);

    if (util_recursive_remove_path(path) != 0) {
        return -1;
    }

    free(path);

    return true;
}

TEST_F(RemoteLayerUnitTest, test_layer_refresh)
{
    flag = false;
    struct remote_overlay_data *overlay = remote_overlay_create("overlay", "overlay/RO");
    struct remote_layer_data *layer = remote_layer_create("layers", "layers/RO");

    if (prepare_layer_home(layer->layer_home, layer->layer_ro, overlay->overlay_home, overlay->overlay_ro, true) != 0) {
        return;
    }

    remote_overlay_refresh(overlay);
    remote_layer_refresh(layer);

    util_scan_subdirs(overlay->overlay_ro, remove_layer, (void *)overlay->overlay_ro);
    util_scan_subdirs(layer->layer_ro, remove_layer, (void *)layer->layer_ro);

    remote_overlay_refresh(overlay);
    remote_layer_refresh(layer);

    clean_layer_home(layer->layer_home);
    clean_layer_home(overlay->overlay_home);
}

TEST_F(RemoteLayerUnitTest, test_layer_refresh3)
{
    flag = false;
    remove_layer_flag = true;
    layer_valid_flag = true;
    overlay_valid_flag = true;
    struct remote_overlay_data *overlay = remote_overlay_create("overlay", "overlay/RO");
    struct remote_layer_data *layer = remote_layer_create("layers", "layers/RO");

    if (prepare_layer_home(layer->layer_home, layer->layer_ro, overlay->overlay_home, overlay->overlay_ro, true) != 0) {
        return;
    }

    remote_overlay_refresh(overlay);
    remote_layer_refresh(layer);

    util_scan_subdirs(overlay->overlay_ro, remove_layer, (void *)overlay->overlay_ro);
    util_scan_subdirs(layer->layer_ro, remove_layer, (void *)layer->layer_ro);

    remote_overlay_refresh(overlay);
    remote_layer_refresh(layer);

    clean_layer_home(layer->layer_home);
    clean_layer_home(overlay->overlay_home);
}

TEST_F(RemoteLayerUnitTest, test_layer_refresh4)
{
    flag = false;
    struct remote_overlay_data *overlay = remote_overlay_create("overlay", "overlay/RO");
    struct remote_layer_data *layer = remote_layer_create("layers", "layers/RO");

    if (prepare_layer_home(layer->layer_home, layer->layer_ro, overlay->overlay_home, overlay->overlay_ro, true) != 0) {
        return;
    }

    clean_layer_home(overlay->overlay_home);
    remote_overlay_refresh(overlay);
    remote_layer_refresh(layer);

    util_scan_subdirs(overlay->overlay_ro, remove_layer, (void *)overlay->overlay_ro);
    util_scan_subdirs(layer->layer_ro, remove_layer, (void *)layer->layer_ro);

    remote_overlay_refresh(overlay);
    remote_layer_refresh(layer);

    clean_layer_home(layer->layer_home);
    clean_layer_home(overlay->overlay_home);
}

TEST_F(RemoteLayerUnitTest, test_layer_refresh2)
{
    flag = true;
    struct remote_overlay_data *overlay = remote_overlay_create("overlay", "overlay/RO");
    struct remote_layer_data *layer = remote_layer_create("layers", "layers/RO");

    if (prepare_layer_home(layer->layer_home, layer->layer_ro, overlay->overlay_home, overlay->overlay_ro, true) != 0) {
        return;
    }

    remote_overlay_refresh(overlay);
    remote_layer_refresh(layer);

    util_scan_subdirs(overlay->overlay_ro, remove_layer, (void *)overlay->overlay_ro);
    util_scan_subdirs(layer->layer_ro, remove_layer, (void *)layer->layer_ro);

    remote_overlay_refresh(overlay);
    remote_layer_refresh(layer);

    clean_layer_home(layer->layer_home);
    clean_layer_home(overlay->overlay_home);
}

TEST(remote_support, start_thread)
{
    pthread_rwlock_t g_rwlock;
    pthread_rwlock_init(&g_rwlock, NULL);
    remote_start_refresh_thread(&g_rwlock);

    sleep(6);
}

static int prepare_empty_home(const char *layer_home, const char *layer_ro, const char *overlay_home,
                              const char *overlay_ro)
{
    char link_home[4096] = { 0x0 };

    clean_layer_home(layer_home);
    clean_layer_home(overlay_home);

    // make a dir with name images
    if (mkdir(layer_home, 0755) != 0) {
        return -1;
    }

    if (mkdir(layer_ro, 0755) != 0) {
        return -1;
    }

    if (mkdir(overlay_home, 0755) != 0) {
        return -1;
    }

    if (mkdir(overlay_ro, 0755) != 0) {
        return -1;
    }

    snprintf(link_home, sizeof(link_home), "%s/%s", overlay_home, "l");

    if (mkdir(link_home, 0755) != 0) {
        return -1;
    }

    return 0;
}

TEST(ro_symlink_maintain, maintain)
{
    char *image_home = util_strdup_s("images2");
    char *layer_home = util_strdup_s("layers2");
    char *overlay_home = util_strdup_s("overlay2");

    remote_image_init(image_home);
    remote_layer_init(layer_home);
    remote_overlay_init(overlay_home);

    clean_layer_home(layer_home);
    clean_layer_home(overlay_home);

    prepare_empty_home(layer_home, "layers2/RO", overlay_home, "overlay2/RO");

    ASSERT_EQ(remote_layer_build_ro_dir("foo"), 0);
    ASSERT_EQ(remote_overlay_build_ro_dir("foo"), 0);

    ASSERT_EQ(remote_layer_remove_ro_dir("foo"), 0);
    ASSERT_EQ(remote_overlay_remove_ro_dir("foo"), 0);

    maintain_context ctx = get_maintain_context();
    ASSERT_EQ(strcmp(ctx.image_home, image_home), 0);
    ASSERT_EQ(strcmp(ctx.layer_home, layer_home), 0);
    ASSERT_EQ(strcmp(ctx.overlay_home, overlay_home), 0);

    remote_maintain_cleanup();
}
