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
 * Author: wangfengtu
 * Create: 2020-06-30
 * Description: provide oci registry images unit test
 ******************************************************************************/
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
#include <gmock/gmock.h>
#include <curl/curl.h>

#include "utils.h"
#include "utils_array.h"
#include "path.h"
#include "isula_libutils/imagetool_images_list.h"
#include "isula_libutils/imagetool_image.h"
#include "isula_libutils/log.h"
#include "http_request.h"
#include "registry.h"
#include "registry_type.h"
#include "http_mock.h"
#include "storage_mock.h"
#include "buffer.h"
#include "aes.h"
#include "auths.h"
#include "oci_image_mock.h"
#include "isulad_config_mock.h"

using ::testing::Args;
using ::testing::ByRef;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::NotNull;
using ::testing::AtLeast;
using ::testing::Invoke;

std::string get_dir()
{
    char abs_path[PATH_MAX] { 0x00 };
    int ret = readlink("/proc/self/exe", abs_path, sizeof(abs_path));
    if (ret < 0 || static_cast<size_t>(ret) >= sizeof(abs_path)) {
        return "";
    }

    for (int i { ret }; i >= 0; --i) {
        if (abs_path[i] == '/') {
            abs_path[i + 1] = '\0';
            break;
        }
    }

    return static_cast<std::string>(abs_path) + "../../../../../test/image/oci/registry";
}

void mockCommonAll(MockStorage *mock, MockOciImage *oci_image_mock);

static struct oci_image_module_data g_oci_image_registry = { 0 };

static void oci_image_registry_init()
{
    g_oci_image_registry.root_dir = util_strdup_s(get_dir().c_str());
    g_oci_image_registry.use_decrypted_key = true;
}

static struct oci_image_module_data *invokeGetOciImageData()
{
    return &g_oci_image_registry;
}

static void oci_image_registry_exit()
{
    free(g_oci_image_registry.root_dir);
    g_oci_image_registry.root_dir = NULL;

    g_oci_image_registry.use_decrypted_key = false;
}

class RegistryUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        MockHttp_SetMock(&m_http_mock);
        MockStorage_SetMock(&m_storage_mock);
        MockOciImage_SetMock(&m_oci_image_mock);
        mockCommonAll(&m_storage_mock, &m_oci_image_mock);
        oci_image_registry_init();
    }

    void TearDown() override
    {
        MockHttp_SetMock(nullptr);
        MockStorage_SetMock(nullptr);
        MockOciImage_SetMock(nullptr);
        oci_image_registry_exit();
    }

    NiceMock<MockHttp> m_http_mock;
    NiceMock<MockStorage> m_storage_mock;
    NiceMock<MockOciImage> m_oci_image_mock;
};

int invokeHttpRequestV1(const char *url, struct http_get_options *options, long *response_code, int recursive_len)
{
    std::string file;
    char *data = nullptr;
    static int ping_count = 0;
    static int token_count = 0;
    Buffer *output_buffer = (Buffer *)options->output;

    std::string data_path = get_dir() + "/data/v1/";
    if (!strcmp(url, "https://quay.io/v2/")) {
        ping_count++;
        if (ping_count == 1) {
            file = data_path + "ping_head1";
        } else {
            file = data_path + "ping_head";
        }
    } else if (!strcmp(url, "https://quay.io/v2/coreos/etcd/manifests/v3.3.17-arm64")) {
        file = data_path + "manifest";
    } else if (util_has_prefix(url, "https://auth.quay.io")) {
        token_count++;
        if (token_count == 2) {
            file = data_path + "token_body2";
        } else {
            if (strstr(url, "quay.io registry") == NULL) {
                ERROR("invalid url %s", url);
                return -1;
            }
            file = data_path + "token_body";
        }
    } else if (util_has_prefix(url, "https://quay.io/v2/coreos/etcd/blobs/sha256")) {
        file = std::string("");
    } else {
        ERROR("%s not match failed", url);
        return -1;
    }

    if (file == std::string("")) {
        data = util_strdup_s("test");
    } else {
        data = util_read_text_file(file.c_str());
        if (data == nullptr) {
            ERROR("read file %s failed", file.c_str());
            return -1;
        }
    }
    if (options->outputtype == HTTP_REQUEST_STRBUF) {
        free(output_buffer->contents);
        output_buffer->contents = util_strdup_s(data);
    } else {
        if (util_write_file((const char *)options->output, data, strlen(data), 0600) != 0) {
            free(data);
            ERROR("write file %s failed", (char *)options->output);
            return -1;
        }
    }
    free(data);

    return 0;
}

int invokeHttpRequestV2(const char *url, struct http_get_options *options, long *response_code, int recursive_len)
{
#define COUNT_TEST_CANCEL 2
#define COUNT_TEST_NOT_FOUND 3
#define COUNT_TEST_SERVER_ERROR 4
    std::string file;
    char *data = nullptr;
    int64_t size = 0;
    Buffer *output_buffer = (Buffer *)options->output;
    static bool retry = true;
    static int count = 0;

    // Test insecure registry, assume registry cann't support https.
    if (util_has_prefix(url, "https://")) {
        return -1;
    }

    std::string data_path = get_dir() + "/data/v2/";
    if (!strcmp(url, "http://hub-mirror.c.163.com/v2/")) {
        count++;
        file = data_path + "ping_head";
    } else if (!strcmp(url, "http://hub-mirror.c.163.com/v2/library/busybox/manifests/latest")) {
        // test not found
        if (count == COUNT_TEST_NOT_FOUND) {
            file = data_path + "manifest_404";
        } else {
            file = data_path + "manifest_list";
        }
    } else if (util_has_prefix(url, "http://hub-mirror.c.163.com/v2/library/busybox/manifests/sha256:2131f09e")) {
        file = data_path + "manifest_body";
    } else if (util_has_prefix(url, "http://hub-mirror.c.163.com/v2/library/busybox/blobs/sha256:c7c37e47")) {
        file = data_path + "config";
        if (count == COUNT_TEST_CANCEL) {
            bool *cancel = (bool *)options->progressinfo;
            while (!(*cancel)) {
                sleep(1); // schedule out to let cancel variable set to be true
            }
            if (options->progress_info_op(options->progressinfo, 0, 0, 0, 0) != 0) {
                return -1;
            }
        }
    } else if (util_has_prefix(url, "http://hub-mirror.c.163.com/v2/library/busybox/blobs/sha256:91f30d77")) {
        if (retry) {
            retry = false;
            options->errcode = CURLE_RANGE_ERROR;
            return -1;
        }
        // test cancel
        if (count == COUNT_TEST_CANCEL) {
            return -1;
        }
        // test server error
        if (count == COUNT_TEST_SERVER_ERROR) {
            file = data_path + "0_server_error";
        } else {
            file = data_path + "0";
        }
    } else {
        ERROR("%s not match failed", url);
        return -1;
    }

    size = util_file_size(file.c_str());
    if (size < 0) {
        ERROR("get file %s size failed", file.c_str());
        return -1;
    }

    data = util_read_text_file(file.c_str());
    if (data == nullptr) {
        ERROR("read file %s failed", file.c_str());
        return -1;
    }

    if (options->outputtype == HTTP_REQUEST_STRBUF) {
        free(output_buffer->contents);
        output_buffer->contents = util_strdup_s(data);
    } else {
        if (util_write_file((const char *)options->output, data, size, 0600) != 0) {
            free(data);
            ERROR("write file %s failed", (char *)options->output);
            return -1;
        }
    }
    free(data);

    return 0;
}

int invokeHttpRequestOCI(const char *url, struct http_get_options *options, long *response_code, int recursive_len)
{
    std::string file;
    char *data = nullptr;
    int64_t size = 0;
    Buffer *output_buffer = (Buffer *)options->output;

    std::string data_path = get_dir() + "/data/oci/";
    if (!strcmp(url, "https://hub-mirror.c.163.com/v2/")) {
        file = data_path + "ping_head";
    } else if (!strcmp(url, "https://hub-mirror.c.163.com/v2/library/busybox/manifests/latest")) {
        file = data_path + "index";
    } else if (util_has_prefix(url, "https://hub-mirror.c.163.com/v2/library/busybox/manifests/sha256:106429d7")) {
        file = data_path + "manifest_body";
    } else if (util_has_prefix(url, "https://hub-mirror.c.163.com/v2/library/busybox/blobs/sha256:c7c37e47")) {
        file = data_path + "config";
    } else if (util_has_prefix(url, "https://hub-mirror.c.163.com/v2/library/busybox/blobs/sha256:91f30d77")) {
        file = data_path + "0";
    } else {
        ERROR("%s not match failed", url);
        return -1;
    }

    size = util_file_size(file.c_str());
    if (size < 0) {
        ERROR("get file %s size failed", file.c_str());
        return -1;
    }

    data = util_read_text_file(file.c_str());
    if (data == nullptr) {
        ERROR("read file %s failed", file.c_str());
        return -1;
    }

    if (options->outputtype == HTTP_REQUEST_STRBUF) {
        free(output_buffer->contents);
        output_buffer->contents = util_strdup_s(data);
    } else {
        if (util_write_file((const char *)options->output, data, size, 0600) != 0) {
            free(data);
            ERROR("write file %s failed", (char *)options->output);
            return -1;
        }
    }
    free(data);

    return 0;
}

int invokeHttpRequestLogin(const char *url, struct http_get_options *options, long *response_code, int recursive_len)
{
    std::string file;
    char *data = nullptr;
    Buffer *output_buffer = (Buffer *)options->output;

    std::string data_path = get_dir() + "/data/v2/";
    if (!strcmp(url, "https://hub-mirror.c.163.com/v2/") || !strcmp(url, "https://test2.com/v2/")) {
        file = data_path + "ping_head";
    } else {
        ERROR("%s not match failed", url);
        return -1;
    }

    data = util_read_text_file(file.c_str());
    if (data == nullptr) {
        ERROR("read file %s failed", file.c_str());
        return -1;
    }

    if (options->outputtype == HTTP_REQUEST_STRBUF) {
        free(output_buffer->contents);
        output_buffer->contents = util_strdup_s(data);
    }
    free(data);

    return 0;
}

int invokeStorageImgCreate(const char *id, const char *parent_id, const char *metadata,
                           struct storage_img_create_options *opts)
{
    static int count = 0;

    count++;
    if (count == 1) {
        return -1;
    }

    return 0;
}

imagetool_image *invokeStorageImgGet(const char *img_id)
{
    return nullptr;
}

imagetool_image_summary *invokeStorageImgGetSummary(const char *img_id)
{
    return nullptr;
}

int invokeStorageImgSetBigData(const char *img_id, const char *key, const char *val)
{
    return 0;
}

int invokeStorageImgAddName(const char *img_id, const char *img_name)
{
    return 0;
}

int invokeStorageImgDelete(const char *img_id, bool commit)
{
    return 0;
}

int invokeStorageImgSetLoadedTime(const char *img_id, types_timestamp_t *loaded_time)
{
    return 0;
}

int invokeStorageImgSetImageSize(const char *image_id)
{
    return 0;
}

char *invokeStorageGetImgTopLayer(const char *id)
{
    return util_strdup_s((char *)"382dfd1b0f139f3fa6a7b14d4b18ad49a8bd86e4b303264088b39b020556da73");
}

int invokeStorageLayerCreate(const char *layer_id, storage_layer_create_opts_t *opts)
{
    return 0;
}

int invokeStorageIncHoldRefs(const char *layer_id)
{
    return 0;
}

int invokeStorageDecHoldRefs(const char *layer_id)
{
    return 0;
}

struct layer *invokeStorageLayerGet(const char *layer_id)
{
    return nullptr;
}

struct layer_list *invokeStorageLayersGetByCompressDigest(const char *digest)
{
    int ret = 0;
    struct layer_list *list = nullptr;

    list = (struct layer_list *)util_common_calloc_s(sizeof(struct layer_list));
    if (list == nullptr) {
        ERROR("out of memory");
        return nullptr;
    }

    list->layers = (struct layer **)util_common_calloc_s(sizeof(struct layer *) * 1);
    if (list->layers == nullptr) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    list->layers[0] = (struct layer *)util_common_calloc_s(sizeof(struct layer));
    if (list->layers[0] == nullptr) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    list->layers_len = 1;
    list->layers[0]->uncompressed_digest =
        util_strdup_s("sha256:50761fe126b6e4d90fa0b7a6e195f6030fe250c016c2fc860ac40f2e8d2f2615");
    list->layers[0]->id = util_strdup_s("sha256:50761fe126b6e4d90fa0b7a6e195f6030fe250c016c2fc860ac40f2e8d2f2615");
    list->layers[0]->parent = nullptr;

out:
    if (ret != 0) {
        free_layer_list(list);
        list = nullptr;
    }

    return list;
}

struct layer *invokeStorageLayerGet1(const char *layer_id)
{
    struct layer *l = nullptr;

    l = (struct layer *)util_common_calloc_s(sizeof(struct layer));
    if (l == nullptr) {
        ERROR("out of memory");
        return nullptr;
    }

    return l;
}

int invokeStorageLayerTryRepairLowers(const char *layer_id, const char *last_layer_id)
{
    return 0;
}

void invokeFreeLayerList(struct layer_list *ptr)
{
    size_t i = 0;
    if (ptr == nullptr) {
        return;
    }

    for (; i < ptr->layers_len; i++) {
        free_layer(ptr->layers[i]);
        ptr->layers[i] = nullptr;
    }
    free(ptr->layers);
    ptr->layers = nullptr;
    free(ptr);
}

void invokeFreeLayer(struct layer *ptr)
{
    if (ptr == nullptr) {
        return;
    }
    free(ptr->id);
    ptr->id = nullptr;
    free(ptr->parent);
    ptr->parent = nullptr;
    free(ptr->mount_point);
    ptr->mount_point = nullptr;
    free(ptr->compressed_digest);
    ptr->compressed_digest = nullptr;
    free(ptr->uncompressed_digest);
    ptr->uncompressed_digest = nullptr;
    free(ptr);
}

bool invokeOciValidTime(char *time)
{
    return true;
}

static int init_log()
{
    struct isula_libutils_log_config lconf = { 0 };

    lconf.name = "registry_unit_test";
    lconf.file = nullptr;
    lconf.priority = "ERROR";
    lconf.driver = "stdout";
    if (isula_libutils_log_enable(&lconf)) {
        fprintf(stderr, "log init failed\n");
        return -1;
    }

    return 0;
}

void mockCommonAll(MockStorage *mock, MockOciImage *oci_image_mock)
{
    EXPECT_CALL(*mock, StorageImgCreate(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeStorageImgCreate));
    EXPECT_CALL(*mock, StorageImgGet(::testing::_)).WillRepeatedly(Invoke(invokeStorageImgGet));
    EXPECT_CALL(*mock, StorageImgGetSummary(::testing::_)).WillRepeatedly(Invoke(invokeStorageImgGetSummary));
    EXPECT_CALL(*mock, StorageImgSetBigData(::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeStorageImgSetBigData));
    EXPECT_CALL(*mock, StorageImgAddName(::testing::_, ::testing::_)).WillRepeatedly(Invoke(invokeStorageImgAddName));
    EXPECT_CALL(*mock, StorageImgDelete(::testing::_, ::testing::_)).WillRepeatedly(Invoke(invokeStorageImgDelete));
    EXPECT_CALL(*mock, StorageImgSetLoadedTime(::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeStorageImgSetLoadedTime));
    EXPECT_CALL(*mock, StorageImgSetImageSize(::testing::_)).WillRepeatedly(Invoke(invokeStorageImgSetImageSize));
    EXPECT_CALL(*mock, StorageGetImgTopLayer(::testing::_)).WillRepeatedly(Invoke(invokeStorageGetImgTopLayer));
    EXPECT_CALL(*mock, StorageLayerCreate(::testing::_, ::testing::_)).WillRepeatedly(Invoke(invokeStorageLayerCreate));
    EXPECT_CALL(*mock, StorageIncHoldRefs(::testing::_)).WillRepeatedly(Invoke(invokeStorageIncHoldRefs));
    EXPECT_CALL(*mock, StorageDecHoldRefs(::testing::_)).WillRepeatedly(Invoke(invokeStorageDecHoldRefs));
    EXPECT_CALL(*mock, StorageLayerGet(::testing::_)).WillRepeatedly(Invoke(invokeStorageLayerGet));
    EXPECT_CALL(*mock, StorageLayerTryRepairLowers(::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeStorageLayerTryRepairLowers));
    EXPECT_CALL(*mock, FreeLayerList(::testing::_)).WillRepeatedly(Invoke(invokeFreeLayerList));
    EXPECT_CALL(*mock, FreeLayer(::testing::_)).WillRepeatedly(Invoke(invokeFreeLayer));
    EXPECT_CALL(*oci_image_mock, OciValidTime(::testing::_)).WillRepeatedly(Invoke(invokeOciValidTime));
    EXPECT_CALL(*oci_image_mock, GetOciImageData()).WillRepeatedly(Invoke(invokeGetOciImageData));
    return;
}

int create_certs(std::string &dir)
{
    std::string ca = dir + "/ca.crt";
    std::string cert = dir + "/tls.cert";
    std::string key = dir + "/tls.key";

    // content of file is meaningless
    if (util_write_file(ca.c_str(), "1", 1, 0600) != 0 || util_write_file(cert.c_str(), "1", 1, 0600) != 0 ||
        util_write_file(key.c_str(), "1", 1, 0600) != 0) {
        ERROR("write certs file failed");
        return -1;
    }

    return 0;
}

int remove_certs(std::string &dir)
{
    std::string ca = dir + "/ca.crt";
    std::string cert = dir + "/tls.cert";
    std::string key = dir + "/tls.key";

    if (util_path_remove(ca.c_str()) != 0 || util_path_remove(cert.c_str()) != 0 ||
        util_path_remove(key.c_str()) != 0) {
        ERROR("remove certs file failed");
        return -1;
    }

    return 0;
}

TEST_F(RegistryUnitTest, test_pull_v1_image)
{
    registry_pull_options options;
    options.image_name = (char *)"quay.io/coreos/etcd:v3.3.17-arm64";
    options.dest_image_name = (char *)"quay.io/coreos/etcd:v3.3.17-arm64";
    options.auth.username = (char *)"test";
    options.auth.password = (char *)"test";
    options.skip_tls_verify = false;
    options.insecure_registry = false;

    std::string auths_dir = get_dir() + "/auths";
    std::string certs_dir = get_dir() + "/certs";
    std::string mirror_dir = certs_dir + "/hub-mirror.c.163.com";
    ASSERT_EQ(util_mkdir_p(auths_dir.c_str(), 0700), 0);
    ASSERT_EQ(util_mkdir_p(mirror_dir.c_str(), 0700), 0);
    ASSERT_EQ(create_certs(mirror_dir), 0);
    ASSERT_EQ(init_log(), 0);
    ASSERT_EQ(registry_init((char *)auths_dir.c_str(), (char *)certs_dir.c_str()), 0);

    EXPECT_CALL(m_http_mock, HttpRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeHttpRequestV1));
    mockCommonAll(&m_storage_mock, &m_oci_image_mock);
    ASSERT_EQ(registry_pull(&options), 0);

    ASSERT_EQ(registry_pull(&options), 0);

    ASSERT_EQ(registry_pull(&options), 0);
}

TEST_F(RegistryUnitTest, test_login)
{
    registry_login_options options = { 0 };

    EXPECT_CALL(m_http_mock, HttpRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeHttpRequestLogin));

    options.host = (char *)"test2.com";
    options.auth.username = (char *)"test2";
    options.auth.password = (char *)"test2";
    options.skip_tls_verify = true;
    options.insecure_registry = true;
    ASSERT_EQ(registry_login(&options), 0);

    options.host = (char *)"hub-mirror.c.163.com";
    options.auth.username = (char *)"test";
    options.auth.password = (char *)"test";
    ASSERT_EQ(registry_login(&options), 0);

    options.host = (char *)"hub-mirror.c.163.com";
    options.auth.username = (char *)"test3";
    options.auth.password = (char *)"test3";
    ASSERT_EQ(registry_login(&options), 0);
}

TEST_F(RegistryUnitTest, test_logout)
{
    char *auth_data = nullptr;
    std::string auths_file = get_dir() + "/auths/" + AUTH_FILE_NAME;

    ASSERT_EQ(registry_logout((char *)"test2.com"), 0);

    auth_data = util_read_text_file(auths_file.c_str());
    ASSERT_NE(strstr(auth_data, "hub-mirror.c.163.com"), nullptr);
    free(auth_data);
    auth_data = nullptr;
}

TEST_F(RegistryUnitTest, test_pull_v2_image)
{
    struct timespec start_time;
    struct timespec end_time;
    registry_pull_options options { 0x00 };
    options.image_name = (char *)"hub-mirror.c.163.com/library/busybox:latest";
    options.dest_image_name = (char *)"isula.org/library/busybox:latest";
    options.skip_tls_verify = true;
    options.insecure_registry = true;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    EXPECT_CALL(m_http_mock, HttpRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeHttpRequestV2));
    mockCommonAll(&m_storage_mock, &m_oci_image_mock);

    // test retry success
    ASSERT_EQ(registry_pull(&options), 0);

    // test cancel
    ASSERT_NE(registry_pull(&options), 0);

    // test not found
    ASSERT_NE(registry_pull(&options), 0);

    // test server error
    ASSERT_NE(registry_pull(&options), 0);

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    ASSERT_TRUE(end_time.tv_sec - start_time.tv_sec <= 10);
}

TEST_F(RegistryUnitTest, test_pull_oci_image)
{
    registry_pull_options *options = nullptr;

    options = (registry_pull_options *)util_common_calloc_s(sizeof(registry_pull_options));
    ASSERT_NE(options, nullptr);

    options->image_name = util_strdup_s("hub-mirror.c.163.com/library/busybox:latest");
    options->dest_image_name = util_strdup_s("isula.org/library/busybox:latest");
    options->auth.username = nullptr;
    options->auth.password = nullptr;
    options->skip_tls_verify = false;
    options->insecure_registry = false;
    EXPECT_CALL(m_http_mock, HttpRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeHttpRequestOCI));
    mockCommonAll(&m_storage_mock, &m_oci_image_mock);
    ASSERT_EQ(registry_pull(options), 0);

    free_registry_pull_options(options);
}

TEST_F(RegistryUnitTest, test_pull_already_exist)
{
    registry_pull_options options;
    options.image_name = (char *)"hub-mirror.c.163.com/library/busybox:latest";
    options.dest_image_name = (char *)"isula.org/library/busybox:latest";
    options.auth.username = (char *)"test";
    options.auth.password = (char *)"test";
    options.skip_tls_verify = true;
    options.insecure_registry = true;

    EXPECT_CALL(m_http_mock, HttpRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeHttpRequestV2));
    mockCommonAll(&m_storage_mock, &m_oci_image_mock);
    EXPECT_CALL(m_storage_mock, StorageLayerGet(::testing::_)).WillRepeatedly(Invoke(invokeStorageLayerGet1));
    ASSERT_EQ(registry_pull(&options), 0);

    options.image_name = (char *)"quay.io/coreos/etcd:v3.3.17-arm64";
    options.dest_image_name = (char *)"quay.io/coreos/etcd:v3.3.17-arm64";
    EXPECT_CALL(m_http_mock, HttpRequest(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(Invoke(invokeHttpRequestV1));
    EXPECT_CALL(m_storage_mock, StorageLayerGet(::testing::_)).WillRepeatedly(Invoke(invokeStorageLayerGet));
    EXPECT_CALL(m_storage_mock, StorageLayersGetByCompressDigest(::testing::_))
    .WillRepeatedly(Invoke(invokeStorageLayersGetByCompressDigest));
    ASSERT_NE(registry_pull(&options), 0);
}

TEST_F(RegistryUnitTest, test_aes)
{
    char *text = (char *)"test";
    unsigned char *encoded = nullptr;
    char *decoded = nullptr;
    ASSERT_EQ(aes_encode((unsigned char *)text, strlen(text), &encoded), 0);
    ASSERT_EQ(aes_decode(encoded, AES_256_CFB_IV_LEN + strlen(text), (unsigned char **)&decoded), 0);
    ASSERT_STREQ(decoded, text);
    free(encoded);
    free(decoded);
}

TEST_F(RegistryUnitTest, test_cleanup)
{
    std::string auths_key = get_dir() + "/auths/" + AUTH_AESKEY_NAME;
    std::string auths_file = get_dir() + "/auths/" + AUTH_FILE_NAME;
    std::string mirror_dir = get_dir() + "/certs" + "/hub-mirror.c.163.com";

    ASSERT_EQ(util_path_remove(auths_key.c_str()), 0);
    ASSERT_EQ(util_path_remove(auths_file.c_str()), 0);
    ASSERT_EQ(remove_certs(mirror_dir), 0);
}
