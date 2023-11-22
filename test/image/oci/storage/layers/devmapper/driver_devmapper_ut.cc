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
 * Author: jikai
 * Create: 2023-11-22
 * Description: provide oci storage driver unit test for devmapper
 ******************************************************************************/

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "driver.h"
#include "driver_devmapper.h"
#include "driver_overlay2.h"
#include "mock.h"
#include "path.h"
#include "utils.h"
#include "util_archive.h"
#include "libdevmapper_mock.h"
#include "isulad_config_mock.h"
#include "wrapper_devmapper.h"

using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::_;

extern "C" {
    DECLARE_WRAPPER_V(util_exec_cmd, bool, (exec_func_t cb_func, void *args, const char *stdin_msg, char **stdout_msg, char **stderr_msg));
    DEFINE_WRAPPER_V(util_exec_cmd, bool, (exec_func_t cb_func, void *args, const char *stdin_msg, char **stdout_msg, char **stderr_msg),
                     (cb_func, args, stdin_msg, stdout_msg, stderr_msg));

    DECLARE_WRAPPER(util_mount, int, (const char *src, const char *dst, const char *mtype, const char *mntopts));
    DEFINE_WRAPPER(util_mount, int, (const char *src, const char *dst, const char *mtype, const char *mntopts), (src, dst, mtype, mntopts));

    DECLARE_WRAPPER(umount2, int, (const char *__special_file, int __flags));
    DEFINE_WRAPPER(umount2, int, (const char *__special_file, int __flags), (__special_file, __flags));

    DECLARE_WRAPPER(archive_unpack, int, (const io_read_wrapper *content, const char *dstdir, const archive_options *options, 
                                          const char *root_dir, char **errmsg));
    DEFINE_WRAPPER(archive_unpack, int, (const io_read_wrapper *content, const char *dstdir, const archive_options *options,
                                         const char *root_dir, char **errmsg),
                                         (content, dstdir, options, root_dir, errmsg));
}

static std::string GetDirectory()
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

    return static_cast<std::string>(abs_path) + "../../../../../../../test/image/oci/storage/layers/devmapper";
}

static bool invokeUtilExecCmd(exec_func_t cb_func, void *args, const char *stdin_msg, char **stdout_msg, char **stderr_msg)
{
    if (cb_func == nullptr || args == nullptr || stdout_msg == nullptr || stderr_msg == nullptr) {
        return false;
    }

    char **tmp_args = static_cast<char **>(args);

    if (util_array_len((const char **)tmp_args) < 1) {
        return false;
    }

    if (strcmp(tmp_args[0], "blkid") == 0) {
        *stdout_msg = util_strdup_s("4fa22307-0c88-4fa4-8f16-a9459e9cbc4a");
    }
    return true;
}

static struct dm_task *invokeDMTaskCreate(int type) {
    return static_cast<struct dm_task *>(util_common_calloc_s(sizeof(0)));
}

static void invokeDMTaskDestroy(struct dm_task *task) {
    free(task);
    return;
}

static int invokeDMTaskGetDriverVersion(struct dm_task *task, char *version, size_t size) {
    if (task == nullptr || version == nullptr || strncpy(version, "4.27.0", size) == NULL) {
        return 0;
    }

    return 1;
}

static int invokeDMTaskGetInfo(struct dm_task *task, struct dm_info *dmi) {
    if (task == nullptr || dmi == nullptr) {
        return 0;
    }

    dmi->exists = 1;
    return 1;
}

static void *invokeDMGetNextTarget(struct dm_task *task, void *next, uint64_t *start, uint64_t *length,
                                   char **target_type, char **params) {
    static char type[] = "thin-pool";
    static char par[] = "0 0/1024 0/1024";
    if (target_type) {
        *target_type = type;
    }
    if (params) {
        *params = par;
    }
    return nullptr;
}

class DriverDevmapperUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        MockLibdevmapper_SetMock(&m_libdevmapper_mock);
        MockIsuladConf_SetMock(&m_isulad_conf_mock);
        std::string isulad_dir { "/tmp/isulad/" };
        mkdir(isulad_dir.c_str(), 0755);
        std::string root_dir = isulad_dir + "data";
        std::string run_dir = isulad_dir + "data/run";
        std::string data_dir = GetDirectory() + "/data";
        std::string driver_home = root_dir + "/devicemapper";

        ASSERT_STRNE(util_clean_path(data_dir.c_str(), data_path, sizeof(data_path)), nullptr);
        std::string cp_command = "cp -r " + std::string(data_path) + " " + isulad_dir;
        ASSERT_EQ(system(cp_command.c_str()), 0);

        opts = (struct storage_module_init_options *)util_common_calloc_s(sizeof(struct storage_module_init_options));
        opts->storage_root = strdup(root_dir.c_str());
        opts->storage_run_root = strdup(run_dir.c_str());
        opts->driver_name = strdup("devicemapper");
        opts->driver_opts = (char **)util_common_calloc_s(6 * sizeof(char *));
        opts->driver_opts[0] = strdup("dm.thinpooldev=/dev/mapper/isulad0-thinpool");
        opts->driver_opts[1] = strdup("dm.fs=ext4");
        opts->driver_opts[2] = strdup("dm.min_free_space=10%");
        opts->driver_opts[3] = strdup("dm.basesize=12G");
        opts->driver_opts[4] = strdup("dm.mkfsarg=-q");
        opts->driver_opts[5] = strdup("dm.mountopt=rw");
        opts->driver_opts_len = 6;

        EXPECT_CALL(m_libdevmapper_mock, DMTaskCreate(_)).WillRepeatedly(Invoke(invokeDMTaskCreate));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskSetMessage(_, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskSetSector(_, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskSetAddNode(_, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskAddTarget(_, _, _, _, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskSetName(_, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskRun(_)).WillRepeatedly(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskDestroy(_)).WillRepeatedly(Invoke(invokeDMTaskDestroy));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskGetInfo(_, _)).WillRepeatedly(Invoke(invokeDMTaskGetInfo));
        EXPECT_CALL(m_libdevmapper_mock, DMGetNextTarget(_, _, _, _, _, _)).WillRepeatedly(Invoke(invokeDMGetNextTarget));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskSetCookie(_, _, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMUdevWait(_)).WillRepeatedly(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMUdevComplete(_)).WillRepeatedly(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskDeferredRemove(_)).WillRepeatedly(Return(1));

        char *names = static_cast<char *>(util_common_calloc_s(sizeof(struct dm_names) + strlen("isulad0-pool") + 1));
        struct dm_names *dname = (struct dm_names *)names;
        dname->dev = 1;
        dname->next = 0;
        strcpy(names + sizeof(struct dm_names), "isulad0-pool");
        EXPECT_CALL(m_libdevmapper_mock, DMTaskGetNames(_)).WillOnce(Return(dname));
        EXPECT_CALL(m_libdevmapper_mock, DMSetDevDir(_)).WillOnce(Return(1));
        EXPECT_CALL(m_libdevmapper_mock, DMTaskGetDriverVersion(_, _, _)).WillOnce(Invoke(invokeDMTaskGetDriverVersion));
        EXPECT_CALL(m_libdevmapper_mock, DMUdevGetSyncSupport()).WillOnce(Return(1));

        MOCK_SET_V(util_exec_cmd, invokeUtilExecCmd);
        MOCK_SET(util_mount, 0);
        MOCK_SET(umount2, 0);
        ASSERT_EQ(graphdriver_init(opts), 0);
        MOCK_CLEAR(util_exec_cmd);
        MOCK_CLEAR(util_mount);
        MOCK_CLEAR(umount2);
    }

    void TearDown() override
    {
        MOCK_SET(umount2, 0);
        ASSERT_EQ(graphdriver_cleanup(), 0);
        MOCK_CLEAR(umount2);

        MockLibdevmapper_SetMock(nullptr);
        MockIsuladConf_SetMock(nullptr);
        std::string rm_command = "rm -rf /tmp/isulad/";
        ASSERT_EQ(system(rm_command.c_str()), 0);

        if (opts != NULL) {
            free(opts->storage_root);
            free(opts->storage_run_root);
            free(opts->driver_name);
            util_free_array_by_len(opts->driver_opts, opts->driver_opts_len);
            free(opts);
        }
    }

    NiceMock<MockLibdevmapper> m_libdevmapper_mock;
    NiceMock<MockIsuladConf> m_isulad_conf_mock;
    char data_path[PATH_MAX] = { 0x00 };
    struct storage_module_init_options *opts = NULL;
};

TEST_F(DriverDevmapperUnitTest, test_devmapper_init)
{
    // cleanup before
    MOCK_SET(umount2, 0);
    ASSERT_EQ(graphdriver_cleanup(), 0);
    MOCK_CLEAR(umount2);

    std::string rm_command = "rm -rf /tmp/isulad/";
    ASSERT_EQ(system(rm_command.c_str()), 0);
    std::string mk_command = "mkdir -p /tmp/isulad/data/devicemapper/mnt";
    ASSERT_EQ(system(mk_command.c_str()), 0);
    char *names = static_cast<char *>(util_common_calloc_s(sizeof(struct dm_names) + strlen("isulad0-pool") + 1));
    struct dm_names *dname = (struct dm_names *)names;
    dname->dev = 1;
    dname->next = 0;
    strcpy(names + sizeof(struct dm_names), "isulad0-pool");
    EXPECT_CALL(m_libdevmapper_mock, DMTaskGetNames(_)).WillOnce(Return(dname));
    EXPECT_CALL(m_libdevmapper_mock, DMSetDevDir(_)).WillOnce(Return(1));
    EXPECT_CALL(m_libdevmapper_mock, DMTaskGetDriverVersion(_, _, _)).WillOnce(Invoke(invokeDMTaskGetDriverVersion));
    EXPECT_CALL(m_libdevmapper_mock, DMUdevGetSyncSupport()).WillOnce(Return(1));

    MOCK_SET_V(util_exec_cmd, invokeUtilExecCmd);
    MOCK_SET(util_mount, 0);
    MOCK_SET(umount2, 0);
    ASSERT_EQ(graphdriver_init(opts), 0);
    MOCK_CLEAR(util_exec_cmd);
    MOCK_CLEAR(util_mount);
    MOCK_CLEAR(umount2);
}

TEST_F(DriverDevmapperUnitTest, test_devmapper_layer_exists)
{
    std::string id { "3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f" };
    std::string incorrectId { "eb29745b8228e1e97c01b1d5c2554a319c00a94d8dd5746a3904222ad65a13f8" };
    ASSERT_TRUE(graphdriver_layer_exists(id.c_str()));
    ASSERT_FALSE(graphdriver_layer_exists(incorrectId.c_str()));
}

TEST_F(DriverDevmapperUnitTest, test_devmapper_create_rw)
{
    std::string id { "eb29745b8228e1e97c01b1d5c2554a319c00a94d8dd5746a3904222ad65a13f8" };
    struct driver_create_opts *create_opts;

    create_opts = (struct driver_create_opts *)util_common_calloc_s(sizeof(struct driver_create_opts));
    ASSERT_NE(create_opts, nullptr);

    create_opts->storage_opt = static_cast<json_map_string_string *>(util_common_calloc_s(sizeof(json_map_string_string)));
    ASSERT_NE(create_opts->storage_opt, nullptr);
    create_opts->storage_opt->keys = static_cast<char **>(util_common_calloc_s(sizeof(char *)));
    create_opts->storage_opt->values = static_cast<char **>(util_common_calloc_s(sizeof(char *)));
    create_opts->storage_opt->keys[0] = strdup("size");
    create_opts->storage_opt->values[0] = strdup("12G");
    create_opts->storage_opt->len = 1;

    ASSERT_EQ(graphdriver_create_rw(id.c_str(), nullptr, create_opts), 0);
    ASSERT_TRUE(graphdriver_layer_exists(id.c_str()));
    free_driver_create_opts(create_opts);
}

TEST_F(DriverDevmapperUnitTest, test_devmapper_create_ro)
{
    std::string id { "eb29745b8228e1e97c01b1d5c2554a319c00a94d8dd5746a3904222ad65a13f8" };
    struct driver_create_opts *create_opts;

    create_opts = (struct driver_create_opts *)util_common_calloc_s(sizeof(struct driver_create_opts));
    ASSERT_NE(create_opts, nullptr);

    create_opts->storage_opt = static_cast<json_map_string_string *>(util_common_calloc_s(sizeof(json_map_string_string)));
    ASSERT_NE(create_opts->storage_opt, nullptr);
    create_opts->storage_opt->keys = static_cast<char **>(util_common_calloc_s(sizeof(char *)));
    create_opts->storage_opt->values = static_cast<char **>(util_common_calloc_s(sizeof(char *)));
    create_opts->storage_opt->keys[0] = strdup("size");
    create_opts->storage_opt->values[0] = strdup("12G");
    create_opts->storage_opt->len = 1;

    ASSERT_EQ(graphdriver_create_ro(id.c_str(), nullptr, create_opts), 0);
    ASSERT_TRUE(graphdriver_layer_exists(id.c_str()));
    free_driver_create_opts(create_opts);
}

TEST_F(DriverDevmapperUnitTest, test_devmapper_rm_layer)
{
    std::string existed_id { "3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f" };
    std::string not_existed_id { "eb29745b8228e1e97c01b1d5c2554a319c00a94d8dd5746a3904222ad65a13f8" };

    ASSERT_EQ(graphdriver_rm_layer(existed_id.c_str()), 0);
    ASSERT_EQ(graphdriver_rm_layer(not_existed_id.c_str()), 0);
}

TEST_F(DriverDevmapperUnitTest, test_devmapper_mount_layer)
{
    std::string id { "3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f" };
    std::string merged_dir = "/tmp/isulad/data/devicemapper/mnt/" + id + "/rootfs";
    struct driver_mount_opts *mount_opts = nullptr;
    char* mount_dir = nullptr;

    MOCK_SET(util_mount, 0);
    mount_dir = graphdriver_mount_layer(id.c_str(), mount_opts);
    ASSERT_STREQ(mount_dir, merged_dir.c_str());
    MOCK_CLEAR(util_mount);

    MOCK_SET(umount2, 0);
    ASSERT_EQ(graphdriver_umount_layer(id.c_str()), 0);
    MOCK_CLEAR(umount2);
    free(mount_dir);
    mount_dir = nullptr;

    mount_opts = static_cast<struct driver_mount_opts *>(util_common_calloc_s(sizeof(struct driver_mount_opts)));
    ASSERT_NE(mount_opts, nullptr);
    mount_opts->options = static_cast<char **>(util_common_calloc_s(1 * sizeof(char *)));
    mount_opts->options[0] = strdup("ro");
    mount_opts->options_len = 1;

    MOCK_SET(util_mount, 0);
    mount_dir = graphdriver_mount_layer(id.c_str(), mount_opts);
    ASSERT_STREQ(mount_dir, merged_dir.c_str());
    MOCK_CLEAR(util_mount);

    MOCK_SET(umount2, 0);
    ASSERT_EQ(graphdriver_umount_layer(id.c_str()), 0);
    MOCK_CLEAR(umount2);
    free_driver_mount_opts(mount_opts);
}

TEST_F(DriverDevmapperUnitTest, test_devmapper_get_data)
{
    std::string id { "3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f" };

    container_inspect_graph_driver *inspect = graphdriver_get_metadata(id.c_str());
    ASSERT_NE(inspect, nullptr);
    ASSERT_STREQ(inspect->data->device_id, "4");
    ASSERT_STREQ(inspect->data->device_size, "10737418240");
    ASSERT_STREQ(inspect->data->merged_dir, "/tmp/isulad/data/devicemapper/mnt/3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f/rootfs");
    free_container_inspect_graph_driver(inspect);

    EXPECT_CALL(m_libdevmapper_mock, DMUdevGetSyncSupport()).WillOnce(Return(1));

    struct graphdriver_status *status = graphdriver_get_status();
    ASSERT_NE(status, nullptr);
    ASSERT_STREQ(status->driver_name, "devicemapper");
    free_graphdriver_status(status);

    ASSERT_EQ(devmapper_repair_lowers(nullptr, nullptr, nullptr), 0);
    ASSERT_EQ(devmapper_get_layer_fs_info(nullptr, nullptr, nullptr), 0);
}

TEST_F(DriverDevmapperUnitTest, test_devmapper_apply_diff)
{
    struct io_read_wrapper reader = {0};
    std::string id { "3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f" };
    MOCK_SET(util_mount, 0);
    MOCK_SET(archive_unpack, 0);
    MOCK_SET(umount2, 0);
    EXPECT_CALL(m_isulad_conf_mock, ConfGetISuladRootDir()).WillOnce(Return(util_strdup_s("/tmp/isulad")));
    ASSERT_EQ(graphdriver_apply_diff(id.c_str(), &reader), 0);
    MOCK_CLEAR(archive_unpack);
    MOCK_CLEAR(util_mount);
    MOCK_CLEAR(umount2);
}

TEST_F(DriverDevmapperUnitTest, test_wrapper_devmapper)
{
    ASSERT_STREQ(dev_strerror(ERR_TASK_RUN), "Task run error");
    ASSERT_STREQ(dev_strerror(ERR_TASK_SET_COOKIE), "Task set cookie error");
    ASSERT_STREQ(dev_strerror(ERR_NIL_COOKIE), "cookie ptr can't be nil");
    ASSERT_STREQ(dev_strerror(ERR_TASK_SET_ADD_NODE), "Task add dm node failed");
    ASSERT_STREQ(dev_strerror(ERR_BUSY), "Device busy");
    ASSERT_STREQ(dev_strerror(ERR_DEVICE_ID_EXISTS), "Device exists already");
    ASSERT_STREQ(dev_strerror(ERR_ENXIO), "No such device of address");
    ASSERT_STREQ(dev_strerror(ERR_TASK_ADD_TARGET), "Task add target device error");
    ASSERT_STREQ(dev_strerror(ERR_TASK_DEFERRED_REMOVE), "dm_task_deferred_remove failed");
    ASSERT_STREQ(dev_strerror(100), "Unknown error");
}