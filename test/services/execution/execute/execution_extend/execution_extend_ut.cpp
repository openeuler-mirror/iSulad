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
 * Author: jikui
 * Create: 2020-02-25
 * Description: provide execution_extend unit test
 ******************************************************************************/

#include "execution_extend.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "runtime_mock.h"
#include "containers_store_mock.h"
#include "container_state_mock.h"
#include "sysinfo_mock.h"
#include "health_check_mock.h"
#include "collector_mock.h"
#include "container_unix_mock.h"
#include "image_mock.h"
#include "isulad_config_mock.h"
#include "containers_gc_mock.h"
#include "engine_mock.h"
#include "restartmanager_mock.h"
#include "container_operator_mock.h"
#include "verify_mock.h"
#include "specs_mock.h"
#include "callback.h"
#include "utils.h"

using ::testing::Args;
using ::testing::ByRef;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::NotNull;
using ::testing::AtLeast;
using ::testing::Invoke;
using ::testing::_;

using namespace std;

class ExecutionExtendUnitTest : public testing::Test {
public:
    void SetUp() override
    {
        MockRuntime_SetMock(&m_runtime);
        MockContainersStore_SetMock(&m_containersStore);
        MockCollector_SetMock(&m_collector);
        MockContainersGc_SetMock(&m_containersGc);
        MockContainersOperator_SetMock(&m_containersOperator);
        MockContainerUnix_SetMock(&m_containerUnix);
        MockHealthCheck_SetMock(&m_healthCheck);
        MockIsuladConf_SetMock(&m_isuladConf);
        MockImage_SetMock(&m_image);
        MockSysinfo_SetMock(&m_sysinfo);
        MockEngine_SetMock(&m_engine);
        MockVerify_SetMock(&m_verify);
        MockRestartmanager_SetMock(&m_restartmanager);
        MockContainerState_SetMock(&m_containerState);
        MockSpecs_SetMock(&m_specs);
        ::testing::Mock::AllowLeak(&m_runtime);
        ::testing::Mock::AllowLeak(&m_containersStore);
        ::testing::Mock::AllowLeak(&m_collector);
        ::testing::Mock::AllowLeak(&m_containersGc);
        ::testing::Mock::AllowLeak(&m_containersOperator);
        ::testing::Mock::AllowLeak(&m_containerUnix);
        ::testing::Mock::AllowLeak(&m_healthCheck);
        ::testing::Mock::AllowLeak(&m_image);
        ::testing::Mock::AllowLeak(&m_isuladConf);
        ::testing::Mock::AllowLeak(&m_sysinfo);
        ::testing::Mock::AllowLeak(&m_engine);
        ::testing::Mock::AllowLeak(&m_restartmanager);
        ::testing::Mock::AllowLeak(&m_containerState);
        ::testing::Mock::AllowLeak(&m_verify);
        ::testing::Mock::AllowLeak(&m_specs);
    }
    void TearDown() override
    {
        MockRuntime_SetMock(nullptr);
        MockContainersStore_SetMock(nullptr);
        MockCollector_SetMock(nullptr);
        MockContainersGc_SetMock(nullptr);
        MockContainerUnix_SetMock(nullptr);
        MockHealthCheck_SetMock(nullptr);
        MockImage_SetMock(nullptr);
        MockIsuladConf_SetMock(nullptr);
        MockSysinfo_SetMock(nullptr);
        MockEngine_SetMock(nullptr);
        MockRestartmanager_SetMock(nullptr);
        MockContainerState_SetMock(nullptr);
        MockVerify_SetMock(nullptr);
        MockSpecs_SetMock(nullptr);
    }

    NiceMock<MockRuntime> m_runtime;
    NiceMock<MockContainersStore> m_containersStore;
    NiceMock<MockCollector> m_collector;
    NiceMock<MockContainersGc> m_containersGc;
    NiceMock<MockContainersOperator> m_containersOperator;
    NiceMock<MockContainerUnix> m_containerUnix;
    NiceMock<MockHealthCheck> m_healthCheck;
    NiceMock<MockImage> m_image;
    NiceMock<MockIsuladConf> m_isuladConf;
    NiceMock<MockSysinfo> m_sysinfo;
    NiceMock<MockEngine> m_engine;
    NiceMock<MockRestartmanager> m_restartmanager;
    NiceMock<MockContainerState> m_containerState;
    NiceMock<MockVerify> m_verify;
    NiceMock<MockSpecs> m_specs;
};

int invokeRuntimePause(const char *name, const char *runtime, const rt_pause_params_t *params)
{
    return 0;
}

int invokeRuntimeResume(const char *name, const char *runtime, const rt_resume_params_t *params)
{
    return 0;
}

container_t *invokeContainersStoreGet(const char *id_or_name)
{
    if (id_or_name == nullptr) {
        return nullptr;
    }
    container_t *cont = (container_t *)util_common_calloc_s(sizeof(container_t));
    cont->common_config =
            (container_config_v2_common_config *)util_common_calloc_s(sizeof(container_config_v2_common_config));
    return cont;
}

bool invokeGcIsGcProgress(const char *id)
{
    return false;
}

int invokeContainerToDisk(const container_t *cont)
{
    return 0;
}

void invokeContainerUnlock(container_t *cont)
{
    return;
}

void invokeContainerLock(container_t *cont)
{
    return;
}

void invokeContainerUnref(container_t *cont)
{
    return;
}

void invokeUpdateHealthMonitor(const char *container_id)
{
    return;
}

bool invokeIsRunning(container_state_t *s)
{
    return true;
}

bool invokeIsPaused(container_state_t *s)
{
    return false;
}

void invokeStateResetPaused(container_state_t *s)
{
    return;
}

bool invokeIsRestarting(container_state_t *s)
{
    return false;
}

void invokeContainerStateSetError(container_state_t *s, const char *err)
{
    return;
}

void invokeStateSetPaused(container_state_t *s)
{
    return;
}

TEST_F(ExecutionExtendUnitTest, test_container_extend_callback_init_pause)
{
    service_container_callback_t cb;
    container_pause_request *request = (container_pause_request *)util_common_calloc_s(sizeof(container_pause_request));
    container_pause_response *response =
            (container_pause_response *)util_common_calloc_s(sizeof(container_pause_response));
    request->id = util_strdup_s("64ff21ebf4e4");

    EXPECT_CALL(m_runtime, RuntimePause(_, _, _)).WillRepeatedly(Invoke(invokeRuntimePause));
    EXPECT_CALL(m_containersStore, ContainersStoreGet(_)).WillRepeatedly(Invoke(invokeContainersStoreGet));
    EXPECT_CALL(m_containerState, IsRunning(_)).WillRepeatedly(Invoke(invokeIsRunning));
    EXPECT_CALL(m_containersOperator, IsGcProgress(_)).WillRepeatedly(Invoke(invokeGcIsGcProgress));
    EXPECT_CALL(m_containerState, IsPaused(_)).WillRepeatedly(Invoke(invokeIsPaused));
    EXPECT_CALL(m_containerState, IsRestarting(_)).WillRepeatedly(Invoke(invokeIsRestarting));
    EXPECT_CALL(m_containerUnix, ContainerToDisk(_)).WillRepeatedly(Invoke(invokeContainerToDisk));
    container_extend_callback_init(&cb);
    ASSERT_EQ(cb.pause(request, &response), 0);
    testing::Mock::VerifyAndClearExpectations(&m_runtime);
    testing::Mock::VerifyAndClearExpectations(&m_containersStore);
    testing::Mock::VerifyAndClearExpectations(&m_containerState);
    testing::Mock::VerifyAndClearExpectations(&m_containersGc);
    testing::Mock::VerifyAndClearExpectations(&m_containersOperator);
    testing::Mock::VerifyAndClearExpectations(&m_containerUnix);
}

TEST_F(ExecutionExtendUnitTest, test_container_extend_callback_init_resume)
{
    service_container_callback_t cb;
    container_resume_request *request =
            (container_resume_request *)util_common_calloc_s(sizeof(container_resume_request));
    container_resume_response *response =
            (container_resume_response *)util_common_calloc_s(sizeof(container_resume_response));
    request->id = util_strdup_s("64ff21ebf4e4");

    EXPECT_CALL(m_runtime, RuntimeResume(_, _, _)).WillRepeatedly(Invoke(invokeRuntimeResume));
    EXPECT_CALL(m_containersStore, ContainersStoreGet(_)).WillRepeatedly(Invoke(invokeContainersStoreGet));
    EXPECT_CALL(m_containerState, IsRunning(_)).WillRepeatedly(Invoke(invokeIsRunning));
    EXPECT_CALL(m_containersOperator, IsGcProgress(_)).WillRepeatedly(Invoke(invokeGcIsGcProgress));
    EXPECT_CALL(m_containerState, IsPaused(_)).WillOnce(Return(true));
    EXPECT_CALL(m_containerUnix, ContainerToDisk(_)).WillRepeatedly(Invoke(invokeContainerToDisk));
    container_extend_callback_init(&cb);
    ASSERT_EQ(cb.resume(request, &response), 0);
    testing::Mock::VerifyAndClearExpectations(&m_runtime);
    testing::Mock::VerifyAndClearExpectations(&m_containersStore);
    testing::Mock::VerifyAndClearExpectations(&m_containerState);
    testing::Mock::VerifyAndClearExpectations(&m_containersGc);
    testing::Mock::VerifyAndClearExpectations(&m_containersOperator);
    testing::Mock::VerifyAndClearExpectations(&m_containerUnix);
}
