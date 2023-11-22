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
 * Author: jikai
 * Create: 2023-11-22
 * Description: provide lib device mapper mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_DEVMAPPER_MOCK_H
#define _ISULAD_TEST_MOCKS_DEVMAPPER_MOCK_H

#include <gmock/gmock.h>

#include <libdevmapper.h>

class MockLibdevmapper {
public:
    virtual ~MockLibdevmapper() = default;
    MOCK_METHOD1(DMTaskCreate, struct dm_task*(int type));
    MOCK_METHOD2(DMTaskSetMessage, int(struct dm_task *dmt, const char *msg));
    MOCK_METHOD2(DMTaskSetSector, int(struct dm_task *dmt, uint64_t sector));
    MOCK_METHOD2(DMTaskSetAddNode, int(struct dm_task *dmt, dm_add_node_t add_node));
    MOCK_METHOD5(DMTaskAddTarget, int(struct dm_task *dmt, uint64_t start, uint64_t size, const char *ttype, const char *params));
    MOCK_METHOD1(DMSetDevDir, int(const char *dir));
    MOCK_METHOD2(DMTaskSetName, int(struct dm_task *dmt, const char *name));
    MOCK_METHOD1(DMTaskRun, int(struct dm_task *dmt));
    MOCK_METHOD3(DMTaskGetDriverVersion, int(struct dm_task *dmt, char *version, size_t size));
    MOCK_METHOD1(DMTaskDestroy, void(struct dm_task *dmt));
    MOCK_METHOD2(DMGetLibraryVersion, int(char *version, size_t size));
    MOCK_METHOD2(DMTaskGetInfo, int(struct dm_task *dmt, struct dm_info *info));
    MOCK_METHOD6(DMGetNextTarget, void*(struct dm_task *dmt, void *next, uint64_t *start, uint64_t *length,
			                            char **target_type, char **params));
    MOCK_METHOD3(DMTaskSetCookie, int(struct dm_task *dmt, uint32_t *cookie, uint16_t flags));
    MOCK_METHOD1(DMUdevWait, int(uint32_t cookie));
    MOCK_METHOD1(DMUdevComplete, int(uint32_t cookie));
    MOCK_METHOD1(DMTaskDeferredRemove, int(struct dm_task *dmt));
    MOCK_METHOD1(DMTaskGetNames, struct dm_names *(struct dm_task *dmt));
    MOCK_METHOD0(DMUdevGetSyncSupport, int(void));
    MOCK_METHOD1(DMUdevSetSyncSupport, void(int sync_with_udev));
    MOCK_METHOD1(DMLogWithErrnoInit, void(void log_cb(int level, const char *file, int line, int dm_errno_or_class, const char *f, ...)));
};

void MockLibdevmapper_SetMock(MockLibdevmapper* mock);

#endif
