/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-07-15
 * Description: Controller common functions for tests
 ******************************************************************************/

#ifndef _ISULAD_TEST_SANDBOX_CONTROLLER_CONTROLLER_COMMON_H
#define _ISULAD_TEST_SANDBOX_CONTROLLER_CONTROLLER_COMMON_H
#include "controller.h"

const std::string DUMMY_SANDBOX_ID = "604db93a33ec4c7787e4f369338f5887";
const std::string DUMMY_CONTAINER_ID = "504db93a32ec4c9789e4d369a38f3889";
const std::string DUMMY_EXEC_ID = "504db93a32ec4c9789e4d369a38f37765";
const uint64_t SECOND_TO_NANOS = 1000000000;
const uint64_t DUMMY_CREATE_AT = 1588 * SECOND_TO_NANOS + 1588;
const uint64_t DUMMY_EXITED_AT = 1688 * SECOND_TO_NANOS + 1588;
const std::string DUMMY_TASK_ADDRESS = "vsock://18982:1";

std::unique_ptr<sandbox::ControllerMountInfo> CreateTestMountInfo();

std::unique_ptr<sandbox::ControllerCreateParams> CreateTestCreateParams();

std::unique_ptr<sandbox::ControllerStreamInfo> CreateTestStreamInfo();

std::unique_ptr<sandbox::ControllerPrepareParams> CreateTestPrepareParams();

std::unique_ptr<sandbox::ControllerUpdateResourcesParams> CreateTestUpdateResourcesParams(
    google::protobuf::Map<std::string, std::string> &annotations);

#endif // _ISULAD_TEST_SANDBOX_CONTROLLER_CONTROLLER_COMMON_H