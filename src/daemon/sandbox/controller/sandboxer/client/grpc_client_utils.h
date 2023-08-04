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
 * Create: 2023-07-28
 * Description: grpc client utils functions
 ******************************************************************************/

#ifndef DAEMON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_GRPC_CLIENT_UTILS_H
#define DAEMON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_GRPC_CLIENT_UTILS_H

#include <google/protobuf/timestamp.pb.h>

uint64_t TimestampToNanos(const google::protobuf::Timestamp &timestamp);

#endif // DAEMON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_GRPC_CLIENT_UTILS_H