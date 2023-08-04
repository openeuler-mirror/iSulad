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

#include "grpc_client_utils.h"

const uint64_t SECOND_TO_NANOS = 1000000000;
const int64_t MAX_SECONDS_FOR_TIMESTAMP = 253402300799; // 9999-12-31T23:59:59Z
const int32_t MAX_NANOS_FOR_TIMESTAMP = 999999999;

auto TimestampToNanos(const google::protobuf::Timestamp &timestamp) -> uint64_t
{
    int64_t seconds = 0;
    int32_t nanos = 0;

    seconds = timestamp.seconds();
    seconds = seconds < 0 ? 0 : seconds;
    seconds = seconds > MAX_SECONDS_FOR_TIMESTAMP ? MAX_SECONDS_FOR_TIMESTAMP : seconds;

    nanos = timestamp.nanos();
    nanos = nanos < 0 ? 0 : nanos;
    nanos = nanos > MAX_NANOS_FOR_TIMESTAMP ? MAX_NANOS_FOR_TIMESTAMP : nanos;

    return seconds * SECOND_TO_NANOS + nanos;
}
