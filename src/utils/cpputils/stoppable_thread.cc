/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2019-4-19
 * Description: provide stoppable thread functions
 *********************************************************************************/

#include "stoppable_thread.h"

StoppableThread &StoppableThread::operator=(StoppableThread &&obj) noexcept
{
    m_exit_signal = std::move(obj.m_exit_signal);
    m_future_obj = std::move(obj.m_future_obj);
    return *this;
}

bool StoppableThread::stopRequested()
{
    return m_future_obj.wait_for(std::chrono::milliseconds(0)) != std::future_status::timeout;
}

void StoppableThread::stop()
{
    m_exit_signal.set_value();
}
