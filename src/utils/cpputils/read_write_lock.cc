/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2021-01-18
 * Description: provide read write lock implementation
 *********************************************************************************/

#include "read_write_lock.h"

void RWMutex::rdlock()
{
    std::unique_lock<std::mutex> autoLock(m_mutex);
    ++m_waiting_readers;
    m_read_cond.wait(autoLock, [&]() {
        return m_waiting_writers == 0 && m_status >= 0;
    });
    --m_waiting_readers;
    ++m_status;
}

void RWMutex::wrlock()
{
    std::unique_lock<std::mutex> autoLock(m_mutex);
    ++m_waiting_writers;
    m_write_cond.wait(autoLock, [&]() {
        return m_status == 0;
    });
    --m_waiting_writers;
    --m_status;
}

void RWMutex::unlock()
{
    std::unique_lock<std::mutex> autoLock(m_mutex);

    if (m_status == -1) { // one writer
        m_status = 0;
    } else if (m_status > 0) { // one or multiple readers
        --m_status;
    } else { // neither readers nor writers
        return;
    }

    if (m_waiting_writers > 0) {
        if (m_status == 0) {
            m_write_cond.notify_one();
        }
    } else {
        m_read_cond.notify_all();
    }
}
