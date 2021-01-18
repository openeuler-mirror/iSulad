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
 * Description: provide read write lock definition
 *********************************************************************************/
#ifndef UTILS_CPPUTILS_READ_WRITE_LOCK_H
#define UTILS_CPPUTILS_READ_WRITE_LOCK_H

#include <iostream>
#include <mutex>
#include <condition_variable>
#include <thread>

class RWMutex {
public:
    RWMutex() = default;
    ~RWMutex() = default;
    RWMutex(const RWMutex &) = delete;
    RWMutex(RWMutex &&) = delete;
    RWMutex &operator = (const RWMutex &) = delete;
    RWMutex &operator = (RWMutex &&) = delete;

    void rdlock();
    void wrlock();
    void unlock();

private:
    volatile long m_status {0};
    volatile long m_waiting_readers {0};
    volatile long m_waiting_writers {0};
    std::mutex m_mutex;
    std::condition_variable m_read_cond;
    std::condition_variable m_write_cond;
};

template<typename RWMutexType>
class ReadGuard {
public:
    explicit ReadGuard(RWMutexType &lock) : m_lock(lock)
    {
        m_lock.rdlock();
    }
    virtual ~ReadGuard()
    {
        m_lock.unlock();
    }

    ReadGuard() = delete;
    ReadGuard(const ReadGuard &) = delete;
    ReadGuard &operator=(const ReadGuard &) = delete;
    ReadGuard(const ReadGuard &&) = delete;
    ReadGuard &operator = (const ReadGuard &&) = delete;

private:
    RWMutexType &m_lock;
};


template<typename RWMutexType>
class WriteGuard {
public:
    explicit WriteGuard(RWMutexType &lock) : m_lock(lock)
    {
        m_lock.wrlock();
    }
    virtual ~WriteGuard()
    {
        m_lock.unlock();
    }

    WriteGuard() = delete;
    WriteGuard(const WriteGuard &) = delete;
    WriteGuard &operator=(const WriteGuard &) = delete;
    WriteGuard(const WriteGuard &&) = delete;
    WriteGuard &operator = (const WriteGuard &&) = delete;

private:
    RWMutexType &m_lock;
};

#endif // UTILS_CPPUTILS_READ_WRITE_LOCK_H
