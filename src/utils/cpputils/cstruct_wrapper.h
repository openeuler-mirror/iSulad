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
 * Author: zhongtao
 * Create: 2023-07-07
 * Description: provide cstruct wrapper
 *********************************************************************************/
#ifndef UTILS_CPPUTILS_CSTRUCTWRAPPER_H
#define UTILS_CPPUTILS_CSTRUCTWRAPPER_H

#include <iostream>
#include <memory>
#include <isula_libutils/utils_memory.h>

template<typename T>
class CStructWrapper {
public:
    explicit CStructWrapper(T* ptr, void (*deleter)(T*)) : m_ptr(ptr), m_deleter(deleter) {}

    ~CStructWrapper()
    {
        if (m_ptr) {
            m_deleter(m_ptr);
        }
    }

    T* get() const
    {
        return m_ptr;
    }

    T* move()
    {
        T* ptr = m_ptr;
        m_ptr = nullptr;
        return ptr;
    }
private:
    T* m_ptr;
    void (*m_deleter)(T*);
};

template<typename T>
std::unique_ptr<CStructWrapper<T>> makeUniquePtrCStructWrapper(void (*deleter)(T*))
{
    T* ptr = static_cast<T*>(isula_common_calloc_s(sizeof(T)));
    if (ptr == nullptr) {
        return nullptr;
    }

    return std::unique_ptr<CStructWrapper<T>>(new CStructWrapper<T>(ptr, deleter));
}

template<typename T>
std::unique_ptr<CStructWrapper<T>> makeUniquePtrCStructWrapper(T* ptr, void (*deleter)(T*))
{
    if (ptr == nullptr) {
        return nullptr;
    }
    return std::unique_ptr<CStructWrapper<T>>(new CStructWrapper<T>(ptr, deleter));
}

#endif // UTILS_CPPUTILS_CSTRUCTWRAPPER_H