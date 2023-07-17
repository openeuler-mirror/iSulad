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
template<typename T>
class CStructWrapper
{
public:
    explicit CStructWrapper(T* ptr, void (*deleter)(T*)) : m_ptr(ptr), m_deleter(deleter) {}

    ~CStructWrapper()
    {
        if (m_ptr)
        {
            m_deleter(m_ptr);
        }
    }

    T* get() const { return m_ptr; }

private:
    T* m_ptr;
    void (*m_deleter)(T*);
};
#endif // UTILS_CPPUTILS_CSTRUCTWRAPPER_H