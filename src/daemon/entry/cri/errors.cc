/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide err functions
 ********************************************************************************/

#include "errors.h"

#include <cstdarg>

Errors::Errors()
{
    m_message.clear();
    m_code = 0;
}

Errors &Errors::operator=(const Errors &other)
{
    if (&other == this) {
        return *this;
    }

    m_message = other.m_message;
    m_code = other.m_code;
    return *this;
}

Errors::~Errors()
{
    Clear();
}

void Errors::Clear()
{
    m_message.clear();
    m_code = 0;
}

std::string &Errors::GetMessage()
{
    return m_message;
}

const char *Errors::GetCMessage() const
{
    return m_message.empty() ? "" : m_message.c_str();
}

int Errors::GetCode() const
{
    return m_code;
}

bool Errors::Empty() const
{
    return (m_message.empty() && (m_code == 0));
}

bool Errors::NotEmpty() const
{
    return !Empty();
}

void Errors::SetError(const char *msg)
{
    m_message = msg ? msg : "";
}

void Errors::SetError(const std::string &msg)
{
    m_message = msg;
}

void Errors::AppendError(const std::string &msg)
{
    m_message.append(msg);
}

void Errors::SetAggregate(const std::vector<std::string> &msgs)
{
    std::string result;
    size_t size = msgs.size();

    if (size == 0) {
        return;
    }

    if (size == 1) {
        m_message = msgs[0];
        return;
    }

    result = "[" + msgs[0];
    for (size_t i = 1; i < size; i++) {
        result += " " + msgs[i];
    }
    result += "]";
    m_message = result;
}

void Errors::Errorf(const char *fmt, ...)
{
    int ret { 0 };
    char errbuf[BUFSIZ + 1] { 0 };
    va_list argp;

    va_start(argp, fmt);

    ret = vsnprintf(errbuf, BUFSIZ, fmt, argp);
    va_end(argp);
    if (ret < 0 || ret >= BUFSIZ) {
        m_message = "Error message is too long";
        return;
    }

    m_message = errbuf;
}
