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
 * Description: Package url parses URLs and implements query escaping.
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef __URL_H_
#define __URL_H_
#include <iostream>
#include <string>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <map>
#include <vector>
#include <sstream>
#include <numeric>

namespace url {
enum class EncodeMode : int {
    ENCODE_PATH = 1,
    ENCODE_PATH_SEGMENT,
    ENCODE_HOST,
    ENCODE_ZONE,
    ENCODE_USER_PASSWORD,
    ENCODE_QUERY_COMPONENT,
    ENCODE_FRAGMENT
};

class Values {
public:
    std::string Get(const std::string &key);
    void Set(const std::string &key, const std::string &value);
    void Add(const std::string &key, const std::string &value);
    void Del(const std::string &key);
    std::string Encode();
private:
    std::map<std::string, std::vector<std::string>> v;
};

class UserInfo {
public:
    UserInfo(const std::string &u, const std::string &p, bool b) : m_username(u), m_password(p),
        m_passwordSet(b) {}
    ~UserInfo() = default;
    std::string String() const ;
    std::string Username() const;
    std::string Password(bool &set) const;

private:
    std::string m_username;
    std::string m_password;
    bool m_passwordSet;
};

class URLDatum {
public:
    URLDatum() = default;
    ~URLDatum();
    std::string EscapedPath();
    std::string String();
    bool IsAbs() const ;
    std::unique_ptr<URLDatum> UrlParse(const std::string &ref);
    std::unique_ptr<URLDatum> ResolveReference(URLDatum *ref);
    auto Query()->std::map<std::string, std::vector<std::string>>;
    std::string RequestURI();
    std::string Hostname() const;
    std::string Port() const;
    int SetPath(const std::string &p);
    void SetScheme(const std::string &value)
    {
        m_scheme = value;
    }
    std::string GetScheme() const
    {
        return m_scheme;
    }
    void SetOpaque(const std::string &value)
    {
        m_opaque = value;
    }
    std::string  GetOpaque() const
    {
        return m_opaque;
    }
    void SetUser(UserInfo *value)
    {
        m_user = value;
    }
    UserInfo   *GetUser() const
    {
        return m_user;
    }
    void SetHost(const std::string &value)
    {
        m_host = value;
    }
    std::string  GetHost() const
    {
        return m_host;
    }
    void SetPathWithoutEscape(const std::string &value)
    {
        m_path = value;
    }
    std::string  GetPath() const
    {
        return m_path;
    }
    void SetForceQuery(bool value)
    {
        m_forceQuery = value;
    }
    bool GetForceQuery() const
    {
        return m_forceQuery;
    }
    void SetRawQuery(const std::string &value)
    {
        m_rawQuery = value;
    }
    std::string  GetRawQuery() const
    {
        return m_rawQuery;
    }
    void SetFragment(const std::string &value)
    {
        m_fragment = value;
    }
    std::string  GetFragment() const
    {
        return m_fragment;
    }

private:
    void StringOpaqueEmptyRules(std::string &buf);

private:
    std::string m_scheme;
    std::string m_opaque;
    UserInfo   *m_user{nullptr};
    std::string m_host;
    std::string m_path;
    std::string m_rawPath;
    bool        m_forceQuery{false};
    std::string m_rawQuery;
    std::string m_fragment;
};

bool IsHex(char c);
bool GetHexDigit(char c, char &d);
bool ShouldEscape(char c, const EncodeMode &mode);
std::string QueryUnescape(const std::string &s);
std::string Unescape(std::string s, const EncodeMode &mode);
std::string QueryEscape(const std::string &s);
std::string Escape(const std::string &s, const EncodeMode &mode);
UserInfo *UserPassword(const std::string &username, const std::string &password) noexcept;
UserInfo *User(const std::string &username) noexcept;
int Getscheme(const std::string &rawurl, std::string &scheme, std::string &path);
void Split(const std::string &s, const std::string &c, bool cutc, std::string &t, std::string &u);
URLDatum *Parse(const std::string &rawurl);
URLDatum *Parse(const std::string &rawurl, bool viaRequest);
int ParseAuthority(const std::string &authority, UserInfo **user, std::string &host);
int ParseHost(std::string host, std::string &out);
bool ValidEncodedPath(const std::string &s);
bool ValidOptionalPort(const std::string &port);
auto ParseQuery(const std::string &query)
->std::map<std::string, std::vector<std::string>>;
int ParseQuery(std::map<std::string, std::vector<std::string>> &m, std::string query);
std::string ResolvePath(const std::string &base, const std::string &ref);
std::string StripPort(const std::string &hostport);
std::string PortOnly(const std::string &hostport);
bool ValidUserinfo(const std::string &s);
} // namespace url

#endif


