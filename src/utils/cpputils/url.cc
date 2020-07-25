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
 * Description: provide url functions
 *********************************************************************************/
#include "url.h"
#include <new>
#include "cxxutils.h"
#include "isula_libutils/log.h"
namespace url {
bool IsHex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

bool GetHexDigit(char c, char &d)
{
    if (!IsHex(c)) {
        return false;
    }

    if (c >= '0' && c <= '9') {
        d = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        d = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        d = c - 'A' + 10;
    }
    return true;
}

int SpecificCharacterCheck(char c, const EncodeMode &mode, bool &result)
{
    int ret = -1;

    if (std::string("-._~").find(c) != std::string::npos) {
        result = false;
    } else if (std::string("&,;?@$+=:/").find(c) != std::string::npos) {
        switch (mode) {
            case EncodeMode::ENCODE_PATH:
                result = (c == '?');
                break;
            case EncodeMode::ENCODE_PATH_SEGMENT:
                result = (c == '/' || c == ';' || c == ',' || c == '?');
                break;
            case EncodeMode::ENCODE_USER_PASSWORD:
                result = (c == '@' || c == '/' || c == '?' || c == ':');
                break;
            case EncodeMode::ENCODE_QUERY_COMPONENT:
                result = true;
                break;
            case EncodeMode::ENCODE_FRAGMENT:
                result = false;
                break;
            default:
                ret = 0;
        }
    } else {
        ret = 0;
    }

    return ret;
}

bool ShouldEscape(char c, const EncodeMode &mode)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
        return false;
    }
    if (mode == EncodeMode::ENCODE_HOST || mode == EncodeMode::ENCODE_ZONE) {
        std::string subDelims = "!$&()'*+,;=:[]<>\"";
        if (subDelims.find(c) != std::string::npos) {
            return false;
        }
    }

    bool result = false;
    int ret = SpecificCharacterCheck(c, mode, result);
    if (ret != 0) {
        return result;
    }

    if (mode == EncodeMode::ENCODE_FRAGMENT) {
        if (std::string("!()*").find(c) != std::string::npos) {
            return false;
        }
    }
    return true;
}

std::string QueryUnescape(const std::string &s)
{
    return Unescape(s, EncodeMode::ENCODE_QUERY_COMPONENT);
}

int UnescapeDealWithPercentSign(size_t &i, std::string &s, const EncodeMode &mode)
{
    if ((size_t)(i + 2) >= s.length() || !IsHex(s[i + 1]) || !IsHex(s[i + 2])) {
        s.erase(s.begin(), s.begin() + (long)i);
        if (s.length() > 3) {
            s.erase(s.begin() + 3, s.end());
        }
        ERROR("invalid URL escape %s", s.c_str());  // quoted
        return -1;
    }
    char s1, s2;
    if (!GetHexDigit(s[i + 1], s1) || !GetHexDigit(s[i + 2], s2)) {
        return -1;
    }
    if (mode == EncodeMode::ENCODE_HOST && s1 < 8 &&
        std::string(s.begin() + (long)i, s.begin() + (long)i + 3) != "%25") {
        ERROR("invalid URL escape %s", std::string(s.begin() + (long)i, s.begin() + (long)i + 3).c_str());
        return -1;
    }
    if (mode == EncodeMode::ENCODE_ZONE) {
        char v = (char)(((unsigned char)s1 << 4) | (unsigned char)s2);
        if (std::string(s.begin() + (long)i, s.begin() + (long)i + 3) != "%25" &&
            v != ' ' && ShouldEscape(v, EncodeMode::ENCODE_HOST)) {
            ERROR("invalid URL escape %s", std::string(s.begin() + (long)i, s.begin() + (long)i + 3).c_str());
            return -1;
        }
    }
    return 0;
}

int CalculatePercentNum(std::string &s, const EncodeMode &mode, bool &hasPlus)
{
    int n = 0;

    for (size_t i = 0; i < s.length();) {
        switch (s.at(i)) {
            case '%': {
                    n++;
                    if (UnescapeDealWithPercentSign(i, s, mode)) {
                        return -1;
                    }
                    i += 3;
                }
                break;
            case '+': {
                    hasPlus = (mode == EncodeMode::ENCODE_QUERY_COMPONENT);
                    i++;
                }
                break;
            default:
                if ((mode == EncodeMode::ENCODE_HOST || mode == EncodeMode::ENCODE_ZONE) &&
                    s[i] < 0x80 && ShouldEscape(s[i], mode)) {
                    ERROR("invalid URL escape %s", std::string(s.begin() + (long)i, s.begin() + (long)i + 1).c_str());
                    return -1;
                }
                i++;
        }
    }
    return n;
}

void DoUnescape(std::string &t, const std::string &s, const EncodeMode &mode)
{
    int j = 0;
    for (size_t i = 0; i < s.length();) {
        switch (s[i]) {
            case '%': {
                    char s1, s2;
                    if (!GetHexDigit(s[i + 1], s1) || !GetHexDigit(s[i + 2], s2)) {
                        return;
                    }
                    t[j++] = (char)(((unsigned char)s1 << 4) | (unsigned char)s2);
                    i += 3;
                }
                break;
            case '+': {
                    if (mode == EncodeMode::ENCODE_QUERY_COMPONENT) {
                        t[j++] = ' ';
                    } else {
                        t[j++] = '+';
                    }
                    i++;
                }
                break;
            default:
                t[j++] = s[i++];
                break;
        }
    }
}

std::string Unescape(std::string s, const EncodeMode &mode)
{
    bool hasPlus = false;
    int n = CalculatePercentNum(s, mode, hasPlus);
    if (n < 0) {
        return "";
    }

    if (n == 0 && !hasPlus) {
        return s;
    }

    std::string t;
    t.resize(s.length() - 2 * n, '0');
    DoUnescape(t, s, mode);
    return t;
}

std::string QueryEscape(const std::string &s)
{
    return Escape(s, EncodeMode::ENCODE_QUERY_COMPONENT);
}

std::string Escape(const std::string &s, const EncodeMode &mode)
{
    size_t spaceCount = 0;
    size_t hexCount = 0;
    for (size_t i = 0; i < s.length(); i++) {
        char c = s[i];
        if (ShouldEscape(c, mode)) {
            if (c == ' ' && mode == EncodeMode::ENCODE_QUERY_COMPONENT) {
                spaceCount++;
            } else {
                hexCount++;
            }
        }
    }

    if (spaceCount == 0 && hexCount == 0) {
        return s;
    }

    std::string t;
    t.resize(s.length() + 2 * hexCount, '0');
    int j = 0;
    for (size_t i = 0; i < s.length(); ++i) {
        char c = s[i];
        if (c == ' ' && mode == EncodeMode::ENCODE_QUERY_COMPONENT) {
            t[j++] = '+';
        } else if (ShouldEscape(c, mode)) {
            t[j] = '%';
            t[j + 1] = "0123456789ABCDEF"[(unsigned char)c >> 4];
            t[j + 2] = "0123456789ABCDEF"[c & 15];
            j += 3;
        } else {
            t[j++] = s[i];
        }
    }
    return t;
}

UserInfo *User(const std::string &username) noexcept
{
    return new UserInfo { username, "", false };
}

UserInfo *UserPassword(const std::string &username, const std::string &password) noexcept
{
    return new UserInfo { username, password, true };
}

int Getscheme(const std::string &rawurl, std::string &scheme, std::string &path)
{
    for (size_t i = 0; i < rawurl.length(); ++i) {
        char c = rawurl[i];
        if (isalpha(c)) {
            continue;
        } else if (isdigit(c) || c == '+' || c == '-' || c == '.') {
            if (i == 0) {
                scheme = "";
                path = rawurl;
                return 0;
            }
        } else if (c == ':') {
            if (i == 0) {
                scheme = "";
                path = "";
                ERROR("missing protocol scheme");
                return -1;
            }
            scheme = std::string(rawurl.begin(), rawurl.begin() + (long)i);
            path = std::string(rawurl.begin() + (long)i + 1, rawurl.end());
            return 0;
        } else {
            scheme = "";
            path = rawurl;
            return 0;
        }
    }
    scheme = "";
    path = rawurl;
    return 0;
}

void Split(const std::string &s, const std::string &c, bool cutc, std::string &t, std::string &u)
{
    size_t i = s.find(c);
    if (i == std::string::npos) {
        t = s;
        u = "";
        return;
    }
    if (cutc) {
        t = s.substr(0, i);
        u = s.substr(i + c.length(), s.size());
        return;
    }
    t = s.substr(0, i);
    u = s.substr(i, s.size());
}

URLDatum *Parse(const std::string &rawurl)
{
    std::string u, frag;
    Split(rawurl, "#", true, u, frag);
    auto url = Parse(u, false);
    if (url == nullptr) {
        return nullptr;
    }
    if (frag.empty()) {
        return url;
    }
    url->SetFragment(Unescape(frag, EncodeMode::ENCODE_FRAGMENT));
    if (url->GetFragment().empty()) {
        return nullptr;
    }
    return url;
}

int SplitOffPossibleLeading(std::string &scheme, const std::string &rawurl, URLDatum *url, std::string &rest)
{
    if (Getscheme(rawurl, scheme, rest)) {
        return -1;
    }
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), ::tolower);
    if (rest.at(rest.length() - 1) == '?' &&
        std::count(rest.begin(), rest.end(), '?') == 1) {
        url->SetForceQuery(true);
        rest = rest.substr(0, rest.length() - 1);
    } else {
        std::string rawQuery = url->GetRawQuery();
        Split(rest, "?", true, rest, rawQuery);
        url->SetRawQuery(rawQuery);
    }
    return 0;
}

URLDatum *HandleNonBackslashPrefix(URLDatum *url, const std::string &scheme,
                                   const std::string &rest, bool viaRequest, bool &should_ret)
{
    if (rest.at(0) == '/') {
        return nullptr;
    }
    if (!scheme.empty()) {
        should_ret = true;
        url->SetOpaque(rest);
        return url;
    }
    if (viaRequest) {
        should_ret = true;
        ERROR("invalid URI for request");
        return nullptr;
    }
    size_t colon = rest.find(":");
    size_t slash = rest.find("/");
    if (colon != std::string::npos && (slash == std::string::npos || colon < slash)) {
        should_ret = true;
        ERROR("first path segment in URL cannot contain colon");
        return nullptr;
    }
    return nullptr;
}

int SetURLDatumInfo(URLDatum *url, const std::string &scheme, bool viaRequest, std::string &rest)
{
    if ((!scheme.empty() || (!viaRequest && rest.substr(0, 3) == "///")) && rest.substr(0, 2) == "//") {
        std::string authority;
        Split(rest.substr(2, rest.size()), "/", false, authority, rest);
        std::string host = url->GetHost();
        UserInfo *user = url->GetUser();
        if (ParseAuthority(authority, &user, host)) {
            return -1;
        }
        url->SetHost(host);
        url->SetUser(user);
    }
    if (url->SetPath(rest)) {
        return -1;
    }
    url->SetScheme(scheme);
    return 0;
}

URLDatum *Parse(const std::string &rawurl, bool viaRequest)
{
    if (rawurl.empty() && viaRequest) {
        ERROR("empty url!");
        return nullptr;
    }
    URLDatum *url = new (std::nothrow) URLDatum;
    if (url == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }
    if (rawurl == "*") {
        url->SetPathWithoutEscape("*");
        return url;
    }
    std::string scheme = url->GetScheme();
    std::string rest;
    if (SplitOffPossibleLeading(scheme, rawurl, url, rest)) {
        return nullptr;
    }
    bool should_ret = false;
    auto tmpret = HandleNonBackslashPrefix(url, scheme, rest, viaRequest, should_ret);
    if (should_ret) {
        return tmpret;
    }
    if (SetURLDatumInfo(url, scheme, viaRequest, rest)) {
        return nullptr;
    }
    return url;
}

int ParseAuthority(const std::string &authority, UserInfo **user, std::string &host)
{
    size_t i = authority.find("@");
    if (i == std::string::npos) {
        if (ParseHost(authority, host)) {
            *user = nullptr;
            host = "";
            return -1;
        }
    } else {
        if (ParseHost(authority.substr(i + 1, authority.size()), host)) {
            *user = nullptr;
            host = "";
            return -1;
        }
    }
    if (i == std::string::npos) {
        *user = nullptr;
        return 0;
    }

    std::string userinfo = authority.substr(0, i);
    if (!ValidUserinfo(userinfo)) {
        *user = nullptr;
        host = "";
        ERROR("net/url: invalid userinfo");
        return -1;
    }
    if (userinfo.find(":") == std::string::npos) {
        userinfo = Unescape(userinfo, EncodeMode::ENCODE_USER_PASSWORD);
        if (userinfo.empty()) {
            *user = nullptr;
            host = "";
            return -1;
        }
        *user = User(userinfo);
    } else {
        std::string servername, serverword;
        Split(userinfo, ":", true, servername, serverword);
        servername = Unescape(servername, EncodeMode::ENCODE_USER_PASSWORD);
        serverword = Unescape(serverword, EncodeMode::ENCODE_USER_PASSWORD);
        if (servername.empty() || serverword.empty()) {
            *user = nullptr;
            host = "";
            return -1;
        }
        *user = UserPassword(servername, serverword);
    }
    return 0;
}

int ParseHost(std::string host, std::string &out)
{
    if (host.at(0) == '[') {
        size_t i = host.find_last_of("]");
        if (i == std::string::npos) {
            ERROR("missing ']' in host");
            out = "";
        }
        std::string colonPort = host.substr(i + 1, host.size());
        if (!ValidOptionalPort(colonPort)) {
            out = "";
            ERROR("invalid port %s after host", colonPort.c_str());
            return -1;
        }
        size_t zone = host.substr(0, i).find("%25");
        if (zone != std::string::npos) {
            std::string host1 = Unescape(host.substr(0, zone), EncodeMode::ENCODE_HOST);
            if (host1.empty()) {
                out = "";
                return -1;
            }
            std::string host2 = Unescape(host.substr(zone, i), EncodeMode::ENCODE_ZONE);
            if (host2.empty()) {
                out = "";
                return -1;
            }
            std::string host3 = Unescape(host.substr(i, host.size()), EncodeMode::ENCODE_HOST);
            if (host3.empty()) {
                out = "";
                return -1;
            }
            out = host1 + host2 + host3;
            return 0;
        }
    }
    host = Unescape(host, EncodeMode::ENCODE_HOST);
    if (host.empty()) {
        out = "";
        return -1;
    }
    out = host;
    return 0;
}

bool ValidEncodedPath(const std::string &s)
{
    std::string subDelims = R"(!$&'()*+,;=:@[]%)";
    for (size_t i = 0; i < s.length(); ++i) {
        if (subDelims.find(s[i]) != std::string::npos) {
            continue;
        }
        if (ShouldEscape(s[i], EncodeMode::ENCODE_PATH)) {
            return false;
        }
    }
    return true;
}

bool ValidOptionalPort(const std::string &port)
{
    if (port.empty()) {
        return true;
    }
    if (port.at(0) != ':') {
        return false;
    }
    for (auto it = port.begin() + 1; it != port.end(); ++it) {
        if (*it < '0' || *it > '9') {
            return false;
        }
    }
    return true;
}

auto ParseQuery(const std::string &query) -> std::map<std::string, std::vector<std::string>>
{
    std::map<std::string, std::vector<std::string>> m;
    ParseQuery(m, query);
    return m;
}

int ParseQuery(std::map<std::string, std::vector<std::string>> &m, std::string query)
{
    while (!query.empty()) {
        std::string key = query;
        size_t i = key.find("&");
        if (i == std::string::npos) {
            i = key.find(";");
            if (i == std::string::npos) {
                query = "";
            }
        }
        if (key.empty()) {
            continue;
        }
        std::string value;
        i = key.find("=");
        value = key.substr(i + 1, key.size());
        key = key.substr(0, i);
        key = QueryUnescape(key);
        if (key.empty()) {
            continue;
        }
        m[key].push_back(value);
    }
    return 0;
}

std::string GetFullPreResolvePath(const std::string &base, const std::string &ref)
{
    if (ref.empty()) {
        return base;
    } else if (ref[0] != '/') {
        size_t i = base.find_last_of("/");
        return base.substr(0, i + 1) + ref;
    }

    return ref;
}

void SplitFullPreResolvePath(const std::string &full, std::vector<std::string> &dst)
{
    std::vector<std::string> src = CXXUtils::Split(full, '/');
    for (auto elem : src) {
        if (elem == ".") {
            continue;
        } else if (elem == "..") {
            if (dst.size() > 0) {
                dst.erase(dst.begin() + (long)(dst.size()), dst.end());
            }
        } else {
            dst.push_back(elem);
        }
    }
    std::string last = src.at(src.size() - 1);
    if (last == "." || last == "..") {
        dst.push_back("");
    }
}

std::string ResolvePath(const std::string &base, const std::string &ref)
{
    std::string full = GetFullPreResolvePath(base, ref);
    if (full.empty()) {
        return "";
    }

    std::vector<std::string> dst;
    SplitFullPreResolvePath(full, dst);

    std::string ret;
    for (auto it = dst.begin(); it != dst.end(); ++it) {
        ret += (*it + ((it + 1 != dst.end()) ? "/" : ""));
    }
    if (ret.at(0) == '/') {
        ret.erase(ret.begin());
    }
    return "/" + ret;
}

std::string StripPort(const std::string &hostport)
{
    size_t colon = hostport.find(":");
    if (colon == std::string::npos) {
        return hostport;
    }
    size_t found = hostport.find("]");
    if (found != std::string::npos) {
        std::string ret = hostport.substr(0, found);
        if (ret.at(0) == '[') {
            ret.erase(ret.begin());
        }
        return ret;
    }
    return hostport.substr(0, colon);
}

std::string PortOnly(const std::string &hostport)
{
    size_t colon = hostport.find(":");
    if (colon == std::string::npos) {
        return "";
    }
    size_t found = hostport.find("]:");
    if (found != std::string::npos) {
        return hostport.substr(found + 2, hostport.size());
    }
    if (hostport.find("]") != std::string::npos) {
        return "";
    }
    return hostport.substr(colon + 1, hostport.size());
}

bool ValidUserinfo(const std::string &s)
{
    std::string subDelims = R"(-._:~!$&'()*+,;=%@)";
    for (const auto &r : s) {
        if (('A' <= r && r <= 'Z') || ('a' <= r && r <= 'z') ||
            ('0' <= r && r <= '9') || (subDelims.find(r) != std::string::npos)) {
            continue;
        }
        return false;
    }
    return true;
}

std::string Values::Get(const std::string &key)
{
    if (v.size() == 0) {
        return "";
    }
    std::vector<std::string> vs = v[key];
    if (vs.size() == 0) {
        return "";
    }
    return vs[0];
}

void Values::Set(const std::string &key, const std::string &value)
{
    v[key] = std::vector<std::string>();
    v[key].push_back(value);
}

void Values::Add(const std::string &key, const std::string &value)
{
    v[key].push_back(value);
}

void Values::Del(const std::string &key)
{
    auto it = v.find(key);
    if (it != v.end()) {
        v.erase(it);
    }
}

std::string Values::Encode()
{
    if (v.size() == 0) {
        return "";
    }
    std::string buf;
    std::vector<std::string> keys;
    keys.reserve(v.size());
    for (auto it = v.cbegin(); it != v.cend(); ++it) {
        keys.push_back(it->first);
    }
    std::sort(keys.begin(), keys.end());
    for (auto k : keys) {
        std::vector<std::string> vs = v[k];
        std::string keyEscaped = QueryEscape(k);
        for (auto elem : vs) {
            if (buf.length() > 0) {
                buf.append("&");
            }
            buf.append(keyEscaped);
            buf.append("=");
            buf.append(QueryEscape(elem));
        }
    }
    return buf;
}

std::string UserInfo::String() const
{
    std::string s;
    if (!m_username.empty()) {
        s = Escape(m_username, EncodeMode::ENCODE_USER_PASSWORD);
        if (m_passwordSet) {
            s += ":" + Escape(m_password, EncodeMode::ENCODE_USER_PASSWORD);
        }
    }
    return s;
}
std::string UserInfo::Username() const
{
    return m_username;
}
std::string UserInfo::Password(bool &set) const
{
    set = m_passwordSet;
    return m_password;
}

URLDatum::~URLDatum()
{
    if (m_user != nullptr) {
        delete m_user;
    }
    m_user = nullptr;
}
int URLDatum::SetPath(const std::string &p)
{
    std::string path = Unescape(p, EncodeMode::ENCODE_PATH);
    if (path.empty()) {
        return -1;
    }
    m_path = path;
    std::string escp = Escape(path, EncodeMode::ENCODE_PATH);
    m_rawPath = (p == escp ? "" : p);
    return 0;
}

std::string URLDatum::EscapedPath()
{
    if (!m_rawPath.empty() && ValidEncodedPath(m_rawPath)) {
        std::string p = Unescape(m_rawPath, EncodeMode::ENCODE_PATH);
        if (!p.empty() && p == m_path) {
            return m_rawPath;
        }
    }
    if (m_path == "*") {
        return "*";
    }
    return Escape(m_path, EncodeMode::ENCODE_PATH);
}

void URLDatum::StringOpaqueEmptyRules(std::string &buf)
{
    if (!m_scheme.empty() || !m_host.empty() || m_user != nullptr) {
        if (!m_host.empty() || !m_path.empty() || m_user != nullptr) {
            buf.append("//");
        }
        if (m_user != nullptr) {
            buf.append(m_user->String());
            buf.append("@");
        }
        if (!m_host.empty()) {
            buf.append(Escape(m_host, EncodeMode::ENCODE_HOST));
        }
    }
    std::string path = EscapedPath();
    if (!m_path.empty() && m_path.at(0) != '/' && !m_host.empty()) {
        buf.append("/");
    }
    if (buf.length() == 0) {
        auto i = m_path.find(":");
        if (i != std::string::npos &&
            path.substr(0, i).find("/") == std::string::npos) {
            buf.append("./");
        }
    }
    buf.append(path);
}

std::string URLDatum::String()
{
    std::string buf;
    if (!m_scheme.empty()) {
        buf.append(m_scheme);
        buf.append(":");
    }
    if (!m_opaque.empty()) {
        buf.append(m_opaque);
    } else {
        StringOpaqueEmptyRules(buf);
    }
    if (m_forceQuery || !m_rawQuery.empty()) {
        buf.append("?");
        buf.append(m_rawQuery);
    }
    if (!m_fragment.empty()) {
        buf.append("#");
        buf.append(Escape(m_fragment, EncodeMode::ENCODE_FRAGMENT));
    }
    return buf;
}

bool URLDatum::IsAbs() const
{
    return (m_scheme != "");
}

std::unique_ptr<URLDatum> URLDatum::UrlParse(const std::string &ref)
{
    auto refurl = Parse(ref);
    if (refurl == nullptr) {
        return nullptr;
    }
    return ResolveReference(refurl);
}

std::unique_ptr<URLDatum> URLDatum::ResolveReference(URLDatum *ref)
{
    std::unique_ptr<URLDatum> url(new (std::nothrow) URLDatum(*ref));
    if (url == nullptr) {
        return nullptr;
    }

    if (url->m_scheme.empty()) {
        url->m_scheme = m_scheme;
    }
    if (!ref->m_scheme.empty() || !ref->m_host.empty() || ref->m_user != nullptr) {
        url->SetPath(ResolvePath(ref->EscapedPath(), ""));
        return url;
    }
    if (!ref->m_opaque.empty()) {
        url->m_user = nullptr;
        url->m_host = "";
        url->m_path = "";
        return url;
    }
    if (ref->m_path.empty() && ref->m_rawQuery.empty()) {
        url->m_rawQuery = m_rawQuery;
        if (ref->m_fragment.empty()) {
            url->m_fragment = m_fragment;
        }
    }
    url->m_host = m_host;
    url->m_user = m_user;
    url->SetPath(ResolvePath(EscapedPath(), ref->EscapedPath()));
    return url;
}


auto URLDatum::Query() ->std::map<std::string, std::vector<std::string>>
{
    return ParseQuery(m_rawQuery);
}

std::string URLDatum::RequestURI()
{
    std::string result = m_opaque;
    if (result.empty()) {
        result = EscapedPath();
        if (result.empty()) {
            result = "/";
        }
    } else {
        if (result.length() >= 2 && result.substr(0, 2) == "//") {
            result = m_scheme + ":" + result;
        }
    }
    if (m_forceQuery || !m_rawQuery.empty()) {
        result += "?" + m_rawQuery;
    }
    return result;
}

std::string URLDatum::Hostname() const
{
    return StripPort(m_host);
}

std::string URLDatum::Port() const
{
    return PortOnly(m_host);
}
}  // namespace url


