/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide container utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_string.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "utils.h"
#include "isula_libutils/log.h"

struct unit_map_def {
    int64_t mltpl;
    char *name;
};

static struct unit_map_def const g_unit_map[] = {
    { .mltpl = 1, .name = "I" },         { .mltpl = 1, .name = "B" },         { .mltpl = 1, .name = "IB" },
    { .mltpl = SIZE_KB, .name = "K" },   { .mltpl = SIZE_KB, .name = "KI" },  { .mltpl = SIZE_KB, .name = "KB" },
    { .mltpl = SIZE_KB, .name = "KIB" }, { .mltpl = SIZE_MB, .name = "M" },   { .mltpl = SIZE_MB, .name = "MI" },
    { .mltpl = SIZE_MB, .name = "MB" },  { .mltpl = SIZE_MB, .name = "MIB" }, { .mltpl = SIZE_GB, .name = "G" },
    { .mltpl = SIZE_GB, .name = "GI" },  { .mltpl = SIZE_GB, .name = "GB" },  { .mltpl = SIZE_GB, .name = "GIB" },
    { .mltpl = SIZE_TB, .name = "T" },   { .mltpl = SIZE_TB, .name = "TI" },  { .mltpl = SIZE_TB, .name = "TB" },
    { .mltpl = SIZE_TB, .name = "TIB" }, { .mltpl = SIZE_PB, .name = "P" },   { .mltpl = SIZE_PB, .name = "PI" },
    { .mltpl = SIZE_PB, .name = "PB" },  { .mltpl = SIZE_PB, .name = "PIB" }
};

static size_t const g_unit_map_len = sizeof(g_unit_map) / sizeof(g_unit_map[0]);

bool strings_contains_any(const char *str, const char *substr)
{
    size_t i = 0;
    size_t j;
    size_t len_str = 0;
    size_t len_substr = 0;

    if (str == NULL || substr == NULL) {
        return false;
    }

    len_str = strlen(str);
    len_substr = strlen(substr);

    for (i = 0; i < len_str; i++) {
        for (j = 0; j < len_substr; j++) {
            if (str[i] == substr[j]) {
                return true;
            }
        }
    }
    return false;
}

bool strings_contains_word(const char *str, const char *substr)
{
    if (str == NULL || substr == NULL) {
        return false;
    }

    if (strcasestr(str, substr) != NULL) {
        return true;
    }
    return false;
}

int strings_count(const char *str, unsigned char c)
{
    size_t i = 0;
    int res = 0;
    size_t len = 0;

    if (str == NULL) {
        return 0;
    }

    len = strlen(str);
    for (i = 0; i < len; i++) {
        if (str[i] == c) {
            res++;
        }
    }
    return res;
}

// strings_in_slice tests whether a string is contained in array of strings or not.
// Comparison is case insensitive
bool strings_in_slice(const char **strarray, size_t alen, const char *str)
{
    size_t i;

    if (strarray == NULL || alen == 0 || str == NULL) {
        return false;
    }

    for (i = 0; i < alen; i++) {
        if (strarray[i] != NULL && strcasecmp(strarray[i], str) == 0) {
            return true;
        }
    }

    return false;
}

// Returns a string that is generated after converting
// all uppercase characters in the str to lowercase.
char *strings_to_lower(const char *str)
{
    char *newstr = NULL;
    char *pos = NULL;

    if (str == NULL) {
        return NULL;
    }

    newstr = util_strdup_s(str);
    if (newstr == NULL) {
        return NULL;
    }

    for (pos = newstr; *pos; ++pos) {
        *pos = (char)tolower((int)(*pos));
    }
    return newstr;
}

// Returns a string that is generated after converting
// all lowercase characters in the str to uppercase.
char *strings_to_upper(const char *str)
{
    char *newstr = NULL;
    char *pos = NULL;

    if (str == NULL) {
        return NULL;
    }

    newstr = util_strdup_s(str);
    if (newstr == NULL) {
        return NULL;
    }

    for (pos = newstr; *pos; ++pos) {
        *pos = (char)toupper((int)(*pos));
    }
    return newstr;
}

static int parse_unit_multiple(const char *unit, int64_t *mltpl)
{
    size_t i;
    if (unit[0] == '\0') {
        *mltpl = 1;
        return 0;
    }

    for (i = 0; i < g_unit_map_len; i++) {
        if (strcasecmp(unit, g_unit_map[i].name) == 0) {
            *mltpl = g_unit_map[i].mltpl;
            return 0;
        }
    }
    return -EINVAL;
}

static int util_parse_size_int_and_float(const char *numstr, int64_t mlt, int64_t *converted)
{
    long long int_size = 0;
    double float_size = 0;
    long long int_real = 0;
    long long float_real = 0;
    char *dot = NULL;
    int nret;

    dot = strchr(numstr, '.');
    if (dot != NULL) {
        char tmp;
        // interger.float
        if (dot == numstr || *(dot + 1) == '\0') {
            return -EINVAL;
        }
        // replace 123.456 to 120.456
        tmp = *(dot - 1);
        *(dot - 1) = '0';
        // parsing 0.456
        nret = util_safe_strtod(dot - 1, &float_size);
        // recover 120.456 to 123.456
        *(dot - 1) = tmp;
        if (nret < 0) {
            return nret;
        }
        float_real = (int64_t)float_size;
        if (mlt > 0) {
            if (INT64_MAX / mlt < (int64_t)float_size) {
                return -ERANGE;
            }
            float_real = (int64_t)(float_size * mlt);
        }
        *dot = '\0';
    }
    nret = util_safe_llong(numstr, &int_size);
    if (nret < 0) {
        return nret;
    }
    int_real = int_size;
    if (mlt > 0) {
        if (INT64_MAX / mlt < int_size) {
            return -ERANGE;
        }
        int_real = int_size * mlt;
    }
    if (INT64_MAX - int_real < float_real) {
        return -ERANGE;
    }

    *converted = int_real + float_real;
    return 0;
}

int util_parse_byte_size_string(const char *s, int64_t *converted)
{
    int ret;
    int64_t mltpl = 0;
    char *dup = NULL;
    char *pmlt = NULL;

    if (s == NULL || converted == NULL || s[0] == '\0' || !isdigit(s[0])) {
        return -EINVAL;
    }

    dup = util_strdup_s(s);
    if (dup == NULL) {
        return -ENOMEM;
    }

    pmlt = dup;
    while (*pmlt != '\0' && (isdigit(*pmlt) || *pmlt == '.')) {
        pmlt++;
    }

    ret = parse_unit_multiple(pmlt, &mltpl);
    if (ret) {
        free(dup);
        return ret;
    }

    // replace the first multiple arg to '\0'
    *pmlt = '\0';
    ret = util_parse_size_int_and_float(dup, mltpl, converted);
    free(dup);
    return ret;
}

int util_parse_percent_string(const char *s, long *converted)
{
    char *dup = NULL;

    if (s == NULL || converted == NULL || s[0] == 0 || strlen(s) < 2 || s[strlen(s) - 1] != '%' ||
        strspn(s, "0123456789%") != strlen(s)) {
        return -EINVAL;
    }
    dup = util_strdup_s(s);
    if (dup == NULL) {
        return -ENOMEM;
    }
    dup[strlen(dup) - 1] = 0;

    *converted = strtol(dup, NULL, 10);
    if ((errno == ERANGE && (*converted == LONG_MAX || *converted == LONG_MIN)) || (errno != 0 && *converted == 0) ||
        *converted < 0 || *converted > 100) {
        free(dup);
        return -EINVAL;
    }

    free(dup);
    return 0;
}

static char **util_shrink_array(char **orig_array, size_t new_size)
{
    char **new_array = NULL;
    size_t i = 0;

    if (new_size == 0) {
        return orig_array;
    }
    if (new_size > SIZE_MAX / sizeof(char *)) {
        ERROR("Invalid arguments");
        return orig_array;
    }
    new_array = util_common_calloc_s(new_size * sizeof(char *));
    if (new_array == NULL) {
        return orig_array;
    }

    for (i = 0; i < new_size; i++) {
        new_array[i] = orig_array[i];
    }
    free(orig_array);
    return new_array;
}

static char **make_empty_array()
{
    char **res_array = NULL;

    res_array = calloc(2, sizeof(char *));
    if (res_array == NULL) {
        return NULL;
    }
    res_array[0] = util_strdup_s("");
    return res_array;
}

char **util_string_split_multi(const char *src_str, char delim)
{
    int ret, tmp_errno;
    char *token = NULL;
    char *cur = NULL;
    char **res_array = NULL;
    char deli[2] = { delim, '\0' };
    size_t count = 0;
    size_t capacity = 0;
    char *tmpstr = NULL;

    if (src_str == NULL) {
        return NULL;
    }

    if (src_str[0] == '\0') {
        return make_empty_array();
    }

    tmpstr = util_strdup_s(src_str);
    cur = tmpstr;
    token = strsep(&cur, deli);
    while (token != NULL) {
        ret = util_grow_array(&res_array, &capacity, count + 1, 16);
        if (ret < 0) {
            goto err_out;
        }
        res_array[count] = util_strdup_s(token);
        count++;
        token = strsep(&cur, deli);
    }
    free(tmpstr);
    return util_shrink_array(res_array, count + 1);

err_out:
    tmp_errno = errno;
    free(tmpstr);
    util_free_array(res_array);
    errno = tmp_errno;
    return NULL;
}

char **util_string_split_n(const char *src, char sep, size_t n)
{
    char **res_array = NULL;
    const char *index = NULL;
    char *token = NULL;
    char *str = NULL;
    size_t count = 0;
    int tmp_errno;

    if (src == NULL || n == 0) {
        return NULL;
    }

    if (src[0] == '\0') {
        return make_empty_array();
    }
    str = util_strdup_s(src);
    index = str;
    for (token = strchr(index, sep); token != NULL; token = strchr(index, sep)) {
        count++;
        if (count >= n) {
            break;
        }
        *token = '\0';
        if (util_array_append(&res_array, index) != 0) {
            goto err_out;
        }
        index = token + 1;
    }
    if (util_array_append(&res_array, index) != 0) {
        goto err_out;
    }
    free(str);
    return res_array;

err_out:
    tmp_errno = errno;
    free(str);
    util_free_array(res_array);
    errno = tmp_errno;
    return NULL;
}

char **util_string_split(const char *src_str, char _sep)
{
    char *token = NULL;
    char *str = NULL;
    char *tmpstr = NULL;
    char *reserve_ptr = NULL;
    char deli[2] = { _sep, '\0' };
    char **res_array = NULL;
    size_t capacity = 0;
    size_t count = 0;
    int ret, tmp_errno;

    if (src_str == NULL) {
        return NULL;
    }
    if (src_str[0] == '\0') {
        return make_empty_array();
    }

    tmpstr = util_strdup_s(src_str);

    str = tmpstr;
    for (; (token = strtok_r(str, deli, &reserve_ptr)); str = NULL) {
        ret = util_grow_array(&res_array, &capacity, count + 1, 16);
        if (ret < 0) {
            goto err_out;
        }
        res_array[count] = util_strdup_s(token);
        count++;
    }
    if (res_array == NULL) {
        free(tmpstr);
        return make_empty_array();
    }
    free(tmpstr);
    return util_shrink_array(res_array, count + 1);

err_out:
    tmp_errno = errno;
    free(tmpstr);
    util_free_array(res_array);
    errno = tmp_errno;
    return NULL;
}

const char *str_skip_str(const char *str, const char *skip)
{
    if (str == NULL || skip == NULL) {
        return NULL;
    }

    for (;; str++, skip++) {
        if (*skip == 0) {
            return str;
        } else if (*str != *skip) {
            return NULL;
        }
    }
}

static char *util_string_delchar_inplace(char *s, unsigned char c)
{
    size_t i = 0;
    size_t j = 0;
    size_t slen = 0;

    if (s == NULL) {
        return NULL;
    }

    slen = strlen(s);

    while (i < slen) {
        if (j == slen) {
            s[i] = '\0';
            break;
        }

        s[i] = s[j];

        if (s[i] != c) {
            i++;
        }
        j++;
    }

    return s;
}

char *util_string_delchar(const char *ss, unsigned char c)
{
    char *s = NULL;

    if (ss == NULL) {
        return NULL;
    }

    s = util_strdup_s(ss);

    return util_string_delchar_inplace(s, c);
}

void util_trim_newline(char *s)
{
    size_t len;

    if (s == NULL) {
        return;
    }
    len = strlen(s);
    while ((len >= 1) && (s[len - 1] == '\n')) {
        s[--len] = '\0';
    }
}

static char *util_left_trim_space(char *str)
{
    char *begin = str;
    char *tmp = str;
    while (isspace(*begin)) {
        begin++;
    }
    while ((*tmp++ = *begin++)) {
    }
    return str;
}

static char *util_right_trim_space(char *str)
{
    char *end = NULL;
    size_t len = strlen(str);
    if (len == 0) {
        return str;
    }
    end = str + len - 1;
    while (isspace(*end)) {
        end--;
    }
    *(end + 1) = '\0';

    return str;
}

char *util_trim_space(char *str)
{
    if (str == NULL) {
        return NULL;
    }
    str = util_left_trim_space(str);
    str = util_right_trim_space(str);
    return str;
}

static char *util_left_trim_quotation(char *str)
{
    char *begin = str;
    char *tmp = str;

    if (*str == '\0') {
        return str;
    }

    while ((*begin) == '\"') {
        begin++;
    }
    while ((*tmp++ = *begin++)) {
    }
    return str;
}

static char *util_right_trim_quotation(char *str)
{
    char *end = NULL;
    size_t len = strlen(str);
    if (len == 0) {
        return str;
    }

    end = str + len - 1;
    while (end >= str && ((*end) == '\0' || (*end) == '\n' || (*end) == '\"')) {
        end--;
    }
    *(end + 1) = '\0';

    return str;
}

char *util_trim_quotation(char *str)
{
    if (str == NULL) {
        return NULL;
    }
    str = util_left_trim_quotation(str);
    str = util_right_trim_quotation(str);
    return str;
}

char **str_array_dup(const char **src, size_t len)
{
    size_t i;
    char **dest = NULL;

    if (len == 0 || src == NULL) {
        return NULL;
    }
    if (len > SIZE_MAX / sizeof(char *) - 1) {
        return NULL;
    }
    dest = (char **)util_common_calloc_s(sizeof(char *) * (len + 1));
    if (dest == NULL) {
        return NULL;
    }

    for (i = 0; i < len; ++i) {
        if (src[i] != NULL) {
            dest[i] = util_strdup_s(src[i]);
        }
    }
    return dest;
}

static char *do_string_join(const char *sep, const char **parts, size_t parts_len, size_t result_len)
{
    char *res_string = NULL;
    size_t iter;

    res_string = calloc(result_len + 1, 1);
    if (res_string == NULL) {
        return NULL;
    }

    for (iter = 0; iter < parts_len - 1; iter++) {
        (void)strcat(res_string, parts[iter]);
        (void)strcat(res_string, sep);
    }
    (void)strcat(res_string, parts[parts_len - 1]);
    return res_string;
}

char *util_string_join(const char *sep, const char **parts, size_t len)
{
    size_t sep_len;
    size_t result_len;
    size_t iter;

    if (len == 0 || parts == NULL || sep == NULL) {
        return NULL;
    }

    sep_len = strlen(sep);

    if ((sep_len != 0) && (sep_len != 1) && (len > SIZE_MAX / sep_len + 1)) {
        return NULL;
    }
    result_len = (len - 1) * sep_len;
    for (iter = 0; iter < len; iter++) {
        if (parts[iter] == NULL || result_len >= SIZE_MAX - strlen(parts[iter])) {
            return NULL;
        }
        result_len += strlen(parts[iter]);
    }

    return do_string_join(sep, parts, len, result_len);
}

char *util_string_append(const char *post, const char *pre)
{
    char *res_string = NULL;
    size_t length = 0;

    if (post == NULL && pre == NULL) {
        return NULL;
    }
    if (pre == NULL) {
        return util_strdup_s(post);
    }
    if (post == NULL) {
        return util_strdup_s(pre);
    }
    if (strlen(post) > ((SIZE_MAX - strlen(pre)) - 1)) {
        ERROR("String is too long to be appended");
        return NULL;
    }
    length = strlen(post) + strlen(pre) + 1;
    res_string = util_common_calloc_s(length);
    if (res_string == NULL) {
        return NULL;
    }
    (void)strcat(res_string, pre);
    (void)strcat(res_string, post);

    return res_string;
}

int dup_array_of_strings(const char **src, size_t src_len, char ***dst, size_t *dst_len)
{
    size_t i;

    if (src == NULL || src_len == 0) {
        return 0;
    }

    if (dst == NULL || dst_len == NULL) {
        return -1;
    }

    *dst = NULL;
    *dst_len = 0;
    if (src_len > SIZE_MAX / sizeof(char *)) {
        ERROR("Src elements is too much!");
        return -1;
    }
    *dst = (char **)util_common_calloc_s(src_len * sizeof(char *));
    if (*dst == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < src_len; i++) {
        (*dst)[*dst_len] = (src[i] != NULL) ? util_strdup_s(src[i]) : NULL;
        (*dst_len)++;
    }
    return 0;
}

char *util_sub_string(const char *source, size_t offset, size_t length)
{
    size_t total_len;
    size_t substr_len;
    char *substring = NULL;

    if (source == NULL || length == 0) {
        return NULL;
    }

    total_len = strlen(source);

    if (offset > total_len) {
        return NULL;
    }

    substr_len = ((total_len - offset) >= length ? length : (total_len - offset)) + 1;
    substring = (char *)util_common_calloc_s(substr_len * sizeof(char));
    if (substring == NULL) {
        ERROR("Out of memory\n");
        return NULL;
    }
    (void)strncpy(substring, source + offset, substr_len - 1);
    substring[substr_len - 1] = '\0';

    return substring;
}

bool util_is_space_string(const char *str)
{
    size_t i;

    if (str == NULL) {
        return false;
    }

    for (i = 0; i < strlen(str); i++) {
        if (!isspace(str[i])) {
            return false;
        }
    }

    return true;
}

bool util_has_prefix(const char *str, const char *prefix)
{
    if (str == NULL || prefix == NULL) {
        return false;
    }

    if (strlen(str) < strlen(prefix)) {
        return false;
    }

    if (strcmp(str, prefix)) {
        return false;
    }

    return true;
}

bool util_has_suffix(const char *str, const char *suffix)
{
    size_t str_len = 0;
    size_t suffix_len = 0;

    if (str == NULL || suffix == NULL) {
        return false;
    }

    str_len = strlen(str);
    suffix_len = strlen(suffix);
    if (str_len < suffix_len) {
        return false;
    }

    if (strcmp(str + str_len - suffix_len, suffix)) {
        return false;
    }

    return true;
}
