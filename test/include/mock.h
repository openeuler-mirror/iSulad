/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: define mock method
 * Author: wangyushui
 * Create: 2019-6-10
 */

#ifndef MOCK_H
#define MOCK_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MOCK_STRUCT_INIT(...) \
    { __VA_ARGS__ }

#define DEFINE_RETURN_MOCK(fn, ret) \
    bool ut_ ## fn ## _mocked = false; \
    ret ut_ ## fn

#define DEFINE_RETURN_MOCK_V(fn, ret, dargs) \
    bool ut_ ## fn ## _mocked = false; \
    ret(* ut_ ## fn) dargs
/*
 * For controlling mocked function behavior, setting
 * and getting values from the stub, the _P macros are
 * for mocking functions that return pointer values.
 */
#define MOCK_SET(fn, val) \
    ut_ ## fn ## _mocked = true; \
    ut_ ## fn = val

#define MOCK_SET_V(fn, fun) \
    ut_ ## fn ## _mocked = true; \
    ut_ ## fn = fun

#define MOCK_GET(fn) \
    ut_ ## fn

#define MOCK_GET_V(fn, args) \
    ut_ ## fn args

#define MOCK_CLEAR(fn) \
    ut_ ## fn ## _mocked = false;

#define MOCK_CLEAR_P(fn) \
    ut_ ## fn ## _mocked = false; \
    ut_ ## fn = NULL;

/* for declaring function protoypes for wrappers */
#define DECLARE_WRAPPER(fn, ret, args) \
    extern bool ut_ ## fn ## _mocked; \
    extern ret ut_ ## fn; \
    ret __wrap_ ## fn args; \
    ret __real_ ## fn args;

#define DECLARE_WRAPPER_V(fn, ret, args) \
    extern bool ut_ ## fn ## _mocked; \
    extern ret(* ut_ ## fn) args; \
    ret __wrap_ ## fn args; \
    ret __real_ ## fn args;

/* for defining the implmentation of wrappers for syscalls */
#define DEFINE_WRAPPER(fn, ret, dargs, pargs) \
    DEFINE_RETURN_MOCK(fn, ret); \
    ret __wrap_ ## fn dargs \
    { \
        if (!ut_ ## fn ## _mocked) { \
            return __real_ ## fn pargs; \
        } else { \
            return MOCK_GET(fn); \
        } \
    }

#define DEFINE_WRAPPER_V(fn, ret, dargs, pargs) \
    DEFINE_RETURN_MOCK_V(fn, ret, dargs); \
    __attribute__((used)) ret __wrap_ ## fn dargs \
    { \
        if (!ut_ ## fn ## _mocked) { \
            return __real_ ## fn pargs; \
        } else { \
            return MOCK_GET_V(fn, pargs); \
        } \
    }

/* DEFINE_STUB is for defining the implmentation of stubs for funcs. */
#define DEFINE_STUB(fn, ret, dargs, val) \
    bool ut_ ## fn ## _mocked = true; \
    ret ut_ ## fn = val; \
    ret fn dargs; \
    ret fn dargs \
    { \
        return MOCK_GET(fn); \
    }

/* DEFINE_STUB_V macro is for stubs that don't have a return value */
#define DEFINE_STUB_V(fn, dargs) \
    void fn dargs; \
    void fn dargs \
    { \
    }

#define HANDLE_RETURN_MOCK(fn) \
    if (ut_ ## fn ## _mocked) { \
        return ut_ ## fn; \
    }

#ifdef __cplusplus
}
#endif

#endif /* MOCK_H */



