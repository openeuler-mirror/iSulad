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
 * Description: provide atomic function definition
 ********************************************************************************/
#ifndef __UTILS_ATOMIC_H
#define __UTILS_ATOMIC_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "isula_libutils/log.h"

#ifdef __cplusplus
extern "C" {
#endif

extern pthread_mutex_t g_atomic_lock;
extern pthread_mutex_t g_atomic_image_lock;

/* atomic mutex lock */
static inline void atomic_mutex_lock(pthread_mutex_t *mutex)
{
    if (pthread_mutex_lock(mutex)) {
        ERROR("Failed to lock atomic mutex");
    }
}

/* atomic mutex unlock */
static inline void atomic_mutex_unlock(pthread_mutex_t *mutex)
{
    if (pthread_mutex_unlock(mutex)) {
        ERROR("Failed to unlock atomic mutex");
    }
}

/* atomic int get */
static inline uint64_t atomic_int_get(const volatile uint64_t *atomic)
{
    uint64_t value;

    atomic_mutex_lock(&g_atomic_lock);
    value = *atomic;
    atomic_mutex_unlock(&g_atomic_lock);

    return value;
}

/* atomic int set */
static inline void atomic_int_set(volatile uint64_t *atomic, uint64_t value)
{
    atomic_mutex_lock(&g_atomic_lock);
    *atomic = value;
    atomic_mutex_unlock(&g_atomic_lock);
}

/* atomic int set for image */
static inline void atomic_int_set_image(volatile uint64_t *atomic, uint64_t value)
{
    atomic_mutex_lock(&g_atomic_image_lock);
    *atomic = value;
    atomic_mutex_unlock(&g_atomic_image_lock);
}


/* atomic int inc */
static inline uint64_t atomic_int_inc(volatile uint64_t *atomic)
{
    uint64_t value;

    atomic_mutex_lock(&g_atomic_lock);
    value = ++(*atomic);
    atomic_mutex_unlock(&g_atomic_lock);

    return value;
}

/* atomic int inc for image */
static inline uint64_t atomic_int_inc_image(volatile uint64_t *atomic)
{
    uint64_t value;

    atomic_mutex_lock(&g_atomic_image_lock);
    value = ++(*atomic);
    atomic_mutex_unlock(&g_atomic_image_lock);

    return value;
}

/* atomic int dec test */
static inline bool atomic_int_dec_test(volatile uint64_t *atomic)
{
    bool is_zero = false;

    atomic_mutex_lock(&g_atomic_lock);
    is_zero = --(*atomic) == 0;
    atomic_mutex_unlock(&g_atomic_lock);

    return is_zero;
}

/* atomic int dec test for image */
static inline bool atomic_int_dec_test_image(volatile uint64_t *atomic)
{
    bool is_zero = false;

    atomic_mutex_lock(&g_atomic_image_lock);
    is_zero = --(*atomic) == 0;
    atomic_mutex_unlock(&g_atomic_image_lock);

    return is_zero;
}


/* atomic int compare exchange */
static inline bool atomic_int_compare_exchange(volatile uint64_t *atomic, uint64_t oldval, uint64_t newval)
{
    bool success = false;

    atomic_mutex_lock(&g_atomic_lock);

    if ((success = (*atomic == oldval))) {
        *atomic = newval;
    }

    atomic_mutex_unlock(&g_atomic_lock);

    return success;
}

/* atomic int add */
static inline uint64_t atomic_int_add(volatile uint64_t *atomic, uint64_t val)
{
    uint64_t oldval;

    atomic_mutex_lock(&g_atomic_lock);
    oldval = *atomic;
    *atomic = oldval + val;
    atomic_mutex_unlock(&g_atomic_lock);

    return oldval;
}

/* atomic int and */
static inline uint64_t atomic_int_and(volatile uint64_t *atomic, uint64_t val)
{
    uint64_t oldval;

    atomic_mutex_lock(&g_atomic_lock);
    oldval = *atomic;
    *atomic = oldval & val;
    atomic_mutex_unlock(&g_atomic_lock);

    return oldval;
}

/* atomic int or */
static inline uint64_t atomic_int_or(volatile uint64_t *atomic, uint64_t val)
{
    uint64_t oldval;

    atomic_mutex_lock(&g_atomic_lock);
    oldval = *atomic;
    *atomic = oldval | val;
    atomic_mutex_unlock(&g_atomic_lock);

    return oldval;
}

/* atomic int xor */
static inline uint64_t atomic_int_xor(volatile uint64_t *atomic, uint64_t val)
{
    uint64_t oldval;

    atomic_mutex_lock(&g_atomic_lock);
    oldval = *atomic;
    *atomic = oldval ^ val;
    atomic_mutex_unlock(&g_atomic_lock);

    return oldval;
}

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_ATOMIC_H */

