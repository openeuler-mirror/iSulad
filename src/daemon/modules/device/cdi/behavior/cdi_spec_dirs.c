/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuxu
 * Create: 2024-03-06
 * Description: provide cdi spec dirs function
 ******************************************************************************/
#include "cdi_spec_dirs.h"

#define DEFAULT_SPEC_DIRS_LEN   2
static char *default_spec_dirs_items[DEFAULT_SPEC_DIRS_LEN] = {CDI_DEFAULT_STATIC_DIR, CDI_DEFAULT_DYNAMIC_DIR};
 
string_array g_default_spec_dirs = {
    .items = default_spec_dirs_items,
    .len = DEFAULT_SPEC_DIRS_LEN,
    .cap = DEFAULT_SPEC_DIRS_LEN,
};
 
char *cdi_scan_spec_dirs(string_array *dirs, struct cdi_scan_fn_maps *scan_fn_maps, cdi_scan_spec_func scan_fn)
{
    return NULL;
}
