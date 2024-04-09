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
 * Description: provide cdi parser linux function
 ******************************************************************************/
#include "cdi_parser.h"

char *cdi_parser_qualified_name(const char *vendor, const char *class, const char *name)
{
    return NULL;
}

bool cdi_parser_is_qualified_name(const char *device)
{
    return true;
}

char *cdi_parser_parse_qualified_name(const char *device, char **vendor, char **class, char **name)
{
    return NULL;
}

int cdi_parser_parse_device(const char *device, char **vendor, char **class, char **name)
{
    return 0;
}

int cdi_parser_parse_qualifier(const char *kind, char **vendor, char **class)
{
    return 0;
}

char *cdi_parser_validate_vendor_name(const char *vendor)
{
    return NULL;
}

char *cdi_parser_validate_class_name(const char *class)
{
    return NULL;
}

char *cdi_parser_validate_device_name(const char *name)
{
    return NULL;
}
