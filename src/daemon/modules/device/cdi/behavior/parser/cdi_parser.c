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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "error.h"
#include "utils_string.h"

/* cdi_parser_qualified_name returns the qualified name for a device.
 * The syntax for a qualified device names is
 *
 *	"<vendor>/<class>=<name>".
 *
 * A valid vendor and class name may contain the following runes:
 *
 *	'A'-'Z', 'a'-'z', '0'-'9', '.', '-', '_'.
 *
 * A valid device name may contain the following runes:
 *
 *	'A'-'Z', 'a'-'z', '0'-'9', '-', '_', '.', ':'
 */
char *cdi_parser_qualified_name(const char *vendor, const char *class, const char *name)
{
    char device_name[PATH_MAX] = { 0 };
    int nret;

    if (vendor == NULL || class == NULL || name == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }

    nret = snprintf(device_name, sizeof(device_name), "%s/%s=%s",
                        vendor, class, name);
    if (nret < 0 || (size_t)nret >= sizeof(device_name)) {
        ERROR("Device name is too long");
        return NULL;
    }
    return util_strdup_s(device_name);
}

// cdi_parser_is_qualified_name tests if a device name is qualified.
bool cdi_parser_is_qualified_name(const char *device)
{
    __isula_auto_free char *vendor = NULL;
    __isula_auto_free char *class = NULL;
    __isula_auto_free char *name = NULL;

    return cdi_parser_parse_qualified_name(device, &vendor, &class, &name) == 0;
}

// cdi_parser_parse_qualified_name splits a qualified name into device vendor, class, and name.
int cdi_parser_parse_qualified_name(const char *device, char **vendor, char **class, char **name)
{
    int ret = 0;

    ret = cdi_parser_parse_device(device, vendor, class, name);
    if (ret != 0) {
        if (*vendor == NULL) {
            ERROR("Unqualified device %s, missing vendor", device);
            return -1;
        }
        if (*class == NULL) {
            ERROR("Unqualified device %s, missing class", device);
            return -1;
        }
        if (*name == NULL) {
            ERROR("Unqualified device %s, missing name", device);
            return -1;
        }
        ERROR("Unqualified device %s", device);
        return -1;
    }

    if (cdi_parser_validate_vendor_name(*vendor) != 0) {
        ERROR("Invalid device %s", device);
        goto err_out;
    }
    if (cdi_parser_validate_class_name(*class) != 0) {
        ERROR("Invalid device %s", device);
        goto err_out;
    }
    if (cdi_parser_validate_device_name(*name) != 0) {
        ERROR("Invalid device %s", device);
        goto err_out;
    }

    return 0;

err_out:
    free(*vendor);
    *vendor = NULL;
    free(*class);
    *class = NULL;
    free(*name);
    *name = NULL;
    return -1;
}

// cdi_parser_parse_device tries to split a device name into vendor, class, and name.
int cdi_parser_parse_device(const char *device, char **vendor, char **class, char **name)
{
    __isula_auto_array_t char **parts = NULL;

    if (vendor == NULL || class == NULL || name == NULL || 
        device == NULL || device[0] == '/') {
        ERROR("Invalid argument");
        return -1;
    }

    parts = util_string_split_n(device, '=', 2);
    if (parts == NULL || util_array_len((const char **)parts) != 2 || parts[0] == NULL || parts[1] == NULL) {
        return -1;
    }

    *name = parts[1];
    parts[1] = NULL;
    (void)cdi_parser_parse_qualifier(parts[0], vendor, class);
    if (*vendor == NULL) {
        ERROR("Failed to parse device qualifier: %s", parts[0]);
        return -1;
    }

    return 0;
}

/* cdi_parser_parse_qualifier splits a device qualifier into vendor and class.
 * The syntax for a device qualifier is
 *
 *	"<vendor>/<class>"
 */
int cdi_parser_parse_qualifier(const char *kind, char **vendor, char **class)
{
    __isula_auto_array_t char **parts = NULL;

    if (kind == NULL || vendor == NULL || class == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    parts = util_string_split_n(kind, '/', 2);
    if (parts == NULL || util_array_len((const char **)parts) != 2 || parts[0] == NULL || parts[1] == NULL) {
        return -1;
    }
    *vendor = parts[0];
    parts[0] = NULL;
    *class = parts[1];
    parts[1] = NULL;

    return 0;
}

static int validate_vendor_or_class_name(const char *name)
{
    int i = 0;

    if (name == NULL) {
        ERROR("Empty name");
        return -1;
    }

    if (!isalpha(name[0])) {
        ERROR("%s, should start with letter", name);
        return -1;
    }
    for (i = 1; name[i] != '\0'; i++) {
        if (!(isalnum(name[i]) || name[i] == '_' || name[i] == '-' || name[i] == '.')) {
            ERROR("Invalid character '%c' in name %s", name[i], name);
            return -1;
        }
    }
    if (!isalnum(name[i - 1])) {
        ERROR("%s, should end with a letter or digit", name);
        return -1;
    }

    return 0;
}

int cdi_parser_validate_vendor_name(const char *vendor)
{
    if (validate_vendor_or_class_name(vendor) != 0) {
        ERROR("Invalid vendor");
        return -1;
    }
    return 0;
}

int cdi_parser_validate_class_name(const char *class)
{
    if (validate_vendor_or_class_name(class) != 0) {
        ERROR("Invalid class.");
        return -1;
    }
    return 0;
}

int cdi_parser_validate_device_name(const char *name)
{
    size_t i;
    
    if (name == NULL) {
        ERROR("Invalid (empty) device name");
        return -1;
    }
    if (!isalnum(name[0])) {
        ERROR("Invalid class %s, should start with a letter or digit", name);
        return -1;
    }
    if (strlen(name) == 1) {
        return 0;
    }
    for (i = 1; name[i] != '\0'; i++) {
        if (!(isalnum(name[i]) || name[i] == '_' || name[i] == '-' || name[i] == '.' || name[i] == ':')) {
            ERROR("Invalid character '%c' in device name %s", name[i], name);
            return -1;
        }
    }
    if (!isalnum(name[i - 1])) {
        ERROR("Invalid name %s, should end with a letter or digit", name);
        return -1;
    }

    return 0;
}
