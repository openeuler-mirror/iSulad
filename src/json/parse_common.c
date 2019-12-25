/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wujing
 * Create: 2019-02-22
 * Description: provide common parse definition
 ******************************************************************************/
#include "parse_common.h"
#include "log.h"

docker_seccomp *get_seccomp_security_opt_spec(const char *file)
{
    docker_seccomp *seccomp_spec = NULL;
    parser_error err = NULL;

    /* parse the input seccomp file */
    seccomp_spec = docker_seccomp_parse_file(file, NULL, &err);
    if (seccomp_spec == NULL) {
        ERROR("Can not parse seccomp file: %s", err);
        goto out;
    }

out:
    free(err);
    return seccomp_spec;
}

