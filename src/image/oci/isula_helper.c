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
* Author: liuhao
* Create: 2019-07-15
* Description: helper functions for isula image
*******************************************************************************/
#include "isula_helper.h"

#include "utils.h"
#include "log.h"
#include "isulad_config.h"

int get_isula_image_connect_config(client_connect_config_t *conf)
{
    char *sock_addr = NULL;

    if (conf == NULL) {
        return -1;
    }

    sock_addr = conf_get_im_server_sock_addr();
    if (sock_addr == NULL) {
        ERROR("Get image server sockot address failed");
        return -1;
    }

    conf->socket = sock_addr;

    conf->deadline = conf_get_im_opt_timeout();

    return 0;
}

void free_client_connect_config_value(client_connect_config_t *conf)
{
    if (conf == NULL) {
        return;
    }
    free(conf->socket);
    conf->socket = NULL;
    free_sensitive_string(conf->ca_file);
    conf->ca_file = NULL;
    free_sensitive_string(conf->cert_file);
    conf->cert_file = NULL;
    free_sensitive_string(conf->key_file);
    conf->key_file = NULL;
}
