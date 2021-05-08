/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: gaohuatao
 * Create: 2020-12-29
 * Description: provide network port parse utils functions
 *******************************************************************************/

#include "utils_port.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <isula_libutils/log.h>

#include "utils.h"
#include "utils_array.h"
#include "utils_convert.h"
#include "utils_network.h"
#include "utils_convert.h"
#include "isula_libutils/json_common.h"

typedef struct {
    uint64_t start_cport;
    uint64_t end_cport;
    uint64_t start_hport;
    uint64_t end_hport;
    char *proto;
} ports_t;

#define IP_ADDR_MIN_LENGTH 7
#define PROTO_NUM 3
const char *g_proto_whitelist[PROTO_NUM] = { "tcp", "udp", "sctp" };

// split --publish value to <host ip> <host port with proto> and <container port with proto>, without verify
static int split_parts(const char *value, char **host_ip, char **host_port, char **container_port)
{
#define POSITION_HOST_PORT 2
    char **split = NULL;
    size_t length = 0;

    split = util_string_split_multi(value, ':');
    if (split == NULL) {
        ERROR("Split network raw ports string error");
        return -1;
    }

    length = util_array_len((const char **)split);
    if (length == 0) {
        ERROR("network param arr length is zero");
        goto out;
    }
    *container_port = util_strdup_s(split[length - 1]);

    switch (length) {
        // --publish format is <container-ip> without host info
        case 1:
            *host_ip = NULL;
            *host_port = NULL;
            break;
        // --publish format is <host port>:<container port>
        case 2:
            *host_ip = NULL;
            *host_port = util_strdup_s(split[0]);
            break;
        // --publish format is <host ip>:<host port>:<container port>
        case 3:
            *host_ip = util_strdup_s(split[0]);
            *host_port = util_strdup_s(split[1]);
            break;
        // --publish format is xxx:<host port>:<container port>
        default:
            *host_ip = util_string_join(":", (const char **)split, length - POSITION_HOST_PORT);
            *host_port = util_strdup_s(split[length - POSITION_HOST_PORT]);
            break;
    }

out:
    util_free_array_by_len(split, length);
    return 0;
}

int util_split_proto_port(const char *raw_port, char **proto, char **port)
{
    int ret = 0;
    char **split = NULL;
    size_t length = 0;

    if (raw_port == NULL || proto == NULL || port == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    split = util_string_split_multi(raw_port, '/');
    if (split == NULL) {
        ERROR("Split proto port from str:%s failed", raw_port);
        ret = -1;
        goto out;
    }

    length = util_array_len((const char **)split);
    if (length == 0 || !util_valid_str(split[0])) {
        goto out;
    }

    if (length == 1) {
        *proto = util_strdup_s("tcp");
        *port = util_strdup_s(raw_port);
        goto out;
    }

    if (!util_valid_str(split[1])) {
        *proto = util_strdup_s("tcp");
        *port = util_strdup_s(split[0]);
        goto out;
    }

    *proto = util_strdup_s(split[1]);
    *port = util_strdup_s(split[0]);

out:
    util_free_array_by_len(split, length);
    return ret;
}

static int parse_format_host_port(const char *value, uint64_t *start_port, uint64_t *end_port)
{
    int ret = 0;
    struct network_port host_p = { 0 };

    if (!util_parse_port_range(value, &host_p)) {
        ERROR("Invalid host port:%s", value);
        ret = -1;
        goto out;
    }

    *start_port = host_p.start;
    *end_port = host_p.end;
out:
    return ret;
}

static int parse_format_container_port(const char *value, uint64_t *start_port, uint64_t *end_port, char **proto)
{
    int ret = 0;
    struct network_port container_p = { 0 };
    char *container_port_range = NULL;
    char *proto_tmp = NULL;

    if (util_split_proto_port(value, &proto_tmp, &container_port_range) != 0) {
        ERROR("Split proto and port from str:%s failed", value);
        ret = -1;
        goto out;
    }

    if (!util_valid_str(container_port_range)) {
        ERROR("No port specified: %s<empty>", value);
        ret = -1;
        goto out;
    }

    if (!util_parse_port_range(container_port_range, &container_p)) {
        ERROR("Invalid container port :%s", container_port_range);
        ret = -1;
        goto out;
    }
    *start_port = container_p.start;
    *end_port = container_p.end;
    *proto = proto_tmp;
    proto_tmp = NULL;

out:
    free(container_port_range);
    free(proto_tmp);
    return ret;
}

char *util_pack_port_proto(uint64_t port, const char *proto)
{
    char port_proto[MAX_BUFFER_SIZE] = { 0 };
    int ret = 0;

    if (proto == NULL) {
        ERROR("Invalid input param");
        return NULL;
    }

    ret = snprintf(port_proto, MAX_BUFFER_SIZE, "%lu/%s", port, proto);
    if (ret < 0 || (size_t)ret >= MAX_BUFFER_SIZE) {
        return NULL;
    }

    return util_strdup_s(port_proto);
}

void util_free_port_mapping(struct port_mapping *data)
{
    if (data == NULL) {
        return;
    }

    UTIL_FREE_AND_SET_NULL(data->host_ip);
    UTIL_FREE_AND_SET_NULL(data->host_port);
    UTIL_FREE_AND_SET_NULL(data->port);

    free(data);
}

static int process_without_host_port(ports_t port_data, struct port_mapping ***ports, size_t *len_ports)
{
    int ret = 0;
    uint64_t i = 0;
    size_t length = 0;
    size_t cnt = 0;
    struct port_mapping **port_map_tmp = NULL;

    port_map_tmp = (struct port_mapping **)util_smart_calloc_s(
                       sizeof(struct port_mapping *), (size_t)(port_data.end_cport - port_data.start_cport + 1));
    if (port_map_tmp == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i <= (port_data.end_cport - port_data.start_cport); i++) {
        port_map_tmp[i] = util_smart_calloc_s(sizeof(struct port_mapping), 1);
        if (port_map_tmp[i] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        length++;

        port_map_tmp[i]->port = util_pack_port_proto(port_data.start_cport + i, port_data.proto);
        if (port_map_tmp[i]->port == NULL) {
            ERROR("Pack container port with proto failed");
            ret = -1;
            goto out;
        }
    }

    *ports = port_map_tmp;
    port_map_tmp = NULL;
    *len_ports = length;
    length = 0;

out:
    for (cnt = 0; cnt < length; cnt++) {
        util_free_port_mapping(port_map_tmp[cnt]);
        port_map_tmp[cnt] = NULL;
    }
    free(port_map_tmp);
    return ret;
}

static int process_range_to_range(ports_t port_data, const char *raw_ip, struct port_mapping ***ports,
                                  size_t *len_ports)
{
    int ret = 0;
    uint64_t i = 0;
    size_t length = 0;
    size_t cnt = 0;
    struct port_mapping **port_map_tmp = NULL;

    port_map_tmp = (struct port_mapping **)util_smart_calloc_s(
                       sizeof(struct port_mapping *), (size_t)(port_data.end_cport - port_data.start_cport + 1));
    if (port_map_tmp == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i <= (port_data.end_cport - port_data.start_cport); i++) {
        char format_host_port[MAX_BUFFER_SIZE] = { 0 };
        int nret = 0;

        nret = snprintf(format_host_port, MAX_BUFFER_SIZE, "%lu", port_data.start_hport + i);
        if (nret < 0 || (size_t)nret >= MAX_BUFFER_SIZE) {
            ERROR("Format print host port err");
            ret = -1;
            goto out;
        }

        port_map_tmp[i] = util_smart_calloc_s(sizeof(struct port_mapping), 1);
        if (port_map_tmp[i] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        length++;

        port_map_tmp[i]->port = util_pack_port_proto(port_data.start_cport + i, port_data.proto);
        if (port_map_tmp[i]->port == NULL) {
            ERROR("Pack container port with proto failed");
            ret = -1;
            goto out;
        }
        port_map_tmp[i]->host_ip = util_strdup_s(raw_ip);
        port_map_tmp[i]->host_port = util_strdup_s(format_host_port);
    }

    *ports = port_map_tmp;
    port_map_tmp = NULL;
    *len_ports = length;
    length = 0;

out:
    for (cnt = 0; cnt < length; cnt++) {
        util_free_port_mapping(port_map_tmp[cnt]);
        port_map_tmp[cnt] = NULL;
    }
    free(port_map_tmp);
    return ret;
}

static int parse_raw_ip(const char *raw_ip, char **ip)
{
    int ret = 0;
    char *ipv6 = NULL;
    size_t len = 0;

    len = strlen(raw_ip);
    if (len < IP_ADDR_MIN_LENGTH) {
        ERROR("Ip addr str too short");
        return -1;
    }

    // ipv6
    if (raw_ip[0] == '[') {
        if (raw_ip[len - 1] != ']') {
            ERROR("Invalid ipv6 addr format");
            ret = -1;
            goto out;
        }
        ipv6 = util_strdup_s(raw_ip);
        ipv6[len - 1] = '\0';

        *ip = util_strdup_s(ipv6 + 1);
    } else {
        if (strchr(raw_ip, ':') != NULL || strchr(raw_ip, '-') != NULL) {
            ERROR("Invalid ipv4 format");
            ret = -1;
            goto out;
        }
        *ip = util_strdup_s(raw_ip);
    }

out:
    free(ipv6);
    return ret;
}

static int parse_port_spec(const char *value, struct port_mapping ***ports, size_t *len_ports)
{
    int ret = 0;
    char *raw_ip = NULL;
    char *ip = NULL;
    char *raw_host_port = NULL;
    char *raw_container_port = NULL;
    ports_t port_data = { 0 };

    if (split_parts(value, &raw_ip, &raw_host_port, &raw_container_port) != 0) {
        ERROR("Split port mapping raw string:%s err", value);
        ret = -1;
        goto out;
    }

    if (util_valid_str(raw_ip)) {
        if (parse_raw_ip(raw_ip, &ip) != 0) {
            ERROR("Parse raw ip failed");
            ret = -1;
            goto out;
        }

        if (!util_validate_ip_address(ip)) {
            ERROR("Invalid input ip addr");
            ret = -1;
            goto out;
        }
    }

    // Parse container port
    if (parse_format_container_port(raw_container_port, &port_data.start_cport, &port_data.end_cport,
                                    &port_data.proto) != 0) {
        ERROR("Failed to get proto and ports from raw container port string");
        ret = -1;
        goto out;
    }

    if (!util_valid_proto(port_data.proto)) {
        ERROR("Invalid proto: %s", port_data.proto);
        ret = -1;
        goto out;
    }

    // 1. Without host port
    if (!util_valid_str(raw_host_port)) {
        if (process_without_host_port(port_data, ports, len_ports) != 0) {
            ERROR("Process port mapping scene of without host ports err");
            ret = -1;
        }
        goto out;
    }

    if (parse_format_host_port(raw_host_port, &port_data.start_hport, &port_data.end_hport) != 0) {
        ERROR("Parse ports from raw host port string:%s failed", raw_host_port);
        ret = -1;
        goto out;
    }

    // 2. container range != host range, illegals
    if (port_data.end_cport - port_data.start_cport != port_data.end_hport - port_data.start_hport) {
        ERROR("Invalid ranges specified for container and host Ports: %s and %s", raw_container_port, raw_host_port);
        ret = -1;
        goto out;
    }

    // 3. container range == host range
    if (process_range_to_range(port_data, ip, ports, len_ports) != 0) {
        ERROR("Process port mapping scene of host ports range equal to container ports range err");
        ret = -1;
        goto out;
    }

out:
    free(raw_ip);
    free(ip);
    free(raw_host_port);
    free(raw_container_port);
    free(port_data.proto);
    return ret;
}

static void port_binding_map_kvfree(void *key, void *value)
{
    free(key);
    free_network_port_binding((network_port_binding *)value);
}

static int util_port_binding_array_append(network_port_binding *binding, const char *host_ip, const char *host_port)
{
    int ret = 0;
    size_t i = 0;
    size_t len = 0;
    network_port_binding_host_element **new_array = NULL;

    if ((binding->host_len + 1) >= SIZE_MAX / sizeof(network_port_binding_host_element *)) {
        ERROR("Too many array elements!");
        return -1;
    }

    new_array = util_smart_calloc_s(sizeof(network_port_binding_host_element *), binding->host_len + 1);
    if (new_array == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }

    for (i = 0; i < (binding->host_len + 1); i++) {
        new_array[i] = util_smart_calloc_s(sizeof(network_port_binding_host_element), 1);
        if (new_array[i] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto free_out;
        }
        len++;

        if (i == binding->host_len) {
            new_array[i]->host_ip = util_strdup_s(host_ip);
            new_array[i]->host_port = util_strdup_s(host_port);
            break;
        }

        new_array[i]->host_ip = util_strdup_s(binding->host[i]->host_ip);
        new_array[i]->host_port = util_strdup_s(binding->host[i]->host_port);
    }

    // Free old array of host info
    for (i = 0; i < binding->host_len; i++) {
        free_network_port_binding_host_element(binding->host[i]);
        binding->host[i] = NULL;
    }
    free(binding->host);

    binding->host = new_array;
    new_array = NULL;
    binding->host_len = len;
    len = 0;

free_out:
    for (i = 0; i < len; i++) {
        free_network_port_binding_host_element(new_array[i]);
        new_array[i] = NULL;
    }
    free(new_array);

    return ret;
}

static int scale_port_binding_arr(map_t *port_binding_m, const struct port_mapping *ports)
{
    int ret = 0;
    network_port_binding *binding = NULL;

    binding = (network_port_binding *)map_search(port_binding_m, ports->port);
    if (binding == NULL) {
        binding = util_smart_calloc_s(sizeof(network_port_binding), 1);
        if (binding == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        if (!map_insert(port_binding_m, ports->port, binding)) {
            ERROR("Insert new host binging element err");
            free_network_port_binding(binding);
            ret = -1;
            goto out;
        }
    }

    if (util_port_binding_array_append(binding, ports->host_ip, ports->host_port) != 0) {
        ERROR("Append new host binding element failed");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int pack_port_data_to_mapping(const char *value, map_t *exposed_m, map_t *port_binding_m)
{
    int ret = 0;
    size_t i = 0;
    struct port_mapping **ports = NULL;
    size_t len_ports = 0;

    if (parse_port_spec(value, &ports, &len_ports) != 0) {
        ERROR("Parse port mapping str err");
        ret = -1;
        goto out;
    }

    for (i = 0; i < len_ports; i++) {
        if (!map_replace(exposed_m, (void *)ports[i]->port, "null")) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        if (scale_port_binding_arr(port_binding_m, ports[i]) != 0) {
            ERROR("Failed to scale host port binding array");
            ret = -1;
            goto out;
        }
    }

out:
    for (i = 0; i < len_ports; i++) {
        util_free_port_mapping(ports[i]);
        ports[i] = NULL;
    }
    free(ports);
    return ret;
}

// parse port data from params to map
int util_parse_port_specs(const char **port_arr, map_t **exposed_map, map_t **port_binding_map)
{
    int ret = 0;
    size_t length = 0;
    size_t i = 0;
    map_t *exposed_m = NULL; // value is null, unused
    map_t *port_binding_m = NULL;

    if (port_arr == NULL || exposed_map == NULL || port_binding_map == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    exposed_m = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (exposed_m == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    port_binding_m = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, port_binding_map_kvfree);
    if (port_binding_m == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    length = util_array_len(port_arr);
    for (i = 0; i < length; i++) {
        if (pack_port_data_to_mapping(port_arr[i], exposed_m, port_binding_m) != 0) {
            ERROR("Failed pack port data to self definitiong mapping");
            ret = -1;
            goto out;
        }
    }
    *exposed_map = exposed_m;
    exposed_m = NULL;
    *port_binding_map = port_binding_m;
    port_binding_m = NULL;

out:
    map_free(exposed_m);
    map_free(port_binding_m);
    return ret;
}

static int pase_expose_single_value(map_t *exposed_m, const char *value)
{
    int ret = 0;
    char *container_port_range = NULL;
    char *proto = NULL;
    char *proto_port = NULL;
    uint64_t port_cnt = 0;
    struct network_port container_p = { 0 };

    if (util_split_proto_port(value, &proto, &container_port_range) != 0) {
        ERROR("Split proto and port from str:%s failed", value);
        ret = -1;
        goto out;
    }

    if (!util_parse_port_range(container_port_range, &container_p)) {
        ERROR("Invalid container port :%s", container_port_range);
        ret = -1;
        goto out;
    }

    for (port_cnt = container_p.start; port_cnt <= container_p.end; port_cnt++) {
        proto_port = util_pack_port_proto(port_cnt, proto);
        if (proto_port == NULL) {
            ERROR("Pack container port with proto failed");
            ret = -1;
            goto out;
        }

        if (!map_replace(exposed_m, (void *)proto_port, "null")) {
            ERROR("Out of memory");
            UTIL_FREE_AND_SET_NULL(proto_port);
            ret = -1;
            goto out;
        }
    }

out:
    free(container_port_range);
    free(proto);
    return ret;
}

int util_parse_expose_ports(const char **expose, map_t **exposed_m)
{
    int ret = 0;
    size_t i = 0;
    size_t length = 0;

    if (expose == NULL || exposed_m == NULL) {
        ERROR("Invalid input param");
        return -1;
    }

    if (*exposed_m == NULL) {
        *exposed_m = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
        if (*exposed_m == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
    }

    length = util_array_len(expose);
    for (i = 0; i < length; i++) {
        if (util_strings_contains_word(expose[i], ":")) {
            COMMAND_ERROR("Invalid port format for --expose: %s", expose[i]);
            ret = -1;
            goto out;
        }

        if (pase_expose_single_value(*exposed_m, expose[i]) != 0) {
            COMMAND_ERROR("Parse param expose value:%s error", expose[i]);
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int copy_network_port_binding(const network_port_binding *old,
                                     defs_map_string_object_port_bindings_element **new)
{
    int ret = 0;
    char *json = NULL;
    struct parser_context ctx = {
        OPT_GEN_SIMPLIFY,
        0,
    };
    parser_error err_json = NULL;
    parser_error err_obj = NULL;
    defs_map_string_object_port_bindings_element *obj_port_binding = NULL;
    network_port_binding *element = NULL;

    obj_port_binding = util_common_calloc_s(sizeof(defs_map_string_object_port_bindings_element));
    if (obj_port_binding == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    json = network_port_binding_generate_json(old, &ctx, &err_json);
    if (json == NULL) {
        ERROR("Marshal network port binding object error:%s", err_json);
        ret = -1;
        goto out;
    }

    element = network_port_binding_parse_data(json, &ctx, &err_obj);
    if (element == NULL) {
        ERROR("Unmarshal json:%s to port binding object error:%s", json, err_obj);
        ret = -1;
        goto out;
    }

    *new = obj_port_binding;
    obj_port_binding = NULL;
    (*new)->element = element;
    element = NULL;

out:
    free(err_json);
    free(err_obj);
    free(json);
    free_defs_map_string_object_port_bindings_element(obj_port_binding);
    free_network_port_binding(element);
    return ret;
}

// defs_map_string_object_port_bindings
int util_copy_port_binding_from_custom_map(defs_map_string_object_port_bindings **data, const map_t *port_binding_m)
{
    int ret = 0;
    size_t len = 0;
    size_t i = 0;
    map_itor *itor = NULL;
    defs_map_string_object_port_bindings *port_bindings = NULL;

    if (data == NULL) {
        return -1;
    }

    len = map_size(port_binding_m);
    if (len == 0) {
        DEBUG("Network publish ports list empty, no need to copy");
        return 0;
    }

    itor = map_itor_new(port_binding_m);
    if (itor == NULL) {
        ERROR("Out of memory, create new map itor failed");
        ret = -1;
        goto out;
    }

    port_bindings = util_common_calloc_s(sizeof(defs_map_string_object_port_bindings));
    if (port_bindings == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    port_bindings->keys = util_common_calloc_s(len * sizeof(char *));
    if (port_bindings->keys == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    port_bindings->values = util_common_calloc_s(len * sizeof(defs_map_string_object_port_bindings_element *));
    if (port_bindings->values == NULL) {
        free(port_bindings->keys);
        port_bindings->keys = NULL;
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (; map_itor_valid(itor) && i < len; map_itor_next(itor), i++) {
        char *key = (char *)map_itor_key(itor);
        network_port_binding *value = (network_port_binding *)map_itor_value(itor);

        if (value == NULL || key == NULL) {
            continue;
        }

        port_bindings->keys[i] = util_strdup_s(key);
        port_bindings->len++;
        if (copy_network_port_binding(value, &port_bindings->values[i]) != 0) {
            ERROR("Copy network port binding err");
            ret = -1;
            goto out;
        }
    }

    *data = port_bindings;
    port_bindings = NULL;

out:
    map_itor_free(itor);
    free_defs_map_string_object_port_bindings(port_bindings);
    return ret;
}

static bool valid_port(uint64_t port)
{
    if (port < 1 || port > 65535) {
        ERROR("Port numbers must be between 1 and 65535 (inclusive), got %lu", port);
        return false;
    }

    return true;
}

bool util_parse_port_range(const char *ports, struct network_port *np)
{
    char **parts = NULL;
    bool ret = true;

    if (ports == NULL || strlen(ports) == 0) {
        ERROR("Empty string specified for ports");
        return false;
    }

    if (strchr(ports, '-') == NULL) {
        if (util_safe_uint64(ports, &np->start) != 0) {
            ERROR("invalid port: %s", ports);
            return false;
        }

        if (!valid_port(np->start)) {
            ERROR("invalid port value:%s", ports);
            return false;
        }
        np->end = np->start;
        return true;
    }

    parts = util_string_split(ports, '-');
    if (parts == NULL || util_array_len((const char **)parts) != 2) {
        ERROR("Invalid port: %s", ports);
        ret = false;
        goto out;
    }

    if (util_safe_uint64(parts[0], &np->start) != 0) {
        ERROR("Invalid port start: %s", parts[0]);
        ret = false;
        goto out;
    }

    if (!valid_port(np->start)) {
        ERROR("invalid port start value:%s", parts[0]);
        ret = false;
        goto out;
    }

    if (util_safe_uint64(parts[1], &np->end) != 0) {
        ERROR("Invalid port end: %s", parts[1]);
        ret = false;
        goto out;
    }

    if (!valid_port(np->end)) {
        ERROR("invalid port start value:%s", parts[1]);
        ret = false;
        goto out;
    }

    if (np->start > np->end) {
        ERROR("Invalid port : %s", ports);
        ret = false;
        goto out;
    }

out:
    if (!ret) {
        np->start = 0;
        np->end = 0;
    }
    util_free_array(parts);
    return ret;
}

bool util_new_network_port(const char *proto, const char *port, struct network_port **res)
{
    struct network_port *work = NULL;
    bool ret = true;
    char buff[MAX_PORT_LEN] = { 0 };

    if (res == NULL || port == NULL) {
        ERROR("Invalid arguments");
        return false;
    }

    work = util_common_calloc_s(sizeof(struct network_port));
    if (work == NULL) {
        ERROR("Out of memory");
        return false;
    }

    if (!util_parse_port_range(port, work)) {
        ret = false;
        goto out;
    }

    if (work->start == work->end) {
        ret = sprintf(buff, "%zu/%s", work->start, proto) > 0;
    } else {
        ret = sprintf(buff, "%zu-%zu/%s", work->start, work->end, proto) > 0;
    }
    if (!ret) {
        ERROR("format port failed");
        goto out;
    }

    work->format_str = util_strdup_s(buff);
    work->proto = util_strdup_s(proto);

    *res = work;
    work = NULL;
out:
    util_free_network_port(work);
    return ret;
}

void util_free_network_port(struct network_port *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->format_str);
    ptr->format_str = NULL;
    free(ptr->proto);
    ptr->proto = NULL;
    ptr->start = 0;
    ptr->end = 0;
    free(ptr);
}

bool util_valid_proto(const char *proto)
{
    size_t i = 0;

    if (proto == NULL) {
        return false;
    }

    for (i = 0; i < PROTO_NUM; i++) {
        if (strcmp(g_proto_whitelist[i], proto) == 0) {
            return true;
        }
    }
    return false;
}

static int do_close(int sock)
{
    size_t i;
    const size_t retry = 10;

    for (i = 0; i < retry; i++) {
        if (close(sock) == 0) {
            return 0;
        }
        WARN("close socket failed: %s, wait to retry: %zu\n", strerror(errno), i);
        // wait 100us to retry
        usleep(10000);
    }

    ERROR("close socket failed: %s", strerror(errno));
    return -1;
}

bool util_check_port_free(int port)
{
    bool ret = true;
    int sock = -1;
    struct sockaddr_in s_addr;

    bzero(&s_addr, sizeof(s_addr));
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = htons(port);
    s_addr.sin_family = AF_INET;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ERROR("get socket failed: %s", strerror(errno));
        return false;
    }

    if (bind(sock, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in)) < 0) {
        ERROR("bind port failed: %s\n", strerror(errno));
        ret = false;
    }

    if (do_close(sock) != 0) {
        ret = false;
    }

    return ret;
}

int util_get_random_port()
{
    int ret = -1;
    int sock = -1;
    struct sockaddr_in s_addr;
    socklen_t s_len;

    bzero(&s_addr, sizeof(s_addr));
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = 0;
    s_addr.sin_family = AF_INET;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ERROR("get socket failed: %s", strerror(errno));
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in)) < 0) {
        ERROR("bind port failed: %s\n", strerror(errno));
        ret = -1;
        goto out;
    }

    s_len = sizeof(struct sockaddr_in);
    if (getsockname(sock, (struct sockaddr *)&s_addr, &s_len) == -1) {
        ERROR("getsockname failed: %s\n", strerror(errno));
        ret = -1;
        goto out;
    }

    ret = ntohs(s_addr.sin_port);

out:
    if (do_close(sock) != 0) {
        return -1;
    }
    return ret;
}