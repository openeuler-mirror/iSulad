/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: utils_network unit test
 * Author: zhangxiaoyu
 * Create: 2023-01-17
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "utils.h"
#include "utils_network.h"

TEST(utils_network, test_parse_ip_from_str)
{
    const char *invalid1 = "192.168";
    const char *invalid2 = "192.168.1.1.1";
    const char *invalid3 = "fe80::215:5dff:fe58:f046::";

    const char *ipv4 = "192.168.123.4";
    uint8_t ipv4_ip[IPV4LEN] = {192, 168, 123, 4};
    const char *ipv6 = "fe80::215:5dff:fe58:f046";
    uint8_t ipv6_ip[IPV6LEN] = {254, 128, 0, 0, 0, 0, 0, 0, 2, 21, 93, 255, 254, 88, 240, 70};

    uint8_t *ips = nullptr;
    size_t len = 0;

    ASSERT_EQ(util_parse_ip_from_str(nullptr, &ips, &len), -1);
    ASSERT_EQ(util_parse_ip_from_str(ipv4, nullptr, &len), -1);
    ASSERT_EQ(util_parse_ip_from_str(ipv4, &ips, nullptr), -1);

    ASSERT_EQ(util_parse_ip_from_str("", &ips, &len), -1);
    ASSERT_EQ(util_parse_ip_from_str(invalid1, &ips, &len), -1);
    ASSERT_EQ(util_parse_ip_from_str(invalid2, &ips, &len), -1);
    ASSERT_EQ(util_parse_ip_from_str(invalid3, &ips, &len), -1);

    ASSERT_EQ(util_parse_ip_from_str(ipv4, &ips, &len), 0);
    ASSERT_EQ(len, IPV4LEN);
    for (size_t i = 0; i < IPV4LEN; i++) {
        ASSERT_EQ(ips[i], ipv4_ip[i]);
    }
    free(ips);

    ASSERT_EQ(util_parse_ip_from_str(ipv6, &ips, &len), 0);
    ASSERT_EQ(len, IPV6LEN);
    for (size_t i = 0; i < IPV6LEN; i++) {
        ASSERT_EQ(ips[i], ipv6_ip[i]);
    }
    free(ips);
}

TEST(utils_network, test_ip_to_string)
{
    uint8_t nonstandard[] = {1, 2, 3, 4, 5, 166};
    uint8_t ipv4_ip[IPV4LEN] = {192, 168, 123, 4};
    uint8_t ipv6_ip[IPV6LEN] = {254, 128, 0, 0, 0, 0, 0, 0, 2, 21, 93, 255, 254, 88, 240, 70};
    uint8_t ipv4_mapped[IPV6LEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 254, 88, 240, 70};
    char *result = nullptr;

    result = util_ip_to_string(nullptr, 0);
    ASSERT_STREQ(result, "<nil>");
    free(result);

    result = util_ip_to_string(nonstandard, 6);
    ASSERT_STREQ(result, "?0102030405a6");
    free(result);

    result = util_ip_to_string(ipv4_ip, IPV4LEN);
    ASSERT_STREQ(result, "192.168.123.4");
    free(result);

    result = util_ip_to_string(ipv6_ip, IPV6LEN);
    ASSERT_STREQ(result, "fe80::215:5dff:fe58:f046");
    free(result);

    result = util_ip_to_string(ipv4_mapped, IPV6LEN);
    ASSERT_STREQ(result, "254.88.240.70");
    free(result);
}

TEST(utils_network, test_parse_ipnet_from_str)
{
    const char *invalid1 = "192.168.1.1";
    const char *invalid2 = "192.168.1.1.1/16";
    const char *invalid3 = "fe80::215:5dff:fe58:f046::/64";
    const char *invalid4 = "fe80::215::fe58:f046::1/64";

    const char *ipv4 = "192.168.123.4/15";
    uint8_t ipv4_ip[] = {192, 168, 123, 4};
    uint8_t ipv4_mask[] = {255, 254, 0, 0};
    struct ipnet ipv4_ipnet = {
        .ip = ipv4_ip,
        .ip_len = IPV4LEN,
        .ip_mask = ipv4_mask,
        .ip_mask_len = IPV4LEN,
    };

    const char *ipv6_1 = "fe80::215:5dff:fe58:f046/66";
    uint8_t ipv6_ip_1[] = {254, 128, 0, 0, 0, 0, 0, 0, 2, 21, 93, 255, 254, 88, 240, 70};
    uint8_t ipv6_mask_1[] = {255, 255, 255, 255, 255, 255, 255, 255, 192, 0, 0, 0, 0, 0, 0, 0};
    struct ipnet ipv6_ipnet_1 = {
        .ip = ipv6_ip_1,
        .ip_len = IPV6LEN,
        .ip_mask = ipv6_mask_1,
        .ip_mask_len = IPV6LEN,
    };
    const char *ipv6_2 = "::1/128";
    uint8_t ipv6_ip_2[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t ipv6_mask_2[] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
    struct ipnet ipv6_ipnet_2 = {
        .ip = ipv6_ip_2,
        .ip_len = IPV6LEN,
        .ip_mask = ipv6_mask_2,
        .ip_mask_len = IPV6LEN,
    };

    struct ipnet *ipnet_val = nullptr;

    ASSERT_EQ(util_parse_ipnet_from_str(nullptr, &ipnet_val), -1);
    ASSERT_EQ(util_parse_ipnet_from_str(ipv4, nullptr), -1);

    ASSERT_EQ(util_parse_ipnet_from_str("", &ipnet_val), -1);
    ASSERT_EQ(util_parse_ipnet_from_str(invalid1, &ipnet_val), -1);
    ASSERT_EQ(util_parse_ipnet_from_str(invalid2, &ipnet_val), -1);
    ASSERT_EQ(util_parse_ipnet_from_str(invalid3, &ipnet_val), -1);
    ASSERT_EQ(util_parse_ipnet_from_str(invalid4, &ipnet_val), -1);
    ASSERT_EQ(util_parse_ipnet_from_str("0.0.0.0/0", &ipnet_val), 0);
    util_free_ipnet(ipnet_val);
    ASSERT_EQ(util_parse_ipnet_from_str("::/128", &ipnet_val), 0);
    util_free_ipnet(ipnet_val);

    ASSERT_EQ(util_parse_ipnet_from_str(ipv4, &ipnet_val), 0);
    ASSERT_EQ(ipnet_val->ip_len, ipv4_ipnet.ip_len);
    ASSERT_EQ(ipnet_val->ip_mask_len, ipv4_ipnet.ip_mask_len);
    for (size_t i = 0; i < ipnet_val->ip_len; i++) {
        ASSERT_EQ(ipnet_val->ip[i], ipv4_ipnet.ip[i]);
        ASSERT_EQ(ipnet_val->ip_mask[i], ipv4_ipnet.ip_mask[i]);
    }
    util_free_ipnet(ipnet_val);

    ASSERT_EQ(util_parse_ipnet_from_str(ipv6_1, &ipnet_val), 0);
    ASSERT_EQ(ipnet_val->ip_len, ipv6_ipnet_1.ip_len);
    ASSERT_EQ(ipnet_val->ip_mask_len, ipv6_ipnet_1.ip_mask_len);
    for (size_t i = 0; i < ipnet_val->ip_len; i++) {
        ASSERT_EQ(ipnet_val->ip[i], ipv6_ipnet_1.ip[i]);
        ASSERT_EQ(ipnet_val->ip_mask[i], ipv6_ipnet_1.ip_mask[i]);
    }
    util_free_ipnet(ipnet_val);

    ASSERT_EQ(util_parse_ipnet_from_str(ipv6_2, &ipnet_val), 0);
    ASSERT_EQ(ipnet_val->ip_len, ipv6_ipnet_2.ip_len);
    ASSERT_EQ(ipnet_val->ip_mask_len, ipv6_ipnet_2.ip_mask_len);
    for (size_t i = 0; i < ipnet_val->ip_len; i++) {
        ASSERT_EQ(ipnet_val->ip[i], ipv6_ipnet_2.ip[i]);
        ASSERT_EQ(ipnet_val->ip_mask[i], ipv6_ipnet_2.ip_mask[i]);
    }
    util_free_ipnet(ipnet_val);
}

TEST(utils_network, test_ipnet_to_string)
{
    uint8_t invalid_ip1[] = {192, 168, 1, 1, 1};
    uint8_t invalid_mask1[] = {255, 255, 255, 0, 0};

    uint8_t ipv4_ip[IPV4LEN] = {192, 168, 123, 4};
    uint8_t ipv4_mask[IPV4LEN] = {255, 254, 0, 0};
    uint8_t ipv6_ip[IPV6LEN] = {254, 128, 0, 0, 0, 0, 0, 0, 2, 21, 93, 255, 254, 88, 240, 70};
    uint8_t ipv6_mask[IPV6LEN] = {255, 255, 255, 255, 255, 255, 255, 255, 192, 0, 0, 0, 0, 0, 0, 0};
    uint8_t ipv4_mapped_ip[IPV6LEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 254, 88, 240, 70};
    uint8_t ipv4_mapped_mask[IPV6LEN] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 240, 0};

    struct ipnet invalid1_ipnet = {
        .ip = invalid_ip1,
        .ip_len = 5,
        .ip_mask = invalid_mask1,
        .ip_mask_len = 5,
    };
    struct ipnet invalid2_ipnet = {
        .ip = ipv4_ip,
        .ip_len = IPV4LEN,
        .ip_mask = ipv6_mask,
        .ip_mask_len = IPV6LEN,
    };

    struct ipnet ipv4_ipnet = {
        .ip = ipv4_ip,
        .ip_len = IPV4LEN,
        .ip_mask = ipv4_mask,
        .ip_mask_len = IPV4LEN,
    };
    struct ipnet ipv6_ipnet = {
        .ip = ipv6_ip,
        .ip_len = IPV6LEN,
        .ip_mask = ipv6_mask,
        .ip_mask_len = IPV6LEN,
    };
    struct ipnet ipv4_mapped = {
        .ip = ipv4_mapped_ip,
        .ip_len = IPV6LEN,
        .ip_mask = ipv4_mapped_mask,
        .ip_mask_len = IPV6LEN,
    };
    char *result = nullptr;

    ASSERT_STREQ(util_ipnet_to_string(nullptr), nullptr);
    ASSERT_STREQ(util_ipnet_to_string(&invalid1_ipnet), nullptr);
    ASSERT_STREQ(util_ipnet_to_string(&invalid2_ipnet), nullptr);

    result = util_ipnet_to_string(&ipv4_ipnet);
    ASSERT_STREQ(result, "192.168.123.4/15");
    free(result);

    result = util_ipnet_to_string(&ipv6_ipnet);
    ASSERT_STREQ(result, "fe80::215:5dff:fe58:f046/66");
    free(result);

    result = util_ipnet_to_string(&ipv4_mapped);
    ASSERT_STREQ(result, "254.88.240.70/20");
    free(result);

    // nonstandard ?
    uint8_t ipv4_mask_nonstandard[IPV4LEN] = {255, 254, 0, 1};
    struct ipnet ipv4_ipnet_nonstandard = {
        .ip = ipv4_ip,
        .ip_len = IPV4LEN,
        .ip_mask = ipv4_mask_nonstandard,
        .ip_mask_len = IPV4LEN,
    };
    result = util_ipnet_to_string(&ipv4_ipnet_nonstandard);
    ASSERT_STREQ(result, "192.168.123.4/fffe0001");
    free(result);
}

TEST(utils_network, test_reduce_ip_by_mask)
{
    uint8_t ipv4_ip[IPV4LEN] = {192, 168, 123, 4};
    uint8_t ipv4_mask[IPV4LEN] = {255, 255, 240, 0};
    uint8_t ipv4_ip_reduce[IPV4LEN] = {192, 168, 112, 0};

    uint8_t ipv6_ip[IPV6LEN] = {254, 128, 0, 0, 0, 0, 0, 0, 193, 21, 93, 255, 254, 88, 240, 70};
    uint8_t ipv6_mask[IPV6LEN] = {255, 255, 255, 255, 255, 255, 255, 255, 192, 0, 0, 0, 0, 0, 0, 0};
    uint8_t ipv6_ip_reduce[IPV6LEN] = {254, 128, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 0};

    struct ipnet invalid_ipnet = {
        .ip = ipv4_ip,
        .ip_len = IPV4LEN,
        .ip_mask = ipv6_mask,
        .ip_mask_len = IPV6LEN,
    };
    struct ipnet ipv4_ipnet = {
        .ip = ipv4_ip,
        .ip_len = IPV4LEN,
        .ip_mask = ipv4_mask,
        .ip_mask_len = IPV4LEN,
    };
    struct ipnet ipv6_ipnet = {
        .ip = ipv6_ip,
        .ip_len = IPV6LEN,
        .ip_mask = ipv6_mask,
        .ip_mask_len = IPV6LEN,
    };

    ASSERT_EQ(util_reduce_ip_by_mask(nullptr), -1);
    ASSERT_EQ(util_reduce_ip_by_mask(&invalid_ipnet), -1);

    ASSERT_EQ(util_reduce_ip_by_mask(&ipv4_ipnet), 0);
    for (size_t i = 0; i < IPV4LEN; i++) {
        ASSERT_EQ(ipv4_ipnet.ip[i], ipv4_ip_reduce[i]);
    }

    ASSERT_EQ(util_reduce_ip_by_mask(&ipv6_ipnet), 0);
    for (size_t i = 0; i < IPV4LEN; i++) {
        ASSERT_EQ(ipv6_ipnet.ip[i], ipv6_ip_reduce[i]);
    }
}

TEST(utils_network, test_net_contain_ip)
{
    uint8_t ipv4_test_ip[IPV4LEN] = {192, 168, 123, 4};
    uint8_t ipv4_first_ip[IPV4LEN] = {192, 168, 112, 0};
    uint8_t ipv4_last_ip[IPV4LEN] = {192, 168, 127, 255};
    uint8_t ipv4_ip[IPV4LEN] = {192, 168, 123, 4};
    uint8_t ipv4_mask[IPV4LEN] = {255, 255, 240, 0};

    uint8_t ipv6_test_ip[IPV6LEN] = {254, 128, 233, 126, 0, 0, 0, 0, 65, 21, 93, 255, 254, 88, 240, 70};
    uint8_t ipv6_first_ip[IPV6LEN] = {254, 128, 233, 126, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0};
    uint8_t ipv6_last_ip[IPV6LEN] = {254, 128, 233, 126, 0, 0, 0, 0, 127, 255, 255, 255, 255, 255, 255, 255};
    uint8_t ipv6_ip[IPV6LEN] = {254, 128, 233, 126, 0, 0, 0, 0, 65, 21, 93, 255, 254, 88, 240, 70};
    uint8_t ipv6_mask[IPV6LEN] = {255, 255, 255, 255, 255, 255, 255, 255, 192, 0, 0, 0, 0, 0, 0, 0};

    struct ipnet ipv4_ipnet = {
        .ip = ipv4_ip,
        .ip_len = IPV4LEN,
        .ip_mask = ipv4_mask,
        .ip_mask_len = IPV4LEN,
    };
    struct ipnet ipv6_ipnet = {
        .ip = ipv6_ip,
        .ip_len = IPV6LEN,
        .ip_mask = ipv6_mask,
        .ip_mask_len = IPV6LEN,
    };


    ASSERT_EQ(util_net_contain_ip(nullptr, ipv4_test_ip, IPV4LEN, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, nullptr, 0, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv6_test_ip, IPV6LEN, false), false);

    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_test_ip, IPV4LEN, false), true);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_first_ip, IPV4LEN, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_first_ip, IPV4LEN, true), true);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_last_ip, IPV4LEN, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_last_ip, IPV4LEN, true), true);

    ASSERT_EQ(util_reduce_ip_by_mask(&ipv4_ipnet), 0);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_test_ip, IPV4LEN, false), true);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_first_ip, IPV4LEN, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_first_ip, IPV4LEN, true), true);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_last_ip, IPV4LEN, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv4_ipnet, ipv4_last_ip, IPV4LEN, true), true);

    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_test_ip, IPV6LEN, false), true);
    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_first_ip, IPV6LEN, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_first_ip, IPV6LEN, true), true);
    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_last_ip, IPV6LEN, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_last_ip, IPV6LEN, true), true);

    ASSERT_EQ(util_reduce_ip_by_mask(&ipv6_ipnet), 0);
    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_test_ip, IPV6LEN, false), true);
    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_first_ip, IPV6LEN, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_first_ip, IPV6LEN, true), true);
    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_last_ip, IPV6LEN, false), false);
    ASSERT_EQ(util_net_contain_ip(&ipv6_ipnet, ipv6_last_ip, IPV6LEN, true), true);
}

TEST(utils_network, test_validate_network_name)
{
    ASSERT_EQ(util_validate_network_name(nullptr), false);
    ASSERT_EQ(util_validate_network_name(std::string(128, 'a').c_str()), true);
    ASSERT_EQ(util_validate_network_name(std::string(129, 'a').c_str()), false);
    ASSERT_EQ(util_validate_network_name(std::string(".abce").c_str()), false);
}

TEST(utils_network, test_native_network_checker)
{
    ASSERT_EQ(util_native_network_checker(nullptr), false);
    ASSERT_EQ(util_native_network_checker("bridge"), true);
    ASSERT_EQ(util_native_network_checker("none"), false);
}

TEST(utils_network, test_post_setup_network)
{
    ASSERT_EQ(util_post_setup_network(nullptr), false);
    ASSERT_EQ(util_post_setup_network("100000:100000:65535"), true);
}

TEST(utils_network, test_validate_network_interface)
{
    ASSERT_EQ(util_validate_network_interface(nullptr), false);
    ASSERT_EQ(util_validate_network_interface(""), false);
    ASSERT_EQ(util_validate_network_interface(std::string(15, 'a').c_str()), true);
    ASSERT_EQ(util_validate_network_interface(std::string(16, 'a').c_str()), false);
    ASSERT_EQ(util_validate_network_interface("."), false);
    ASSERT_EQ(util_validate_network_interface(".."), false);
    ASSERT_EQ(util_validate_network_interface("abc/"), false);
    ASSERT_EQ(util_validate_network_interface("def:gh"), false);
}

TEST(utils_network, test_validate_ip_address)
{
    const char *invalid1 = "192.168";
    const char *invalid2 = "192.168.1.1.1";
    const char *invalid3 = "fe80::215:5dff:fe58:f046::";

    const char *ipv4 = "192.168.123.4";
    const char *ipv6 = "fe80::215:5dff:fe58:f046";

    ASSERT_EQ(util_validate_ip_address(nullptr), false);
    ASSERT_EQ(util_validate_ip_address(""), false);
    ASSERT_EQ(util_validate_ip_address(invalid1), false);
    ASSERT_EQ(util_validate_ip_address(invalid2), false);
    ASSERT_EQ(util_validate_ip_address(invalid3), false);
    ASSERT_EQ(util_validate_ip_address(ipv4), true);
    ASSERT_EQ(util_validate_ip_address(ipv6), true);

    ASSERT_EQ(util_validate_ipv4_address(ipv4), true);
    ASSERT_EQ(util_validate_ipv4_address(ipv6), false);
    ASSERT_EQ(util_validate_ipv6_address(ipv4), false);
    ASSERT_EQ(util_validate_ipv6_address(ipv6), true);
}

TEST(utils_network, test_validate_mac_address)
{
    ASSERT_EQ(util_validate_mac_address(nullptr), false);
    ASSERT_EQ(util_validate_mac_address(""), false);
    ASSERT_EQ(util_validate_mac_address("00:15:5d:58:f2"), false);
    ASSERT_EQ(util_validate_mac_address(":00:15:5d:58:f2:5e"), false);
    ASSERT_EQ(util_validate_mac_address("00:15:5d:58:f2:5e:"), false);
    ASSERT_EQ(util_validate_mac_address("00:15:5d:58:f2:5v"), false);
    ASSERT_EQ(util_validate_mac_address("00:15:5d:5-:f2:5e"), false);
    ASSERT_EQ(util_validate_mac_address("00:15:5d:58:f2:5e"), true);
}
