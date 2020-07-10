/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-02-11
 * Description: provide selinux label mock
 ******************************************************************************/


#ifndef _ISULAD_TEST_MOCKS_SELINUX_LABEL_MOCK_H
#define _ISULAD_TEST_MOCKS_SELINUX_LABEL_MOCK_H

#include <gmock/gmock.h>
#include "selinux_label.h"

class MockSelinuxLabel {
public:
    virtual ~MockSelinuxLabel() = default;
    MOCK_METHOD0(SelinuxStateInit, int(void));
    MOCK_METHOD0(SelinuxSetDisabled, void(void));
    MOCK_METHOD0(SelinuxGetEnable, bool(void));
    MOCK_METHOD4(InitLabel,
                 int(const char **label_opts, size_t label_opts_len, char **process_label, char **mount_label));
    MOCK_METHOD3(Relabel, int(const char *path, const char *file_label, bool shared));
    MOCK_METHOD2(GetDisableSecurityOpt, int(char ***labels, size_t *labels_len));
    MOCK_METHOD3(DupSecurityOpt, int(const char *src, char ***dst, size_t *len));
};

void SelinuxLabel_SetMock(MockSelinuxLabel* mock);

#endif // _ISULAD_TEST_MOCKS_SELINUX_LABEL_MOCK_H
