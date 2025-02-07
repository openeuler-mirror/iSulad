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
 * Create: 2024-10-22
 * Description: provide sandbox class definition
 *********************************************************************************/

#ifndef DAEMON_SANDBOX_SANDBOX_TASK_H
#define DAEMON_SANDBOX_SANDBOX_TASK_H

#include <string>
#include <mutex>

#include <isula_libutils/sandbox_tasks.h>

#include "api_v1.grpc.pb.h"
#include "errors.h"
#include "read_write_lock.h"

namespace sandbox {

class SandboxTask : public std::enable_shared_from_this<SandboxTask> {
public:
    SandboxTask(sandbox_task *task);
    ~SandboxTask();

    auto GetTask() -> sandbox_task *;
    auto AddSandboxTasksProcess(sandbox_process *processes) -> bool;
    void DeleteSandboxTasksProcess(const char *execId);

private:
    auto FindProcessByID(const char *execId) -> int;
private:
    // Do not modify m_task concurrently.
    RWMutex m_taskMutex;
    sandbox_task *m_task;
};
} // namespace sandbox

#endif // DAEMON_SANDBOX_SANDBOX_TASK_H