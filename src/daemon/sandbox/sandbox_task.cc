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
#include "sandbox_task.h"

#include <mutex>

#include <isula_libutils/log.h>

#include "utils.h"
#include "errors.h"

namespace sandbox {

SandboxTask::SandboxTask(sandbox_task *task): m_task(task)
{
}

SandboxTask::~SandboxTask()
{
    free_sandbox_task(m_task);
    m_task = nullptr;
}

auto SandboxTask::GetTask() -> sandbox_task *
{
    ReadGuard<RWMutex> lock(m_taskMutex);
    return m_task;
}

auto SandboxTask::AddSandboxTasksProcess(sandbox_process *processes) -> bool
{
    if (processes == nullptr) {
        ERROR("Empty args.");
        return false;
    }

    WriteGuard<RWMutex> lock(m_taskMutex);
    if (util_mem_realloc((void **)(&m_task->processes),
                         (m_task->processes_len + 1) * sizeof(sandbox_process *),
                         (void *)m_task->processes,
                         m_task->processes_len * sizeof(sandbox_process *)) != 0) {  
        ERROR("Out of memory");
        return false;
    }
    m_task->processes[m_task->processes_len] = processes;
    m_task->processes_len++;

    return true;
}

auto SandboxTask::FindProcessByID(const char *execId) -> int
{
    int i;
    int processes_len = m_task->processes_len;

    if (m_task->processes == nullptr) {
        return -1;
    }

    for (i = 0; i < processes_len; i++) {
        if (strcmp(m_task->processes[i]->exec_id, execId) == 0) {
            return i;
        }
    }
    return -1;
}

void SandboxTask::DeleteSandboxTasksProcess(const char *execId)
{
    if (execId == nullptr) {
        return;
    }

    int idx;

    WriteGuard<RWMutex> lock(m_taskMutex);
    idx = FindProcessByID(execId);
    if (idx < 0) {
        return;
    }
    free_sandbox_process(m_task->processes[idx]);
    m_task->processes[idx] = nullptr;
    if (idx != (int)m_task->processes_len - 1) {
        (void)memcpy((void **)&m_task->processes[idx], (void **)&m_task->processes[idx + 1],
            (m_task->processes_len - idx - 1) * sizeof(void *));
    }
    m_task->processes_len--;
}

}