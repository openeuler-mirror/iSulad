/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Start: 2022-06-30
 * Description: implement grpc container stats service functions
 ******************************************************************************/
#include "stats_service.h"

void ContainerStatsService::SetThreadName()
{
    SetOperationThreadName("ContStats");
}

Status ContainerStatsService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_stats");
}

bool ContainerStatsService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.stats != nullptr;
}

int ContainerStatsService::FillRequestFromgRPC(const StatsRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_stats_request *>(util_common_calloc_s(sizeof(container_stats_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->containers_size() > 0) {
        tmpreq->containers = (char **)util_smart_calloc_s(sizeof(char *), request->containers_size());
        if (tmpreq->containers == nullptr) {
            ERROR("Out of memory");
            free_container_stats_request(tmpreq);
            return -1;
        }
        for (int i = 0; i < request->containers_size(); i++) {
            tmpreq->containers[i] = util_strdup_s(request->containers(i).c_str());
            tmpreq->containers_len++;
        }
    }

    tmpreq->all = request->all();

    *static_cast<container_stats_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerStatsService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.stats(static_cast<container_stats_request *>(containerReq),
                              static_cast<container_stats_response **>(containerRes));
}

void ContainerStatsService::FillResponseTogRPC(void *containerRes, StatsResponse *gresponse)
{
    const container_stats_response *response = static_cast<const container_stats_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->container_stats == nullptr || response->container_stats_len == 0) {
        return;
    }
    for (size_t i = 0; i < response->container_stats_len; i++) {
        containers::Container_info *stats = gresponse->add_containers();
        if (response->container_stats[i]->id != nullptr) {
            stats->set_id(response->container_stats[i]->id);
        }
        stats->set_pids_current(response->container_stats[i]->pids_current);
        stats->set_cpu_use_nanos(response->container_stats[i]->cpu_use_nanos);
        stats->set_cpu_system_use(response->container_stats[i]->cpu_system_use);
        stats->set_online_cpus(response->container_stats[i]->online_cpus);
        stats->set_blkio_read(response->container_stats[i]->blkio_read);
        stats->set_blkio_write(response->container_stats[i]->blkio_write);
        stats->set_mem_used(response->container_stats[i]->mem_used);
        stats->set_mem_limit(response->container_stats[i]->mem_limit);
        stats->set_kmem_used(response->container_stats[i]->kmem_used);
        stats->set_kmem_limit(response->container_stats[i]->kmem_limit);
        stats->set_avaliable_bytes(response->container_stats[i]->avaliable_bytes);
        stats->set_workingset_bytes(response->container_stats[i]->workingset_bytes);
        stats->set_mem_used(response->container_stats[i]->mem_used);
        stats->set_rss_bytes(response->container_stats[i]->rss_bytes);
        stats->set_page_faults(response->container_stats[i]->page_faults);
        stats->set_major_page_faults(response->container_stats[i]->major_page_faults);
        if (response->container_stats[i]->name != nullptr) {
            stats->set_name(response->container_stats[i]->name);
        }
        if (response->container_stats[i]->status != nullptr) {
            stats->set_status(response->container_stats[i]->status);
        }
        stats->set_cache(response->container_stats[i]->cache);
        stats->set_cache_total(response->container_stats[i]->cache_total);
        stats->set_inactive_file_total(response->container_stats[i]->inactive_file_total);
    }
}

void ContainerStatsService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_stats_request(static_cast<container_stats_request *>(containerReq));
    free_container_stats_response(static_cast<container_stats_response *>(containerRes));
}