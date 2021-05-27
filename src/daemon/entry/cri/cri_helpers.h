/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide cri helpers functions
 *********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_CRI_HELPERS_H
#define DAEMON_ENTRY_CRI_CRI_HELPERS_H
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "api.pb.h"
#include "callback.h"
#include "checkpoint_handler.h"
#include "constants.h"
#include "errors.h"
#include "image_api.h"
#include "isula_libutils/cri_pod_network.h"
#include "isula_libutils/docker_seccomp.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_inspect.h"
namespace CRIHelpers {
class Constants {
public:
    static const std::string DEFAULT_RUNTIME_NAME;
    static const std::string POD_NETWORK_ANNOTATION_KEY;
    static const std::string CONTAINER_TYPE_LABEL_KEY;
    static const std::string CONTAINER_TYPE_LABEL_SANDBOX;
    static const std::string CONTAINER_TYPE_LABEL_CONTAINER;
    static const std::string CONTAINER_LOGPATH_LABEL_KEY;
    static const std::string CONTAINER_HUGETLB_ANNOTATION_KEY;
    static const std::string SANDBOX_ID_LABEL_KEY;
    static const std::string KUBERNETES_CONTAINER_NAME_LABEL;
    // DOCKER_IMAGEID_PREFIX is the prefix of image id in container status.
    static const std::string DOCKER_IMAGEID_PREFIX;
    // DOCKER_PULLABLE_IMAGEID_PREFIX is the prefix of pullable image id in container status.
    static const std::string DOCKER_PULLABLE_IMAGEID_PREFIX;
    static const std::string RUNTIME_READY;
    static const std::string NETWORK_READY;
    static const std::string POD_CHECKPOINT_KEY;
    static const size_t MAX_CHECKPOINT_KEY_LEN { 250 };
    static const std::string CONTAINER_TYPE_ANNOTATION_KEY;
    static const std::string CONTAINER_TYPE_ANNOTATION_CONTAINER;
    static const std::string CONTAINER_TYPE_ANNOTATION_SANDBOX;
    static const std::string SANDBOX_ID_ANNOTATION_KEY;

    static const std::string NET_PLUGIN_EVENT_POD_CIDR_CHANGE;
    static const std::string NET_PLUGIN_EVENT_POD_CIDR_CHANGE_DETAIL_CIDR;
    static const std::string CNI_MUTL_NET_EXTENSION_KEY;
    static const std::string CNI_MUTL_NET_EXTENSION_ARGS_KEY;
    static const std::string CNI_ARGS_EXTENSION_PREFIX_KEY;
};

auto GetDefaultSandboxImage(Errors &err) -> std::string;

auto MakeLabels(const google::protobuf::Map<std::string, std::string> &mapLabels, Errors &error)
-> json_map_string_string *;

auto MakeAnnotations(const google::protobuf::Map<std::string, std::string> &mapAnnotations, Errors &error)
-> json_map_string_string *;

void ExtractLabels(json_map_string_string *input, google::protobuf::Map<std::string, std::string> &labels);

void ExtractAnnotations(json_map_string_string *input, google::protobuf::Map<std::string, std::string> &annotations);

auto FiltersAdd(defs_filters *filters, const std::string &key, const std::string &value) -> int;

auto FiltersAddLabel(defs_filters *filters, const std::string &key, const std::string &value) -> int;

void ProtobufAnnoMapToStd(const google::protobuf::Map<std::string, std::string> &annotations,
                          std::map<std::string, std::string> &newAnnos);

auto ContainerStatusToRuntime(Container_Status status) -> runtime::v1alpha2::ContainerState;

auto StringVectorToCharArray(std::vector<std::string> &path) -> char **;

auto InspectImageByID(const std::string &imageID, Errors &err) -> imagetool_image_summary *;

auto ToPullableImageID(const char *image_name, const char *image_ref) -> std::string;

auto IsContainerNotFoundError(const std::string &err) -> bool;

auto IsImageNotFoundError(const std::string &err) -> bool;

auto sha256(const char *val) -> std::string;

auto GetNetworkPlaneFromPodAnno(const std::map<std::string, std::string> &annotations, size_t *len, Errors &error)
-> cri_pod_network_element **;

auto CheckpointToSandbox(const std::string &id, const CRI::PodSandboxCheckpoint &checkpoint)
-> std::unique_ptr<runtime::v1alpha2::PodSandbox>;

auto StringsJoin(const std::vector<std::string> &vec, const std::string &sep) -> std::string;

void UpdateCreateConfig(container_config *createConfig, host_config *hc,
                        const runtime::v1alpha2::ContainerConfig &config, const std::string &podSandboxID,
                        Errors &error);

void GenerateMountBindings(const google::protobuf::RepeatedPtrField<runtime::v1alpha2::Mount> &mounts,
                           host_config *hostconfig, Errors &err);

auto GenerateEnvList(const ::google::protobuf::RepeatedPtrField<::runtime::v1alpha2::KeyValue> &envs)
-> std::vector<std::string>;

auto ValidateCheckpointKey(const std::string &key, Errors &error) -> bool;

auto ToIsuladContainerStatus(const runtime::v1alpha2::ContainerStateValue &state) -> std::string;

auto GetSecurityOpts(const std::string &seccompProfile, const char &separator, Errors &error)
-> std::vector<std::string>;

auto CreateCheckpoint(CRI::PodSandboxCheckpoint &checkpoint, Errors &error) -> std::string;

void GetCheckpoint(const std::string &jsonCheckPoint, CRI::PodSandboxCheckpoint &checkpoint, Errors &error);

auto InspectContainer(const std::string &Id, Errors &err, bool with_host_config) -> container_inspect *;

auto ToInt32Timeout(int64_t timeout) -> int32_t;

void GetContainerLogPath(const std::string &containerID, char **path, char **realPath, Errors &error);

void RemoveContainerLogSymlink(const std::string &containerID, Errors &error);

void GetContainerTimeStamps(const container_inspect *inspect, int64_t *createdAt,
                            int64_t *startedAt, int64_t *finishedAt, Errors &err);

auto GetRealContainerOrSandboxID(service_executor_t *cb, const std::string &id,
                                 bool isSandbox, Errors &error) -> std::string;

void RemoveContainer(service_executor_t *cb, const std::string &containerID, Errors &error);

void StopContainer(service_executor_t *cb, const std::string &containerID, int64_t timeout, Errors &error);

char *GenerateExecSuffix();
}; // namespace CRIHelpers

#endif // DAEMON_ENTRY_CRI_CRI_HELPERS_H
