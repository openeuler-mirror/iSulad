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
#ifndef _CRI_HELPERS_H_
#define _CRI_HELPERS_H_
#include <string>
#include <memory>
#include <vector>
#include <map>

#include "api.pb.h"
#include "errors.h"
#include "isula_libutils/host_config.h"
#include "callback.h"
#include "isula_libutils/docker_seccomp.h"
#include "isula_libutils/cri_pod_network.h"
#include "checkpoint_handler.h"
#include "image_api.h"

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
};

std::string GetDefaultSandboxImage(Errors &err);

json_map_string_string *MakeLabels(const google::protobuf::Map<std::string, std::string> &mapLabels, Errors &error);

json_map_string_string *MakeAnnotations(const google::protobuf::Map<std::string, std::string> &mapAnnotations,
                                        Errors &error);

void ExtractLabels(json_map_string_string *input, google::protobuf::Map<std::string, std::string> &labels);

void ExtractAnnotations(json_map_string_string *input, google::protobuf::Map<std::string, std::string> &annotations);

int FiltersAdd(defs_filters *filters, const std::string &key, const std::string &value);

int FiltersAddLabel(defs_filters *filters, const std::string &key, const std::string &value);

void ProtobufAnnoMapToStd(const google::protobuf::Map<std::string, std::string> &annotations,
                          std::map<std::string, std::string> &newAnnos);

runtime::v1alpha2::ContainerState ContainerStatusToRuntime(Container_Status status);

char **StringVectorToCharArray(std::vector<std::string> &path);

imagetool_image *InspectImageByID(const std::string &imageID, Errors &err);

std::string ToPullableImageID(const std::string &id, imagetool_image *image);

bool IsContainerNotFoundError(const std::string &err);

bool IsImageNotFoundError(const std::string &err);

std::string sha256(const char *val);

cri_pod_network_element **GetNetworkPlaneFromPodAnno(const google::protobuf::Map<std::string, std::string> &annotations,
                                                     size_t *len, Errors &error);

std::unique_ptr<runtime::v1alpha2::PodSandbox> CheckpointToSandbox(const std::string &id,
                                                                   const cri::PodSandboxCheckpoint &checkpoint);

std::string StringsJoin(const std::vector<std::string> &vec, const std::string &sep);

void UpdateCreateConfig(container_config *createConfig, host_config *hc,
                        const runtime::v1alpha2::ContainerConfig &config, const std::string &podSandboxID,
                        Errors &error);

void GenerateMountBindings(const google::protobuf::RepeatedPtrField<runtime::v1alpha2::Mount> &mounts,
                           host_config *hostconfig, Errors &err);

std::vector<std::string>
GenerateEnvList(const ::google::protobuf::RepeatedPtrField<::runtime::v1alpha2::KeyValue> &envs);

bool ValidateCheckpointKey(const std::string &key, Errors &error);

std::string ToIsuladContainerStatus(const runtime::v1alpha2::ContainerStateValue &state);

std::vector<std::string> GetSecurityOpts(const std::string &seccompProfile, const char &separator, Errors &error);

std::string CreateCheckpoint(cri::PodSandboxCheckpoint &checkpoint, Errors &error);

void GetCheckpoint(const std::string &jsonCheckPoint, cri::PodSandboxCheckpoint &checkpoint, Errors &error);

}; // namespace CRIHelpers

#endif /* _CRI_HELPERS_H_ */
