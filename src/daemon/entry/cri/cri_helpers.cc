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
 * Description: provide cni network plugin
 *********************************************************************************/

#include "cri_helpers.h"
#include <algorithm>
#include <functional>
#include <iostream>
#include <openssl/sha.h>
#include <sys/utsname.h>
#include <utility>

#include "api.pb.h"
#include "cri_runtime_service.h"
#include "cri_security_context.h"
#include "cxxutils.h"
#include "isula_libutils/log.h"
#include "isula_libutils/parse_common.h"
#include "path.h"
#include "utils.h"

namespace CRIHelpers {
const std::string Constants::DEFAULT_RUNTIME_NAME { "lcr" };
const std::string Constants::POD_NETWORK_ANNOTATION_KEY { "network.alpha.kubernetes.io/network" };
const std::string Constants::CONTAINER_TYPE_LABEL_KEY { "cri.isulad.type" };
const std::string Constants::CONTAINER_TYPE_LABEL_SANDBOX { "podsandbox" };
const std::string Constants::CONTAINER_TYPE_LABEL_CONTAINER { "container" };
const std::string Constants::CONTAINER_LOGPATH_LABEL_KEY { "cri.container.logpath" };
const std::string Constants::CONTAINER_HUGETLB_ANNOTATION_KEY { "cri.container.hugetlblimit" };
const std::string Constants::SANDBOX_ID_LABEL_KEY { "cri.sandbox.id" };
const std::string Constants::KUBERNETES_CONTAINER_NAME_LABEL { "io.kubernetes.container.name" };
const std::string Constants::DOCKER_IMAGEID_PREFIX { "docker://" };
const std::string Constants::DOCKER_PULLABLE_IMAGEID_PREFIX { "docker-pullable://" };
const std::string Constants::RUNTIME_READY { "RuntimeReady" };
const std::string Constants::NETWORK_READY { "NetworkReady" };
const std::string Constants::POD_CHECKPOINT_KEY { "cri.sandbox.isulad.checkpoint" };
const std::string Constants::CONTAINER_TYPE_ANNOTATION_KEY { "io.kubernetes.cri.container-type" };
const std::string Constants::CONTAINER_TYPE_ANNOTATION_CONTAINER { "container" };
const std::string Constants::CONTAINER_TYPE_ANNOTATION_SANDBOX { "sandbox" };
const std::string Constants::SANDBOX_ID_ANNOTATION_KEY { "io.kubernetes.cri.sandbox-id" };
const std::string Constants::NET_PLUGIN_EVENT_POD_CIDR_CHANGE { "pod-cidr-change" };
const std::string Constants::NET_PLUGIN_EVENT_POD_CIDR_CHANGE_DETAIL_CIDR { "pod-cidr" };
const std::string Constants::CNI_MUTL_NET_EXTENSION_KEY { "extension.network.kubernetes.io/cni" };
const std::string Constants::CNI_MUTL_NET_EXTENSION_ARGS_KEY { "CNI_MUTLINET_EXTENSION" };
const std::string Constants::CNI_ARGS_EXTENSION_PREFIX_KEY { "extension.network.kubernetes.io/cniargs/" };

const char *InternalLabelKeys[] = { CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY.c_str(),
                                    CRIHelpers::Constants::CONTAINER_LOGPATH_LABEL_KEY.c_str(),
                                    CRIHelpers::Constants::SANDBOX_ID_LABEL_KEY.c_str(), nullptr
                                  };

auto GetDefaultSandboxImage(Errors &err) -> std::string
{
    const std::string defaultPodSandboxImageName { "pause" };
    const std::string defaultPodSandboxImageVersion { "3.0" };
    std::string machine;
    struct utsname uts {
    };

    if (uname(&uts) < 0) {
        err.SetError("Failed to read host arch.");
        return "";
    }

    if (strcasecmp("i386", uts.machine) == 0) {
        machine = "386";
    } else if ((strcasecmp("x86_64", uts.machine) == 0) || (strcasecmp("x86-64", uts.machine) == 0)) {
        machine = "amd64";
    } else if (strcasecmp("aarch64", uts.machine) == 0) {
        machine = "aarch64";
    } else if ((strcasecmp("armhf", uts.machine) == 0) || (strcasecmp("armel", uts.machine) == 0) ||
               (strcasecmp("arm", uts.machine) == 0)) {
        machine = "aarch";
    } else {
        machine = uts.machine;
    }
    return defaultPodSandboxImageName + "-" + machine + ":" + defaultPodSandboxImageVersion;
}

auto MakeLabels(const google::protobuf::Map<std::string, std::string> &mapLabels, Errors &error)
-> json_map_string_string *
{
    json_map_string_string *labels = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (labels == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }

    if (!mapLabels.empty()) {
        if (mapLabels.size() > LIST_SIZE_MAX) {
            error.Errorf("Labels list is too long, the limit is %d", LIST_SIZE_MAX);
            goto cleanup;
        }
        for (auto &iter : mapLabels) {
            if (append_json_map_string_string(labels, iter.first.c_str(), iter.second.c_str()) != 0) {
                ERROR("Failed to append string");
                goto cleanup;
            }
        }
    }
    return labels;
cleanup:
    free_json_map_string_string(labels);
    return nullptr;
}

auto MakeAnnotations(const google::protobuf::Map<std::string, std::string> &mapAnnotations, Errors &error)
-> json_map_string_string *
{
    json_map_string_string *annotations =
        (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (annotations == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }

    if (!mapAnnotations.empty()) {
        if (mapAnnotations.size() > LIST_SIZE_MAX) {
            error.Errorf("Annotations list is too long, the limit is %d", LIST_SIZE_MAX);
            goto cleanup;
        }
        for (auto &iter : mapAnnotations) {
            if (append_json_map_string_string(annotations, iter.first.c_str(), iter.second.c_str()) != 0) {
                ERROR("Failed to append string");
                goto cleanup;
            }
        }
    }
    return annotations;
cleanup:
    free_json_map_string_string(annotations);
    return nullptr;
}

void ProtobufAnnoMapToStd(const google::protobuf::Map<std::string, std::string> &annotations,
                          std::map<std::string, std::string> &newAnnos)
{
    for (auto &iter : annotations) {
        newAnnos.insert(std::pair<std::string, std::string>(iter.first, iter.second));
    }
}

static auto IsSandboxLabel(json_map_string_string *input) -> bool
{
    bool is_sandbox_label { false };

    for (size_t j = 0; j < input->len; j++) {
        if (strcmp(input->keys[j], CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY.c_str()) == 0 &&
            strcmp(input->values[j], CRIHelpers::Constants::CONTAINER_TYPE_LABEL_SANDBOX.c_str()) == 0) {
            is_sandbox_label = true;
            break;
        }
    }

    return is_sandbox_label;
}

void ExtractLabels(json_map_string_string *input, google::protobuf::Map<std::string, std::string> &labels)
{
    if (input == nullptr) {
        return;
    }

    for (size_t i = 0; i < input->len; i++) {
        bool internal = false;
        const char **internal_key = InternalLabelKeys;
        // Check if the key is used internally by the shim.
        while (*internal_key != nullptr) {
            if (strcmp(input->keys[i], *internal_key) == 0) {
                internal = true;
                break;
            }
            internal_key++;
        }
        if (internal) {
            continue;
        }

        // Delete the container name label for the sandbox. It is added
        // in the shim, should not be exposed via CRI.
        if (strcmp(input->keys[i], Constants::KUBERNETES_CONTAINER_NAME_LABEL.c_str()) == 0) {
            bool is_sandbox_label = IsSandboxLabel(input);
            if (is_sandbox_label) {
                continue;
            }
        }

        labels[input->keys[i]] = input->values[i];
    }
}

void ExtractAnnotations(json_map_string_string *input, google::protobuf::Map<std::string, std::string> &annotations)
{
    if (input == nullptr) {
        return;
    }

    for (size_t i = 0; i < input->len; i++) {
        annotations[input->keys[i]] = input->values[i];
    }
}

auto FiltersAdd(defs_filters *filters, const std::string &key, const std::string &value) -> int
{
    if (filters == nullptr) {
        return -1;
    }

    size_t len = filters->len + 1;
    if (len > SIZE_MAX / sizeof(char *)) {
        ERROR("Invalid filter size");
        return -1;
    }
    char **keys = (char **)util_common_calloc_s(len * sizeof(char *));
    if (keys == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    json_map_string_bool **vals = (json_map_string_bool **)util_common_calloc_s(len * sizeof(json_map_string_bool *));
    if (vals == nullptr) {
        free(keys);
        ERROR("Out of memory");
        return -1;
    }

    if (filters->len != 0u) {
        (void)memcpy(keys, filters->keys, filters->len * sizeof(char *));

        (void)memcpy(vals, filters->values, filters->len * sizeof(json_map_string_bool *));
    }
    free(filters->keys);
    filters->keys = keys;
    free(filters->values);
    filters->values = vals;

    filters->values[filters->len] = (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
    if (filters->values[filters->len] == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    if (append_json_map_string_bool(filters->values[filters->len], value.c_str(), true) != 0) {
        ERROR("Append failed");
        return -1;
    }

    filters->keys[filters->len] = util_strdup_s(key.c_str());
    filters->len++;
    return 0;
}

auto FiltersAddLabel(defs_filters *filters, const std::string &key, const std::string &value) -> int
{
    if (filters == nullptr) {
        return -1;
    }
    return FiltersAdd(filters, "label", key + "=" + value);
}

auto ContainerStatusToRuntime(Container_Status status) -> runtime::v1alpha2::ContainerState
{
    switch (status) {
        case CONTAINER_STATUS_CREATED:
        case CONTAINER_STATUS_STARTING:
            return runtime::v1alpha2::CONTAINER_CREATED;
        case CONTAINER_STATUS_PAUSED:
        case CONTAINER_STATUS_RESTARTING:
        case CONTAINER_STATUS_RUNNING:
            return runtime::v1alpha2::CONTAINER_RUNNING;
        case CONTAINER_STATUS_STOPPED:
            return runtime::v1alpha2::CONTAINER_EXITED;
        default:
            return runtime::v1alpha2::CONTAINER_UNKNOWN;
    }
}

auto StringVectorToCharArray(std::vector<std::string> &path) -> char **
{
    size_t len = path.size();
    if (len == 0 || len > (SIZE_MAX / sizeof(char *)) - 1) {
        return nullptr;
    }
    char **result = (char **)util_common_calloc_s((len + 1) * sizeof(char *));
    if (result == nullptr) {
        return nullptr;
    }
    size_t i {};
    for (const auto &it : path) {
        result[i++] = util_strdup_s(it.c_str());
    }

    return result;
}

auto InspectImageByID(const std::string &imageID, Errors &err) -> imagetool_image *
{
    im_status_request *request { nullptr };
    im_status_response *response { nullptr };
    imagetool_image *image { nullptr };

    if (imageID.empty()) {
        err.SetError("Empty image ID");
        return nullptr;
    }

    request = (im_status_request *)util_common_calloc_s(sizeof(im_status_request));
    if (request == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        return nullptr;
    }
    request->image.image = util_strdup_s(imageID.c_str());

    if (im_image_status(request, &response) != 0) {
        if (response != nullptr && response->errmsg != nullptr) {
            err.SetError(response->errmsg);
        } else {
            err.SetError("Failed to call status image");
        }
        goto cleanup;
    }

    if (response->image_info != nullptr) {
        image = response->image_info->image;
        response->image_info->image = nullptr;
    }

cleanup:
    free_im_status_request(request);
    free_im_status_response(response);
    return image;
}

auto ToPullableImageID(const std::string &id, imagetool_image *image) -> std::string
{
    // Default to the image ID, but if RepoDigests is not empty, use
    // the first digest instead.
    std::string imageID = Constants::DOCKER_IMAGEID_PREFIX + id;
    if (image != nullptr && image->repo_digests != nullptr && image->repo_digests_len > 0) {
        imageID = Constants::DOCKER_PULLABLE_IMAGEID_PREFIX + std::string(image->repo_digests[0]);
    }
    return imageID;
}

// IsContainerNotFoundError checks whether the error is container not found error.
auto IsContainerNotFoundError(const std::string &err) -> bool
{
    return err.find("No such container:") != std::string::npos ||
           err.find("No such image or container") != std::string::npos;
}

// IsImageNotFoundError checks whether the error is Image not found error.
auto IsImageNotFoundError(const std::string &err) -> bool
{
    return err.find("No such image:") != std::string::npos;
}

auto sha256(const char *val) -> std::string
{
    if (val == nullptr) {
        return "";
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, val, strlen(val));
    unsigned char hash[SHA256_DIGEST_LENGTH] = { 0 };
    SHA256_Final(hash, &ctx);

    char outputBuffer[(SHA256_DIGEST_LENGTH * 2) + 1] { 0 };
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        int ret = snprintf(outputBuffer + (i * 2), 3, "%02x", (unsigned int)hash[i]);
        if (ret >= 3 || ret < 0) {
            return "";
        }
    }
    outputBuffer[SHA256_DIGEST_LENGTH * 2] = 0;

    return outputBuffer;
}

auto GetNetworkPlaneFromPodAnno(const google::protobuf::Map<std::string, std::string> &annotations, size_t *len,
                                Errors &error) -> cri_pod_network_element **
{
    auto iter = annotations.find(CRIHelpers::Constants::POD_NETWORK_ANNOTATION_KEY);

    cri_pod_network_element **result { nullptr };
    if (iter != annotations.end()) {
        parser_error err = nullptr;
        result = cri_pod_network_parse_data(iter->second.c_str(), nullptr, &err, len);
        if (result == nullptr) {
            error.Errorf("parse pod network json failed: %s", err);
        }
        free(err);
    }

    return result;
}

auto CheckpointToSandbox(const std::string &id, const cri::PodSandboxCheckpoint &checkpoint)
-> std::unique_ptr<runtime::v1alpha2::PodSandbox>
{
    std::unique_ptr<runtime::v1alpha2::PodSandbox> result(new (std::nothrow) runtime::v1alpha2::PodSandbox);
    if (result == nullptr) {
        return nullptr;
    }
    runtime::v1alpha2::PodSandboxMetadata *metadata = new (std::nothrow) runtime::v1alpha2::PodSandboxMetadata;
    if (metadata == nullptr) {
        return nullptr;
    }

    metadata->set_name(checkpoint.GetName());
    metadata->set_namespace_(checkpoint.GetNamespace());
    result->set_allocated_metadata(metadata);
    result->set_id(id);
    result->set_state(runtime::v1alpha2::SANDBOX_NOTREADY);

    return result;
}

void UpdateCreateConfig(container_config *createConfig, host_config *hc,
                        const runtime::v1alpha2::ContainerConfig &config, const std::string &podSandboxID,
                        Errors &error)
{
    if (createConfig == nullptr || hc == nullptr) {
        return;
    }
    DEBUG("Apply security context");
    CRISecurity::ApplyContainerSecurityContext(config.linux(), podSandboxID, createConfig, hc, error);
    if (error.NotEmpty()) {
        error.SetError("failed to apply container security context for container " + config.metadata().name() + ": " +
                       error.GetCMessage());
        return;
    }
    if (config.linux().has_resources()) {
        runtime::v1alpha2::LinuxContainerResources rOpts = config.linux().resources();
        hc->memory = rOpts.memory_limit_in_bytes();
        hc->memory_swap = CRIRuntimeService::Constants::DefaultMemorySwap;
        hc->cpu_shares = rOpts.cpu_shares();
        hc->cpu_quota = rOpts.cpu_quota();
        hc->cpu_period = rOpts.cpu_period();
        if (!rOpts.cpuset_cpus().empty()) {
            hc->cpuset_cpus = util_strdup_s(rOpts.cpuset_cpus().c_str());
        }
        if (!rOpts.cpuset_mems().empty()) {
            hc->cpuset_mems = util_strdup_s(rOpts.cpuset_mems().c_str());
        }
        hc->oom_score_adj = rOpts.oom_score_adj();
    }

    createConfig->open_stdin = config.stdin();
    createConfig->tty = config.tty();
}

void GenerateMountBindings(const google::protobuf::RepeatedPtrField<runtime::v1alpha2::Mount> &mounts,
                           host_config *hostconfig, Errors &err)
{
    if (mounts.empty() || hostconfig == nullptr) {
        return;
    }
    if ((size_t)mounts.size() > INT_MAX / sizeof(char *)) {
        err.SetError("Too many mounts");
        return;
    }

    hostconfig->binds = (char **)util_common_calloc_s(mounts.size() * sizeof(char *));
    if (hostconfig->binds == nullptr) {
        err.SetError("Out of memory");
        return;
    }
    for (int i = 0; i < mounts.size(); i++) {
        std::string bind = mounts[i].host_path() + ":" + mounts[i].container_path();
        std::vector<std::string> attrs;
        if (mounts[i].readonly()) {
            attrs.push_back("ro");
        }
        // Only request relabeling if the pod provides an SELinux context. If the pod
        // does not provide an SELinux context relabeling will label the volume with
        // the container's randomly allocated MCS label. This would restrict access
        // to the volume to the container which mounts it first.
        if (mounts[i].selinux_relabel()) {
            attrs.push_back("Z");
        }
        if (mounts[i].propagation() == runtime::v1alpha2::PROPAGATION_PRIVATE) {
            ; // noop, private is default
        } else if (mounts[i].propagation() == runtime::v1alpha2::PROPAGATION_BIDIRECTIONAL) {
            attrs.push_back("rshared");
        } else if (mounts[i].propagation() == runtime::v1alpha2::PROPAGATION_HOST_TO_CONTAINER) {
            attrs.push_back("rslave");
        } else {
            WARN("unknown propagation mode for hostPath %s", mounts[i].host_path().c_str());
            // Falls back to "private"
        }

        if (!attrs.empty()) {
            bind += ":" + CXXUtils::StringsJoin(attrs, ",");
        }
        hostconfig->binds[i] = util_strdup_s(bind.c_str());
        hostconfig->binds_len++;
    }
}

auto GenerateEnvList(const ::google::protobuf::RepeatedPtrField<::runtime::v1alpha2::KeyValue> &envs)
-> std::vector<std::string>
{
    std::vector<std::string> vect;
    std::for_each(envs.begin(), envs.end(), [&vect](const ::runtime::v1alpha2::KeyValue & elem) {
        vect.push_back(elem.key() + "=" + elem.value());
    });
    return vect;
}

auto ValidateCheckpointKey(const std::string &key, Errors &error) -> bool
{
    const std::string PATTERN { "^([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]$" };

    if (key.empty()) {
        goto err_out;
    }

    if (key.size() <= CRIHelpers::Constants::MAX_CHECKPOINT_KEY_LEN &&
        util_reg_match(PATTERN.c_str(), key.c_str()) == 0) {
        return true;
    }

err_out:
    error.Errorf("invalid key: %s", key.c_str());
    return false;
}

auto ToIsuladContainerStatus(const runtime::v1alpha2::ContainerStateValue &state) -> std::string
{
    if (state.state() == runtime::v1alpha2::CONTAINER_CREATED) {
        return "created";
    } else if (state.state() == runtime::v1alpha2::CONTAINER_RUNNING) {
        return "running";
    } else if (state.state() == runtime::v1alpha2::CONTAINER_EXITED) {
        return "exited";
    } else {
        return "unknown";
    }
}

struct iSuladOpt {
    std::string key;
    std::string value;
    std::string msg;
};

auto fmtiSuladOpts(const std::vector<iSuladOpt> &opts, const char &sep) -> std::vector<std::string>
{
    std::vector<std::string> fmtOpts(opts.size());
    for (size_t i {}; i < opts.size(); i++) {
        fmtOpts[i] = opts.at(i).key + sep + opts.at(i).value;
    }
    return fmtOpts;
}

auto GetSeccompiSuladOpts(const std::string &seccompProfile, Errors &error) -> std::vector<iSuladOpt>
{
    if (seccompProfile.empty() || seccompProfile == "unconfined") {
        return std::vector<iSuladOpt> { { "seccomp", "unconfined", "" } };
    }
    if (seccompProfile == "iSulad/default" || seccompProfile == "docker/default" ||
        seccompProfile == "runtime/default") {
        // return nil so docker will load the default seccomp profile
        return std::vector<iSuladOpt> {};
    }
    if (seccompProfile.compare(0, strlen("localhost/"), "localhost/") != 0) {
        error.Errorf("unknown seccomp profile option: %s", seccompProfile.c_str());
        return std::vector<iSuladOpt> {};
    }
    std::string fname = seccompProfile.substr(std::string("localhost/").length(), seccompProfile.length());
    char dstpath[PATH_MAX] { 0 };
    if (util_clean_path(fname.c_str(), dstpath, sizeof(dstpath)) == nullptr) {
        error.Errorf("failed to get clean path");
        return std::vector<iSuladOpt> {};
    }
    if (dstpath[0] != '/') {
        error.Errorf("seccomp profile path must be absolute, but got relative path %s", fname.c_str());
        return std::vector<iSuladOpt> {};
    }
    docker_seccomp *seccomp_spec = get_seccomp_security_opt_spec(dstpath);
    if (seccomp_spec == nullptr) {
        error.Errorf("failed to parse seccomp profile");
        return std::vector<iSuladOpt> {};
    }
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = nullptr;
    char *seccomp_json = docker_seccomp_generate_json(seccomp_spec, &ctx, &err);
    if (seccomp_json == nullptr) {
        free(err);
        free_docker_seccomp(seccomp_spec);
        error.Errorf("failed to generate seccomp json!");
        return std::vector<iSuladOpt> {};
    }

    // msg does not need
    std::vector<iSuladOpt> ret { { "seccomp", seccomp_json, "" } };
    free(err);
    free(seccomp_json);
    free_docker_seccomp(seccomp_spec);
    return ret;
}

auto GetSeccompSecurityOpts(const std::string &seccompProfile, const char &separator, Errors &error)
-> std::vector<std::string>
{
    std::vector<iSuladOpt> seccompOpts = GetSeccompiSuladOpts(seccompProfile, error);
    if (error.NotEmpty()) {
        return std::vector<std::string>();
    }

    return fmtiSuladOpts(seccompOpts, separator);
}

auto GetSecurityOpts(const std::string &seccompProfile, const char &separator, Errors &error)
-> std::vector<std::string>
{
    std::vector<std::string> seccompSecurityOpts = GetSeccompSecurityOpts(seccompProfile, separator, error);
    if (error.NotEmpty()) {
        error.Errorf("failed to generate seccomp security options for container");
    }
    return seccompSecurityOpts;
}

auto CreateCheckpoint(cri::PodSandboxCheckpoint &checkpoint, Errors &error) -> std::string
{
    cri_checkpoint *criCheckpoint { nullptr };
    struct parser_context ctx {
        OPT_GEN_SIMPLIFY, 0
    };
    parser_error err { nullptr };
    char *jsonStr { nullptr };
    std::string result;

    checkpoint.CheckpointToCStruct(&criCheckpoint, error);
    if (error.NotEmpty()) {
        goto out;
    }
    free(criCheckpoint->checksum);
    criCheckpoint->checksum = nullptr;
    jsonStr = cri_checkpoint_generate_json(criCheckpoint, &ctx, &err);
    if (jsonStr == nullptr) {
        error.Errorf("Generate cri checkpoint json failed: %s", err);
        goto out;
    }
    checkpoint.SetCheckSum(CRIHelpers::sha256(jsonStr));
    if (checkpoint.GetCheckSum().empty()) {
        error.SetError("checksum is empty");
        goto out;
    }
    criCheckpoint->checksum = util_strdup_s(checkpoint.GetCheckSum().c_str());

    free(jsonStr);
    jsonStr = cri_checkpoint_generate_json(criCheckpoint, &ctx, &err);
    if (jsonStr == nullptr) {
        error.Errorf("Generate cri checkpoint json failed: %s", err);
        goto out;
    }

    result = jsonStr;
out:
    free(err);
    free(jsonStr);
    free_cri_checkpoint(criCheckpoint);
    return result;
}

void GetCheckpoint(const std::string &jsonCheckPoint, cri::PodSandboxCheckpoint &checkpoint, Errors &error)
{
    cri_checkpoint *criCheckpoint { nullptr };
    struct parser_context ctx {
        OPT_GEN_SIMPLIFY, 0
    };
    parser_error err { nullptr };
    std::string tmpChecksum;
    char *jsonStr { nullptr };
    char *storeChecksum { nullptr };

    criCheckpoint = cri_checkpoint_parse_data(jsonCheckPoint.c_str(), &ctx, &err);
    if (criCheckpoint == nullptr) {
        ERROR("Failed to unmarshal checkpoint, removing checkpoint. ErrMsg: %s", err);
        error.SetError("Failed to unmarshal checkpoint");
        goto out;
    }

    tmpChecksum = criCheckpoint->checksum;
    storeChecksum = criCheckpoint->checksum;
    criCheckpoint->checksum = nullptr;
    jsonStr = cri_checkpoint_generate_json(criCheckpoint, &ctx, &err);
    criCheckpoint->checksum = storeChecksum;
    if (jsonStr == nullptr) {
        error.Errorf("Generate cri json str failed: %s", err);
        goto out;
    }

    if (tmpChecksum != CRIHelpers::sha256(jsonStr)) {
        ERROR("Checksum of checkpoint is not valid");
        error.SetError("checkpoint is corrupted");
        goto out;
    }

    checkpoint.CStructToCheckpoint(criCheckpoint, error);
out:
    free(jsonStr);
    free(err);
    free_cri_checkpoint(criCheckpoint);
}

} // namespace CRIHelpers
