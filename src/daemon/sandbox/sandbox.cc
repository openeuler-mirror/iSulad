/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2023-06-19
 * Description: provide sandbox class definition
 *********************************************************************************/
#include "sandbox.h"

#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <mutex>
#include <memory>
#include <sstream>
#include <sys/mount.h>

#include <isula_libutils/log.h>
#include <isula_libutils/sandbox_metadata.h>
#include <isula_libutils/sandbox_state.h>
#include <google/protobuf/util/json_util.h>
#include <isula_libutils/auto_cleanup.h>

#include "utils_file.h"
#include "constants.h"
#include "isulad_config.h"
#include "utils.h"
#include "namespace.h"
#include "transform.h"
#include "cxxutils.h"
#include "controller_manager.h"
#include "utils_timestamp.h"
#include "mailbox.h"

namespace sandbox {

const std::string SHM_MOUNT_POINT = "/dev/shm";
const uint32_t VSOCK_START_PORT = 2000;
const uint32_t VSOCK_END_PORT = 65535;

static int WriteDefaultSandboxHosts(const std::string &path, const std::string &hostname)
{
    std::string defaultConfig = "127.0.0.1       localhost\n"
                                "::1     localhost ip6-localhost ip6-loopback\n"
                                "fe00::0 ip6-localnet\n"
                                "ff00::0 ip6-mcastprefix\n"
                                "ff02::1 ip6-allnodes\n"
                                "ff02::2 ip6-allrouters\n";
    std::string loopIp = "127.0.0.1    ";
    std::string content;

    if (hostname.length() > (((SIZE_MAX - defaultConfig.length()) - loopIp.length()) - 2)) {
        ERROR("Hosts content greater than SIZE_MAX");
        return -1;
    }

    content = defaultConfig + loopIp + hostname + std::string("\n");
    if (util_write_file(path.c_str(), content.c_str(), content.length(), NETWORK_MOUNT_FILE_MODE) != 0) {
        ERROR("Failed to write default hosts");
        return -1;
    }

    return 0;
}

static int WriteDefaultSandboxResolve(const std::string &path)
{
    std::string defaultIpv4Dns = "\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n";

    return util_write_file(path.c_str(), defaultIpv4Dns.c_str(), defaultIpv4Dns.length(), NETWORK_MOUNT_FILE_MODE);
}

Sandbox::Sandbox(const std::string id, const std::string &rootdir, const std::string &statedir, const std::string name,
                 const RuntimeInfo info, std::string netMode, std::string netNsPath, const runtime::v1::PodSandboxConfig sandboxConfig,
                 const std::string image)
{
    m_id = id;
    m_name = name;
    m_runtimeInfo.runtime = info.runtime;
    m_runtimeInfo.sandboxer = info.sandboxer;
    m_runtimeInfo.runtimeHandler = info.runtimeHandler;
    m_rootdir = rootdir + "/" + m_id;
    m_statedir = statedir + "/" + m_id;
    // the sandbox instance is not initialized and will not be used,
    // and the state does not need to be locked
    m_state.status = SANDBOX_STATUS_UNKNOWN;
    m_netNsPath = netNsPath;
    m_networkReady = false;
    m_netMode = netMode;
    m_sandboxConfig = std::make_shared<runtime::v1::PodSandboxConfig>(sandboxConfig);
    m_statsInfo = {0, 0};
    // CRI won't allow createdAt of zero, we initially set it to 1 and update it in start
    const uint64_t defaultCreatedAt { 1 };
    m_state.createdAt = defaultCreatedAt;
    m_image = image;
}

auto Sandbox::IsReady() -> bool
{
    ReadGuard<RWMutex> lock(m_stateMutex);
    return m_state.status == SANDBOX_STATUS_RUNNING;
}

auto Sandbox::GetId() const -> const std::string &
{
    return m_id;
}

auto Sandbox::GetName() const -> const std::string &
{
    return m_name;
}

auto Sandbox::GetRuntime() const -> const std::string &
{
    return m_runtimeInfo.runtime;
}

auto Sandbox::GetSandboxer() const -> const std::string &
{
    return m_runtimeInfo.sandboxer;
}

auto Sandbox::GetRuntimeHandle() const -> const std::string &
{
    return m_runtimeInfo.runtimeHandler;
}

auto Sandbox::GetSandboxConfig() const -> const runtime::v1::PodSandboxConfig &
{
    return *m_sandboxConfig;
}

auto Sandbox::GetMutableSandboxConfig() -> std::shared_ptr<runtime::v1::PodSandboxConfig>
{
    return m_sandboxConfig;
}

auto Sandbox::GetRootDir() const -> const std::string &
{
    return m_rootdir;
}

auto Sandbox::GetStateDir() const -> const std::string &
{
    return m_statedir;
}

auto Sandbox::GetResolvPath() const -> std::string
{
    return m_rootdir + std::string("/resolv.conf");
}

auto Sandbox::GetShmPath() const -> std::string
{
    if (m_sandboxConfig->linux().has_security_context() &&
        m_sandboxConfig->linux().security_context().namespace_options().ipc() == runtime::v1::NamespaceMode::NODE) {
        return SHM_MOUNT_POINT;
    } else {
        return m_rootdir + std::string("/mounts/shm");
    }
}

auto Sandbox::GetStatsInfo() -> StatsInfo
{
    ReadGuard<RWMutex> lock(m_stateMutex);
    StatsInfo info;
    info.cpuUseNanos = m_statsInfo.cpuUseNanos;
    info.timestamp = m_statsInfo.timestamp;
    return info;
}

auto Sandbox::GetNetworkReady() const -> bool
{
    return m_networkReady;
}

auto Sandbox::GetNetMode() const -> const std::string &
{
    return m_netMode;
}

auto Sandbox::GetNetNsPath() const -> const std::string &
{
    return m_netNsPath;
}

auto Sandbox::GetNetworkSettings() -> const std::string &
{
    ReadGuard<RWMutex> lock(m_stateMutex);
    return m_networkSettings;
}

auto Sandbox::GetCreatedAt() -> uint64_t
{
    ReadGuard<RWMutex> lock(m_stateMutex);
    return m_state.createdAt;
}

auto Sandbox::GetPid() -> uint32_t
{
    ReadGuard<RWMutex> lock(m_stateMutex);
    return m_state.pid;
}

auto Sandbox::GetImage() -> const std::string &
{
    return m_image;
}

void Sandbox::DoUpdateExitedStatus(const ControllerExitInfo &exitInfo)
{
    WriteGuard<RWMutex> lock(m_stateMutex);
    m_state.exitStatus = exitInfo.exitStatus;
    m_state.exitedAt = exitInfo.exitedAt;
    m_state.status = SANDBOX_STATUS_STOPPED;
}

auto Sandbox::CreateHostname(bool shareHost, Errors &error) -> bool
{
    int ret = 0;
    std::string hostname;
    std::string hostnameContent;
    char tmp_name[MAX_HOST_NAME_LEN] = { 0x00 };
    if (m_sandboxConfig->hostname().length() == 0) {
        if (shareHost) {
            ret = gethostname(tmp_name, sizeof(tmp_name));
            if (ret != 0) {
                error.Errorf("Create hostname error");
                ERROR("Create hostname error");
                return false;
            }
            hostname = std::string(tmp_name);
        } else {
            hostname = m_id;
        }
        m_sandboxConfig->set_hostname(hostname);
    }

    hostnameContent = m_sandboxConfig->hostname() + std::string("\n");
    if (util_write_file(GetHostnamePath().c_str(), hostnameContent.c_str(), hostnameContent.length(),
                        NETWORK_MOUNT_FILE_MODE) != 0) {
        error.Errorf("Failed to create default hostname");
        ERROR("Failed to create default hostname");
        return false;
    }

    return true;
}

auto Sandbox::CreateHosts(bool shareHost, Errors &error) -> bool
{
    int ret = 0;

    if (shareHost && util_file_exists(ETC_HOSTS)) {
        ret = util_copy_file(ETC_HOSTS, GetHostsPath().c_str(), NETWORK_MOUNT_FILE_MODE);
    } else {
        ret = WriteDefaultSandboxHosts(GetHostsPath(), m_sandboxConfig->hostname());
    }

    if (ret != 0) {
        error.Errorf("Failed to create default hosts");
        ERROR("Failed to create default hosts");
        return false;
    }

    return true;
}

// Might be overwritten by network setup
auto Sandbox::CreateResolvConf(Errors &error) -> bool
{
    int ret = 0;

    if (util_file_exists(RESOLV_CONF_PATH)) {
        ret = util_copy_file(RESOLV_CONF_PATH, GetResolvPath().c_str(), NETWORK_MOUNT_FILE_MODE);
    } else {
        ret = WriteDefaultSandboxResolve(GetResolvPath());
    }

    if (ret != 0) {
        error.Errorf("Failed to create default resolv.conf");
        ERROR("Failed to create default resolv.conf");
        return false;
    }

    return true;
}

auto Sandbox::CreateShmDev(Errors &error) -> bool
{
    if (m_sandboxConfig->linux().has_security_context() &&
        m_sandboxConfig->linux().security_context().namespace_options().ipc() == runtime::v1::NamespaceMode::NODE) {
        if (!util_file_exists(SHM_MOUNT_POINT.c_str())) {
            ERROR("/dev/shm is not mounted, but must be for --ipc=host");
            return false;
        }
    } else {
        if (util_create_shm_path(GetShmPath().c_str(), DEFAULT_SHM_SIZE) != 0) {
            error.Errorf("Failed to create default shm");
            ERROR("Failed to create default shm");
            return false;
        }
#ifdef ENABLE_USERNS_REMAP
        if (util_chown_for_shm(spath, host_spec->user_remap) != 0) {
            error.Errorf("Failed to change shm owner");
            ERROR("Failed to change shm owner");
            return false;
        }
#endif
    }

    return true;
}

auto Sandbox::SetupSandboxFiles(Errors &error) -> bool
{
    bool shareHost = namespace_is_host(m_netMode.c_str());

    if (!CreateHostname(shareHost, error)) {
        return false;
    }
    if (!CreateHosts(shareHost, error)) {
        return false;
    }
    if (!CreateResolvConf(error)) {
        return false;
    }
    if (!CreateShmDev(error)) {
        return false;
    }

    return true;
}

auto Sandbox::CleanupSandboxFiles(Errors &error) -> bool
{
    if (m_sandboxConfig->linux().has_security_context() &&
        m_sandboxConfig->linux().security_context().namespace_options().ipc() != runtime::v1::NamespaceMode::NODE) {
        if (!util_deal_with_mount_info(util_umount_residual_shm, GetShmPath().c_str())) {
            error.Errorf("Failed to umount residual shm, %s", GetShmPath().c_str());
            ERROR("Failed to umount residual shm, %s", GetShmPath().c_str());
            return false;
        }
    }
    return true;
}

void Sandbox::DoUpdateStatus(std::unique_ptr<ControllerSandboxStatus> status, Errors &error)
{
    if (status == nullptr) {
        ERROR("Status is nullptr, %s", m_id.c_str());
        error.Errorf("Status is nullptr, %s", m_id.c_str());
        return;
    }
    m_taskAddress = status->taskAddress;
    WriteGuard<RWMutex> lock(m_stateMutex);
    // now, info is unused
    m_state.pid = status->pid;
    m_state.createdAt = status->createdAt;
    m_state.exitedAt = status->exitedAt;
    if (status->state == std::string(SANDBOX_READY_STATE_STR)) {
        m_state.status = SANDBOX_STATUS_RUNNING;
    } else {
        m_state.status = SANDBOX_STATUS_STOPPED;
    }
}

void Sandbox::SetNetMode(const std::string &mode)
{
    m_netMode = mode;
}

void Sandbox::SetController(std::shared_ptr<Controller> controller)
{
    m_controller = controller;
}

void Sandbox::AddAnnotations(const std::string &key, const std::string &value)
{
    m_sandboxConfig->mutable_annotations()->insert({key, value});
}

void Sandbox::RemoveAnnotations(const std::string &key)
{
    m_sandboxConfig->mutable_annotations()->erase(key);
}

void Sandbox::AddLabels(const std::string &key, const std::string &value)
{
    m_sandboxConfig->mutable_labels()->insert({key, value});
}

void Sandbox::RemoveLabels(const std::string &key)
{
    m_sandboxConfig->mutable_labels()->erase(key);
}

void Sandbox::UpdateNetworkSettings(const std::string &settingsJson, Errors &error)
{
    if (settingsJson.length() == 0) {
        error.Errorf("Empty settingsJson for %s", m_id.c_str());
        return;
    }

    if (!m_controller->UpdateNetworkSettings(m_id, settingsJson, error)) {
        error.Errorf("Failed to update networkSettings for %s", m_id.c_str());
        return;
    }

    SetNetworkSettings(settingsJson, error);
    if (error.NotEmpty()) {
        ERROR("Failed to set networkSettings for %s", m_id.c_str());
    }
}

auto Sandbox::UpdateStatsInfo(const StatsInfo &info) -> StatsInfo
{
    WriteGuard<RWMutex> lock(m_stateMutex);
    StatsInfo old;
    old.cpuUseNanos = m_statsInfo.cpuUseNanos;
    old.timestamp = m_statsInfo.timestamp;

    m_statsInfo.cpuUseNanos = info.cpuUseNanos;
    m_statsInfo.timestamp = info.timestamp;
    return old;
}

void Sandbox::SetNetworkReady(bool ready)
{
    m_networkReady = ready;
}

auto Sandbox::Save(Errors &error) -> bool
{
    if (!SaveState(error)) {
        ERROR("Failed to save state for %s", m_id.c_str());
        return false;
    }

    if (!SaveMetadata(error)) {
        ERROR("Failed to save metadata for %s", m_id.c_str());
        return false;
    }

    if (!SaveNetworkSetting(error)) {
        ERROR("Failed to save networkSettings for %s", m_id.c_str());
        return false;
    }

    return true;
}

bool Sandbox::DoStatusUpdateAndWaitInLoad(const std::string &sandboxID, Errors &error)
{
    if (!UpdateStatus(error)) {
        ERROR("Failed to update status of Sandbox, id='%s'", sandboxID.c_str());
        return false;
    }

    // Regardless of whether the sandbox is ready,
    // Wait() is required to call to monitor whether the kuasar sandbox is ready or exits.
    // TODO: distinguish the meaning of Wait() return value in different states of sandbox
    if (!m_controller->Wait(shared_from_this(), sandboxID, error)) {
        ERROR("Failed to restore wait callback");
        return false;
    }

    return true;
}

auto Sandbox::Load(Errors &error) -> bool
{
    if (!LoadState(error)) {
        return false;
    }

    if (!LoadMetadata(error)) {
        return false;
    }

    m_controller = ControllerManager::GetInstance()->GetController(m_runtimeInfo.sandboxer);
    if (m_controller == nullptr) {
        error.Errorf("Failed to find controller %s", m_runtimeInfo.sandboxer.c_str());
        ERROR("Failed to find controller %s", m_runtimeInfo.sandboxer.c_str());
        return false;
    }

    LoadNetworkSetting();

    // When the sandbox status acquisition fails or wait fails, the sandbox status is set to not ready,
    // and the user decides whether to delete the sandbox.
    if (!DoStatusUpdateAndWaitInLoad(m_id, error)) {
        WriteGuard<RWMutex> lock(m_stateMutex);
        m_state.status = SANDBOX_STATUS_STOPPED;
    }

    return true;
}

void Sandbox::OnSandboxReady()
{
    WriteGuard<RWMutex> lock(m_stateMutex);
    if (m_state.status == SANDBOX_STATUS_STOPPED || m_state.status == SANDBOX_STATUS_REMOVING) {
        return;
    }
    INFO("sandbox %s is ready", m_id.c_str());
    m_state.status = SANDBOX_STATUS_RUNNING;
}

void Sandbox::OnSandboxPending()
{
    WriteGuard<RWMutex> lock(m_stateMutex);
    if (m_state.status == SANDBOX_STATUS_STOPPED || m_state.status == SANDBOX_STATUS_REMOVING) {
        return;
    }
    INFO("sandbox %s is pending", m_id.c_str());
    m_state.status = SANDBOX_STATUS_PENDING;
}

void Sandbox::OnSandboxExit(const ControllerExitInfo &exitInfo)
{
    Errors error;

    // When stop is called multiple times, only the first exit is valid,
    // and subsequent exits do not need to update the status.
    // Likewise, the exits during deletion does not require updating state.
    if (IsStopped() || IsRemovalInProcess()) {
        return;
    }

    DoUpdateExitedStatus(exitInfo);

    if (!SaveState(error)) {
        ERROR("Failed to save sandbox state, %s", m_id.c_str());
    }

    if (error.Empty()) {
        cri_container_message_t msg = { 0 };
        msg.container_id = GetId().c_str();
        msg.sandbox_id = GetId().c_str();
        msg.type = CRI_CONTAINER_MESSAGE_TYPE_STOPPED;
        mailbox_publish(MAILBOX_TOPIC_CRI_CONTAINER, &msg);
    }
}

auto Sandbox::UpdateStatus(Errors &error) -> bool
{
    bool verbose = false;
    std::unique_ptr<ControllerSandboxStatus> status = m_controller->Status(m_id, verbose, error);
    if (status == nullptr) {
        ERROR("Failed to get status of Sandbox, id='%s'", m_id.c_str());
        return false;
    }

    DoUpdateStatus(std::move(status), error);
    if (error.NotEmpty()) {
        return false;
    }

    if (!SaveState(error)) {
        ERROR("Failed to save sandbox state, %s", m_id.c_str());
        return false;
    }
    return true;
}

void Sandbox::CleanupSandboxDirs()
{
    if (!util_deal_with_mount_info(util_umount_residual_shm, GetRootDir().c_str())) {
        ERROR("Failed to clean sandbox's mounts: %s", m_id.c_str());
    }

    if (util_recursive_rmdir(m_rootdir.c_str(), 0) != 0) {
        ERROR("Failed to delete sandbox's root directory %s", m_rootdir.c_str());
    }

    if (util_recursive_rmdir(m_statedir.c_str(), 0) != 0) {
        ERROR("Failed to delete sandbox's state directory %s", m_rootdir.c_str());
    }
}

void Sandbox::PrepareSandboxDirs(Errors &error)
{
    int nret = -1;
    mode_t mask = umask(S_IWOTH);
#ifdef ENABLE_USERNS_REMAP
    __isula_auto_free char *userns_remap = conf_get_isulad_userns_remap();
#endif

    nret = util_mkdir_p(m_rootdir.c_str(), CONFIG_DIRECTORY_MODE);
    if (nret != 0 && errno != EEXIST) {
        error.Errorf("Failed to create sandbox path %s", m_rootdir.c_str());
        SYSERROR("Failed to create sandbox path %s", m_rootdir.c_str());
        return;
    }
#ifdef ENABLE_USERNS_REMAP
    if (set_file_owner_for_userns_remap(m_rootdir.c_str(), userns_remap) != 0) {
        error.Errorf("Unable to change directory %s owner for user remap.", m_rootdir.c_str());
        ERROR("Unable to change directory %s owner for user remap.", m_rootdir.c_str());
        goto out;
    }
#endif

    if (!SetupSandboxFiles(error)) {
        ERROR("Failed to set up sandbox files, %s", m_id.c_str());
        goto out;
    }

    nret = util_mkdir_p(m_statedir.c_str(), TEMP_DIRECTORY_MODE);
    if (nret < 0) {
        error.Errorf("Unable to create sandbox state directory %s.", m_statedir.c_str());
        ERROR("Unable to create sandbox state directory %s.", m_statedir.c_str());
        goto out;
    }

    umask(mask);
    return;

out:
    umask(mask);
    CleanupSandboxDirs();
    return;
}

auto Sandbox::Create(Errors &error) -> bool
{
    struct ControllerCreateParams params;

    // currently, params.mounts is unused.
    params.config = m_sandboxConfig;
    params.netNSPath = m_netNsPath;
    params.sandboxName = m_name;
    params.image = m_image;
    params.netMode = m_netMode;
    params.runtime = GetRuntime();
    params.sandboxer = GetSandboxer();
    params.hostname = m_sandboxConfig->hostname();
    params.hostnamePath = GetHostnamePath();
    params.hostsPath = GetHostsPath();
    params.resolvConfPath = GetResolvPath();
    params.shmPath = GetShmPath();

    if (!m_controller->Create(m_id, params, error)) {
        ERROR("Failed to create sandbox by controller, %s", m_id.c_str());
        return false;
    }

    return true;
}

auto Sandbox::IsRemovalInProcess() -> bool
{
    ReadGuard<RWMutex> lock(m_stateMutex);
    return m_state.status == SANDBOX_STATUS_REMOVING;
}

auto Sandbox::IsStopped() -> bool
{
    ReadGuard<RWMutex> lock(m_stateMutex);
    return m_state.status == SANDBOX_STATUS_STOPPED;
}

// There is no competition between start, but there is competition between stop and remove
auto Sandbox::Start(Errors &error) -> bool
{
    if (IsRemovalInProcess()) {
        error.Errorf("Sandbox is marked for removal and cannot be started, id='%s'", m_id.c_str());
        ERROR("Sandbox is marked for removal and cannot be started, id='%s'", m_id.c_str());
        return false;
    }
    WriteGuard<RWMutex> lock(m_mutex);

    std::unique_ptr<ControllerSandboxInfo> info = m_controller->Start(m_id, error);
    if (!error.Empty()) {
        ERROR("Failed to start Sandbox, id='%s' : %s", m_id.c_str(), error.GetMessage().c_str());
        return false;
    }

    // selinux_label has the format of user:role:type[:level], level might be omitted? has the format of s0:c1,c2
    std::vector<std::string> seLabels = CXXUtils::SplitN(info->labels[std::string("selinux_label")], ':', 4);
    if (seLabels.size() >= 3) {
        m_sandboxConfig->mutable_linux()->mutable_security_context()->mutable_selinux_options()->set_user(seLabels[0]);
        m_sandboxConfig->mutable_linux()->mutable_security_context()->mutable_selinux_options()->set_role(seLabels[1]);
        m_sandboxConfig->mutable_linux()->mutable_security_context()->mutable_selinux_options()->set_type(seLabels[2]);
        if (seLabels.size() == 4) {
            m_sandboxConfig->mutable_linux()->mutable_security_context()->mutable_selinux_options()->set_level(seLabels[3]);
        }
    }

    m_state.pid = info->pid;
    m_state.createdAt = info->createdAt;
    m_taskAddress = info->taskAddress;
    m_state.status = SANDBOX_STATUS_RUNNING;

    if (!SaveState(error)) {
        ERROR("Failed to save sandbox state, %s", m_id.c_str());
        return false;
    }

    if (!IsReady()) {
        error.Errorf("Sandbox is still not ready after start, id='%s'", m_id.c_str());
        ERROR("Sandbox is still not ready after start, id='%s'", m_id.c_str());
        return false;
    }

    if (!m_controller->Wait(shared_from_this(), m_id, error)) {
        ERROR("Failed to wait sandbox, id=%s", m_id.c_str());
        return false;
    }

    return true;
}

auto Sandbox::DoStop(uint32_t timeoutSecs, Errors &error) -> bool
{
    if (!m_controller->Stop(m_id, timeoutSecs, error)) {
        ERROR("Failed to stop Sandbox, id='%s'", m_id.c_str());
        return false;
    }

    return true;
}

auto Sandbox::Stop(uint32_t timeoutSecs, Errors &error) -> bool
{
    if (IsRemovalInProcess()) {
        error.Errorf("Sandbox is marked for removal and cannot be stopped, id='%s'", m_id.c_str());
        ERROR("Sandbox is marked for removal and cannot be stopped, id='%s'", m_id.c_str());
        return false;
    }
    // If the sandbox is already in the notready state or the removal state, stop is meaningless.
    // So first judge the state to reduce meaningless lock competition.
    if (!IsReady()) {
        INFO("Sandbox has already been not ready, id='%s'", m_id.c_str());
        return true;
    }
    WriteGuard<RWMutex> lock(m_mutex);

    // Although the state of the sandbox has been judged before, the state of the sandbox may have
    // changed during the period of competing for the lock. Here, the state is determined again after the lock is obtained.
    if (!IsReady()) {
        INFO("Sandbox has already been not ready, id='%s'", m_id.c_str());
        return true;
    }

    if (!DoStop(timeoutSecs, error)) {
        return false;
    }

    return true;
}

auto Sandbox::Remove(Errors &error) -> bool
{
    Errors tmp_error;

    if (IsRemovalInProcess()) {
        error.Errorf("Sandbox is marked for removal and cannot be removed, id='%s'", m_id.c_str());
        ERROR("Sandbox is marked for removal and cannot be removed, id='%s'", m_id.c_str());
        return false;
    }

    WriteGuard<RWMutex> lock(m_mutex);

    // Only stop the sandbox when it is running
    if (IsReady() && !DoStop(DEFAULT_STOP_TIMEOUT, error)) {
        ERROR("Failed to stop Sandbox before removing, id='%s'", m_id.c_str());
        return false;
    }

    SandboxStatus before = m_state.status;
    m_state.status = SANDBOX_STATUS_REMOVING;

    if (!m_controller->Shutdown(m_id, error)) {
        ERROR("Failed to shutdown Sandbox, id='%s'", m_id.c_str());
        goto error_out;
    }

    return true;
error_out:
    m_state.status = before;
    return false;
}

void Sandbox::Status(runtime::v1::PodSandboxStatus &status)
{
    // networkStatus set in network module
    runtime::v1::NamespaceOption *options { nullptr };
    runtime::v1::LinuxPodSandboxStatus linuxs;
    status.set_id(m_id);
    status.set_state(IsReady() ? runtime::v1::SANDBOX_READY : runtime::v1::SANDBOX_NOTREADY);
    status.set_created_at(m_state.createdAt);

    options = status.mutable_linux()->mutable_namespaces()->mutable_options();
    options->set_network(
        m_sandboxConfig->mutable_linux()->mutable_security_context()->mutable_namespace_options()->network());
    options->set_pid(m_sandboxConfig->mutable_linux()->mutable_security_context()->mutable_namespace_options()->pid());
    options->set_ipc(m_sandboxConfig->mutable_linux()->mutable_security_context()->mutable_namespace_options()->ipc());

    status.mutable_metadata()->CopyFrom(m_sandboxConfig->metadata());
    *status.mutable_labels() = m_sandboxConfig->labels();
    *status.mutable_annotations() = m_sandboxConfig->annotations();

    status.set_runtime_handler(m_runtimeInfo.runtimeHandler);
}

auto Sandbox::GenerateSandboxStateJson(sandbox_state *state) -> std::string
{
    __isula_auto_free parser_error error;
    std::string ret;
    __isula_auto_free char *state_json = NULL;
    state_json = sandbox_state_generate_json(state, NULL, &(error));
    if (state_json == NULL || strlen(state_json) == 0) {
        return ret;
    }
    ret = std::string(state_json);
    return ret;
}

auto Sandbox::SaveState(Errors &error) -> bool
{
    sandbox_state state = { 0 };
    std::string stateJson;
    int nret = -1;
    const std::string path = GetStatePath();
    WriteGuard<RWMutex> lock(m_stateMutex);

    state.created_at = m_state.createdAt;
    state.exited_at = m_state.exitedAt;
    state.pid = m_state.pid;
    state.status = m_state.status;
    state.updated_at = m_state.updatedAt;

    stateJson = GenerateSandboxStateJson(&state);
    if (stateJson.length() == 0) {
        error.Errorf("Failed to get sandbox state json for sandbox: '%s'", m_id.c_str());
        return false;
    }

    nret = util_atomic_write_file(path.c_str(), stateJson.c_str(), stateJson.length(), CONFIG_FILE_MODE, false);
    if (nret != 0) {
        SYSERROR("Failed to write file %s");
        error.Errorf("Failed to write file %s", path.c_str());
        return false;
    }

    return true;
}

auto Sandbox::SaveNetworkSetting(Errors &error) -> bool
{
    int nret = -1;
    const std::string path = GetNetworkSettingsPath();
    WriteGuard<RWMutex> lock(m_stateMutex);

    nret = util_atomic_write_file(path.c_str(), m_networkSettings.c_str(), m_networkSettings.length(), CONFIG_FILE_MODE,
                                  false);
    if (nret != 0) {
        SYSERROR("Failed to write file %s", path.c_str());
        error.Errorf("Failed to write file %s", path.c_str());
        return false;
    }

    return true;
}

auto Sandbox::GenerateSandboxMetadataJson(sandbox_metadata *metadata) -> std::string
{
    __isula_auto_free parser_error error;
    std::string ret;
    __isula_auto_free char *metadata_json = NULL;
    metadata_json = sandbox_metadata_generate_json(metadata, NULL, &(error));
    if (metadata_json == NULL || strlen(metadata_json) == 0) {
        return ret;
    }
    ret = std::string(metadata_json);
    return ret;
}

auto Sandbox::SaveMetadata(Errors &error) -> bool
{
    sandbox_metadata_runtime_info info = { 0 };
    sandbox_metadata metadata = { 0 };
    int nret = -1;
    const std::string path = GetMetadataJsonPath();
    std::string metadataJson;

    metadata.runtime_info = &info;

    FillSandboxMetadata(&metadata, error);
    if (!error.Empty()) {
        return false;
    }

    metadataJson = GenerateSandboxMetadataJson(&metadata);
    if (metadataJson.length() == 0) {
        error.Errorf("Failed to get sandbox metadata json for sandbox: '%s'", m_id.c_str());
        return false;
    }

    nret = util_atomic_write_file(path.c_str(), metadataJson.c_str(), metadataJson.length(), CONFIG_FILE_MODE, false);
    if (nret != 0) {
        SYSERROR("Failed to write file %s", path.c_str());
        error.Errorf("Failed to write file %s", path.c_str());
        return false;
    }
    return true;
}

auto Sandbox::ParseSandboxStateFile() ->std::unique_ptr<CStructWrapper<sandbox_state>>
{
    __isula_auto_free parser_error err = NULL;
    const std::string path = GetStatePath();
    sandbox_state *state = NULL;

    state = sandbox_state_parse_file(path.c_str(), NULL, &err);
    if (state == NULL) {
        return nullptr;
    }
    return std::unique_ptr<CStructWrapper<sandbox_state>>(new CStructWrapper<sandbox_state>(state, free_sandbox_state));
}

auto Sandbox::LoadState(Errors &error) -> bool
{
    std::unique_ptr<CStructWrapper<sandbox_state>> state;

    state = ParseSandboxStateFile();
    if (state == nullptr || state->get() == nullptr) {
        error.Errorf("Failed to parse sandbox state file");
        return false;
    }

    // the sandbox instance has not been loaded and will not be used,
    // and the state does not need to be locked
    m_state.pid = state->get()->pid;
    m_state.exitedAt = state->get()->exited_at;
    m_state.createdAt = state->get()->created_at;
    m_state.updatedAt = state->get()->updated_at;
    m_state.status = (SandboxStatus)state->get()->status;

    return true;
}

auto Sandbox::ParseSandboxMetadataFile() -> std::unique_ptr<CStructWrapper<sandbox_metadata>>
{
    __isula_auto_free parser_error err = NULL;
    const std::string path = GetMetadataJsonPath();
    sandbox_metadata *metadata = NULL;

    metadata = sandbox_metadata_parse_file(path.c_str(), NULL, &err);
    if (metadata == NULL) {
        return nullptr;
    }
    return std::unique_ptr<CStructWrapper<sandbox_metadata>>(new CStructWrapper<sandbox_metadata>(metadata,
                                                                                                  free_sandbox_metadata));
}

auto Sandbox::isValidMetadata(std::unique_ptr<CStructWrapper<sandbox_metadata>> &metadata) -> bool
{
    bool invalid = metadata->get()->id == nullptr || metadata->get()->name == nullptr ||
                   metadata->get()->runtime_info->runtime == nullptr || metadata->get()->runtime_info->sandboxer == nullptr ||
                   metadata->get()->runtime_info->runtime_handler == nullptr || metadata->get()->net_mode == nullptr ||
                   metadata->get()->task_address == nullptr || metadata->get()->net_ns_path == nullptr;
    if (invalid) {
        return false;
    }
    return true;
}

auto Sandbox::LoadMetadata(Errors &error) -> bool
{
    bool ret = false;
    runtime::v1::PodSandboxConfig config;
    std::unique_ptr<CStructWrapper<sandbox_metadata>> metadata;

    metadata = ParseSandboxMetadataFile();
    if (metadata == nullptr || metadata->get() == nullptr) {
        error.Errorf("Failed to parse sandbox metadata file for sandbox: '%s'", m_id.c_str());
        return false;
    }

    if (!isValidMetadata(metadata)) {
        error.Errorf("Failed to load corrupt sandbox metadata file for sandbox: '%s'", m_id.c_str());
        return false;
    }

    m_name = std::string(metadata->get()->name);
    m_runtimeInfo.runtime = std::string(metadata->get()->runtime_info->runtime);
    m_runtimeInfo.sandboxer = std::string(metadata->get()->runtime_info->sandboxer);
    m_runtimeInfo.runtimeHandler = std::string(metadata->get()->runtime_info->runtime_handler);
    m_netMode = std::string(metadata->get()->net_mode);
    m_networkReady = metadata->get()->network_ready;
    m_taskAddress = std::string(metadata->get()->task_address);
    m_netNsPath = std::string(metadata->get()->net_ns_path);

    ret = google::protobuf::util::JsonStringToMessage(metadata->get()->sandbox_config_json, &config).ok();
    if (!ret) {
        error.Errorf("Failed to parse sandbox config json for sandbox: '%s'", m_id.c_str());
        return false;
    }
    m_sandboxConfig = std::make_shared<runtime::v1::PodSandboxConfig>(config);

    return true;
}

void Sandbox::LoadNetworkSetting()
{
    __isula_auto_free char *settings = NULL;
    const std::string path = GetNetworkSettingsPath();

    // for the sandbox whose net_mode is host. No need to load networkSetting.
    if (namespace_is_host(m_netMode.c_str())) {
        return;
    }

    settings = util_read_content_from_file(path.c_str());
    if (settings == NULL || strlen(settings) == 0 || strcmp(settings, "\n") == 0) {
        // If isulad has not cni set, the network json file will be empty
        // RunPodSandbox allows empty network setting json file
        WARN("%s: failed to read file %s", m_id.c_str(), path.c_str());
        return;
    }

    m_networkSettings = std::string(settings);
}

void Sandbox::SetSandboxConfig(const runtime::v1::PodSandboxConfig &config)
{
    m_sandboxConfig = std::make_shared<runtime::v1::PodSandboxConfig>(config);
}

void Sandbox::SetNetworkSettings(const std::string &settings, Errors &error)
{
    m_stateMutex.wrlock();
    m_networkSettings = settings;
    m_stateMutex.unlock();
    if (!SaveNetworkSetting(error)) {
        ERROR("Failed to save networkSettings for %s", m_id.c_str());
    }
}

auto Sandbox::FindAvailableVsockPort(uint32_t &port) -> bool
{
    std::unique_lock<std::mutex> lock(m_vsockPortsMutex);
    for (uint32_t i = VSOCK_START_PORT; i < VSOCK_END_PORT; i++) {
        if (m_vsockPorts.find(i) == m_vsockPorts.end()) {
            m_vsockPorts.insert(i);
            port = i;
            return true;
        }
    }
    return false;
}

void Sandbox::ReleaseVsockPort(uint32_t port)
{
    std::unique_lock<std::mutex> lock(m_vsockPortsMutex);
    m_vsockPorts.erase(port);
}

auto Sandbox::GetTaskAddress() const -> const std::string &
{
    return m_taskAddress;
}

auto Sandbox::GetHostnamePath() const -> std::string
{
    return m_rootdir + std::string("/hostname");
}

auto Sandbox::GetHostsPath() const -> std::string
{
    return m_rootdir + std::string("/hosts");
}

auto Sandbox::GetMetadataJsonPath() -> std::string
{
    return m_rootdir + std::string("/") + SANDBOX_METADATA_JSON;
}

auto Sandbox::GetStatePath() -> std::string
{
    return m_rootdir + std::string("/") + SANDBOX_STATE_JSON;
}

auto Sandbox::GetNetworkSettingsPath() -> std::string
{
    return m_rootdir + std::string("/") + NETWORK_SETTINGS_JSON;
}

void Sandbox::FillSandboxMetadata(sandbox_metadata* metadata, Errors &error)
{
    std::string jsonStr;
    metadata->id = util_strdup_s(m_id.c_str());
    metadata->name = util_strdup_s(m_name.c_str());
    metadata->runtime_info->runtime = util_strdup_s(m_runtimeInfo.runtime.c_str());
    metadata->runtime_info->sandboxer = util_strdup_s(m_runtimeInfo.sandboxer.c_str());
    metadata->runtime_info->runtime_handler = util_strdup_s(m_runtimeInfo.runtimeHandler.c_str());
    metadata->net_mode = util_strdup_s(m_netMode.c_str());
    metadata->network_ready = m_networkReady;
    metadata->task_address = util_strdup_s(m_taskAddress.c_str());
    metadata->net_ns_path = util_strdup_s(m_netNsPath.c_str());

    if (!google::protobuf::util::MessageToJsonString(*m_sandboxConfig.get(), &jsonStr).ok()) {
        error.Errorf("Failed to get sandbox config json for sandbox: '%s'", m_id.c_str());
        ERROR("Failed to get sandbox config json for sandbox: '%s'", m_id.c_str());
    }

    metadata->sandbox_config_json = util_strdup_s(jsonStr.c_str());
}
}