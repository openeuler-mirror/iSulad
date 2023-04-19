// TODO: Merge sandbox_network with execution_network

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "namespace.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "sandbox_network.h"

static int create_default_sandbox_hostname(const char *id, const char *rootpath, bool share_host,
                                           sandbox_config *sandboxconfig)
{
    int ret = 0;
    int nret = 0;
    char file_path[PATH_MAX] = { 0x0 };
    // 2 is '\0' + '\n'
    char hostname_content[MAX_HOST_NAME_LEN + 2] = { 0 };

    if (sandboxconfig->hostname == NULL) {
        char hostname[MAX_HOST_NAME_LEN] = { 0x00 };
        if (share_host) {
            ret = gethostname(hostname, sizeof(hostname));
        } else {
            // hostname max length is 12 + '\0'
            nret = snprintf(hostname, 13, "%s", id);
            ret = nret < 0 ? 1 : 0;
        }
        if (ret != 0) {
            ERROR("Create hostname error");
            goto out;
        }
        sandboxconfig->hostname = util_strdup_s(hostname);
    }

    nret = snprintf(file_path, PATH_MAX, "%s/%s/%s", rootpath, id, "hostname");
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    // 2 is '\0' + '\n'
    nret = snprintf(hostname_content, MAX_HOST_NAME_LEN + 2, "%s\n", sandboxconfig->hostname);
    if (nret < 0 || (size_t)nret >= sizeof(hostname_content)) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    if (util_write_file(file_path, hostname_content, strlen(hostname_content), NETWORK_MOUNT_FILE_MODE) != 0) {
        ERROR("Failed to create default hostname");
        ret = -1;
        goto out;
    }

    free(sandboxconfig->hostname_path);
    sandboxconfig->hostname_path = util_strdup_s(file_path);

out:
    return ret;
}

static int write_default_sandbox_hosts(const char *file_path, const char *hostname)
{
    int ret = 0;
    char *content = NULL;
    size_t content_len = 0;
    const char *default_config = "127.0.0.1       localhost\n"
                                 "::1     localhost ip6-localhost ip6-loopback\n"
                                 "fe00::0 ip6-localnet\n"
                                 "ff00::0 ip6-mcastprefix\n"
                                 "ff02::1 ip6-allnodes\n"
                                 "ff02::2 ip6-allrouters\n";
    const char *loop_ip = "127.0.0.1    ";

    if (strlen(hostname) > (((SIZE_MAX - strlen(default_config)) - strlen(loop_ip)) - 2)) {
        ret = -1;
        goto out_free;
    }

    content_len = strlen(default_config) + strlen(loop_ip) + strlen(hostname) + 1 + 1;
    content = util_common_calloc_s(content_len);
    if (content == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out_free;
    }

    ret = snprintf(content, content_len, "%s%s%s\n", default_config, loop_ip, hostname);
    if (ret < 0 || (size_t)ret >= content_len) {
        ERROR("Failed to generate default hosts");
        ret = -1;
        goto out_free;
    }

    ret = util_write_file(file_path, content, strlen(content), NETWORK_MOUNT_FILE_MODE);
    if (ret != 0) {
        ret = -1;
        goto out_free;
    }

out_free:
    free(content);
    return ret;
}

static int create_default_sandbox_hosts(const char *id, const char *rootpath, bool share_host,
                                        sandbox_config *sandboxconfig)
{
    int ret = 0;
    char file_path[PATH_MAX] = { 0x0 };

    ret = snprintf(file_path, PATH_MAX, "%s/%s/%s", rootpath, id, "hosts");
    if (ret < 0 || ret >= PATH_MAX) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    if (share_host && util_file_exists(ETC_HOSTS)) {
        ret = util_copy_file(ETC_HOSTS, file_path, NETWORK_MOUNT_FILE_MODE);
    } else {
        ret = write_default_sandbox_hosts(file_path, sandboxconfig->hostname);
    }

    if (ret != 0) {
        ERROR("Failed to create default hosts");
        goto out;
    }

    free(sandboxconfig->hosts_path);
    sandboxconfig->hosts_path = util_strdup_s(file_path);

out:
    return ret;
}

static int write_default_sandbox_resolve(const char *file_path)
{
    const char *default_ipv4_dns = "\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n";

    return util_write_file(file_path, default_ipv4_dns, strlen(default_ipv4_dns), NETWORK_MOUNT_FILE_MODE);
}

static int create_default_sandbox_resolv(const char *id, const char *rootpath, sandbox_config *sandboxconfig)
{
    int ret = 0;
    char file_path[PATH_MAX] = { 0x0 };

    ret = snprintf(file_path, PATH_MAX, "%s/%s/%s", rootpath, id, "resolv.conf");
    if (ret < 0 || ret >= PATH_MAX) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    if (util_file_exists(RESOLV_CONF_PATH)) {
        ret = util_copy_file(RESOLV_CONF_PATH, file_path, NETWORK_MOUNT_FILE_MODE);
    } else {
        ret = write_default_sandbox_resolve(file_path);
    }

    if (ret != 0) {
        ERROR("Failed to create default resolv.conf");
        goto out;
    }

    free(sandboxconfig->resolv_conf_path);
    sandboxconfig->resolv_conf_path = util_strdup_s(file_path);

out:
    return ret;
}

int init_sandbox_network_confs(const char *sandbox_id, const char *rootpath,
                               host_config *hostconfig, sandbox_config *sandboxconfig)
{
    int ret = 0;
    bool share_host;

    if (sandbox_id == NULL || rootpath == NULL || hostconfig == NULL || sandboxconfig == NULL) {
        ERROR("Invalid argument for sandbox network initialization");
        return -1;
    }
    share_host = namespace_is_host(hostconfig->network_mode);

    if (create_default_sandbox_hostname(sandbox_id, rootpath, share_host, sandboxconfig) != 0) {
        ERROR("Failed to create default hostname");
        ret = -1;
        goto out;
    }

    if (create_default_sandbox_hosts(sandbox_id, rootpath, share_host, sandboxconfig) != 0) {
        ERROR("Failed to create default hosts");
        ret = -1;
        goto out;
    }

    if (create_default_sandbox_resolv(sandbox_id, rootpath, sandboxconfig) != 0) {
        ERROR("Failed to create default resolv.conf");
        ret = -1;
        goto out;
    }

out:
    return ret;
}
