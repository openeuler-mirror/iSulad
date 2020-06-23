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
 * Description: provide container gc functions
 ******************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

#include "constants.h"
#include "containers_gc.h"
#include "isulad_config.h"
#include "isula_libutils/container_garbage_config.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "container_operator.h"
#include "containers_store.h"
#include "runtime.h"

static containers_gc_t g_gc_containers;

/* gc containers lock */
static void gc_containers_lock()
{
    if (pthread_mutex_lock(&(g_gc_containers.mutex)) != 0) {
        ERROR("Failed to lock garbage containers list");
    }
}

/* gc containers unlock */
static void gc_containers_unlock()
{
    if (pthread_mutex_unlock(&(g_gc_containers.mutex)) != 0) {
        ERROR("Failed to unlock garbage containers list");
    }
}

#define GCCONFIGJSON "garbage.json"
/* save gc config */
static int save_gc_config(const char *json_gc_config)
{
    int ret = 0;
    int nret;
    char filename[PATH_MAX] = { 0 };
    char *rootpath = NULL;
    int fd = -1;

    rootpath = conf_get_isulad_rootdir();
    if (rootpath == NULL) {
        ERROR("Root path is NULL");
        ret = -1;
        goto out;
    }

    nret = snprintf(filename, sizeof(filename), "%s/%s", rootpath, GCCONFIGJSON);
    if (nret < 0 || (size_t)nret >= sizeof(filename)) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    fd = util_open(filename, O_CREAT | O_TRUNC | O_CLOEXEC | O_WRONLY, CONFIG_FILE_MODE);
    if (fd == -1) {
        ERROR("Create file %s failed: %s", filename, strerror(errno));
        ret = -1;
        goto out;
    }

    if (write(fd, json_gc_config, strlen(json_gc_config)) == -1) {
        ERROR("write %s failed: %s", filename, strerror(errno));
        ret = -1;
    }
    close(fd);

out:
    free(rootpath);
    return ret;
}

/* gc save containers config */
static int gc_save_containers_config(const container_garbage_config *saves)
{
    int ret = 0;
    parser_error err = NULL;
    char *json_gc_config = NULL;

    if (saves == NULL) {
        return -1;
    }

    json_gc_config = container_garbage_config_generate_json(saves, NULL, &err);
    if (json_gc_config == NULL) {
        ERROR("Failed to generate container gc config json string:%s", err ? err : " ");
        ret = -1;
        goto out;
    }

    ret = save_gc_config(json_gc_config);
    if (ret != 0) {
        ERROR("Failed to save container gc config json to file");
        ret = -1;
        goto out;
    }

out:
    free(json_gc_config);
    free(err);
    return ret;
}

/* notes: this funciton must be called with gc_containers_lock */
static int gc_containers_to_disk()
{
    int ret = 0;
    size_t size = 0;
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    container_garbage_config_gc_containers_element **conts = NULL;
    container_garbage_config saves = { 0 };

    size = linked_list_len(&g_gc_containers.containers_list);

    if (size != 0) {
        size_t i = 0;
        if (size > SIZE_MAX / sizeof(container_garbage_config_gc_containers_element *)) {
            ERROR("Garbage collection list is too long!");
            return -1;
        }
        conts = util_common_calloc_s(sizeof(container_garbage_config_gc_containers_element *) * size);
        if (conts == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        linked_list_for_each_safe(it, &g_gc_containers.containers_list, next) {
            conts[i] = (container_garbage_config_gc_containers_element *)it->elem;
            i++;
        }
    }

    saves.gc_containers_len = size;
    saves.gc_containers = conts;

    ret = gc_save_containers_config(&saves);

    free(conts);

    return ret;
}

/* gc is gc progress */
bool gc_is_gc_progress(const char *id)
{
    bool ret = false;
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    container_garbage_config_gc_containers_element *cont = NULL;

    gc_containers_lock();

    linked_list_for_each_safe(it, &g_gc_containers.containers_list, next) {
        cont = (container_garbage_config_gc_containers_element *)it->elem;
        if (strcmp(id, cont->id) == 0) {
            ret = true;
            break;
        }
    }

    gc_containers_unlock();

    return ret;
}

/* gc add container */
int gc_add_container(const char *id, const char *runtime, const container_pid_t *pid_info)
{
    struct linked_list *newnode = NULL;
    container_garbage_config_gc_containers_element *gc_cont = NULL;

    if (pid_info == NULL) {
        CRIT("Invalid inputs for add garbage collector.");
        return -1;
    }

    newnode = util_common_calloc_s(sizeof(struct linked_list));
    if (newnode == NULL) {
        CRIT("Memory allocation error.");
        return -1;
    }

    gc_cont = util_common_calloc_s(sizeof(container_garbage_config_gc_containers_element));
    if (gc_cont == NULL) {
        CRIT("Memory allocation error.");
        free(newnode);
        return -1;
    }

    gc_cont->id = util_strdup_s(id);
    gc_cont->runtime = util_strdup_s(runtime);
    gc_cont->pid = pid_info->pid;
    gc_cont->start_time = pid_info->start_time;
    gc_cont->ppid = pid_info->ppid;
    gc_cont->p_start_time = pid_info->pstart_time;

    gc_containers_lock();

    linked_list_add_elem(newnode, gc_cont);
    linked_list_add_tail(&g_gc_containers.containers_list, newnode);
    (void)gc_containers_to_disk();

    gc_containers_unlock();

    return 0;
}

/* read gc config */
container_garbage_config *read_gc_config()
{
    int nret;
    char filename[PATH_MAX] = { 0x00 };
    parser_error err = NULL;
    container_garbage_config *gcconfig = NULL;
    char *rootpath = NULL;

    rootpath = conf_get_isulad_rootdir();
    if (rootpath == NULL) {
        ERROR("Root path is NULL");
        goto out;
    }

    nret = snprintf(filename, sizeof(filename), "%s/%s", rootpath, GCCONFIGJSON);
    if (nret < 0 || (size_t)nret >= sizeof(filename)) {
        ERROR("Failed to print string");
        goto out;
    }

    gcconfig = container_garbage_config_parse_file(filename, NULL, &err);
    if (gcconfig == NULL) {
        INFO("Failed to parse gc config file:%s", err);
        goto out;
    }
out:
    free(err);
    free(rootpath);
    return gcconfig;
}

/* gc restore */
int gc_restore()
{
    int ret = 0;
    size_t i = 0;
    container_garbage_config *gcconfig = NULL;
    struct linked_list *newnode = NULL;

    gcconfig = read_gc_config();
    if (gcconfig == NULL) {
        goto out;
    }

    gc_containers_lock();

    for (i = 0; i < gcconfig->gc_containers_len; i++) {
        newnode = util_common_calloc_s(sizeof(struct linked_list));
        if (newnode == NULL) {
            gc_containers_unlock();
            CRIT("Memory allocation error, failed to restore garbage collector.");
            ret = -1;
            goto out;
        }

        linked_list_add_elem(newnode, gcconfig->gc_containers[i]);
        linked_list_add_tail(&g_gc_containers.containers_list, newnode);
        gcconfig->gc_containers[i] = NULL;
    }
    gcconfig->gc_containers_len = 0;

    (void)gc_containers_to_disk();
    gc_containers_unlock();

out:
    free_container_garbage_config(gcconfig);
    return ret;
}

/* apply restart policy after gc */
static void apply_auto_remove_after_gc(const char *id)
{
    container_t *cont = NULL;

    cont = containers_store_get(id);
    if (cont == NULL) {
        INFO("Container '%s' already removed", id);
        goto out;
    }

    if (is_running(cont->state)) {
        INFO("container %s already running, skip apply auto remove after gc", id);
        goto out;
    }

    if (cont->hostconfig != NULL && cont->hostconfig->auto_remove_bak) {
        (void)set_container_to_removal(cont);
        (void)cleanup_container(cont, true);
    }

out:
    container_unref(cont);
    return;
}

/* apply restart policy after gc */
static void apply_restart_policy_after_gc(const char *id)
{
    container_t *cont = NULL;
    char *started_at = NULL;
    bool should_restart = false;
    uint64_t timeout;
    uint32_t exit_code;

    cont = containers_store_get(id);
    if (cont == NULL) {
        INFO("Container '%s' already removed", id);
        goto out;
    }

    container_lock(cont);

    if (is_running(cont->state)) {
        INFO("container %s already running, skip apply restart policy after gc", id);
        goto unlock_out;
    }

    started_at = state_get_started_at(cont->state);
    exit_code = state_get_exitcode(cont->state);

    should_restart = restart_manager_should_restart(id, exit_code, cont->common_config->has_been_manually_stopped,
                                                    time_seconds_since(started_at), &timeout);
    free(started_at);

    if (should_restart) {
        cont->common_config->restart_count++;
        state_set_restarting(cont->state, (int)exit_code);
        INFO("Try to restart container %s after %.2fs", id, (double)timeout / Time_Second);
        (void)container_restart_in_thread(id, timeout, (int)exit_code);
        if (container_to_disk(cont)) {
            ERROR("Failed to save container \"%s\" to disk", id);
            goto unlock_out;
        }
    }

unlock_out:
    container_unlock(cont);
out:
    container_unref(cont);
    return;
}

static void gc_monitor_process(const char *id, pid_t pid, unsigned long long start_time)
{
    INFO("Received garbage collector monitor of %s with pid %d", id, pid);

    if (util_process_alive(pid, start_time)) {
        int ret = kill(pid, SIGKILL);
        if (ret < 0 && errno != ESRCH) {
            ERROR("Can not kill monitor process (pid=%d) with SIGKILL", pid);
        }
    }
}

static void add_to_list_tail_to_retry_gc(struct linked_list *it)
{
    gc_containers_lock();
    linked_list_del(it);
    linked_list_add_tail(&g_gc_containers.containers_list, it);
    gc_containers_unlock();
}

static int do_runtime_resume_container(const container_t *cont)
{
    int ret = 0;
    rt_resume_params_t params = { 0 };
    const char *id = cont->common_config->id;

    params.rootpath = cont->root_path;

    if (runtime_resume(id, cont->runtime, &params)) {
        ERROR("Failed to resume container:%s", id);
        ret = -1;
        goto out;
    }

    state_reset_paused(cont->state);

    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static void try_to_resume_container(const char *id, const char *runtime)
{
    int ret = 0;
    container_t *cont = NULL;

    if (id == NULL || runtime == NULL) {
        ERROR("Invalid input arguments");
        goto out;
    }

    cont = containers_store_get(id);
    if (cont == NULL) {
        WARN("No such container:%s", id);
        goto out;
    }

    ret = do_runtime_resume_container(cont);
    if (ret != 0) {
        ERROR("try to runtime resume failed");
        goto out;
    }
out:
    container_unref(cont);
}

static void gc_container_process(struct linked_list *it)
{
    int ret = 0;
    int pid = 0;
    unsigned long long start_time = 0;
    char *runtime = NULL;
    char *id = NULL;
    container_garbage_config_gc_containers_element *gc_cont = NULL;

    gc_cont = (container_garbage_config_gc_containers_element *)it->elem;
    id = gc_cont->id;
    runtime = gc_cont->runtime;
    pid = gc_cont->pid;
    start_time = gc_cont->start_time;

    if (util_process_alive(pid, start_time) == false) {
        ret = clean_container_resource(id, runtime, pid);
        if (ret != 0) {
            WARN("Failed to clean resources of container %s", id);
            add_to_list_tail_to_retry_gc(it);
            return;
        }

        /* remove container from gc list */
        gc_containers_lock();

        linked_list_del(it);
        (void)gc_containers_to_disk();

        gc_containers_unlock();

        /* apply restart policy for the container after gc */
        apply_restart_policy_after_gc(id);

        apply_auto_remove_after_gc(id);

        free_container_garbage_config_gc_containers_element(gc_cont);
        free(it);
    } else {
        try_to_resume_container(id, runtime);
        ret = kill(pid, SIGKILL);
        if (ret < 0 && errno != ESRCH) {
            ERROR("Can not kill process (pid=%d) with SIGKILL for container %s", pid, id);
        }
        add_to_list_tail_to_retry_gc(it);
    }
}
static void do_gc_container(struct linked_list *it)
{
    container_garbage_config_gc_containers_element *gc_cont = NULL;

    gc_cont = (container_garbage_config_gc_containers_element *)it->elem;

    gc_monitor_process(gc_cont->id, gc_cont->ppid, gc_cont->p_start_time);

    gc_container_process(it);

    return;
}

static void *gchandler(void *arg)
{
    int ret = 0;
    struct linked_list *it = NULL;

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Set thread detach fail");
        goto error;
    }

    prctl(PR_SET_NAME, "Garbage_collector");

    for (;;) {
        gc_containers_lock();

        if (linked_list_empty(&g_gc_containers.containers_list)) {
            gc_containers_unlock();
            goto wait_continue;
        }
        it = linked_list_first_node(&g_gc_containers.containers_list);

        gc_containers_unlock();

        do_gc_container(it);

wait_continue:
        usleep_nointerupt(100 * 1000); /* wait 100 millisecond to check next gc container */
    }
error:
    return NULL;
}

/* new gchandler */
int new_gchandler()
{
    int ret = -1;

    linked_list_init(&(g_gc_containers.containers_list));

    ret = pthread_mutex_init(&(g_gc_containers.mutex), NULL);
    if (ret != 0) {
        CRIT("Mutex initialization failed");
        goto out;
    }

    INFO("Restoring garbage collector...");

    if (gc_restore()) {
        ERROR("Failed to restore garbage collector");
        pthread_mutex_destroy(&(g_gc_containers.mutex));
        goto out;
    }

    ret = 0;
out:
    return ret;
}

/* start gchandler */
int start_gchandler()
{
    int ret = -1;
    pthread_t a_thread;

    INFO("Starting garbage collector...");

    ret = pthread_create(&a_thread, NULL, gchandler, NULL);
    if (ret != 0) {
        CRIT("Thread creation failed");
        goto out;
    }

    ret = 0;
out:
    return ret;
}
