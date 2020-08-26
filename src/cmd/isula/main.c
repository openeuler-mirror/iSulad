/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide init process of isula
 ******************************************************************************/

#include <stdio.h>

#include "isula_commands.h"
#include "create.h"
#include "ps.h"
#include "rm.h"
#include "start.h"
#include "inspect.h"
#include "stop.h"
#include "exec.h"
#include "run.h"
#include "images.h"
#include "rmi.h"
#include "tag.h"
#include "import.h"
#include "wait.h"
#include "restart.h"
#include "pause.h"
#include "resume.h"
#include "logs.h"
#include "events.h"
#include "kill.h"
#include "load.h"
#include "update.h"
#include "attach.h"
#include "info.h"
#include "stats.h"
#include "export.h"
#include "cp.h"
#include "top.h"
#include "pull.h"
#include "login.h"
#include "logout.h"
#include "isula_connect.h"
#include "version.h"
#include "rename.h"
#include "utils.h"
#include "volume.h"
#include "remove.h"
#include "prune.h"
#include "list.h"

// The list of our supported commands
struct command g_commands[] = {
    {
        // `create` sub-command
        "create", NULL, cmd_create_main, g_cmd_create_desc, NULL, NULL, &g_cmd_create_args
    },
    {
        // `rm` sub-command
        "rm", NULL, cmd_delete_main, g_cmd_delete_desc, NULL, NULL, &g_cmd_delete_args
    },
    {
        // `ps` sub-command
        "ps", NULL, cmd_list_main, g_cmd_list_desc, NULL, NULL, &g_cmd_list_args
    },
    {
        // `start` sub-command
        "start", NULL, cmd_start_main, g_cmd_start_desc, NULL, NULL, &g_cmd_start_args
    },
    {
        // `run` sub-command
        "run", NULL, cmd_run_main, g_cmd_run_desc, NULL, NULL, &g_cmd_run_args
    },
    {
        // `restart` sub-command
        "restart", NULL, cmd_restart_main, g_cmd_restart_desc, NULL, NULL, &g_cmd_restart_args
    },
    {
        // `inspect` sub-command
        "inspect", NULL, cmd_inspect_main, g_cmd_inspect_desc, NULL, NULL, &g_cmd_inspect_args
    },
    {
        // `pause` sub-command
        "pause", NULL, cmd_pause_main, g_cmd_pause_desc, NULL, NULL, &g_cmd_pause_args
    },
    {
        // `unpause` sub-command
        "unpause", NULL, cmd_resume_main, g_cmd_resume_desc, NULL, NULL, &g_cmd_resume_args
    },
#ifdef ENABLE_OCI_IMAGE
    {
        // `stats` sub-command
        "stats", NULL, cmd_stats_main, g_cmd_stats_desc, NULL, NULL, &g_cmd_stats_args
    },
    {
        // `cp` sub-command
        "cp", NULL, cmd_cp_main, g_cmd_cp_desc, NULL, NULL, &g_cmd_cp_args
    },
#endif
    {
        // `stop` sub-command
        "stop", NULL, cmd_stop_main, g_cmd_stop_desc, NULL, NULL, &g_cmd_stop_args
    },
    {
        // `version` sub-command
        "version", NULL, cmd_version_main, g_cmd_version_desc, NULL, NULL, &g_cmd_version_args
    },
    {
        // `exec` sub-command
        "exec", NULL, cmd_exec_main, g_cmd_exec_desc, NULL, NULL, &g_cmd_exec_args
    },
    {
        // `images` sub-command
        "images", NULL, cmd_images_main, g_cmd_images_desc, NULL, NULL, &g_cmd_images_args
    },
#ifdef ENABLE_OCI_IMAGE
    {
        // `info` sub-command
        "info", NULL, cmd_info_main, g_cmd_info_desc, NULL, NULL, &g_cmd_info_args
    },
#endif
    {
        // `remove images` sub-command
        "rmi", NULL, cmd_rmi_main, g_cmd_rmi_desc, NULL, NULL, &g_cmd_rmi_args
    },
#ifdef ENABLE_OCI_IMAGE
    {
        // `wait` sub-command
        "wait", NULL, cmd_wait_main, g_cmd_wait_desc, NULL, NULL, &g_cmd_wait_args
    },
    {
        // `logs` sub-command
        "logs", NULL, cmd_logs_main, g_cmd_logs_desc, NULL, NULL, &g_cmd_logs_args
    },
    {
        // `events` sub-command
        "events", NULL, cmd_events_main, g_cmd_events_desc, NULL, NULL, &g_cmd_events_args
    },
#endif
    {
        // `kill` sub-command
        "kill", NULL, cmd_kill_main, g_cmd_kill_desc, NULL, NULL, &g_cmd_kill_args
    },
    {
        // `load` sub-command
        "load", NULL, cmd_load_main, g_cmd_load_desc, NULL, NULL, &g_cmd_load_args
    },
#ifdef ENABLE_OCI_IMAGE
    {
        // `update` sub-command
        "update", NULL, cmd_update_main, g_cmd_update_desc, NULL, NULL, &g_cmd_update_args
    },
#endif
    {
        // `attach` sub-command
        "attach", NULL, cmd_attach_main, g_cmd_attach_desc, NULL, NULL, &g_cmd_attach_args
    },
#ifdef ENABLE_OCI_IMAGE
    {
        // `export` sub-command
        "export", NULL, cmd_export_main, g_cmd_export_desc, NULL, NULL, &g_cmd_export_args
    },
    {
        // `top` sub-command
        "top", NULL, cmd_top_main, g_cmd_top_desc, NULL, NULL, &g_cmd_top_args
    },
    {
        // `rename` sub-command
        "rename", NULL, cmd_rename_main, g_cmd_rename_desc, NULL, NULL, &g_cmd_rename_args
    },
    {
        // `pull` sub-command
        "pull", NULL, cmd_pull_main, g_cmd_pull_desc, NULL, NULL, &g_cmd_pull_args
    },
    {
        // `login` sub-command
        "login", NULL, cmd_login_main, g_cmd_login_desc, NULL, NULL, &g_cmd_login_args
    },
    {
        // `logout` sub-command
        "logout", NULL, cmd_logout_main, g_cmd_logout_desc, NULL, NULL, &g_cmd_logout_args
    },
    {
        // `tag` sub-command
        "tag", NULL, cmd_tag_main, g_cmd_tag_desc, NULL, NULL, &g_cmd_tag_args
    },
    {
        // `import` sub-command
        "import", NULL, cmd_import_main, g_cmd_import_desc, NULL, NULL, &g_cmd_import_args
    },
    {
        // `volume rm` sub-command
        "volume", "rm", cmd_volume_rm_main, g_cmd_volume_desc, g_cmd_volume_rm_desc, NULL, &g_cmd_volume_rm_args
    },
    {
        // `volume prune` sub-command
        "volume", "prune", cmd_volume_prune_main, g_cmd_volume_desc, g_cmd_volume_prune_desc, NULL,
        &g_cmd_volume_prune_args
    },
    {
        // `volume ls` sub-command
        "volume", "ls", cmd_volume_ls_main, g_cmd_volume_desc, g_cmd_volume_ls_desc, NULL, &g_cmd_volume_ls_args
    },
#endif
    { NULL, NULL, NULL, NULL, NULL } // End of the list
};

int main(int argc, char **argv)
{
    if (connect_client_ops_init()) {
        return ECOMMON;
    }
    return run_command(g_commands, argc, (const char **)argv);
}
