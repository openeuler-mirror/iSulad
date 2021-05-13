/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
* Author: lifeng
* Create: 2020-06-15
* Description: provide oci image operator definition
*******************************************************************************/
#include "image_rootfs_handler.h"

#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <isula_libutils/host_config.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "err_msg.h"
#include "utils.h"
#include "path.h"
#include "utils_convert.h"
#include "utils_file.h"

#define MINUID 0
#define MAXUID (((1LL << 31) - 1))
#define DEFAULT_UID 0

#define UnixPasswdPath "/etc/passwd"
#define UnixGroupPath "/etc/group"

static void uids_gids_range_err_log()
{
    ERROR("uids and gids must be in range 0-%lld", MAXUID);
    isulad_set_error_message("uids and gids must be in range 0-%d", MAXUID);
    return;
}

static bool b_user_found(const char *user, const struct passwd *pwbufp)
{
    int uret = -1;
    long long n_user = 0;
    bool userfound = false;

    if (pwbufp == NULL) {
        return false;
    }

    if (user != NULL) {
        uret = util_safe_llong(user, &n_user);
    }

    if (user == NULL && pwbufp->pw_uid == DEFAULT_UID) {
        userfound = true;
    }
    // Treat numeric usename as valid UID
    if (uret == 0 && (long long)pwbufp->pw_uid == n_user) {
        userfound = true;
    }
    if (uret != 0 && user != NULL && strcmp(user, pwbufp->pw_name) == 0) {
        userfound = true;
    }

    return userfound;
}

static int proc_by_fpasswd(FILE *f_passwd, const char *user, defs_process_user *puser, char **matched_username)
{
    int ret = 0;
    int errval = 0;
    int uret = -1;
    bool userfound = false;
    long long n_user = 0;
    char buf[BUFSIZ];
    struct passwd pw;
    struct passwd *pwbufp = NULL;

    if (f_passwd != NULL) {
        errval = fgetpwent_r(f_passwd, &pw, buf, sizeof(buf), &pwbufp);

        while (errval == 0 && pwbufp != NULL) {
            userfound = b_user_found(user, pwbufp);
            // Take the first match as valid user
            if (userfound) {
                // oci spec donot use username spec on linux
                free(puser->username);
                puser->username = NULL;
                puser->uid = pwbufp->pw_uid;
                puser->gid = pwbufp->pw_gid;
                *matched_username = util_strdup_s(pwbufp->pw_name);
                break;
            }
            errval = fgetpwent_r(f_passwd, &pw, buf, sizeof(buf), &pwbufp);
        }
    }

    if (errval != 0 && errval != ENOENT) {
        ERROR("Failed to parse passwd file: Insufficient buffer space supplied");
        isulad_set_error_message("Failed to parse passwd file: Insufficient buffer space supplied");
        ret = -1;
        goto out;
    }
    if (!userfound && user != NULL) {
        uret = util_safe_llong(user, &n_user);
        // user is not a valid numeric UID
        if (uret != 0) {
            ERROR("Unable to find user '%s'", user);
            isulad_set_error_message("Unable to find user '%s': no matching entries in passwd file", user);
            ret = -1;
            goto out;
        }
        if (n_user < MINUID || n_user > MAXUID) {
            uids_gids_range_err_log();
            ret = -1;
            goto out;
        }
        puser->uid = (uid_t)n_user;
    }

out:
    return ret;
}

static int append_additional_gids(gid_t gid, gid_t **additional_gids, size_t *len)
{
    int ret = 0;
    size_t new_len = 0;
    size_t i;
    gid_t *new_gids = NULL;

    if (*len > (SIZE_MAX / sizeof(gid_t)) - 1) {
        ERROR("Out of memory");
        return -1;
    }

    new_len = *len + 1;

    for (i = 0; i < *len; i++) {
        if ((*additional_gids)[i] == gid) {
            return 0;
        }
    }

    ret = util_mem_realloc((void **)&new_gids, new_len * sizeof(gid_t), *additional_gids, (*len) * sizeof(gid_t));
    if (ret != 0) {
        ERROR("Out of memory");
        return -1;
    }
    *additional_gids = new_gids;
    (*additional_gids)[*len] = gid;
    *len = new_len;
    return 0;
}

static int search_group_list(struct group *gbufp, const char *username, defs_process_user *puser)
{
    char **username_list = gbufp->gr_mem;
    while (username_list != NULL && *username_list != NULL) {
        if (strcmp(*username_list, username) == 0) {
            if (append_additional_gids(gbufp->gr_gid, &puser->additional_gids, &puser->additional_gids_len)) {
                ERROR("Failed to append additional groups");
                return -1;
            }
            break;
        }
        username_list++;
    }
    return 0;
}

static bool check_group_found(const char *group, const struct group *gbufp)
{
    int gret = -1;
    long long n_grp = 0;

    if (group != NULL) {
        gret = util_safe_llong(group, &n_grp);
    }

    if (gret == 0 && n_grp == (long long)gbufp->gr_gid) {
        return true;
    }
    if (gret != 0 && group != NULL && strcmp(group, gbufp->gr_name) == 0) {
        return true;
    }

    return false;
}

static int do_proc_by_froup(FILE *f_group, const char *group, defs_process_user *puser, const char *matched_username,
                            int *groupcnt)
{
    int errval = 0;
    char buf[BUFSIZ] = { 0 };
    bool groupfound = false;
    struct group grp;
    struct group *gbufp = NULL;

    if (f_group == NULL) {
        return 0;
    }

    errval = fgetgrent_r(f_group, &grp, buf, sizeof(buf), &gbufp);
    while (errval == 0 && gbufp != NULL) {
        // Treat numeric group as valid GID
        if (group == NULL) {
            if (search_group_list(gbufp, matched_username, puser) != 0) {
                return -1;
            }
            errval = fgetgrent_r(f_group, &grp, buf, sizeof(buf), &gbufp);
            continue;
        }

        groupfound = check_group_found(group, gbufp);
        if (groupfound && *groupcnt != 1) {
            // Continue search group list, but only take first found group
            puser->gid = gbufp->gr_gid;
            *groupcnt = 1;
        }
        errval = fgetgrent_r(f_group, &grp, buf, sizeof(buf), &gbufp);
    }

    return 0;
}

static int proc_by_fgroup(FILE *f_group, const char *group, defs_process_user *puser, const char *matched_username)
{
    int ret = 0;
    int gret = -1;
    int groupcnt = 0;
    long long n_grp = 0;

    if (group != NULL || matched_username != NULL) {
        if (do_proc_by_froup(f_group, group, puser, matched_username, &groupcnt) != 0) {
            goto out;
        }

        if (group != NULL && groupcnt == 0) {
            gret = util_safe_llong(group, &n_grp);
            // group is not a valid numeric GID
            if (gret != 0) {
                ERROR("Unable to find group '%s'", group);
                isulad_set_error_message("Unable to find group '%s': no matching entries in group file", group);
                ret = -1;
                goto out;
            }
            if (n_grp < MINUID || n_grp > MAXUID) {
                uids_gids_range_err_log();
                ret = -1;
                goto out;
            }
            puser->gid = (gid_t)n_grp;
        }
    }

out:
    return ret;
}

static int append_additional_groups(const struct group *grp, struct group **groups, size_t *len)
{
    int ret = 0;
    struct group *new_groups = NULL;
    size_t new_len = *len + 1;

    ret = util_mem_realloc((void **)&new_groups, new_len * sizeof(struct group), *groups,
                           (*len) * sizeof(struct group));
    if (ret != 0) {
        ERROR("Out of memory");
        return -1;
    }
    *groups = new_groups;
    (*groups)[*len].gr_name = util_strdup_s(grp->gr_name);
    (*groups)[*len].gr_gid = grp->gr_gid;
    *len = new_len;
    return 0;
}

static bool group_matched(const char *group, const struct group *gbufp)
{
    bool matched = false;
    long long n_gid = 0;
    int gret = -1;

    if (group == NULL || gbufp == NULL) {
        return false;
    }

    gret = util_safe_llong(group, &n_gid);
    if (strcmp(group, gbufp->gr_name) == 0 || (gret == 0 && n_gid == gbufp->gr_gid)) {
        matched = true;
    }

    return matched;
}

static int get_one_additional_group(const char *additional_group, struct group *groups, size_t groups_len,
                                    defs_process_user *puser)
{
    int ret = 0;
    int gret = -1;
    long long n_gid = 0;
    bool found = false;
    size_t j;

    for (j = 0; groups != NULL && j < groups_len; j++) {
        // Only take the first founded group
        if (group_matched(additional_group, &groups[j])) {
            found = true;
            if (append_additional_gids(groups[j].gr_gid, &puser->additional_gids, &puser->additional_gids_len)) {
                ERROR("Failed to append additional groups");
                ret = -1;
                goto out;
            }
            break;
        }
    }

    if (!found) {
        gret = util_safe_llong(additional_group, &n_gid);
        if (gret != 0) {
            ERROR("Unable to find group %s", additional_group);
            isulad_set_error_message("Unable to find group %s", additional_group);
            ret = -1;
            goto out;
        }
        if (n_gid < MINUID || n_gid > MAXUID) {
            uids_gids_range_err_log();
            ret = -1;
            goto out;
        }
        if (append_additional_gids((gid_t)n_gid, &puser->additional_gids, &puser->additional_gids_len)) {
            ERROR("Failed to append additional groups");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int get_additional_groups(char **additional_groups, size_t additional_groups_len, FILE *f_group,
                                 defs_process_user *puser)
{
    int ret = 0;
    size_t i;
    size_t groups_len = 0;
    char buf[BUFSIZ] = { 0 };
    struct group grp;
    struct group *gbufp = NULL;
    struct group *groups = NULL;

    while (f_group != NULL && fgetgrent_r(f_group, &grp, buf, sizeof(buf), &gbufp) == 0) {
        for (i = 0; i < additional_groups_len; i++) {
            if (!group_matched(additional_groups[i], gbufp)) {
                continue;
            }
            if (append_additional_groups(gbufp, &groups, &groups_len)) {
                ret = -1;
                goto cleanup;
            }
        }
    }

    for (i = 0; i < additional_groups_len; i++) {
        ret = get_one_additional_group(additional_groups[i], groups, groups_len, puser);
        if (ret != 0) {
            ret = -1;
            goto cleanup;
        }
    }

cleanup:
    for (i = 0; groups != NULL && i < groups_len; i++) {
        free(groups[i].gr_name);
    }
    free(groups);

    return ret;
}

static int read_user_file(const char *basefs, const char *user_path, FILE **stream)
{
    int ret = 0;
    int64_t filesize = 0;
    char *real_path = NULL;

    if (util_realpath_in_scope(basefs, user_path, &real_path) < 0) {
        ERROR("user target file '%s' real path must be under '%s'", user_path, basefs);
        isulad_set_error_message("user target file '%s' real path must be under '%s'", user_path, basefs);
        ret = -1;
        goto out;
    }

    filesize = util_file_size(real_path);
    if (filesize > REGULAR_FILE_SIZE) {
        ERROR("File %s is more than %lld", real_path, (long long)REGULAR_FILE_SIZE);
        isulad_set_error_message("File %s is more than %lld", real_path, (long long)REGULAR_FILE_SIZE);
        ret = -1;
        goto out;
    }

    *stream = util_fopen(real_path, "r");
    if (*stream == NULL) {
        WARN("Failed to open %s: %s", real_path, strerror(errno));
        ret = 0;
        goto out;
    }

out:
    free(real_path);
    return ret;
}

static int resolve_basefs(const char *basefs, char **resolved_basefs)
{
    struct stat s;
    char real_path[PATH_MAX + 1] = { 0 };

    if (strlen(basefs) > PATH_MAX || !realpath(basefs, real_path)) {
        ERROR("invalid file path %s", basefs);
        return -1;
    }

    if (stat(real_path, &s) < 0) {
        ERROR("stat failed, error: %s", strerror(errno));
        return -1;
    }

    if ((s.st_mode & S_IFMT) == S_IFDIR) {
        *resolved_basefs = util_strdup_s(real_path);
    } else {
        *resolved_basefs = util_strdup_s("/");
    }

    return 0;
}

static int get_exec_user(const char *username, FILE *f_passwd, FILE *f_group, defs_process_user *puser)
{
    int ret = 0;
    char *tmp = NULL;
    char *user = NULL;
    char *group = NULL;
    char *matched_username = NULL;

    // parse user and group by username
    util_parse_user_group(username, &user, &group, &tmp);

    // proc by f_passwd
    ret = proc_by_fpasswd(f_passwd, user, puser, &matched_username);
    if (ret != 0) {
        ret = -1;
        goto cleanup;
    }

    // proc by f_group
    ret = proc_by_fgroup(f_group, group, puser, matched_username);
    if (ret != 0) {
        ret = -1;
        goto cleanup;
    }

cleanup:
    free(matched_username);
    free(tmp);
    return ret;
}

int get_user_from_image_roofs(const char *basefs, const host_config *hc, const char *userstr, defs_process_user *puser)
{
    int ret = 0;
    FILE *f_passwd = NULL;
    FILE *f_group = NULL;
    char *resolved_basefs = NULL;

    if (basefs == NULL || puser == NULL || hc == NULL) {
        return -1;
    }

    ret = resolve_basefs(basefs, &resolved_basefs);
    if (ret != 0) {
        goto cleanup;
    }

    ret = read_user_file(resolved_basefs, UnixPasswdPath, &f_passwd);
    if (ret != 0) {
        goto cleanup;
    }
    ret = read_user_file(resolved_basefs, UnixGroupPath, &f_group);
    if (ret != 0) {
        goto cleanup;
    }

    ret = get_exec_user(userstr, f_passwd, f_group, puser);
    if (ret != 0) {
        goto cleanup;
    }

    if (hc->group_add != NULL && hc->group_add_len > 0) {
        if (hc->group_add_len > LIST_SIZE_MAX) {
            ERROR("Too many groups to add, the limit is %lld", LIST_SIZE_MAX);
            isulad_set_error_message("Too many groups to add, the limit is %d", LIST_SIZE_MAX);
            ret = -1;
            goto cleanup;
        }
        // Rewind f_group to serach from beginning again.
        if (f_group != NULL) {
            rewind(f_group);
        }
        ret = get_additional_groups(hc->group_add, hc->group_add_len, f_group, puser);
        if (ret != 0) {
            goto cleanup;
        }
    }

cleanup:
    if (f_passwd != NULL) {
        fclose(f_passwd);
    }
    if (f_group != NULL) {
        fclose(f_group);
    }

    free(resolved_basefs);

    return ret;
}
