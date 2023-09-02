/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2022-10-31
 * Description: provide cleanup functions
 *********************************************************************************/
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"
#include "utils_fs.h"
#include "path.h"
#include "cleanup.h"
#include "oci_rootfs_clean.h"

static struct cleaners *create_cleaners()
{
    struct cleaners *ret = NULL;

    ret = util_common_calloc_s(sizeof(struct cleaners));
    if (ret == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    linked_list_init(&(ret->cleaner_list));

    return ret;
}

void destroy_cleaners(struct cleaners *clns)
{
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    struct clean_node *c_node = NULL;

    if (clns == NULL) {
        return;
    }

    linked_list_for_each_safe(it, &(clns->cleaner_list), next) {
        c_node = (struct clean_node *)it->elem;
        linked_list_del(it);
        free(c_node);
        free(it);
        it = NULL;
    }

    free(clns);
}

static int add_clean_node(struct cleaners *clns, clean_func_t f, const char *desc)
{
    struct linked_list *new_node = NULL;
    struct clean_node *c_node = NULL;

    new_node = util_common_calloc_s(sizeof(struct linked_list));
    if (new_node == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    c_node = util_common_calloc_s(sizeof(struct clean_node));
    if (c_node == NULL) {
        ERROR("Out of memory");
        free(new_node);
        return -1;
    }
    c_node->cleaner = f;
    c_node->desc = desc;

    linked_list_add_elem(new_node, c_node);
    linked_list_add_tail(&(clns->cleaner_list), new_node);
    clns->count++;

    return 0;
}

static int default_cleaner()
{
    return 0;
}

struct cleaners *cleaners_init()
{
    int ret = 0;
    struct cleaners *clns = create_cleaners();

    if (clns == NULL) {
        return NULL;
    }

    ret = add_clean_node(clns, default_cleaner, "default clean");
    if (ret != 0) {
        ERROR("Add default_cleaner error");
        return clns;
    }

#ifdef ENABLE_OCI_IMAGE
    ret = add_clean_node(clns, oci_broken_rootfs_cleaner, "clean broken rootfs");
    if (ret != 0) {
        ERROR("Clean broken rootfs failed");
        return clns;
    }

    ret = add_clean_node(clns, oci_rootfs_cleaner, "clean rootfs");
    if (ret != 0) {
        ERROR("Add oci_rootfs_cleaner error");
        return clns;
    }
#endif

    return clns;
}

void cleaners_do_clean(struct cleaners *clns, struct clean_ctx *ctx)
{
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    struct clean_node *c_node = NULL;

    linked_list_for_each_safe(it, &(clns->cleaner_list), next) {
        c_node = (struct clean_node *)it->elem;
        if (c_node->cleaner(ctx) != 0) {
            ERROR("Failed to clean for: %s", c_node->desc);
        } else {
            DEBUG("do clean success for: %s", c_node->desc);
            clns->done_clean++;
        }
    }
}

// always return true;
// if umount/remove failed, just ignore it
static bool walk_isulad_tmpdir_cb(const char *path_name, const struct dirent *sub_dir, void *context)
{
    int nret = 0;
    char tmpdir[PATH_MAX] = { 0 };
    const char *chroot_prefix = "tar-chroot-";

    if (sub_dir == NULL || !util_has_prefix(sub_dir->d_name, chroot_prefix)) {
        // only umount/remove chroot directory
        return true;
    }

    nret = snprintf(tmpdir, PATH_MAX, "%s/%s", path_name, sub_dir->d_name);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        WARN("Failed to snprintf for %s", sub_dir->d_name);
        return true;
    }

    if (util_detect_mounted(tmpdir)) {
        if (umount(tmpdir) != 0) {
            ERROR("Failed to umount target %s, error: %s", tmpdir, strerror(errno));
        }
    }

    if (util_path_remove(tmpdir) != 0) {
        WARN("Failed to remove path %s", tmpdir);
    }

    return true;
}

static int isulad_tmpdir_security_check(const char *tmpdir)
{
    struct stat st = { 0 };

    if (lstat(tmpdir, &st) != 0) {
        SYSERROR("Failed to lstat %s", tmpdir);
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        return -1;
    }

    if ((st.st_mode & 0777) != ISULAD_TEMP_DIRECTORY_MODE) {
        return -1;
    }

    if (st.st_uid != 0) {
        return -1;
    }

    if (S_ISLNK(st.st_mode)) {
        return -1;
    }

    return 0;
}

static int recreate_tmpdir(const char *tmpdir)
{
    int ret;
    struct stat st = { 0 };

    if (util_recursive_rmdir(tmpdir, 0)) {
        ERROR("Failed to remove directory %s", tmpdir);
        return -1;
    }

    if (util_mkdir_p(tmpdir, ISULAD_TEMP_DIRECTORY_MODE)) {
        ERROR("Failed to create directory %s", tmpdir);
        return -1;
    }

    if (lstat(tmpdir, &st) != 0) {
        SYSERROR("Failed to lstat %s", tmpdir);
        return -1;
    }

    return ret;
}

static int ensure_isulad_tmpdir_security(const char *tmpdir)
{
    if (isulad_tmpdir_security_check(tmpdir) == 0) {
        return 0;
    }

    INFO("iSulad tmpdir does not meet security requirements, recreate it");
    return recreate_tmpdir(tmpdir);
}

static void cleanup_path(char *dir)
{
    int nret;
    char tmp_dir[PATH_MAX] = { 0 };
    char cleanpath[PATH_MAX] = { 0 };

    nret = snprintf(tmp_dir, PATH_MAX, "%s/isulad_tmpdir", dir);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Failed to snprintf");
        return;
    }

    if (util_clean_path(tmp_dir, cleanpath, sizeof(cleanpath)) == NULL) {
        ERROR("clean path for %s failed", tmp_dir);
        return;
    }

    // preventing the use of insecure isulad tmpdir directory
    if (ensure_isulad_tmpdir_security(cleanpath) != 0) {
        return;
    }

    nret = util_scan_subdirs(cleanpath, walk_isulad_tmpdir_cb, NULL);
    if (nret != 0) {
        ERROR("failed to scan isulad tmp subdirs");
    }
}

// try to umount/remove isulad_tmpdir/tar-chroot-XXX directory
// ignore return value
void do_isulad_tmpdir_cleaner(void)
{
    char *isula_tmp_dir = NULL;

    isula_tmp_dir = getenv("ISULAD_TMPDIR");
    if (util_valid_str(isula_tmp_dir)) {
        cleanup_path(isula_tmp_dir);
    }
    // No matter whether ISULAD_TMPDIR is set or not,
    // clean up the "/tmp" directory to prevent the mount point from remaining
    cleanup_path("/tmp");

    return;
}
