/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2020-04-02
 * Description: provide quota function definition
 ******************************************************************************/
#include "project_quota.h"
#include <pthread.h>

#include "utils.h"
#include "utils_string.h"
#include "log.h"

// define for quotactl commands
#define PDQ_ACCT_BIT 4 // 4 means project quota accounting ops
#define PDQ_ENFD_BIT 5 // 5 means project quota limits enforcement

// make device of the driver home directory
static char *make_backing_fs_device(const char *home_dir)
{
    int ret = 0;
    char full_path[PATH_MAX] = { 0 };
    struct stat current_stat = { 0 };

    ret = snprintf(full_path, PATH_MAX, "%s/%s", home_dir, "backingFsBlockDev");
    if (ret < 0 || ret >= PATH_MAX) {
        ERROR("Failed to get backing fs device");
        goto err_out;
    }

    ret = stat(home_dir, &current_stat);
    if (ret) {
        SYSERROR("get %s state failed", home_dir);
        goto err_out;
    }

    unlink(full_path);
    ret = mknod(full_path, S_IFBLK | S_IRUSR | S_IWUSR, current_stat.st_dev);
    if (ret != 0) {
        SYSERROR("Failed to mknod %s", full_path);
        goto err_out;
    }

    return util_strdup_s(full_path);

err_out:
    return NULL;
}

static int set_project_quota_id(const uint32_t projectid, const char *target)
{
    int ret = 0;
    struct fsxattr fsxattr_for_prjid = { 0 };
    DIR *dir = NULL;
    int fd = -1;

    dir = opendir(target);
    if (dir == NULL) {
        ret = -1;
        SYSERROR("opendir with path %s failed", target);
        goto out;
    }

    fd = dirfd(dir);
    if (fd < 0) {
        ret = -1;
        SYSERROR("open %s failed.", target);
        goto out;
    }

    ret = ioctl(fd, FS_IOC_FSGETXATTR, &fsxattr_for_prjid);
    if (ret != 0) {
        SYSERROR("failed to get projid for %s", target);
        goto out;
    }

    fsxattr_for_prjid.fsx_projid = projectid;
    fsxattr_for_prjid.fsx_xflags |= FS_XFLAG_PROJINHERIT;
    ret = ioctl(fd, FS_IOC_FSSETXATTR, &fsxattr_for_prjid);
    if (ret != 0) {
        SYSERROR("failed to set projid for %s", target);
        goto out;
    }

out:
    if (dir != NULL) {
        closedir(dir);
    }
    return ret;
}

static int ext4_set_project_quota(const char *backing_fs_blockdev, uint32_t project_id, uint64_t size)
{
    int ret;
    struct dqblk d = {0};
    d.dqb_bhardlimit = size / SIZE_KB;
    d.dqb_bsoftlimit = d.dqb_bhardlimit;
    d.dqb_valid = QIF_LIMITS;

    ret = quotactl(QCMD(Q_SETQUOTA, FS_PROJ_QUOTA), backing_fs_blockdev,
                   project_id, (caddr_t)&d);
    if (ret != 0) {
        SYSERROR("Failed to set quota limit for projid %d on %s", project_id, backing_fs_blockdev);
    }
    return ret;
}

static int ext4_set_quota(const char *target, struct pquota_control *ctrl, uint64_t size)
{
    int ret = 0;
    uint32_t project_id = 0;

    if (target == NULL || ctrl == NULL) {
        return -1;
    }

    if (pthread_rwlock_wrlock(&(ctrl->rwlock)) != 0) {
        SYSERROR("Failed to get rwlock in set_quota");
        ret = -1;
        goto out;
    }

    project_id = ctrl->next_project_id;
    if (set_project_quota_id(project_id, target) != 0) {
        ERROR("Failed to set project id %d to %s.", project_id, target);
        ret = -1;
        goto unlock;
    }
    ctrl->next_project_id++;

    if (ext4_set_project_quota(ctrl->backing_fs_device, project_id, size) != 0) {
        ERROR("Failed to set project id %d to %s.", project_id, target);
        ret = -1;
        goto unlock;
    }

unlock:
    (void)pthread_rwlock_unlock(&(ctrl->rwlock));
out:
    return ret;
}

static int xfs_set_project_quota(const char *backing_fs_blockdev, uint32_t project_id, uint64_t size)
{
    int ret;
    fs_disk_quota_t d = {0};
    d.d_version = FS_DQUOT_VERSION;
    d.d_id = project_id;
    d.d_flags = FS_PROJ_QUOTA;
    d.d_fieldmask = FS_DQ_BHARD | FS_DQ_BSOFT;
    d.d_blk_hardlimit = (size / 512);
    d.d_blk_softlimit = d.d_blk_hardlimit;

    ret = quotactl(QCMD(Q_XSETQLIM, FS_PROJ_QUOTA), backing_fs_blockdev,
                   project_id, (caddr_t)&d);
    if (ret != 0) {
        SYSERROR("Failed to set quota limit for projid %d on %s", project_id, backing_fs_blockdev);
    }
    return ret;
}

static int xfs_set_quota(const char *target, struct pquota_control *ctrl, uint64_t size)
{
    int ret = 0;
    uint32_t project_id = 0;

    if (target == NULL || ctrl == NULL) {
        return -1;
    }

    if (pthread_rwlock_wrlock(&(ctrl->rwlock)) != 0) {
        SYSERROR("Failed to get rwlock in set_quota");
        ret = -1;
        goto out;
    }

    project_id = ctrl->next_project_id;
    if (set_project_quota_id(project_id, target) != 0) {
        ERROR("Failed to set project id %d to %s.", project_id, target);
        ret = -1;
        goto unlock;
    }
    ctrl->next_project_id++;

    if (xfs_set_project_quota(ctrl->backing_fs_device, project_id, size) != 0) {
        ERROR("Failed to set project id %d to %s.", project_id, target);
        ret = -1;
        goto unlock;
    }

unlock:
    (void)pthread_rwlock_unlock(&(ctrl->rwlock));
out:
    return ret;
}

static int get_project_quota_id(const char *path, uint32_t *project_id)
{
    int ret = 0;
    DIR *dir = NULL;
    int fd = -1;
    struct fsxattr fsxattr = {0};

    dir = opendir(path);
    if (dir == NULL) {
        ret = -1;
        SYSERROR("opendir with path %s failed", path);
        goto out;
    }
    fd = dirfd(dir);
    if (fd < 0) {
        ret = -1;
        SYSERROR("open %s failed.", path);
        goto out;
    }
    ret = ioctl(fd, FS_IOC_FSGETXATTR, &fsxattr);
    if (ret != 0) {
        SYSERROR("failed to get projid for %s", path);
        goto out;
    }

    *project_id = (uint32_t)fsxattr.fsx_projid;
out:
    if (dir != NULL) {
        closedir(dir);
    }
    return ret;
}

static void get_next_project_id(const char *dirpath, struct pquota_control *ctrl)
{
    int nret = 0;
    struct dirent *pdirent = NULL;
    DIR *directory = NULL;
    char fname[PATH_MAX];

    directory = opendir(dirpath);
    if (directory == NULL) {
        ERROR("Failed to open %s", dirpath);
        return;
    }
    pdirent = readdir(directory);
    for (; pdirent != NULL; pdirent = readdir(directory)) {
        struct stat fstat;
        int pathname_len;
        uint32_t project_id = 0;

        if (!strcmp(pdirent->d_name, ".") || !strcmp(pdirent->d_name, "..")) {
            continue;
        }

        (void)memset(fname, 0, sizeof(fname));

        pathname_len = snprintf(fname, PATH_MAX, "%s/%s", dirpath, pdirent->d_name);
        if (pathname_len < 0 || pathname_len >= PATH_MAX) {
            ERROR("Pathname too long");
            continue;
        }

        nret = lstat(fname, &fstat);
        if (nret != 0) {
            ERROR("get_next_project_id failed to stat %s", fname);
            continue;
        }

        if (!S_ISDIR(fstat.st_mode)) {
            continue;
        }

        if (get_project_quota_id(fname, &project_id) != 0) {
            ERROR("Failed to get %s project id", fname);
            continue;
        }
        if (ctrl->next_project_id <= project_id) {
            ctrl->next_project_id = project_id + 1;
        }
    }

    nret = closedir(directory);
    if (nret) {
        ERROR("Failed to close directory %s", dirpath);
    }

    return;
}

static void free_pquota_control(struct pquota_control *ctrl)
{
    if (ctrl == NULL) {
        return;
    }

    free(ctrl->backing_fs_type);
    ctrl->backing_fs_type = NULL;

    free(ctrl->backing_fs_device);
    ctrl->backing_fs_device = NULL;

    if (pthread_rwlock_destroy(&(ctrl->rwlock)) != 0) {
        SYSERROR("destory pquota_control rwlock failed");
    }
    free(ctrl);
}

static int get_quota_stat(const char *backing_fs_blockdev)
{
    int ret = 0;
    int nret = 0;
    fs_quota_stat_t fs_quota_stat_info = {0};

    ret = quotactl(QCMD(Q_XGETQSTAT, FS_PROJ_QUOTA), backing_fs_blockdev,
                   0, (caddr_t)&fs_quota_stat_info);
    if (ret != 0) {
        SYSERROR("Failed to get quota stat on %s", backing_fs_blockdev);
        return ret;
    }

    nret = ((fs_quota_stat_info.qs_flags & FS_QUOTA_PDQ_ACCT) >> PDQ_ACCT_BIT) +
           ((fs_quota_stat_info.qs_flags & FS_QUOTA_PDQ_ENFD) >> PDQ_ENFD_BIT);
    if (nret == FS_PROJ_QUOTA) { // return FS_PROJ_QUOTA(2) means project quota is on
        ret = 0;
    } else {
        ret = -1;
    }

    return ret;
}

static bool fs_support_quota(const char *fs)
{
    if (fs == NULL) {
        return false;
    }

    return (strcmp(fs, "xfs") == 0 || strcmp(fs, "ext4") == 0);
}

struct pquota_control *project_quota_control_init(const char *home_dir, const char *fs)
{
    int ret = 0;
    struct pquota_control *ctrl = NULL;
    uint32_t min_project_id = 0;

    if (home_dir == NULL || fs == NULL) {
        ERROR("Invalid input auguments");
        goto err_out;
    }

    if (!fs_support_quota(fs)) {
        ERROR("quota isn't supported for filesystem %s", fs);
        goto err_out;
    }

    ctrl = util_common_calloc_s(sizeof(struct pquota_control));
    if (ctrl == NULL) {
        ERROR("out of memory");
        goto err_out;
    }

    ret = pthread_rwlock_init(&(ctrl->rwlock), NULL);
    if (ret) {
        SYSERROR("init project quota rwlock failed");
        goto err_out;
    }

    ret = get_project_quota_id(home_dir, &min_project_id);
    if (ret) {
        ERROR("Failed to get mininal project id %s", home_dir);
        goto err_out;
    }
    min_project_id++;
    ctrl->next_project_id = min_project_id;
    get_next_project_id(home_dir, ctrl);

    ctrl->backing_fs_device = make_backing_fs_device(home_dir);
    if (ctrl->backing_fs_device == NULL) {
        ERROR("Failed to make backing fs device %s", home_dir);
        goto err_out;
    }

    if (get_quota_stat(ctrl->backing_fs_device) != 0) {
        ERROR("quota isn't supported on your system %s", home_dir);
        goto err_out;
    }

    ctrl->backing_fs_type = util_strdup_s(fs);

    if (strcmp(ctrl->backing_fs_type, "ext4") == 0) {
        ctrl->set_quota = ext4_set_quota;
    } else {
        ctrl->set_quota = xfs_set_quota;
    }

    return ctrl;

err_out:
    free_pquota_control(ctrl);
    return NULL;
}
