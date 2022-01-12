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
 * Author: wujing
 * Create: 2020-12-15
 * Description: provide cri image manager service function definition
 *********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_IMAGE_MANAGER_SERVICE_H
#define DAEMON_ENTRY_CRI_IMAGE_MANAGER_SERVICE_H
#include <memory>
#include <string>
#include <vector>

#include "api.pb.h"
#include "errors.h"

namespace CRI {
class ImageManagerService {
public:
    ImageManagerService() = default;
    virtual ~ImageManagerService() = default;

    virtual void ListImages(const runtime::v1alpha2::ImageFilter &filter,
                            std::vector<std::unique_ptr<runtime::v1alpha2::Image>> *images, Errors &error) = 0;

    virtual auto ImageStatus(const runtime::v1alpha2::ImageSpec &image,
                             Errors &error) -> std::unique_ptr<runtime::v1alpha2::Image> = 0;

    virtual auto PullImage(const runtime::v1alpha2::ImageSpec &image, const runtime::v1alpha2::AuthConfig &auth,
                           Errors &error) -> std::string = 0;

    virtual void RemoveImage(const runtime::v1alpha2::ImageSpec &image, Errors &error) = 0;

    virtual void ImageFsInfo(std::vector<std::unique_ptr<runtime::v1alpha2::FilesystemUsage>> *usages,
                             Errors &error) = 0;
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_IMAGE_MANAGER_SERVICE_H