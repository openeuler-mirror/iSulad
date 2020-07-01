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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container mediatype definition
 ******************************************************************************/
#ifndef _MEDIATYPE_H
#define _MEDIATYPE_H

#define MediaTypeDockerSchema2Layer "application/vnd.docker.image.rootfs.diff.tar"
#define MediaTypeDockerSchema2LayerGzip "application/vnd.docker.image.rootfs.diff.tar.gzip"
#define MediaTypeDockerSchema2Config "application/vnd.docker.container.image.v1+json"
#define MediaTypeDockerSchema2Manifest "application/vnd.docker.distribution.manifest.v2+json"
#define MediaTypeDockerSchema2ManifestList "application/vnd.docker.distribution.manifest.list.v2+json"
// Checkpoint/Restore Media Types
#define MediaTypeContainerd1Checkpoint "application/vnd.containerd.container.criu.checkpoint.criu.tar"
#define MediaTypeContainerd1CheckpointPreDump "application/vnd.containerd.container.criu.checkpoint.predump.tar"
#define MediaTypeContainerd1Resource "application/vnd.containerd.container.resource.tar"
#define MediaTypeContainerd1RW "application/vnd.containerd.container.rw.tar"
#define MediaTypeContainerd1CheckpointConfig "application/vnd.containerd.container.checkpoint.config.v1+proto"
// Legacy Docker schema1 manifest
#define MediaTypeDockerSchema1Manifest "application/vnd.docker.distribution.manifest.v1+prettyjws"

// MediaTypeDescriptor specifies the media type for a content descriptor.
#define MediaTypeDescriptor "application/vnd.oci.descriptor.v1+json"

// MediaTypeLayoutHeader specifies the media type for the oci-layout.
#define MediaTypeLayoutHeader "application/vnd.oci.layout.header.v1+json"

// MediaTypeImageManifest specifies the media type for an image manifest.
#define MediaTypeImageManifest "application/vnd.oci.image.manifest.v1+json"

// MediaTypeImageIndex specifies the media type for an image index.
#define MediaTypeImageIndex "application/vnd.oci.image.index.v1+json"

// MediaTypeImageLayer is the media type used for layers referenced by the manifest.
#define MediaTypeImageLayer "application/vnd.oci.image.layer.v1.tar"

// MediaTypeImageLayerGzip is the media type used for gzipped layers
// referenced by the manifest.
#define MediaTypeImageLayerGzip "application/vnd.oci.image.layer.v1.tar+gzip"

// MediaTypeImageLayerNonDistributable is the media type for layers referenced by
// the manifest but with distribution restrictions.
#define MediaTypeImageLayerNonDistributable "application/vnd.oci.image.layer.nondistributable.v1.tar"

// MediaTypeImageLayerNonDistributableGzip is the media type for
// gzipped layers referenced by the manifest but with distribution
// restrictions.
#define MediaTypeImageLayerNonDistributableGzip "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"

// MediaTypeImageConfig specifies the media type for the image configuration.
#define MediaTypeImageConfig "application/vnd.oci.image.config.v1+json"

// MediaTypeImageEmbedded specifies the media type for the embedded image configuration.
#define MediaTypeEmbeddedImageManifest "application/embedded.manifest+json"
#define MediaTypeEmbeddedLayerSquashfs "application/squashfs.image.rootfs.diff.img"
#define MediaTypeEmbeddedLayerDir "application/bind.image.rootfs.diff.dir"

#define MediaTypeJson "application/json"

#define DOCKER_HOSTNAME "docker.io"
#define DOCKER_V1HOSTNAME "index.docker.io"
#define DOCKER_REGISTRY "registry-1.docker.io"
#define DOCKER_MANIFEST_SCHEMA2_JSON "application/vnd.docker.distribution.manifest.v2+json"
#define DOCKER_MANIFEST_SCHEMA2_LIST "application/vnd.docker.distribution.manifest.list.v2+json"
#define DOCKER_MANIFEST_SCHEMA1_JSON "application/vnd.docker.distribution.manifest.v1+json"
#define DOCKER_MANIFEST_SCHEMA1_PRETTYJWS "application/vnd.docker.distribution.manifest.v1+prettyjws"
#define MEDIA_TYPE_APPLICATION_JSON "application/json"
#define OCI_MANIFEST_V1_JSON "application/vnd.oci.image.manifest.v1+json"
#define OCI_INDEX_V1_JSON "application/vnd.oci.image.index.v1+json"
#define DOCKER_IMAGE_LAYER_TAR_GZIP "application/vnd.docker.image.rootfs.diff.tar.gzip"
#define DOCKER_IMAGE_LAYER_FOREIGN_TAR_GZIP "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
#define DOCKER_IMAGE_V1 "application/vnd.docker.container.image.v1+json"
#define OCI_IMAGE_V1 "application/vnd.oci.image.config.v1+json"
#define OCI_IMAGE_LAYER_TAR "application/vnd.oci.image.layer.v1.tar"
#define OCI_IMAGE_LAYER_TAR_GZIP "application/vnd.oci.image.layer.v1.tar+gzip"
#define OCI_IMAGE_LAYER_ND_TAR "application/vnd.oci.image.layer.nondistributable.v1.tar"
#define OCI_IMAGE_LAYER_ND_TAR_GZIP "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"

#endif

