

#ifndef __METADATA_STORE_H
#define __METADATA_STORE_H

#include "map.h"
#include "isula_libutils/image_devmapper_device_info.h"

#ifdef __cplusplus
extern "C" {
#endif

int metadata_store_init(void);

bool metadata_store_add(const char *hash, image_devmapper_device_info *device);

image_devmapper_device_info *metadata_store_get(const char *hash);

bool metadata_store_remove(const char *hash);

char **metadata_store_list_hashes(void);

#ifdef __cplusplus
}
#endif
#endif