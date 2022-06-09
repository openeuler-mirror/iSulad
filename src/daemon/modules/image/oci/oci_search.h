#ifndef DAEMON_MODULES_IMAGE_OCI_OCI_SEARCH_H
#define DAEMON_MODULES_IMAGE_OCI_OCI_SEARCH_H

#include "image_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int oci_do_search_image(const im_search_request *request, im_search_response *response);

#ifdef __cplusplus
}
#endif
#endif