# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_service_cri_v1alpha_srcs)

set(SERVICE_CRI_V1ALPHA_SRCS
    ${local_service_cri_v1alpha_srcs}
    PARENT_SCOPE
)