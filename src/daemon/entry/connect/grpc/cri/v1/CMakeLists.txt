# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_service_cri_v1_srcs)

set(SERVICE_CRI_V1_SRCS
    ${local_service_cri_v1_srcs}
    PARENT_SCOPE
)