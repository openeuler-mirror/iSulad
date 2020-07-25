# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_service_rest_srcs)

set(SERVICE_REST_SRCS
    ${local_service_rest_srcs}
    PARENT_SCOPE
    )
