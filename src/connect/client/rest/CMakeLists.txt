# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_client_rest_srcs)

set(CLIENT_REST_SRCS
    ${local_client_rest_srcs}
    PARENT_SCOPE
    )
