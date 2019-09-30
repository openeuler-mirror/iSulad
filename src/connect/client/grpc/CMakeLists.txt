# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_client_grpc_srcs)

set(CLIENT_GRPC_SRCS
    ${local_client_grpc_srcs}
    PARENT_SCOPE
    )
