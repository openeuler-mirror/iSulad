# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_service_grpc_srcs)

set(SERVICE_GRPC_SRCS
    ${local_service_grpc_srcs}
    PARENT_SCOPE
    )
