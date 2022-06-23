# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_grpc_container_service_srcs)

set(GRPC_CONTAINER_SERVICE_SRCS
    ${local_grpc_container_service_srcs}
    PARENT_SCOPE
)
