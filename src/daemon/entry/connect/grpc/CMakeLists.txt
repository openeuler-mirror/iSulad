# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_service_grpc_srcs)

if(NOT ENABLE_NATIVE_NETWORK)
    list(REMOVE_ITEM local_service_grpc_srcs "${CMAKE_CURRENT_SOURCE_DIR}/grpc_network_service.cc")
endif()

set(SERVICE_GRPC_SRCS
    ${local_service_grpc_srcs}
    PARENT_SCOPE
    )
