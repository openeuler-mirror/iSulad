aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_client_grpc_srcs)

if(NOT ENABLE_NATIVE_NETWORK)
    list(REMOVE_ITEM local_client_grpc_srcs "${CMAKE_CURRENT_SOURCE_DIR}/grpc_network_client.cc")
endif()


set(CLIENT_GRPC_SRCS
    ${local_client_grpc_srcs}
    PARENT_SCOPE
    )