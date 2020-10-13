if (GRPC_CONNECTOR)
    set(CLIENT_GRPC_SRCS
        ${CMAKE_CURRENT_SOURCE_DIR}/grpc_client.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/grpc_containers_client.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/grpc_images_client.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/grpc_volumes_client.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/grpc_network_client.cc
        PARENT_SCOPE
        )
endif()
