# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_server_connect_srcs)

set(local_server_connect_incs ${CMAKE_CURRENT_SOURCE_DIR})

if (GRPC_CONNECTOR)
    add_subdirectory(grpc)
    list(APPEND local_server_connect_srcs ${SERVICE_GRPC_SRCS})
    list(APPEND local_server_connect_incs ${CMAKE_CURRENT_SOURCE_DIR}/grpc)
else()
    add_subdirectory(rest)
    list(APPEND local_server_connect_srcs ${SERVICE_REST_SRCS})
    list(APPEND local_server_connect_incs ${CMAKE_CURRENT_SOURCE_DIR}/rest)
endif()

if (GRPC_CONNECTOR)
     # GRPC
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/containers CONNECT_API_CONTAINERS)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/images CONNECT_API_IMAGES)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/volumes CONNECT_API_VOLUMES)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/cri CONNECT_API_CRI)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/network CONNECT_API_NETWORK)
    set(CONNECT_API ${CONNECT_API_CONTAINERS} ${CONNECT_API_VOLUMES} ${CONNECT_API_IMAGES} ${CONNECT_API_CRI} ${CONNECT_API_NETWORK})
    list(APPEND local_server_connect_srcs ${CONNECT_API})

    list(APPEND local_server_connect_incs
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/containers
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/images
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/volumes
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/network
        )
endif()


set(SERVER_CONNECT_SRCS ${local_server_connect_srcs} PARENT_SCOPE)
set(SERVER_CONNECT_INCS ${local_server_connect_incs} PARENT_SCOPE)
