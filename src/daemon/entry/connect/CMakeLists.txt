# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_server_connect_srcs)

set(local_server_connect_incs ${CMAKE_CURRENT_SOURCE_DIR})

if (GRPC_CONNECTOR)
    add_subdirectory(grpc)
    list(APPEND local_server_connect_srcs ${SERVICE_GRPC_SRCS})
    list(APPEND local_server_connect_incs ${CMAKE_CURRENT_SOURCE_DIR}/grpc)
    if(NOT ENABLE_NATIVE_NETWORK)
        list(REMOVE_ITEM local_server_connect_incs "${CMAKE_CURRENT_SOURCE_DIR}/grpc/grpc_network_service.h")
    endif()
else()
    add_subdirectory(rest)
    list(APPEND local_server_connect_srcs ${SERVICE_REST_SRCS})
    list(APPEND local_server_connect_incs ${CMAKE_CURRENT_SOURCE_DIR}/rest)
    if(NOT ENABLE_NATIVE_NETWORK)
        list(REMOVE_ITEM local_server_connect_incs "${CMAKE_CURRENT_SOURCE_DIR}/rest/rest_network_service.h")
    endif()
endif()

if (ENABLE_METRICS)
    add_subdirectory(metrics)
    list(APPEND local_server_connect_srcs ${METRICS_SERVICE_SRCS})
    list(APPEND local_server_connect_incs ${CMAKE_CURRENT_SOURCE_DIR}/metrics)
endif()

if (GRPC_CONNECTOR)
     # GRPC
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/containers CONNECT_API_CONTAINERS)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/images CONNECT_API_IMAGES)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/volumes CONNECT_API_VOLUMES)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/cri CONNECT_API_CRI)
    set(CONNECT_API ${CONNECT_API_CONTAINERS} ${CONNECT_API_VOLUMES} ${CONNECT_API_IMAGES} ${CONNECT_API_CRI})
    list(APPEND local_server_connect_srcs ${CONNECT_API})

    list(APPEND local_server_connect_incs
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/containers
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/images
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/volumes
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri
        )

    if (ENABLE_NATIVE_NETWORK)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/network CONNECT_API_NETWORK)
    list(APPEND local_server_connect_srcs ${CONNECT_API_NETWORK})
    list(APPEND local_server_connect_incs ${CMAKE_BINARY_DIR}/grpc/src/api/services/network)
    endif()
endif()


set(SERVER_CONNECT_SRCS ${local_server_connect_srcs} PARENT_SCOPE)
set(SERVER_CONNECT_INCS ${local_server_connect_incs} PARENT_SCOPE)
