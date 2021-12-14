set(local_client_connect_srcs
    ${CMAKE_CURRENT_SOURCE_DIR}/isula_connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/protocol_type.c
    )

set(local_client_connect_incs ${CMAKE_CURRENT_SOURCE_DIR})

if (GRPC_CONNECTOR)
    add_subdirectory(grpc)

    list(APPEND local_client_connect_srcs ${CLIENT_GRPC_SRCS})
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/containers CONNECT_API_CONTAINERS)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/images CONNECT_API_IMAGES)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/volumes CONNECT_API_VOLUMES)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/cri CONNECT_API_CRI)
    set(CONNECT_API ${CONNECT_API_VOLUMES} ${CONNECT_API_CONTAINERS} ${CONNECT_API_IMAGES} ${CONNECT_API_CRI})
    list(APPEND local_client_connect_srcs ${CONNECT_API})

    list(APPEND local_client_connect_incs ${CMAKE_CURRENT_SOURCE_DIR}/grpc)
    list(APPEND local_client_connect_incs
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/volumes
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/containers
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/images
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri
        )

    if(ENABLE_NATIVE_NETWORK)
        aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/network CONNECT_API_NETWORK)
        list(APPEND local_client_connect_srcs ${CONNECT_API_NETWORK})
        list(APPEND local_client_connect_incs ${CMAKE_BINARY_DIR}/grpc/src/api/services/network)
    endif(ENABLE_NATIVE_NETWORK)
    
else()
    add_subdirectory(rest)
    list(APPEND local_client_connect_srcs ${CLIENT_REST_SRCS})
    list(APPEND local_client_connect_incs ${CMAKE_CURRENT_SOURCE_DIR}/rest)
endif()

set(CLIENT_CONNECT_SRCS ${local_client_connect_srcs} PARENT_SCOPE)
set(CLIENT_CONNECT_INCS ${local_client_connect_incs} PARENT_SCOPE)
