# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_service_grpc_srcs)

add_subdirectory(container)
list(APPEND local_service_grpc_srcs ${GRPC_CONTAINER_SERVICE_SRCS})

if(NOT ENABLE_NATIVE_NETWORK)
    list(REMOVE_ITEM local_service_grpc_srcs "${CMAKE_CURRENT_SOURCE_DIR}/grpc_network_service.cc")
endif()

add_subdirectory(cri)

set(SERVICE_GRPC_SRCS
    ${local_service_grpc_srcs}
    ${SERVICE_CRI_SRCS}
    PARENT_SCOPE
)

set(SERVICE_GRPC_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/container
    ${SERVICE_CRI_INCS}
    PARENT_SCOPE
)