# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_service_rest_srcs)

if(NOT ENABLE_NATIVE_NETWORK)
    list(REMOVE_ITEM local_service_rest_srcs "${CMAKE_CURRENT_SOURCE_DIR}/rest_network_service.c")
endif()

set(SERVICE_REST_SRCS
    ${local_service_rest_srcs}
    PARENT_SCOPE
    )
