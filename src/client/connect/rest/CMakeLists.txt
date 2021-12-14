# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_client_rest_srcs)

if(NOT ENABLE_NATIVE_NETWORK)
    list(REMOVE_ITEM local_client_rest_srcs "${CMAKE_CURRENT_SOURCE_DIR}/rest_network_client.c")
endif(ENABLE_NATIVE_NETWORK)


set(CLIENT_REST_SRCS
    ${local_client_rest_srcs}
    PARENT_SCOPE
    )
