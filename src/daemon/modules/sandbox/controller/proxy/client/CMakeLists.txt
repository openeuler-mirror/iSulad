# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_proxy_client_srcs)
add_subdirectory(grpc)

set(local_sandbox_controller_proxy_client_srcs
    ${sandbox_controller_proxy_client_srcs}
    )

set(local_sandbox_controller_proxy_client_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

set(CONTROLLER_PROXY_CLIENT_SRCS
    ${local_sandbox_controller_proxy_client_srcs}
    ${CONTROLLER_PROXY_CLIENT_GRPC_SRCS}
    PARENT_SCOPE
    )

set(CONTROLLER_PROXY_CLIENT_INCS
    ${local_sandbox_controller_proxy_client_incs}
    ${CONTROLLER_PROXY_CLIENT_GRPC_INCS}
    {CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox
    PARENT_SCOPE
    )


