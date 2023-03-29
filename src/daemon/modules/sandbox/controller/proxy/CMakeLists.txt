# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_proxy_srcs)
add_subdirectory(client)

set(local_sandbox_controller_proxy_srcs
    ${sandbox_controller_proxy_srcs}
    )

set(local_sandbox_controller_proxy_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

set(CONTROLLER_PROXY_SRCS
    ${local_sandbox_controller_proxy_srcs}
    ${CONTROLLER_PROXY_CLIENT_SRCS}
    PARENT_SCOPE
    )
set(CONTROLLER_PROXY_INCS
    ${local_sandbox_controller_proxy_incs}
    ${CONTROLLER_PROXY_CLIENT_INCS}
    PARENT_SCOPE
    )
