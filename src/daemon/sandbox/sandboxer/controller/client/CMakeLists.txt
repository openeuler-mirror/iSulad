# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_sandboxer_client_srcs)

set(CONTROLLER_SANDBOXER_CLIENT_SRCS
    ${sandbox_controller_sandboxer_client_srcs}
    PARENT_SCOPE
    )

set(CONTROLLER_SANDBOXER_CLIENT_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
