# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_sandboxer_srcs)

add_subdirectory(client)

set(CONTROLLER_SANDBOXER_SRCS
    ${sandbox_controller_sandboxer_srcs}
    ${CONTROLLER_SANDBOXER_CLIENT_SRCS}
    PARENT_SCOPE
    )
set(CONTROLLER_SANDBOXER_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CONTROLLER_SANDBOXER_CLIENT_INCS}
    PARENT_SCOPE
    )
