# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_sandboxer_srcs)

set(CONTROLLER_SANDBOXER_SRCS
    ${sandbox_controller_sandboxer_srcs}
    PARENT_SCOPE
    )
set(CONTROLLER_SANDBOXER_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
