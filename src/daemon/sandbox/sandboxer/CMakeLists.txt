# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandboxer_sandbox_srcs)

add_subdirectory(controller)

set(SANDBOXER_SANDBOX_SRCS
    ${sandboxer_sandbox_srcs}
    ${CONTROLLER_SANDBOXER_SRCS}
    PARENT_SCOPE
    )
set(SANDBOXER_SANDBOX_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CONTROLLER_SANDBOXER_INCS}
    PARENT_SCOPE
    )
