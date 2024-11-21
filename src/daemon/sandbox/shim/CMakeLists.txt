# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} shim_sandbox_srcs)

add_subdirectory(controller)

set(SHIM_SANDBOX_SRCS
    ${shim_sandbox_srcs}
    ${CONTROLLER_SHIM_SRCS}
    PARENT_SCOPE
    )
set(SHIM_SANDBOX_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CONTROLLER_SHIM_INCS}
    PARENT_SCOPE
    )
