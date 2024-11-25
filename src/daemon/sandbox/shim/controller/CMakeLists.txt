# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_shim_srcs)

set(CONTROLLER_SHIM_SRCS
    ${sandbox_controller_shim_srcs}
    PARENT_SCOPE
    )
set(CONTROLLER_SHIM_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
