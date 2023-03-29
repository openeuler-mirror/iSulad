# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_shim_srcs)

set(local_sandbox_controller_shim_srcs
    ${sandbox_controller_shim_srcs}
    )

set(local_sandbox_controller_shim_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

set(CONTROLLER_SHIM_SRCS
    ${local_sandbox_controller_shim_srcs}
    PARENT_SCOPE
    )
set(CONTROLLER_SHIM_INCS
    ${local_sandbox_controller_shim_incs}
    PARENT_SCOPE
    )
