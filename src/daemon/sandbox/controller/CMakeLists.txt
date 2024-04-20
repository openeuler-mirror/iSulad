# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_top_srcs)

set(local_sandbox_controller_top_srcs
    ${sandbox_controller_top_srcs}
    )
set(local_sandbox_controller_top_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

if (ENABLE_CRI_API_V1 AND ENABLE_SANDBOXER)
    add_subdirectory(sandboxer)
    list (APPEND local_sandbox_controller_top_srcs
        ${CONTROLLER_SANDBOXER_SRCS}
        )
    list (APPEND local_sandbox_controller_top_incs
        ${CONTROLLER_SANDBOXER_INCS}
        )
endif()

add_subdirectory(shim)
set(SANDBOX_CONTROLLER_SRCS
    ${local_sandbox_controller_top_srcs}
    ${CONTROLLER_SHIM_SRCS}
    PARENT_SCOPE
    )
set(SANDBOX_CONTROLLER_INCS
    ${local_sandbox_controller_top_incs}
    ${CONTROLLER_SHIM_INCS}
    PARENT_SCOPE
    )