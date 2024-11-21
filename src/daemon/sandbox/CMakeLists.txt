# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_top_srcs)

set(local_sandbox_top_srcs
    ${sandbox_top_srcs}
    )
set(local_sandbox_top_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

if (ENABLE_CRI_API_V1 AND ENABLE_SANDBOXER)
    add_subdirectory(sandboxer)
    list (APPEND local_sandbox_top_srcs
        ${SANDBOXER_SANDBOX_SRCS}
        )
    list (APPEND local_sandbox_top_incs
        ${SANDBOXER_SANDBOX_INCS}
        )
endif()

add_subdirectory(shim)
set(SANDBOX_SRCS
    ${local_sandbox_top_srcs}
    ${SHIM_SANDBOX_SRCS}
    PARENT_SCOPE
    )
set(SANDBOX_INCS
    ${local_sandbox_top_incs}
    ${SHIM_SANDBOX_INCS}
    PARENT_SCOPE
    )