# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} runtime_top_srcs)
add_subdirectory(lcr)

set(local_runtime_srcs
    ${runtime_top_srcs}
    ${LCR_SRCS}
    )

set(local_runtime_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/lcr
    )

set(RUNTIME_SRCS
    ${local_runtime_srcs}
    PARENT_SCOPE
    )
set(RUNTIME_INCS
    ${local_runtime_incs}
    PARENT_SCOPE
    )
