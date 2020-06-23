# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} runtime_lcr_top_srcs)

set(local_runtime_lcr_srcs
    ${runtime_lcr_top_srcs}
    )

set(local_runtime_lcr_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

set(LCR_SRCS
    ${local_runtime_lcr_srcs}
    PARENT_SCOPE
    )
set(LCR_INCS
    ${local_runtime_lcr_incs}
    PARENT_SCOPE
    )
