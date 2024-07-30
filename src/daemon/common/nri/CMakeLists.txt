# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_common_nri_srcs)
set(local_common_nri_incs ${CMAKE_CURRENT_SOURCE_DIR})

set(COMMON_NRI_SRCS
    ${local_common_nri_srcs}
    PARENT_SCOPE
)

set(COMMON_NRI_INCS
    ${local_common_nri_incs}
    PARENT_SCOPE
)
