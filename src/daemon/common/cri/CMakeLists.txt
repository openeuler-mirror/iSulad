# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_common_cri_srcs)
set(local_common_cri_incs ${CMAKE_CURRENT_SOURCE_DIR})

if (ENABLE_CRI_API_V1)
    add_subdirectory(v1)
    list(APPEND local_common_cri_srcs ${COMMON_CRI_V1_SRCS})
    list(APPEND local_common_cri_incs ${COMMON_CRI_V1_INCS})
endif()

set(COMMON_CRI_SRCS
    ${local_common_cri_srcs}
    PARENT_SCOPE
)

set(COMMON_CRI_INCS
    ${local_common_cri_incs}
    PARENT_SCOPE
)
