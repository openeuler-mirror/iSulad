# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} common_cri_v1_srcs)

set(COMMON_CRI_V1_SRCS ${common_cri_v1_srcs} PARENT_SCOPE)
set(COMMON_CRI_V1_INCS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)