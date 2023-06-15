# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} cri_v1alpha_srcs)

set(CRI_V1ALPHA_SRCS ${cri_v1alpha_srcs} PARENT_SCOPE)
set(CRI_V1ALPHA_INCS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
