# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} nri_top_srcs)

set(NRI_INCS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)

set(NRI_SRCS ${nri_top_srcs} PARENT_SCOPE)
