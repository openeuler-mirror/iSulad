# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} top_srcs)

set(OPT_SRCS ${top_srcs} PARENT_SCOPE)
set(OPT_INCS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
