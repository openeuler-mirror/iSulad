# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_common_cgroup_srcs)

set(COMMON_CGROUP_SRCS ${local_common_cgroup_srcs} PARENT_SCOPE)
set(COMMON_CGROUP_INCS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
