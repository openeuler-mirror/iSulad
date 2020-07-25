# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} service_comm_srcs)

set(WB_SERVICE_SRCS ${service_comm_srcs} PARENT_SCOPE)
set(WB_SERVICE_INCS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
