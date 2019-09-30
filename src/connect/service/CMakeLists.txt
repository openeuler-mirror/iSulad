# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} service_srcs)

set(incs ${CMAKE_CURRENT_SOURCE_DIR})

if (GRPC_CONNECTOR)
    add_subdirectory(grpc)
    list(APPEND service_srcs ${SERVICE_GRPC_SRCS})
    list(APPEND incs ${CMAKE_CURRENT_SOURCE_DIR}/grpc)
else()
    add_subdirectory(rest)
    list(APPEND service_srcs ${SERVICE_REST_SRCS})
    list(APPEND incs ${CMAKE_CURRENT_SOURCE_DIR}/rest)
endif()

set(CONNECT_SERVICE_SRCS ${service_srcs} PARENT_SCOPE)
set(CONNECT_SERVICE_INCS ${incs} PARENT_SCOPE)
