# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} client_srcs)

set(incs ${CMAKE_CURRENT_SOURCE_DIR})

if (GRPC_CONNECTOR)
    add_subdirectory(grpc)
    list(APPEND client_srcs ${CLIENT_GRPC_SRCS})
    list(APPEND incs ${CMAKE_CURRENT_SOURCE_DIR}/grpc)
else()
    add_subdirectory(rest)
    list(APPEND client_srcs ${CLIENT_REST_SRCS})
    list(APPEND incs ${CMAKE_CURRENT_SOURCE_DIR}/rest)
endif()


set(CONNECT_CLIENT_SRCS ${client_srcs} PARENT_SCOPE)
set(CONNECT_CLIENT_INCS ${incs} PARENT_SCOPE)
