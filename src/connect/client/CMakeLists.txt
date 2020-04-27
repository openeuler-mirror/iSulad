set(client_srcs
    ${CMAKE_CURRENT_SOURCE_DIR}/isula_connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pack_config.c
    )

set(incs ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(grpc)

if (GRPC_CONNECTOR)
    list(APPEND client_srcs ${CLIENT_GRPC_SRCS})
    list(APPEND incs ${CMAKE_CURRENT_SOURCE_DIR}/grpc)
else()
    add_subdirectory(rest)
    list(APPEND client_srcs ${CLIENT_REST_SRCS})
    list(APPEND incs ${CMAKE_CURRENT_SOURCE_DIR}/rest)
endif()

set(CONNECT_CLIENT_SRCS ${client_srcs} PARENT_SCOPE)
set(CONNECT_CLIENT_INCS ${incs} PARENT_SCOPE)
