# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} client_top_srcs)
add_subdirectory(connect)

set(local_client_srcs
    ${client_top_srcs}
    ${CLIENT_CONNECT_SRCS}
    )

set(local_client_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CLIENT_CONNECT_INCS}
    )

set(CLIENT_SRCS
    ${local_client_srcs}
    PARENT_SCOPE
    )
set(CLIENT_INCS
    ${local_client_incs}
    PARENT_SCOPE
    )
