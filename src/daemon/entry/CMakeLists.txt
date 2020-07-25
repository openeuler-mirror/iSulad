# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} entry_top_srcs)
add_subdirectory(connect)

set(local_entry_srcs
    ${entry_top_srcs}
    ${SERVER_CONNECT_SRCS}
    )

set(local_entry_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SERVER_CONNECT_INCS}
    )

if (GRPC_CONNECTOR)
        add_subdirectory(cri)
        list(APPEND local_entry_srcs ${CRI_SRCS})
        list(APPEND local_entry_incs ${CRI_INCS})
endif()

set(ENTRY_SRCS
    ${local_entry_srcs}
    PARENT_SCOPE
    )
set(ENTRY_INCS
    ${local_entry_incs}
    PARENT_SCOPE
    )
