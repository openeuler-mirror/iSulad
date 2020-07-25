# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/ daemon_common_top_srcs)
set(local_daemon_common_srcs ${daemon_common_top_srcs})
set(local_daemon_common_incs ${CMAKE_CURRENT_SOURCE_DIR})

set(DAEMON_COMMON_SRCS
    ${local_daemon_common_srcs}
    PARENT_SCOPE
    )
set(DAEMON_COMMON_INCS
    ${local_daemon_common_incs}
    PARENT_SCOPE
    )
