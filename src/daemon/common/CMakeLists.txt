# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} daemon_common_top_srcs)

if (NOT ENABLE_SELINUX)
    list(REMOVE_ITEM daemon_common_top_srcs "${CMAKE_CURRENT_SOURCE_DIR}/selinux_label.c")
endif()

if (GRPC_CONNECTOR)
    add_subdirectory(cri)
endif()

add_subdirectory(cgroup)

set(local_daemon_common_srcs ${daemon_common_top_srcs})

set(DAEMON_COMMON_SRCS
    ${COMMON_CRI_SRCS}
    ${COMMON_CGROUP_SRCS}
    ${local_daemon_common_srcs}
    PARENT_SCOPE
    )

set(DAEMON_COMMON_INCS
    ${COMMON_CRI_INCS}
    ${COMMON_CGROUP_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
