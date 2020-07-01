# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} daemon_top_srcs)
add_subdirectory(executor)
add_subdirectory(entry)
add_subdirectory(modules)
add_subdirectory(config)

set(local_daemon_srcs
    ${daemon_top_srcs}
    ${EXECUTOR_SRCS}
    ${ENTRY_SRCS}
    ${MODULES_SRCS}
    ${CONFIG_SRCS}
    )

set(local_daemon_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${EXECUTOR_INCS}
    ${ENTRY_INCS}
    ${MODULES_INCS}
    ${CONFIG_INCS}
    )

set(DAEMON_SRCS
    ${local_daemon_srcs}
    PARENT_SCOPE
    )
set(DAEMON_INCS
    ${local_daemon_incs}
    PARENT_SCOPE
    )
