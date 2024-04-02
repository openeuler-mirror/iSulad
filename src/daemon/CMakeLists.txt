# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} daemon_top_srcs)
add_subdirectory(executor)
add_subdirectory(entry)
add_subdirectory(mailbox)
add_subdirectory(modules)
add_subdirectory(config)
add_subdirectory(common)

set(local_daemon_srcs
    ${daemon_top_srcs}
    ${EXECUTOR_SRCS}
    ${ENTRY_SRCS}
    ${MAILBOX_SRCS}
    ${MODULES_SRCS}
    ${CONFIG_SRCS}
    ${DAEMON_COMMON_SRCS}
    )

set(local_daemon_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${EXECUTOR_INCS}
    ${ENTRY_INCS}
    ${MAILBOX_INCS}
    ${MODULES_INCS}
    ${CONFIG_INCS}
    ${DAEMON_COMMON_INCS}
    )

if (ENABLE_CRI_API_V1)
    add_subdirectory(sandbox)
    list (APPEND local_daemon_srcs
        ${SANDBOX_SRCS}
        )
    list (APPEND local_daemon_incs
        ${SANDBOX_INCS}
        )
endif()

set(DAEMON_SRCS
    ${local_daemon_srcs}
    PARENT_SCOPE
    )
set(DAEMON_INCS
    ${local_daemon_incs}
    PARENT_SCOPE
    )

set(DAEMON_NETWORK_SRCS
    ${DAEMON_NETWORK_SRCS}
    PARENT_SCOPE
    )
set(DAEMON_NETWORK_INCS
    ${DAEMON_NETWORK_INCS}
    PARENT_SCOPE
    )
