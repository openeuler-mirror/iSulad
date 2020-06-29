# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} daemon_top_srcs)
add_subdirectory(runtime)
add_subdirectory(image)
add_subdirectory(plugin)
add_subdirectory(executor)
add_subdirectory(spec)
add_subdirectory(container)
add_subdirectory(log)
add_subdirectory(events)
add_subdirectory(events_sender)
add_subdirectory(entry)

set(local_daemon_srcs
    ${daemon_top_srcs}
    ${RUNTIME_SRCS}
    ${IMAGE_SRCS}
    ${PLUGIN_SRCS}
    ${EXECUTOR_SRCS}
    ${SPEC_SRCS}
    ${MANAGER_SRCS}
    ${ENTRY_SRCS}
    ${LOG_GATHER_SRCS}
    ${EVENTS_SRCS}
    ${EVENTS_SENDER_SRCS}
    )

set(local_daemon_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${RUNTIME_INCS}
    ${IMAGE_INCS}
    ${PLUGIN_INCS}
    ${EXECUTOR_INCS}
    ${SPEC_INCS}
    ${MANAGER_INCS}
    ${ENTRY_INCS}
    ${LOG_GATHER_INCS}
    ${EVENTS_INCS}
    ${EVENTS_SENDER_INCS}
    )

set(DAEMON_SRCS
    ${local_daemon_srcs}
    PARENT_SCOPE
    )
set(DAEMON_INCS
    ${local_daemon_incs}
    PARENT_SCOPE
    )
