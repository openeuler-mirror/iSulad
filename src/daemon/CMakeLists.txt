# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} daemon_top_srcs)
add_subdirectory(engines)
add_subdirectory(runtime)
add_subdirectory(image)
add_subdirectory(plugin)
add_subdirectory(callback)
add_subdirectory(spec)
add_subdirectory(container)
add_subdirectory(connect)
add_subdirectory(log)
add_subdirectory(events)

set(local_daemon_srcs
    ${daemon_top_srcs}
    ${ENGINES_SRCS}
    ${RUNTIME_SRCS}
    ${IMAGE_SRCS}
    ${PLUGIN_SRCS}
    ${CALLBACK_SRCS}
    ${SPEC_SRCS}
    ${MANAGER_SRCS}
    ${SERVER_CONNECT_SRCS}
    ${LOG_GATHER_SRCS}
    ${EVENTS_SRCS}
    )

set(local_daemon_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${ENGINES_INCS}
    ${RUNTIME_INCS}
    ${IMAGE_INCS}
    ${PLUGIN_INCS}
    ${CALLBACK_INCS}
    ${SPEC_INCS}
    ${MANAGER_INCS}
    ${SERVER_CONNECT_INCS}
    ${LOG_GATHER_INCS}
    ${EVENTS_INCS}
    )

if (GRPC_CONNECTOR)
        add_subdirectory(cri)
        list(APPEND local_daemon_srcs ${CRI_SRCS})
        list(APPEND local_daemon_incs ${CRI_INCS})
endif()

set(DAEMON_SRCS
    ${local_daemon_srcs}
    PARENT_SCOPE
    )
set(DAEMON_INCS
    ${local_daemon_incs}
    PARENT_SCOPE
    )
