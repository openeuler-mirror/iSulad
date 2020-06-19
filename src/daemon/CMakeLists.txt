# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} daemon_top_srcs)
add_subdirectory(engines)
add_subdirectory(runtime)
add_subdirectory(image)
add_subdirectory(plugin)
add_subdirectory(services)
add_subdirectory(connect)

set(local_daemon_srcs
    ${daemon_top_srcs}
    ${ENGINES_SRCS}
    ${RUNTIME_SRCS}
    ${IMAGE_SRCS}
    ${PLUGIN_SRCS}
    ${SERVICES_SRCS}
    ${SERVER_CONNECT_SRCS}
    )

set(local_daemon_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${ENGINES_INCS}
    ${RUNTIME_INCS}
    ${IMAGE_INCS}
    ${PLUGIN_INCS}
    ${SERVICES_INCS}
    ${SERVER_CONNECT_INCS}
    )

set(DAEMON_SRCS
    ${local_daemon_srcs}
    PARENT_SCOPE
    )
set(DAEMON_INCS
    ${local_daemon_incs}
    PARENT_SCOPE
    )
