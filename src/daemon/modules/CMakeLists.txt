# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} modules_top_srcs)
add_subdirectory(runtime)
add_subdirectory(image)
add_subdirectory(plugin)
add_subdirectory(spec)
add_subdirectory(container)
add_subdirectory(log)
add_subdirectory(events)
add_subdirectory(events_sender)

set(local_modules_srcs
    ${modules_top_srcs}
    ${RUNTIME_SRCS}
    ${IMAGE_SRCS}
    ${PLUGIN_SRCS}
    ${SPEC_SRCS}
    ${MANAGER_SRCS}
    ${LOG_GATHER_SRCS}
    ${EVENTS_SRCS}
    ${EVENTS_SENDER_SRCS}
    )

set(local_modules_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${RUNTIME_INCS}
    ${IMAGE_INCS}
    ${PLUGIN_INCS}
    ${SPEC_INCS}
    ${MANAGER_INCS}
    ${LOG_GATHER_INCS}
    ${EVENTS_INCS}
    ${EVENTS_SENDER_INCS}
    )

set(MODULES_SRCS
    ${local_modules_srcs}
    PARENT_SCOPE
    )
set(MODULES_INCS
    ${local_modules_incs}
    PARENT_SCOPE
    )
