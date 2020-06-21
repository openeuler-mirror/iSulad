# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_container_cb_srcs)
add_subdirectory(events)
add_subdirectory(execute)

set(CONTAINER_CB_SRCS
    ${local_container_cb_srcs}
    ${EVENTS_SRCS}
    ${EXECUTE_SRCS}
    PARENT_SCOPE
    )
set(CONTAINER_CB_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/events
    ${CMAKE_CURRENT_SOURCE_DIR}/execute
    PARENT_SCOPE
    )
