# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_execution_srcs)
add_subdirectory(events)
add_subdirectory(execute)
add_subdirectory(manager)
add_subdirectory(spec)

set(EXECUTION_SRCS
    ${local_execution_srcs}
    ${EVENTS_SRCS}
    ${EXECUTE_SRCS}
    ${MANAGER_SRCS}
    ${SPEC_SRCS}
    PARENT_SCOPE
    )
set(EXECUTION_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/events
    ${CMAKE_CURRENT_SOURCE_DIR}/execute
    ${CMAKE_CURRENT_SOURCE_DIR}/manager
    ${CMAKE_CURRENT_SOURCE_DIR}/spec
    PARENT_SCOPE
    )
