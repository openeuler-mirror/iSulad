# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_top_srcs)
add_subdirectory(controller)

set(SANDBOX_SRCS
    ${sandbox_top_srcs}
    ${SANDBOX_CONTROLLER_SRCS}
    PARENT_SCOPE
    )
set(SANDBOX_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SANDBOX_CONTROLLER_INCS}
    PARENT_SCOPE
    )