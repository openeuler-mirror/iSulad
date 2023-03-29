# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_top_srcs)
add_subdirectory(proxy)
add_subdirectory(shim)

set(SANDBOX_CONTROLLER_SRCS
    ${sandbox_controller_top_srcs}
    ${CONTROLLER_PROXY_SRCS}
    ${CONTROLLER_SHIM_SRCS}
    PARENT_SCOPE
    )
set(SANDBOX_CONTROLLER_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CONTROLLER_PROXY_INCS}
    ${CONTROLLER_SHIM_INCS}
    PARENT_SCOPE
    )
