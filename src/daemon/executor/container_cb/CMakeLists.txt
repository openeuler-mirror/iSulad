# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_container_cb_srcs)

set(CONTAINER_CB_SRCS
    ${local_container_cb_srcs}
    PARENT_SCOPE
    )
set(CONTAINER_CB_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
