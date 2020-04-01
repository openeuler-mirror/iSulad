# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_container_store_srcs)

set(CONTAINER_STORE_SRCS
    ${local_container_store_srcs}
    PARENT_SCOPE
    )
set(CONTAINER_STORE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
