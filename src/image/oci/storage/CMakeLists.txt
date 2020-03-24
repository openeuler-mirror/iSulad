# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_storage_srcs)
add_subdirectory(graphdriver)

set(STORAGE_SRCS
    ${local_storage_srcs}
    ${GRAPHDRIVER_SRCS}
    PARENT_SCOPE
    )

set(STORAGE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${GRAPHDRIVER_INCS}
    PARENT_SCOPE
    )
