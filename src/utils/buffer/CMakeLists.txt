# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_buffer_srcs)

set(BUFFER_SRCS
    ${local_buffer_srcs}
    PARENT_SCOPE
    )

set(BUFFER_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )

