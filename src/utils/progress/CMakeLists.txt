# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_progress_srcs)

set(PROGRESS_SRCS
    ${local_progress_srcs}
    PARENT_SCOPE
    )

set(PROGRESS_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )

