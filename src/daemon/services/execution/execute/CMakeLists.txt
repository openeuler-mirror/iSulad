# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_execute_srcs)

set(EXECUTE_SRCS
    ${local_execute_srcs}
    PARENT_SCOPE
    )
