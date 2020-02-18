# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_isula_srcs)

set(ISULA_SRCS
    ${local_isula_srcs}
    PARENT_SCOPE
    )
