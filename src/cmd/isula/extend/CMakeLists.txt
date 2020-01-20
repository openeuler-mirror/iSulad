# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_extend_srcs)

set(ISULA_EXTEND_SRCS
    ${isula_extend_srcs}
    PARENT_SCOPE
    )
