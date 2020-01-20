# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_base_srcs)

set(ISULA_BASE_SRCS
    ${isula_base_srcs}
    PARENT_SCOPE
    )
