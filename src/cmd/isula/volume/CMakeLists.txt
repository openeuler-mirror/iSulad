# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_volume_srcs)

set(ISULA_VOLUME_SRCS
    ${isula_volume_srcs}
    PARENT_SCOPE
    )
