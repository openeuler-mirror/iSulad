# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_stream_srcs)

set(ISULA_STREAM_SRCS
    ${isula_stream_srcs}
    PARENT_SCOPE
    )
