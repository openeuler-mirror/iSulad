# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} lcrc_stream_srcs)

set(LCRC_STREAM_SRCS
    ${lcrc_stream_srcs}
    PARENT_SCOPE
    )
