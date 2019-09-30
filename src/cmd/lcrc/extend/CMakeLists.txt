# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} lcrc_extend_srcs)

set(LCRC_EXTEND_SRCS
    ${lcrc_extend_srcs}
    PARENT_SCOPE
    )
