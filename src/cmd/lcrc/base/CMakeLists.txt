# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} lcrc_base_srcs)

set(LCRC_BASE_SRCS
    ${lcrc_base_srcs}
    PARENT_SCOPE
    )
