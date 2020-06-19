# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_lcr_srcs)

set(ENGINES_LCR_SRCS
    ${local_lcr_srcs}
    PARENT_SCOPE
    )
